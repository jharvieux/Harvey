// Orchestrates the "connected" Supabase project-config pass: Advisor security lints, Storage
// bucket policy coverage, auto-exposed public-schema tables, Auth config, and dangerous
// extensions. Read-only against the CLIENT's project — parameterized by project ref, never
// hardcoded to this repo's own Supabase connections (this repo's own supabase-* MCP servers
// were used only as a reference for real advisor/extension response shapes while building
// src/scan/supabase-advisors.ts and src/scan/supabase-config.ts).
//
// CLI: `pnpm exec tsx src/cli/scan.ts --supabase <project-ref|local>`
//
// Hosted mode uses the Supabase Management API with a personal access token
// (env SUPABASE_ACCESS_TOKEN, or the managementApiToken option). Two endpoints are confirmed
// against the published OpenAPI spec (https://api.supabase.com/api/v1-json):
//   GET  /v1/projects/{ref}/advisors/security
//   GET  /v1/projects/{ref}/config/auth
// Table/extension/storage-bucket data needs a SQL read, done via the Management API's SQL
// endpoint:
//   POST /v1/projects/{ref}/database/query   { query: "<read-only SQL>" }
// That endpoint's exact request/response envelope was NOT independently re-verified against
// the live OpenAPI spec in this session (unlike the two GET endpoints above) — confirm the
// request body key and response shape (bare row array vs. a wrapper object) before the first
// real hosted run, and adjust managementApiQuery below if it differs.
//
// Local mode (`--supabase local`) targets a `supabase start` stack directly over Postgres
// (default: postgresql://postgres:postgres@127.0.0.1:54322/postgres) using the `postgres`
// package (already a project dependency) — no Management API assumptions needed. Advisor
// lints are a hosted-dashboard feature backed by Splinter (Supabase's open-source Postgres
// linter); local mode runs the vendored copy directly (src/scan/rules/splinter.sql, via
// src/scan/supabase-splinter.ts#runSplinter) against the same connection, so local scans get
// the full Advisor lint set, not just the SQL-derived checks below. Those SQL-derived checks
// (checkAutoExposedTables/checkDangerousExtensions/checkPublicBucketsWithNoPolicies) cover
// ground Splinter doesn't (dangerous extensions, public-bucket policy coverage) and are kept;
// checkAutoExposedTables overlaps Splinter's rls_disabled_in_public lint for the same table,
// so that overlap is deduped (dedupeAutoExposed below) rather than double-emitted. The Supabase
// CLI also ships `supabase db lint`, which may cover similar ground, but its JSON output wasn't
// verified here, so it isn't wired in.
//
// Edge function secret/webhook-signature checks read source from the client repo's
// `supabase/functions/<name>/index.ts` layout (functionsDir option) rather than fetching
// deployed bundles through the Management API — the source lives in the repo either way for
// both hosted and local targets, and fetching deployed function source wasn't a verified
// Management API surface in this session.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../findings.js";
import { parseAdvisorFindings, type AdvisorsResponse } from "./supabase-advisors.js";
import { runSplinter } from "./supabase-splinter.js";
import {
  checkAuthConfig,
  checkAutoExposedTables,
  checkDangerousExtensions,
  checkEdgeFunctionSecrets,
  checkExposedSchemas,
  checkGotrueVersion,
  checkGraphqlIntrospection,
  checkPublicBucketsWithNoPolicies,
  checkRealtimeAuthorization,
  checkUnsignedWebhookHandlers,
  type AuthConfig,
  type EdgeFunctionSource,
  type ExtensionInfo,
  type GotrueInfo,
  type StorageBucket,
  type TableInfo,
} from "./supabase-config.js";

const MANAGEMENT_API = "https://api.supabase.com/v1";
const LOCAL_CONNECTION = "postgresql://postgres:postgres@127.0.0.1:54322/postgres";

const TABLES_SQL = `select schemaname as schema, tablename as name, rowsecurity as "rlsEnabled" from pg_tables where schemaname = 'public';`;
const EXTENSIONS_SQL = `select extname as name, extnamespace::regnamespace::text as schema, extversion as installed_version from pg_extension;`;
const BUCKETS_SQL = `select id, name, public from storage.buckets;`;
const BUCKET_POLICY_COUNTS_SQL = `select (regexp_match(qual, 'bucket_id = ''([^'']+)'''))[1] as bucket_id, count(*) from pg_policies where schemaname = 'storage' and tablename = 'objects' group by 1;`;
const REALTIME_MESSAGES_SQL = `select rowsecurity as "rlsEnabled" from pg_tables where schemaname = 'realtime' and tablename = 'messages';`;

// PostgREST config exposes the schema allow-list as `db_schema` (comma-separated). The GET
// endpoint is documented but its response shape was NOT independently re-verified against the
// live OpenAPI spec this session — confirm the `db_schema` key before the first real hosted run.
interface PostgrestConfig {
  db_schema?: string;
}

// GoTrue (Supabase Auth) exposes its running version at `{authUrl}/health` and its enabled
// providers at `{authUrl}/settings`, both reachable with only the anon `apikey` header. Shapes
// verified live 2026-07-10: health → {version:"v2.192.0",...}; settings → {external:{apple,azure,…}}.
// Hosted Supabase auto-patches GoTrue, so this probe is primarily for self-hosted targets.
interface SupabaseScanOptions {
  projectRef?: string; // required unless local
  local?: boolean;
  managementApiToken?: string; // falls back to SUPABASE_ACCESS_TOKEN
  fetchImpl?: typeof fetch; // injection point for tests
  functionsDir?: string; // path to the client repo's supabase/functions directory, if scanning it
  splinterImpl?: (connectionString: string) => AdvisorsResponse; // injection point for tests, defaults to runSplinter
  gotrueProbe?: { authUrl: string; anonKey: string }; // self-hosted GoTrue version/provider probe
}

function parseExposedSchemas(config: PostgrestConfig): string[] {
  return (config.db_schema ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

async function probeGotrue(authUrl: string, anonKey: string, fetchImpl: typeof fetch): Promise<GotrueInfo> {
  const base = authUrl.replace(/\/$/, "");
  const headers = { apikey: anonKey };
  const health = (await managementFetchJson(`${base}/health`, headers, fetchImpl)) as { version?: string };
  const settings = (await managementFetchJson(`${base}/settings`, headers, fetchImpl)) as { external?: Record<string, boolean> };
  return { version: health.version ?? null, appleEnabled: settings.external?.apple, azureEnabled: settings.external?.azure };
}

async function managementFetchJson(url: string, headers: Record<string, string>, fetchImpl: typeof fetch): Promise<unknown> {
  const res = await fetchImpl(url, { headers });
  if (!res.ok) throw new Error(`GET ${url} failed: ${res.status} ${res.statusText}`);
  return res.json();
}

function readEdgeFunctionSources(functionsDir: string): EdgeFunctionSource[] {
  if (!existsSync(functionsDir)) return [];
  const sources: EdgeFunctionSource[] = [];
  for (const entry of readdirSync(functionsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const indexPath = ["index.ts", "index.js"].map((f) => join(functionsDir, entry.name, f)).find(existsSync);
    if (indexPath) sources.push({ name: entry.name, content: readFileSync(indexPath, "utf8") });
  }
  return sources;
}

async function managementApiGet<T>(path: string, token: string, fetchImpl: typeof fetch): Promise<T> {
  const res = await fetchImpl(`${MANAGEMENT_API}${path}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`Supabase Management API GET ${path} failed: ${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

async function managementApiQuery<T>(ref: string, sql: string, token: string, fetchImpl: typeof fetch): Promise<T> {
  const res = await fetchImpl(`${MANAGEMENT_API}/projects/${ref}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query: sql }),
  });
  if (!res.ok) throw new Error(`Supabase Management API SQL query failed: ${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function bucketPolicyCounts(rows: { bucket_id: string; count: number }[]): Record<string, number> {
  return Object.fromEntries(rows.map((r) => [r.bucket_id, Number(r.count)]));
}

async function scanHosted(ref: string, token: string, fetchImpl: typeof fetch): Promise<Finding[]> {
  const findings: Finding[] = [];

  const advisors = await managementApiGet<AdvisorsResponse>(`/projects/${ref}/advisors/security`, token, fetchImpl);
  findings.push(...parseAdvisorFindings(advisors));

  const authConfig = await managementApiGet<AuthConfig>(`/projects/${ref}/config/auth`, token, fetchImpl);
  findings.push(...checkAuthConfig(authConfig));

  const tables = await managementApiQuery<TableInfo[]>(ref, TABLES_SQL, token, fetchImpl);
  findings.push(...checkAutoExposedTables(tables));

  const extensions = await managementApiQuery<ExtensionInfo[]>(ref, EXTENSIONS_SQL, token, fetchImpl);
  findings.push(...checkDangerousExtensions(extensions));

  const buckets = await managementApiQuery<StorageBucket[]>(ref, BUCKETS_SQL, token, fetchImpl);
  const policyRows = await managementApiQuery<{ bucket_id: string; count: number }[]>(ref, BUCKET_POLICY_COUNTS_SQL, token, fetchImpl);
  findings.push(...checkPublicBucketsWithNoPolicies(buckets, bucketPolicyCounts(policyRows)));

  const realtime = await managementApiQuery<{ rlsEnabled: boolean }[]>(ref, REALTIME_MESSAGES_SQL, token, fetchImpl);
  findings.push(...checkRealtimeAuthorization({ exists: realtime.length > 0, rlsEnabled: realtime[0]?.rlsEnabled ?? false }));

  const postgrest = await managementApiGet<PostgrestConfig>(`/projects/${ref}/postgrest`, token, fetchImpl);
  const exposedSchemas = parseExposedSchemas(postgrest);
  const pgGraphqlInstalled = extensions.some((e) => e.name === "pg_graphql" && Boolean(e.installed_version));
  findings.push(...checkExposedSchemas(exposedSchemas), ...checkGraphqlIntrospection(pgGraphqlInstalled, exposedSchemas));

  return findings;
}

// checkAutoExposedTables and Splinter's rls_disabled_in_public lint both flag "public-schema
// table, RLS disabled" for the same table — Splinter is the ground-truth Advisor source, so
// drop the checkAutoExposedTables hit for any table Splinter already caught rather than
// double-emit the same underlying issue under two taxonomies.
export function dedupeAutoExposed(splinterFindings: Finding[], autoExposedFindings: Finding[]): Finding[] {
  const covered = new Set(splinterFindings.filter((f) => f.taxonomy === "rls_disabled_in_public").map((f) => f.location));
  return autoExposedFindings.filter((f) => !covered.has(f.location));
}

async function scanLocal(connectionString: string = LOCAL_CONNECTION, splinterImpl: (connectionString: string) => AdvisorsResponse = runSplinter): Promise<Finding[]> {
  const { default: postgres } = await import("postgres");
  const sql = postgres(connectionString, { max: 1, idle_timeout: 5 });
  try {
    const tables = (await sql.unsafe(TABLES_SQL)) as unknown as TableInfo[];
    const extensions = (await sql.unsafe(EXTENSIONS_SQL)) as unknown as ExtensionInfo[];
    const buckets = (await sql.unsafe(BUCKETS_SQL)) as unknown as StorageBucket[];
    const policyRows = (await sql.unsafe(BUCKET_POLICY_COUNTS_SQL)) as unknown as { bucket_id: string; count: number }[];
    const realtime = (await sql.unsafe(REALTIME_MESSAGES_SQL)) as unknown as { rlsEnabled: boolean }[];

    const splinterFindings = parseAdvisorFindings(splinterImpl(connectionString));

    // Exposed-schema / pg_graphql breadth reads PostgREST's db-schema config, which isn't in
    // Postgres — hosted-only. Local mode covers the realtime-authorization class (SQL-readable).
    return [
      ...splinterFindings,
      ...dedupeAutoExposed(splinterFindings, checkAutoExposedTables(tables)),
      ...checkDangerousExtensions(extensions),
      ...checkPublicBucketsWithNoPolicies(buckets, bucketPolicyCounts(policyRows)),
      ...checkRealtimeAuthorization({ exists: realtime.length > 0, rlsEnabled: realtime[0]?.rlsEnabled ?? false }),
    ];
  } finally {
    await sql.end();
  }
}

export async function runSupabaseScan(opts: SupabaseScanOptions): Promise<Finding[]> {
  let findings: Finding[];
  if (opts.local) {
    findings = await scanLocal(LOCAL_CONNECTION, opts.splinterImpl);
  } else {
    if (!opts.projectRef) throw new Error("runSupabaseScan requires projectRef unless local is set");
    const token = opts.managementApiToken ?? process.env.SUPABASE_ACCESS_TOKEN;
    if (!token) throw new Error("Supabase Management API token required (SUPABASE_ACCESS_TOKEN env var or managementApiToken option)");
    findings = await scanHosted(opts.projectRef, token, opts.fetchImpl ?? fetch);
  }

  if (opts.functionsDir) {
    const edgeFunctions = readEdgeFunctionSources(opts.functionsDir);
    findings.push(...checkEdgeFunctionSecrets(edgeFunctions), ...checkUnsignedWebhookHandlers(edgeFunctions));
  }

  if (opts.gotrueProbe) {
    findings.push(...checkGotrueVersion(await probeGotrue(opts.gotrueProbe.authUrl, opts.gotrueProbe.anonKey, opts.fetchImpl ?? fetch)));
  }

  return findings;
}
