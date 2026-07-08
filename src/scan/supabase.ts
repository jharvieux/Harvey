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
// lints are a hosted-dashboard feature backed by Splinter; local mode skips them and relies
// on the SQL-derived checks only. The Supabase CLI also ships `supabase db lint`, which may
// cover similar ground locally, but its JSON output wasn't verified here, so it isn't wired in.
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
import {
  checkAuthConfig,
  checkAutoExposedTables,
  checkDangerousExtensions,
  checkEdgeFunctionSecrets,
  checkPublicBucketsWithNoPolicies,
  checkUnsignedWebhookHandlers,
  type AuthConfig,
  type EdgeFunctionSource,
  type ExtensionInfo,
  type StorageBucket,
  type TableInfo,
} from "./supabase-config.js";

const MANAGEMENT_API = "https://api.supabase.com/v1";
const LOCAL_CONNECTION = "postgresql://postgres:postgres@127.0.0.1:54322/postgres";

const TABLES_SQL = `select schemaname as schema, tablename as name, rowsecurity as "rlsEnabled" from pg_tables where schemaname = 'public';`;
const EXTENSIONS_SQL = `select extname as name, extnamespace::regnamespace::text as schema, extversion as installed_version from pg_extension;`;
const BUCKETS_SQL = `select id, name, public from storage.buckets;`;
const BUCKET_POLICY_COUNTS_SQL = `select (regexp_match(qual, 'bucket_id = ''([^'']+)'''))[1] as bucket_id, count(*) from pg_policies where schemaname = 'storage' and tablename = 'objects' group by 1;`;

interface SupabaseScanOptions {
  projectRef?: string; // required unless local
  local?: boolean;
  managementApiToken?: string; // falls back to SUPABASE_ACCESS_TOKEN
  fetchImpl?: typeof fetch; // injection point for tests
  functionsDir?: string; // path to the client repo's supabase/functions directory, if scanning it
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

  return findings;
}

async function scanLocal(connectionString: string = LOCAL_CONNECTION): Promise<Finding[]> {
  const { default: postgres } = await import("postgres");
  const sql = postgres(connectionString, { max: 1, idle_timeout: 5 });
  try {
    const tables = (await sql.unsafe(TABLES_SQL)) as unknown as TableInfo[];
    const extensions = (await sql.unsafe(EXTENSIONS_SQL)) as unknown as ExtensionInfo[];
    const buckets = (await sql.unsafe(BUCKETS_SQL)) as unknown as StorageBucket[];
    const policyRows = (await sql.unsafe(BUCKET_POLICY_COUNTS_SQL)) as unknown as { bucket_id: string; count: number }[];
    return [
      ...checkAutoExposedTables(tables),
      ...checkDangerousExtensions(extensions),
      ...checkPublicBucketsWithNoPolicies(buckets, bucketPolicyCounts(policyRows)),
    ];
  } finally {
    await sql.end();
  }
}

export async function runSupabaseScan(opts: SupabaseScanOptions): Promise<Finding[]> {
  let findings: Finding[];
  if (opts.local) {
    findings = await scanLocal();
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

  return findings;
}
