// Orchestrates the "connected" Supabase project-config pass: Advisor security lints, Storage
// bucket policy coverage, auto-exposed public-schema tables, Auth config, and dangerous
// extensions. Read-only against the CLIENT's project — parameterized by project ref, never
// hardcoded to this repo's own Supabase connections (this repo's own supabase-* MCP servers
// were used only as a reference for real advisor/extension response shapes while building
// src/scan/supabase-advisors.ts and src/scan/supabase-config.ts).
//
// CLI: `pnpm exec tsx src/cli/scan.ts --supabase <project-ref|local> [--migrations <dir>]`
//
// #1280 — with --migrations, the pass also diffs the deployed public schema against the end state of
// the committed migration history (src/scan/supabase-drift.ts): tables on each side, RLS enablement,
// and policy identities. Read-only on both halves, and against the SAME connected project the rest
// of this pass already reads — it is not the production-probe tier declined on #904.
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

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import type { Finding } from "../findings.js";
import { parseAdvisorFindings, type AdvisorsResponse } from "./supabase-advisors.js";
import { runSplinter } from "./supabase-splinter.js";
import {
  checkMigrationDrift,
  loadMigrations,
  type DriftLivePolicy,
  type DriftLiveTable,
  type MigrationFile,
} from "./supabase-drift.js";
import {
  checkAuthConfig,
  deriveAuthMethods,
  checkAutoExposedTables,
  checkColumnGrantsToClientRoles,
  checkCronJobs,
  checkDangerousExtensions,
  checkDefaultPrivilegesToClientRoles,
  checkEdgeFunctionSecrets,
  checkExposedSchemas,
  checkGotrueVersion,
  checkGraphqlIntrospection,
  checkPublicBucketsWithNoPolicies,
  checkRealtimeAuthorization,
  checkRealtimePublicationRls,
  checkUnsignedWebhookHandlers,
  type ColumnGrant,
  type CronJob,
  type DefaultAclGrant,
  type PublishedTable,
  type AuthConfig,
  type EdgeFunctionSource,
  type ExtensionInfo,
  type GotrueInfo,
  type RealtimeMessagesInfo,
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
const REALTIME_PUBLICATION_SQL = `select pt.schemaname as schema, pt.tablename as name, c.relrowsecurity as "rlsEnabled" from pg_publication_tables pt join pg_namespace n on n.nspname = pt.schemaname join pg_class c on c.relname = pt.tablename and c.relnamespace = n.oid where pt.pubname = 'supabase_realtime';`;
const DEFAULT_ACL_SQL = `select n.nspname as schema, r.rolname as role, case d.defaclobjtype when 'r' then 'table' when 'f' then 'function' when 'S' then 'sequence' else d.defaclobjtype::text end as "objectType", array_agg(distinct a.privilege_type order by a.privilege_type) as privileges from pg_default_acl d join pg_namespace n on n.oid = d.defaclnamespace cross join lateral aclexplode(d.defaclacl) a join pg_roles r on r.oid = a.grantee where r.rolname in ('anon', 'authenticated') group by 1, 2, 3;`;
const COLUMN_GRANTS_SQL = `select n.nspname as schema, c.relname as "tableName", a.attname as "columnName", r.rolname as role, x.privilege_type as "privilegeType" from pg_attribute a join pg_class c on c.oid = a.attrelid join pg_namespace n on n.oid = c.relnamespace cross join lateral aclexplode(a.attacl) x join pg_roles r on r.oid = x.grantee where a.attacl is not null and r.rolname in ('anon', 'authenticated');`;
const CRON_SCHEMA_EXISTS_SQL = `select exists (select 1 from pg_namespace where nspname = 'cron') as exists;`;
const CRON_JOBS_SQL = `select j.jobid, j.schedule, j.command, j.nodename, j.database, j.username, j.active, coalesce(r.rolsuper, false) as "isSuperuser" from cron.job j left join pg_roles r on r.rolname = j.username;`;
const DEFINER_FUNCTION_NAMES_SQL = `select p.proname as name from pg_proc p where p.prosecdef = true;`;

// #1280 — the live half of the prod-vs-migration drift comparison (src/scan/supabase-drift.ts).
// Read from pg_class rather than reusing TABLES_SQL because the drift pass needs one extra fact:
// whether an installed extension owns the table (pg_depend deptype 'e'). An extension's own tables
// are legitimately absent from the client's migrations, and without this they read as "someone
// created a table by hand".
const DRIFT_TABLES_SQL = `select n.nspname as schema, c.relname as name, c.relrowsecurity as "rlsEnabled", exists (select 1 from pg_depend d where d.objid = c.oid and d.deptype = 'e') as "extensionOwned" from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind = 'r' and n.nspname = 'public';`;
const DRIFT_POLICIES_SQL = `select schemaname as schema, tablename as "table", policyname as name from pg_policies where schemaname = 'public';`;

// PostgREST config exposes the schema allow-list as `db_schema` (comma-separated).
// MEASURED 2026-07-28 against a live hosted project (operator-authorized read-only Management API
// call, GET /v1/projects/<ref>/postgrest → HTTP 200): the key IS `db_schema` and its value is a
// comma-separated list, e.g. "public,graphql_public". The shape is confirmed, so a `[]` from
// parseExposedSchemas now means the allow-list is genuinely empty, not that the key was misnamed.
// The response ALSO carries the project's `jwt_secret` — extract only what a check needs and never
// put the raw object into a finding's evidence or a scan artifact.
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
  // #1280 — the client repo's supabase/migrations (or the repo root containing it). Supplying it
  // turns on the prod-vs-migration drift comparison; omitting it emits SB-DRIFT-00 as not-assessed
  // rather than leaving the topic out of the report.
  migrationsDir?: string;
}

export function parseExposedSchemas(config: PostgrestConfig): string[] {
  return (config.db_schema ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

// The authoritative pg_graphql signal: it's in `pg_extension` (installed extensions only) WITH a
// non-null version. Never infer this from an HTTP status — pg_graphql returns 200 with an error
// body (`pg_graphql extension is not enabled`) when it's off, which reads as a false positive.
export function hasPgGraphql(extensions: ExtensionInfo[]): boolean {
  return extensions.some((e) => e.name === "pg_graphql" && Boolean(e.installed_version));
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
  for (const entry of readEntriesSafe(functionsDir).entries) {
    if (!entry.isDirectory) continue;
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

async function scanHosted(ref: string, token: string, fetchImpl: typeof fetch, migrations: MigrationFile[], driftReason?: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // #671 — read the auth config first so its enabled-methods signal (external_email_enabled /
  // external_phone_enabled) can gate the password/OTP-specific advisor lints too: on an OAuth-only
  // project the leaked-password advisor is a not-applicable false positive, not an asserted Medium.
  const authConfig = await managementApiGet<AuthConfig>(`/projects/${ref}/config/auth`, token, fetchImpl);
  const authMethods = deriveAuthMethods(authConfig);
  findings.push(...checkAuthConfig(authConfig, authMethods));

  const advisors = await managementApiGet<AdvisorsResponse>(`/projects/${ref}/advisors/security`, token, fetchImpl);
  findings.push(...parseAdvisorFindings(advisors, authMethods));

  const tables = await managementApiQuery<TableInfo[]>(ref, TABLES_SQL, token, fetchImpl);
  findings.push(...checkAutoExposedTables(tables));

  const extensions = await managementApiQuery<ExtensionInfo[]>(ref, EXTENSIONS_SQL, token, fetchImpl);
  findings.push(...checkDangerousExtensions(extensions));

  const buckets = await managementApiQuery<StorageBucket[]>(ref, BUCKETS_SQL, token, fetchImpl);
  const policyRows = await managementApiQuery<{ bucket_id: string; count: number }[]>(ref, BUCKET_POLICY_COUNTS_SQL, token, fetchImpl);
  findings.push(...checkPublicBucketsWithNoPolicies(buckets, bucketPolicyCounts(policyRows)));

  const realtime = await managementApiQuery<{ rlsEnabled: boolean }[]>(ref, REALTIME_MESSAGES_SQL, token, fetchImpl);
  const realtimeInfo: RealtimeMessagesInfo = { exists: realtime.length > 0, rlsEnabled: realtime[0]?.rlsEnabled ?? false };
  findings.push(...checkRealtimeAuthorization(realtimeInfo));

  const published = await managementApiQuery<PublishedTable[]>(ref, REALTIME_PUBLICATION_SQL, token, fetchImpl);
  findings.push(...checkRealtimePublicationRls(published));

  const defaultAclGrants = await managementApiQuery<DefaultAclGrant[]>(ref, DEFAULT_ACL_SQL, token, fetchImpl);
  findings.push(...checkDefaultPrivilegesToClientRoles(defaultAclGrants));

  const columnGrants = await managementApiQuery<ColumnGrant[]>(ref, COLUMN_GRANTS_SQL, token, fetchImpl);
  findings.push(...checkColumnGrantsToClientRoles(columnGrants));

  const cronSchemaExists = await managementApiQuery<{ exists: boolean }[]>(ref, CRON_SCHEMA_EXISTS_SQL, token, fetchImpl);
  if (cronSchemaExists[0]?.exists) {
    const cronJobs = await managementApiQuery<CronJob[]>(ref, CRON_JOBS_SQL, token, fetchImpl);
    const definerFunctions = await managementApiQuery<{ name: string }[]>(ref, DEFINER_FUNCTION_NAMES_SQL, token, fetchImpl);
    findings.push(...checkCronJobs(cronJobs, definerFunctions.map((f) => f.name)));
  }

  const postgrest = await managementApiGet<PostgrestConfig>(`/projects/${ref}/postgrest`, token, fetchImpl);
  const exposedSchemas = parseExposedSchemas(postgrest);
  const pgGraphqlInstalled = hasPgGraphql(extensions);
  findings.push(...checkExposedSchemas(exposedSchemas), ...checkGraphqlIntrospection(pgGraphqlInstalled, exposedSchemas));

  // The two drift reads are skipped entirely when there is no migration history to compare against —
  // no point spending two round trips on a client's project to feed a comparison with no expectation.
  // checkMigrationDrift is still called either way: it owns the SB-DRIFT-00 row in both cases.
  const driftTables = migrations.length > 0 ? await managementApiQuery<DriftLiveTable[]>(ref, DRIFT_TABLES_SQL, token, fetchImpl) : [];
  const driftPolicies = migrations.length > 0 ? await managementApiQuery<DriftLivePolicy[]>(ref, DRIFT_POLICIES_SQL, token, fetchImpl) : [];
  findings.push(...checkMigrationDrift(driftTables, driftPolicies, migrations, driftReason));

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

// Gate 4b (#1330). Local mode runs a strict subset of hosted mode's checks: three of them read the
// hosted platform's own configuration (PostgREST's `db-schema` setting and the Management API's
// auth config), which is not held in Postgres, so a local connection cannot answer their question.
// Returning the shorter list in silence made a locally-scanned project indistinguishable from one
// whose schema exposure and auth config were checked and found clean. The omissions are enumerated
// in CONDITIONAL_SCANS (src/conditional-scan.ts), which fails loud if a fourth one appears or if
// this row stops naming one of them.
function localScopeFinding(): Finding[] {
  return [
    {
      id: "SB-SCOPE-00",
      title: "3 Supabase project-config checks a local-mode scan could not run",
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
      taxonomy: "Coverage — Supabase checks local mode could not run",
      location: "(supabase project config)",
      status: "Open",
      evidence:
        "This scan ran against a local `supabase start` stack over Postgres. Three checks the hosted-mode scan " +
        "runs did not run here: PostgREST-exposed schemas (which non-public schemas the REST API serves to " +
        "clients), GraphQL introspection (whether pg_graphql exposes a queryable schema over that same REST " +
        "surface), and GoTrue auth configuration (auto-confirm, leaked-password protection, OTP expiry, redirect " +
        "allow-list). The first two read PostgREST's `db-schema` setting and the third reads the Management API's " +
        "auth config — both are held by the hosted platform, not in the database, so a local Postgres connection " +
        "cannot read either.",
      impact:
        "The absence of a schema-exposure, GraphQL-introspection or auth-configuration finding in this report " +
        "means those questions were never asked — not that the answers are safe. Counted and named here so the " +
        "gap cannot be read as a clean result.",
      fix:
        "Re-run the Supabase pass in hosted mode against the deployed project (`pnpm exec tsx src/cli/scan.ts " +
        "--supabase <project-ref>`, with a read-only Management API token) to cover these three classes.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}

// #1264. The Splinter lint set arrives as delimited text, so a lint whose detail/metadata/cache_key
// contains the field separator cannot be split back into its 10 columns. Those rows used to be
// dropped by a bare `continue` — no finding, no count, no row — which is the exact silent-omission
// shape the disclosure family exists to prevent. The separator moved to ASCII 0x1F so the collision
// should no longer occur; this row exists because "should no longer" is a claim, and a residual
// drop must be counted rather than assumed away.
function unparsedSplinterFinding(unparsedRows: number): Finding[] {
  if (unparsedRows === 0) return [];
  return [
    {
      id: "SB-SPLINTER-00",
      title: `${unparsedRows} Supabase Advisor lint row(s) this scan could not parse`,
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
      taxonomy: "Coverage — Supabase Advisor lints that could not be parsed",
      location: "(splinter.sql output)",
      status: "Open",
      evidence:
        `${unparsedRows} row(s) of the Supabase Advisor (Splinter) lint output carried the field separator inside ` +
        "a value — a database identifier containing that character — so they could not be split back into their " +
        "ten columns and are absent from the advisor findings below.",
      impact:
        "Those lints were produced by the linter and then lost in transit: the security and performance " +
        "advisories they carried are missing from this report, and their absence is not evidence that the " +
        "underlying objects are clean. Counted and named here so the loss cannot be read as a clean result.",
      fix:
        "Re-run the Supabase pass and report the count above (issue #1264) — the parser's separator needs to " +
        "move to one the affected identifiers do not contain.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}

async function scanLocal(connectionString: string = LOCAL_CONNECTION, splinterImpl: (connectionString: string) => AdvisorsResponse = runSplinter, migrations: MigrationFile[] = [], driftReason?: string): Promise<Finding[]> {
  const { default: postgres } = await import("postgres");
  const sql = postgres(connectionString, { max: 1, idle_timeout: 5 });
  try {
    const tables = (await sql.unsafe(TABLES_SQL)) as unknown as TableInfo[];
    const extensions = (await sql.unsafe(EXTENSIONS_SQL)) as unknown as ExtensionInfo[];
    const buckets = (await sql.unsafe(BUCKETS_SQL)) as unknown as StorageBucket[];
    const policyRows = (await sql.unsafe(BUCKET_POLICY_COUNTS_SQL)) as unknown as { bucket_id: string; count: number }[];
    const realtime = (await sql.unsafe(REALTIME_MESSAGES_SQL)) as unknown as { rlsEnabled: boolean }[];
    const published = (await sql.unsafe(REALTIME_PUBLICATION_SQL)) as unknown as PublishedTable[];
    const defaultAclGrants = (await sql.unsafe(DEFAULT_ACL_SQL)) as unknown as DefaultAclGrant[];
    const columnGrants = (await sql.unsafe(COLUMN_GRANTS_SQL)) as unknown as ColumnGrant[];

    const cronSchemaExists = ((await sql.unsafe(CRON_SCHEMA_EXISTS_SQL)) as unknown as { exists: boolean }[])[0]?.exists ?? false;
    const cronFindings = cronSchemaExists
      ? checkCronJobs(
          (await sql.unsafe(CRON_JOBS_SQL)) as unknown as CronJob[],
          ((await sql.unsafe(DEFINER_FUNCTION_NAMES_SQL)) as unknown as { name: string }[]).map((f) => f.name),
        )
      : [];

    const driftTables = migrations.length > 0 ? ((await sql.unsafe(DRIFT_TABLES_SQL)) as unknown as DriftLiveTable[]) : [];
    const driftPolicies = migrations.length > 0 ? ((await sql.unsafe(DRIFT_POLICIES_SQL)) as unknown as DriftLivePolicy[]) : [];

    const splinterResponse = splinterImpl(connectionString);
    const splinterFindings = parseAdvisorFindings(splinterResponse);

    return [
      ...checkMigrationDrift(driftTables, driftPolicies, migrations, driftReason),
      ...localScopeFinding(),
      ...unparsedSplinterFinding(splinterResponse.unparsedRows ?? 0),
      ...splinterFindings,
      ...dedupeAutoExposed(splinterFindings, checkAutoExposedTables(tables)),
      ...checkDangerousExtensions(extensions),
      ...checkPublicBucketsWithNoPolicies(buckets, bucketPolicyCounts(policyRows)),
      ...checkRealtimeAuthorization({ exists: realtime.length > 0, rlsEnabled: realtime[0]?.rlsEnabled ?? false }),
      ...checkRealtimePublicationRls(published),
      ...checkDefaultPrivilegesToClientRoles(defaultAclGrants),
      ...checkColumnGrantsToClientRoles(columnGrants),
      ...cronFindings,
    ];
  } finally {
    await sql.end();
  }
}

export async function runSupabaseScan(opts: SupabaseScanOptions): Promise<Finding[]> {
  // #1280 — loaded once, before either path, so the two modes compare against the same expectation.
  // With no --migrations there is no expectation to compare against, and the scan says so on its way past
  // rather than returning a finding list in which the topic simply does not appear.
  const migrations = opts.migrationsDir ? loadMigrations(opts.migrationsDir) : [];
  const driftReason = !opts.migrationsDir
    ? "No migrations directory was supplied to this scan (`--migrations <dir>`), so the deployed schema was never compared against the committed migration history."
    : migrations.length === 0
      ? `The migrations path supplied (${opts.migrationsDir}) contains no .sql files, either at it or at its supabase/migrations subdirectory, so there is no expectation to compare the deployed schema against.`
      : undefined;

  let findings: Finding[];
  if (opts.local) {
    findings = await scanLocal(LOCAL_CONNECTION, opts.splinterImpl, migrations, driftReason);
  } else {
    if (!opts.projectRef) throw new Error("runSupabaseScan requires projectRef unless local is set");
    const token = opts.managementApiToken ?? process.env.SUPABASE_ACCESS_TOKEN;
    if (!token) throw new Error("Supabase Management API token required (SUPABASE_ACCESS_TOKEN env var or managementApiToken option)");
    findings = await scanHosted(opts.projectRef, token, opts.fetchImpl ?? fetch, migrations, driftReason);
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
