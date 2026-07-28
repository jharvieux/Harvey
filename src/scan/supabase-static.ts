// Static Supabase-config checks read from COMMITTED files (B13, #71) — no live project needed, so
// these run in the mechanical scan / free-count gate (unlike supabase-config.ts, which scores
// live-fetched Advisor/Management-API inputs at connected tier). Two checks:
//   - checkMigrationRlsStatic: `create table public.X` in supabase/migrations/*.sql with no
//     matching `enable row level security` anywhere — the static path for P-RLS-DISABLED, which
//     was connected-tier only. High precision: both signals are exact DDL, the enable-check is
//     aggregated across the WHOLE migration set (a table enabled in a LATER migration, or a
//     service-only deny-all table with RLS on + zero policies, is cleared), and views are ignored.
//   - checkEdgeFunctionVerifyJwt: `[functions.X] verify_jwt = false` in supabase/config.toml — an
//     Edge Function callable without a valid JWT. Review: a webhook that HMAC-verifies its own
//     payload legitimately disables verify_jwt.
//   - checkMigrationPolicySemantics (#220): the semantic RLS review, run from committed migration
//     SQL instead of live pg_policies. The highest-value bug class (a policy that IS enabled and
//     syntactically fine but keys on the wrong column) lives in `create policy` statements in
//     committed .sql — statically visible, but until now only reachable at connected tier. It also
//     emits SB-RLS-TENANCY-MODEL (#258): one Info record stating the tenancy model it ASSUMED per
//     table, because that inference is a fixed name list and a failed inference is otherwise
//     indistinguishable from a clean result.

import { existsSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { readEntriesSafe, readNamesSafe } from "../fs-walk.js";
import { classifyMigrationSql, type TableDataMapEntry } from "../../tools/pii-classify.mjs";
import { definerReviewFindings } from "../definer-review.js";
import type { Finding } from "../findings.js";
import { parseDefinerFunctions, parseLivePolicies } from "../migration-sql-parse.js";
import { isUsingTrueGated, policyReviewFindings, type LivePolicy, type TenancyModel } from "../rls-policy-review.js";
import { reviewFinding } from "../review-tier.js";
import { mechanicalFinding } from "./common.js";
import { gateOnAuthMethod, type AuthMethods } from "./supabase-config.js";

// #611 — the schema qualifier is OPTIONAL. A no-code Table-Editor export (Lovable/Bolt/v0) emits
// bare `create table workspaces` — public is the implicit default schema — so requiring the literal
// `public.` enumerated zero tables and every RLS-off table in the export stayed invisible. The
// optional first group captures an EXPLICIT schema so the loop can keep only public-schema tables
// (a `create table private.secrets` is not PostgREST-exposed and must not be flagged); a bare name
// has no schema group and defaults to public. ENABLE_RLS is broadened symmetrically so a bare
// `alter table workspaces enable row level security` still clears the bare create.
const CREATE_TABLE = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:([a-z0-9_]+)\.)?([a-z0-9_]+)/gi;
const ENABLE_RLS = /alter\s+table\s+(?:only\s+)?(?:([a-z0-9_]+)\.)?([a-z0-9_]+)\s+enable\s+row\s+level\s+security/gi;

interface CreatedTable {
  name: string;
  file: string; // path relative to the scanned dir
  line: number;
}

// #565 — a Supabase Table-Editor / no-code (Lovable/Bolt/v0) export commits its schema as a single
// root `schema.sql` instead of supabase/migrations/*.sql, so the migrations-only discovery returned
// [] and every RLS-off table in that export was invisible. Read BOTH: every supabase/migrations/*.sql
// AND a root schema.sql. (This M1 static-RLS side only; M2/M10 schema discovery is handled in #574/#529.)
function readRlsSqlSources(dir: string): { file: string; raw: string }[] {
  const out: { file: string; raw: string }[] = [];
  const migrationsDir = join(dir, "supabase", "migrations");
  if (existsSync(migrationsDir)) {
    for (const file of readNamesSafe(migrationsDir).filter((f) => f.endsWith(".sql")).sort()) {
      out.push({ file: relative(dir, join(migrationsDir, file)), raw: readFileSync(join(migrationsDir, file), "utf8") });
    }
  }
  const rootSchema = join(dir, "schema.sql");
  if (existsSync(rootSchema)) out.push({ file: "schema.sql", raw: readFileSync(rootSchema, "utf8") });
  return out;
}

export function checkMigrationRlsStatic(dir: string): Finding[] {
  const sources = readRlsSqlSources(dir);
  if (sources.length === 0) return [];

  const created = new Map<string, CreatedTable>();
  const enabled = new Set<string>();

  for (const { file: rel, raw } of sources) {
    // Strip comments so commented-out DDL (e.g. an "intentionally NO enable RLS" note that quotes
    // the statement it's warning about) can't register as a real create/enable. Keep line count
    // stable by blanking rather than deleting, so the create-site line number stays accurate.
    const sql = raw.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/--[^\n]*/g, "");
    for (const m of sql.matchAll(CREATE_TABLE)) {
      if ((m[1] ?? "public").toLowerCase() !== "public") continue;
      const name = m[2]!.toLowerCase();
      if (!created.has(name)) {
        const line = sql.slice(0, m.index).split("\n").length;
        created.set(name, { name, file: rel, line });
      }
    }
    for (const m of sql.matchAll(ENABLE_RLS)) {
      if ((m[1] ?? "public").toLowerCase() !== "public") continue;
      enabled.add(m[2]!.toLowerCase());
    }
  }

  return [...created.values()]
    .filter((t) => !enabled.has(t.name))
    .map((t) =>
      mechanicalFinding({
        id: `SB-RLS-STATIC-${t.name}`,
        title: `public.${t.name} is created but never gets RLS enabled in any migration`,
        severity: "Critical",
        category: "Supabase config",
        taxonomy: "Migration table without RLS (static)",
        location: `${t.file}:${t.line}`,
        evidence: `create table public.${t.name} has no matching "alter table public.${t.name} enable row level security" anywhere in supabase/migrations/.`,
        impact: "A public-schema table with RLS off is auto-exposed via PostgREST — every row is readable/writable by anyone holding the anon key, with no per-row restriction.",
        fix: "Add `alter table public." + t.name + " enable row level security;` plus policies, or move the table out of the exposed public schema.",
        precisionTier: "high",
      }),
    );
}

// Roles granted BYPASSRLS, and tables whose row security is enabled but not FORCEd. Both are ways a
// correct-looking set of policies is void at runtime.
//
// WHY, and how this gap was found (MEASURED 2026-07-26 against the OWASP Multi-Tenant Application
// Security Cheat Sheet at CheatSheetSeries commit 46f8d04, as an answer key Harvey did not author):
// checkMigrationRlsStatic above catches a table with NO row security. Nothing caught a table that
// has row security and a correct tenant policy but is still readable in full by a privileged role.
// Two distinct shapes:
//
//   BYPASSRLS — per the PostgreSQL documentation, "Superusers and roles with the BYPASSRLS attribute
//   always bypass the row security system when accessing a table." Unconditionally: FORCE ROW LEVEL
//   SECURITY does not constrain it, because FORCE governs the table OWNER. A Supabase service-role
//   key is exactly this role. Granting it to the role an application connects as makes every policy
//   in the schema decorative.
//
//   Missing FORCE — a table owner bypasses row security by default. The cheat sheet flags this
//   ("Force RLS for table owners too (important!)") and its own example gets it right; app schemas
//   frequently do not, and migrations commonly run as the owner.
//
// This is the detector behind the gap we proposed adding to that sheet upstream
// (OWASP/CheatSheetSeries#2309 item 1) — filed because the sheet documents the FORCE line but not
// the BYPASSRLS bypass it does not close.
const BYPASSRLS_ROLE = /(?:create|alter)\s+role\s+([a-z0-9_"]+)([^;]*?)\bbypassrls\b/gi;
const FORCE_RLS = /alter\s+table\s+(?:only\s+)?(?:([a-z0-9_]+)\.)?([a-z0-9_]+)\s+force\s+row\s+level\s+security/gi;
const CREATE_POLICY_ON = /create\s+policy\s+[a-z0-9_"]+\s+on\s+(?:([a-z0-9_]+)\.)?([a-z0-9_]+)/gi;

export function checkMigrationRlsBypass(dir: string): Finding[] {
  const sources = readRlsSqlSources(dir);
  if (sources.length === 0) return [];

  const findings: Finding[] = [];
  const enabled = new Set<string>();
  const forced = new Set<string>();
  const policied = new Set<string>();
  const enabledAt = new Map<string, { file: string; line: number }>();

  for (const { file: rel, raw } of sources) {
    const sql = raw.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/--[^\n]*/g, "");

    for (const m of sql.matchAll(ENABLE_RLS)) {
      if ((m[1] ?? "public").toLowerCase() !== "public") continue;
      const name = m[2]!.toLowerCase();
      enabled.add(name);
      if (!enabledAt.has(name)) enabledAt.set(name, { file: rel, line: sql.slice(0, m.index).split("\n").length });
    }
    for (const m of sql.matchAll(FORCE_RLS)) {
      if ((m[1] ?? "public").toLowerCase() !== "public") continue;
      forced.add(m[2]!.toLowerCase());
    }
    for (const m of sql.matchAll(CREATE_POLICY_ON)) {
      if ((m[1] ?? "public").toLowerCase() !== "public") continue;
      policied.add(m[2]!.toLowerCase());
    }
    for (const m of sql.matchAll(BYPASSRLS_ROLE)) {
      const role = m[1]!.replace(/"/g, "").toLowerCase();
      // `nobypassrls` contains "bypassrls"; the \b in the pattern does not exclude it because the
      // preceding "no" is a word character run, so reject it explicitly.
      if (/\bnobypassrls\b/i.test(m[0])) continue;
      const line = sql.slice(0, m.index).split("\n").length;
      findings.push(
        mechanicalFinding({
          id: `SB-RLS-BYPASSRLS-${role}`,
          title: `Role ${role} is granted BYPASSRLS, which voids every row-level policy for that role`,
          severity: "Critical",
          category: "Supabase config",
          taxonomy: "Role with BYPASSRLS defeats row-level security (static)",
          location: `${rel}:${line}`,
          evidence: `${m[0].trim().replace(/\s+/g, " ")} — in ${rel}.`,
          impact:
            "PostgreSQL documents that roles with BYPASSRLS always bypass row security; FORCE ROW LEVEL SECURITY does not constrain them, because FORCE governs the table owner. Any request served over a connection using this role reads and writes every tenant's rows regardless of the policies defined on the table.",
          fix: `Remove BYPASSRLS from ${role} (\`alter role ${role} nobypassrls;\`) and reserve privileged connections for migrations and administrative jobs. If a code path must use one to serve user requests, it has to re-implement tenant scoping itself, because the database will no longer do it.`,
          precisionTier: "high",
        }),
      );
    }
  }

  // Enabled + has at least one policy, but never FORCEd. Requiring a policy keeps this off tables
  // where RLS-enabled-with-no-policy already denies everything — there the missing FORCE changes
  // nothing, and SB-RLS-STATIC/policy checks own that shape.
  //
  // ONE ROLLED-UP REVIEW-TIER FINDING, NOT ONE PER TABLE — and deliberately not High. MEASURED
  // 2026-07-26 when this was first written per-table at high tier: it fired on 21 of the calibration
  // corpus's tables, i.e. essentially every RLS-enabled table, because almost no schema forces RLS.
  // Two reasons that output would have been wrong:
  //
  //   1. Precision. In a standard Supabase deployment public-schema tables are owned by `postgres`
  //      while PostgREST serves requests as `anon`/`authenticated` — NOT the owner. The owner-bypass
  //      is therefore not on the request path, so a per-table High overstates it. The genuinely
  //      dangerous privileged-role case is BYPASSRLS, caught precisely above (1 hit, 0 false fires,
  //      same run).
  //   2. Volume. 21 new High rows per report is the shape #935 exists to prevent. A disclosed rollup
  //      is the sanctioned answer; demoting a module's band would not be.
  //
  // Review tier, never free-count: whether an owner-role connection reaches runtime is a fact about
  // deployment that migration SQL cannot answer, so this asks rather than asserts.
  const unforced = [...enabled].filter((n) => !forced.has(n) && policied.has(n)).sort();
  if (unforced.length > 0) {
    const first = enabledAt.get(unforced[0]!)!;
    findings.push(
      reviewFinding({
        id: "SB-RLS-NOFORCE-ROLLUP",
        title: `${unforced.length} RLS-enabled table(s) never force row level security, so the owning role bypasses their policies`,
        severity: "Low",
        category: "Supabase config",
        taxonomy: "RLS enabled without FORCE — owner bypasses policies (static)",
        location: `${first.file}:${first.line}`,
        evidence:
          `${unforced.length} table(s) have "enable row level security" and at least one policy but no matching ` +
          `"force row level security" in any migration: ${unforced.join(", ")}.`,
        question:
          "Does any runtime code path connect as the role that OWNS these tables? On a stock Supabase project PostgREST connects as anon/authenticated, which are not the owner, and this is defence-in-depth only. A self-hosted or custom-pooled deployment that connects as the owning role has no row-level isolation on these tables at all.",
        impact:
          "PostgreSQL exempts a table's owner from row security unless FORCE ROW LEVEL SECURITY is set. Where the owning role is used at runtime, every policy listed here holds for non-owner roles only.",
        fix: "Add `alter table public.<table> force row level security;` alongside each enable statement — inert when the owner never serves requests, and closes the gap when it does.",
        okWhen:
          "Runtime access is exclusively through PostgREST as anon/authenticated, or through a role that does not own these tables — the stock hosted-Supabase arrangement. FORCE is then hardening, not a fix.",
        notOkWhen:
          "Any application connection, pooler, migration job or edge function connects as the table-owning role (common in self-hosted deployments and in direct-Postgres access alongside PostgREST) — those paths read and write every tenant's rows.",
      }),
    );
  }

  return findings;
}

// #1182 (cipherx CX-10) — storage buckets and storage.objects read policies declared in COMMITTED
// migration SQL. checkPublicBucketsWithNoPolicies (supabase.ts) reads `select id, name, public from
// storage.buckets` off a live database (connected tier) and the #560 semgrep rule reads
// createBucket(…, {public:true}) in app/seed code; a bucket committed as an INSERT into
// storage.buckets was visible to neither, which is how CX-10 was recorded a mechanical MISS.
//
// Two shapes, both plain text in the migration set:
//   1. `insert into storage.buckets (…, public, …) values (…, true, …)` — Supabase serves every
//      object in a public bucket unauthenticated from /storage/v1/object/public/<bucket>/<path>,
//      and storage.objects RLS does not apply to that path.
//   2. a storage.objects SELECT policy whose grantees include anon/public and whose USING clause
//      names no caller at all — the bucket is private but its read policy is not.
// Review tier, per the issue's "static analysis indicates … confirm live" framing: a deliberately
// public asset bucket (avatars, marketing images) is a legitimate design, and the migration text
// cannot say which one this is.
const STORAGE_BUCKET_INSERT = /insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values/gi;
const CALLER_PREDICATE = /auth\.(uid|jwt|role)\s*\(\)|current_setting\s*\(|\bowner\b/i;
const ANON_ROLE = /^(anon|public)$/;

// The top-level `( … )` groups of a VALUES list, from `after` to the statement's terminating ";".
function valueTuples(sql: string, after: number): string[] {
  const end = sql.indexOf(";", after);
  const list = sql.slice(after, end === -1 ? undefined : end);
  const tuples: string[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < list.length; i++) {
    if (list[i] === "(") {
      if (depth === 0) start = i + 1;
      depth++;
    } else if (list[i] === ")") {
      depth--;
      if (depth === 0 && start >= 0) tuples.push(list.slice(start, i));
    }
  }
  return tuples;
}

export function checkMigrationStorageBuckets(dir: string): Finding[] {
  const sources = readRlsSqlSources(dir);
  if (sources.length === 0) return [];

  const findings: Finding[] = [];
  for (const { file: rel, raw } of sources) {
    const sql = raw.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/--[^\n]*/g, "");
    for (const m of sql.matchAll(STORAGE_BUCKET_INSERT)) {
      const cols = columnDefs(m[1]!).map((c) => c.trim().toLowerCase());
      const publicIdx = cols.indexOf("public");
      if (publicIdx === -1) continue; // no `public` column — Postgres defaults it to false
      const idIdx = cols.indexOf("id") === -1 ? cols.indexOf("name") : cols.indexOf("id");
      for (const tuple of valueTuples(sql, m.index + m[0].length)) {
        const values = columnDefs(tuple).map((v) => v.trim());
        if (!/^true$/i.test(values[publicIdx] ?? "")) continue;
        const bucket = (values[idIdx] ?? "(unnamed)").replace(/'/g, "");
        const line = sql.slice(0, m.index).split("\n").length;
        findings.push(
          mechanicalFinding({
            id: `SB-STORAGE-PUBLIC-BUCKET-${bucket}`,
            title: `Storage bucket "${bucket}" is created public in migration SQL`,
            severity: "High",
            category: "Multi-tenant security",
            taxonomy: "Public storage bucket declared in migration SQL (static)",
            location: `${rel}:${line}`,
            evidence: `insert into storage.buckets sets public = true for "${bucket}" in ${rel}. Supabase serves every object in a public bucket unauthenticated from /storage/v1/object/public/${bucket}/<path>; storage.objects RLS policies do not apply to that path.`,
            impact: `Anyone who learns or guesses an object path reads it — no session, no policy evaluation. If "${bucket}" holds user uploads (documents, identity scans, invoices) rather than public assets, every tenant's files are world-readable by URL.`,
            fix: `Set public = false for "${bucket}" and serve its objects through signed URLs, plus a storage.objects SELECT policy scoping objects to their owner/tenant. Leave it public only if the bucket holds assets that are meant to be served to anonymous visitors.`,
            precisionTier: "review",
            bftb: { value: 5, ease: 4, safety: 3 },
          }),
        );
      }
    }
  }

  for (const p of parseLivePolicies(readMigrations(dir)).policies) {
    if (p.schema.toLowerCase() !== "storage" || p.table.toLowerCase() !== "objects") continue;
    if (p.cmd !== "SELECT" && p.cmd !== "ALL") continue;
    if (!p.roles.some((r) => ANON_ROLE.test(r))) continue;
    // A clause that names the caller at all is the semantic reviewer's business (it already flags
    // "references the caller but binds no row column to auth.uid()"); this rule owns the shape that
    // reviewer stays silent on — a read policy with no caller reference whatsoever.
    if (p.qual === null || CALLER_PREDICATE.test(p.qual)) continue;
    findings.push(
      mechanicalFinding({
        id: `SB-STORAGE-ANON-READ-${p.name}`,
        title: `storage.objects policy ${p.name} grants anonymous read with no owner predicate`,
        severity: "High",
        category: "Multi-tenant security",
        taxonomy: "storage.objects read policy open to anon (static)",
        location: `${p.file}:${p.line} (storage.objects.${p.name})`,
        evidence: `Policy ${p.name} is FOR ${p.cmd} TO ${p.roles.join(", ")} with USING (${p.qual.trim()}) — the clause narrows the bucket but never references the caller (auth.uid()/auth.jwt()/owner), so every object it covers is readable by an unauthenticated holder of the anon key.`,
        impact: "Storage is a separate door onto tenant data. A private bucket whose SELECT policy is open to anon leaks every object in it — the PostgREST/RLS results say nothing about this surface.",
        fix: `Scope the policy to the object's owner or tenant (e.g. USING (bucket_id = '…' and (storage.foldername(name))[1] = auth.uid()::text)), or grant it TO authenticated only if every signed-in user is genuinely entitled to every object.`,
        precisionTier: "review",
        bftb: { value: 5, ease: 4, safety: 4 },
      }),
    );
  }

  return findings;
}

// Tenant-key column names, in preference order. At connected tier the operator DECLARES the
// tenancy model (`--tenant-key`); source-only there's nobody to ask, so it's inferred — UNLESS
// the same override is supplied here too (#280; see TenancyOverride below).
const TENANT_KEY_CANDIDATES = ["tenant_id", "org_id", "organization_id", "workspace_id", "account_id", "company_id"];

// #280 — the same declaration shape detect-deeper.ts already accepts (`--tenant-key`/
// `--tenant-mode`), threaded down to the static reviewer instead of only the connected tier. A
// column name only, validated before use since it lands in a RegExp built from it.
export interface TenancyOverride {
  tenantKey?: string;
  mode?: "per-tenant" | "per-user";
}

const VALID_COLUMN_NAME = /^[a-z0-9_]+$/i;

// Inferred PER TABLE, not per app. A real multi-tenant app is a mix: tenant-scoped data tables
// (notes.tenant_id) alongside per-user own-row tables (profiles keyed id = auth.uid(), the
// standard one-folder-per-user storage pattern). Judging the whole app against one model flags
// every correct own-row policy — the #206 FP, which per-user mode only solved for apps that are
// per-user end to end. A table is per-tenant only if it actually DECLARES a tenant column;
// otherwise a row bound to auth.uid() is the isolation boundary, and reviewPolicy is told so.
//
// A table this parser never saw declared (storage.objects and other system tables) falls through
// to per-user for the same reason: we have no evidence of a tenant column, and inventing one
// would manufacture findings against policies we cannot see the schema for.
//
// `override` (#280) lets the operator DECLARE the convention instead of leaving it to inference:
// `--tenant-mode per-user` forces every table to per-user (a genuinely single-tenant app, no
// column to find); `--tenant-key <col>` is tried per table AHEAD of the built-in list, so a table
// that declares it reviews per-tenant on it while tables that don't still fall through exactly as
// before — the per-table mix above is preserved, not replaced by one global model.
function inferTenancyModel(sql: string, table: string | undefined, override?: TenancyOverride): TenancyModel {
  if (override?.mode === "per-user") return { tenantKey: "", mode: "per-user" };
  const body = table ? tableBody(sql, table) : sql;
  if (body === null) return { tenantKey: "", mode: "per-user" };
  const declared = override?.tenantKey && VALID_COLUMN_NAME.test(override.tenantKey) ? override.tenantKey : undefined;
  const candidates = declared ? [declared, ...TENANT_KEY_CANDIDATES] : TENANT_KEY_CANDIDATES;
  const key = candidates.find((c) => new RegExp(`[(,\\n]\\s*${c}\\s+\\w`, "i").test(body));
  return key ? { tenantKey: key } : { tenantKey: "", mode: "per-user" };
}

// Columns that name a row's OWNER or its own identity — per-user by design, not a missed tenant
// key. Excluded from the unrecognised-scope report below so the honest per-user tables
// (profiles.id, notes.user_id) don't drown the one table that actually uses an off-list convention.
const OWNER_COLUMNS = /^(id|user_id|owner_id|created_by|updated_by|author_id|profile_id)$/i;
const SCOPE_COLUMN = /[(,\n]\s*([a-z0-9_]*_id)\s+\w/gi;

// Tables whose NAME marks them as the tenant/org/account root. A bare column (no `_id` suffix,
// off the known tenant-key list) that FOREIGN-KEYs to one of these is the one precision-preserving
// widening of the scope-column scan (#301): the FK to a tenant-shaped table is structural evidence
// it is the tenant key under an off-list name, so we can name it WITHOUT widening the name match —
// which would flood ordinary schemas, since nearly any column is a name candidate. An FK to any
// other table (a `city → cities` lookup, a `plan → plans` catalog) is an ordinary relation and
// stays silent. Deliberately tight: only names that are unambiguously a tenancy root.
const TENANT_TABLE = /^(tenants?|orgs?|organi[sz]ations?|accounts?|workspaces?|companies|company)$/i;

// Split a `create table (...)` body into its top-level, comma-separated column/constraint defs so
// each can be inspected in isolation. `body` still carries the opening "(" from tableBody; strip it
// so the outer paren doesn't hold depth at 1 forever and suppress every split.
function columnDefs(body: string): string[] {
  const s = body.replace(/^\s*\(/, "");
  const defs: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === "," && depth === 0) {
      defs.push(s.slice(start, i));
      start = i + 1;
    }
  }
  defs.push(s.slice(start));
  return defs;
}

// The [column, referencedTable] a column/constraint def foreign-keys to, or null. Handles both the
// inline form (`site uuid references public.tenants (id)`) and the table-level constraint
// (`foreign key (site) references public.tenants (id)`).
function foreignKeyOf(def: string): [string, string] | null {
  const ref = /\breferences\s+(?:"?\w+"?\.)?"?([a-z0-9_]+)"?/i.exec(def);
  if (!ref) return null;
  const constraint = /\bforeign\s+key\s*\(\s*"?([a-z0-9_]+)"?/i.exec(def);
  const column = constraint ? constraint[1]! : def.trim().split(/\s+/)[0]!;
  return [column.toLowerCase(), ref[1]!.toLowerCase()];
}

// A per-user table's scoping columns that the review did NOT recognise, so a reader can falsify the
// per-user verdict. Two structural signals, both narrow enough to stay quiet on ordinary schemas:
// a `*_id`-suffixed column (#258), and — #301 — a bare column that foreign-keys to a tenant-shaped
// table. Owner columns and the known tenant keys are dropped: the first is per-user by design, the
// second would have made the table per-tenant and never reached here.
function unrecognisedScopeColumns(sql: string, table: string): string[] {
  const body = tableBody(sql, table);
  if (body === null) return [];
  const idCols = [...body.matchAll(SCOPE_COLUMN)].map((m) => m[1]!.toLowerCase());
  const fkCols = columnDefs(body)
    .map(foreignKeyOf)
    .filter((fk): fk is [string, string] => fk !== null && TENANT_TABLE.test(fk[1]))
    .map(([col]) => col);
  return [...new Set([...idCols, ...fkCols].filter((c) => !OWNER_COLUMNS.test(c) && !TENANT_KEY_CANDIDATES.includes(c)))];
}

// #258 — the tenant-key inference is a fixed 6-name list, so an app using `site_id` reviews every
// table in per-user mode and the misses are INVISIBLE: silence from a failed inference reads
// exactly like "clean". This reports what was assumed per table so a reader can falsify it, and
// names the tables whose scoping column we did not recognise. Info-tier: an assumption made
// visible is not itself a vulnerability, and this must never inflate a finding count.
function tenancyModelFinding(models: Map<string, TenancyModel>, unrecognised: Map<string, string[]>): Finding {
  const perTenant = [...models].filter(([, m]) => m.mode !== "per-user");
  const perUser = [...models].filter(([, m]) => m.mode === "per-user");
  const suspect = perUser.map(([t]) => [t, unrecognised.get(t) ?? []] as const).filter(([, cols]) => cols.length > 0);

  const assumed = perTenant.length > 0 ? perTenant.map(([t, m]) => `${t} → per-tenant on "${m.tenantKey}"`).join("; ") : "(none — no table declared a recognised tenant column)";
  const owned = perUser.length > 0 ? perUser.map(([t]) => t).join(", ") : "(none)";
  const unknown = suspect.length > 0 ? suspect.map(([t, cols]) => `${t} (declares ${cols.join(", ")})`).join("; ") : "";

  return mechanicalFinding({
    id: "SB-RLS-TENANCY-MODEL",
    title: "Tenancy model assumed by the static RLS review",
    severity: "Info",
    category: "Multi-tenant security",
    taxonomy: "M1 — Multi-tenant security",
    location: "supabase/migrations/",
    evidence:
      `The static policy review inferred tenancy PER TABLE by looking for one of the known tenant-key columns (${TENANT_KEY_CANDIDATES.join(", ")}). ` +
      `Reviewed as per-tenant: ${assumed}. Reviewed as per-user (no recognised tenant column — a row bound to auth.uid() is treated as the isolation boundary): ${owned}.` +
      (unknown
        ? ` NOT RECOGNISED — these tables declare a scoping column that is not on the known list, so they were reviewed as per-user and any cross-tenant policy bug in them WAS NOT LOOKED FOR: ${unknown}.`
        : "") +
      // #281 / #301 — the NOT RECOGNISED scan names a column on two structural signals: a "*_id"
      // suffix (#258), or a bare column that foreign-keys to a tenant-shaped table (#301). A bare
      // tenant column with NEITHER — an off-list name like "tenant"/"site"/"region_slug" and no FK
      // to a tenant table — is still reviewed as per-user and never appears above. Stated rather
      // than silently left, per #281's acceptance criteria. Worded to avoid the literal phrase "NOT
      // RECOGNISED" so it can't be mistaken for another entry in that list by a reader (or a test)
      // scanning for the marker.
      ` Coverage note: the scoping-column scan above names a column when it ends in "_id" OR is a foreign key to a tenant-shaped table (tenants/orgs/accounts/workspaces/companies). A bare tenant column with NEITHER signal — an off-list name (e.g. "tenant", "site", "region_slug") and no FK to a tenant table — is still reviewed as per-user and will not be named. An empty list above is not proof that no such column exists.`,
    impact:
      "This is the review's central assumption, not a defect. If a table listed as per-user is really tenant-scoped under a name the list does not know (e.g. site_id), its policies were judged against the wrong model and cross-tenant findings were silently missed — a failed inference is indistinguishable from a clean result unless it is stated.",
    // #280 — this used to point only at the connected tier ("buy the paid tier to fix it"). The
    // same declaration is now accepted right here at the free tier: --tenant-key is tried ahead of
    // the built-in list for every table, so a table that has it reviews per-tenant on it while
    // tables that don't still fall through to per-user exactly as before.
    fix: "Confirm the assumed model above. If a table is tenant-scoped under a column not listed, re-run this scan with `--tenant-key <column>` (quick-scan / mechanical scan, or detect-deeper at the connected tier) — the reviewer uses the declared column for any table that has it instead of guessing from the built-in list. Use `--tenant-mode per-user` instead if the app is genuinely single-tenant end to end. Until re-run, treat the per-user verdict for any unlisted table as not assessed.",
    precisionTier: "review",
    bftb: { value: 1, ease: 5, safety: 5 },
  });
}

// #338 — usingTrueReview SPARES `USING (true)` on a table with no recognised tenant key, which is
// what protects the intentional public-catalog case (a published price list). But a spared policy
// returns null exactly like a correct one, so a genuinely leaky reference-shaped table is silent in
// the same way a catalog is: nothing separates "assessed and cleared" from "not assessable". This
// names every table where a `USING (true)` was spared for want of a tenant key, so a reader can
// confirm the sparing rather than infer safety from the absence of a finding. Info + review tier:
// an assumption disclosure, never graded and never in the free count (same contract as #258's
// SB-RLS-TENANCY-MODEL, one level down).
function usingTrueUnassessedFinding(spared: Map<string, string[]>): Finding {
  const list = [...spared].map(([t, names]) => `${t} (${names.join(", ")})`).join("; ");
  return mechanicalFinding({
    id: "SB-RLS-USING-TRUE-UNASSESSED",
    title: "USING (true) policies left unassessed — no recognised tenant key to judge them against",
    severity: "Info",
    category: "Multi-tenant security",
    taxonomy: "M1 — Multi-tenant security",
    location: "supabase/migrations/",
    evidence:
      `These policies open every row of their table (USING is "true") on a table that declares no recognised tenant key, so the tenant-scoped USING(true) rule did NOT assess them — an intentional public/reference table (a catalog) and a genuine cross-user leak look identical here, and only a declared tenant key would let the rule tell them apart. Named so the sparing can be checked rather than read as clean from the absence of a finding: ${list}.`,
    impact:
      "This is an assumption disclosure, not a defect. A spared USING(true) may be a correct world-readable catalog OR a reference-shaped table that is actually leaking rows across users — the static review cannot decide without a tenant key, and silence here is not evidence of safety.",
    fix:
      "Confirm each table above is intentionally world-readable (a published catalog/reference list). If it is really tenant- or owner-scoped under a column the review did not recognise, re-run with `--tenant-key <column>` so the USING(true) rule assesses it instead of sparing it.",
    precisionTier: "review",
    bftb: { value: 1, ease: 5, safety: 5 },
  });
}

// #1183 (supatest F9) — the M1↔M10 join that turns a SPARED `USING (true)` SELECT into an asserted
// finding. The spare itself is the correct precision call and stays: a world-readable catalog (a
// published price list) and a leaking per-user table are the same text, and without a tenant key
// the reviewer cannot tell them apart. What it cannot see is that another module ALREADY decided —
// M10 classifies the same table's columns from the same migration SQL, and on supatest's `profiles`
// it returned EMAIL. A USING(true) SELECT over that is an email breach, not an open question.
//
// The gate is deliberately NOT "the table appears in the data map". MEASURED 2026-07-27 against
// targets/calibration: the map classifies `plans.name` and `cities.name` as low-confidence NAME?
// and `notes.body`/`documents.body` as FREE_TEXT_REVIEW — a public catalog's product name IS a
// name, so any-hit would upgrade exactly the case the spare protects. The qualifying signal is a
// column M10 is CONFIDENT about (an unambiguous direct identifier: email, SSN, phone) or one in a
// regulated category, where even a medium-confidence hit is worth asserting.
const REGULATED_CATEGORIES = new Set(["SENSITIVE_PII", "PHI", "PCI", "SECRET"]);

function personalDataColumns(entry: TableDataMapEntry | undefined): TableDataMapEntry["columns"] {
  return (entry?.columns ?? []).filter((c) => c.confidence === "high" || REGULATED_CATEGORIES.has(c.category));
}

function usingTruePiiFinding(
  table: string,
  policies: string[],
  entry: TableDataMapEntry,
  personal: TableDataMapEntry["columns"],
  location: string,
): Finding {
  const columns = personal.map((c) => `${c.column} (${c.infotype})`).join(", ");
  return mechanicalFinding({
    id: `SB-RLS-USING-TRUE-PII-${table}`,
    title: `World-readable policy on ${table}, which M10 classified as holding personal data`,
    severity: "High",
    category: "Multi-tenant security",
    taxonomy: "USING(true) read policy on an M10-classified PII table (static)",
    location,
    evidence: `${policies.length > 1 ? "Policies" : "Policy"} ${policies.join(", ")} on public.${table} read with USING (true), so every row is in scope for every caller the policy applies to — including anon, unless a role restriction narrows it. The table declares no recognised tenant key, which normally leaves this shape SPARED as an unassessed catalog; M10's classification of the same migration SQL says it is not a catalog: ${columns} (${entry.categories.join("/")}, data score ${entry.severityScore}).`,
    impact: `Every row of ${table} — including ${personal.map((c) => c.column).join(", ")} for every user — is readable by anyone the policy admits. This is the shape that reads as "no findings" when the two signals are looked at separately: the policy review spares it for want of a tenant key, and the data map records the columns without knowing who can read them.`,
    fix: `Confirm public.${table} is genuinely meant to be world-readable. If it is not, replace USING (true) with an owner or tenant predicate (e.g. USING (id = auth.uid()) for a per-user table), and re-run with \`--tenant-key <column>\` if the table is tenant-scoped under a name the review does not recognise.`,
    precisionTier: "review",
    bftb: { value: 5, ease: 4, safety: 4 },
  });
}

// The column list of `create table [schema.]<table> ( … )`, or null if this SQL never declares it.
function tableBody(sql: string, table: string): string | null {
  const m = new RegExp(`create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?(?:\\w+\\.)?${table}\\s*\\(`, "i").exec(sql);
  if (!m) return null;
  const open = sql.indexOf("(", m.index);
  const end = sql.indexOf(");", open);
  return sql.slice(open, end === -1 ? undefined : end);
}

function readMigrations(dir: string): { file: string; sql: string }[] {
  const migrationsDir = join(dir, "supabase", "migrations");
  if (!existsSync(migrationsDir)) return [];
  return readNamesSafe(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => ({ file: relative(dir, join(migrationsDir, f)), sql: readFileSync(join(migrationsDir, f), "utf8") }));
}

// Semantic RLS review over committed migration SQL (#220) — the source-tier path to the class the
// public sweep proved matters most (a self-join INSERT policy, an unscoped invite UPDATE): both
// were plain `create policy` text, findable with no DB.
//
// Deliberately NOT a second copy of the review logic. parsePolicies extracts the same
// {cmd, qual, withCheck} struct the live pg_policies pull produces, and the EXISTING reviewer
// (rls-policy-review.ts) judges it — one semantic rule set, two feeds. Findings stay at review
// tier: static text can show a policy's shape but never how it behaves against real data, so
// these surface as free-tier INDICATORS (#227), never graded.
export function checkMigrationPolicySemantics(dir: string, tenancyOverride?: TenancyOverride): Finding[] {
  const migrations = readMigrations(dir);
  if (migrations.length === 0) return [];

  const allSql = migrations.map((m) => m.sql).join("\n");
  const byTable = new Map<string, LivePolicy[]>();
  const sites = new Map<string, string>(); // schema.table.name -> file:line
  const findings: Finding[] = [];

  // #937 — review the policies LIVE at the end of history, not every `create policy` ever written.
  // parseLivePolicies drops a policy a later migration DROPs and keeps the final definition of a
  // re-created one, so a correctly-fixed schema no longer reports the broken policy it replaced.
  const { policies: live, unparsed } = parseLivePolicies(migrations);
  for (const p of live) {
    const forTable = byTable.get(p.table) ?? [];
    forTable.push(p);
    byTable.set(p.table, forTable);
    sites.set(`${p.schema}.${p.table}.${p.name}`, `${p.file}:${p.line}`);
  }
  // Fail loud: a policy we couldn't read is reported as unread. Dropping it would make a failed
  // parse indistinguishable from a clean policy, which is how a scanner lies by omission.
  for (const u of unparsed) {
    findings.push(
      reviewFinding({
        id: `SB-RLS-POLICY-UNPARSED-${u.table}-${u.name}`,
        title: `RLS policy ${u.schema}.${u.table}.${u.name} could not be read from migration SQL`,
        severity: "Medium",
        category: "Multi-tenant security",
        taxonomy: "M1 — Multi-tenant security",
        location: u.file,
        evidence: `${u.reason}. The static reviewer could not evaluate this policy, so its absence from the results above means "not assessed", NOT "clean".`,
        question: "Does this policy restrict every row it exposes or accepts to the caller's own tenant?",
        impact: "An unreviewed policy is an unknown: it may be the one that lets another tenant read or write these rows.",
        fix: "Review this policy by hand, or run the connected-tier scan, which reads the live policy from the database instead of parsing SQL.",
        okWhen: "Manual review confirms the policy constrains rows to the caller's own tenant.",
        notOkWhen: "The policy keys on a non-tenant column or under-constrains writes.",
      }),
    );
  }

  // Re-locate each review finding from `schema.table.policy` to its migration file:line — at
  // source tier the file is the actionable address, and location is never gated (anti-shakedown).
  // ids are re-keyed off the policy site because policyReviewFindings numbers its findings per
  // call, and it's called once per table here.
  const models = new Map<string, TenancyModel>();
  const unrecognised = new Map<string, string[]>();
  const usingTrueSpared = new Map<string, string[]>(); // table -> policy names whose USING(true) went unassessed (#338)
  // #1183 — M10's classification of the SAME migration SQL, read here so a spare can be overruled
  // by what the table actually holds. Same static feed dry-run.ts's M10 phase uses; no live tier.
  const dataMap = classifyMigrationSql(allSql).dataMap;
  for (const [table, policies] of byTable) {
    const model = inferTenancyModel(allSql, table, tenancyOverride);
    models.set(table, model);
    if (model.mode === "per-user") {
      unrecognised.set(table, unrecognisedScopeColumns(allSql, table));
      const spared = policies.filter(isUsingTrueGated);
      const personal = personalDataColumns(dataMap[table]);
      if (spared.length > 0 && personal.length > 0 && tenancyOverride?.mode !== "per-user") {
        // Asserted, so it must NOT also appear in the unassessed disclosure — it was assessed.
        findings.push(
          usingTruePiiFinding(table, spared.map((p) => p.name), dataMap[table]!, personal, sites.get(`${spared[0]!.schema}.${table}.${spared[0]!.name}`) ?? "supabase/migrations/"),
        );
      } else if (spared.length > 0) {
        usingTrueSpared.set(table, spared.map((p) => p.name));
      }
    }
    for (const f of policyReviewFindings(policies, model)) {
      const site = sites.get(f.location);
      const id = `SB-RLS-POLICY-${f.location}`;
      findings.push(site ? { ...f, id, location: `${site} (${f.location})` } : { ...f, id });
    }
  }
  if (models.size > 0) findings.push(tenancyModelFinding(models, unrecognised));
  // #338 — only when the model was INFERRED per-user (no tenant key found), not when the operator
  // DECLARED per-user globally: --tenant-mode per-user is an assertion, not an unassessed silence.
  if (usingTrueSpared.size > 0 && tenancyOverride?.mode !== "per-user") findings.push(usingTrueUnassessedFinding(usingTrueSpared));
  return findings;
}

// Postgres grants EXECUTE on a new function to PUBLIC unless it is revoked, and Supabase's
// anon/authenticated roles inherit that — so a migration that never mentions grants still exposes
// the function to the client. Same assumption dry-run.ts makes from the same static feed; it is
// stated in the evidence below rather than presented as a verified grant, because an app's own
// migrations are not where Supabase's platform grants necessarily live.
const ASSUMED_DEFAULT_FUNCTION_EXPOSURE = ["anon", "authenticated"];

// A `revoke execute on function <name> ... from <role>` for THIS function — the one static signal
// that contradicts the PUBLIC-grant default above. Only the roles a client can actually hold
// matter; a revoke from some other role leaves the function client-reachable.
function revokedFromClient(sql: string, name: string): boolean {
  const revoke = new RegExp(`revoke\\s+execute\\s+on\\s+function\\s+[\\w.]*\\b${name}\\s*\\([^)]*\\)\\s*from\\s+([^;]+);`, "i").exec(sql);
  return revoke !== null && /\b(anon|authenticated|public)\b/i.test(revoke[1]!);
}

// SECURITY DEFINER caller-authorization review over committed migration SQL (#264) — the source-
// tier feed for the class definer-review.ts already adjudicates live (detect-deeper.ts's
// pg_get_functiondef pull). Same arrangement as checkMigrationPolicySemantics above: parse-
// DefinerFunctions extracts the same {name, argNames, body} struct the live query produces, and
// the EXISTING reviewer judges it — one rule set, two feeds, no second copy of the logic.
//
// P-SECDEF-PRIV-WRITE-NOAUTH (b16-storage-secdef.entries.ts) was filed as an LLM-tier miss on the
// grounds that function-body semantics need semantic reasoning. That was true of the CLASSIFIER's
// job (is this function's exposure intended?) but not of this one: needsAuthzReview asks only
// whether a privileged write runs with no auth.uid()/auth.jwt() anywhere in the body — a textual
// fact. It clears promote_to_admin_checked (which does check the caller) and flags
// promote_to_admin (which does not), which is exactly the pair the corpus plants.
export function checkMigrationDefinerAuthz(dir: string): Finding[] {
  const migrations = readMigrations(dir);
  const findings: Finding[] = [];

  for (const { file, sql } of migrations) {
    const parsed = parseDefinerFunctions(sql).filter((fn) => !revokedFromClient(sql, fn.name));
    const byName = new Map(parsed.map((fn) => [`${fn.schema}.${fn.name}`, fn]));
    const reviewable = parsed.map((fn) => ({ ...fn, exposedTo: ASSUMED_DEFAULT_FUNCTION_EXPOSURE }));

    for (const f of definerReviewFindings(reviewable)) {
      // Re-key off the function rather than definerReviewFindings' per-call index, and re-locate
      // to file:line: at source tier the migration file is the actionable address. The parameter
      // list stays in the address because Postgres permits overloads — `promote(uuid)` and
      // `promote(uuid, text)` are different functions, and one may be gated where the other isn't.
      const fn = byName.get(f.location)!;
      const signature = `${f.location}(${fn.argNames.join(", ")})`;
      const at = sql.toLowerCase().indexOf(`function ${f.location.toLowerCase()}`);
      const line = at >= 0 ? sql.slice(0, at).split("\n").length : 1;
      findings.push({ ...f, id: `SB-DEFINER-AUTHZ-${signature}`, location: `${file}:${line} (${signature})` });
    }
  }
  return findings;
}

// #602 (cipherx CX-12) — plpgsql dynamic-SQL injection over committed migration SQL. A function body
// that builds a query with `EXECUTE` and CONCATENATES a declared parameter (`|| p_query ||`) or
// interpolates one with format()'s `%s` placeholder is classic CWE-89: the parameter is spliced into
// the SQL text unescaped. The safe forms — quote_literal()/quote_ident() around the param, or
// format() with `%L` (literal) / `%I` (identifier) — are explicitly cleared. Runs over ALL functions,
// not just SECURITY DEFINER (a plain function is injectable too), but a DEFINER function is called out
// as higher-impact (it runs as the owner, bypassing RLS). Review tier: static text shows the concat
// shape; whether the param is genuinely attacker-reachable is confirmed at the connected/semantic tier.
const CREATE_FUNCTION = /create\s+(?:or\s+replace\s+)?function\s+(?:(\w+)\.)?(\w+)\s*\(([^)]*)\)([\s\S]*?)as\s+\$(\w*)\$([\s\S]*?)\$\5\$/gi;
const EXECUTE_KW = /\bexecute\b/i;

function functionArgNames(argsRaw: string): string[] {
  return argsRaw
    .split(",")
    .map((a) => a.trim())
    .filter(Boolean)
    // drop a leading arg-mode keyword (in/out/inout/variadic) so `in p_query text` yields `p_query`.
    .map((a) => a.replace(/^(in|out|inout|variadic)\s+/i, "").split(/\s+/)[0]!)
    .filter((n) => /^[a-z_][a-z0-9_]*$/i.test(n));
}

// The QUERY-STRING part of each `EXECUTE` — the text from the `execute` keyword up to the bound-
// parameter clause (`USING`/`INTO`) or the statement end. Scoping to this range is what keeps the
// SAFE parameterized form clear: `EXECUTE '… where x = $1' USING '%' || p || '%'` concatenates the
// param into the USING *value* (bound, not spliced into SQL text), which lands AFTER `using` and so
// is excluded — only a concat inside the query string itself is injection.
function executeQueryStrings(body: string): string[] {
  const out: string[] = [];
  const re = /\bexecute\b/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const rest = body.slice(m.index + m[0].length);
    const end = rest.search(/\b(using|into)\b|;/i);
    out.push(end >= 0 ? rest.slice(0, end) : rest);
  }
  return out;
}

// A parameter concatenated raw into an EXECUTE query string — `|| p` or `p ||` — not wrapped in a
// safe escaper (quote_literal/quote_ident). Also the format() `%s` interpolation of the param
// (unsafe for SQL; %L/%I are the safe placeholders).
function unsafeDynamicParam(queryStrings: string[], param: string): boolean {
  const p = param.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return queryStrings.some((q) => {
    if (new RegExp(`quote_(literal|ident)\\s*\\(\\s*${p}\\b`, "i").test(q)) return false;
    const concatenated = new RegExp(`\\|\\|\\s*${p}\\b`, "i").test(q) || new RegExp(`\\b${p}\\s*\\|\\|`, "i").test(q);
    const formatUnsafe = /\bformat\s*\(/i.test(q) && /%s/.test(q) && new RegExp(`\\b${p}\\b`, "i").test(q) && !/%[LI]/.test(q);
    return concatenated || formatUnsafe;
  });
}

export function checkMigrationDynamicSqlInjection(dir: string): Finding[] {
  const findings: Finding[] = [];
  for (const { file, sql } of readMigrations(dir)) {
    const clean = sql.replace(/--[^\n]*/g, "");
    for (const m of clean.matchAll(CREATE_FUNCTION)) {
      const schema = m[1] ?? "public";
      const name = m[2]!;
      const decl = m[4] ?? "";
      const body = m[6] ?? "";
      if (!EXECUTE_KW.test(body)) continue;
      const params = functionArgNames(m[3]!);
      const queryStrings = executeQueryStrings(body);
      const injected = params.filter((p) => unsafeDynamicParam(queryStrings, p));
      if (injected.length === 0) continue;
      const isDefiner = /security\s+definer/i.test(decl);
      const at = clean.toLowerCase().indexOf(`function ${schema.toLowerCase()}.${name.toLowerCase()}`);
      const line = at >= 0 ? clean.slice(0, at).split("\n").length : 1;
      findings.push(
        mechanicalFinding({
          id: `SB-PLPGSQL-SQLI-${schema}.${name}`,
          title: `Function ${schema}.${name} builds dynamic SQL by concatenating a parameter (SQL injection)`,
          severity: "Critical",
          category: "Injection",
          taxonomy: "plpgsql dynamic SQL injection (static)",
          location: `${file}:${line} (${schema}.${name})`,
          evidence: `EXECUTE in ${schema}.${name} splices the parameter(s) ${injected.join(", ")} into the dynamic query by string concatenation (|| / format %s) with no quote_literal/quote_ident/%L/%I escaping${isDefiner ? " — and the function is SECURITY DEFINER, so the injected query runs as the owner, bypassing RLS" : ""}. CWE-89.`,
          impact: "A caller controls the SQL text: they can read, modify, or drop any data the function's role can reach (for a SECURITY DEFINER function, that is the table owner's full access, bypassing RLS).",
          fix: "Never concatenate a parameter into EXECUTE. Use parameterized dynamic SQL (`EXECUTE '… where col = $1' USING p`), or quote_literal()/quote_ident() / format() with %L/%I for identifiers and literals.",
          precisionTier: "review",
          bftb: { value: 5, ease: 3, safety: 4 },
        }),
      );
    }
  }
  return findings;
}

// #602 (cipherx CX-11) — a SECURITY DEFINER function EXPLICITLY `grant execute … to anon`/`to public`
// that returns/reads data with no caller-authorization check. checkMigrationDefinerAuthz only flags
// privileged WRITES (needsAuthzReview), so a definer function that merely DUMPS data (get_user_by_email,
// search_lab_data, export_demo_secrets) reachable by the UNAUTHENTICATED anon role fell through. An
// explicit anon grant is a stronger signal than the PUBLIC-default inference: the app deliberately
// exposed a bypass-RLS reader to anon. Scoped to anon/public (an `authenticated` grant is normal for a
// user-facing RPC), to data-returning functions (not triggers/void), and to functions with no
// auth.uid()/auth.jwt() caller check — so a legitimately anon-scoped reader that checks its caller is
// cleared, and the write case stays with the authz pass (no double-report). Review tier.
const DEFINER_CALLER_AUTH = /auth\.(uid|jwt)\s*\(\)/i;
const PRIVILEGED_WRITE_BODY = /\b(update|insert\s+into|delete\s+from|grant)\b/i;
const RETURNS_DATA = /returns\s+(setof|table|record)\b/i;

function grantedToAnon(sql: string, name: string): boolean {
  const grant = new RegExp(`grant\\s+execute\\s+on\\s+function\\s+[\\w.]*\\b${name}\\s*\\([^)]*\\)\\s*to\\s+([^;]+);`, "i").exec(sql);
  return grant !== null && /\b(anon|public)\b/i.test(grant[1]!);
}

export function checkMigrationDefinerAnonGrant(dir: string): Finding[] {
  const findings: Finding[] = [];
  for (const { file, sql } of readMigrations(dir)) {
    for (const fn of parseDefinerFunctions(sql)) {
      if (!grantedToAnon(sql, fn.name)) continue;
      // The write case is the authz pass's job; here we surface the READ/dump case it misses.
      if (PRIVILEGED_WRITE_BODY.test(fn.body)) continue;
      // A definer reader that checks its caller (auth.uid()/auth.jwt()) can be legitimately anon-scoped.
      if (DEFINER_CALLER_AUTH.test(fn.body)) continue;
      // Only a data-returning function is a dump risk — the function's signature (before `as $$`) must
      // declare it returns rows. The full declaration text precedes the body in the SQL.
      const declStart = sql.toLowerCase().indexOf(`function ${fn.schema.toLowerCase()}.${fn.name.toLowerCase()}`);
      const decl = declStart >= 0 ? sql.slice(declStart, sql.indexOf(fn.body, declStart)) : "";
      if (!RETURNS_DATA.test(decl) && !/\breturn\s+query\b/i.test(fn.body) && !/\bselect\b/i.test(fn.body)) continue;
      const at = sql.toLowerCase().indexOf(`function ${fn.schema.toLowerCase()}.${fn.name.toLowerCase()}`);
      const line = at >= 0 ? sql.slice(0, at).split("\n").length : 1;
      const signature = `${fn.schema}.${fn.name}(${fn.argNames.join(", ")})`;
      findings.push(
        mechanicalFinding({
          id: `SB-DEFINER-ANON-GRANT-${signature}`,
          title: `SECURITY DEFINER ${fn.schema}.${fn.name} is granted to anon and reads data with no caller check`,
          severity: "High",
          category: "Multi-tenant security",
          taxonomy: "SECURITY DEFINER granted to anon (static)",
          location: `${file}:${line} (${signature})`,
          evidence: `${fn.schema}.${fn.name} is SECURITY DEFINER (runs as owner, bypasses RLS), returns/reads data, has no auth.uid()/auth.jwt() caller check, and is EXPLICITLY granted execute to the anon/public role. An unauthenticated caller can invoke it to enumerate or dump data across every tenant.`,
          impact: "A SECURITY DEFINER reader reachable by anon runs with the owner's privileges and no RLS — anyone holding the anon key can dump or enumerate the data it returns for any tenant.",
          fix: "REVOKE EXECUTE … FROM anon (and public), or add a caller-authorization check (auth.uid()/role/tenant) inside the function before it returns data. Grant only to the specific authenticated role that needs it, if any.",
          precisionTier: "review",
          bftb: { value: 5, ease: 4, safety: 4 },
        }),
      );
    }
  }
  return findings;
}

// Static auth_rls_initplan (#374) — the source-tier mirror of Splinter's performance lint of the
// same name (LINT_PROFILES.auth_rls_initplan in src/perf-scan.ts, connected tier). A policy
// calling auth.uid()/auth.role()/auth.jwt()/auth.email() bare inside USING/WITH CHECK makes
// Postgres re-evaluate the call once PER ROW; wrapping it as `(select auth.uid())` hoists it to a
// once-per-query initplan. The clause text is already extracted by parsePolicies for the semantic
// review above — this check reads the same feed for the perf shape.
//
// Review tier, not free-count: the free count is the security grade, and a perf lint must never
// inflate it. (Before #937 this note also cited cumulative reads that couldn't see a later `drop
// policy` / re-create; that gap is now closed — parseLivePolicies lints only the final live
// policy — but the live advisor remains the ground truth the connected tier confirms against.)
const AUTH_FN_CALL = /\bauth\.(uid|role|jwt|email)\s*\(\s*\)/gi;

// Whether the auth.* call at `index` in `clause` is already hoisted: walk outward to the nearest
// unclosed "(" to its left and confirm the token following it is `select` — the `(select …)`
// wrapper (Splinter's own distinction). No enclosing paren, or a paren not opening a subquery
// (e.g. `(auth.uid())`), means the call is evaluated per row. Note parsePolicies returns the
// clause with the outer USING(…) parens already stripped, so a bare call has no enclosing paren.
function isSelectWrapped(clause: string, index: number): boolean {
  let depth = 0;
  for (let i = index - 1; i >= 0; i--) {
    const c = clause[i];
    if (c === ")") depth++;
    else if (c === "(") {
      if (depth === 0) return /^\s*select\b/i.test(clause.slice(i + 1, index));
      depth--;
    }
  }
  return false;
}

export function checkMigrationRlsInitplanStatic(dir: string): Finding[] {
  const findings: Finding[] = [];
  // #937 — lint only the policies live at the end of history; a bare-call policy a later migration
  // rewrote (wrapping the call in `(select …)`) is no longer reported from its superseded original.
  for (const p of parseLivePolicies(readMigrations(dir)).policies) {
    const bare: string[] = [];
    for (const [clauseName, clause] of [["USING", p.qual], ["WITH CHECK", p.withCheck]] as const) {
      if (!clause) continue;
      for (const m of clause.matchAll(AUTH_FN_CALL)) {
        if (!isSelectWrapped(clause, m.index)) bare.push(`${m[0].replace(/\s+/g, "")} in ${clauseName}`);
      }
    }
    if (bare.length === 0) continue;
    findings.push(
      mechanicalFinding({
        id: `SB-RLS-INITPLAN-${p.table}-${p.name}`,
        title: `RLS policy ${p.name} re-evaluates auth.* per row`,
        severity: "Perf",
        category: "Performance",
        taxonomy: "auth_rls_initplan (static)",
        location: `${p.file}:${p.line} (${p.schema}.${p.table}.${p.name})`,
        evidence: `Policy ${p.name} on ${p.schema}.${p.table} calls ${bare.join(", ")} without a (select …) wrapper, so Postgres re-evaluates it once per candidate row instead of once per query — Supabase's auth_rls_initplan advisor lint, read here from migration SQL.`,
        impact: "Every query the policy guards pays the auth function call per row scanned — linear slowdown that grows with table size and is invisible until the table does.",
        fix: `Wrap the call in a subquery — e.g. auth.uid() → (select auth.uid()) — to hoist it to a once-per-query initplan. Verify the rewritten policy is behavior-identical before shipping. Confirm against the live advisor (pnpm perf-scan).`,
        precisionTier: "review",
        bftb: { value: 4, ease: 4, safety: 4 },
      }),
    );
  }
  return findings;
}

const FUNCTIONS_HEADER = /^\s*\[functions\.([a-z0-9_-]+)\]/i;
const VERIFY_JWT_FALSE = /^\s*verify_jwt\s*=\s*false\b/i;
const TABLE_HEADER = /^\s*\[/;

// Parse supabase/config.toml for [functions.X] tables that set verify_jwt = false.
export function checkEdgeFunctionVerifyJwt(dir: string): Finding[] {
  const configPath = join(dir, "supabase", "config.toml");
  if (!existsSync(configPath)) return [];

  const findings: Finding[] = [];
  let currentFn: string | undefined;
  const lines = readFileSync(configPath, "utf8").split("\n");
  lines.forEach((line, i) => {
    const header = FUNCTIONS_HEADER.exec(line);
    if (header) {
      currentFn = header[1];
      return;
    }
    if (TABLE_HEADER.test(line)) currentFn = undefined;
    if (currentFn && VERIFY_JWT_FALSE.test(line)) {
      findings.push(
        mechanicalFinding({
          id: `SB-EDGEFN-VERIFYJWT-${currentFn}`,
          title: `Edge Function "${currentFn}" has verify_jwt = false`,
          severity: "Medium",
          category: "Supabase config",
          taxonomy: "Edge Function verify_jwt disabled",
          location: `supabase/config.toml:${i + 1}`,
          evidence: `[functions.${currentFn}] sets verify_jwt = false — the function accepts requests with no valid JWT.`,
          impact: "If the handler does privileged (service-role) work, an unauthenticated caller who finds the URL can invoke it.",
          fix: "Set verify_jwt = true, or if this is a webhook, verify the provider's HMAC signature inside the handler.",
          precisionTier: "review",
        }),
      );
      currentFn = undefined;
    }
  });
  return findings;
}

const AUTH_SECTION_HEADER = /^\s*\[(auth(?:\.[a-z0-9_]+)*)\]/i;
const ENABLE_SIGNUP_TRUE = /^\s*enable_signup\s*=\s*true\b/i;
const ENABLE_CONFIRMATIONS_FALSE = /^\s*enable_confirmations\s*=\s*false\b/i;

// #588 — the source-tier counterpart of the connected-tier checkAuthConfig (mailer_autoconfirm) in
// src/scan/supabase-config.ts. Reads supabase/config.toml for two open-registration weaknesses that
// are committed FACTS, so they run in the free/mechanical scan with no live project:
//   - [auth] enable_signup = true — anyone can self-register an account.
//   - [auth.email] enable_confirmations = false — accounts authenticate without proving they own the
//     email address (the static twin of the live mailer_autoconfirm=true check).
// Scoped by section: enable_signup is read only under the top-level [auth] table, enable_confirmations
// only under [auth.email], so the [auth.sms]/[auth.mfa] siblings (where these keys are normal and
// carry different meaning) are not flagged. Review tier: whether open signup / no-confirm is a defect
// depends on product intent (a deliberately frictionless-signup product is legitimate) — confirm.
export function checkOpenSignupConfig(dir: string, authMethods?: AuthMethods): Finding[] {
  const configPath = join(dir, "supabase", "config.toml");
  if (!existsSync(configPath)) return [];

  const findings: Finding[] = [];
  let section: string | undefined;
  const lines = readFileSync(configPath, "utf8").split("\n");
  lines.forEach((line, i) => {
    const header = AUTH_SECTION_HEADER.exec(line);
    if (header) {
      section = header[1]!.toLowerCase();
      return;
    }
    if (/^\s*\[/.test(line)) section = undefined; // a non-auth table header ends the auth scope
    if (section === "auth" && ENABLE_SIGNUP_TRUE.test(line)) {
      findings.push(
        mechanicalFinding({
          id: "SB-OPEN-SIGNUP",
          title: "Open signup enabled ([auth] enable_signup = true)",
          severity: "Low",
          category: "Supabase config",
          taxonomy: "Open signup enabled",
          location: `supabase/config.toml:${i + 1}`,
          evidence: `[auth] sets enable_signup = true — anyone can self-register an account without an invite.`,
          impact: "Any anonymous visitor can create an account, enabling mass fake-account signup and abuse of any per-account resource.",
          fix: "Set enable_signup = false and provision users via invite/admin, unless open self-registration is a deliberate product decision with abuse controls.",
          precisionTier: "review",
        }),
      );
    }
    if (section === "auth.email" && ENABLE_CONFIRMATIONS_FALSE.test(line)) {
      // #671 — email confirmation only matters if the email provider is actually used. When the
      // caller supplies inferred auth methods and the app is OAuth/OTP-only (email off), reframe this
      // to a conditional note rather than an asserted Medium.
      const input = {
        id: "SB-EMAIL-CONFIRM-OFF",
        title: "Email confirmation disabled ([auth.email] enable_confirmations = false)",
        severity: "Medium" as const,
        category: "Supabase config",
        taxonomy: "Email confirmation disabled",
        location: `supabase/config.toml:${i + 1}`,
        evidence: `[auth.email] sets enable_confirmations = false — accounts authenticate without proving ownership of the email address.`,
        impact: "Signups are effectively auto-confirmed: an attacker can register accounts against emails they do not control (mass fake-account signup, account-takeover setups). The static twin of the live mailer_autoconfirm=true check.",
        fix: "Set enable_confirmations = true so a signup must confirm the email before the account is usable.",
        precisionTier: "review" as const,
      };
      findings.push(mechanicalFinding(authMethods ? gateOnAuthMethod(input, "email authentication", authMethods.email) : input));
    }
  });
  return findings;
}

// #671 source tier — infer which auth methods a repo actually uses, for framing password/email/OTP-
// specific advisories when there is no live Auth to query. Two evidence sources, ORed:
//   - client auth-method calls in committed source: signInWithPassword / password signUp /
//     resetPasswordForEmail / email signInWithOtp → email in use; phone signInWithOtp/verifyOtp →
//     phone in use; signInWithOAuth/IdToken/SSO → OAuth (no password/email evidence on its own).
//   - supabase/config.toml provider toggles: [auth.email] enable_signup = true → email configured;
//     [auth.sms] enable_signup = true → phone; [auth.external.<x>] enabled = true → OAuth.
// A method is `false` (→ conditional framing) only when there IS auth evidence but none for that
// method (an OAuth/OTP-only app, the ATC shape); with no auth evidence at all it stays `undefined`.
const AUTH_SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage"]);
const AUTH_SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const EMAIL_CALL = /\bsignInWithPassword\b|\bresetPasswordForEmail\b|\bsignUp\s*\([^)]*password|\bsignInWithOtp\s*\(\s*\{[^}]*\bemail\b/i;
const PHONE_CALL = /\bsignInWithOtp\s*\(\s*\{[^}]*\bphone\b|\bverifyOtp\s*\([^)]*\bphone\b/i;
const OAUTH_CALL = /\bsignInWithOAuth\b|\bsignInWithIdToken\b|\bsignInWithSSO\b/i;

function scanSourceAuthSignals(dir: string): { email: boolean; phone: boolean; oauth: boolean } {
  const signals = { email: false, phone: false, oauth: false };
  const walk = (d: string): void => {
    for (const entry of readEntriesSafe(d).entries) {
      if (AUTH_SKIP_DIRS.has(entry.name)) continue;
      const full = join(d, entry.name);
      if (entry.isDirectory) walk(full);
      else if (AUTH_SOURCE_EXT.test(entry.name)) {
        const c = readFileSync(full, "utf8");
        if (!signals.email) signals.email = EMAIL_CALL.test(c);
        if (!signals.phone) signals.phone = PHONE_CALL.test(c);
        if (!signals.oauth) signals.oauth = OAUTH_CALL.test(c);
      }
    }
  };
  if (existsSync(dir)) walk(dir);
  return signals;
}

export function inferAuthMethodsFromSource(dir: string): AuthMethods {
  const src = scanSourceAuthSignals(dir);

  const configPath = join(dir, "supabase", "config.toml");
  const toml = existsSync(configPath) ? readFileSync(configPath, "utf8") : "";
  const emailConfig = /\[auth\.email\][\s\S]*?enable_signup\s*=\s*true/i.test(toml);
  const phoneConfig = /\[auth\.sms\][\s\S]*?enable_signup\s*=\s*true/i.test(toml);
  const oauthConfig = /\[auth\.external\.[a-z0-9_]+\][\s\S]*?enabled\s*=\s*true/i.test(toml);

  const emailInUse = src.email || emailConfig;
  const phoneInUse = src.phone || phoneConfig;
  const anyEvidence = emailInUse || phoneInUse || src.oauth || oauthConfig;

  return {
    email: emailInUse ? true : anyEvidence ? false : undefined,
    phone: phoneInUse ? true : anyEvidence ? false : undefined,
  };
}
