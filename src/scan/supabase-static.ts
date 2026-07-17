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

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { definerReviewFindings } from "../definer-review.js";
import type { Finding } from "../findings.js";
import { parseDefinerFunctions, parsePolicies } from "../migration-sql-parse.js";
import { isUsingTrueGated, policyReviewFindings, type LivePolicy, type TenancyModel } from "../rls-policy-review.js";
import { reviewFinding } from "../review-tier.js";
import { mechanicalFinding } from "./common.js";

const CREATE_TABLE = /create\s+table\s+(?:if\s+not\s+exists\s+)?public\.([a-z0-9_]+)/gi;
const ENABLE_RLS = /alter\s+table\s+(?:only\s+)?public\.([a-z0-9_]+)\s+enable\s+row\s+level\s+security/gi;

interface CreatedTable {
  name: string;
  file: string; // path relative to the scanned dir
  line: number;
}

export function checkMigrationRlsStatic(dir: string): Finding[] {
  const migrationsDir = join(dir, "supabase", "migrations");
  if (!existsSync(migrationsDir)) return [];

  const created = new Map<string, CreatedTable>();
  const enabled = new Set<string>();

  for (const file of readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort()) {
    const raw = readFileSync(join(migrationsDir, file), "utf8");
    // Strip comments so commented-out DDL (e.g. an "intentionally NO enable RLS" note that quotes
    // the statement it's warning about) can't register as a real create/enable. Keep line count
    // stable by blanking rather than deleting, so the create-site line number stays accurate.
    const sql = raw.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/--[^\n]*/g, "");
    const rel = relative(dir, join(migrationsDir, file));
    for (const m of sql.matchAll(CREATE_TABLE)) {
      const name = m[1]!.toLowerCase();
      if (!created.has(name)) {
        const line = sql.slice(0, m.index).split("\n").length;
        created.set(name, { name, file: rel, line });
      }
    }
    for (const m of sql.matchAll(ENABLE_RLS)) enabled.add(m[1]!.toLowerCase());
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

// Foreign keys to a per-tenant table are how an off-list convention shows itself: a `site_id uuid`
// on a policied table is either the tenant key under another name (#258's failure) or a plain
// relation. We cannot tell statically — so we report the assumption instead of guessing.
function unrecognisedScopeColumns(sql: string, table: string): string[] {
  const body = tableBody(sql, table);
  if (body === null) return [];
  const cols = [...body.matchAll(SCOPE_COLUMN)].map((m) => m[1]!.toLowerCase());
  return [...new Set(cols.filter((c) => !OWNER_COLUMNS.test(c) && !TENANT_KEY_CANDIDATES.includes(c)))];
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
      // #281 — the NOT RECOGNISED scan only matches "*_id" columns (SCOPE_COLUMN), so a tenant
      // column named without that suffix (tenant, site, account_slug, ...) is reviewed as per-user
      // and never appears above — same invisible-miss shape this finding exists to surface, one
      // level down. Stated rather than silently left, per #281's own acceptance criteria. Worded to
      // avoid the literal phrase "NOT RECOGNISED" so it can't be mistaken for another entry in that
      // list by a reader (or a test) scanning for the marker.
      ` Coverage note: the scoping-column scan above only matches column names ending in "_id" — a tenant column named without that suffix (e.g. "tenant", "site", "account_slug") is reviewed as per-user and will not be named even though it is the same off-list convention. No such column named above means none was found ending in "_id"; it does not mean none exists.`,
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
  return readdirSync(migrationsDir)
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

  for (const { file, sql } of migrations) {
    const { policies: parsed, unparsed } = parsePolicies(sql);
    for (const p of parsed) {
      const forTable = byTable.get(p.table) ?? [];
      forTable.push(p);
      byTable.set(p.table, forTable);
      const at = sql.toLowerCase().indexOf(`policy ${p.name.toLowerCase()}`);
      sites.set(`${p.schema}.${p.table}.${p.name}`, `${file}:${at >= 0 ? sql.slice(0, at).split("\n").length : 1}`);
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
          location: file,
          evidence: `${u.reason}. The static reviewer could not evaluate this policy, so its absence from the results above means "not assessed", NOT "clean".`,
          question: "Does this policy restrict every row it exposes or accepts to the caller's own tenant?",
          impact: "An unreviewed policy is an unknown: it may be the one that lets another tenant read or write these rows.",
          fix: "Review this policy by hand, or run the connected-tier scan, which reads the live policy from the database instead of parsing SQL.",
          okWhen: "Manual review confirms the policy constrains rows to the caller's own tenant.",
          notOkWhen: "The policy keys on a non-tenant column or under-constrains writes.",
        }),
      );
    }
  }

  // Re-locate each review finding from `schema.table.policy` to its migration file:line — at
  // source tier the file is the actionable address, and location is never gated (anti-shakedown).
  // ids are re-keyed off the policy site because policyReviewFindings numbers its findings per
  // call, and it's called once per table here.
  const models = new Map<string, TenancyModel>();
  const unrecognised = new Map<string, string[]>();
  const usingTrueSpared = new Map<string, string[]>(); // table -> policy names whose USING(true) went unassessed (#338)
  for (const [table, policies] of byTable) {
    const model = inferTenancyModel(allSql, table, tenancyOverride);
    models.set(table, model);
    if (model.mode === "per-user") {
      unrecognised.set(table, unrecognisedScopeColumns(allSql, table));
      const spared = policies.filter(isUsingTrueGated).map((p) => p.name);
      if (spared.length > 0) usingTrueSpared.set(table, spared);
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

// Static auth_rls_initplan (#374) — the source-tier mirror of Splinter's performance lint of the
// same name (LINT_PROFILES.auth_rls_initplan in src/perf-scan.ts, connected tier). A policy
// calling auth.uid()/auth.role()/auth.jwt()/auth.email() bare inside USING/WITH CHECK makes
// Postgres re-evaluate the call once PER ROW; wrapping it as `(select auth.uid())` hoists it to a
// once-per-query initplan. The clause text is already extracted by parsePolicies for the semantic
// review above — this check reads the same feed for the perf shape.
//
// Review tier, not free-count, for two reasons: (1) migrations are cumulative and this check
// doesn't track `drop policy` / re-creates, so a policy rewritten in a later migration could
// still be reported from its original file — the live advisor is the ground truth the connected
// tier confirms against; (2) the free count is the security grade, and a perf lint must never
// inflate it.
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
  for (const { file, sql } of readMigrations(dir)) {
    for (const p of parsePolicies(sql).policies) {
      const bare: string[] = [];
      for (const [clauseName, clause] of [["USING", p.qual], ["WITH CHECK", p.withCheck]] as const) {
        if (!clause) continue;
        for (const m of clause.matchAll(AUTH_FN_CALL)) {
          if (!isSelectWrapped(clause, m.index)) bare.push(`${m[0].replace(/\s+/g, "")} in ${clauseName}`);
        }
      }
      if (bare.length === 0) continue;
      const at = sql.toLowerCase().indexOf(`policy ${p.name.toLowerCase()}`);
      findings.push(
        mechanicalFinding({
          id: `SB-RLS-INITPLAN-${p.table}-${p.name}`,
          title: `RLS policy ${p.name} re-evaluates auth.* per row`,
          severity: "Perf",
          category: "Performance",
          taxonomy: "auth_rls_initplan (static)",
          location: `${file}:${at >= 0 ? sql.slice(0, at).split("\n").length : 1} (${p.schema}.${p.table}.${p.name})`,
          evidence: `Policy ${p.name} on ${p.schema}.${p.table} calls ${bare.join(", ")} without a (select …) wrapper, so Postgres re-evaluates it once per candidate row instead of once per query — Supabase's auth_rls_initplan advisor lint, read here from migration SQL.`,
          impact: "Every query the policy guards pays the auth function call per row scanned — linear slowdown that grows with table size and is invisible until the table does.",
          fix: `Wrap the call in a subquery — e.g. auth.uid() → (select auth.uid()) — to hoist it to a once-per-query initplan. Verify the rewritten policy is behavior-identical before shipping. Confirm against the live advisor (pnpm perf-scan) in case a later migration already rewrote this policy.`,
          precisionTier: "review",
          bftb: { value: 4, ease: 4, safety: 4 },
        }),
      );
    }
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
