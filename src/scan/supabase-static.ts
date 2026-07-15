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
//     committed .sql — statically visible, but until now only reachable at connected tier.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding } from "../findings.js";
import { parsePolicies } from "../migration-sql-parse.js";
import { policyReviewFindings, type LivePolicy, type TenancyModel } from "../rls-policy-review.js";
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
// tenancy model (`--tenant-key`); source-only there's nobody to ask, so it's inferred.
const TENANT_KEY_CANDIDATES = ["tenant_id", "org_id", "organization_id", "workspace_id", "account_id", "company_id"];

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
function inferTenancyModel(sql: string, table?: string): TenancyModel {
  const body = table ? tableBody(sql, table) : sql;
  if (body === null) return { tenantKey: "", mode: "per-user" };
  const key = TENANT_KEY_CANDIDATES.find((c) => new RegExp(`[(,\\n]\\s*${c}\\s+\\w`, "i").test(body));
  return key ? { tenantKey: key } : { tenantKey: "", mode: "per-user" };
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
export function checkMigrationPolicySemantics(dir: string): Finding[] {
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
  for (const [table, policies] of byTable) {
    for (const f of policyReviewFindings(policies, inferTenancyModel(allSql, table))) {
      const site = sites.get(f.location);
      const id = `SB-RLS-POLICY-${f.location}`;
      findings.push(site ? { ...f, id, location: `${site} (${f.location})` } : { ...f, id });
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
