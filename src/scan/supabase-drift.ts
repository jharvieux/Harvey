// #1280 / #1070 — connected-tier drift: does the DEPLOYED database still match the migrations that
// are checked in? Read-only against the client's own connected project; nothing here probes a
// production system Harvey was not handed credentials for (the production-probe tier was declined
// on #904 and this is not it — it reads the same connected project the rest of the Supabase pass
// already reads).
//
// Both halves of the comparison already existed and had simply never met: src/scan/supabase.ts
// holds the live state (pg_class / pg_policies over the connected project) and
// src/migration-sql-parse.ts holds the migration-derived expectation as an ORDER-AWARE fold to the
// end state (parseLiveTableNames / parseLivePolicies — "live" there means "still in force at the
// end of the migration history", not "in the database"). A table dropped and re-created, or a
// policy dropped and re-created with a fixed clause, resolves to the last event, so the expectation
// is the schema a fresh `supabase db reset` would produce.
//
// WHY THE RLS DIRECTION IS THE ONE THAT MATTERS: a migration turns RLS on, someone turns it off in
// the dashboard to debug something, and it never goes back. The repo still says the table is
// protected, `supabase db reset` locally still protects it, and every source-tier check that reads
// the migrations agrees — while production has been open the whole time. That is invisible to every
// other tier Harvey runs, because every other tier reads the repo.
//
// DELIBERATELY NOT COMPARED — policy BODIES. Postgres does not store a policy's USING/WITH CHECK
// clause as written; it stores a parsed expression tree and renders it back normalised. MEASURED
// 2026-07-28 against a local `supabase start` stack: the migration text `using (tenant_id =
// auth.uid())` reads back from pg_policies.qual as `(tenant_id = auth.uid())`, and
// `using (tenant_id in (select ...))` reads back with the subquery re-rendered and schema-qualified.
// A textual diff of the two therefore reports every policy in the project as drifted. Comparing
// them properly needs the expression normalised on both sides (parse the migration clause to the
// same tree Postgres builds), which is real work and not attempted here. The consequence is stated
// in SB-DRIFT-00 rather than left silent: a policy whose NAME is unchanged but whose USING clause
// was edited in the dashboard is NOT detected by this pass.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";
import { parseLivePolicies, parseLiveTableNames } from "../migration-sql-parse.js";

// One live table as the drift queries return it. `extensionOwned` marks a table pg_depend attributes
// to an installed extension (postgis' spatial_ref_sys, pg_cron's job tables when they land in
// public): it is legitimately absent from the client's migrations, so it is excluded from the
// "exists in prod, not in your migrations" direction rather than reported as unmanaged.
export interface DriftLiveTable {
  schema: string;
  name: string;
  rlsEnabled: boolean;
  extensionOwned: boolean;
}

export interface DriftLivePolicy {
  schema: string;
  table: string;
  name: string;
}

export interface MigrationFile {
  file: string;
  sql: string;
}

// `alter table [only] [schema.]table enable|disable row level security`. Order-aware below, because a
// migration that enables RLS and a later one that disables it leaves the table legitimately open —
// reporting that as drift would flag the repo's own stated intent.
const RLS_TOGGLE =
  /\balter\s+table\s+(?:only\s+)?(?:"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s*\.\s*)?"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s+(enable|disable)\s+row\s+level\s+security/gi;

// Any `create table` the migration set contains, by name only — deliberately more permissive than
// parseLiveTableNames, which shares migration-sql-parse's CREATE_TABLE and therefore requires the
// column body to end with `);` on its own line. MEASURED 2026-07-28: a single-line
// `create table quotes (id uuid, tenant_id uuid);` is NOT matched by that regex. The two directions
// of the table diff need different answers to that, and getting it wrong is asymmetric:
//   - "in the migrations, missing from prod" uses the strict fold, so an unreadable CREATE simply
//     produces no expectation and the row is not emitted — a false NEGATIVE, which is safe.
//   - "in prod, not in the migrations" would ACCUSE the client of hand-creating a table that is in
//     fact right there in their migration file — a false POSITIVE, which is not. It uses this set,
//     which only ever needs the name.
const CREATE_TABLE_NAME =
  /\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s*\.\s*)?"?([a-zA-Z_][a-zA-Z0-9_]*)"?/gi;

// Every table name the migrations create, regardless of whether the body could be read.
function mentionedTables(migrations: MigrationFile[]): Set<string> {
  const out = new Set<string>();
  for (const { sql } of migrations) {
    for (const m of sql.matchAll(CREATE_TABLE_NAME)) out.add(key(m[1] ?? "public", m[2]!));
  }
  return out;
}

const key = (schema: string, table: string): string => `${schema}.${table}`.toLowerCase();
const policyKey = (schema: string, table: string, name: string): string => `${schema}.${table}.${name}`.toLowerCase();

// Tables whose migration end-state has RLS ENABLED. Last toggle per table wins.
export function expectedRlsEnabled(migrations: MigrationFile[]): Set<string> {
  const last = new Map<string, "enable" | "disable">();
  for (const { sql } of migrations) {
    for (const m of sql.matchAll(RLS_TOGGLE)) {
      last.set(key(m[1] ?? "public", m[2]!), m[3]!.toLowerCase() as "enable" | "disable");
    }
  }
  return new Set([...last.entries()].filter(([, op]) => op === "enable").map(([k]) => k));
}

function readMigrationFiles(dir: string): MigrationFile[] {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) return [];
  return readdirSync(dir)
    .filter((f) => f.toLowerCase().endsWith(".sql"))
    .sort()
    .map((f) => ({ file: f, sql: readFileSync(join(dir, f), "utf8") }));
}

// The migrations directory for a connected Supabase project. Accepts either the directory itself or
// a repo root that contains supabase/migrations, so `--migrations ./client-repo` works as well as
// `--migrations ./client-repo/supabase/migrations`.
export function loadMigrations(dir: string): MigrationFile[] {
  const direct = readMigrationFiles(dir);
  if (direct.length > 0) return direct;
  return readMigrationFiles(join(dir, "supabase", "migrations"));
}

// SCOPE ROW. Emitted on every connected run, whether or not the comparison could be made — an
// absent drift section otherwise reads as "your database matches your migrations", which is exactly
// the silent-omission shape the disclosure family exists to prevent (#1070's second acceptance
// criterion: a connected run never omits the topic silently).
function driftScopeFinding(migrationCount: number, reason?: string): Finding {
  const ran = migrationCount > 0 && !reason;
  return mechanicalFinding({
    id: "SB-DRIFT-00",
    title: ran
      ? `Prod-vs-migration drift: what was compared against ${migrationCount} migration file${migrationCount === 1 ? "" : "s"}`
      : "Prod-vs-migration drift was NOT assessed on this run",
    severity: "Info",
    confidence: "N/A",
    category: "Coverage",
    taxonomy: "Coverage — prod-vs-migration drift scope",
    location: "(supabase project schema)",
    evidence: ran
      ? `The deployed database was compared against the end state of ${migrationCount} committed migration file${migrationCount === 1 ? "" : "s"}. COMPARED: which public-schema tables exist on each side; whether row-level security is enabled on each table; and the identities (schema, table, name) of the RLS policies on each side. NOT COMPARED: column definitions, types, defaults and nullability; indexes and constraints; triggers; functions, including SECURITY DEFINER bodies; grants, roles and default privileges; installed extensions; and the BODIES of policies — Postgres stores a policy's USING/WITH CHECK clause as a normalised expression tree rather than the text the migration wrote, so a textual diff reports every policy as drifted and is not attempted here.`
      : `No comparison was made. ${reason}`,
    impact: ran
      ? "A policy whose name is unchanged but whose USING clause was edited in the dashboard is NOT detected by this pass, and neither is a column, index, trigger, function or grant that differs between the deployed database and the migrations. The absence of a drift finding for those classes means they were never compared, not that they match."
      : "The absence of drift findings in this report means the question was never asked — not that the deployed database matches the committed migrations. A table whose RLS was disabled in the dashboard after the last migration would not appear anywhere in this report.",
    fix: ran
      ? "For the classes above, compare a `supabase db dump --schema public` of the deployed project against a local `supabase db reset` rebuilt from the committed migrations."
      : "Re-run the Supabase pass with `--migrations <path to the client repo's supabase/migrations>` so the deployed schema can be compared against the committed migration history.",
    precisionTier: "high",
    bftb: { value: 1, ease: 4, safety: 5 },
  });
}

// Diff the deployed public schema against the migration-derived expectation. Read-only on both
// sides: the live half is already-fetched query output, the expectation is a fold over .sql files.
export function checkMigrationDrift(
  liveTables: DriftLiveTable[],
  livePolicies: DriftLivePolicy[],
  migrations: MigrationFile[],
  notAssessedReason?: string,
): Finding[] {
  // Exactly one SB-DRIFT-00 on every run, from here — the caller does not emit its own, so there is
  // no path on which the topic appears twice or not at all.
  if (migrations.length === 0) {
    return [
      driftScopeFinding(
        0,
        notAssessedReason ??
          "No committed migration files were found at the path supplied, so there is no expectation to compare the deployed schema against.",
      ),
    ];
  }

  const findings: Finding[] = [driftScopeFinding(migrations.length)];
  const concatenated = migrations.map((m) => m.sql).join("\n");

  const expectedTables = new Set(parseLiveTableNames(concatenated).map((t) => key(t.schema, t.table)));
  const namedInMigrations = mentionedTables(migrations);
  const expectedRls = expectedRlsEnabled(migrations);
  const parsedPolicies = parseLivePolicies(migrations);
  // A policy the parser could not READ is still a policy the migrations CREATE. Counting only the
  // parsed set would report every unreadable-but-present policy as one someone added by hand, so the
  // unparsed identities join the expectation — the identity is all this comparison needs.
  const expectedPolicies = new Set([
    ...parsedPolicies.policies.map((p) => policyKey(p.schema, p.table, p.name)),
    ...parsedPolicies.unparsed.map((p) => policyKey(p.schema, p.table, p.name)),
  ]);

  const publicLiveTables = liveTables.filter((t) => t.schema === "public");
  const liveTableKeys = new Set(publicLiveTables.map((t) => key(t.schema, t.name)));

  for (const t of publicLiveTables) {
    const k = key(t.schema, t.name);

    // The security-relevant direction: the repo says protected, the deployed database is not.
    if (expectedRls.has(k) && !t.rlsEnabled) {
      findings.push(
        mechanicalFinding({
          id: `SB-DRIFT-RLS-${t.schema}-${t.name}`,
          title: `RLS is enabled by the migrations but DISABLED on the deployed ${t.schema}.${t.name}`,
          severity: "Critical",
          category: "Supabase config",
          taxonomy: "Prod-vs-migration drift — RLS disabled in production",
          location: `${t.schema}.${t.name}`,
          evidence: `The committed migrations end with row-level security ENABLED on ${t.schema}.${t.name} (\`alter table ... enable row level security\`, not subsequently disabled). The deployed database reports row-level security DISABLED. The deployed state was therefore changed outside the migration history.`,
          impact: `Every source-tier check Harvey runs reads the migrations and sees this table as protected, and a local rebuild from the same migrations protects it — while the deployed table is readable and writable by anyone holding the anon key, subject only to grants. The repo cannot show this and no other tier of this audit would surface it.`,
          fix: `Re-enable RLS on the deployed table (\`alter table ${t.schema}.${t.name} enable row level security;\`) and confirm its policies are present. Then find out what disabled it — a change made in the dashboard is not in version control and will be silently reverted by the next rebuild, or silently re-applied by the next person who repeats it.`,
          precisionTier: "high",
        }),
      );
    }

    if (!namedInMigrations.has(k) && !t.extensionOwned) {
      findings.push(
        mechanicalFinding({
          id: `SB-DRIFT-TABLE-UNMANAGED-${t.schema}-${t.name}`,
          title: `${t.schema}.${t.name} exists on the deployed database but is not created by any migration`,
          severity: "Medium",
          category: "Supabase config",
          taxonomy: "Prod-vs-migration drift — table not in migrations",
          location: `${t.schema}.${t.name}`,
          evidence: `The deployed public schema contains ${t.schema}.${t.name}, and no committed migration creates it (and it is not owned by an installed extension). It was created directly against the database.`,
          impact: `The table is not reproducible: a fresh environment built from the migrations will not have it, and any code that reads it will fail there while working in production. Its RLS and grants are also outside review, since nothing in the repo describes them.`,
          fix: `Capture the table in a migration (\`supabase db diff\` will generate one from the deployed state), or drop it if it is a leftover.`,
          precisionTier: "review",
        }),
      );
    }
  }

  for (const k of expectedTables) {
    if (liveTableKeys.has(k)) continue;
    const [schema, table] = k.split(".");
    findings.push(
      mechanicalFinding({
        id: `SB-DRIFT-TABLE-MISSING-${schema}-${table}`,
        title: `${k} is created by the migrations but is absent from the deployed database`,
        severity: "Medium",
        category: "Supabase config",
        taxonomy: "Prod-vs-migration drift — migration not applied",
        location: k,
        evidence: `The committed migrations end with ${k} created and not dropped. The deployed public schema does not contain it.`,
        impact: `The deployed database is behind the committed migration history, or the table was dropped by hand. Code paths that use it are broken in production while passing every check that reads the repo.`,
        fix: `Confirm which migrations have actually been applied to this project (\`supabase migration list\`) and apply the outstanding ones.`,
        precisionTier: "review",
      }),
    );
  }

  const livePolicyKeys = new Set(livePolicies.filter((p) => p.schema === "public").map((p) => policyKey(p.schema, p.table, p.name)));

  for (const k of expectedPolicies) {
    // A policy on a table that is itself missing is already reported as the missing table; a second
    // row per policy on it would bury the one finding that explains all of them.
    const table = k.split(".").slice(0, 2).join(".");
    if (!liveTableKeys.has(table)) continue;
    if (livePolicyKeys.has(k)) continue;
    const name = k.split(".").slice(2).join(".");
    findings.push(
      mechanicalFinding({
        id: `SB-DRIFT-POLICY-MISSING-${table}-${name}`,
        title: `RLS policy "${name}" on ${table} is created by the migrations but is absent from the deployed database`,
        severity: "High",
        category: "Supabase config",
        taxonomy: "Prod-vs-migration drift — policy missing in production",
        location: table,
        evidence: `The committed migrations end with a policy named "${name}" on ${table}, not subsequently dropped. The deployed database has no policy of that name on that table.`,
        impact: `The access this policy was written to grant or restrict is not in force on the deployed database. If it was the only policy granting access, the table reads as empty to clients; if it was one of several restricting access, the remaining policies may be more permissive than the migrations describe.`,
        fix: `Re-apply the migration that creates "${name}", and establish why the deployed policy set diverged from the committed one.`,
        precisionTier: "high",
      }),
    );
  }

  for (const p of livePolicies.filter((x) => x.schema === "public")) {
    const k = policyKey(p.schema, p.table, p.name);
    if (expectedPolicies.has(k)) continue;
    // Only for tables the migrations DO manage — an unmanaged table's policies are covered by the
    // unmanaged-table row above.
    if (!namedInMigrations.has(key(p.schema, p.table))) continue;
    findings.push(
      mechanicalFinding({
        id: `SB-DRIFT-POLICY-UNMANAGED-${p.schema}.${p.table}-${p.name}`,
        title: `RLS policy "${p.name}" on ${p.schema}.${p.table} exists on the deployed database but is not created by any migration`,
        severity: "High",
        category: "Supabase config",
        taxonomy: "Prod-vs-migration drift — policy not in migrations",
        location: `${p.schema}.${p.table}`,
        evidence: `The deployed database has an RLS policy named "${p.name}" on ${p.schema}.${p.table}. No committed migration creates a policy of that name on that table.`,
        impact: `An access rule that no one can review is in force on production data, and it is not reproducible — a rebuild from the migrations will not have it, so an environment that looks identical will behave differently. If it was added to work around a problem, it may be broader than intended.`,
        fix: `Capture the policy in a migration (\`supabase db diff\`), or drop it if it was a temporary workaround.`,
        precisionTier: "high",
      }),
    );
  }

  return findings;
}
