// Live-query wrapper for the M1 DETECT DEEPER classifiers (definer-classifier.ts,
// grant-classifier.ts) and the connected-tier review passes (definer-review.ts,
// rls-policy-review.ts). Read-only against a CLIENT's database — never Harvey's own
// Supabase project. The classification logic itself is pure and unit-tested
// without a DB connection; this file only gathers the structured input.
//
//   SUPABASE_DB_URL=postgres://... pnpm detect-deeper [--queried-tables tables.json] [--tenant-key <column>] [--tenant-mode per-tenant|per-user] [--findings-out <file>]
//
// --tenant-key names the column that scopes a row to its tenant (the declared tenancy model);
// with it, the live pg_policies bodies are semantically reviewed against that key (#199).
// --tenant-mode per-user reviews a per-user app (ownership is auth.uid() keyed on any column, no
// single tenant key) instead of the default per-tenant model (#206).
//
// --queried-tables points at a JSON array of "schema.table" strings — a static
// grep of the client's own code for tables it queries directly (not via
// service-role). Without it, every no-policy table is treated as "not queried by
// client code" (conservative: real client reads would show up as a vestigial-
// grant flag instead of a broken-read flag — still a flag, just the wrong reason).
//
// --findings-out (#1364): writes the bare Finding[] to a file, the same shape `pnpm record-pass
// --findings <file>` reads. Before this flag the only output was the combined
// `{ definer, grants, findings }` blob on stdout, so recording the M1 live pass meant capturing
// stdout and hand-extracting `.findings` before calling record-pass — the "no hand-editing" #448
// asked for did not hold for this pass. `record-pass --module M1 --pass live --findings <file>
// --out <artifacts-dir>` is still the write step that produces M1.pass.json; this flag just removes
// the manual extraction in front of it.

import { readFileSync, writeFileSync } from "node:fs";
import postgres from "postgres";
import type { Finding } from "../findings.js";
import {
  classifyDefinerFunctions,
  definerFindings,
  type DefinerFunction,
  type DefinerVerdict,
} from "../definer-classifier.js";
import {
  classifyNoPolicyTables,
  grantFindings,
  type NoPolicyTable,
  type TableVerdict,
} from "../grant-classifier.js";
import { definerReviewFindings } from "../definer-review.js";
import { policyReviewFindings, type LivePolicy, type TenancyModel } from "../rls-policy-review.js";

const DEFINER_FUNCTIONS_QUERY = `
  select
    n.nspname as schema,
    p.proname as name,
    coalesce(p.proargnames, '{}') as arg_names,
    pg_get_functiondef(p.oid) as full_definition,
    coalesce(array_agg(distinct r.rolname) filter (where a.privilege_type = 'EXECUTE'), '{}') as exposed_to
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  left join lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a on true
  left join pg_roles r on r.oid = a.grantee
  where p.prosecdef = true
    and n.nspname not in ('pg_catalog', 'information_schema')
  group by n.nspname, p.proname, p.proargnames, p.oid
`;

const NO_POLICY_TABLES_QUERY = `
  select t.schemaname as schema, t.tablename as table
  from pg_tables t
  where t.rowsecurity = true
    and t.schemaname not in ('pg_catalog', 'information_schema')
    and not exists (
      select 1 from pg_policies pol
      where pol.schemaname = t.schemaname and pol.tablename = t.tablename
    )
`;

const GRANTS_QUERY = `
  select grantee, privilege_type as privilege
  from information_schema.role_table_grants
  where table_schema = $1 and table_name = $2
    and grantee in ('anon', 'authenticated', 'service_role')
`;

const POLICIES_QUERY = `
  select schemaname as schema, tablename as table, policyname as name, cmd, qual, with_check
  from pg_policies
  where schemaname not in ('pg_catalog', 'information_schema')
`;

// pg_get_functiondef returns the full CREATE statement; the classifier only
// wants the body between the dollar-quote delimiters.
export function extractBody(fullDefinition: string): string {
  const match = /\$(\w*)\$([\s\S]*?)\$\1\$/.exec(fullDefinition);
  return match ? match[2]! : fullDefinition;
}

interface Sql {
  <T = Record<string, unknown>>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T[]>;
  unsafe<T = Record<string, unknown>>(query: string, params?: unknown[]): Promise<T[]>;
}

async function fetchDefinerFunctions(sql: Sql): Promise<DefinerFunction[]> {
  const rows = await sql.unsafe<{
    schema: string;
    name: string;
    arg_names: string[];
    full_definition: string;
    exposed_to: string[];
  }>(DEFINER_FUNCTIONS_QUERY);
  return rows.map((r) => ({
    schema: r.schema,
    name: r.name,
    argNames: r.arg_names,
    exposedTo: r.exposed_to,
    body: extractBody(r.full_definition),
  }));
}

async function fetchNoPolicyTables(sql: Sql, queriedTables: Set<string>): Promise<NoPolicyTable[]> {
  const tables = await sql.unsafe<{ schema: string; table: string }>(NO_POLICY_TABLES_QUERY);
  const result: NoPolicyTable[] = [];
  for (const t of tables) {
    const grants = await sql.unsafe<{ grantee: string; privilege: string }>(GRANTS_QUERY, [t.schema, t.table]);
    result.push({
      schema: t.schema,
      table: t.table,
      grants,
      queriedByClientCode: queriedTables.has(`${t.schema}.${t.table}`),
    });
  }
  return result;
}

async function fetchPolicies(sql: Sql): Promise<LivePolicy[]> {
  const rows = await sql.unsafe<{
    schema: string;
    table: string;
    name: string;
    cmd: string;
    qual: string | null;
    with_check: string | null;
  }>(POLICIES_QUERY);
  return rows.map((r) => ({ schema: r.schema, table: r.table, name: r.name, cmd: r.cmd, qual: r.qual, withCheck: r.with_check }));
}

export async function runDetectDeeper(
  sql: Sql,
  queriedTables: Set<string> = new Set(),
  tenancyModel?: TenancyModel,
): Promise<{ definer: DefinerVerdict[]; grants: TableVerdict[]; findings: Finding[] }> {
  const [functions, tables] = await Promise.all([fetchDefinerFunctions(sql), fetchNoPolicyTables(sql, queriedTables)]);
  const definer = classifyDefinerFunctions(functions);
  const grants = classifyNoPolicyTables(tables);
  // Route the non-ok definer verdicts (flag/ambiguous) through the caller-authorization body-read.
  const reviewable = functions.filter((_, i) => definer[i]!.verdict !== "ok");
  const findings = [...definerFindings(definer), ...grantFindings(grants), ...definerReviewFindings(reviewable)];
  if (tenancyModel) findings.push(...policyReviewFindings(await fetchPolicies(sql), tenancyModel));
  return { definer, grants, findings };
}

async function main() {
  const dbUrl = process.env.SUPABASE_DB_URL;
  if (!dbUrl) {
    console.error(
      "usage: SUPABASE_DB_URL=postgres://... pnpm detect-deeper [--queried-tables tables.json] [--tenant-key <column>] [--tenant-mode per-tenant|per-user] [--findings-out <file>]",
    );
    process.exit(2);
  }

  const args = process.argv.slice(2);
  const queriedTablesIdx = args.indexOf("--queried-tables");
  const queriedTables = new Set<string>(
    queriedTablesIdx >= 0 ? (JSON.parse(readFileSync(args[queriedTablesIdx + 1]!, "utf8")) as string[]) : [],
  );
  const tenantKeyIdx = args.indexOf("--tenant-key");
  const tenantModeIdx = args.indexOf("--tenant-mode");
  const tenantMode = tenantModeIdx >= 0 ? (args[tenantModeIdx + 1] as "per-tenant" | "per-user") : undefined;
  const tenancyModel: TenancyModel | undefined =
    tenantKeyIdx >= 0 || tenantMode === "per-user"
      ? { tenantKey: tenantKeyIdx >= 0 ? args[tenantKeyIdx + 1]! : "", mode: tenantMode }
      : undefined;
  const findingsOutIdx = args.indexOf("--findings-out");
  const findingsOutPath = findingsOutIdx >= 0 ? args[findingsOutIdx + 1] : undefined;

  const sql = postgres(dbUrl, { max: 1, idle_timeout: 5 }) as unknown as Sql;
  try {
    const { definer, grants, findings } = await runDetectDeeper(sql, queriedTables, tenancyModel);

    const okCount = definer.filter((v) => v.verdict === "ok").length + grants.filter((v) => v.verdict === "ok").length;
    const ambiguousCount =
      definer.filter((v) => v.verdict === "ambiguous").length + grants.filter((v) => v.verdict === "ambiguous").length;
    console.error(
      `M1 detect-deeper: ${findings.length} flagged, ${okCount} checked & ruled out, ${ambiguousCount} ambiguous (needs manual review)`,
    );
    console.log(JSON.stringify({ definer, grants, findings }, null, 2));
    if (findingsOutPath) {
      writeFileSync(findingsOutPath, `${JSON.stringify(findings, null, 2)}\n`);
      console.error(`${findings.length} finding(s) → ${findingsOutPath} (feed to \`pnpm record-pass --module M1 --pass live --findings ${findingsOutPath}\`)`);
    }
  } finally {
    await (sql as unknown as { end: () => Promise<void> }).end();
  }
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err: unknown) => {
    console.error(err);
    process.exit(1);
  });
}
