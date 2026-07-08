// Live-query wrapper for the M1 DETECT DEEPER classifiers (definer-classifier.ts,
// grant-classifier.ts). Read-only against a CLIENT's database — never Harvey's own
// Supabase project. The classification logic itself is pure and unit-tested
// without a DB connection; this file only gathers the structured input.
//
//   SUPABASE_DB_URL=postgres://... pnpm detect-deeper [--queried-tables tables.json]
//
// --queried-tables points at a JSON array of "schema.table" strings — a static
// grep of the client's own code for tables it queries directly (not via
// service-role). Without it, every no-policy table is treated as "not queried by
// client code" (conservative: real client reads would show up as a vestigial-
// grant flag instead of a broken-read flag — still a flag, just the wrong reason).

import { readFileSync } from "node:fs";
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

export async function runDetectDeeper(
  sql: Sql,
  queriedTables: Set<string> = new Set(),
): Promise<{ definer: DefinerVerdict[]; grants: TableVerdict[]; findings: Finding[] }> {
  const [functions, tables] = await Promise.all([fetchDefinerFunctions(sql), fetchNoPolicyTables(sql, queriedTables)]);
  const definer = classifyDefinerFunctions(functions);
  const grants = classifyNoPolicyTables(tables);
  const findings = [...definerFindings(definer), ...grantFindings(grants)];
  return { definer, grants, findings };
}

async function main() {
  const dbUrl = process.env.SUPABASE_DB_URL;
  if (!dbUrl) {
    console.error("usage: SUPABASE_DB_URL=postgres://... pnpm detect-deeper [--queried-tables tables.json]");
    process.exit(2);
  }

  const args = process.argv.slice(2);
  const queriedTablesIdx = args.indexOf("--queried-tables");
  const queriedTables = new Set<string>(
    queriedTablesIdx >= 0 ? (JSON.parse(readFileSync(args[queriedTablesIdx + 1]!, "utf8")) as string[]) : [],
  );

  const sql = postgres(dbUrl, { max: 1, idle_timeout: 5 }) as unknown as Sql;
  try {
    const { definer, grants, findings } = await runDetectDeeper(sql, queriedTables);

    const okCount = definer.filter((v) => v.verdict === "ok").length + grants.filter((v) => v.verdict === "ok").length;
    const ambiguousCount =
      definer.filter((v) => v.verdict === "ambiguous").length + grants.filter((v) => v.verdict === "ambiguous").length;
    console.error(
      `M1 detect-deeper: ${findings.length} flagged, ${okCount} checked & ruled out, ${ambiguousCount} ambiguous (needs manual review)`,
    );
    console.log(JSON.stringify({ definer, grants, findings }, null, 2));
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
