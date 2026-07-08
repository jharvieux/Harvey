// Static extraction of the structures the M1 detect-deeper classifiers (definer-classifier.ts,
// grant-classifier.ts) and the PII data-map (tools/pii-classify.mjs) need, read directly out of
// a client's `supabase/migrations/*.sql` text instead of a live DB connection (src/cli/detect-
// deeper.ts's normal path). Built for the dry-run harness (src/cli/dry-run.ts, issue #34): when
// there's no live Postgres to introspect, this is how far static migration SQL alone can get you.
//
// Deliberately NOT a general SQL parser — it matches the column/table/function declaration shapes
// Supabase migrations actually use (see the type keyword list and regexes below). A migration
// using an unusual formatting style (multi-statement lines, exotic types) will under-extract
// rather than mis-extract; every regex here is anchored to avoid false structural matches.
//
// One real gap this file can't paper over: GRANT/REVOKE and role membership aren't always present
// in an app's own migrations (Supabase's default anon/authenticated grants are often applied by
// the platform/CLI's own system migrations, not the app's). Callers must treat exposedTo/grants
// derived here as an explicit assumption, not a verified fact — see dry-run.ts's usage.

// Strips `-- ...` line comments before any regex runs. Naive (doesn't special-case "--" inside
// a string literal) but sufficient here — one migration in this repo has a comment that literally
// narrates a SQL statement it deliberately omits ("-- ... alter table ... enable row level
// security ..."), and without stripping, that comment text itself would match ENABLE_RLS below.
function stripLineComments(sql: string): string {
  return sql
    .split("\n")
    .map((line) => line.replace(/--.*$/, ""))
    .join("\n");
}

interface ParsedColumn {
  table_name: string;
  column_name: string;
  data_type?: string;
}

interface ParsedDefinerFunction {
  schema: string;
  name: string;
  argNames: string[];
  body: string;
}

interface ParsedRlsTable {
  schema: string;
  table: string;
  rlsEnabled: boolean;
  hasPolicy: boolean;
}

const SQL_TYPES = [
  "uuid", "text", "timestamptz", "timestamp", "integer", "bigint", "boolean",
  "numeric", "jsonb", "json", "date", "smallint", "varchar", "real", "double precision",
];
const COLUMN_LINE = new RegExp(`^\\s*(\\w+)\\s+(${SQL_TYPES.join("|")})\\b`, "i");
const CREATE_TABLE = /create table\s+(?:if not exists\s+)?(?:(\w+)\.)?(\w+)\s*\(([\s\S]*?)\n\s*\);/gi;

export function parseColumns(sql: string): ParsedColumn[] {
  sql = stripLineComments(sql);
  const out: ParsedColumn[] = [];
  for (const m of sql.matchAll(CREATE_TABLE)) {
    const table = m[2]!;
    const body = m[3]!;
    for (const line of body.split("\n")) {
      const cm = COLUMN_LINE.exec(line);
      if (cm) out.push({ table_name: table, column_name: cm[1]!, data_type: cm[2]!.toLowerCase() });
    }
  }
  return out;
}

export function parseTableNames(sql: string): { schema: string; table: string }[] {
  return [...stripLineComments(sql).matchAll(CREATE_TABLE)].map((m) => ({ schema: m[1] ?? "public", table: m[2]! }));
}

const DEFINER_FUNCTION =
  /create\s+(?:or\s+replace\s+)?function\s+(?:(\w+)\.)?(\w+)\s*\(([^)]*)\)[\s\S]*?security\s+definer[\s\S]*?as\s+\$(\w*)\$([\s\S]*?)\$\4\$/gi;

function parseArgNames(argsRaw: string): string[] {
  return argsRaw
    .split(",")
    .map((a) => a.trim())
    .filter(Boolean)
    .map((a) => a.split(/\s+/)[0]!);
}

export function parseDefinerFunctions(sql: string): ParsedDefinerFunction[] {
  return [...stripLineComments(sql).matchAll(DEFINER_FUNCTION)].map((m) => ({
    schema: m[1] ?? "public",
    name: m[2]!,
    argNames: parseArgNames(m[3]!),
    body: m[5]!,
  }));
}

const ENABLE_RLS = /alter table\s+(?:(\w+)\.)?(\w+)\s+enable row level security/gi;
const CREATE_POLICY = /create policy\s+\w+\s+on\s+(?:(\w+)\.)?(\w+)/gi;

// Combines every `create table` across the migration set with the RLS enable/policy
// statements to report, per table, whether RLS is on and whether it has >=1 policy.
// A table absent from CREATE_TABLE input (e.g. declared in a migration not passed in)
// won't appear — callers should pass the full concatenated migration set.
export function parseRlsState(schemaSql: string, rlsSql: string): ParsedRlsTable[] {
  const tables = parseTableNames(schemaSql);
  const cleanRlsSql = stripLineComments(rlsSql);
  const enabled = new Set([...cleanRlsSql.matchAll(ENABLE_RLS)].map((m) => `${m[1] ?? "public"}.${m[2]}`));
  const policied = new Set([...cleanRlsSql.matchAll(CREATE_POLICY)].map((m) => `${m[1] ?? "public"}.${m[2]}`));
  return tables.map(({ schema, table }) => ({
    schema,
    table,
    rlsEnabled: enabled.has(`${schema}.${table}`),
    hasPolicy: policied.has(`${schema}.${table}`),
  }));
}
