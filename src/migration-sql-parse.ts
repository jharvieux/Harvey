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

// #375: inet/cidr/citext/bytea/geography/geometry matter to the M10 PII feed specifically — an
// `ip_address inet` or `email citext` column that never reaches classifyColumn is an invisible
// PII column, not an under-extraction. geography/geometry are PostGIS; bytea sometimes holds
// encrypted PII blobs. Same failure shape as #307 (SERIAL).
const SQL_TYPES = [
  "uuid", "text", "timestamptz", "timestamp", "integer", "bigint", "boolean",
  "numeric", "jsonb", "json", "date", "smallint", "varchar", "real", "double precision",
  "serial", "bigserial", "smallserial",
  "inet", "cidr", "citext", "bytea", "geography", "geometry",
];

// #299: Prisma-generated migrations (prisma/migrations/**/migration.sql) double-quote every
// identifier ("Account", "userId") — Postgres's standard quoting, which makes them case-sensitive
// and lets them contain characters a bare \w+ can't. IDENT matches either shape: group 1 is a
// quoted identifier's raw (still-escaped) text, group 2 is a bare one. identText below is what
// resolves a capture pair to the real name — never read group 1 or 2 directly.
const IDENT = `(?:"((?:[^"]|"")*)"|(\\w+))`;
// A double `""` inside a quoted identifier is Postgres's escape for a literal `"` (SQL standard,
// same rule as '' inside a string literal) — unescape it, and never touch case: quoted identifiers
// are case-sensitive by design, unlike bare ones which Postgres folds to lowercase itself.
function identText(quoted: string | undefined, bare: string | undefined): string {
  return quoted !== undefined ? quoted.replace(/""/g, '"') : bare!;
}

const COLUMN_LINE = new RegExp(`^\\s*${IDENT}\\s+(${SQL_TYPES.join("|")})\\b`, "i");
const CREATE_TABLE = new RegExp(
  `create table\\s+(?:if not exists\\s+)?(?:${IDENT}\\.)?${IDENT}\\s*\\(([\\s\\S]*?)\\n\\s*\\);`,
  "gi",
);

export function parseColumns(sql: string): ParsedColumn[] {
  sql = stripLineComments(sql);
  const out: ParsedColumn[] = [];
  for (const m of sql.matchAll(CREATE_TABLE)) {
    const table = identText(m[3], m[4]);
    const body = m[5]!;
    for (const line of body.split("\n")) {
      const cm = COLUMN_LINE.exec(line);
      if (cm) out.push({ table_name: table, column_name: identText(cm[1], cm[2]), data_type: cm[3]!.toLowerCase() });
    }
  }
  return out;
}

export function parseTableNames(sql: string): { schema: string; table: string }[] {
  return [...stripLineComments(sql).matchAll(CREATE_TABLE)].map((m) => ({
    schema: m[1] !== undefined || m[2] !== undefined ? identText(m[1], m[2]) : "public",
    table: identText(m[3], m[4]),
  }));
}

// Columns that FK to auth.users — the seed must fill these with a REAL auth user id (an id the
// live pipeline created via the admin API), not a random uuid: they're the profile/membership
// link an RLS `current_tenant_id()`-style resolver reads, and a random uuid both violates the FK
// at apply time and leaves the resolver unable to map the seeded JWT to a tenant. `references
// auth.users` on the same column line is how a Supabase migration declares this link.
const AUTH_USER_REF = new RegExp(`^\\s*${IDENT}\\s+\\w+[\\s\\S]*?references\\s+"?auth"?\\."?users"?`, "i");

export function parseAuthUserRefs(sql: string): { table_name: string; column_name: string }[] {
  sql = stripLineComments(sql);
  const out: { table_name: string; column_name: string }[] = [];
  for (const m of sql.matchAll(CREATE_TABLE)) {
    const table = identText(m[3], m[4]);
    for (const line of m[5]!.split("\n")) {
      const cm = AUTH_USER_REF.exec(line);
      if (cm) out.push({ table_name: table, column_name: identText(cm[1], cm[2]) });
    }
  }
  return out;
}

// Columns that carry a DEFAULT — the seed can (and should) OMIT these and let Postgres fill them,
// which is what lets a generic seed survive a `CHECK (plan IN (...))` on a defaulted enum column, a
// `UNIQUE ... DEFAULT gen_random_bytes()` token, etc.: the default value is by construction a legal
// one, whereas a generic placeholder is not. `\bdefault\b` on the column's own declaration line.
const COLUMN_DEFAULT = new RegExp(`^\\s*${IDENT}\\s+(?:${SQL_TYPES.join("|")})\\b[\\s\\S]*?\\bdefault\\b`, "i");

export function parseColumnDefaults(sql: string): { table_name: string; column_name: string }[] {
  sql = stripLineComments(sql);
  const out: { table_name: string; column_name: string }[] = [];
  for (const m of sql.matchAll(CREATE_TABLE)) {
    const table = identText(m[3], m[4]);
    for (const line of m[5]!.split("\n")) {
      const cm = COLUMN_DEFAULT.exec(line);
      if (cm) out.push({ table_name: table, column_name: identText(cm[1], cm[2]) });
    }
  }
  return out;
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
const CREATE_POLICY = /create policy\s+(?:"([^"]+)"|(\w+))\s+on\s+(?:(\w+)\.)?(\w+)/gi;

// A policy parsed out of migration SQL, shaped to feed rls-policy-review.ts's reviewPolicy()
// unchanged — that reviewer takes a policy struct and doesn't care whether the clauses came from
// live pg_policies or from this text. `cmd` defaults to ALL, matching Postgres when `FOR` is
// omitted. A null clause means genuinely absent (no USING / no WITH CHECK), which is itself a
// signal the reviewer reads — never "we failed to read it". That case is `UnparsedPolicy`.
interface ParsedPolicy {
  schema: string;
  table: string;
  name: string;
  cmd: string;
  qual: string | null;
  withCheck: string | null;
}

// A `create policy` we located but could not extract clauses from — an unbalanced/unterminated
// statement, or a formatting shape these regexes don't cover. Surfaced rather than dropped: a
// failed parse and a clean policy look identical from the outside, and silently reporting
// "nothing suspicious" about a policy we never actually read is exactly the coverage failure the
// fail-loud principle exists to prevent (CLAUDE.md).
interface UnparsedPolicy {
  schema: string;
  table: string;
  name: string;
  reason: string;
}

interface ParsedPolicySet {
  policies: ParsedPolicy[];
  unparsed: UnparsedPolicy[];
}

// Reads a parenthesised expression starting at `open` (the index of its "("), tracking nesting
// and single-quoted literals so a subquery, an EXISTS join, or a string containing ")" doesn't
// truncate it. Returns the inner text, or null if the parens never balance.
function readBalanced(sql: string, open: number): string | null {
  let depth = 0;
  let inString = false;
  for (let i = open; i < sql.length; i++) {
    const c = sql[i];
    if (inString) {
      // '' is an escaped quote inside a literal, not a terminator.
      if (c === "'") {
        if (sql[i + 1] === "'") i++;
        else inString = false;
      }
      continue;
    }
    if (c === "'") inString = true;
    else if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return sql.slice(open + 1, i).trim();
    }
  }
  return null;
}

// The statement text from `start` to its terminating ";" at paren depth 0 (a ";" inside a
// function body or literal doesn't end it). Returns null if unterminated.
function statementText(sql: string, start: number): string | null {
  let depth = 0;
  let inString = false;
  for (let i = start; i < sql.length; i++) {
    const c = sql[i];
    if (inString) {
      if (c === "'") {
        if (sql[i + 1] === "'") i++;
        else inString = false;
      }
      continue;
    }
    if (c === "'") inString = true;
    else if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === ";" && depth === 0) return sql.slice(start, i);
  }
  return null;
}

const FOR_CMD = /\bfor\s+(all|select|insert|update|delete)\b/i;
const USING_AT = /\busing\s*\(/i;
const WITH_CHECK_AT = /\bwith\s+check\s*\(/i;

function clauseAt(stmt: string, marker: RegExp): { value: string | null; failed: boolean } {
  const m = marker.exec(stmt);
  if (!m) return { value: null, failed: false };
  const open = stmt.indexOf("(", m.index);
  const body = readBalanced(stmt, open);
  return body === null ? { value: null, failed: true } : { value: body, failed: false };
}

// Extracts every `create policy` in the migration set with its USING / WITH CHECK bodies intact,
// so the connected-tier semantic reviewer (rls-policy-review.ts) can run against source alone.
export function parsePolicies(sql: string): ParsedPolicySet {
  const clean = stripLineComments(sql);
  const policies: ParsedPolicy[] = [];
  const unparsed: UnparsedPolicy[] = [];

  for (const m of clean.matchAll(CREATE_POLICY)) {
    const name = (m[1] ?? m[2])!;
    const schema = m[3] ?? "public";
    const table = m[4]!;
    const stmt = statementText(clean, m.index);
    if (stmt === null) {
      unparsed.push({ schema, table, name, reason: "statement has no terminating ';' — could not read its clauses" });
      continue;
    }
    const qual = clauseAt(stmt, USING_AT);
    const withCheck = clauseAt(stmt, WITH_CHECK_AT);
    if (qual.failed || withCheck.failed) {
      unparsed.push({ schema, table, name, reason: `unbalanced parentheses in the ${qual.failed ? "USING" : "WITH CHECK"} clause — could not read it` });
      continue;
    }
    policies.push({
      schema,
      table,
      name,
      cmd: (FOR_CMD.exec(stmt)?.[1] ?? "ALL").toUpperCase(),
      qual: qual.value,
      withCheck: withCheck.value,
    });
  }

  return { policies, unparsed };
}

// Combines every `create table` across the migration set with the RLS enable/policy
// statements to report, per table, whether RLS is on and whether it has >=1 policy.
// A table absent from CREATE_TABLE input (e.g. declared in a migration not passed in)
// won't appear — callers should pass the full concatenated migration set.
export function parseRlsState(schemaSql: string, rlsSql: string): ParsedRlsTable[] {
  const tables = parseTableNames(schemaSql);
  const cleanRlsSql = stripLineComments(rlsSql);
  const enabled = new Set([...cleanRlsSql.matchAll(ENABLE_RLS)].map((m) => `${m[1] ?? "public"}.${m[2]}`));
  const policied = new Set([...cleanRlsSql.matchAll(CREATE_POLICY)].map((m) => `${m[3] ?? "public"}.${m[4]}`));
  return tables.map(({ schema, table }) => ({
    schema,
    table,
    rlsEnabled: enabled.has(`${schema}.${table}`),
    hasPolicy: policied.has(`${schema}.${table}`),
  }));
}
