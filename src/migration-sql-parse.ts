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
const SQL_TYPE_SET = new Set(SQL_TYPES);

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

// Columns declared as an ARRAY (`<type>[]`, `varchar(n)[]`, or `<type> ARRAY`). The two-tenant seed
// must seed these with an array literal (`'{}'`), not the scalar placeholder a base-type match would
// pick — a scalar aborts the INSERT with "malformed array literal" (#641). `COLUMN_LINE` records only
// the base type, so array-ness is a separate signal.
const ARRAY_COLUMN = new RegExp(`^\\s*${IDENT}\\s+(?:${SQL_TYPES.join("|")})(?:\\s*\\([^)]*\\))?\\s*(?:\\[\\s*\\]|\\barray\\b)`, "i");

export function parseArrayColumns(sql: string): { table_name: string; column_name: string }[] {
  sql = stripLineComments(sql);
  const out: { table_name: string; column_name: string }[] = [];
  for (const m of sql.matchAll(CREATE_TABLE)) {
    const table = identText(m[3], m[4]);
    for (const line of m[5]!.split("\n")) {
      const cm = ARRAY_COLUMN.exec(line);
      if (cm) out.push({ table_name: table, column_name: identText(cm[1], cm[2]) });
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

// `DROP TABLE [IF EXISTS] [schema.]table` — group 1/2 schema, 3/4 table. A comma-separated multi-table
// drop matches only the first table (rare in Supabase migrations; a disclosed limitation).
const DROP_TABLE = new RegExp(`\\bdrop\\s+table\\s+(?:if\\s+exists\\s+)?(?:${IDENT}\\.)?${IDENT}`, "gi");

// Tables that still EXIST at the end of the migration history: created and not subsequently dropped.
// The two-tenant seed must not INSERT into a table a later migration DROPped (ATC drops pending_rag_sync
// after creating it, #640) — that aborts the whole seed under `psql -v ON_ERROR_STOP=1`. Order-aware,
// not "any DROP excludes": a DROP followed by a re-CREATE leaves the table live (ATC drops+recreates
// email_log). Migrations are concatenated in filename order = chronological, so the LAST create/drop
// event per table wins.
export function parseLiveTableNames(sql: string): { schema: string; table: string }[] {
  sql = stripLineComments(sql);
  const events: { pos: number; schema: string; table: string; op: "create" | "drop" }[] = [];
  const ident = (m: RegExpMatchArray) => ({
    schema: m[1] !== undefined || m[2] !== undefined ? identText(m[1], m[2]) : "public",
    table: identText(m[3], m[4]),
  });
  for (const m of sql.matchAll(CREATE_TABLE)) events.push({ pos: m.index!, ...ident(m), op: "create" });
  for (const m of sql.matchAll(DROP_TABLE)) events.push({ pos: m.index!, ...ident(m), op: "drop" });
  events.sort((a, b) => a.pos - b.pos);
  const last = new Map<string, (typeof events)[number]>();
  for (const e of events) last.set(`${e.schema}.${e.table}`.toLowerCase(), e);
  return [...last.values()].filter((e) => e.op === "create").map(({ schema, table }) => ({ schema, table }));
}

// Columns of each live table's EFFECTIVE definition — the CREATE TABLE currently in force at the end
// of the migration history, not the union of every CREATE for that name. When a table is DROPped and
// re-CREATEd with a different shape (ATC email_log gains to_email/from_email and LOSES recipient_email,
// #643), parseColumns' union would carry stale columns from the dead definition, and the seed would
// name a column that no longer exists. Resolved by event order: a plain CREATE after a DROP replaces
// the definition; a `CREATE ... IF NOT EXISTS` on an already-live table is a no-op (keeps the first).
export function parseLiveColumns(sql: string): ParsedColumn[] {
  sql = stripLineComments(sql);
  const events: { pos: number; key: string; table: string; body?: string; ifNotExists?: boolean; op: "create" | "drop" }[] = [];
  for (const m of sql.matchAll(CREATE_TABLE)) {
    events.push({
      pos: m.index!,
      key: `${m[1] !== undefined || m[2] !== undefined ? identText(m[1], m[2]) : "public"}.${identText(m[3], m[4])}`.toLowerCase(),
      table: identText(m[3], m[4]),
      body: m[5]!,
      ifNotExists: /create\s+table\s+if\s+not\s+exists/i.test(m[0]),
      op: "create",
    });
  }
  for (const m of sql.matchAll(DROP_TABLE)) {
    events.push({ pos: m.index!, key: `${m[1] !== undefined || m[2] !== undefined ? identText(m[1], m[2]) : "public"}.${identText(m[3], m[4])}`.toLowerCase(), table: identText(m[3], m[4]), op: "drop" });
  }
  events.sort((a, b) => a.pos - b.pos);
  const live = new Map<string, { table: string; body: string }>();
  for (const e of events) {
    if (e.op === "drop") live.delete(e.key);
    else if (!(e.ifNotExists && live.has(e.key))) live.set(e.key, { table: e.table, body: e.body! });
  }
  const out: ParsedColumn[] = [];
  for (const { table, body } of live.values()) {
    for (const line of body.split("\n")) {
      const cm = COLUMN_LINE.exec(line);
      if (cm) out.push({ table_name: table, column_name: identText(cm[1], cm[2]), data_type: cm[3]!.toLowerCase() });
    }
  }
  return out;
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

// Columns constrained by a CHECK, and the enum-like allow-list of literal values that satisfies it.
// The two-tenant seed uses these to pick a LEGAL value for a NOT-NULL column with no default (a
// generic placeholder like 'harvey-seed-a' would violate the CHECK and fail the INSERT — #547).
//
// `values` is the derived allow-list, or `null` when we located a CHECK on the column but could NOT
// derive a literal allow-list from it (a regex/comparison/expression check like `qty > 0` or `slug ~
// '…'`) — the seed treats `null` as a fail-loud limitation to disclose, never a value it can pick.
//
// Three CHECK shapes yield an allow-list: `col IN ('a','b',…)`, `col = 'x'`, and the same guarded by
// `col IS NULL OR …` (the IN/eq sub-expression still derives). All three are matched whether the
// CHECK is written inline on the column line, as a table-level constraint, OR added later via
// `ALTER TABLE … ADD CONSTRAINT/ADD COLUMN … CHECK (…)` — the last is the shape that drifts onto a
// column after its table is created (ATC's tenants_onboarding_stage_check, #622), which a
// CREATE-TABLE-only scan misses. Values are returned unquoted ('' collapsed to a single quote).
const STRING_LITERAL = /'((?:[^']|'')*)'/g;
const CHECK_AT = /\bcheck\s*\(/gi;
const IN_ALLOWLIST = new RegExp(`${IDENT}\\s+in\\s*\\(([^)]*)\\)`, "i");
const EQ_LITERAL = new RegExp(`${IDENT}\\s*=\\s*'((?:[^']|'')*)'`, "i");
// `alter table [only] [schema.]table` — the target a later CHECK attaches to.
const ALTER_TABLE = new RegExp(`\\balter\\s+table\\s+(?:only\\s+)?(?:${IDENT}\\.)?${IDENT}`, "gi");

interface CheckConstraint { table_name: string; column_name: string; values: string[] | null }

// Derive {column, allow-list} from a single CHECK expression's inner text: an `IN (…)` list wins,
// else a `= 'literal'` equality. Returns null when neither shape is present (an un-derivable check).
function deriveCheckAllowList(body: string): { column: string; values: string[] } | null {
  const inM = IN_ALLOWLIST.exec(body);
  if (inM) {
    const values = [...inM[3]!.matchAll(STRING_LITERAL)].map((v) => v[1]!.replace(/''/g, "'"));
    if (values.length) return { column: identText(inM[1], inM[2]), values };
  }
  const eqM = EQ_LITERAL.exec(body);
  if (eqM) return { column: identText(eqM[1], eqM[2]), values: [eqM[3]!.replace(/''/g, "'")] };
  return null;
}

// Collect every CHECK in `text` (a CREATE TABLE body or an ALTER TABLE statement) attributed to
// `table`. Derivable checks record their allow-list; an un-derivable check is recorded with a null
// allow-list ONLY when it sits on a column-definition line we can attribute it to (the common inline
// case) — an un-attributable table-level expression check is left to the seed's apply-time fail-loud.
function collectChecks(text: string, table: string, out: CheckConstraint[]): void {
  CHECK_AT.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = CHECK_AT.exec(text))) {
    const open = text.indexOf("(", m.index);
    const body = readBalanced(text, open);
    if (body === null) continue;
    const derived = deriveCheckAllowList(body);
    if (derived) {
      out.push({ table_name: table, column_name: derived.column, values: derived.values });
      continue;
    }
    const lineStart = text.lastIndexOf("\n", m.index) + 1;
    const cm = COLUMN_LINE.exec(text.slice(lineStart, m.index));
    if (cm) out.push({ table_name: table, column_name: identText(cm[1], cm[2]), values: null });
  }
}

export function parseCheckConstraints(sql: string): CheckConstraint[] {
  sql = stripLineComments(sql);
  const out: CheckConstraint[] = [];
  for (const m of sql.matchAll(CREATE_TABLE)) {
    collectChecks(m[5]!, identText(m[3], m[4]), out);
  }
  for (const am of sql.matchAll(ALTER_TABLE)) {
    const stmt = statementText(sql, am.index) ?? sql.slice(am.index);
    collectChecks(stmt, identText(am[3], am[4]), out);
  }
  return out;
}

// The derivable subset: enum-like allow-lists the seed can pick a legal value from (#547).
export function parseCheckInConstraints(sql: string): { table_name: string; column_name: string; values: string[] }[] {
  return parseCheckConstraints(sql)
    .filter((c): c is { table_name: string; column_name: string; values: string[] } => c.values !== null);
}

// Single-column PRIMARY KEY / UNIQUE columns — the arbiters an idempotent seed can target with
// `INSERT ... ON CONFLICT (col)`. Matches an inline `primary key`/`unique` on the column's own line
// and a table-level `primary key (col)` / `unique (col)` (including a named `constraint … unique
// (col)`). Multi-column keys are intentionally skipped: they are not a single-column ON CONFLICT
// arbiter. Used by the two-tenant seed to seed an auth.users-linked table (profiles) idempotently,
// so a `handle_new_user`-style signup trigger that already inserted the row doesn't dup-key (#598).
const INLINE_PK_UNIQUE = new RegExp(`^\\s*${IDENT}\\s+(?:${SQL_TYPES.join("|")})\\b[\\s\\S]*?\\b(?:primary\\s+key|unique)\\b`, "i");
const TABLE_PK_UNIQUE = new RegExp(`\\b(?:primary\\s+key|unique)\\s*\\(\\s*${IDENT}\\s*\\)`, "gi");

export function parseUniqueColumns(sql: string): { table_name: string; column_name: string }[] {
  sql = stripLineComments(sql);
  const out: { table_name: string; column_name: string }[] = [];
  for (const m of sql.matchAll(CREATE_TABLE)) {
    const table = identText(m[3], m[4]);
    const body = m[5]!;
    for (const line of body.split("\n")) {
      const cm = INLINE_PK_UNIQUE.exec(line);
      if (cm) out.push({ table_name: table, column_name: identText(cm[1], cm[2]) });
    }
    for (const cm of body.matchAll(TABLE_PK_UNIQUE)) {
      out.push({ table_name: table, column_name: identText(cm[1], cm[2]) });
    }
  }
  return out;
}

// Generic foreign-key columns and the parent table they REFERENCE, so the two-tenant seed can fill a
// FK with a value that resolves instead of a dangling `gen_random_uuid()` that aborts the INSERT
// (ATC `tenants.tier_id` → `tier_definitions`, #630). Covers the inline column-level `<col> <type> …
// REFERENCES [schema.]<table>[(col)]` shape, the table-level `FOREIGN KEY (col) REFERENCES
// [schema.]<table>` shape, and either added later via `ALTER TABLE … ADD [CONSTRAINT …] FOREIGN KEY`.
// `auth.users` refs are still emitted here but the seed resolves those via parseAuthUserRefs (a real
// created user id), so callers filter them out. The referenced COLUMN is not captured — the seed
// references the parent's own row identity, which for a Supabase table is its `id`.
interface ForeignKey { table_name: string; column_name: string; ref_schema: string; ref_table: string }

// A column-declaration line that ends in a REFERENCES — group 1/2 the column ident, 3/4 the optional
// ref schema, 5/6 the ref table. Guarded (in the loop) against a table-level `foreign key (…)` /
// `constraint … references` line, which starts with a keyword, not a column+type.
const INLINE_FK = new RegExp(`^\\s*${IDENT}\\s+\\w+[\\s\\S]*?\\breferences\\s+(?:${IDENT}\\.)?${IDENT}`, "i");
// `FOREIGN KEY (col) REFERENCES [schema.]table` — table-level or ALTER-added. Group 1/2 col, 3/4 ref
// schema, 5/6 ref table.
const TABLE_FK = new RegExp(`foreign\\s+key\\s*\\(\\s*${IDENT}\\s*\\)\\s*references\\s+(?:${IDENT}\\.)?${IDENT}`, "gi");
const CONSTRAINT_LEAD = /^\s*(?:foreign|constraint|primary|unique|check|references|exclude)\b/i;

export function parseForeignKeys(sql: string): ForeignKey[] {
  sql = stripLineComments(sql);
  const out: ForeignKey[] = [];
  const push = (table: string, m: RegExpExecArray | RegExpMatchArray, colA: number): void => {
    out.push({
      table_name: table,
      column_name: identText(m[colA], m[colA + 1]),
      ref_schema: m[colA + 2] !== undefined || m[colA + 3] !== undefined ? identText(m[colA + 2], m[colA + 3]) : "public",
      ref_table: identText(m[colA + 4], m[colA + 5]),
    });
  };
  for (const m of sql.matchAll(CREATE_TABLE)) {
    const table = identText(m[3], m[4]);
    const body = m[5]!;
    for (const line of body.split("\n")) {
      if (CONSTRAINT_LEAD.test(line)) continue; // table-level constraint line — handled by TABLE_FK below
      const cm = INLINE_FK.exec(line);
      if (cm) push(table, cm, 1);
    }
    for (const cm of body.matchAll(TABLE_FK)) push(table, cm, 1);
  }
  for (const am of sql.matchAll(ALTER_TABLE)) {
    const table = identText(am[3], am[4]);
    const stmt = statementText(sql, am.index) ?? sql.slice(am.index);
    for (const cm of stmt.matchAll(TABLE_FK)) push(table, cm, 1);
  }
  return out;
}

// Columns declared NOT NULL inline on their own declaration line. The seed needs this so a generic FK
// it cannot resolve is handled correctly: a NULLABLE FK is simply OMITTED (left NULL), but a NOT NULL
// FK cannot be — it needs a real parent row (#630). A column absent from this set is nullable
// (Postgres's default), which is exactly the signal the seed reads.
const NOT_NULL_LINE = new RegExp(`^\\s*${IDENT}\\s+(?:${SQL_TYPES.join("|")})\\b[\\s\\S]*?\\bnot\\s+null\\b`, "i");

export function parseNotNullColumns(sql: string): { table_name: string; column_name: string }[] {
  sql = stripLineComments(sql);
  const out: { table_name: string; column_name: string }[] = [];
  for (const m of sql.matchAll(CREATE_TABLE)) {
    const table = identText(m[3], m[4]);
    for (const line of m[5]!.split("\n")) {
      const cm = NOT_NULL_LINE.exec(line);
      if (cm) out.push({ table_name: table, column_name: identText(cm[1], cm[2]) });
    }
  }
  return out;
}

// Columns removed later via `ALTER TABLE [only] [schema.]table … DROP COLUMN [IF EXISTS] <col>` (one
// ALTER may drop several columns in a comma-separated clause list). The two-tenant seed must not name
// a dropped column — it no longer exists in the final schema and aborts the seed (ATC drops
// quotes.cruise_line and 10 others, #642). Column-level analog of parseLiveTableNames. Group 1/2 col.
const DROP_COLUMN = new RegExp(`\\bdrop\\s+column\\s+(?:if\\s+exists\\s+)?${IDENT}`, "gi");

export function parseDroppedColumns(sql: string): { table_name: string; column_name: string }[] {
  sql = stripLineComments(sql);
  const out: { table_name: string; column_name: string }[] = [];
  for (const am of sql.matchAll(ALTER_TABLE)) {
    const table = identText(am[3], am[4]);
    const stmt = statementText(sql, am.index) ?? sql.slice(am.index);
    for (const dm of stmt.matchAll(DROP_COLUMN)) out.push({ table_name: table, column_name: identText(dm[1], dm[2]) });
  }
  return out;
}

// #851/#854: a column-definition line whose TYPE token is NOT one of SQL_TYPES — a Postgres enum, a
// user-defined/composite type, char/money/xml, or an array of one. `parseColumns` extracts only
// recognized-type columns, so these used to vanish before classification (silent omission — the
// answer key never listed them). ANY_COLUMN_LINE captures the column ident (1/2) and its type name
// (3 = double-quoted, as Prisma-generated SQL writes custom types; 4 = bare) so the M10 classifier
// can still classify by NAME and DISCLOSE them, rather than drop them.
const ANY_COLUMN_LINE = new RegExp(`^\\s*${IDENT}\\s+(?:"([^"]+)"|(\\w+))`, "i");
// Second-word tokens that mean the line is NOT a `name type` column definition (a table-level
// clause or a modifier-led continuation) — guards the unknown-type branch against emitting a bogus
// column. The recognized-type branch is immune already: none of these is a SQL_TYPE.
const NON_TYPE_SECOND_WORD =
  /^(by|key|null|not|default|references|primary|foreign|unique|check|constraint|using|with|on|as|like|include|generated|collate|deferrable|initially|partition|inherits|tablespace)$/i;

interface ClassifiableColumns {
  columns: ParsedColumn[]; // recognized SQL type — full type-aware classification applies
  unknownType: ParsedColumn[]; // unrecognized type — NAME-only classification, surfaced as a gap
}

function extractColumnLine(line: string, table: string, out: ClassifiableColumns): void {
  if (CONSTRAINT_LEAD.test(line)) return; // table-level constraint, not a column
  const cm = COLUMN_LINE.exec(line);
  if (cm) {
    out.columns.push({ table_name: table, column_name: identText(cm[1], cm[2]), data_type: cm[3]!.toLowerCase() });
    return;
  }
  const am = ANY_COLUMN_LINE.exec(line);
  if (!am) return;
  const rawType = am[3] ?? am[4];
  if (!rawType || NON_TYPE_SECOND_WORD.test(rawType)) return;
  out.unknownType.push({ table_name: table, column_name: identText(am[1], am[2]), data_type: rawType.toLowerCase() });
}

// #852: columns added to an existing table by a later migration via `ALTER TABLE … ADD COLUMN`.
// `parseColumns` reads only CREATE TABLE bodies, so on a migrations-directory schema a PII column a
// follow-up migration adds (`ALTER TABLE users ADD COLUMN ssn text`) was invisible to M10. The
// `COLUMN` keyword is required — an under-extract guard so `ADD CONSTRAINT`/`ADD PRIMARY KEY` never
// read as a column. Group 1/2 the column ident, 3 a quoted type, 4 a bare one.
const ADD_COLUMN = new RegExp(`\\badd\\s+column\\s+(?:if\\s+not\\s+exists\\s+)?${IDENT}\\s+(?:"([^"]+)"|(\\w+))`, "gi");

function extractAddedColumns(sql: string, out: ClassifiableColumns): void {
  for (const am of sql.matchAll(ALTER_TABLE)) {
    const table = identText(am[3], am[4]);
    const stmt = statementText(sql, am.index!) ?? sql.slice(am.index!);
    for (const cm of stmt.matchAll(ADD_COLUMN)) {
      const rawType = cm[3] ?? cm[4];
      if (!rawType) continue;
      const col = { table_name: table, column_name: identText(cm[1], cm[2]), data_type: rawType.toLowerCase() };
      if (SQL_TYPE_SET.has(rawType.toLowerCase())) out.columns.push(col);
      else out.unknownType.push(col);
    }
  }
}

// The full set of columns M10 should classify from migration SQL: CREATE TABLE bodies (#250) PLUS
// `ALTER TABLE … ADD COLUMN` (#852), split by whether the declared type is recognized. A column a
// later migration DROPs is removed from both sets (it isn't in the live schema). `columns` and
// `unknownType` together are everything to classify; keeping them separate lets the caller disclose
// the NAME-only subset (the type-based signals — jsonb-container, boolean-flag — couldn't apply).
export function parseClassifiableColumns(sql: string): ClassifiableColumns {
  sql = stripLineComments(sql);
  const out: ClassifiableColumns = { columns: [], unknownType: [] };
  for (const m of sql.matchAll(CREATE_TABLE)) {
    const table = identText(m[3], m[4]);
    for (const line of m[5]!.split("\n")) extractColumnLine(line, table, out);
  }
  extractAddedColumns(sql, out);
  const dropped = new Set(parseDroppedColumns(sql).map((d) => `${d.table_name}.${d.column_name}`.toLowerCase()));
  const live = (c: ParsedColumn): boolean => !dropped.has(`${c.table_name}.${c.column_name}`.toLowerCase());
  return { columns: out.columns.filter(live), unknownType: out.unknownType.filter(live) };
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
// `drop policy [if exists] <name> on [schema.]<table>` — the statement a later migration uses to
// remove (or, paired with a fresh CREATE POLICY of the same name, replace) an earlier policy (#937).
const DROP_POLICY = /drop\s+policy\s+(?:if\s+exists\s+)?(?:"([^"]+)"|(\w+))\s+on\s+(?:(\w+)\.)?(\w+)/gi;

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

// The policies LIVE at the end of migration history, with `drop policy` / re-create tracked in
// statement order (#937). parsePolicies reads a single file's text cumulatively: a broken policy
// dropped or replaced by a LATER migration is still returned, so a correctly-fixed schema looks
// byte-identical to the still-broken one it replaced. This reduces the whole set — each `create
// policy` defines (or redefines) a policy identity `schema.table.name`, each `drop policy` removes
// it, and the LAST event per identity in file-then-position order wins. Callers that judge the
// final schema (the static RLS review, the initplan lint) must use this, not per-file parsePolicies.
//
// Ordering is position-aware within a file too, so the common `drop policy X; create policy X (fixed)`
// pair in one migration resolves to the fixed create, not to an empty result. Unparsed creates go
// through the same lifecycle — an unreadable policy a later migration drops is not reported either.
export interface LivePolicy extends ParsedPolicy {
  file: string;
  line: number;
}
export interface LiveUnparsedPolicy extends UnparsedPolicy {
  file: string;
  line: number;
}
export interface LivePolicySet {
  policies: LivePolicy[];
  unparsed: LiveUnparsedPolicy[];
}

export function parseLivePolicies(migrations: { file: string; sql: string }[]): LivePolicySet {
  const key = (schema: string, table: string, name: string): string => `${schema}.${table}.${name}`.toLowerCase();
  interface CreateRec { schema: string; table: string; name: string; file: string; line: number; parsed?: ParsedPolicy; unparsed?: UnparsedPolicy }
  interface Event { seq: number; k: string; op: "create" | "drop"; rec?: CreateRec }
  const events: Event[] = [];
  let seq = 0;

  for (const { file, sql } of migrations) {
    const clean = stripLineComments(sql);
    const { policies, unparsed } = parsePolicies(sql);
    // Index this file's creates by identity. Within a file the LAST create of an identity is the
    // one that survives (an earlier one is dropped+recreated, or is an illegal duplicate), and it
    // is exactly the clause set that must be live — so last-in-source (= map insertion order) wins.
    const parsedByKey = new Map<string, ParsedPolicy>(policies.map((p) => [key(p.schema, p.table, p.name), p]));
    const unparsedByKey = new Map<string, UnparsedPolicy>(unparsed.map((u) => [key(u.schema, u.table, u.name), u]));

    const local: { pos: number; op: "create" | "drop"; schema: string; table: string; name: string }[] = [];
    for (const m of clean.matchAll(CREATE_POLICY)) local.push({ pos: m.index!, op: "create", name: (m[1] ?? m[2])!, schema: m[3] ?? "public", table: m[4]! });
    for (const m of clean.matchAll(DROP_POLICY)) local.push({ pos: m.index!, op: "drop", name: (m[1] ?? m[2])!, schema: m[3] ?? "public", table: m[4]! });
    local.sort((a, b) => a.pos - b.pos);

    for (const e of local) {
      const k = key(e.schema, e.table, e.name);
      if (e.op === "drop") {
        events.push({ seq: seq++, k, op: "drop" });
        continue;
      }
      const line = clean.slice(0, e.pos).split("\n").length;
      events.push({ seq: seq++, k, op: "create", rec: { schema: e.schema, table: e.table, name: e.name, file, line, parsed: parsedByKey.get(k), unparsed: unparsedByKey.get(k) } });
    }
  }

  const live = new Map<string, CreateRec>();
  for (const e of events) {
    if (e.op === "drop") live.delete(e.k);
    else live.set(e.k, e.rec!);
  }

  const out: LivePolicySet = { policies: [], unparsed: [] };
  for (const rec of live.values()) {
    if (rec.parsed) out.policies.push({ ...rec.parsed, file: rec.file, line: rec.line });
    else if (rec.unparsed) out.unparsed.push({ ...rec.unparsed, file: rec.file, line: rec.line });
  }
  return out;
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
