// Lightweight schema.prisma structural parser (#758) — the M10 schema-tier fallback for a Prisma
// app when the target's own Prisma CLI isn't runnable (no local install, and `npx --no-install`
// can't resolve a cached binary either — see tools/pii-classify.mjs's columnsFromPrismaSchema,
// which tries the CLI-generated-SQL path first and only calls into this parser on that failure).
//
// Reads model/field declarations straight out of the Prisma schema DSL and maps them to the exact
// {table_name, column_name, data_type} shape src/migration-sql-parse.ts's parseColumns produces
// from SQL, so the SAME downstream classifier (tools/pii-classify.mjs's buildDataMap) runs
// unchanged regardless of which of the two paths produced the columns.
//
// Deliberately NOT a full Prisma schema parser — same under-extract-rather-than-mis-extract
// philosophy as migration-sql-parse.ts. A relation field (its declared type is another model, e.g.
// `posts Post[]`) has no column of its own — it's backed by a scalar FK field elsewhere (`authorId
// String`) — so it's skipped rather than misread as a stored column. To tell a relation apart from
// an enum-typed column (both carry a capitalized custom type name), the parser first collects every
// `model`/`enum`/`type` DECLARATION in the file: a field whose type names a declared enum IS a
// stored column and is classified by NAME (#854 — e.g. `gender Gender` → the SPECIAL_CATEGORY rule),
// while a field whose type names a declared model is a relation and is skipped. Composite `type`
// blocks are parsed like models so their embedded fields are classified too. A field with an
// unresolved capitalized type (declared nowhere) is skipped rather than guessed at, and a
// malformed/unbalanced block is skipped entirely.

interface PrismaColumn {
  table_name: string;
  column_name: string;
  data_type: string;
}

// Prisma's own scalar field types (schema reference §Model field scalar types). Any OTHER
// capitalized type name is a relation to another model (or an enum this parser doesn't resolve),
// never a stored column — see the module comment above.
const SCALAR_TYPE_MAP: Record<string, string> = {
  String: "text",
  Boolean: "boolean",
  Int: "integer",
  BigInt: "bigint",
  Float: "double precision",
  Decimal: "numeric",
  DateTime: "timestamptz",
  Json: "jsonb",
  Bytes: "bytea",
};

// Prisma's only comment syntax is `//` (no block comments in the DSL).
function stripLineComments(text: string): string {
  return text
    .split("\n")
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join("\n");
}

// A `@map("db_name")` attribute's quoted argument on a single FIELD line — Prisma's column-rename
// escape hatch. The map name is always a single quoted string literal in the DSL, never a
// dotted/qualified identifier, so a plain quoted-string capture is sufficient.
const MAP_ATTR = /@map\(\s*"([^"]+)"\s*\)/;
// The block-level `@@map("db_name")` table rename — anchored to the start of its own line (after
// leading whitespace) so it's never confused with a field's `@map(...)`, which always sits after a
// field name and type on that field's line, never alone at line-start.
const BLOCK_MAP_ATTR = /^\s*@@map\(\s*"([^"]+)"\s*\)/m;

// Reads the balanced `{ ... }` body starting at `open` (index of the "{"). Prisma model bodies
// don't nest braces themselves, but staying depth-aware (rather than assuming a single level, the
// way migration-sql-parse.ts's readBalanced handles SQL parens) costs nothing and avoids a wrong
// truncation if a default value or attribute argument ever contains one.
function readBalancedBraces(text: string, open: number): { body: string; end: number } | null {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}") {
      depth--;
      if (depth === 0) return { body: text.slice(open + 1, i), end: i };
    }
  }
  return null; // unterminated block — under-extract, don't guess where it ends
}

const MODEL_START = /\bmodel\s+(\w+)\s*\{/g;
// Composite `type` blocks (embedded objects) and `enum` declarations. Prisma keywords are lowercase,
// so these case-sensitive patterns won't match a model named `Type`/`Enum`.
const TYPE_START = /\btype\s+(\w+)\s*\{/g;
const ENUM_START = /\benum\s+(\w+)\s*\{/g;
// A field declaration line: `name Type[]? @attrs...`. Group 2 is the base type, stripped of the
// trailing `?` (optional) / `[]` (list) modifiers a relation or scalar field may carry.
const FIELD_LINE = /^\s*(\w+)\s+(\w+)(?:\?|\[\])?/;
const BLOCK_ATTR_LINE = /^\s*@@/;

// The names declared by every `re`-shaped block in the schema (model/type/enum). Collected up front
// so a field's type can be resolved to what it references regardless of declaration order.
function declaredNames(clean: string, re: RegExp): Set<string> {
  const names = new Set<string>();
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(clean))) names.add(m[1]!);
  return names;
}

// Emits a column for every scalar-typed OR enum-typed field in each `startRe`-shaped block. A field
// typed as a declared model is a relation (skipped); a declared enum is a stored column classified
// by name (data_type = the enum's own name, which the downstream boolean/jsonb checks correctly
// ignore); anything unresolved is skipped (under-extract).
function emitBlockColumns(clean: string, startRe: RegExp, enums: Set<string>, out: PrismaColumn[]): void {
  startRe.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = startRe.exec(clean))) {
    const declName = m[1]!;
    const open = clean.indexOf("{", m.index);
    const block = readBalancedBraces(clean, open);
    if (!block) break; // unterminated block — nothing after it can be trusted either
    startRe.lastIndex = block.end + 1;

    const tableName = BLOCK_MAP_ATTR.exec(block.body)?.[1] ?? declName;
    for (const line of block.body.split("\n")) {
      if (BLOCK_ATTR_LINE.test(line)) continue; // @@map/@@index/@@id/… — not a field declaration
      const fm = FIELD_LINE.exec(line);
      if (!fm) continue;
      const [, fieldName, baseType] = fm;
      const columnName = MAP_ATTR.exec(line)?.[1] ?? fieldName!;
      const scalar = SCALAR_TYPE_MAP[baseType!];
      if (scalar) out.push({ table_name: tableName, column_name: columnName, data_type: scalar });
      else if (enums.has(baseType!)) out.push({ table_name: tableName, column_name: columnName, data_type: baseType!.toLowerCase() });
      // else a relation (model type) or an unresolved type — no stored scalar column, see module comment
    }
  }
}

/**
 * Parses `model` and composite `type` blocks out of schema.prisma text into the same column shape
 * the SQL-migration parser produces, so both feed the identical M10 classifier. Table name is the
 * block's `@@map` target when declared, else the block name as written (Prisma's own default table
 * name). Column name is the field's `@map` target when declared, else the field name as written.
 */
export function parsePrismaSchema(schema: string): PrismaColumn[] {
  const clean = stripLineComments(schema);
  const enums = declaredNames(clean, ENUM_START);
  const out: PrismaColumn[] = [];
  emitBlockColumns(clean, MODEL_START, enums, out);
  emitBlockColumns(clean, TYPE_START, enums, out);
  return out;
}
