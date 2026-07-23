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
// String`) — so it's skipped rather than misread as a stored column. An enum-typed field is skipped
// for the same reason: this parser has no visibility into `enum` declarations to confirm the type
// name isn't itself a model, so treating an unrecognized capitalized type as "definitely a scalar"
// would risk misreading a relation as data. A malformed/unbalanced model block is skipped entirely
// rather than guessed at.

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
// A field declaration line: `name Type[]? @attrs...`. Group 2 is the base type, stripped of the
// trailing `?` (optional) / `[]` (list) modifiers a relation or scalar field may carry.
const FIELD_LINE = /^\s*(\w+)\s+(\w+)(?:\?|\[\])?/;
const BLOCK_ATTR_LINE = /^\s*@@/;

/**
 * Parses `model` blocks out of schema.prisma text into the same column shape the SQL-migration
 * parser produces, so both feed the identical M10 classifier. Table name is the model's `@@map`
 * target when declared, else the model name as written (Prisma's own default table name). Column
 * name is the field's `@map` target when declared, else the field name as written.
 */
export function parsePrismaSchema(schema: string): PrismaColumn[] {
  const clean = stripLineComments(schema);
  const out: PrismaColumn[] = [];
  MODEL_START.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MODEL_START.exec(clean))) {
    const modelName = m[1]!;
    const open = clean.indexOf("{", m.index);
    const block = readBalancedBraces(clean, open);
    if (!block) break; // unterminated model block — nothing after it can be trusted either
    MODEL_START.lastIndex = block.end + 1;

    const tableName = BLOCK_MAP_ATTR.exec(block.body)?.[1] ?? modelName;
    for (const line of block.body.split("\n")) {
      if (BLOCK_ATTR_LINE.test(line)) continue; // @@map/@@index/@@id/… — not a field declaration
      const fm = FIELD_LINE.exec(line);
      if (!fm) continue;
      const [, fieldName, baseType] = fm;
      const dataType = SCALAR_TYPE_MAP[baseType!];
      if (!dataType) continue; // relation or enum field — no stored column here, see module comment
      const columnName = MAP_ATTR.exec(line)?.[1] ?? fieldName!;
      out.push({ table_name: tableName, column_name: columnName, data_type: dataType });
    }
  }
  return out;
}
