// #1230 / D-091 item 13 — MIGRATION-COLUMN-DRIFT. A migration drops or renames a column while app
// code still names it. Column names live in app code as STRINGS inside the query chain
// (`.from("quotes").select("cruise_line")`), so `tsc` is completely blind — nothing fails to
// compile, nothing fails until those readers 500 in production. ATC's own instance (#137) dropped
// nine columns off `quotes` in the same commit that was supposed to only expand it, and a tenth
// reader was missed even by the follow-up switchover.
//
// #1230 recorded this as needing "migration history + app-code cross-reference OVER TIME", which
// is what made it read as un-mechanical. Re-checked: the migration files ARE the history and they
// are checked into the repo, so the cross-reference is a single-snapshot fold over
// `supabase/migrations/*.sql` in filename order — no VCS archaeology, no two-deploy window. The
// fold is what makes it precise: a column dropped and later re-added, or renamed and renamed back,
// or on a table that was subsequently dropped, leaves nothing to report.
//
// TABLE-AWARE AND WHOLE-WORD, both load-bearing: `quotes.cruise_line` being dropped says nothing
// about `bookings.cruise_line`, and `total_amount` is not `total_amount_cents`. Without either
// narrowing the rule reports every reader of a common column name in the schema.
//
// DISCLOSED BOUNDARY: only columns named as string literals inside the `.from("<table>")` chain are
// seen. A `.select("*")` followed by `row.dropped_col`, or a column referenced through a variable,
// is invisible here — this is a backstop for the contract-before-switchover ordering mistake, not a
// substitute for grepping every reader before shipping the drop.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

const IDENT = String.raw`"?([a-zA-Z_][a-zA-Z0-9_]*)"?`;
const QUALIFIED = String.raw`(?:"?[a-zA-Z_][a-zA-Z0-9_]*"?\s*\.\s*)?` + IDENT;
const CREATE_TABLE = new RegExp(String.raw`create\s+table\s+(?:if\s+not\s+exists\s+)?${QUALIFIED}\s*\(`, "gi");
const DROP_TABLE = new RegExp(String.raw`drop\s+table\s+(?:if\s+exists\s+)?${QUALIFIED}`, "gi");
const ALTER_TABLE = new RegExp(String.raw`alter\s+table\s+(?:only\s+)?${QUALIFIED}\s+([^;]*)`, "gi");
const ADD_COLUMN = new RegExp(String.raw`add\s+column\s+(?:if\s+not\s+exists\s+)?${IDENT}`, "gi");
const DROP_COLUMN = new RegExp(String.raw`drop\s+column\s+(?:if\s+exists\s+)?${IDENT}`, "gi");
const RENAME_COLUMN = new RegExp(String.raw`rename\s+column\s+${IDENT}\s+to\s+${IDENT}`, "gi");

interface DroppedColumn {
  table: string;
  column: string;
  file: string;
  line: number;
  how: "dropped" | "renamed";
  renamedTo?: string;
}

// Blank comments rather than delete them, so a commented-out DROP can't register while line
// numbers stay accurate — the same handling checkMigrationRlsStatic uses.
export function stripComments(raw: string): string {
  return raw.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/--[^\n]*/g, "");
}

function lineAt(sql: string, index: number): number {
  return sql.slice(0, index).split("\n").length;
}

// Fold the migration history: a column is REPORTED only if it is dropped/renamed and never comes
// back, on a table that still exists at the end.
export function droppedColumns(migrations: { file: string; sql: string }[]): Map<string, Map<string, DroppedColumn>> {
  const dropped = new Map<string, Map<string, DroppedColumn>>();
  const record = (table: string, col: DroppedColumn) => {
    const forTable = dropped.get(table) ?? new Map<string, DroppedColumn>();
    forTable.set(col.column, col);
    dropped.set(table, forTable);
  };
  const unrecord = (table: string, column: string) => dropped.get(table)?.delete(column);

  for (const { file, sql: raw } of migrations) {
    const sql = stripComments(raw);
    // A CREATE TABLE re-establishes every column it names.
    for (const m of sql.matchAll(CREATE_TABLE)) {
      const table = m[1]!.toLowerCase();
      const body = sql.slice(m.index + m[0].length);
      for (const line of body.slice(0, body.indexOf(";")).split(",")) {
        const col = /^\s*"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s/.exec(line);
        if (col) unrecord(table, col[1]!.toLowerCase());
      }
    }
    for (const m of sql.matchAll(DROP_TABLE)) dropped.delete(m[1]!.toLowerCase());
    for (const m of sql.matchAll(ALTER_TABLE)) {
      const table = m[1]!.toLowerCase();
      const clause = m[2] ?? "";
      const at = m.index + m[0].length - clause.length;
      for (const c of clause.matchAll(ADD_COLUMN)) unrecord(table, c[1]!.toLowerCase());
      for (const c of clause.matchAll(DROP_COLUMN)) {
        record(table, { table, column: c[1]!.toLowerCase(), file, line: lineAt(sql, at + c.index), how: "dropped" });
      }
      for (const c of clause.matchAll(RENAME_COLUMN)) {
        const from = c[1]!.toLowerCase();
        const to = c[2]!.toLowerCase();
        unrecord(table, to);
        record(table, { table, column: from, file, line: lineAt(sql, at + c.index), how: "renamed", renamedTo: to });
      }
    }
  }
  return dropped;
}

// Every string literal in the call chain that `.from("<table>")` belongs to, split into the
// identifiers a PostgREST column list can hold.
function chainRoot(node: ts.Node): ts.Node {
  let cur = node;
  while (
    cur.parent &&
    (ts.isPropertyAccessExpression(cur.parent) || (ts.isCallExpression(cur.parent) && cur.parent.expression === cur))
  ) {
    cur = cur.parent;
  }
  return cur;
}

function namedIdentifiers(node: ts.Node): { name: string; node: ts.Node }[] {
  const out: { name: string; node: ts.Node }[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isStringLiteralLike(n)) {
      for (const part of n.text.split(/[^a-zA-Z0-9_]+/)) if (part) out.push({ name: part.toLowerCase(), node: n });
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  return out;
}

function detectFile(path: string, sf: ts.SourceFile, dropped: Map<string, Map<string, DroppedColumn>>): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "from") {
      const arg = n.arguments[0];
      if (arg && ts.isStringLiteralLike(arg)) {
        const table = arg.text.toLowerCase();
        const forTable = dropped.get(table);
        if (forTable) {
          for (const { name, node } of namedIdentifiers(chainRoot(n))) {
            const hit = forTable.get(name);
            if (!hit || node === arg) continue;
            const key = `${table}.${name}`;
            if (seen.has(key)) continue;
            seen.add(key);
            const gone =
              hit.how === "renamed"
                ? `renamed to \`${hit.renamedTo}\` by ${hit.file}:${hit.line}`
                : `dropped by ${hit.file}:${hit.line}`;
            findings.push(
              mechanicalFinding({
                id: `SCHEMA-dropped-column-read-${table}-${name}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}`,
                title: `${path} — reads \`${table}.${name}\`, a column the migrations already removed`,
                severity: "High",
                category: "Configuration",
                taxonomy: "App code reads a column the migrations dropped",
                location: loc(path, sf, node),
                evidence: `Heuristic "migration-column-drift" matched \`${name}\` named as a string inside a \`.from("${table}")\` chain, on a column ${gone} and never re-added by a later migration.`,
                impact:
                  "The query fails at runtime the first time this path is exercised. Column names are strings inside the query chain, so the type checker cannot see the break and happy-path tests written against the new schema still pass — the contract migration shipped before the readers were switched over.",
                fix: `Switch this reader off \`${name}\` and deploy that first; expand-migrate-contract is three separate merges, and the drop belongs only in the third, after every reader is live on the new column.`,
                precisionTier: "high",
              }),
            );
          }
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

export function detectMigrationColumnDriftFindings(files: SourceInput[], dropped: Map<string, Map<string, DroppedColumn>>): Finding[] {
  if (dropped.size === 0) return [];
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text), dropped));
}
