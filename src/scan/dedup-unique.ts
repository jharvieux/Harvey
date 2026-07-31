// #1257 / D-091 item 25 — DEDUP WITHOUT A UNIQUE CONSTRAINT. App code dedupes by reading for an
// existing row and inserting when it finds none; the schema has no UNIQUE index behind the columns
// it read on. Two concurrent callers both see "absent" and both insert, and the duplicate then
// breaks every later `.maybeSingle()` on that predicate — a read-path outage created by a write-path
// race, arriving long after the deploy that caused it.
//
// #1230 filed this under a blanket "cross-statement or cross-time dataflow question a mechanical
// pass is a poor fit for". It is neither: the dedup predicate is in the app code, the constraint set
// is in the migrations, and folding those two together is exactly what migration-column-drift.ts
// already does for item 13. Both halves are in one repo snapshot.
//
// SOUNDNESS — the check runs only where it can be RIGHT. A table whose CREATE TABLE this pass never
// read is skipped outright: "no unique constraint found" and "no schema found" are the same silence
// otherwise, and the second is not a finding. Protection is subset-based, not equality-based — a
// UNIQUE on any SUBSET of the columns read (a bare `UNIQUE (external_ref)` under a two-column
// predicate) still makes the second insert fail, so it clears. Primary keys count as unique
// constraints. `.upsert()` is the fix and never a finding.
//
// DISCLOSED BOUNDS, stated in the finding's own impact text: constraints are read from the
// migration DDL and a root schema snapshot only, so one added by hand in a dashboard or by an ORM
// outside the migration history is not seen; and the read and the insert must be in the same
// function, so a dedup split across a helper is not assessed.

import { existsSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding, walkSourceFiles } from "./common.js";
import { readMigrations, stripComments } from "./migration-column-drift.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

const IDENT = String.raw`"?([a-zA-Z_][a-zA-Z0-9_]*)"?`;
const QUALIFIED = String.raw`(?:"?[a-zA-Z_][a-zA-Z0-9_]*"?\s*\.\s*)?` + IDENT;
const CREATE_TABLE = new RegExp(String.raw`create\s+table\s+(?:if\s+not\s+exists\s+)?${QUALIFIED}\s*\(`, "gi");
const DROP_TABLE = new RegExp(String.raw`drop\s+table\s+(?:if\s+exists\s+)?${QUALIFIED}`, "gi");
const ALTER_TABLE = new RegExp(String.raw`alter\s+table\s+(?:only\s+)?${QUALIFIED}\s+([^;]*)`, "gi");
const ADD_UNIQUE = /\b(?:unique|primary\s+key)\s*\(([^)]*)\)/gi;
const CREATE_UNIQUE_INDEX = new RegExp(String.raw`create\s+unique\s+index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?(?:${IDENT}\s+)?on\s+${QUALIFIED}\s*\(([^)]*)\)`, "gi");

function columnList(raw: string): string[] {
  return raw
    .split(",")
    .map((c) => c.trim().replace(/^"|"$/g, "").split(/\s/)[0]!.toLowerCase())
    .filter(Boolean);
}

// Every table the schema DECLARES, mapped to the unique/primary-key column sets on it. A table
// absent from this map was never seen, which is different from having no constraints.
export function uniqueConstraints(sources: { file: string; sql: string }[]): Map<string, string[][]> {
  const tables = new Map<string, string[][]>();
  for (const { sql: raw } of sources) {
    const sql = stripComments(raw);
    for (const m of sql.matchAll(CREATE_TABLE)) {
      const table = m[1]!.toLowerCase();
      const body = sql.slice(m.index + m[0].length);
      const decl = body.slice(0, body.indexOf(";"));
      const sets = tables.get(table) ?? [];
      // Column-level `col text unique` / `id uuid primary key`, one per comma-separated clause.
      for (const clause of decl.split(",")) {
        const inline = /^\s*"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s+[^(]*\b(unique|primary\s+key)\b/i.exec(clause);
        if (inline) sets.push([inline[1]!.toLowerCase()]);
      }
      for (const u of decl.matchAll(ADD_UNIQUE)) sets.push(columnList(u[1]!));
      tables.set(table, sets);
    }
    for (const m of sql.matchAll(DROP_TABLE)) tables.delete(m[1]!.toLowerCase());
    for (const m of sql.matchAll(ALTER_TABLE)) {
      const table = m[1]!.toLowerCase();
      if (!tables.has(table)) continue;
      for (const u of (m[2] ?? "").matchAll(ADD_UNIQUE)) tables.get(table)!.push(columnList(u[1]!));
    }
    for (const m of sql.matchAll(CREATE_UNIQUE_INDEX)) {
      const table = m[2]!.toLowerCase();
      if (tables.has(table)) tables.get(table)!.push(columnList(m[3]!));
    }
  }
  return tables;
}

// A snapshot does not record that a column was ever dropped, which is why migration-column-drift.ts
// refuses to read one — but it states the constraints in force perfectly well, so it is read here.
function readSchemaSnapshots(dir: string): { file: string; sql: string }[] {
  const out: { file: string; sql: string }[] = [];
  for (const rel of ["schema.sql", join("supabase", "schema.sql"), join("db", "schema.sql")]) {
    const full = join(dir, rel);
    if (existsSync(full)) out.push({ file: relative(dir, full), sql: readFileSync(full, "utf8") });
  }
  return out;
}

interface Chain {
  table: string;
  kind: "read" | "insert";
  columns: string[];
  node: ts.Node;
}

function chainCalls(node: ts.CallExpression): { name: string; call: ts.CallExpression }[] {
  const out: { name: string; call: ts.CallExpression }[] = [];
  for (let cur: ts.Node = node; ts.isCallExpression(cur) || ts.isPropertyAccessExpression(cur); ) {
    if (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
      out.push({ name: cur.expression.name.text, call: cur });
      cur = cur.expression.expression;
    } else if (ts.isPropertyAccessExpression(cur)) cur = cur.expression;
    else break;
  }
  return out.reverse();
}

// The outermost call the `.from("t")` node belongs to, so the whole chain is visible from one node.
function chainRoot(node: ts.Node): ts.CallExpression | undefined {
  let cur: ts.Node = node;
  while (cur.parent && (ts.isPropertyAccessExpression(cur.parent) || (ts.isCallExpression(cur.parent) && cur.parent.expression === cur))) cur = cur.parent;
  return ts.isCallExpression(cur) ? cur : undefined;
}

function objectKeys(arg: ts.Expression | undefined): string[] {
  if (!arg || !ts.isObjectLiteralExpression(arg)) return [];
  return arg.properties
    .map((p) => (p.name && (ts.isIdentifier(p.name) || ts.isStringLiteralLike(p.name)) ? p.name.text.toLowerCase() : undefined))
    .filter((n): n is string => !!n);
}

function classify(from: ts.CallExpression): Chain | undefined {
  const arg = from.arguments[0];
  if (!arg || !ts.isStringLiteralLike(arg)) return undefined;
  const root = chainRoot(from);
  if (!root) return undefined;
  const calls = chainCalls(root);
  const names = new Set(calls.map((c) => c.name));
  if (names.has("upsert")) return undefined;

  if (names.has("insert")) {
    const insert = calls.find((c) => c.name === "insert")!;
    return { table: arg.text.toLowerCase(), kind: "insert", columns: objectKeys(insert.call.arguments[0]), node: from };
  }
  // A dedup READ is a single-row lookup on an equality predicate: `.select().eq(…).maybeSingle()`.
  if (!names.has("select") || !(names.has("maybeSingle") || names.has("single"))) return undefined;
  const columns = calls
    .filter((c) => c.name === "eq")
    .map((c) => c.call.arguments[0])
    .filter((a): a is ts.StringLiteralLike => !!a && ts.isStringLiteralLike(a))
    .map((a) => a.text.toLowerCase());
  return columns.length > 0 ? { table: arg.text.toLowerCase(), kind: "read", columns, node: from } : undefined;
}

function enclosingFunction(node: ts.Node): ts.Node | undefined {
  for (let cur: ts.Node | undefined = node.parent; cur; cur = cur.parent) {
    if (ts.isFunctionDeclaration(cur) || ts.isFunctionExpression(cur) || ts.isArrowFunction(cur) || ts.isMethodDeclaration(cur)) return cur;
  }
  return undefined;
}

function detectFile(path: string, sf: ts.SourceFile, constraints: Map<string, string[][]>): Finding[] {
  const chains: { fn: ts.Node | undefined; chain: Chain }[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "from") {
      const chain = classify(n);
      if (chain) chains.push({ fn: enclosingFunction(n), chain });
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);

  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const { fn, chain: read } of chains) {
    if (read.kind !== "read" || !fn) continue;
    const sets = constraints.get(read.table);
    if (!sets) continue; // table never declared in anything this pass read — not assessable
    if (sets.some((set) => set.every((col) => read.columns.includes(col)))) continue;
    const insert = chains.find(
      ({ fn: other, chain }) => other === fn && chain.kind === "insert" && chain.table === read.table && read.columns.every((c) => chain.columns.includes(c)),
    );
    if (!insert) continue;

    const key = `${read.table}:${read.columns.join(",")}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const predicate = read.columns.map((c) => `\`${c}\``).join(", ");
    findings.push(
      mechanicalFinding({
        id: `RACE-dedup-no-unique-${read.table}-${read.columns.join("-")}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}`,
        title: `${path} — SELECT-then-INSERT dedup on \`${read.table}\` with no unique constraint behind it`,
        severity: "Medium",
        category: "Application logic",
        taxonomy: "SELECT-then-INSERT dedup with no unique constraint",
        location: loc(path, sf, read.node),
        evidence: `Heuristic "dedup-without-unique" matched a single-row read of \`${read.table}\` on ${predicate} followed in the same function by an insert writing those same columns, while no UNIQUE or PRIMARY KEY constraint on \`${read.table}\` covers them.`,
        impact:
          "The read and the insert are two round trips with no lock between them, so two concurrent callers both see 'absent' and both insert. The duplicate is silent at write time and surfaces later as an error on every `.maybeSingle()` reading that predicate — a read-path outage produced by a write-path race, long after the deploy. SCOPE: constraints are read from the migration DDL and a root schema snapshot only, so one added by hand in a dashboard is not seen; the read and the insert must be in the same function, so a dedup split across a helper is not assessed; and a table this pass never saw declared is skipped rather than reported.",
        fix: `Add \`unique (${read.columns.join(", ")})\` on \`${read.table}\` in a migration and let the database arbitrate — then either upsert on that constraint (\`.upsert(…, { onConflict: "${read.columns.join(",")}" })\`) or catch the duplicate-key error and re-read. Application-side dedup cannot be made correct without it.`,
        precisionTier: "review",
        cwe: ["CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"],
      }),
    );
  }
  return findings;
}

export function detectDedupWithoutUniqueFindings(files: SourceInput[], constraints: Map<string, string[][]>): Finding[] {
  if (constraints.size === 0) return [];
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text), constraints));
}

export function scanDedupWithoutUnique(projectDir: string): Finding[] {
  return detectDedupWithoutUniqueFindings(walkSourceFiles(projectDir), uniqueConstraints([...readMigrations(projectDir), ...readSchemaSnapshots(projectDir)]));
}
