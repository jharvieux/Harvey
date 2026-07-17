// #353 COUNTER-RACE — non-atomic read-modify-write on a Supabase table. Detects the shape where a
// column is `.select()`ed from a table into a variable, an arithmetic (+/-) value is derived from
// it, and that derived value is written back with `.update()` on the SAME table — two concurrent
// requests both read the old value and one increment is lost. The atomic form (a single
// `value = value + 1` RPC) has no select-then-update pair and is not flagged.
//
// Review tier, and it earns that by requiring the actual DATAFLOW, not just table co-occurrence:
// the written value must be arithmetic derived (directly or through one local `const`) from a name
// bound off the select on the same table. A read-then-write of an UNRELATED fresh value is the FP
// shape this dataflow gate clears. It still can't see a DB-side lock/transaction wrapper, so it
// stays review, never free-count.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";
import type { Finding } from "../findings.js";
import { callChainNames, loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

// Plain .js is deliberately in scope — the calibration fixtures (and many Next.js pages/api routes)
// are .js, which the shared loadSources() SOURCE_FILE regex excludes; this pass walks its own tree.
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage"]);

// The string table name in a `.from("<table>")` call anywhere in a call chain, if any.
function tableOf(node: ts.Node): string | undefined {
  let cur: ts.Node = node;
  while (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
    if (cur.expression.name.text === "from") {
      const arg = cur.arguments[0];
      if (arg && ts.isStringLiteralLike(arg)) return arg.text;
    }
    cur = cur.expression.expression;
  }
  return undefined;
}

function boundIdentifiers(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  if (ts.isObjectBindingPattern(name)) return name.elements.flatMap((el) => boundIdentifiers(el.name));
  if (ts.isArrayBindingPattern(name)) return name.elements.flatMap((el) => (ts.isBindingElement(el) ? boundIdentifiers(el.name) : []));
  return [];
}

function identifiersIn(node: ts.Node): Set<string> {
  const names = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (ts.isIdentifier(n)) names.add(n.text);
    ts.forEachChild(n, visit);
  };
  visit(node);
  return names;
}

function hasArithmetic(node: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (ts.isBinaryExpression(n) && (n.operatorToken.kind === ts.SyntaxKind.PlusToken || n.operatorToken.kind === ts.SyntaxKind.MinusToken)) found = true;
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  // Names bound from a `.from(T).select(...)` chain → the table T they read.
  const selectBindings = new Map<string, string>();
  // Local `const <name> = <init>` initializers, for one hop of dataflow expansion.
  const constInit = new Map<string, ts.Expression>();

  const collect = (n: ts.Node): void => {
    if (ts.isVariableDeclaration(n) && n.initializer) {
      const init = ts.isAwaitExpression(n.initializer) ? n.initializer.expression : n.initializer;
      const names = callChainNames(init as ts.Expression);
      if (ts.isCallExpression(init) && names.includes("select") && names.includes("from")) {
        const table = tableOf(init);
        if (table) for (const id of boundIdentifiers(n.name)) selectBindings.set(id, table);
      }
      if (ts.isIdentifier(n.name)) constInit.set(n.name.text, n.initializer);
    }
    ts.forEachChild(n, collect);
  };
  collect(sf);
  if (selectBindings.size === 0) return [];

  const findings: Finding[] = [];
  const seen = new Set<string>();

  const visitUpdate = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "update") {
      const table = tableOf(n);
      const payload = n.arguments[0];
      if (table && payload && ts.isObjectLiteralExpression(payload)) {
        for (const prop of payload.properties) {
          if (!ts.isPropertyAssignment(prop)) continue;
          // Expand the written value through at most one local const, then require it to be
          // arithmetic derived from a name that was selected off THIS table.
          let value: ts.Expression = prop.initializer;
          if (ts.isIdentifier(value) && constInit.has(value.text)) value = constInit.get(value.text)!;
          if (!hasArithmetic(value)) continue;
          const refs = identifiersIn(value);
          const derivedFromRead = [...refs].some((r) => selectBindings.get(r) === table);
          if (derivedFromRead && !seen.has(table)) {
            seen.add(table);
            findings.push(
              mechanicalFinding({
                id: `RACE-read-modify-write-${table}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}`,
                title: `${path} — non-atomic read-modify-write on \`${table}\``,
                severity: "Medium",
                category: "Business logic",
                taxonomy: "Non-atomic read-modify-write race condition",
                location: loc(path, sf, n),
                evidence: `Heuristic "read-modify-write" matched a .select() of \`${table}\` whose value is written back via .update() after an arithmetic (+/-) derivation in ${path} — two concurrent requests can lose an update.`,
                impact: "Concurrent requests read the same value and both write value±1; interleaved increments are lost (lost-update race).",
                fix: "Make the update atomic — a single `update ... set value = value + 1` / an RPC / a row lock — instead of select-then-update in application code.",
                precisionTier: "review",
              }),
            );
          }
        }
      }
    }
    ts.forEachChild(n, visitUpdate);
  };
  visitUpdate(sf);
  return findings;
}

export function detectCounterRaceFindings(files: SourceInput[]): Finding[] {
  return files.filter((f) => SOURCE_EXT.test(f.path)).flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

function walk(dir: string, root: string, out: SourceInput[]): void {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, root, out);
    else if (SOURCE_EXT.test(entry)) out.push({ path: relative(root, full), text: readFileSync(full, "utf8") });
  }
}

export function scanCounterRace(projectDir: string): Finding[] {
  const files: SourceInput[] = [];
  walk(projectDir, projectDir, files);
  return detectCounterRaceFindings(files);
}
