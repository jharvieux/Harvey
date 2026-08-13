// #1230 / D-091 item 6 — STALE-QUOTA-READ. A budget or limit gate reads its allowance ONCE, then
// consumes it across a loop of operations without re-reading. From the second iteration on, the cap
// is enforced against a number that stopped being true — the classic TOCTOU shape, and the reason
// ATC's Apify monthly budget was checked at run start and never again across nine line batches.
//
// Distinct from item 18 / counter-race.ts, which owns the single select-then-update pair in one
// statement sequence. Here nothing is written back at all: the read is simply stale by the time it
// is used again.
//
// #1230 recorded this as cross-statement dataflow and therefore un-mechanical. Re-checked: the
// dataflow needed is one hop — a binding whose initializer is a DB READ, referenced in a comparison
// inside a loop that consumes something. The DB-read requirement is what makes it shippable, and it
// is the same narrowing counter-race.ts leans on: a locally-computed running total compared against
// a constant ceiling is recomputed every iteration and is NOT this bug, so requiring the guard
// value to come off a `.from(…).select(…)` chain clears the largest FP class outright.
//
// `review`, not free-count: this pass cannot see a DB-side reserve row, an advisory lock, or a
// transactional gate wrapping the loop, any of which makes the single read correct.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { callChainNames, loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

const QUOTA_NAME = /^(budget|quota|remaining|credits?|allowance|balance|cap|caps|limit|limits|spend|usage|available|headroom)/i;
const COMPARISON = new Set([
  ts.SyntaxKind.LessThanToken,
  ts.SyntaxKind.LessThanEqualsToken,
  ts.SyntaxKind.GreaterThanToken,
  ts.SyntaxKind.GreaterThanEqualsToken,
]);

function isLoop(n: ts.Node): boolean {
  return ts.isForStatement(n) || ts.isForOfStatement(n) || ts.isForInStatement(n) || ts.isWhileStatement(n) || ts.isDoStatement(n);
}

function boundIdentifiers(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  if (ts.isObjectBindingPattern(name)) return name.elements.flatMap((el) => boundIdentifiers(el.name));
  if (ts.isArrayBindingPattern(name)) return name.elements.flatMap((el) => (ts.isBindingElement(el) ? boundIdentifiers(el.name) : []));
  return [];
}

// Names bound from a `.from(T).select(…)` read whose identifier reads like an allowance.
function quotaBindings(sf: ts.SourceFile): Map<string, string> {
  const bindings = new Map<string, string>();
  const visit = (n: ts.Node) => {
    if (ts.isVariableDeclaration(n) && n.initializer) {
      const init = ts.isAwaitExpression(n.initializer) ? n.initializer.expression : n.initializer;
      if (ts.isCallExpression(init)) {
        const chain = callChainNames(init);
        if (chain.includes("select") && chain.includes("from")) {
          for (const id of boundIdentifiers(n.name)) {
            if (QUOTA_NAME.test(id)) bindings.set(id, init.getText(sf).replace(/\s+/g, " ").slice(0, 120));
          }
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return bindings;
}

function hasRefreshingRead(loop: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
      const name = n.expression.name.text;
      if (name === "select" || name === "rpc") found = true;
    }
    ts.forEachChild(n, visit);
  };
  visit(loop);
  return found;
}

function comparisonsAgainst(loop: ts.Node, names: Set<string>): { name: string; node: ts.Node }[] {
  const out: { name: string; node: ts.Node }[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isBinaryExpression(n) && COMPARISON.has(n.operatorToken.kind)) {
      const text = n.getText();
      for (const name of names) if (new RegExp(`\\b${name}\\b`).test(text)) out.push({ name, node: n });
    }
    ts.forEachChild(n, visit);
  };
  visit(loop);
  return out;
}

function consumes(loop: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (ts.isAwaitExpression(n)) found = true;
    ts.forEachChild(n, visit);
  };
  visit(loop);
  return found;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const bindings = quotaBindings(sf);
  if (bindings.size === 0) return [];

  const findings: Finding[] = [];
  const visit = (n: ts.Node) => {
    if (isLoop(n) && !hasRefreshingRead(n) && consumes(n)) {
      const seen = new Set<string>();
      for (const hit of comparisonsAgainst(n, new Set(bindings.keys()))) {
        if (seen.has(hit.name)) continue;
        seen.add(hit.name);
        findings.push(
          mechanicalFinding({
            id: `RACE-stale-quota-read-${hit.name}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${n.getStart(sf)}`,
            title: `${path} — allowance \`${hit.name}\` read once, then consumed across a loop without re-reading`,
            severity: "Medium",
            category: "Business logic",
            taxonomy: "Quota gate consumed across a loop without re-reading",
            location: loc(path, sf, hit.node),
            evidence: `Heuristic "stale-quota-read" matched \`${hit.name}\`, bound from \`${bindings.get(hit.name)}\`, compared inside a loop whose body awaits work and contains no re-read of that value.`,
            impact:
              "From the second iteration on, the cap is enforced against a value that stopped being true. Two overlapping runs, or a long enough batch, overrun the budget without any error — sequential single-run tests pass because a single iteration is always within the cap.",
            fix: "Re-read the allowance between consuming operations, or make the gate atomic at the database level — an advisory lock, or a transactional reserve-row that debits the allowance in the same statement that checks it.",
            precisionTier: "review",
          }),
        );
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

export function detectStaleQuotaReadFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}
