// M6 (simplification) — mechanical "looks hand-rolled" indicator detectors (#267). The FREE tier
// of the M6 split (operator ruling 2026-07-15, quality-extras.txt "TIER SPLIT"): each finding
// states, hedged, that a recognisable hand-rolled shape is present and may be worth investigating.
// It NEVER names the replacement library/primitive — deciding what a shape should be replaced
// with is the asserted judgment, and that is the paid M6 triage (docs/design/
// m6-simplification-eval.md §5/§5.1). The wording is load-bearing: copy that drifts to "should
// be replaced with X" re-asserts the judgment and voids the free/paid split. handrolled.test.ts
// locks the vocabulary mechanically.
//
// Non-grading by construction: every indicator is severity "Info", which every counting surface
// in the repo (external-corpus `countedFor`, the quick-scan loud-indicator rule) already excludes.
//
// The classes are the "YES" graduates of the #267 Phase-1 shortlist, minus the boundary calls:
//   • JSON round-trip clone (shortlist #1) is NOT here — perf-code.ts's detectJsonDeepClone
//     (`M7 — JSON deep-clone`) already catches that exact node shape. Emitting it under M6 too
//     would repeat the M5-knip/M5-slop double-count #278 had to unwind, so M6 cross-references
//     the M7 class instead of re-detecting it (measured: both fired on the same line in dogfood).
//   • retry/backoff did not graduate: its benign case is depdrop-shaped — telling the real thing
//     from the justified one needs judgment, so it stays LLM-tier.
//   • Supabase pagination reinvention is deferred: needs cross-statement correlation.
// The class-merge detector is gated on a merge library already being in the target's dependency
// tree — hand-rolling one when no such dep exists is the deliberate dep-drop shape, not a
// reinvention indicator.
//
// Method: TypeScript compiler API, same conventions as slop.ts (M5). Emits Finding[] with
// taxonomy `M6 — Indicator: …`, ids `M6IND-…`, category "Maintainability". Every class is gated
// by a positive+negative fixture pair (handrolled.test.ts) — the #61 discipline.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { parse, type NextId, type SourceInput } from "./common.js";

// One shared, deliberately hedged pair — the tier split lives in these two strings as much as in
// the detectors. Neither may ever name a concrete replacement.
const INDICATOR_IMPACT =
  "If unintentional, a hand-rolled copy of standard behavior adds maintenance cost and can differ from the standard behavior in edge cases; if deliberate, the reason is worth recording.";
const INDICATOR_FIX =
  "Non-grading indicator — worth investigating whether this shape is deliberate. The paid M6 triage decides whether it is a genuine reinvention and names the concrete replacement; if it is deliberate, record the reason in a WHY comment.";

function makeIndicator(
  nextId: NextId,
  input: { title: string; taxonomy: string; location: string; evidence: string },
): Finding {
  return {
    id: nextId(),
    status: "Open",
    category: "Maintainability",
    severity: "Info",
    confidence: "Review",
    impact: INDICATOR_IMPACT,
    fix: INDICATOR_FIX,
    value: 2,
    ease: 3,
    safety: 4,
    ...input,
  };
}

function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

function unwrapParens(node: ts.Expression): ts.Expression {
  return ts.isParenthesizedExpression(node) ? unwrapParens(node.expression) : node;
}

// `JSON.parse(...)` / `JSON.stringify(...)` — the exact global, not a lookalike method.
function isJsonCall(node: ts.Node, method: "parse" | "stringify"): node is ts.CallExpression {
  return (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === "JSON" &&
    node.expression.name.text === method
  );
}

// --- 1. JSON deep-equal: JSON.stringify(a) === JSON.stringify(b) ---------------
// (The round-trip CLONE, JSON.parse(JSON.stringify(x)), is deliberately absent — see header.)

const EQUALITY_OPS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
]);

function detectJsonStringifyEquality(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isBinaryExpression(node) &&
      EQUALITY_OPS.has(node.operatorToken.kind) &&
      isJsonCall(unwrapParens(node.left), "stringify") &&
      isJsonCall(unwrapParens(node.right), "stringify")
    ) {
      findings.push(
        makeIndicator(nextId, {
          title: "Looks hand-rolled: deep equality via JSON string comparison — may be worth investigating",
          taxonomy: "M6 — Indicator: JSON deep-equal",
          location: `${path}:${lineOf(sf, node)}`,
          evidence: `\`${node.getText(sf).slice(0, 70)}\` — compares two values by comparing their JSON serializations (key order and unserializable values change the result).`,
        }),
      );
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 2. Manual query-string parsing: .split("&") + .split("=") in one scope ----

function splitLiteral(node: ts.Node): string | undefined {
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "split" &&
    node.arguments.length >= 1 &&
    ts.isStringLiteralLike(node.arguments[0] as ts.Expression)
  ) {
    return (node.arguments[0] as ts.StringLiteralLike).text;
  }
  return undefined;
}

function enclosingScope(node: ts.Node): ts.Node {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isFunctionLike(cur) || ts.isSourceFile(cur)) return cur;
    cur = cur.parent;
  }
  return node.getSourceFile();
}

function detectQueryStringParse(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const ampSplits: ts.CallExpression[] = [];
  const eqSplits: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    const sep = splitLiteral(node);
    if (sep === "&") ampSplits.push(node as ts.CallExpression);
    else if (sep === "=") eqSplits.push(node as ts.CallExpression);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  const findings: Finding[] = [];
  for (const amp of ampSplits) {
    const scope = enclosingScope(amp);
    if (eqSplits.some((eq) => eq.pos >= scope.pos && eq.end <= scope.end)) {
      findings.push(
        makeIndicator(nextId, {
          title: "Looks hand-rolled: query-string parsing via string splits — may be worth investigating",
          taxonomy: "M6 — Indicator: query-string parsing",
          location: `${path}:${lineOf(sf, amp)}`,
          evidence: `\`${amp.getText(sf).slice(0, 70)}\` — splits on "&" with a companion split on "=" in the same scope, the shape of by-hand key=value parsing (no percent-decoding, no repeated-key handling).`,
        }),
      );
    }
  }
  return findings;
}

// --- 3. Manual cookie parsing --------------------------------------------------

const COOKIE_PARSE_METHODS = new Set(["split", "match", "matchAll"]);
const DOCUMENT_COOKIE_RE = /(^|\.)document\.cookie$/;

function detectCookieParse(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const push = (node: ts.Node) =>
    findings.push(
      makeIndicator(nextId, {
        title: "Looks hand-rolled: cookie-header parsing — may be worth investigating",
        taxonomy: "M6 — Indicator: cookie parsing",
        location: `${path}:${lineOf(sf, node)}`,
        evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — takes a raw cookie string apart by hand (quoting, encoding, and attribute edge cases are easy to get wrong).`,
      }),
    );
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && COOKIE_PARSE_METHODS.has(node.expression.name.text)) {
      const receiverText = node.expression.expression.getText(sf);
      if (DOCUMENT_COOKIE_RE.test(receiverText)) {
        push(node);
      } else if (
        node.expression.name.text === "split" &&
        node.arguments.length >= 1 &&
        ts.isStringLiteralLike(node.arguments[0] as ts.Expression) &&
        (node.arguments[0] as ts.StringLiteralLike).text.includes(";") &&
        /cookie/i.test(receiverText)
      ) {
        push(node);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 4. Random-string id: Math.random().toString(radix > 10) -------------------
// Radix > 10 is what turns a float into letters — the id-building shape. toString(2)/(10) are
// numeric formatting, not ids, and never flag. This is a distinct call-shape from the char-array
// loop the M6 corpus plants in `id.ts`; the two are separate fixtures on purpose (#267 shortlist).

function isMathRandomCall(node: ts.Expression): boolean {
  const inner = unwrapParens(node);
  return (
    ts.isCallExpression(inner) &&
    ts.isPropertyAccessExpression(inner.expression) &&
    ts.isIdentifier(inner.expression.expression) &&
    inner.expression.expression.text === "Math" &&
    inner.expression.name.text === "random"
  );
}

function detectRandomStringId(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "toString" &&
      node.arguments.length === 1 &&
      ts.isNumericLiteral(node.arguments[0] as ts.Expression) &&
      Number((node.arguments[0] as ts.NumericLiteral).text) > 10 &&
      isMathRandomCall(node.expression.expression)
    ) {
      findings.push(
        makeIndicator(nextId, {
          title: "Looks hand-rolled: random-string id from Math.random() — may be worth investigating",
          taxonomy: "M6 — Indicator: random-string id",
          location: `${path}:${lineOf(sf, node)}`,
          evidence: `\`${node.getText(sf).slice(0, 70)}\` — builds an identifier from Math.random(), which is neither collision-safe nor unpredictable.`,
        }),
      );
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 5. Hand-rolled class-string merge: [..].filter(Boolean).join(" ") ---------
// Dep-gated: only fires when a class-merge library is ALREADY in a package.json in the scanned
// set. With no such dep, hand-rolling the join is the deliberate dep-drop shape the M6 corpus's
// depdrop.ts protects, so the class stays silent (and stays silent when no package.json is in the
// scanned set at all — the gate is unverifiable, so it fails closed).

const CLASS_MERGE_DEPS = ["clsx", "classnames", "tailwind-merge"];
const CLASS_MERGE_NAME_RE = /^(cn|cx|clsx|class-?names?|merge-?class(-?names?)?|join-?class(-?names?)?)$/i;

export function hasClassMergeDep(files: SourceInput[]): boolean {
  for (const f of files) {
    if (!/(^|\/)package\.json$/.test(f.path)) continue;
    try {
      const pkg = JSON.parse(f.text) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (CLASS_MERGE_DEPS.some((d) => d in deps)) return true;
    } catch {
      // not JSON — a fixture or template; the gate simply doesn't open on it
    }
  }
  return false;
}

function isFilterBooleanJoinSpace(node: ts.Node): node is ts.CallExpression {
  if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression) || node.expression.name.text !== "join") return false;
  if (node.arguments.length !== 1 || !ts.isStringLiteralLike(node.arguments[0] as ts.Expression)) return false;
  if ((node.arguments[0] as ts.StringLiteralLike).text !== " ") return false;
  const receiver = node.expression.expression;
  return (
    ts.isCallExpression(receiver) &&
    ts.isPropertyAccessExpression(receiver.expression) &&
    receiver.expression.name.text === "filter" &&
    receiver.arguments.length === 1 &&
    ts.isIdentifier(receiver.arguments[0] as ts.Expression) &&
    (receiver.arguments[0] as ts.Identifier).text === "Boolean"
  );
}

// The merge chain alone isn't enough — `.filter(Boolean).join(" ")` also builds sentences. It
// only reads as a class-string merge in a className context: a JSX `className` attribute, a
// merge-named enclosing function, or a class-named variable binding.
function inClassNameContext(node: ts.Node): boolean {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isJsxAttribute(cur) && cur.name.getText() === "className") return true;
    if (ts.isFunctionDeclaration(cur) && cur.name && CLASS_MERGE_NAME_RE.test(cur.name.text)) return true;
    if (ts.isVariableDeclaration(cur) && ts.isIdentifier(cur.name) && (CLASS_MERGE_NAME_RE.test(cur.name.text) || /class/i.test(cur.name.text))) return true;
    cur = cur.parent;
  }
  return false;
}

function detectClassMerge(sf: ts.SourceFile, path: string, nextId: NextId, depGateOpen: boolean): Finding[] {
  if (!depGateOpen) return [];
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (isFilterBooleanJoinSpace(node) && inClassNameContext(node)) {
      findings.push(
        makeIndicator(nextId, {
          title: "Looks hand-rolled: class-string merge — may be worth investigating",
          taxonomy: "M6 — Indicator: class-string merge",
          location: `${path}:${lineOf(sf, node)}`,
          evidence: `\`${node.getText(sf).slice(0, 70)}\` — merges conditional class names by hand while a class-merge library is already in the dependency tree.`,
        }),
      );
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- Orchestrator ----------------------------------------------------------------

/**
 * Runs the M6 free-tier hand-rolled-shape indicators over the given source set and returns
 * Finding[] (taxonomy `M6 — Indicator: …`, all severity "Info" / non-grading). These are
 * descriptive shape-presence indicators, not verdicts: the paid M6 triage (the simplify-scan
 * packet + reviewer) owns the judgment and the replacement.
 */
export function detectHandrolledFindings(files: SourceInput[]): Finding[] {
  let n = 0;
  const nextId: NextId = () => `M6IND-${String(++n).padStart(2, "0")}`;
  const depGateOpen = hasClassMergeDep(files);
  const findings: Finding[] = [];
  for (const f of files) {
    if (!/\.(ts|tsx|jsx|mjs)$/.test(f.path)) continue;
    const sf = parse(f.path, f.text);
    findings.push(
      ...detectJsonStringifyEquality(sf, f.path, nextId),
      ...detectQueryStringParse(sf, f.path, nextId),
      ...detectCookieParse(sf, f.path, nextId),
      ...detectRandomStringId(sf, f.path, nextId),
      ...detectClassMerge(sf, f.path, nextId, depGateOpen),
    );
  }
  return findings;
}
