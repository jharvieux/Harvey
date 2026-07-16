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
// reinvention indicator. The gate itself is generic (`depGatePresent`, #406); its consumers are
// class-merge, raw-millisecond date math (28), and email-shape regex (81).
//
// Batch 2 (#406 item 2): the eight measured-nonzero YES entries of the catalogue, built in
// measured order (docs/design/m6-corpus-frequency.md): 28 raw-ms date math (dep-gated on a date
// lib), 41 MIME-type lookup table, 88 currency via symbol+toFixed, 81 email-shape regex
// (dep-gated on zod), 29 manual date formatting, 37 query-string building (the mirror of the
// shipped parse class — must never fire on the parse shape), 42 base64url conversion, and
// 52 cookie serialization (the shipped parse class covers reads; this is writes).
//
// WHY-comment suppression (#406, catalogue follow-up 4): every indicator class is suppressed by
// an adjacent `WHY:` comment — the depdrop discipline generalized. A flagged shape whose comment
// records a deliberate reason IS the answer an investigation would surface. Suppressed shapes
// emit NOTHING, and that is a deliberate design decision, not a silent skip: the WHY comment is
// the in-code record of the reason, visible to any reader at the flagged site, so the
// suppression is auditable in the target itself in a way a scanner-side omission never is;
// emitting a "suppressed" row would only restate the comment. The check lives in the shared
// emission path (makeIndicator), never per-detector.
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

// Adjacency for WHY suppression is mechanical (catalogue entry 58's /why:/i): the marker in the
// leading comment trivia of the flagged node's enclosing statement, or in a trailing comment at
// that statement's end (the shape's own line). A comment without the marker never suppresses —
// narration is not a recorded reason.
const WHY_MARKER = /why:/i;

function enclosingStatement(node: ts.Node): ts.Node {
  let cur: ts.Node = node;
  while (cur.parent && !ts.isStatement(cur)) cur = cur.parent;
  return cur;
}

function isWhySuppressed(sf: ts.SourceFile, node: ts.Node): boolean {
  const stmt = enclosingStatement(node);
  const ranges = [
    ...(ts.getLeadingCommentRanges(sf.text, stmt.getFullStart()) ?? []),
    ...(ts.getTrailingCommentRanges(sf.text, stmt.end) ?? []),
  ];
  return ranges.some((r) => WHY_MARKER.test(sf.text.slice(r.pos, r.end)));
}

// The one shared emission path — every detector emits through here, so WHY-comment suppression
// applies to every current and future indicator class without per-detector wiring.
function makeIndicator(
  nextId: NextId,
  sf: ts.SourceFile,
  path: string,
  node: ts.Node,
  input: { title: string; taxonomy: string; evidence: string },
): Finding | undefined {
  if (isWhySuppressed(sf, node)) return undefined;
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
    location: `${path}:${lineOf(sf, node)}`,
    ...input,
  };
}

// Generic dep-gate for dep-gated indicator classes (#406): open only when one of the named
// libraries is already in dependencies/devDependencies of a package.json in the scanned set.
// Fails CLOSED — no package.json in the set, or none that parses, means the gate cannot be
// verified and stays shut.
export function depGatePresent(files: SourceInput[], libNames: string[]): boolean {
  for (const f of files) {
    if (!/(^|\/)package\.json$/.test(f.path)) continue;
    try {
      const pkg = JSON.parse(f.text) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (libNames.some((d) => d in deps)) return true;
    } catch {
      // not JSON — a fixture or template; the gate simply doesn't open on it
    }
  }
  return false;
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
      const f = makeIndicator(nextId, sf, path, node, {
        title: "Looks hand-rolled: deep equality via JSON string comparison — may be worth investigating",
        taxonomy: "M6 — Indicator: JSON deep-equal",
        evidence: `\`${node.getText(sf).slice(0, 70)}\` — compares two values by comparing their JSON serializations (key order and unserializable values change the result).`,
      });
      if (f) findings.push(f);
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
      const f = makeIndicator(nextId, sf, path, amp, {
        title: "Looks hand-rolled: query-string parsing via string splits — may be worth investigating",
        taxonomy: "M6 — Indicator: query-string parsing",
        evidence: `\`${amp.getText(sf).slice(0, 70)}\` — splits on "&" with a companion split on "=" in the same scope, the shape of by-hand key=value parsing (no percent-decoding, no repeated-key handling).`,
      });
      if (f) findings.push(f);
    }
  }
  return findings;
}

// --- 3. Manual cookie parsing --------------------------------------------------

const COOKIE_PARSE_METHODS = new Set(["split", "match", "matchAll"]);
const DOCUMENT_COOKIE_RE = /(^|\.)document\.cookie$/;

function detectCookieParse(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const push = (node: ts.Node) => {
    const f = makeIndicator(nextId, sf, path, node, {
      title: "Looks hand-rolled: cookie-header parsing — may be worth investigating",
      taxonomy: "M6 — Indicator: cookie parsing",
      evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — takes a raw cookie string apart by hand (quoting, encoding, and attribute edge cases are easy to get wrong).`,
    });
    if (f) findings.push(f);
  };
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
      const f = makeIndicator(nextId, sf, path, node, {
        title: "Looks hand-rolled: random-string id from Math.random() — may be worth investigating",
        taxonomy: "M6 — Indicator: random-string id",
        evidence: `\`${node.getText(sf).slice(0, 70)}\` — builds an identifier from Math.random(), which is neither collision-safe nor unpredictable.`,
      });
      if (f) findings.push(f);
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
      const f = makeIndicator(nextId, sf, path, node, {
        title: "Looks hand-rolled: class-string merge — may be worth investigating",
        taxonomy: "M6 — Indicator: class-string merge",
        evidence: `\`${node.getText(sf).slice(0, 70)}\` — merges conditional class names by hand while a class-merge library is already in the dependency tree.`,
      });
      if (f) findings.push(f);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 6. Date math on raw millisecond constants (catalogue 28, dep-gated) --------
// Only fires when a date library is ALREADY in the tree — with no such dep, hand-rolling the
// offset is the deliberate dep-drop shape, exactly like class-merge. Flags bare hour/day
// constants and all-literal multiplication chains whose product is a whole number of hours
// (60*60*1000, 24*60*60*1000, 7*24*60*60*1000, …).

const DATE_MATH_DEPS = ["date-fns", "dayjs", "luxon", "moment"];
const MS_PER_HOUR = 3_600_000;
const MS_LITERALS = new Set([3_600_000, 86_400_000]);

function numericValue(node: ts.Node): number | undefined {
  return ts.isNumericLiteral(node) ? Number(node.text.replace(/_/g, "")) : undefined;
}

function isMultiplication(node: ts.Node): node is ts.BinaryExpression {
  return ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.AsteriskToken;
}

// Product of a multiplication chain made ENTIRELY of numeric literals; undefined otherwise.
function literalChainProduct(expr: ts.Expression): number | undefined {
  const e = unwrapParens(expr);
  if (isMultiplication(e)) {
    const l = literalChainProduct(e.left);
    const r = literalChainProduct(e.right);
    return l !== undefined && r !== undefined ? l * r : undefined;
  }
  return numericValue(e);
}

// True when the node feeds a wider `*` chain — the outermost chain carries the flag, so inner
// sub-products and the constants inside a flagged chain never emit twice.
function insideMultiplication(node: ts.Node): boolean {
  let p: ts.Node | undefined = node.parent;
  while (p && ts.isParenthesizedExpression(p)) p = p.parent;
  return p !== undefined && isMultiplication(p);
}

function detectRawMsDateMath(sf: ts.SourceFile, path: string, nextId: NextId, depGateOpen: boolean): Finding[] {
  if (!depGateOpen) return [];
  const findings: Finding[] = [];
  const push = (node: ts.Node) => {
    const f = makeIndicator(nextId, sf, path, node, {
      title: "Looks hand-rolled: date math on raw millisecond constants — may be worth investigating",
      taxonomy: "M6 — Indicator: raw-millisecond date math",
      evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — computes a time span from raw millisecond arithmetic while a date library is already in the dependency tree (DST and calendar boundaries don't fit fixed offsets).`,
    });
    if (f) findings.push(f);
  };
  const visit = (node: ts.Node) => {
    if (isMultiplication(node) && !insideMultiplication(node)) {
      const product = literalChainProduct(node);
      if (product !== undefined && product >= MS_PER_HOUR && product % MS_PER_HOUR === 0) push(node);
    } else if (ts.isNumericLiteral(node) && !insideMultiplication(node) && MS_LITERALS.has(numericValue(node) ?? 0)) {
      push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 7. MIME-type lookup table (catalogue 41) ------------------------------------
// An object literal with several extension→content-type rows. Several are required so a single
// content-type constant (a header object, one Content-Type entry) never flags.

const MIME_VALUE_RE = /^(?:image|application|text|video|audio|font)\/[\w.+-]+$/;
const EXTENSION_KEY_RE = /^\.?[\w+-]{1,6}$/;

function propertyKeyText(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) return name.text;
  return undefined;
}

function detectMimeLookupTable(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isObjectLiteralExpression(node)) {
      const rows = node.properties.filter((p) => {
        if (!ts.isPropertyAssignment(p)) return false;
        const key = propertyKeyText(p.name);
        return (
          key !== undefined &&
          EXTENSION_KEY_RE.test(key) &&
          ts.isStringLiteralLike(p.initializer) &&
          MIME_VALUE_RE.test(p.initializer.text)
        );
      });
      if (rows.length >= 3) {
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: file-extension content-type table — may be worth investigating",
          taxonomy: "M6 — Indicator: MIME-type lookup table",
          evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — maps file extensions to content-type strings by hand (${rows.length} rows; types outside the table fall through).`,
        });
        if (f) findings.push(f);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 8. Currency via symbol + toFixed concat (catalogue 88) ----------------------

const CURRENCY_PREFIX_RE = /[$€£]\s*$/;
const CURRENCY_SUFFIX_RE = /^\s*[$€£]/;

function isToFixedCall(expr: ts.Expression): boolean {
  const e = unwrapParens(expr);
  return ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression) && e.expression.name.text === "toFixed";
}

function isStringLiteralNode(node: ts.Expression): node is ts.StringLiteralLike {
  return ts.isStringLiteralLike(node);
}

function detectCurrencyToFixed(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const push = (node: ts.Node) => {
    const f = makeIndicator(nextId, sf, path, node, {
      title: "Looks hand-rolled: currency formatting via symbol + toFixed concatenation — may be worth investigating",
      taxonomy: "M6 — Indicator: currency formatting",
      evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — formats money by gluing a currency symbol onto toFixed output (locale, grouping, and negative amounts are unhandled).`,
    });
    if (f) findings.push(f);
  };
  const visit = (node: ts.Node) => {
    if (ts.isTemplateExpression(node)) {
      const symbolThenToFixed = node.templateSpans.some((span, i) => {
        const before = i === 0 ? node.head.text : (node.templateSpans[i - 1] as ts.TemplateSpan).literal.text;
        return CURRENCY_PREFIX_RE.test(before) && isToFixedCall(span.expression);
      });
      if (symbolThenToFixed) push(node);
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = unwrapParens(node.left);
      const right = unwrapParens(node.right);
      if (
        (isStringLiteralNode(left) && CURRENCY_PREFIX_RE.test(left.text) && isToFixedCall(right)) ||
        (isToFixedCall(left) && isStringLiteralNode(right) && CURRENCY_SUFFIX_RE.test(right.text))
      ) {
        push(node);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 9. Email-shape validation regex (catalogue 81, dep-gated on zod) ------------
// Without a schema-validation library in the tree, a hand-written regex IS the standard
// approach — the gate keeps the class honest, exactly like class-merge and date math.

const EMAIL_SCHEMA_DEPS = ["zod"];
// A character class (or \S/\w) quantified into an @ — the spine of email-shaped regexes.
const EMAIL_REGEX_SPINE = /(?:\]|\\S|\\w)[+*]@/;

function detectEmailShapeRegex(sf: ts.SourceFile, path: string, nextId: NextId, depGateOpen: boolean): Finding[] {
  if (!depGateOpen) return [];
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isRegularExpressionLiteral(node) && EMAIL_REGEX_SPINE.test(node.text)) {
      const f = makeIndicator(nextId, sf, path, node, {
        title: "Looks hand-rolled: email-shape validation regex — may be worth investigating",
        taxonomy: "M6 — Indicator: email-shape regex",
        evidence: `\`${node.getText(sf).slice(0, 70)}\` — an email-shaped regex literal while a schema-validation library is already in the dependency tree (hand-written email regexes drift from the addresses they intend to accept).`,
      });
      if (f) findings.push(f);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 10. Manual date formatting via calendar getters (catalogue 29) --------------
// getFullYear()/getMonth()/getDate() co-occurring in ONE template or string-concat expression.
// The getters used separately (comparisons, standalone values) never flag.

const DATE_GETTERS = ["getFullYear", "getMonth", "getDate"];

function zeroArgCallNames(node: ts.Node): Set<string> {
  const names = new Set<string>();
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.arguments.length === 0) {
      names.add(n.expression.name.text);
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  return names;
}

function isPlusExpression(node: ts.Node): node is ts.BinaryExpression {
  return ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken;
}

function plusOperands(expr: ts.Expression, out: ts.Expression[]): void {
  const e = unwrapParens(expr);
  if (isPlusExpression(e)) {
    plusOperands(e.left, out);
    plusOperands(e.right, out);
  } else {
    out.push(e);
  }
}

function insidePlusChain(node: ts.Node): boolean {
  let p: ts.Node | undefined = node.parent;
  while (p && ts.isParenthesizedExpression(p)) p = p.parent;
  return p !== undefined && isPlusExpression(p);
}

function detectDateGetterFormat(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const push = (node: ts.Node) => {
    const f = makeIndicator(nextId, sf, path, node, {
      title: "Looks hand-rolled: date formatting via calendar-getter concatenation — may be worth investigating",
      taxonomy: "M6 — Indicator: manual date formatting",
      evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — assembles a date string from the year/month/day getters by hand (zero-based months, zero-padding, and locale order are all manual here).`,
    });
    if (f) findings.push(f);
  };
  const allGettersPresent = (node: ts.Node) => {
    const names = zeroArgCallNames(node);
    return DATE_GETTERS.every((g) => names.has(g));
  };
  const visit = (node: ts.Node) => {
    if (ts.isTemplateExpression(node) && allGettersPresent(node)) {
      push(node);
      return; // one flag per formatting expression
    }
    if (isPlusExpression(node) && !insidePlusChain(node)) {
      const operands: ts.Expression[] = [];
      plusOperands(node, operands);
      const isConcat = operands.some((o) => ts.isStringLiteralLike(o) || ts.isTemplateExpression(o));
      if (isConcat && allGettersPresent(node)) {
        push(node);
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 11. Query-string BUILDING via key=value joins (catalogue 37) ----------------
// The mirror of the shipped parse class: `.join("&")` over `.map(...)` callbacks that produce
// `k=v`-shaped strings. A join("&") over plain values (an ampersand-delimited list) never
// flags, and the parse shape (splits) is a different class entirely.

function isJoinOn(node: ts.Node, separator: string): node is ts.CallExpression {
  return (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "join" &&
    node.arguments.length === 1 &&
    ts.isStringLiteralLike(node.arguments[0] as ts.Expression) &&
    (node.arguments[0] as ts.StringLiteralLike).text === separator
  );
}

function returnedExpressions(fn: ts.ArrowFunction | ts.FunctionExpression): ts.Expression[] {
  if (ts.isArrowFunction(fn) && !ts.isBlock(fn.body)) return [fn.body];
  const out: ts.Expression[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isReturnStatement(n) && n.expression) out.push(n.expression);
    ts.forEachChild(n, visit);
  };
  visit(fn.body);
  return out;
}

function isKeyEqualsValueString(expr: ts.Expression): boolean {
  const e = unwrapParens(expr);
  if (ts.isTemplateExpression(e)) {
    return e.head.text.includes("=") || e.templateSpans.some((s) => s.literal.text.includes("="));
  }
  if (isPlusExpression(e)) {
    const operands: ts.Expression[] = [];
    plusOperands(e, operands);
    return operands.some((o) => ts.isStringLiteralLike(o) && o.text.includes("="));
  }
  return false;
}

function detectQueryStringBuild(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (isJoinOn(node, "&")) {
      const receiver = unwrapParens((node.expression as ts.PropertyAccessExpression).expression);
      const mapCallback =
        ts.isCallExpression(receiver) &&
        ts.isPropertyAccessExpression(receiver.expression) &&
        receiver.expression.name.text === "map" &&
        receiver.arguments.length >= 1
          ? receiver.arguments[0]
          : undefined;
      if (
        mapCallback !== undefined &&
        (ts.isArrowFunction(mapCallback) || ts.isFunctionExpression(mapCallback)) &&
        returnedExpressions(mapCallback).some(isKeyEqualsValueString)
      ) {
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: query-string building via key=value joins — may be worth investigating",
          taxonomy: "M6 — Indicator: query-string building",
          evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — assembles a query string by joining key=value templates on "&" (encoding and repeated-key handling are easy to get wrong).`,
        });
        if (f) findings.push(f);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 12. base64url conversion via replace chain (catalogue 42) -------------------
// The +/− and /→_ alphabet swaps (plus padding strips) beside btoa/atob or base64 context.
// One statement = one finding: two swaps in a statement are self-evidencing; a single swap
// needs base64 context in the same statement, so a lone slug/URL replace never flags.

function replaceSwapOf(node: ts.Node): [string, string] | undefined {
  if (
    !ts.isCallExpression(node) ||
    !ts.isPropertyAccessExpression(node.expression) ||
    !["replace", "replaceAll"].includes(node.expression.name.text) ||
    node.arguments.length !== 2 ||
    !ts.isStringLiteralLike(node.arguments[1] as ts.Expression)
  ) {
    return undefined;
  }
  const target = node.arguments[0] as ts.Expression;
  const replacement = (node.arguments[1] as ts.StringLiteralLike).text;
  if (ts.isRegularExpressionLiteral(target)) {
    const source = target.text.slice(1, target.text.lastIndexOf("/"));
    return [source, replacement];
  }
  if (ts.isStringLiteralLike(target)) return [target.text, replacement];
  return undefined;
}

function isBase64AlphabetSwap(source: string, replacement: string): boolean {
  return (
    ((source === "\\+" || source === "+") && replacement === "-") ||
    ((source === "\\/" || source === "/") && replacement === "_") ||
    (source === "-" && replacement === "+") ||
    (source === "_" && replacement === "/") ||
    (/^=+\$?$|^=\{1,2\}\$$/.test(source) && replacement === "")
  );
}

function detectBase64UrlChain(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const swapsByStatement = new Map<ts.Node, ts.Node[]>();
  const visit = (node: ts.Node) => {
    const swap = replaceSwapOf(node);
    if (swap && isBase64AlphabetSwap(swap[0], swap[1])) {
      const stmt = enclosingStatement(node);
      const list = swapsByStatement.get(stmt) ?? [];
      list.push(node);
      swapsByStatement.set(stmt, list);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  const findings: Finding[] = [];
  for (const [stmt, swaps] of swapsByStatement) {
    if (swaps.length >= 2 || /\batob\(|\bbtoa\(|base64/i.test(stmt.getText(sf))) {
      const anchor = swaps[0] as ts.Node;
      const f = makeIndicator(nextId, sf, path, anchor, {
        title: "Looks hand-rolled: URL-safe base64 conversion via replace chain — may be worth investigating",
        taxonomy: "M6 — Indicator: base64url conversion",
        evidence: `\`${stmt.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — converts between the standard and URL-safe base64 alphabets by character replacement (padding and alphabet edge cases are easy to get wrong).`,
      });
      if (f) findings.push(f);
    }
  }
  return findings;
}

// --- 13. Cookie serialization by hand (catalogue 52) -----------------------------
// Building cookie/Set-Cookie strings with attribute literals (`; Path=`, `; Max-Age=`,
// `; HttpOnly`, …). The shipped cookie-parsing class covers reads; this covers writes — an
// attribute literal used to PROBE an existing cookie string (includes/startsWith/split/…)
// stays the parse side's territory and never fires here.

const COOKIE_ATTR_RE = /;\s*(?:path|max-age|expires|domain|samesite)=|;\s*(?:httponly|secure)\b/i;
const STRING_PROBE_METHODS = new Set([
  "includes",
  "startsWith",
  "endsWith",
  "indexOf",
  "lastIndexOf",
  "split",
  "match",
  "matchAll",
  "search",
  "replace",
  "replaceAll",
  "test",
]);

function stringChunksOf(node: ts.Node): string[] | undefined {
  if (ts.isTemplateExpression(node)) return [node.head.text, ...node.templateSpans.map((s) => s.literal.text)];
  if (ts.isStringLiteralLike(node)) return [node.text];
  return undefined;
}

function isProbeArgument(node: ts.Node): boolean {
  const parent = node.parent;
  return (
    ts.isCallExpression(parent) &&
    parent.arguments.some((a) => a === node) &&
    ts.isPropertyAccessExpression(parent.expression) &&
    STRING_PROBE_METHODS.has(parent.expression.name.text)
  );
}

function detectCookieSerialize(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const flaggedStatements = new Set<ts.Node>();
  const visit = (node: ts.Node) => {
    const chunks = stringChunksOf(node);
    if (chunks?.some((c) => COOKIE_ATTR_RE.test(c)) && !isProbeArgument(node)) {
      const stmt = enclosingStatement(node);
      if (!flaggedStatements.has(stmt)) {
        flaggedStatements.add(stmt);
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: cookie-header serialization — may be worth investigating",
          taxonomy: "M6 — Indicator: cookie serialization",
          evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — builds a cookie string with attribute literals by hand (attribute rules, encoding, and expiry formats are easy to get wrong).`,
        });
        if (f) findings.push(f);
      }
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
  const classMergeGateOpen = depGatePresent(files, CLASS_MERGE_DEPS);
  const dateMathGateOpen = depGatePresent(files, DATE_MATH_DEPS);
  const emailRegexGateOpen = depGatePresent(files, EMAIL_SCHEMA_DEPS);
  const findings: Finding[] = [];
  for (const f of files) {
    if (!/\.(ts|tsx|jsx|mjs)$/.test(f.path)) continue;
    const sf = parse(f.path, f.text);
    findings.push(
      ...detectJsonStringifyEquality(sf, f.path, nextId),
      ...detectQueryStringParse(sf, f.path, nextId),
      ...detectCookieParse(sf, f.path, nextId),
      ...detectRandomStringId(sf, f.path, nextId),
      ...detectClassMerge(sf, f.path, nextId, classMergeGateOpen),
      // Batch 2 (#406 item 2), in measured corpus order:
      ...detectRawMsDateMath(sf, f.path, nextId, dateMathGateOpen),
      ...detectMimeLookupTable(sf, f.path, nextId),
      ...detectCurrencyToFixed(sf, f.path, nextId),
      ...detectEmailShapeRegex(sf, f.path, nextId, emailRegexGateOpen),
      ...detectDateGetterFormat(sf, f.path, nextId),
      ...detectQueryStringBuild(sf, f.path, nextId),
      ...detectBase64UrlChain(sf, f.path, nextId),
      ...detectCookieSerialize(sf, f.path, nextId),
    );
  }
  return findings;
}
