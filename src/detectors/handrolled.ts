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

// --- Batch 3 (#542): the eight organic-AI-tier YES entries -----------------------
// Graduated from docs/design/m6-handrolled-catalogue.md after #413/#543 measured them firing on
// organic AI-generated code (docs/design/m6-corpus-frequency.md, AI-tier section). Entry 76
// (Supabase storage public-URL concat) is deliberately NOT here — its only evidence is the curated
// teardown repo, so it stays a YES-not-yet-graduated candidate. Three entries carry a "+ M1 check"
// in the catalogue (27 weak-hash inputs, 53 authz-gating decoded claims, 98 HTML sink): those are
// paid/semantic-tier yield conditions on the INPUTS, not a mechanical double-count — verified
// 2026-07-18 that no M1 semgrep/AST rule fires on these exact hand-rolled shapes (semgrep
// weak-hash targets named md5/sha1 inputs; the JWT rule targets alg:none, not a hand-rolled
// decode; XSS targets the dangerouslySetInnerHTML sink, not the replace). The M6 indicator stays
// descriptive on the shape.

// A CallExpression `Obj.method()` anywhere in the subtree (used for composite-id + hash-loop).
function subtreeHasCall(node: ts.Node, obj: string, method: string): boolean {
  let found = false;
  const v = (n: ts.Node) => {
    if (found) return;
    if (
      ts.isCallExpression(n) &&
      ts.isPropertyAccessExpression(n.expression) &&
      ts.isIdentifier(n.expression.expression) &&
      n.expression.expression.text === obj &&
      n.expression.name.text === method
    ) {
      found = true;
      return;
    }
    ts.forEachChild(n, v);
  };
  v(node);
  return found;
}

function subtreeHas(node: ts.Node, pred: (n: ts.Node) => boolean): boolean {
  let found = false;
  const v = (n: ts.Node) => {
    if (found) return;
    if (pred(n)) {
      found = true;
      return;
    }
    ts.forEachChild(n, v);
  };
  v(node);
  return found;
}

// --- 14. Array-unique via filter + indexOf self-compare (catalogue 3) ------------
// `arr.filter((v, i, a) => a.indexOf(v) === i)` — the three-arg callback comparing the array's
// indexOf back to the element index. A two-arg filter or a different predicate never flags.

function isIndexOfSelfCompare(expr: ts.Expression, val: string, idx: string, arr: string): boolean {
  const e = unwrapParens(expr);
  if (!ts.isBinaryExpression(e) || !EQUALITY_OPS.has(e.operatorToken.kind)) return false;
  const indexOfOf = (side: ts.Expression) => {
    const s = unwrapParens(side);
    return (
      ts.isCallExpression(s) &&
      ts.isPropertyAccessExpression(s.expression) &&
      s.expression.name.text === "indexOf" &&
      ts.isIdentifier(s.expression.expression) &&
      s.expression.expression.text === arr &&
      s.arguments.length >= 1 &&
      ts.isIdentifier(s.arguments[0] as ts.Expression) &&
      (s.arguments[0] as ts.Identifier).text === val
    );
  };
  const isIdx = (side: ts.Expression) => {
    const s = unwrapParens(side);
    return ts.isIdentifier(s) && s.text === idx;
  };
  return (indexOfOf(e.left) && isIdx(e.right)) || (indexOfOf(e.right) && isIdx(e.left));
}

function detectFilterIndexOfUnique(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "filter" &&
      node.arguments.length === 1
    ) {
      const cb = node.arguments[0] as ts.Expression;
      if ((ts.isArrowFunction(cb) || ts.isFunctionExpression(cb)) && cb.parameters.length === 3) {
        const names = cb.parameters.map((p) => (ts.isIdentifier(p.name) ? p.name.text : undefined));
        const [v, i, a] = names;
        if (v && i && a && returnedExpressions(cb).some((r) => isIndexOfSelfCompare(r, v, i, a))) {
          const f = makeIndicator(nextId, sf, path, node, {
            title: "Looks hand-rolled: array de-duplication via filter + indexOf — may be worth investigating",
            taxonomy: "M6 — Indicator: array-unique via filter",
            evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — de-duplicates by scanning for each element's first index (quadratic, and NaN/object identity behave surprisingly).`,
          });
          if (f) findings.push(f);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 15. Composite timestamp + random id (catalogue 24) --------------------------
// A template or string-concat expression combining Date.now() with Math.random() in one shape.
// Either call alone (a bare timestamp, a standalone random number) never flags.

function detectCompositeTimestampId(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const push = (node: ts.Node) => {
    const f = makeIndicator(nextId, sf, path, node, {
      title: "Looks hand-rolled: composite id from a timestamp and Math.random() — may be worth investigating",
      taxonomy: "M6 — Indicator: composite timestamp-random id",
      evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — builds an identifier by gluing Date.now() to Math.random(), which is neither collision-safe nor unpredictable.`,
    });
    if (f) findings.push(f);
  };
  const visit = (node: ts.Node) => {
    const combining =
      ts.isTemplateExpression(node) || (isPlusExpression(node) && !insidePlusChain(node));
    if (combining && subtreeHasCall(node, "Date", "now") && subtreeHasCall(node, "Math", "random")) {
      push(node);
      return; // the combining node carries the flag; don't double-count nested spans
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 16. Non-crypto string-hash loop (catalogue 27, + M1 check) ------------------
// A `<< 5` or `* 31` accumulate co-occurring with charCodeAt in the same scope — the djb2/FNV/
// java-31 shape. The co-occurrence guard keeps a bare `days * 31` (no charCodeAt in scope) silent.
// One flag per enclosing scope.

function multiplyByOrShift(node: ts.Node): boolean {
  if (!ts.isBinaryExpression(node)) return false;
  if (node.operatorToken.kind === ts.SyntaxKind.LessThanLessThanToken) {
    return numericValue(unwrapParens(node.right)) === 5;
  }
  if (node.operatorToken.kind === ts.SyntaxKind.AsteriskToken) {
    return numericValue(unwrapParens(node.left)) === 31 || numericValue(unwrapParens(node.right)) === 31;
  }
  return false;
}

function detectNonCryptoHash(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const flaggedScopes = new Set<ts.Node>();
  const isCharCodeAt = (n: ts.Node) =>
    ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "charCodeAt";
  const visit = (node: ts.Node) => {
    if (multiplyByOrShift(node)) {
      const scope = enclosingScope(node);
      if (!flaggedScopes.has(scope) && subtreeHas(scope, isCharCodeAt)) {
        flaggedScopes.add(scope);
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: non-cryptographic string hash loop — may be worth investigating",
          taxonomy: "M6 — Indicator: non-crypto string hash",
          evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — accumulates a hash over character codes by shift/multiply (collision-prone, and not a cryptographic digest).`,
        });
        if (f) findings.push(f);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 17. Month/day-name literal arrays (catalogue 30) ----------------------------
// An array literal carrying >= 3 month names or >= 3 day names spelled out as string literals.

const MONTH_NAMES = new Set([
  "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december",
  "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec",
]);
const DAY_NAMES = new Set([
  "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
  "sun", "mon", "tue", "tues", "wed", "thu", "thur", "thurs", "fri", "sat",
]);

function detectNameArrays(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isArrayLiteralExpression(node)) {
      const lits = node.elements.filter(ts.isStringLiteralLike).map((e) => e.text.trim().toLowerCase());
      const months = lits.filter((t) => MONTH_NAMES.has(t)).length;
      const days = lits.filter((t) => DAY_NAMES.has(t)).length;
      if (months >= 3 || days >= 3) {
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: month/day-name literal array — may be worth investigating",
          taxonomy: "M6 — Indicator: month/day-name array",
          evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — spells out calendar names as string literals (locale and ordering are then all manual).`,
        });
        if (f) findings.push(f);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 18. JWT payload decode by hand (catalogue 53, + M1 check) --------------------
// JSON.parse over an atob/Buffer decode of a `token.split(".")[n]` segment — the three-step
// by-hand decode. Any single step alone stays silent (a file-extension split, a plain JSON.parse,
// a bare atob). The authz half (trusting unverified claims) is M1's; this notes only the decode.

function isSplitDotIndex(node: ts.Node): boolean {
  if (!ts.isElementAccessExpression(node) || !ts.isNumericLiteral(node.argumentExpression)) return false;
  const call = node.expression;
  return (
    ts.isCallExpression(call) &&
    ts.isPropertyAccessExpression(call.expression) &&
    call.expression.name.text === "split" &&
    call.arguments.length >= 1 &&
    ts.isStringLiteralLike(call.arguments[0] as ts.Expression) &&
    (call.arguments[0] as ts.StringLiteralLike).text === "."
  );
}

function isBase64Decode(node: ts.Node): boolean {
  if (!ts.isCallExpression(node)) return false;
  if (ts.isIdentifier(node.expression) && node.expression.text === "atob") return true;
  return (
    ts.isPropertyAccessExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === "Buffer" &&
    node.expression.name.text === "from"
  );
}

function detectJwtDecodeByHand(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (isJsonCall(node, "parse") && node.arguments.length >= 1) {
      const arg = node.arguments[0] as ts.Node;
      if (subtreeHas(arg, isSplitDotIndex) && subtreeHas(arg, isBase64Decode)) {
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: token payload decoded by hand — may be worth investigating",
          taxonomy: "M6 — Indicator: JWT decode by hand",
          evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — splits a token on ".", base64-decodes a segment, and parses it as JSON, with no signature verification.`,
        });
        if (f) findings.push(f);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 19. Hand-rolled ErrorBoundary class (catalogue 61) --------------------------
// A class carrying the React error-boundary lifecycle members (componentDidCatch /
// getDerivedStateFromError) — near-unique to error boundaries.

const ERROR_BOUNDARY_MEMBERS = new Set(["componentDidCatch", "getDerivedStateFromError"]);

function detectErrorBoundaryClass(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isClassLike(node)) {
      const isBoundary = node.members.some(
        (m) => m.name !== undefined && ts.isIdentifier(m.name) && ERROR_BOUNDARY_MEMBERS.has(m.name.text),
      );
      if (isBoundary) {
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: React error-boundary class — may be worth investigating",
          taxonomy: "M6 — Indicator: hand-rolled ErrorBoundary",
          evidence: `a class implementing the error-boundary lifecycle members by hand (framework and library error boundaries already handle the reset and fallback edges).`,
        });
        if (f) findings.push(f);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 20. Markdown-to-HTML via regex replaces (catalogue 98, + M1 check) -----------
// A .replace/.replaceAll whose replacement literal emits an HTML tag (<strong>/<em>/<h1..6>/
// <blockquote>) — the by-hand markdown converter. If the result feeds an HTML sink the XSS half
// is M1's; this notes only the hand-rolled conversion.

const MD_HTML_TAG_RE = /<\/?(?:strong|em|h[1-6]|blockquote)\b/i;

function detectMarkdownToHtml(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      (node.expression.name.text === "replace" || node.expression.name.text === "replaceAll") &&
      node.arguments.length === 2
    ) {
      const chunks = stringChunksOf(node.arguments[1] as ts.Expression);
      if (chunks?.some((c) => MD_HTML_TAG_RE.test(c))) {
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: markdown-to-HTML via string replace — may be worth investigating",
          taxonomy: "M6 — Indicator: markdown-to-HTML by regex",
          evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — emits HTML tags from a string replace (nesting, escaping, and — if rendered as HTML — injection are all unhandled here).`,
        });
        if (f) findings.push(f);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 21. Thousands-separator lookahead regex (catalogue 89) ----------------------
// The byte-exact `(\d{3})+(?!\d)` fragment — the copy-pasted Stack Overflow grouping regex.

const THOUSANDS_REGEX_RE = /\(\\d\{3\}\)\+\(\?!\\d\)/;

function detectThousandsRegex(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isRegularExpressionLiteral(node) && THOUSANDS_REGEX_RE.test(node.text)) {
      const f = makeIndicator(nextId, sf, path, node, {
        title: "Looks hand-rolled: thousands-separator grouping regex — may be worth investigating",
        taxonomy: "M6 — Indicator: thousands-separator regex",
        evidence: `\`${node.getText(sf).slice(0, 70)}\` — inserts digit-group separators with a lookahead regex (locale grouping and decimals are unhandled).`,
      });
      if (f) findings.push(f);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- Batch 4 (#628): the remaining measured-zero YES entries + the Vite env idiom ---
// Operator un-gate 2026-07-19 (#413 comment): the measure-before-graduate rule was circular
// (a pattern's frequency can't be measured without a detector) and corpus-bounded. New rule:
// build any plausible catalogued YES shape and gate on PRECISION — a paired negative fixture and
// no false-fire on the existing calibration corpus — not on corpus-frequency. Zero corpus
// positives is expected and fine. These graduate the 9 YES entries still standing after batch 3
// (4, 11, 13, 16, 23, 44, 68, 76, 95) plus #628's two Vite/no-code idioms: the import.meta.env
// coercion shape and the hand-rolled react-router route guard (the SPA ProtectedRoute idiom).
// Every class keeps the free-tier discipline: hedged, Info, never naming a replacement
// (vocabulary-locked).

// A bare-identifier call `name(...)` anywhere in the subtree (fetch(), setTimeout ref).
function subtreeHasIdentifierCall(node: ts.Node, name: string): boolean {
  return subtreeHas(node, (n) => ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === name);
}

function subtreeHasIdentifier(node: ts.Node, name: string): boolean {
  return subtreeHas(node, (n) => ts.isIdentifier(n) && n.text === name);
}

// --- 22. Array flatten via reduce + concat (catalogue 4) -------------------------
// arr.reduce((a, b) => a.concat(b), []) — the two-param callback whose returned body is a bare
// `a.concat(b)` over an empty-array seed. A non-empty seed, a different body, or Buffer.concat
// (a static-member call, not a param.concat(param)) never flags.

function isConcatOfParams(expr: ts.Expression, accName: string, itemName: string): boolean {
  const e = unwrapParens(expr);
  return (
    ts.isCallExpression(e) &&
    ts.isPropertyAccessExpression(e.expression) &&
    e.expression.name.text === "concat" &&
    ts.isIdentifier(e.expression.expression) &&
    e.expression.expression.text === accName &&
    e.arguments.length === 1 &&
    ts.isIdentifier(e.arguments[0] as ts.Expression) &&
    (e.arguments[0] as ts.Identifier).text === itemName
  );
}

function detectReduceConcatFlatten(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "reduce" &&
      node.arguments.length === 2 &&
      ts.isArrayLiteralExpression(node.arguments[1] as ts.Expression) &&
      (node.arguments[1] as ts.ArrayLiteralExpression).elements.length === 0
    ) {
      const cb = node.arguments[0] as ts.Expression;
      if ((ts.isArrowFunction(cb) || ts.isFunctionExpression(cb)) && cb.parameters.length === 2) {
        const [acc, item] = cb.parameters.map((p) => (ts.isIdentifier(p.name) ? p.name.text : undefined));
        if (acc && item && returnedExpressions(cb).some((r) => isConcatOfParams(r, acc, item))) {
          const f = makeIndicator(nextId, sf, path, node, {
            title: "Looks hand-rolled: array flattening via reduce + concat — may be worth investigating",
            taxonomy: "M6 — Indicator: array flatten via reduce",
            evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — flattens a nested array by reducing with concat over an empty-array seed (a new array is allocated at each step).`,
          });
          if (f) findings.push(f);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 23. Shuffle via a random sort comparator (catalogue 11) ---------------------
// arr.sort(() => Math.random() - 0.5) and its sign variants — any .sort() whose comparator body
// calls Math.random(). No legitimate ordering comparator uses randomness, so the call inside the
// comparator is the whole signature; an ordinary numeric comparator never flags.

function detectShuffleSort(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "sort" &&
      node.arguments.length === 1
    ) {
      const cb = node.arguments[0] as ts.Expression;
      if ((ts.isArrowFunction(cb) || ts.isFunctionExpression(cb)) && subtreeHasCall(cb, "Math", "random")) {
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: array shuffle via a random sort comparator — may be worth investigating",
          taxonomy: "M6 — Indicator: random-comparator shuffle",
          evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — shuffles by sorting with a Math.random() comparator (the resulting order is biased and engine-dependent).`,
        });
        if (f) findings.push(f);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 24. Zero-padding via string concat + negative slice (catalogue 13) ----------
// ("0" + n).slice(-2), ("00" + x).slice(-3) — a .slice(negative) on a parenthesized concatenation
// whose leftmost operand is a string of only "0"s. A slice on other strings, or a positive slice,
// never flags.

function leftmostConcatOperand(expr: ts.Expression): ts.Expression {
  let e = unwrapParens(expr);
  while (isPlusExpression(e)) e = unwrapParens(e.left);
  return e;
}

function isNegativeNumericArg(node: ts.Expression): boolean {
  return (
    ts.isPrefixUnaryExpression(node) &&
    node.operator === ts.SyntaxKind.MinusToken &&
    ts.isNumericLiteral(node.operand)
  );
}

function detectZeroPadSlice(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "slice" &&
      node.arguments.length === 1 &&
      isNegativeNumericArg(node.arguments[0] as ts.Expression)
    ) {
      const receiver = unwrapParens(node.expression.expression);
      if (isPlusExpression(receiver)) {
        const lead = leftmostConcatOperand(receiver);
        if (ts.isStringLiteralLike(lead) && /^0+$/.test(lead.text)) {
          const f = makeIndicator(nextId, sf, path, node, {
            title: "Looks hand-rolled: zero-padding via string concatenation and slice — may be worth investigating",
            taxonomy: "M6 — Indicator: zero-pad via slice",
            evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — pads a value to a fixed width by prepending zeros and slicing (values wider than the prefix silently truncate).`,
          });
          if (f) findings.push(f);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 25. Nested-path get via split(".").reduce (catalogue 16, dep-gated) ---------
// path.split(".").reduce((o, k) => o?.[k], obj) — a .reduce whose receiver is a .split(".") call.
// Dep-gated on a path-access helper family: with none in the tree there is no stdlib form for a
// DYNAMIC path, so hand-rolling the walk is the deliberate dep-drop shape, not a reinvention.

const PATH_GET_DEPS = ["lodash", "lodash.get", "es-toolkit", "dlv", "get-value", "just-safe-get"];

function isSplitDotCall(node: ts.Node): boolean {
  return (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "split" &&
    node.arguments.length >= 1 &&
    ts.isStringLiteralLike(node.arguments[0] as ts.Expression) &&
    (node.arguments[0] as ts.StringLiteralLike).text === "."
  );
}

function detectPathGetReduce(sf: ts.SourceFile, path: string, nextId: NextId, gateOpen: boolean): Finding[] {
  if (!gateOpen) return [];
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "reduce" &&
      isSplitDotCall(unwrapParens(node.expression.expression))
    ) {
      const f = makeIndicator(nextId, sf, path, node, {
        title: "Looks hand-rolled: nested property access via a dotted-path split + reduce — may be worth investigating",
        taxonomy: "M6 — Indicator: nested-path get via split/reduce",
        evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — walks a dotted path string to read a nested property by hand while a helper for this is already in the dependency tree (missing keys and array indices are unhandled).`,
      });
      if (f) findings.push(f);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 26. Placeholder-template id string (catalogue 23) ---------------------------
// The 8-4-4-4-12 hyphenated placeholder template ('xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx') that is
// character-replaced into an id. The shape guard (all x/y/hex, plus >= 8 literal 'x' characters)
// separates the placeholder template from a real hex id string, which carries no 'x'.

const ID_TEMPLATE_SHAPE = /^[0-9a-fxy]{8}-[0-9a-fxy]{4}-[0-9a-fxy]{4}-[0-9a-fxy]{4}-[0-9a-fxy]{12}$/i;

function detectIdTemplate(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isStringLiteralLike(node)) {
      const t = node.text;
      if (ID_TEMPLATE_SHAPE.test(t) && (t.match(/x/gi)?.length ?? 0) >= 8) {
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: id built from an 'xxxx' placeholder template — may be worth investigating",
          taxonomy: "M6 — Indicator: placeholder-template id",
          evidence: `\`${node.getText(sf).slice(0, 70)}\` — generates an identifier by replacing placeholder characters in a template string (the result is not collision-resistant).`,
        });
        if (f) findings.push(f);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 27. fetch timeout via Promise.race (catalogue 44) ---------------------------
// Promise.race([fetch(...), <setTimeout-based promise>]) — a Promise.race over an array whose
// subtree contains both a fetch() call and a setTimeout reference. Promise.all, or a race without
// both a fetch and a timer, never flags.

function isPromiseRace(node: ts.Node): node is ts.CallExpression {
  return (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === "Promise" &&
    node.expression.name.text === "race"
  );
}

function detectFetchTimeoutRace(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (isPromiseRace(node) && node.arguments.length >= 1 && ts.isArrayLiteralExpression(node.arguments[0] as ts.Expression)) {
      const arr = node.arguments[0] as ts.ArrayLiteralExpression;
      if (subtreeHasIdentifierCall(arr, "fetch") && subtreeHasIdentifier(arr, "setTimeout")) {
        const f = makeIndicator(nextId, sf, path, node, {
          title: "Looks hand-rolled: fetch timeout via Promise.race against a timer — may be worth investigating",
          taxonomy: "M6 — Indicator: fetch timeout via Promise.race",
          evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — imposes a request timeout by racing fetch against a setTimeout promise (the underlying request keeps running after the timeout).`,
        });
        if (f) findings.push(f);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 28. JSON.parse of a process.env value (catalogue 68, dep-gated) --------------
// JSON.parse(process.env.X) — parsing structured config out of an environment variable by hand.
// Dep-gated on a schema-validation library: with none in the tree, a by-hand parse is the ordinary
// approach, so the gate stays shut.

const ENV_SCHEMA_DEPS = ["zod", "valibot", "@t3-oss/env-core", "@t3-oss/env-nextjs", "envalid", "znv"];

function referencesProcessEnv(node: ts.Node): boolean {
  return subtreeHas(
    node,
    (n) =>
      ts.isPropertyAccessExpression(n) &&
      n.name.text === "env" &&
      ts.isIdentifier(n.expression) &&
      n.expression.text === "process",
  );
}

function detectEnvJsonParse(sf: ts.SourceFile, path: string, nextId: NextId, gateOpen: boolean): Finding[] {
  if (!gateOpen) return [];
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (isJsonCall(node, "parse") && node.arguments.length >= 1 && referencesProcessEnv(node.arguments[0] as ts.Node)) {
      const f = makeIndicator(nextId, sf, path, node, {
        title: "Looks hand-rolled: configuration parsed from an environment variable by hand — may be worth investigating",
        taxonomy: "M6 — Indicator: env JSON parsing",
        evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — parses JSON out of a process environment variable while a schema-validation library is already in the dependency tree (a malformed value throws at the parse with nothing validated).`,
      });
      if (f) findings.push(f);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 29. Vite env value coerced/validated by hand (#628) -------------------------
// Hand-rolled coercion of an import.meta.env value: a `=== "true"`/`=== "false"` boolean coercion,
// or a Number()/parseInt()/parseFloat()/JSON.parse() over an import.meta.env member. A BARE read
// (`apiKey: import.meta.env.VITE_X`) — the correct way to read Vite env — never flags, and a MODE
// check against a non-boolean literal never flags. Dep-gated on a schema-validation library.

const ENV_COERCE_FNS = new Set(["Number", "parseInt", "parseFloat"]);
const BOOL_STRING_RE = /^(?:true|false)$/i;

function isImportMetaEnvMember(e: ts.Expression): boolean {
  const u = unwrapParens(e);
  const base = ts.isPropertyAccessExpression(u) || ts.isElementAccessExpression(u) ? u.expression : undefined;
  return (
    base !== undefined &&
    ts.isPropertyAccessExpression(base) &&
    base.name.text === "env" &&
    ts.isMetaProperty(base.expression) &&
    base.expression.keywordToken === ts.SyntaxKind.ImportKeyword
  );
}

function detectViteEnvCoercion(sf: ts.SourceFile, path: string, nextId: NextId, gateOpen: boolean): Finding[] {
  if (!gateOpen) return [];
  const findings: Finding[] = [];
  const push = (node: ts.Node) => {
    const f = makeIndicator(nextId, sf, path, node, {
      title: "Looks hand-rolled: environment value coerced or validated by hand — may be worth investigating",
      taxonomy: "M6 — Indicator: Vite env coercion",
      evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — coerces or parses a build-time environment value by hand while a schema-validation library is already in the dependency tree (types, ranges, and defaults go unchecked).`,
    });
    if (f) findings.push(f);
  };
  const visit = (node: ts.Node) => {
    if (ts.isBinaryExpression(node) && EQUALITY_OPS.has(node.operatorToken.kind)) {
      const l = unwrapParens(node.left);
      const r = unwrapParens(node.right);
      const boolStr = (x: ts.Expression) => ts.isStringLiteralLike(x) && BOOL_STRING_RE.test(x.text);
      if ((isImportMetaEnvMember(l) && boolStr(r)) || (isImportMetaEnvMember(r) && boolStr(l))) push(node);
    } else if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      ENV_COERCE_FNS.has(node.expression.text) &&
      node.arguments.length >= 1 &&
      isImportMetaEnvMember(node.arguments[0] as ts.Expression)
    ) {
      push(node);
    } else if (isJsonCall(node, "parse") && node.arguments.length >= 1 && isImportMetaEnvMember(node.arguments[0] as ts.Expression)) {
      push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- 30. Storage object URL built by concatenation (catalogue 76) ----------------
// The Supabase-specific `/storage/v1/object/public/` path literal assembled into a URL by
// interpolation or `+` concat. A standalone complete URL literal (no interpolation) stays silent
// — the reinvention is BUILDING the URL, not mentioning the path.

const STORAGE_PUBLIC_URL_RE = /\/storage\/v1\/object\/public\//;

function detectStoragePublicUrl(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const push = (node: ts.Node) => {
    const f = makeIndicator(nextId, sf, path, node, {
      title: "Looks hand-rolled: storage object URL built by string concatenation — may be worth investigating",
      taxonomy: "M6 — Indicator: storage object URL concat",
      evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — assembles a storage object URL from the fixed \`/storage/v1/object/public/\` path by hand (bucket names and path encoding are manual here).`,
    });
    if (f) findings.push(f);
  };
  const visit = (node: ts.Node) => {
    if (ts.isTemplateExpression(node)) {
      // The path must sit in a chunk FOLLOWED by an interpolation — the URL-building signal (a
      // dynamic bucket/path segment). The trailing chunk (prose after the last ${}) is excluded,
      // so an English sentence that merely mentions the path never flags.
      const followedChunks = [node.head.text, ...node.templateSpans.slice(0, -1).map((s) => s.literal.text)];
      if (followedChunks.some((c) => STORAGE_PUBLIC_URL_RE.test(c))) {
        push(node);
        return;
      }
    } else if (isPlusExpression(node) && !insidePlusChain(node)) {
      const operands: ts.Expression[] = [];
      plusOperands(node, operands);
      // The path literal must be followed by another operand (the dynamic segment being appended),
      // not be the final operand of the concatenation.
      const idx = operands.findIndex((o) => ts.isStringLiteralLike(o) && STORAGE_PUBLIC_URL_RE.test(o.text));
      if (idx >= 0 && idx < operands.length - 1) {
        push(node);
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// Catalogue item "hand-rolled SPA route guard" (#628 follow-up, #638): attempted and RETIRED, not
// shipped as an indicator. #654 briefly shipped a ProtectedRoute/RequireAuth detector (a component
// conditionally redirecting with <Navigate> and otherwise rendering children/<Outlet>), but #638's
// analysis found that shape has no framework/stdlib primitive it reinvents — react-router ships no
// built-in guard component, so composing one from <Navigate>/<Outlet> is exactly the idiomatic,
// documented way to gate a route, not a hand-rolled reinvention. Flagging it would false-fire on
// ordinary idiomatic react-router use. Recorded EXCLUDED in docs/design/m6-handrolled-catalogue.md.

// --- 31. Clipboard copy via deprecated execCommand (catalogue 95) ----------------
// document.execCommand("copy"|"cut") — the deprecated clipboard path (needs a hidden element and
// focus juggling). execCommand with any other argument (rich-text editing: "bold", …) never flags.

const EXEC_COMMAND_CLIPBOARD = new Set(["copy", "cut"]);

function detectClipboardExecCommand(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "execCommand" &&
      node.arguments.length >= 1 &&
      ts.isStringLiteralLike(node.arguments[0] as ts.Expression) &&
      EXEC_COMMAND_CLIPBOARD.has((node.arguments[0] as ts.StringLiteralLike).text.toLowerCase())
    ) {
      const f = makeIndicator(nextId, sf, path, node, {
        title: "Looks hand-rolled: clipboard copy via a deprecated command — may be worth investigating",
        taxonomy: "M6 — Indicator: clipboard via execCommand",
        evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 70)}\` — copies text through the deprecated execCommand path (which needs a hidden element and focus juggling and is unsupported on newer browsers).`,
      });
      if (f) findings.push(f);
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
  const pathGetGateOpen = depGatePresent(files, PATH_GET_DEPS);
  const envSchemaGateOpen = depGatePresent(files, ENV_SCHEMA_DEPS);
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
      // Batch 3 (#542): the eight organic-AI-tier YES entries (docs/design/m6-corpus-frequency.md):
      ...detectFilterIndexOfUnique(sf, f.path, nextId),
      ...detectCompositeTimestampId(sf, f.path, nextId),
      ...detectNonCryptoHash(sf, f.path, nextId),
      ...detectNameArrays(sf, f.path, nextId),
      ...detectJwtDecodeByHand(sf, f.path, nextId),
      ...detectErrorBoundaryClass(sf, f.path, nextId),
      ...detectMarkdownToHtml(sf, f.path, nextId),
      ...detectThousandsRegex(sf, f.path, nextId),
      // Batch 4 (#628): the remaining measured-zero YES entries + the Vite env idiom:
      ...detectReduceConcatFlatten(sf, f.path, nextId),
      ...detectShuffleSort(sf, f.path, nextId),
      ...detectZeroPadSlice(sf, f.path, nextId),
      ...detectPathGetReduce(sf, f.path, nextId, pathGetGateOpen),
      ...detectIdTemplate(sf, f.path, nextId),
      ...detectFetchTimeoutRace(sf, f.path, nextId),
      ...detectEnvJsonParse(sf, f.path, nextId, envSchemaGateOpen),
      ...detectViteEnvCoercion(sf, f.path, nextId, envSchemaGateOpen),
      ...detectStoragePublicUrl(sf, f.path, nextId),
      ...detectClipboardExecCommand(sf, f.path, nextId),
    );
  }
  return findings;
}
