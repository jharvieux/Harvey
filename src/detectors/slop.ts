// M5 (slop) — mechanical AI-slop detectors over TypeScript/TSX source. Harvey had no slop
// detector at all; this gives it a complete mechanical slop capability for CLIENT code,
// complementing knip dead-code (src/quality-scan.ts) and the M6 /simplify LLM pass.
//
// Three provenance groups:
//   • Ported from ATC's `scripts/slop-check.ts` (which only runs on ATC's own diffs): orphan
//     TODOs, narrating comments, try/catch-rethrow, single-call wrappers.
//   • Additional classes researched for this module: placeholder stubs, elision comments,
//     AI comment phrasing, redundant booleans, else-after-return, decorative emoji,
//     redundant JSDoc.
//   • Coverage fan-out (#362, #364, #370, #371): unused parameter, unused import, single-use
//     helper (the general "called exactly once" shape, broader than single-call-wrapper's
//     pass-through-only scope), unreachable branch (tier-1 literal conditions).
//
// Method: TypeScript compiler API. Comment-text checks run over the file's comment trivia
// (scanned once); structural checks walk the AST or match the source text. Emits Finding[]
// with taxonomy `M5 — …`, ids `SLOP-01…`, category "Maintainability". Every class is gated by
// a positive+negative fixture pair (slop.test.ts) — the #61 discipline.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { parse, type NextId, type SourceInput } from "./common.js";
import { SOURCE_FILE } from "./load-sources.js";

function makeFinding(
  nextId: NextId,
  input: {
    title: string;
    severity: Finding["severity"];
    confidence: Finding["confidence"];
    taxonomy: string;
    location: string;
    evidence: string;
    impact: string;
    fix: string;
    value: number;
    ease: number;
    safety: number;
  },
): Finding {
  return { id: nextId(), status: "Open", category: "Maintainability", ...input };
}

interface Comment {
  text: string; // full comment text including // or /* */
  line: number; // 1-based
  single: boolean; // // line comment vs /* */ block
}

function collectComments(sf: ts.SourceFile): Comment[] {
  const full = sf.getFullText();
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, /* skipTrivia */ false, sf.languageVariant, full);
  const out: Comment[] = [];
  let token = scanner.scan();
  while (token !== ts.SyntaxKind.EndOfFileToken) {
    if (token === ts.SyntaxKind.SingleLineCommentTrivia || token === ts.SyntaxKind.MultiLineCommentTrivia) {
      out.push({
        text: scanner.getTokenText(),
        line: sf.getLineAndCharacterOfPosition(scanner.getTokenStart()).line + 1,
        single: token === ts.SyntaxKind.SingleLineCommentTrivia,
      });
    }
    token = scanner.scan();
  }
  return out;
}

function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

function lineAt(sf: ts.SourceFile, pos: number): number {
  return sf.getLineAndCharacterOfPosition(pos).line + 1;
}

// Comment body with the //, /*, */, and leading `*` gutter stripped — the human-readable text.
function commentBody(text: string): string {
  return text
    .replace(/^\/\//, "")
    .replace(/^\/\*+/, "")
    .replace(/\*+\/$/, "")
    .split("\n")
    .map((l) => l.replace(/^\s*\*\s?/, "").trim())
    .join(" ")
    .trim();
}

// --- Ported from ATC slop-check.ts (4 classes) ------------------------------

const MARKER_GROUP = "(TODO|FIXME|XXX|HACK)";
const LINE_MARKER_RE = new RegExp(`^\\s*${MARKER_GROUP}\\b(?!\\s*\\()`, "i");
const PAREN_MARKER_RE = new RegExp(`\\(\\s*${MARKER_GROUP}\\b(?!\\s*[@#]|\\()`, "i");

function detectOrphanTodo(comments: Comment[], path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const c of comments) {
    const body = commentBody(c.text);
    if (LINE_MARKER_RE.test(body) || PAREN_MARKER_RE.test(c.text)) {
      findings.push(
        makeFinding(nextId, {
          title: "TODO/FIXME marker with no owner or issue reference",
          severity: "Low",
          confidence: "Likely",
          taxonomy: "M5 — Orphan TODO",
          location: `${path}:${c.line}`,
          evidence: `\`${c.text.trim().slice(0, 70)}\` — a TODO/FIXME/XXX/HACK with no \`(@owner)\` or \`(#issue)\`; untracked, so it never gets done.`,
          impact: "Untracked deferrals accumulate as silent debt no one owns.",
          fix: "Attach an owner or issue ref (`TODO(@alice)` / `TODO(#123)`), or resolve and delete it.",
          value: 2,
          ease: 5,
          safety: 5,
        }),
      );
    }
  }
  return findings;
}

// A short //-comment that starts with a narrating verb and just restates the next line.
const NARRATING_RE =
  /^\/\/\s*(loop|iterate|fetch|set|get|load|store|save|validate|verify|check|ensure|create|update|delete|remove|initialize|init|return|build|parse|compute|calculate|handle|process|read|write|apply|execute|invoke|call|trigger)(\s+(the|a|an|all|every|this|that|each|some|any))?\s+\w+\.?\s*$/i;
const DIRECTIVE_RE = /^\/\/\s*(eslint|ts-|prettier|@|§|#|D-\d|bp\d+|--|=|>|---|\*)/i;

function detectNarratingComment(comments: Comment[], path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const c of comments) {
    if (!c.single) continue;
    const t = c.text.trim();
    if (!DIRECTIVE_RE.test(t) && NARRATING_RE.test(t)) {
      findings.push(
        makeFinding(nextId, {
          title: "Narrating comment (restates WHAT the code does)",
          severity: "Info",
          confidence: "Review",
          taxonomy: "M5 — Narrating comment",
          location: `${path}:${c.line}`,
          evidence: `\`${t.slice(0, 70)}\` — a verb-first comment that narrates the next line rather than explaining WHY.`,
          impact: "Adds reading cost and drifts out of sync with the code it mirrors.",
          fix: "Delete it, or replace with a WHY comment if there's a non-obvious reason.",
          value: 1,
          ease: 5,
          safety: 5,
        }),
      );
    }
  }
  return findings;
}

// `} catch (err) { throw err; }` — a catch that only re-throws the same error.
const RETHROW_CATCH_RE = /catch\s*\(\s*(\w+)\s*\)\s*\{\s*throw\s+\1\s*;?\s*\}/g;

function detectRethrowCatch(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const text = sf.text;
  for (const m of text.matchAll(RETHROW_CATCH_RE)) {
    findings.push(
      makeFinding(nextId, {
        title: "try/catch that only re-throws the caught error",
        severity: "Low",
        confidence: "Likely",
        taxonomy: "M5 — Rethrow catch",
        location: `${path}:${lineAt(sf, m.index)}`,
        evidence: `\`${m[0].replace(/\s+/g, " ").slice(0, 70)}\` — the catch adds nothing; the try/catch is pure ceremony.`,
        impact: "Dead error-handling structure that reads as if it does something.",
        fix: "Remove the try/catch and let the error propagate (or handle it for real).",
        value: 2,
        ease: 5,
        safety: 4,
      }),
    );
  }
  return findings;
}

// An exported function whose whole body is `return f(...)`, forwarding its params unchanged —
// a pointless wrapper. AST (not ATC's regex) so it only fires on true pass-throughs.
function passThroughReturnCall(fn: ts.FunctionLikeDeclaration, fnName: string | undefined): ts.CallExpression | undefined {
  const body = fn.body;
  if (!body || !ts.isBlock(body) || body.statements.length !== 1) return undefined;
  const only = body.statements[0];
  if (!only || !ts.isReturnStatement(only) || !only.expression || !ts.isCallExpression(only.expression)) return undefined;
  const call = only.expression;
  // Only forwarding to a FREE FUNCTION (`return fetchUser(id)`) is rename-indirection slop.
  // Method calls (`return SET.has(x)`, `arr.includes(x)`) are usually meaningful named
  // predicates/transforms, not pointless wrappers — don't flag them (dogfood, 2026-07-11).
  if (!ts.isIdentifier(call.expression)) return undefined;
  if (call.expression.text === fnName) return undefined; // recursion, not a wrapper
  const params = new Set(fn.parameters.filter((p) => ts.isIdentifier(p.name)).map((p) => (p.name as ts.Identifier).text));
  const forwardsParams = call.arguments.length > 0 && call.arguments.every((a) => ts.isIdentifier(a) && params.has(a.text));
  return forwardsParams ? call : undefined;
}

function detectSingleCallWrapper(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const push = (node: ts.Node, name: string, call: ts.CallExpression) =>
    findings.push(
      makeFinding(nextId, {
        title: `Single-call wrapper \`${name}\` forwards its params unchanged`,
        severity: "Low",
        confidence: "Review",
        taxonomy: "M5 — Single-call wrapper",
        location: `${path}:${lineOf(sf, node)}`,
        evidence: `\`${name}\` does nothing but \`return ${call.getText(sf).slice(0, 50)}\` — an indirection with no added behavior.`,
        impact: "A layer the reader must trace through for no benefit (unless it's a deliberate seam).",
        fix: "Inline it at the call sites, unless it exists as an intentional test/refactor seam.",
        value: 2,
        ease: 3,
        safety: 4,
      }),
    );
  for (const stmt of sf.statements) {
    const exported = ts.canHaveModifiers(stmt) && ts.getModifiers(stmt)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (!exported) continue;
    if (ts.isFunctionDeclaration(stmt) && stmt.name) {
      const call = passThroughReturnCall(stmt, stmt.name.text);
      if (call) push(stmt, stmt.name.text, call);
    } else if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (ts.isIdentifier(decl.name) && decl.initializer && (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))) {
          const call = passThroughReturnCall(decl.initializer, decl.name.text);
          if (call) push(decl, decl.name.text, call);
        }
      }
    }
  }
  return findings;
}

// --- Additional researched classes (7) --------------------------------------

const STUB_THROW = /not\s*implemented|unimplemented|implement\s*me|not\s*yet\s*implemented/i;
const STUB_COMMENT = /^(todo:?\s*implement|your code (goes )?here|implementation goes here|implement (this|me)\b|fill (this )?in|code (goes )?here)/i;

function detectPlaceholder(sf: ts.SourceFile, comments: Comment[], path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const push = (line: number, snippet: string) =>
    findings.push(
      makeFinding(nextId, {
        title: "Placeholder / unimplemented stub left in source",
        severity: "Low",
        confidence: "Likely",
        taxonomy: "M5 — Placeholder stub",
        location: `${path}:${line}`,
        evidence: `\`${snippet.slice(0, 80)}\` — an unfinished/generated stub that shipped instead of a real implementation.`,
        impact: "A path that throws, no-ops, or returns a dummy at runtime — a latent bug and a sign generated scaffolding was committed unfinished.",
        fix: "Implement the body, or delete the stub and its dead call sites.",
        value: 3,
        ease: 4,
        safety: 4,
      }),
    );
  const visit = (node: ts.Node) => {
    if (ts.isThrowStatement(node) && ts.isNewExpression(node.expression)) {
      const arg = node.expression.arguments?.[0];
      if (arg && ts.isStringLiteralLike(arg) && STUB_THROW.test(arg.text)) push(lineOf(sf, node), node.getText(sf));
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  for (const c of comments) if (STUB_COMMENT.test(commentBody(c.text))) push(c.line, c.text.trim());
  return findings;
}

// Requires a real elision phrase (an ellipsis next to a placeholder word, or an explicit
// "rest of the code"/"existing code"/"unchanged" marker) — NOT a bare leading "existing"/
// "other", which are common in legitimate comments (dogfooded against ATC, 2026-07-11).
// A true elision marker is either ellipsis-adjacent (`... existing code ...`) or a SHORT
// standalone marker (`// existing code`). The phrase alone isn't enough: "operator chose to
// keep the existing SERVICE_JWT" and "existing imports continue to work" are legit prose that
// merely mentions these words. So the phrase form is gated on a short comment body (dogfood,
// 2026-07-11). The trailing "unchanged"/"omitted" rule was dropped for the same reason.
// `\s+` (not `\s*`) so a Next.js catch-all route segment `[...rest]` — no space — doesn't
// match, while the real marker `... rest of the code` does (dogfood, 2026-07-11).
const ELLIPSIS_ELISION = /(?:\.\.\.|…)\s+(?:rest|existing|remaining|unchanged|omitted|same|previous|and so on|etc)\b/i;
const PHRASE_ELISION =
  /\b(?:rest|remainder) of (?:the )?(?:code|file|function|method|implementation|logic|imports|component)\b|\bexisting (?:code|implementation|logic|imports)\b|\bcode (?:unchanged|omitted|goes here|continues|here)\b|\bkeep (?:the )?(?:rest|existing|previous|same)\b|\bsame as (?:before|above)\b/i;
const ELISION_MAX_STANDALONE = 35;

function isElision(body: string): boolean {
  return ELLIPSIS_ELISION.test(body) || (PHRASE_ELISION.test(body) && body.length <= ELISION_MAX_STANDALONE);
}

function detectElision(comments: Comment[], path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const c of comments) {
    if (isElision(commentBody(c.text))) {
      findings.push(
        makeFinding(nextId, {
          title: "Elision / 'keep existing code' placeholder comment",
          severity: "Low",
          confidence: "Likely",
          taxonomy: "M5 — Elision placeholder",
          location: `${path}:${c.line}`,
          evidence: `\`${c.text.trim().slice(0, 80)}\` — an abbreviation marker an assistant leaves for omitted code; it should never survive into committed source.`,
          impact: "Strong signal that generated code was pasted with sections elided — the surrounding code may be incomplete.",
          fix: "Replace the marker with the real code it stands in for, or delete it if the code is present.",
          value: 3,
          ease: 5,
          safety: 5,
        }),
      );
    }
  }
  return findings;
}

const AI_PHRASE =
  /\b(as you can see|it'?s worth noting|note that we|in this (implementation|example|case) we|this (function|method|component|class|helper) is responsible for|here we (define|create|set ?up|implement|handle)|we (can see|will (now|then)|simply)|let'?s (define|create|start|begin|now)|now,? let'?s|first,? we'?ll|as (mentioned|described) (above|earlier)|for demonstration purposes|in a (real|production) (app|application|scenario))\b/i;

function detectAiPhrasing(comments: Comment[], path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const c of comments) {
    const m = commentBody(c.text).match(AI_PHRASE);
    if (m) {
      findings.push(
        makeFinding(nextId, {
          title: "AI-authored comment phrasing (tutorial/narration voice)",
          severity: "Info",
          confidence: "Review",
          taxonomy: "M5 — AI comment phrasing",
          location: `${path}:${c.line}`,
          evidence: `\`${m[0]}\` — conversational/tutorial phrasing characteristic of generated comments rather than intent-explaining WHY comments.`,
          impact: "Narration that restates the code in prose; reading cost without documenting a reason.",
          fix: "Delete, or rewrite as a WHY comment stating the non-obvious constraint if there is one.",
          value: 1,
          ease: 5,
          safety: 5,
        }),
      );
    }
  }
  return findings;
}

// Only the ternary form `cond ? true : false` — always redundant regardless of operand type.
// The `x === true`/`=== false` comparison form is intentionally NOT flagged: on a
// `boolean | undefined` operand it is semantically meaningful (excludes undefined), and
// without a type checker we can't tell it apart from the redundant case (dogfood FP).
function detectRedundantBoolean(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const isBool = (n: ts.Node) => n.kind === ts.SyntaxKind.TrueKeyword || n.kind === ts.SyntaxKind.FalseKeyword;
  const visit = (node: ts.Node) => {
    if (ts.isConditionalExpression(node) && isBool(node.whenTrue) && isBool(node.whenFalse)) {
      findings.push(
        makeFinding(nextId, {
          title: "Redundant boolean ternary (`cond ? true : false`)",
          severity: "Low",
          confidence: "Likely",
          taxonomy: "M5 — Redundant boolean",
          location: `${path}:${lineOf(sf, node)}`,
          evidence: `\`${node.getText(sf).slice(0, 60)}\` — the condition already is the boolean; the ternary is noise.`,
          impact: "Verbosity that obscures intent; a reliable tell of mechanically-expanded code.",
          fix: "Use the condition directly (`Boolean(cond)` if a cast is needed), or its negation.",
          value: 1,
          ease: 5,
          safety: 5,
        }),
      );
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

function branchExits(stmt: ts.Statement): boolean {
  if (ts.isReturnStatement(stmt) || ts.isThrowStatement(stmt) || ts.isContinueStatement(stmt) || ts.isBreakStatement(stmt)) return true;
  if (ts.isBlock(stmt)) {
    const last = stmt.statements[stmt.statements.length - 1];
    return !!last && branchExits(last);
  }
  return false;
}

function detectElseAfterReturn(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node) && node.elseStatement && !ts.isIfStatement(node.elseStatement) && branchExits(node.thenStatement)) {
      findings.push(
        makeFinding(nextId, {
          title: "Unnecessary `else` after a terminating `if` branch",
          severity: "Low",
          confidence: "Likely",
          taxonomy: "M5 — Else after return",
          location: `${path}:${lineOf(sf, node)}`,
          evidence: "The `if` branch returns/throws, so the `else` is dead structure — its body can de-indent to the top level.",
          impact: "Extra nesting mechanically-generated code adds; harder to read for no benefit.",
          fix: "Drop the `else` and de-indent its body (early-return style).",
          value: 1,
          ease: 4,
          safety: 5,
        }),
      );
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// Colorful/decorative emoji only: the supplementary-plane pictographs plus the handful of
// BMP emoji used decoratively (✅❌❗❓✨⭐❤➕➖). Deliberately EXCLUDES arrows (↗→), status
// marks (⚠✔✓✗), and geometric shapes — those are used functionally, not as slop (dogfood:
// ↗ external-link marker, ⚠ CLI warnings, 2026-07-11).
const DECORATIVE_EMOJI = /[\u{1F000}-\u{1FAFF}✅❌❗❓✨⭐❤➕➖]/u;

function hasDecorativeEmoji(s: string): boolean {
  return DECORATIVE_EMOJI.test(s);
}

function detectEmoji(sf: ts.SourceFile, comments: Comment[], path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const push = (line: number, where: string, snippet: string) =>
    findings.push(
      makeFinding(nextId, {
        title: `Decorative emoji in ${where}`,
        severity: "Info",
        confidence: "Review",
        taxonomy: "M5 — Decorative emoji",
        location: `${path}:${line}`,
        evidence: `\`${snippet.slice(0, 60)}\` — decorative emoji in ${where}, a common generated-code affectation.`,
        impact: "Cosmetic noise; in log output it also complicates grepping and can break log parsers.",
        fix: "Remove the emoji.",
        value: 1,
        ease: 5,
        safety: 5,
      }),
    );
  for (const c of comments) if (hasDecorativeEmoji(c.text)) push(c.line, "a comment", c.text.trim());
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const obj = node.expression.expression.getText(sf);
      if (/^(console|logger|log)$/.test(obj)) {
        for (const arg of node.arguments) {
          if ((ts.isStringLiteralLike(arg) || ts.isTemplateLiteral(arg)) && hasDecorativeEmoji(arg.getText(sf))) {
            push(lineOf(sf, arg), "a log call", arg.getText(sf));
            break;
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

function idWords(id: string): string {
  return id.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").toLowerCase().trim();
}

function isEmptyParamDoc(paramName: string, description: string): boolean {
  const desc = description.replace(/^(the|a|an)\s+/i, "").replace(/[.,]/g, "").toLowerCase().trim();
  return desc === "" || desc === idWords(paramName) || desc === paramName.toLowerCase();
}

function detectRedundantJsdoc(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    for (const doc of ts.getJSDocCommentsAndTags(node).filter(ts.isJSDoc)) {
      const tags: ts.JSDocTag[] = doc.tags ? [...doc.tags] : [];
      const paramTags = tags.filter((t): t is ts.JSDocParameterTag => ts.isJSDocParameterTag(t));
      if (paramTags.length === 0) continue;
      const allRedundant = paramTags.every((t) => {
        const name = t.name.getText(sf);
        const desc = typeof t.comment === "string" ? t.comment : (t.comment ?? []).map((c) => c.text).join(" ");
        return isEmptyParamDoc(name, desc);
      });
      const freeText = typeof doc.comment === "string" ? doc.comment : (doc.comment ?? []).map((c) => c.text).join(" ");
      if (allRedundant && freeText.trim().length < 40) {
        findings.push(
          makeFinding(nextId, {
            title: "Redundant JSDoc that only restates the signature",
            severity: "Low",
            confidence: "Review",
            taxonomy: "M5 — Redundant JSDoc",
            location: `${path}:${lineOf(sf, doc)}`,
            evidence: `\`@param\` descriptions merely repeat the parameter names (e.g. \`${paramTags[0]?.name.getText(sf)}\`) — the block documents nothing the signature doesn't.`,
            impact: "JSDoc bloat maintained in lockstep with the code but conveying no additional information.",
            fix: "Delete the block, or keep only lines stating a non-obvious constraint (units, ownership, invariants).",
            value: 1,
            ease: 5,
            safety: 5,
          }),
        );
        break;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- Coverage additions (#362, #364, #370, #371) -----------------------------

// Unused parameter (#362): a declared parameter never referenced in the function body — the
// "stub-shaped code" D-091 #1 shape (`getPublicKey(kid)` ignoring `kid`). Mirrors ESLint
// no-unused-vars' own `args: "after-used"` default: only the TRAILING run of unused params
// (nothing used after them) is flagged, so a leading unused param followed by a used one
// (Express-style `(err, req, res, next)`) stays silent. Only named declarations (function
// declarations, `const f = (...) => ...`, methods) are checked — an anonymous arrow passed
// straight into a call (`arr.map((item, index, array) => item * 2)`) is never visited by this
// walk at all, which is what keeps caller-mandated callback shapes silent (measured against a
// real ESLint run, 2026-07-16: unlike this issue's own doc claim, ESLint's after-used does NOT
// exempt that shape — the anonymous-callback guard here is what actually does).
function isReferenced(body: ts.Node, name: string): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isIdentifier(node) && node.text === name) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(body);
  return found;
}

function unusedParamFindings(fn: ts.FunctionLikeDeclaration, fnName: string, sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const body = fn.body;
  if (!body) return [];
  const params = fn.parameters;
  // Destructured patterns, rest params, and `this` params are treated as "used" — never flagged
  // themselves, and they correctly terminate the trailing-unused run for params before them.
  const usedFlags = params.map((p) => {
    if (!ts.isIdentifier(p.name) || p.dotDotDotToken) return true;
    const name = p.name.text;
    if (name === "this" || name.startsWith("_")) return true;
    return isReferenced(body, name);
  });
  let lastUsedIdx = -1;
  usedFlags.forEach((used, i) => {
    if (used) lastUsedIdx = i;
  });
  const findings: Finding[] = [];
  for (let i = lastUsedIdx + 1; i < params.length; i++) {
    const p = params[i];
    if (!p || !ts.isIdentifier(p.name)) continue;
    findings.push(
      makeFinding(nextId, {
        title: `Parameter \`${p.name.text}\` in \`${fnName}\` is declared but never used`,
        severity: "Low",
        confidence: "Review",
        taxonomy: "M5 — Unused parameter",
        location: `${path}:${lineOf(sf, p)}`,
        evidence: `\`${fnName}(${params.map((x) => x.getText(sf)).join(", ")})\` — \`${p.name.text}\` never appears in the body, so the function's output can't depend on it.`,
        impact: "Stub-shaped code: the signature looks parameterized but silently ignores an input — the historical D-091 example (`getPublicKey(kid)` always returning the same PEM) was exactly this shape.",
        fix: "Reference the parameter, prefix it `_name` if intentionally unused, or remove it (and update call sites).",
        value: 3,
        ease: 4,
        safety: 4,
      }),
    );
  }
  return findings;
}

function detectUnusedParameter(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name && node.body) {
      findings.push(...unusedParamFindings(node, node.name.text, sf, path, nextId));
    } else if (ts.isMethodDeclaration(node) && node.body) {
      const name = ts.isIdentifier(node.name) ? node.name.text : node.name.getText(sf);
      findings.push(...unusedParamFindings(node, name, sf, path, nextId));
    } else if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      findings.push(...unusedParamFindings(node.initializer, node.name.text, sf, path, nextId));
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// Unused import (#364): an import specifier never referenced elsewhere in the file. Side-effect
// imports (no clause) and re-exports (`export {...} from`, a different AST node entirely) are
// never visited. `import React from "react"` in a .tsx file is exempted unconditionally — the
// classic-transform JSX pragma has no textual reference even when required (no `ts.Program`/
// compiler-options in this single-file pipeline to check the actual `jsx` setting, so this is a
// documented small allowlist per the issue's own fallback, not a detected fact).
function isReactPragma(path: string, name: string): boolean {
  // #1065: .js/.mjs/.cjs are JSX modules too (React/Next allow JSX in plain .js) — they parse as
  // TSX here, so the same pragma exemption has to apply or every one of them false-fires.
  return name === "React" && /\.([jt]sx|[cm]?js)$/.test(path);
}

function importedBindings(clause: ts.ImportClause): { name: string; node: ts.Node }[] {
  const out: { name: string; node: ts.Node }[] = [];
  if (clause.name) out.push({ name: clause.name.text, node: clause.name });
  if (clause.namedBindings) {
    if (ts.isNamespaceImport(clause.namedBindings)) {
      out.push({ name: clause.namedBindings.name.text, node: clause.namedBindings.name });
    } else if (ts.isNamedImports(clause.namedBindings)) {
      for (const el of clause.namedBindings.elements) out.push({ name: el.name.text, node: el.name });
    }
  }
  return out;
}

function referencedOutsideImport(sf: ts.SourceFile, importStmt: ts.Statement, name: string): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found || node === importStmt) return;
    if (ts.isIdentifier(node) && node.text === name) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);
  return found;
}

function detectUnusedImport(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !stmt.importClause) continue; // no clause = side-effect-only import
    const moduleSpecifier = ts.isStringLiteralLike(stmt.moduleSpecifier) ? stmt.moduleSpecifier.text : stmt.moduleSpecifier.getText(sf);
    for (const b of importedBindings(stmt.importClause)) {
      if (isReactPragma(path, b.name)) continue;
      if (referencedOutsideImport(sf, stmt, b.name)) continue;
      findings.push(
        makeFinding(nextId, {
          title: `Unused import \`${b.name}\` from "${moduleSpecifier}"`,
          severity: "Low",
          confidence: "Likely",
          taxonomy: "M5 — Unused import",
          location: `${path}:${lineOf(sf, b.node)}`,
          evidence: `\`${b.name}\` is imported from "${moduleSpecifier}" but never referenced elsewhere in the file.`,
          impact: "Dead import left behind by a refactor or generation pass — adds a phantom dependency edge and reading cost.",
          fix: "Remove the unused specifier (or the whole import if nothing else from it is used).",
          value: 1,
          ease: 5,
          safety: 5,
        }),
      );
    }
  }
  return findings;
}

// Single-use helper (#370): a non-exported, block-bodied function/const-arrow called from
// exactly one site in the same file — the general "called exactly once" class, broader than
// detectSingleCallWrapper's pass-through-only scope (which only checks EXPORTED declarations,
// so the two detectors never double-fire on the same node). Exported declarations are API
// surface, not slop — restricting to non-exported is the mechanical stand-in for "intent",
// per the issue's own guidance. `confidence: "Review"` for the same reason as the existing
// single-call-wrapper detector: a mechanical count can't know it's a deliberate test/refactor
// seam.
function callSites(sf: ts.SourceFile, name: string, ownNode: ts.Node): ts.CallExpression[] {
  const sites: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (node === ownNode) return; // excludes the declaration itself and any self-recursive calls
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name) sites.push(node);
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);
  return sites;
}

function containsAwait(node: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    // Don't descend into a nested function — its awaits belong to it, not to `node`.
    if (n !== node && ts.isFunctionLike(n)) return;
    if (ts.isAwaitExpression(n)) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

// A function can do I/O without ever writing `await`, and `containsAwait` looks only for `await`
// (#1532). These three mechanisms are MEASURED, not guessed: every one comes from a row in the
// 50-row seeded sample of what the #1447 seam exemption spares across the ten pinned corpus
// targets (2026-07-30) — `spawnSync("vercel"|"copilot", …)`, `spawn(opener, …)`, `existsSync(…)`
// and a hand-rolled `new Promise((res) => stream.on("data", …))`. All four were spared as "pure
// helpers" while being the I/O half outright.
//
// Its own bound, stated because the vocabulary is a LIST and a list is never closed: an I/O
// primitive outside it still reads as pure. The `Sync` suffix rule is the generic half (it covers
// every `fs`/`child_process` sync API without naming them); `new Promise` covers callback and
// event I/O; the bare `child_process` spawners and `process.exit` are named because neither
// pattern reaches them.
const SYNC_IO_CALLEE = /^(spawn|exec|execFile|fork)$/;
function doesOwnIo(node: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (n !== node && ts.isFunctionLike(n)) return;
    if (ts.isNewExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "Promise") found = true;
    if (ts.isCallExpression(n)) {
      const callee = ts.isPropertyAccessExpression(n.expression) ? n.expression.name.text : ts.isIdentifier(n.expression) ? n.expression.text : "";
      if (callee.endsWith("Sync") || SYNC_IO_CALLEE.test(callee) || (ts.isPropertyAccessExpression(n.expression) && n.expression.expression.getText() === "process" && callee === "exit")) found = true;
    }
    if (found) return;
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

function isAsync(node: ts.Node): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node)?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword) ?? false);
}

// #370 acceptance criterion 3 — the "kept as a test seam" FP class briefs/quality-extras.txt names,
// shared with M6 via #325's M6-N-SEAM fixture (targets/calibration/simplify/reconcile.ts).
//
// The two detectors DID diverge, MEASURED 2026-07-28 by running detectSlopFindings over that fixture
// and over a copy with one keyword removed: the exported original draws 0 M5 findings, but drop the
// `export` and detectSingleUseHelper flags it — while M6's rubric spares it for a reason the `export`
// keyword has nothing to do with. GROUND-TRUTH.md states that contract as "pure helper + I/O-entangled
// sole caller", and it is AST-visible: the helper awaits nothing, its one caller does. A seam split
// out to keep money-math testable without a Supabase client is the brief's own MISSING SEAMS remedy,
// so inlining it is the wrong advice whether or not the module chose to export it.
//
// #1532 — the POPULATION #1447 shipped without. MEASURED 2026-07-30 by running detect-static over
// the ten pinned corpus targets at their pinned commits with and without this exemption: it spares
// 653 candidates, 26% of inbox-zero's whole M5-slop reading and 20% of tanstack-com's. A seeded
// random sample of 50 (mulberry32, seed 20260730, over the population sorted by
// target|file|line|helper) was read at source and graded against the exemption's own premise —
// "a pure helper whose sole caller does the I/O". 45 held. 5 did not, and all 5 failed the SAME
// half: the helper was doing the I/O itself, through a mechanism `containsAwait` does not look for
// (`spawnSync`, `spawn`, `existsSync`, a hand-rolled `new Promise` over stream events).
// `doesOwnIo` closes that half; 10% wrongly spared, Wilson 95% CI [4.3%, 21.4%], so an estimated
// 65 of the 653 (CI [28, 139]) were being dropped for a premise that did not hold.
//
// Two sub-populations are COUNTED AND LEFT, not silently accepted — the sample says neither is
// reliably a defect, and disclosing a measured number beats narrowing on a hunch:
//   * 401 of 653 have a caller whose awaits never touch the helper's result. The sample drew 36 of
//     them; 3 were among the 5 defects above and now fire, and every one of the 33 that REMAIN
//     spared was a genuine seam. So this shape is not itself the error — the caller is entangled
//     with I/O either way, so extracting the pure half still buys what the brief asks for. This is
//     the exemption's deliberate conservatism, now with a number on it.
//   * 39 of 653 have a caller declared `async` with ZERO awaits. This one is MIXED, which is
//     exactly why it is not narrowed: inbox-zero utils/outlook/mail.ts:408 is a genuine seam whose
//     caller does its I/O by RETURNING a promise, while saas-lite app/sitemap.xml/route.ts:24 and
//     mvp-boilerplate app/api/og/route.tsx:15 have callers that do nothing asynchronous at all.
//     Separating them means knowing what the returned call does — a cross-file question. ONE
//     mechanism was tried (require a real `await` in the caller) and it turns the inbox-zero row
//     into a false positive, so it was not shipped. `buildImportGraph` is the untried candidate
//     and is the first thing to reach for. Tracked as #1533; do not read "not narrowed" as
//     "not narrowable" — one failed attempt is not a proof.
function isTestabilitySeam(helperBody: ts.Node, isAsyncHelper: boolean, callSite: ts.CallExpression): boolean {
  if (isAsyncHelper || containsAwait(helperBody) || doesOwnIo(helperBody)) return false; // the helper does the I/O — not a pure seam
  let enclosing: ts.Node | undefined = callSite.parent;
  while (enclosing && !ts.isFunctionLike(enclosing)) enclosing = enclosing.parent;
  if (!enclosing) return false;
  return isAsync(enclosing) || containsAwait(enclosing);
}

function detectSingleUseHelper(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  interface Candidate {
    name: string;
    node: ts.Node;
    declNode: ts.Node;
    body: ts.Node;
    async: boolean;
  }
  const candidates: Candidate[] = [];
  for (const stmt of sf.statements) {
    const exported = ts.canHaveModifiers(stmt) && ts.getModifiers(stmt)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (exported) continue;
    if (ts.isFunctionDeclaration(stmt) && stmt.name && stmt.body && ts.isBlock(stmt.body) && stmt.body.statements.length >= 1) {
      candidates.push({ name: stmt.name.text, node: stmt, declNode: stmt, body: stmt.body, async: isAsync(stmt) });
    } else if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (
          ts.isIdentifier(decl.name) &&
          decl.initializer &&
          (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer)) &&
          decl.initializer.body &&
          ts.isBlock(decl.initializer.body)
        ) {
          candidates.push({ name: decl.name.text, node: stmt, declNode: decl, body: decl.initializer.body, async: isAsync(decl.initializer) });
        }
      }
    }
  }
  for (const c of candidates) {
    const sites = callSites(sf, c.name, c.declNode);
    if (sites.length !== 1) continue;
    if (isTestabilitySeam(c.body, c.async, sites[0]!)) continue;
    findings.push(
      makeFinding(nextId, {
        title: `Single-use helper \`${c.name}\` is only called from one site`,
        severity: "Low",
        confidence: "Review",
        taxonomy: "M5 — Single-use helper",
        location: `${path}:${lineOf(sf, c.node)}`,
        evidence: `\`${c.name}\` is a non-exported helper with a real body, called from exactly one place in this file. Scope of this rule: it counts call sites WITHIN this file only, and it exempts a helper that does no I/O of its own whose one caller is async or awaits — the testability seam \`briefs/quality-extras.txt\` demands — so this one is not that shape. What the exemption costs is MEASURED, not estimated (2026-07-30, ten pinned corpus repos): it spares 653 helpers, of which 401 have a caller whose awaits never touch the helper's result and 39 have a caller that awaits nothing at all, so a genuinely single-use helper sitting next to unrelated I/O is spared with them. A 50-row seeded sample read at source put the wrongly-spared rate at 10% (95% CI 4.3–21.4%).`,
        impact: "An extracted layer the reader must trace through for a single caller — unless it's a deliberate test/refactor seam.",
        fix: "Inline it at its one call site, unless it exists as an intentional seam (leave it if so).",
        value: 2,
        ease: 3,
        safety: 4,
      }),
    );
  }
  return findings;
}

// Unreachable branch (#371): tier-1 literal-condition detection — `if`/`while`/ternary
// conditions that are a boolean literal or a constant-foldable literal-vs-literal comparison
// (`1 === 2`). Pure AST pattern match, no dataflow, so it deliberately does NOT catch the
// harder D-091 example (`else if` provably false only given an earlier runtime check) — that
// needs real control-flow analysis and is left to tier 2 / the M6 semantic pass per the issue.
function literalValue(node: ts.Expression): string | number | boolean | undefined {
  if (ts.isStringLiteralLike(node)) return node.text;
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  return undefined;
}

function literalBoolValue(node: ts.Expression): boolean | undefined {
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (ts.isParenthesizedExpression(node)) return literalBoolValue(node.expression);
  if (ts.isBinaryExpression(node)) {
    const op = node.operatorToken.kind;
    const isEq = op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken;
    const isNeq = op === ts.SyntaxKind.ExclamationEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken;
    if (!isEq && !isNeq) return undefined;
    const l = literalValue(node.left);
    const r = literalValue(node.right);
    if (l === undefined || r === undefined) return undefined;
    const eq = l === r;
    return isEq ? eq : !eq;
  }
  return undefined;
}

function detectUnreachableBranch(sf: ts.SourceFile, path: string, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const flag = (node: ts.Node, snippet: string) =>
    findings.push(
      makeFinding(nextId, {
        title: "Unreachable branch (condition can never hold at runtime)",
        severity: "Low",
        confidence: "Likely",
        taxonomy: "M5 — Unreachable branch",
        location: `${path}:${lineOf(sf, node)}`,
        evidence: `\`${snippet.slice(0, 70)}\` — the condition is a constant, so this branch never runs.`,
        impact: "Dead branch that reads as live logic; the D-091 catalog's own example (an always-false `else if`) shipped as a real bug this shape would have caught.",
        fix: "Delete the unreachable branch, or fix the condition if it was meant to be reachable.",
        value: 3,
        ease: 4,
        safety: 4,
      }),
    );
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node)) {
      const val = literalBoolValue(node.expression);
      if (val === false) flag(node, node.getText(sf));
      else if (val === true && node.elseStatement) flag(node, node.getText(sf));
    } else if (ts.isWhileStatement(node)) {
      if (literalBoolValue(node.expression) === false) flag(node, node.getText(sf));
    } else if (ts.isConditionalExpression(node)) {
      const val = literalBoolValue(node.condition);
      if (val === true || val === false) flag(node, node.getText(sf));
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- Orchestrator ------------------------------------------------------------

/**
 * Runs the mechanical AI-slop checks over the given source set and returns Finding[]
 * (taxonomy `M5 — …`). Covers the four patterns ported from ATC's slop-check, seven
 * additional researched classes, and the #362/#364/#370/#371 coverage fan-out (unused
 * parameter, unused import, single-use helper, unreachable branch); no overlap with knip
 * dead-code.
 */
export function detectSlopFindings(files: SourceInput[]): Finding[] {
  let n = 0;
  const nextId: NextId = () => `SLOP-${String(++n).padStart(2, "0")}`;
  const findings: Finding[] = [];
  for (const f of files) {
    if (!SOURCE_FILE.test(f.path)) continue; // #1065: the loader's own filter, imported so the two can never drift apart
    const sf = parse(f.path, f.text);
    const comments = collectComments(sf);
    findings.push(
      ...detectOrphanTodo(comments, f.path, nextId),
      ...detectNarratingComment(comments, f.path, nextId),
      ...detectRethrowCatch(sf, f.path, nextId),
      ...detectSingleCallWrapper(sf, f.path, nextId),
      ...detectPlaceholder(sf, comments, f.path, nextId),
      ...detectElision(comments, f.path, nextId),
      ...detectAiPhrasing(comments, f.path, nextId),
      ...detectRedundantBoolean(sf, f.path, nextId),
      ...detectElseAfterReturn(sf, f.path, nextId),
      ...detectEmoji(sf, comments, f.path, nextId),
      ...detectRedundantJsdoc(sf, f.path, nextId),
      ...detectUnusedParameter(sf, f.path, nextId),
      ...detectUnusedImport(sf, f.path, nextId),
      ...detectSingleUseHelper(sf, f.path, nextId),
      ...detectUnreachableBranch(sf, f.path, nextId),
    );
  }
  return findings;
}
