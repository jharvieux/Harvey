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
import { collectPathAliases, resolveImport } from "./app-router.js";
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
//
// The spawner names match a BARE IDENTIFIER only — `import { spawn } from "child_process"` is how
// all three sampled rows called it (tanstack-com scripts/auth-login.ts:37 among them). Matching the
// method half as well made `/re/.exec(text)` and `regex.exec(s)` read as spawning a process:
// MEASURED 2026-07-31, that is the whole reason tanstack-com scripts/check-docs-menu-links.ts:554
// was disqualified, a helper whose deepest side effect is a string split.
const SYNC_IO_CALLEE = /^(spawn|exec|execFile|fork)$/;
function doesOwnIo(node: ts.Node, hop?: { path: string; sf: ts.SourceFile; resolve: CalleeResolver }): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (n !== node && ts.isFunctionLike(n)) return;
    if (ts.isNewExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "Promise") found = true;
    if (ts.isCallExpression(n)) {
      const callee = ts.isPropertyAccessExpression(n.expression) ? n.expression.name.text : ts.isIdentifier(n.expression) ? n.expression.text : "";
      if (
        callee.endsWith("Sync") ||
        (ts.isIdentifier(n.expression) && SYNC_IO_CALLEE.test(callee)) ||
        (ts.isPropertyAccessExpression(n.expression) && n.expression.expression.getText() === "process" && callee === "exit")
      ) {
        found = true;
      }
      // One hop, and only where the callee RESOLVES (#1532 residual, MEASURED 2026-07-31): carbon
      // `packages/dev/src/services/apps.ts:367` was drawn in the 30-row re-check and graded wrongly
      // spared — `depsInSync` does `existsSync`/`statSync` through `isAtLeastAsNew`, one call away,
      // and a body-only scan reads it as pure. Same cross-file resolver as #1533; an unresolvable
      // callee still reads as pure, so this only ever finds I/O that is present in the source.
      if (!found && hop && ts.isIdentifier(n.expression)) {
        const target = hop.resolve(hop.path, hop.sf, n.expression.text);
        if (target && doesOwnIo((target.fn as ts.FunctionLikeDeclaration).body ?? target.fn)) found = true;
      }
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

// #1533's cross-file half. `buildImportGraph`'s own resolver (`resolveImport` + `collectPathAliases`,
// exported from app-router.ts for exactly this) turns a callee NAME into the declaration it refers
// to, one repo-local import hop away. Built lazily per `detectSlopFindings` call and only consulted
// for the rare async-caller-with-no-await shape, so the common path pays nothing.
interface CalleeResolver {
  (fromPath: string, fromFile: ts.SourceFile, name: string): { sf: ts.SourceFile; fn: ts.FunctionLikeDeclaration } | undefined;
}

function functionNamed(sf: ts.SourceFile, name: string): ts.FunctionLikeDeclaration | undefined {
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name?.text === name && stmt.body) return stmt;
    if (!ts.isVariableStatement(stmt)) continue;
    for (const d of stmt.declarationList.declarations) {
      if (ts.isIdentifier(d.name) && d.name.text === name && d.initializer && (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))) return d.initializer;
    }
  }
  return undefined;
}

function importSpecifierFor(sf: ts.SourceFile, name: string): string | undefined {
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier) || stmt.importClause?.isTypeOnly) continue;
    const bindings = stmt.importClause?.namedBindings;
    if (bindings && ts.isNamedImports(bindings) && bindings.elements.some((e) => !e.isTypeOnly && e.name.text === name)) return stmt.moduleSpecifier.text;
  }
  return undefined;
}

function makeCalleeResolver(files: SourceInput[]): CalleeResolver {
  let allPaths: Set<string> | undefined;
  let textByPath: Map<string, string> | undefined;
  let aliases: ReturnType<typeof collectPathAliases> | undefined;
  const parsed = new Map<string, ts.SourceFile | undefined>();
  const sourceAt = (p: string): ts.SourceFile | undefined => {
    if (!parsed.has(p)) {
      const text = textByPath?.get(p);
      parsed.set(p, text !== undefined && SOURCE_FILE.test(p) ? parse(p, text) : undefined);
    }
    return parsed.get(p);
  };
  return (fromPath, fromFile, name) => {
    const local = functionNamed(fromFile, name);
    if (local) return { sf: fromFile, fn: local };
    const specifier = importSpecifierFor(fromFile, name);
    if (specifier === undefined) return undefined;
    // Deferred to the first cross-file question: parsing every tsconfig and workspace manifest is
    // wasted on the overwhelming majority of source sets, where no candidate ever reaches here.
    allPaths ??= new Set(files.map((f) => f.path));
    textByPath ??= new Map(files.map((f) => [f.path, f.text] as const));
    aliases ??= collectPathAliases(files);
    // `resolveImport` appends extensions to the specifier verbatim, so the ESM-TS convention of
    // importing `../helpers.js` from `helpers.ts` resolves to nothing. MEASURED 2026-07-31: that is
    // why the very row this hop was built for — carbon `packages/dev/src/services/apps.ts:367`,
    // whose `isAtLeastAsNew` comes `from "../helpers.js"` — was still spared with the hop in place.
    // Stripped here rather than in `resolveImport` itself: that function also backs M9's import
    // graph and #1344's reachability gate, so widening it moves baselines this change has not
    // measured. Tracked for the shared resolver as #1659, whose first acceptance criterion is to
    // measure that corpus-wide M9 movement BEFORE the fallback moves into `resolveImport`.
    const target = resolveImport(fromPath, specifier, allPaths, aliases) ?? resolveImport(fromPath, specifier.replace(/\.(m|c)?js$/, ""), allPaths, aliases);
    const sf = target === undefined ? undefined : sourceAt(target);
    const fn = sf && functionNamed(sf, name);
    return fn ? { sf, fn } : undefined;
  };
}

function bodyOf(fn: ts.Node): ts.Node {
  return (fn as ts.FunctionLikeDeclaration).body ?? fn;
}

function returnedExpressions(fn: ts.Node): ts.Expression[] {
  const body = (fn as ts.FunctionLikeDeclaration).body;
  if (!body) return [];
  if (!ts.isBlock(body)) return [body];
  const out: ts.Expression[] = [];
  const visit = (n: ts.Node) => {
    if (n !== body && ts.isFunctionLike(n)) return; // a nested function's returns are its own
    if (ts.isReturnStatement(n) && n.expression) out.push(n.expression);
    ts.forEachChild(n, visit);
  };
  visit(body);
  return out;
}

/** The `const x = <init>` / `let x = <init>` that binds `name` inside `scope`, if there is exactly one. */
function soleBindingIn(scope: ts.Node, name: string): ts.Expression | undefined {
  const hits: ts.Expression[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name && n.initializer) hits.push(n.initializer);
    ts.forEachChild(n, visit);
  };
  visit(scope);
  return hits.length === 1 ? hits[0] : undefined;
}

// Can this expression be PROVEN never to be a promise, reading only source? Deliberately one-sided:
// anything it does not resolve — a method call, a parameter, a package outside the repo — answers
// `false`, which keeps the exemption. It is the FIRING direction that has to be earned.
function isProvablySynchronous(expr: ts.Expression, scope: ts.Node, path: string, sf: ts.SourceFile, resolve: CalleeResolver, depth: number): boolean {
  if (
    ts.isObjectLiteralExpression(expr) ||
    ts.isArrayLiteralExpression(expr) ||
    ts.isStringLiteral(expr) ||
    ts.isNoSubstitutionTemplateLiteral(expr) ||
    ts.isTemplateExpression(expr) ||
    ts.isNumericLiteral(expr) ||
    ts.isRegularExpressionLiteral(expr) ||
    ts.isJsxElement(expr) ||
    ts.isJsxSelfClosingElement(expr) ||
    ts.isJsxFragment(expr) ||
    expr.kind === ts.SyntaxKind.TrueKeyword ||
    expr.kind === ts.SyntaxKind.FalseKeyword ||
    expr.kind === ts.SyntaxKind.NullKeyword
  ) {
    return true;
  }
  // A constructor call yields the constructed object, never a promise — except `new Promise`, which
  // is the hand-rolled-async shape #1532's `doesOwnIo` already names.
  if (ts.isNewExpression(expr)) return !(ts.isIdentifier(expr.expression) && expr.expression.text === "Promise");
  if (depth <= 0) return false;
  if (ts.isPropertyAccessExpression(expr)) return isProvablySynchronous(expr.expression, scope, path, sf, resolve, depth);
  if (ts.isIdentifier(expr)) {
    const bound = soleBindingIn(scope, expr.text);
    return bound !== undefined && isProvablySynchronous(bound, scope, path, sf, resolve, depth - 1);
  }
  if (ts.isCallExpression(expr) && ts.isIdentifier(expr.expression)) {
    const target = resolve(path, sf, expr.expression.text);
    if (!target) return false;
    const body = bodyOf(target.fn);
    if (isAsync(target.fn) || containsAwait(body) || doesOwnIo(body)) return false;
    const rets = returnedExpressions(target.fn);
    // A void callee returns `undefined`; a callee whose returns are all provably synchronous is too.
    return rets.every((r) => isProvablySynchronous(r, body, path, target.sf, resolve, depth - 1));
  }
  return false;
}

// An `await`, or an `async` function, ANYWHERE under this node — nested functions included, which
// is exactly where `containsAwait` stops. A caller that hands an async callback to something is
// orchestrating I/O even though its own body awaits nothing. MEASURED 2026-07-31: without this,
// inbox-zero `apps/worker/src/runtime.mjs:13` fired twice — `startWorkerRuntime` opens a Redis
// connection and starts BullMQ workers whose job handler is `async (job) => { await forwardJob(…) }`,
// and its own `return` is a plain object literal, so reading returns alone declared it synchronous.
function schedulesAsyncWork(node: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isAwaitExpression(n) || (ts.isFunctionLike(n) && isAsync(n))) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(node, visit);
  return found;
}

// #1533 — is a caller declared `async` that contains ZERO awaits actually doing the I/O the
// exemption credits it with? It can only be doing it by RETURNING a promise or by scheduling one,
// so read the returns and look for nested async work. Spare unless neither is present.
function asyncCallerDoesNoAsyncWork(caller: ts.Node, path: string, sf: ts.SourceFile, resolve: CalleeResolver): boolean {
  if (doesOwnIo(bodyOf(caller)) || schedulesAsyncWork(bodyOf(caller))) return false;
  const rets = returnedExpressions(caller);
  // No return at all says nothing: inbox-zero's `analyzeSenderPatternIfAiMatch` does its I/O inside
  // a fire-and-forget `after(async () => …)` callback, which is a genuine seam.
  if (rets.length === 0) return false;
  return rets.every((r) => isProvablySynchronous(r, bodyOf(caller), path, sf, resolve, 2));
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
// pinned corpus targets at their pinned commits with and without this exemption: it spares
// 653 candidates, 26% of inbox-zero's whole M5-slop reading and 20% of tanstack-com's.
// The pin count this paragraph originally gave ("ten") is NOT reproducible and has been removed
// rather than corrected: `src/scan/external-corpus.ts` carried FOURTEEN M5-slop baselines at
// dfff5a8/5c983ea when the 653 was drawn and carries SEVENTEEN now (#1524 added cravab, flori-web
// and effective on 2026-07-30), so "ten" describes neither, and the measuring script was not
// committed, so the repo does not record which subset the 653 / 592 / 380 actually cover.
// Re-deriving them is a re-run, not a recovery: clone the pins and diff the detector with and
// without the exemption, which is how the async-caller figures below were re-measured.
// Pinning those three totals to a stated population is part of #1660. The async-caller figures
// below ARE re-derived here and carry their own scope. A seeded
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
//   * #1660 SETTLED, 2026-07-31: "a caller whose awaits never touch the helper's result" had two
//     candidate readings (401/653 inherited from #1532 with no stated predicate; 411/653 from an
//     independently written predicate; 380/592 from the predicate PR #1654 shipped) — three
//     unreconciled figures for one quantity, one of them client-facing. Settled on definition (b):
//     DATAFLOW through a one-hop local binding, implemented as `callerAwaitTouchesHelperResult`
//     below — the call expression, or an identifier a same-scope `const`/`let` binds to its result,
//     is read inside an `await` operand. Chosen over the purely lexical "is the call syntactically
//     inside an await" reading (a) because (a) calls `const x = helper(); await save(x)` a
//     non-touch even though the awaited call's argument IS the helper's result, which is exactly
//     the shape the three prior figures disagreed on. RE-MEASURED over ALL SEVENTEEN pinned
//     M5-slop targets with THIS predicate, reproducible via
//     `pnpm exec tsx src/cli/measure-m5-caller-await.ts` against `src/scan/external-corpus.ts`'s
//     pins (a mechanism, not a one-off script — re-run it if this number is suspected stale): 624
//     spared corpus-wide (not 592/653, both of which were measured over a ten/fourteen-target
//     subset before cravab/flori-web/effective were pinned — see the SCOPE note below). Of those
//     624: 599 have a caller that awaits SOMETHING, of which 407 never touch the helper's result
//     and 192 do (spared anyway — this file's deliberate conservatism, see the next paragraph);
//     25 have an async caller that awaits nothing (the next bullet's class). The 50-row sample
//     below and its "36 of them" draw predate this re-measurement and are kept for their own
//     finding (5 wrongly-spared defects, since fixed by `doesOwnIo`) — they are not re-drawn here,
//     since #1660 is a definition/reconciliation fix, not a fresh precision audit.
//     Of the sample's 36 drawn from the (then 653-row) caller-awaits population, 3 were among the
//     5 `doesOwnIo` defects above and now fire, and every one of the 33 that REMAIN spared was a
//     genuine seam. So this shape is not itself the error — the caller is entangled with I/O
//     either way, so extracting the pure half still buys what the brief asks for.
//   * 39 of 653 have a caller declared `async` with ZERO awaits. #1533 NARROWED this one rather
//     than leaving it disclosed, using the cross-file resolver `buildImportGraph` is built on. An
//     async caller that awaits nothing can only be doing I/O by RETURNING a promise, so the returns
//     are read and the row fires only when EVERY one of them is provably synchronous — a `new`
//     expression, a literal, or a call whose callee resolves (same file, or one repo-local import
//     hop) to a function that is itself not async, awaits nothing, and returns only such values.
//     Everything it does not resolve — a method call, a parameter, a package outside the repo —
//     stays spared, so the firing direction is the one that has to be earned.
//     RE-MEASURED 2026-07-31, by running the detector over each pinned clone three times — as
//     shipped, with this class forced to spare, and with it forced to fire — so the class is sized
//     by difference rather than by inspection. Over the fourteen pins this bullet's siblings were
//     measured on: the class is 38, of which 14 now fire and 24 stay spared. An earlier draft of
//     this line said "14 of the 39 … 25 stay spared": 39 was the population BEFORE #1532's
//     `doesOwnIo`, which had already recovered one of those rows on its own (inbox-zero
//     apps/web/scripts/eval-report/generate-eval-report.ts:78 `findWorkspaceRoot` calls
//     `fs.existsSync` in its own body at :83), so the subtraction was stale by one and disagreed
//     with the 24 the `evidence` string below correctly ships.
//     SCOPE, stated rather than assumed: `src/scan/external-corpus.ts` carries SEVENTEEN M5-slop
//     baselines today, not fourteen — #1524 added cravab, flori-web and effective on 2026-07-30,
//     after this population was drawn. They are deliberately NOT folded into the figures above,
//     which would mix two populations across one bullet list; measured separately, they add 10 to
//     the class (cravab 9, flori-web 1) of which 9 fire, for 48 / 23 / 25 across all seventeen —
//     #1660's independent same-classifier re-measurement above reproduces this exactly (25 async-
//     no-proof-sync across all seventeen), which cross-checks both measurements.
//     Every one of the 14 was read at source. The three rows the class was named for come out right:
//     mvp-boilerplate app/api/og/route.tsx:15 fires (`return new ImageResponse(…)`), inbox-zero
//     utils/outlook/mail.ts:408 stays spared (`return sendEmailWithHtml(…)`, a local async), and
//     saas-lite app/sitemap.xml/route.ts:24 stays spared — that third one CORRECTS #1533's body,
//     which called its caller synchronous: it returns `getServerSideSitemap(…)` from `next-sitemap`,
//     outside the repo and unreadable here, so it is a disclosed miss, not a proven seam.
// #1660 — SETTLED definition of "the caller's awaits touch the helper's result": the helper's
// call expression, or an identifier bound to its result by a same-scope `const`/`let` declared
// in the caller (one hop — matching this file's existing one-hop local-binding convention in
// `isProvablySynchronous`/`asyncCallerDoesNoAsyncWork`), is read inside an `await` expression's
// operand. This is definition (b) from #1660's two candidates — dataflow through a direct local
// binding — over definition (a), a purely lexical "is the call syntactically inside an await"
// check: (a) would call `const x = helper(); await save(x)` a non-touch even though the awaited
// call's argument IS the helper's result, which is the shape #1660 named as the reason the two
// definitions diverge. `await helper()` directly, and `const x = helper(); await save(x)`, both
// read as "touches"; `const x = helper(); await somethingElse()` does not.
function callerAwaitTouchesHelperResult(enclosing: ts.Node, calleeName: string): boolean {
  const boundNames = new Set<string>();
  const isHelperCall = (n: ts.Node): boolean => ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === calleeName;
  const mentionsHelper = (n: ts.Node): boolean => {
    if (isHelperCall(n)) return true;
    if (ts.isIdentifier(n) && boundNames.has(n.text)) return true;
    return ts.forEachChild(n, mentionsHelper) ?? false;
  };
  let touches = false;
  const visit = (n: ts.Node) => {
    if (touches) return;
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && isHelperCall(n.initializer)) boundNames.add(n.name.text);
    if (ts.isAwaitExpression(n) && mentionsHelper(n.expression)) {
      touches = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(enclosing);
  return touches;
}

type SeamOutcome = "fires-not-pure" | "fires-no-caller-await" | "fires-async-provably-sync" | "spared-caller-awaits" | "spared-async-no-proof-sync";
const SPARED_OUTCOMES: ReadonlySet<SeamOutcome> = new Set(["spared-caller-awaits", "spared-async-no-proof-sync"]);

// The one place that decides fire-vs-spare — `isTestabilitySeam` and the #1660 measurement CLI
// (`src/cli/measure-m5-caller-await.ts`) both read this, so the number that ships in the finding's
// `evidence` string can never diverge from what actually fires (the #1660 failure mode: two
// independently typed literal numbers for one quantity).
function helperSeamOutcome(helperBody: ts.Node, isAsyncHelper: boolean, callSite: ts.CallExpression, path: string, sf: ts.SourceFile, resolve: CalleeResolver): SeamOutcome {
  if (isAsyncHelper || containsAwait(helperBody) || doesOwnIo(helperBody, { path, sf, resolve })) return "fires-not-pure"; // the helper does the I/O — not a pure seam
  let enclosing: ts.Node | undefined = callSite.parent;
  while (enclosing && !ts.isFunctionLike(enclosing)) enclosing = enclosing.parent;
  if (!enclosing) return "fires-no-caller-await";
  if (containsAwait(enclosing)) return "spared-caller-awaits";
  if (!isAsync(enclosing)) return "fires-no-caller-await";
  return asyncCallerDoesNoAsyncWork(enclosing, path, sf, resolve) ? "fires-async-provably-sync" : "spared-async-no-proof-sync";
}

function isTestabilitySeam(helperBody: ts.Node, isAsyncHelper: boolean, callSite: ts.CallExpression, path: string, sf: ts.SourceFile, resolve: CalleeResolver): boolean {
  return SPARED_OUTCOMES.has(helperSeamOutcome(helperBody, isAsyncHelper, callSite, path, sf, resolve));
}

interface SingleUseHelperCandidate {
  name: string;
  node: ts.Node;
  declNode: ts.Node;
  body: ts.Node;
  async: boolean;
}

function collectSingleUseHelperCandidates(sf: ts.SourceFile): SingleUseHelperCandidate[] {
  const candidates: SingleUseHelperCandidate[] = [];
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
  return candidates;
}

// #1660's measurement CLI, exported so it reuses the exact classification `detectSingleUseHelper`
// fires from — never a second, hand-rolled walk that could drift from production behaviour.
interface SingleUseHelperClassification {
  location: string;
  name: string;
  outcome: SeamOutcome;
  awaitTouchesResult?: boolean; // set only when outcome === "spared-caller-awaits"
}

export function classifySingleUseHelperCandidates(files: SourceInput[]): SingleUseHelperClassification[] {
  const resolve = makeCalleeResolver(files);
  const out: SingleUseHelperClassification[] = [];
  for (const f of files) {
    if (!SOURCE_FILE.test(f.path)) continue;
    const sf = parse(f.path, f.text);
    for (const c of collectSingleUseHelperCandidates(sf)) {
      const sites = callSites(sf, c.name, c.declNode);
      if (sites.length !== 1) continue;
      const outcome = helperSeamOutcome(c.body, c.async, sites[0]!, f.path, sf, resolve);
      let enclosing: ts.Node | undefined = sites[0]!.parent;
      while (enclosing && !ts.isFunctionLike(enclosing)) enclosing = enclosing.parent;
      out.push({
        location: `${f.path}:${lineOf(sf, c.node)}`,
        name: c.name,
        outcome,
        awaitTouchesResult: outcome === "spared-caller-awaits" && enclosing ? callerAwaitTouchesHelperResult(enclosing, c.name) : undefined,
      });
    }
  }
  return out;
}

function detectSingleUseHelper(sf: ts.SourceFile, path: string, nextId: NextId, resolve: CalleeResolver): Finding[] {
  const findings: Finding[] = [];
  for (const c of collectSingleUseHelperCandidates(sf)) {
    const sites = callSites(sf, c.name, c.declNode);
    if (sites.length !== 1) continue;
    if (isTestabilitySeam(c.body, c.async, sites[0]!, path, sf, resolve)) continue;
    findings.push(
      makeFinding(nextId, {
        title: `Single-use helper \`${c.name}\` is only called from one site`,
        severity: "Low",
        confidence: "Review",
        taxonomy: "M5 — Single-use helper",
        location: `${path}:${lineOf(sf, c.node)}`,
        evidence: `\`${c.name}\` is a non-exported helper with a real body, called from exactly one place in this file. Scope of this rule: it counts call sites WITHIN this file only, and it exempts a helper that does no I/O of its own whose one caller is async or awaits — the testability seam \`briefs/quality-extras.txt\` demands — so this one is not that shape. What the exemption costs is MEASURED, not estimated: re-measured 2026-07-31 with the SETTLED #1660 predicate (dataflow through a one-hop local binding — see \`callerAwaitTouchesHelperResult\`) over ALL SEVENTEEN pinned M5-slop corpus targets (\`pnpm exec tsx src/cli/measure-m5-caller-await.ts\`, reproducible against \`src/scan/external-corpus.ts\`'s pins). It spares 624 helpers, of which 407 have a caller whose awaits never touch the helper's result under that settled predicate (192 do touch it and are spared anyway — the exemption's deliberate conservatism, see this file's source comment), and 25 have a caller declared async that awaits nothing and whose returns could not be shown to be synchronous — so a genuinely single-use helper sitting next to unrelated I/O is still spared with them. A 50-row seeded sample of the pre-#1532 population, read at source, put the wrongly-spared rate at 10% (95% CI 4.3–21.4%).`,
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
  const resolve = makeCalleeResolver(files);
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
      ...detectSingleUseHelper(sf, f.path, nextId, resolve),
      ...detectUnreachableBranch(sf, f.path, nextId),
    );
  }
  return findings;
}
