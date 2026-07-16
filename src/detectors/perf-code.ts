// M7 (code layer) — code-level performance detectors (#170). Static AST checks over
// TypeScript/TSX source for DB-independent performance cost: React render waste, N+1 /
// unbounded data fetching, bundle weight, and request-path blocking work. Complements the
// connected-tier Supabase performance advisor (src/perf-scan.ts) so M7 says something on
// source-only engagements. Shapes results as Finding[] (src/findings.ts) for §3b Performance.
//
// Method: TypeScript compiler API, same conventions as the M9 detector (app-router.ts).
// Every check here is mechanical ([M] in the #170 catalog); the [B] bundle-stats and [L]
// review-tier classes are deliberately not in this module. Per-check limitations are in
// docs/m7-performance.md §2a.
//
// React Compiler: when the target's next.config/babel config enables it, the manual-memo
// classes (context value / inline literal props) are auto-fixed by compilation, so those
// findings are downgraded to Info instead of dropped — visible but not counted as work.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { callChainNames, leadingDirective, loc, parse, type NextId, type SourceInput } from "./common.js";

export type { SourceInput } from "./common.js";

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
  return { id: nextId(), status: "Open", category: "Performance", ...input };
}

// Render-once contexts — email templates and PDF documents render exactly once per send/
// export, so the React re-render classes don't apply (and email clients REQUIRE raw <img>).
// Signals (ATC dogfood, 2026-07-10): an @react-email/@react-pdf import, or an emails/ path
// segment (plain-JSX templates rendered via renderToStaticMarkup carry no import marker).
const RENDER_ONCE_IMPORT = /^@react-(email|pdf)(\/|$)/;
const RENDER_ONCE_PATH = /(^|\/)emails?\//;

function isRenderOnce(path: string, sf: ts.SourceFile): boolean {
  if (RENDER_ONCE_PATH.test(path)) return true;
  return sf.statements.some(
    (s) => ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier) && RENDER_ONCE_IMPORT.test(s.moduleSpecifier.text),
  );
}

// A JSX tag that renders a component (not a DOM element): capitalized or member access.
function isComponentTag(tagText: string): boolean {
  return /^[A-Z]/.test(tagText) || tagText.includes(".");
}

function isContextTag(tagText: string): boolean {
  return tagText.endsWith(".Provider") || /Context$/.test(tagText);
}

function jsxAttrExpression(attr: ts.JsxAttributeLike): ts.Expression | undefined {
  if (!ts.isJsxAttribute(attr) || !attr.initializer) return undefined;
  if (!ts.isJsxExpression(attr.initializer)) return undefined;
  return attr.initializer.expression;
}

function forEachJsxElement(sf: ts.SourceFile, cb: (el: ts.JsxOpeningElement | ts.JsxSelfClosingElement) => void): void {
  const visit = (node: ts.Node) => {
    if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) cb(node);
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

// --- React Compiler gate -----------------------------------------------------

// The `reactCompiler:` value in next.config, classified from its literal source text.
// "unresolvable" covers anything that isn't a literal `true`/`false`/object (e.g. an
// identifier read from `process.env`, as in saas-lite's `reactCompiler: ENABLE_REACT_COMPILER`)
// — we can't know at scan time what that evaluates to (#249).
type CompilerFlagValue = { status: "on" | "off"; file?: never; raw?: never } | { status: "unresolvable"; file: string; raw: string; index: number };

function reactCompilerFlag(files: SourceInput[]): CompilerFlagValue {
  for (const f of files) {
    const base = f.path.split("/").pop() ?? "";
    if (/^(\.babelrc|\.babelrc\.json|babel\.config\.(js|json|mjs|cjs))$/.test(base) && f.text.includes("react-compiler")) {
      return { status: "on" };
    }
    if (!/^next\.config\.(js|mjs|cjs|ts)$/.test(base)) continue;
    const m = /reactCompiler\s*:\s*([^,}\n]+)/.exec(f.text);
    if (!m) continue;
    const raw = m[1]!.trim();
    if (/^true$/.test(raw) || raw.startsWith("{")) return { status: "on" };
    if (/^false$/.test(raw)) return { status: "off" };
    return { status: "unresolvable", file: f.path, raw, index: m.index + m[0].indexOf(raw) };
  }
  return { status: "off" };
}

// True when the target enables React Compiler (next.config `reactCompiler: true|{...}` under
// experimental or top-level, or babel-plugin-react-compiler in a babel config). Auto-memoization
// then covers the manual-memo classes below, so they report as Info instead of Perf/Low.
// A variable/env-derived flag is NOT treated as "on" here — see reactCompilerFlag above and
// detectUnresolvableCompilerFlag, which surfaces that case instead of silently assuming false.
export function reactCompilerEnabled(files: SourceInput[]): boolean {
  return reactCompilerFlag(files).status === "on";
}

const COMPILER_NOTE =
  " React Compiler is enabled in this project's config, so this shape is auto-memoized at build time — reported as informational only.";

// --- A0. React Compiler flag can't be statically resolved [WATCH] ------------

function detectUnresolvableCompilerFlag(files: SourceInput[], nextId: NextId): Finding[] {
  const flag = reactCompilerFlag(files);
  if (flag.status !== "unresolvable") return [];
  const line = flag.file
    ? files.find((f) => f.path === flag.file)!.text.slice(0, flag.index).split("\n").length
    : 1;
  return [
    makeFinding(nextId, {
      title: "React Compiler flag set from a variable — cannot be statically resolved",
      severity: "Watch",
      confidence: "Review",
      taxonomy: "M7 — React Compiler flag unresolvable",
      location: `${flag.file}:${line}`,
      evidence: `\`reactCompiler: ${flag.raw}\` reads its value from a variable/env rather than a literal \`true\`/\`false\`/object, so this scan can't confirm at scan time whether React Compiler is actually enabled at build/runtime.`,
      impact: "If this resolves to true in the deployed build, the manual-memo findings below (context value / inline literal props) are auto-fixed by the compiler and shouldn't count as outstanding work. Until confirmed, this audit conservatively keeps them at counted severity rather than assuming the flag is off.",
      fix: "Confirm the resolved value of this flag for the deployed build (check the variable/env var's actual value) and re-triage the manual-memo M7 findings accordingly.",
      value: 1,
      ease: 5,
      safety: 5,
    }),
  ];
}

// --- A1. Context value recreated every render [PERF] ------------------------

// Whether `contextName`'s Context object is actually created (`createContext(...)`) somewhere
// in this project's own scanned sources — as opposed to a shadcn/ui or other library primitive
// whose Provider the app merely re-exports/wraps. The app doesn't own that context's
// memoization; flagging it is noise the app can't act on (#230 dogfood FP).
function isLocallyDefinedContext(contextName: string, sources: Map<string, ts.SourceFile>): boolean {
  for (const sf of sources.values()) {
    let found = false;
    const visit = (n: ts.Node) => {
      if (found) return;
      if (
        ts.isVariableDeclaration(n) &&
        ts.isIdentifier(n.name) &&
        n.name.text === contextName &&
        n.initializer &&
        ts.isCallExpression(n.initializer) &&
        ts.isIdentifier(n.initializer.expression) &&
        n.initializer.expression.text === "createContext"
      ) {
        found = true;
        return;
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
    if (found) return true;
  }
  return false;
}

function detectContextValueLiteral(sources: Map<string, ts.SourceFile>, nextId: NextId, compilerOn: boolean): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (isRenderOnce(path, sf)) continue; // email/PDF templates render once — re-render classes don't apply
    forEachJsxElement(sf, (el) => {
      const tagText = el.tagName.getText(sf);
      if (!isContextTag(tagText)) return;
      if (!isLocallyDefinedContext(tagText.replace(/\.Provider$/, ""), sources)) return; // a library/shadcn-owned context, not app state to memoize
      for (const attr of el.attributes.properties) {
        if (!ts.isJsxAttribute(attr) || attr.name.getText(sf) !== "value") continue;
        const expr = jsxAttrExpression(attr);
        if (!expr) continue;
        if (!ts.isObjectLiteralExpression(expr) && !ts.isArrayLiteralExpression(expr) && !ts.isArrowFunction(expr)) continue;
        findings.push(
          makeFinding(nextId, {
            title: `Context value recreated on every render of <${tagText}>`,
            severity: compilerOn ? "Info" : "Perf",
            confidence: "Likely",
            taxonomy: "M7 — Context value recreated every render",
            location: loc(path, sf, attr),
            evidence: `\`value={${expr.getText(sf).slice(0, 80)}}\` is a fresh literal each render, so every consumer of ${tagText} re-renders whenever this provider's parent does.${compilerOn ? COMPILER_NOTE : ""}`,
            impact: "Every context consumer in the subtree re-renders on unrelated parent state changes — the classic app-wide re-render amplifier.",
            fix: "Memoize the provider value (`useMemo(() => ({...}), [deps])`) or split the context so its value is stable.",
            value: 4,
            ease: 5,
            safety: 5,
          }),
        );
      }
    });
  }
  return findings;
}

// --- A2. Inline object/array literal props [LOW] — one per file --------------

// framer-motion components (`<motion.div>`, or the `m.div` shorthand) take animation props
// (animate/initial/exit/transition/variants) that are idiomatically inline object literals —
// the library diffs by value every render regardless of reference identity, so there's no
// memoization win to chase here (#230 dogfood FP).
const FRAMER_MOTION_TAG = /^(motion|m)\./;

// An array built entirely from i18n translation calls (`[t("a"), t("b")]` /
// `[i18n.t("a")]`) — a fresh array each render is unavoidable since the strings themselves
// are looked up live; there's nothing stable to hoist (#230 dogfood FP: `cols={[t(...)]}`).
function isTranslationCallArray(expr: ts.Expression): boolean {
  if (!ts.isArrayLiteralExpression(expr) || expr.elements.length === 0) return false;
  return expr.elements.every((el) => {
    if (!ts.isCallExpression(el)) return false;
    const callee = el.expression;
    if (ts.isIdentifier(callee)) return callee.text === "t";
    if (ts.isPropertyAccessExpression(callee)) return callee.name.text === "t";
    return false;
  });
}

function detectInlinePropLiterals(sources: Map<string, ts.SourceFile>, nextId: NextId, compilerOn: boolean): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (isRenderOnce(path, sf)) continue; // email/PDF templates render once — re-render classes don't apply
    const hits: { attr: ts.JsxAttribute; tagText: string }[] = [];
    forEachJsxElement(sf, (el) => {
      const tagText = el.tagName.getText(sf);
      if (!isComponentTag(tagText)) return; // DOM elements don't re-render as components
      if (FRAMER_MOTION_TAG.test(tagText)) return; // animation props are idiomatically inline — no memoization win
      for (const attr of el.attributes.properties) {
        if (!ts.isJsxAttribute(attr)) continue;
        const attrName = attr.name.getText(sf);
        if (isContextTag(tagText) && attrName === "value") continue; // A1 owns that shape
        if (attrName === "style") continue; // inline style objects are idiomatic and near-zero cost to recreate
        const expr = jsxAttrExpression(attr);
        if (expr && isTranslationCallArray(expr)) continue; // built from live i18n lookups — nothing stable to hoist
        if (expr && (ts.isObjectLiteralExpression(expr) || ts.isArrayLiteralExpression(expr))) {
          hits.push({ attr, tagText });
        }
      }
    });
    const first = hits[0];
    if (!first) continue;
    findings.push(
      makeFinding(nextId, {
        title: `Inline object/array literals passed as component props (${hits.length}× in ${path})`,
        severity: compilerOn ? "Info" : "Low",
        confidence: "Review",
        taxonomy: "M7 — Inline literal prop",
        location: loc(path, sf, first.attr),
        evidence: `\`${first.attr.getText(sf).slice(0, 80)}\` on <${first.tagText}> (first of ${hits.length}) — a new reference every render, so \`memo\`/\`useMemo\` on the child can never bail out.${compilerOn ? COMPILER_NOTE : ""}`,
        impact: "Defeats memoization on the receiving component; only costs when the child is (or should be) memoized — confirm before reporting.",
        fix: "Hoist static literals to module scope; memoize computed ones with `useMemo`.",
        value: 2,
        ease: 4,
        safety: 5,
      }),
    );
  }
  return findings;
}

// --- A3. Raw <img> instead of next/image [PERF] — one per file ---------------

// A `src` that's a data:/blob: URI (or `URL.createObjectURL(...)`) — a client-generated,
// one-shot image (MFA QR code in a dialog, an authenticated in-memory blob preview) that
// `next/image` can't optimize anyway since there's no remote URL for it to fetch/resize
// (#230 dogfood FP).
const ONE_SHOT_IMG_SRC = /^(data|blob):/;

function isOneShotImgSrc(el: ts.JsxOpeningElement | ts.JsxSelfClosingElement, sf: ts.SourceFile): boolean {
  for (const attr of el.attributes.properties) {
    if (!ts.isJsxAttribute(attr) || attr.name.getText(sf) !== "src") continue;
    const expr = jsxAttrExpression(attr);
    if (!expr) continue;
    if (ts.isStringLiteralLike(expr) && ONE_SHOT_IMG_SRC.test(expr.text)) return true;
    if (ts.isTemplateExpression(expr) && ONE_SHOT_IMG_SRC.test(expr.head.text)) return true;
    if (
      ts.isCallExpression(expr) &&
      ts.isPropertyAccessExpression(expr.expression) &&
      expr.expression.name.text === "createObjectURL"
    ) {
      return true;
    }
  }
  return false;
}

function detectRawImgElement(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (isRenderOnce(path, sf)) continue; // email/PDF templates render once — re-render classes don't apply
    if (sf.text.includes("@next/next/no-img-element")) continue; // the codebase already adjudicated its <img>s via an explicit eslint-disable
    const hits: (ts.JsxOpeningElement | ts.JsxSelfClosingElement)[] = [];
    forEachJsxElement(sf, (el) => {
      if (el.tagName.getText(sf) === "img" && !isOneShotImgSrc(el, sf)) hits.push(el);
    });
    const first = hits[0];
    if (!first) continue;
    findings.push(
      makeFinding(nextId, {
        title: `Raw <img> instead of next/image (${hits.length}× in ${path})`,
        severity: "Perf",
        confidence: "Likely",
        taxonomy: "M7 — Raw <img> instead of next/image",
        location: loc(path, sf, first),
        evidence: `\`${first.getText(sf).slice(0, 80)}\` — served at original size/format with no lazy-loading or srcset, and no reserved layout box.`,
        impact: "Slower LCP (unoptimized bytes, no priority hints) and CLS from late-loading unsized images.",
        fix: "Use `next/image` (automatic resizing, modern formats, lazy-load, layout reservation); add `priority` on the LCP image.",
        value: 3,
        ease: 4,
        safety: 5,
      }),
    );
  }
  return findings;
}

// --- A4. Array index used as list key [LOW] ----------------------------------

// #230: a hardcoded `const NAV_LINKS = [...]` (or an inline array literal) never reorders,
// inserts, or deletes at runtime — the whole failure mode index-as-key guards against can't
// happen. ATC dogfood: every raw hit in this shape was a Footer/FAQ/Stepper-style static list.
function isStaticListSource(sf: ts.SourceFile, source: ts.Expression): boolean {
  if (ts.isArrayLiteralExpression(source)) return true;
  if (!ts.isIdentifier(source)) return false;
  const name = source.text;
  let isStatic = false;
  const visit = (n: ts.Node) => {
    if (isStatic) return;
    if (
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.name.text === name &&
      n.initializer &&
      ts.isArrayLiteralExpression(n.initializer) &&
      n.parent &&
      ts.isVariableDeclarationList(n.parent) &&
      (n.parent.flags & ts.NodeFlags.Const) !== 0
    ) {
      isStatic = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return isStatic;
}

function detectIndexAsKey(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (isRenderOnce(path, sf)) continue; // email/PDF templates render once — re-render classes don't apply
    const visit = (node: ts.Node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === "map" &&
        !isStaticListSource(sf, node.expression.expression) // a hardcoded/literal list — reorder/insert/delete can't happen
      ) {
        const cb = node.arguments[0];
        if (cb && (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb))) {
          const idxParam = cb.parameters[1];
          const idxName = idxParam && ts.isIdentifier(idxParam.name) ? idxParam.name.text : undefined;
          if (idxName) {
            const findKeyAttr = (n: ts.Node): ts.JsxAttribute | undefined => {
              if (ts.isJsxAttribute(n) && n.name.getText(sf) === "key") {
                const expr = jsxAttrExpression(n);
                if (expr && ts.isIdentifier(expr) && expr.text === idxName) return n;
              }
              return ts.forEachChild(n, findKeyAttr);
            };
            const keyAttr = findKeyAttr(cb.body);
            if (keyAttr) {
              findings.push(
                makeFinding(nextId, {
                  title: "Array index used as React list key",
                  severity: "Low",
                  confidence: "Likely",
                  taxonomy: "M7 — Index used as list key",
                  location: loc(path, sf, keyAttr),
                  evidence: `\`key={${idxName}}\` inside \`.map((…, ${idxName}) => …)\` — the key changes for every item when the list reorders, inserts, or deletes.`,
                  impact: "Insert/remove/reorder re-mounts (not updates) every following row — wasted renders plus lost input/focus state.",
                  fix: "Key on a stable identity from the item itself (`item.id`), never the position.",
                  value: 2,
                  ease: 5,
                  safety: 5,
                }),
              );
            }
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return findings;
}

// --- A5. Sort in render body (inside JSX) [LOW] -------------------------------

function detectSortInJsx(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (isRenderOnce(path, sf)) continue; // email/PDF templates render once — re-render classes don't apply
    const visit = (node: ts.Node) => {
      if (ts.isJsxExpression(node) && node.expression) {
        let hit: ts.CallExpression | undefined;
        const findSort = (n: ts.Node) => {
          if (hit) return;
          if (
            ts.isCallExpression(n) &&
            ts.isPropertyAccessExpression(n.expression) &&
            (n.expression.name.text === "sort" || n.expression.name.text === "toSorted")
          ) {
            hit = n;
            return;
          }
          ts.forEachChild(n, findSort);
        };
        findSort(node.expression);
        if (hit) {
          findings.push(
            makeFinding(nextId, {
              title: "List sorted inside JSX on every render",
              severity: "Low",
              confidence: "Review",
              taxonomy: "M7 — Sort in render body",
              location: loc(path, sf, hit),
              evidence: `\`${hit.getText(sf).slice(0, 80)}\` runs directly in JSX — an O(n log n) pass on every render${hit.expression.getText(sf).endsWith("toSorted") ? "" : ", and `.sort()` mutates the source array in place (a state/props mutation if it came from either)"}.`,
              impact: "Re-sorts on every unrelated re-render; in-place `.sort()` on props/state also causes subtle stale-render bugs.",
              fix: "Move the sort into `useMemo(() => [...items].sort(…), [items])` (or sort where the data is produced).",
              value: 2,
              ease: 4,
              safety: 5,
            }),
          );
          return; // one per JSX expression is enough
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return findings;
}

// --- A6. State sprawl — god component [LOW] -----------------------------------

const STATE_SPRAWL_THRESHOLD = 8;

function detectStateSprawl(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (isRenderOnce(path, sf)) continue; // email/PDF templates render once — re-render classes don't apply
    const checkComponent = (name: string, fn: ts.Node) => {
      let count = 0;
      const countStates = (n: ts.Node) => {
        if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "useState") count++;
        ts.forEachChild(n, countStates);
      };
      countStates(fn);
      if (count >= STATE_SPRAWL_THRESHOLD) {
        findings.push(
          makeFinding(nextId, {
            title: `Component ${name} holds ${count} useState hooks`,
            severity: "Low",
            confidence: "Review",
            taxonomy: "M7 — State sprawl",
            location: loc(path, sf, fn),
            evidence: `${name} declares ${count} separate useState hooks — every setter triggers a full re-render of this (evidently large) component.`,
            impact: "Frequent broad re-renders and interlocking state updates; a symptom the component owns too much.",
            fix: "Consolidate related state into `useReducer` (or extract child components that own their own slice).",
            value: 2,
            ease: 2,
            safety: 4,
          }),
        );
      }
    };
    for (const stmt of sf.statements) {
      if (ts.isFunctionDeclaration(stmt) && stmt.name && /^[A-Z]/.test(stmt.name.text) && stmt.body) {
        checkComponent(stmt.name.text, stmt);
      } else if (ts.isVariableStatement(stmt)) {
        for (const decl of stmt.declarationList.declarations) {
          if (
            ts.isIdentifier(decl.name) &&
            /^[A-Z]/.test(decl.name.text) &&
            decl.initializer &&
            (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))
          ) {
            checkComponent(decl.name.text, decl.initializer);
          }
        }
      }
    }
  }
  return findings;
}

// --- B1. Await in a loop over a collection — N+1 [PERF] ------------------------

// Identifiers assigned (not declared) anywhere in the loop body — the loop-carried-state
// signal. `cursor = page.next` makes iterations genuinely sequential; skip those loops.
function collectAssignedNames(body: ts.Node): Set<string> {
  const names = new Set<string>();
  const visit = (n: ts.Node) => {
    if (ts.isBinaryExpression(n) && n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && n.operatorToken.kind <= ts.SyntaxKind.LastAssignment && ts.isIdentifier(n.left)) {
      names.add(n.left.text);
    } else if ((ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) && ts.isIdentifier(n.operand)) {
      names.add(n.operand.text);
    }
    ts.forEachChild(n, visit);
  };
  visit(body);
  return names;
}

function loopBindingNames(stmt: ts.ForOfStatement | ts.ForInStatement | ts.ForStatement): Set<string> {
  const names = new Set<string>();
  const init = stmt.initializer;
  if (init && ts.isVariableDeclarationList(init)) {
    for (const d of init.declarations) {
      if (ts.isIdentifier(d.name)) names.add(d.name.text);
      if (ts.isObjectBindingPattern(d.name) || ts.isArrayBindingPattern(d.name)) {
        for (const el of d.name.elements) {
          if (ts.isBindingElement(el) && ts.isIdentifier(el.name)) names.add(el.name.text);
        }
      }
    }
  }
  return names;
}

function referencesAny(node: ts.Node, names: Set<string>): boolean {
  if (names.size === 0) return false;
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isIdentifier(n) && names.has(n.text)) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

// Awaits directly in the loop body — not inside nested function boundaries.
function collectAwaits(body: ts.Node): ts.AwaitExpression[] {
  const awaits: ts.AwaitExpression[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isFunctionDeclaration(n) || ts.isArrowFunction(n) || ts.isFunctionExpression(n)) return;
    if (ts.isAwaitExpression(n)) awaits.push(n);
    ts.forEachChild(n, visit);
  };
  visit(body);
  return awaits;
}

// A chunked-batch loop (`for (let i = 0; …; i += BATCH_SIZE)`) is the FIX for N+1, not the
// bug — the step deliberately trades round-trips for statement size (ATC dogfood FP shape).
function isBatchChunkLoop(stmt: ts.ForStatement): boolean {
  const inc = stmt.incrementor;
  if (!inc || !ts.isBinaryExpression(inc) || inc.operatorToken.kind !== ts.SyntaxKind.PlusEqualsToken) return false;
  return !(ts.isNumericLiteral(inc.right) && inc.right.text === "1");
}

// User-facing request path (routes, pages, actions) vs background/batch (workers, jobs,
// scripts, lib helpers only jobs call). Both are real costs, but only the former is
// user-visible latency — the confidence tier and impact wording reflect that.
const REQUEST_PATH = /(^|\/)(app|pages)\//;

function detectAwaitInLoop(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    const hits: ts.AwaitExpression[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isForOfStatement(node) || ts.isForInStatement(node) || ts.isForStatement(node)) {
        const streaming = ts.isForOfStatement(node) && node.awaitModifier; // `for await … of` is sequential by design
        const chunked = ts.isForStatement(node) && isBatchChunkLoop(node);
        if (!streaming && !chunked) {
          const loopVars = loopBindingNames(node);
          const assigned = collectAssignedNames(node.statement);
          const awaits = collectAwaits(node.statement);
          // The N+1 signature: a per-item await (references the loop binding) whose input
          // doesn't depend on state carried across iterations.
          const perItem = awaits.find((a) => referencesAny(a.expression, loopVars) && !referencesAny(a.expression, assigned));
          if (perItem) hits.push(perItem);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
    const first = hits[0];
    if (!first) continue;
    const onRequestPath = REQUEST_PATH.test(path);
    findings.push(
      makeFinding(nextId, {
        title: `Per-item await inside a loop — serial N+1 round-trips (${hits.length} loop${hits.length === 1 ? "" : "s"} in ${path})`,
        severity: "Perf",
        confidence: onRequestPath ? "Likely" : "Review",
        taxonomy: "M7 — Await in loop (N+1)",
        location: loc(path, sf, first),
        evidence: `\`${first.getText(sf).slice(0, 100)}\`${hits.length > 1 ? ` (first of ${hits.length} such loops in this file)` : ""} runs once per iteration and each iteration's input is independent of the previous one — n items cost n serial round-trips.${onRequestPath ? "" : " This file is off the request path (worker/job/script), so the cost is job runtime and DB load rather than user-facing latency."}`,
        impact: onRequestPath
          ? "Latency scales linearly with collection size (100 rows ≈ 100 sequential network/DB round-trips on this path)."
          : "Job/batch runtime and DB load scale linearly with collection size; long-running workers hold connections and delay downstream steps.",
        fix: "Batch into one query (`.in(…)` / a join / an RPC) or run iterations concurrently with `Promise.all` (bounded if n can be large).",
        value: onRequestPath ? 4 : 3,
        ease: 4,
        safety: 4,
      }),
    );
  }
  return findings;
}

// --- B2. Unbounded select — no limit/pagination [PERF] --------------------------

// #230: `.in('id', [...])` bounds the result to the (finite) id list passed in — a specific-row
// lookup, not a table scan; `.insert(...)`/`.upsert(...)` before `.select()` bounds the result
// to the mutated rows, not the whole table. Both were raw hits mislabeled as unbounded scans.
const CHAIN_BOUNDS = new Set(["limit", "range", "single", "maybeSingle", "csv", "in", "insert", "upsert"]);

function detectUnboundedSelect(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    const visit = (node: ts.Node) => {
      // Only inspect the outermost call of a chain so one query flags once.
      if (ts.isCallExpression(node) && !(node.parent && ts.isPropertyAccessExpression(node.parent))) {
        const names = callChainNames(node);
        if (names.includes("from") && names.includes("select") && !names.some((n) => CHAIN_BOUNDS.has(n))) {
          const selectArg = findSelectArg(node);
          if ((selectArg === undefined || selectArg === "*") && !isCountOnlySelect(node)) {
            findings.push(
              makeFinding(nextId, {
                title: "Unbounded `select('*')` — whole table/partition fetched",
                severity: "Perf",
                confidence: "Review",
                taxonomy: "M7 — Unbounded select",
                location: loc(path, sf, node),
                evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` selects every column with no \`.limit()\`/\`.range()\` (and isn't a \`.single()\` read) — result size grows with the table.`,
                impact: "Response time and memory degrade as data grows; works in the demo, times out at 100k rows. (A deliberately small config table is benign — confirm table size before reporting.)",
                fix: "Select the columns the caller uses and page with `.range()`/`.limit()` (plus a cursor/page param on the API).",
                value: 3,
                ease: 4,
                safety: 4,
              }),
            );
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return findings;
}

// `select("*", { count: "exact", head: true })` fetches ZERO rows — it's a count query,
// not an unbounded read (ATC dogfood: half the raw hits were this shape).
function isCountOnlySelect(chainRoot: ts.CallExpression): boolean {
  let cur: ts.Expression = chainRoot;
  while (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
    if (cur.expression.name.text === "select") {
      const opts = cur.arguments[1];
      if (opts && ts.isObjectLiteralExpression(opts)) {
        return opts.properties.some(
          (p) =>
            ts.isPropertyAssignment(p) &&
            ts.isIdentifier(p.name) &&
            p.name.text === "head" &&
            p.initializer.kind === ts.SyntaxKind.TrueKeyword,
        );
      }
      return false;
    }
    cur = cur.expression.expression;
  }
  return false;
}

// First argument of the `.select(…)` link in the chain: its string text, or undefined if
// the call has no arguments (which the client treats as `*`). Returns "-" when the arg
// is a non-literal expression (dynamic column list — not decidable, treated as bounded).
function findSelectArg(chainRoot: ts.CallExpression): string | undefined | "-" {
  let cur: ts.Expression = chainRoot;
  while (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
    if (cur.expression.name.text === "select") {
      const arg = cur.arguments[0];
      if (!arg) return undefined;
      return ts.isStringLiteralLike(arg) ? arg.text : "-";
    }
    cur = cur.expression.expression;
  }
  return "-";
}

// --- B3. Client-side data fetch in useEffect [PERF] — one per file ---------------

// A 'use client' component fetching its own data on mount (`useEffect(() => { fetch(...) }, [])`
// or a Supabase read chain) instead of a Server Component fetch or a cache-aware client hook —
// the default shape AI assistants produce when they don't know App Router conventions (#383).
// Ships a client-server round trip after hydration, a loading spinner, and no request de-dup.

// Files that import a cache-aware data-fetching library already route client data through it —
// flagging their internals would be noise (issue #383's explicit exclusion).
const DATA_FETCH_LIB = /^(swr|@tanstack\/react-query|react-query)(\/|$)/;

function importsDataFetchLib(sf: ts.SourceFile): boolean {
  return sf.statements.some(
    (s) => ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier) && DATA_FETCH_LIB.test(s.moduleSpecifier.text),
  );
}

// A data READ: a `fetch(...)` whose result is consumed (`.then` chain or awaited — a bare
// fire-and-forget statement like `fetch("/api/track", {method:"POST"})` is a beacon, not a
// waterfall), or the outermost call of a Supabase `.from(...).select(...)` chain.
function isMountDataRead(n: ts.CallExpression): boolean {
  if (ts.isIdentifier(n.expression) && n.expression.text === "fetch") {
    return ts.isPropertyAccessExpression(n.parent) || ts.isAwaitExpression(n.parent);
  }
  if (!ts.isPropertyAccessExpression(n.parent)) {
    const names = callChainNames(n);
    return names.includes("from") && names.includes("select");
  }
  return false;
}

// Data reads that actually RUN when the effect runs: direct calls in the effect body, plus the
// bodies of IIFEs and of local functions the body invokes (`(async () => {...})()` and
// `const load = async () => {...}; load();` — the two common shapes). A nested function that is
// only DEFINED and handed elsewhere (an event-listener callback, a returned cleanup) does not
// run on mount and must not count — that's the user-action / unmount path, not a waterfall.
function mountDataReads(effectBody: ts.Node): ts.CallExpression[] {
  const reads: ts.CallExpression[] = [];
  const localFns = new Map<string, ts.Node>();
  const invoked = new Set<string>();
  const walked = new Set<string>();

  const walk = (n: ts.Node): void => {
    if (ts.isCallExpression(n)) {
      if (ts.isIdentifier(n.expression)) invoked.add(n.expression.text);
      const callee = ts.isParenthesizedExpression(n.expression) ? n.expression.expression : n.expression;
      if (ts.isArrowFunction(callee) || ts.isFunctionExpression(callee)) {
        walk(callee.body); // an IIFE's body runs on mount
        return;
      }
      if (isMountDataRead(n)) reads.push(n);
    }
    if (ts.isFunctionDeclaration(n) && n.name && n.body) {
      localFns.set(n.name.text, n.body);
      return;
    }
    if (
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.initializer &&
      (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))
    ) {
      localFns.set(n.name.text, n.initializer.body);
      return;
    }
    if (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) return; // defined, not invoked here
    ts.forEachChild(n, walk);
  };
  walk(effectBody);

  // Local functions the mount path invokes (directly or via another invoked one) also run.
  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, body] of localFns) {
      if (invoked.has(name) && !walked.has(name)) {
        walked.add(name);
        changed = true;
        walk(body);
      }
    }
  }
  return reads;
}

function detectClientFetchEffect(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (leadingDirective(sf) !== "use client") continue; // Server Components fetch server-side — that's the fix, not the bug
    if (isRenderOnce(path, sf)) continue;
    if (importsDataFetchLib(sf)) continue;
    const hits: ts.CallExpression[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "useEffect") {
        const cb = node.arguments[0];
        if (cb && (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb))) hits.push(...mountDataReads(cb.body));
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
    const first = hits[0];
    if (!first) continue;
    findings.push(
      makeFinding(nextId, {
        title: `Client-side data fetch in useEffect (${hits.length}× in ${path})`,
        severity: "Perf",
        confidence: "Review",
        taxonomy: "M7 — Client fetch in useEffect",
        location: loc(path, sf, first),
        evidence: `\`${first.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` runs on mount inside useEffect in a 'use client' component${hits.length > 1 ? ` (first of ${hits.length})` : ""} — the data round-trip starts only after the JS bundle downloads, parses, and hydrates, with no caching or request de-duplication.`,
        impact: "A serial network waterfall (HTML → JS → data) plus a loading spinner on every visit; concurrent mounts of the component each refetch. A Server Component fetch ships the data in the initial HTML; a cache hook de-dupes on the client.",
        fix: "Fetch in a Server Component (or route loader) and pass the data down; if it must stay client-side (third-party API, live widget), use a cache-aware hook (useSWR / React Query) instead of raw fetch-in-effect.",
        value: 3,
        ease: 3,
        safety: 4,
      }),
    );
  }
  return findings;
}

// --- C1. Whole-library import [PERF] --------------------------------------------

// CJS libraries where ANY bare import ships the entire package (no tree-shaking), plus
// the alternative to name in the fix.
const WHOLE_LIB: Record<string, string> = {
  lodash: "lodash-es (tree-shakeable) or per-method `lodash/pick` subpath imports",
  moment: "date-fns or dayjs (moment ships every locale and is in maintenance mode)",
  underscore: "lodash-es or native array/object methods",
};

// ESM barrels that are fine with named imports (Next's optimizePackageImports handles
// them) but ship whole under a namespace import.
const BARREL_NAMESPACE = new Set(["date-fns", "@mui/material", "@mui/icons-material", "lucide-react", "lodash-es", "ramda"]);

function detectWholeLibraryImport(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      const spec = stmt.moduleSpecifier.text;
      const isNamespace = !!stmt.importClause?.namedBindings && ts.isNamespaceImport(stmt.importClause.namedBindings);
      const alternative = WHOLE_LIB[spec] ?? (BARREL_NAMESPACE.has(spec) && isNamespace ? `named imports (\`import { x } from "${spec}"\`) so the barrel can be tree-shaken/optimized` : undefined);
      if (!alternative) continue;
      findings.push(
        makeFinding(nextId, {
          title: `Whole-library import of ${spec}`,
          severity: "Perf",
          confidence: "Likely",
          taxonomy: "M7 — Whole-library import",
          location: loc(path, sf, stmt),
          evidence: `\`${stmt.getText(sf).slice(0, 100)}\` — ${spec in WHOLE_LIB ? `${spec} is a CJS package, so any import form pulls the entire library into the bundle` : "a namespace import defeats tree-shaking of this barrel"}.`,
          impact: "Tens to hundreds of KB of dead code in the bundle that imports it — worst when it lands in a client chunk (parse/execute cost on every visitor).",
          fix: `Switch to ${alternative}.`,
          value: 3,
          ease: 4,
          safety: 5,
        }),
      );
    }
  }
  return findings;
}

// --- C2. Heavy library statically imported into a client module [PERF] ----------

// Known-heavy packages (hundreds of KB to multiple MB minified) that should reach client
// code via `next/dynamic`/lazy so they don't sit in the route's first-load JS.
const HEAVY_CLIENT_LIBS = new Set([
  "three",
  "monaco-editor",
  "@monaco-editor/react",
  "pdfjs-dist",
  "xlsx",
  "exceljs",
  "jspdf",
  "html2canvas",
  "fabric",
  "konva",
  "echarts",
  "plotly.js",
  "chart.js",
  "mapbox-gl",
  "@ffmpeg/ffmpeg",
]);

function heavyLibOf(spec: string): string | undefined {
  if (HEAVY_CLIENT_LIBS.has(spec)) return spec;
  for (const lib of HEAVY_CLIENT_LIBS) {
    if (spec.startsWith(`${lib}/`)) return lib;
  }
  return undefined;
}

function detectHeavyClientImport(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (leadingDirective(sf) !== "use client") continue;
    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      const lib = heavyLibOf(stmt.moduleSpecifier.text);
      if (!lib) continue;
      findings.push(
        makeFinding(nextId, {
          title: `Heavy library ${lib} statically imported in a 'use client' module`,
          severity: "Perf",
          confidence: "Likely",
          taxonomy: "M7 — Heavy import in client bundle",
          location: loc(path, sf, stmt),
          evidence: `\`${stmt.getText(sf).slice(0, 100)}\` — ${lib} is a known-heavy package and this file is a Client Component, so it loads in the route's first-load JS even before the feature is used.`,
          impact: "Hundreds of KB (or more) of JS downloaded, parsed, and executed on first paint for a feature the user may never open.",
          fix: `Load the component that needs ${lib} with \`next/dynamic\` (client-only, \`ssr: false\` if appropriate) so the chunk loads on demand.`,
          value: 4,
          ease: 3,
          safety: 4,
        }),
      );
    }
  }
  return findings;
}

// --- C3. Heavy barrel imports on a Next version that can't optimize them [PERF] ---

// Barrels whose NAMED imports Next.js auto-optimizes via optimizePackageImports since
// 13.5 (modularizeImports before that). On older Next, a named import still loads the
// whole barrel — hundreds of modules at dev/build and often shipped weight.
// Subset of the documented default list that's plausibly in a Supabase/Next app.
const AUTO_OPTIMIZED_BARRELS = new Set([
  "lucide-react",
  "date-fns",
  "lodash-es",
  "ramda",
  "antd",
  "react-icons",
  "@headlessui/react",
  "@heroicons/react",
  "@mui/material",
  "@mui/icons-material",
  "recharts",
  "react-bootstrap",
  "@tabler/icons-react",
  "rxjs",
]);

// Lowest `next` version across every package.json in the source set (a monorepo can pin
// different versions per app — the worst one is the honest gate), as [major, minor].
function lowestNextVersion(files: SourceInput[]): [number, number] | undefined {
  let lowest: [number, number] | undefined;
  for (const f of files) {
    if (!/(^|\/)package\.json$/.test(f.path)) continue;
    let deps: Record<string, string>;
    try {
      const pkg = JSON.parse(f.text) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      deps = { ...pkg.dependencies, ...pkg.devDependencies };
    } catch {
      continue;
    }
    const raw = deps.next?.replace(/^[\^~>=\s]+/, "");
    const m = raw?.match(/^(\d+)\.(\d+)/);
    if (!m) continue;
    const v: [number, number] = [Number(m[1]), Number(m[2])];
    if (!lowest || v[0] < lowest[0] || (v[0] === lowest[0] && v[1] < lowest[1])) lowest = v;
  }
  return lowest;
}

function configOptimizesPackage(files: SourceInput[], pkg: string): boolean {
  return files.some(
    (f) =>
      /(^|\/)next\.config\.(js|mjs|cjs|ts)$/.test(f.path) &&
      f.text.includes("optimizePackageImports") &&
      f.text.includes(pkg),
  );
}

function detectUnoptimizedBarrelImports(files: SourceInput[], sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const nextVersion = lowestNextVersion(files);
  // No Next manifest found (unknown version) or new enough to auto-optimize → nothing to say.
  if (!nextVersion || nextVersion[0] > 13 || (nextVersion[0] === 13 && nextVersion[1] >= 5)) return [];

  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    const barrels = new Set<string>();
    let firstStmt: ts.ImportDeclaration | undefined;
    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      const spec = stmt.moduleSpecifier.text;
      if (!AUTO_OPTIMIZED_BARRELS.has(spec)) continue;
      const named = stmt.importClause?.namedBindings && ts.isNamedImports(stmt.importClause.namedBindings);
      if (!named || configOptimizesPackage(files, spec)) continue;
      barrels.add(spec);
      firstStmt ??= stmt;
    }
    if (!firstStmt) continue;
    const list = [...barrels].join(", ");
    findings.push(
      makeFinding(nextId, {
        title: `Barrel imports (${list}) on Next ${nextVersion[0]}.${nextVersion[1]} — below the 13.5 auto-optimization floor`,
        severity: "Perf",
        confidence: "Likely",
        taxonomy: "M7 — Unoptimized barrel import",
        location: loc(path, sf, firstStmt),
        evidence: `\`${firstStmt.getText(sf).slice(0, 100)}\` — named imports from ${list} load the whole barrel on this Next version (optimizePackageImports ships defaults from 13.5, and this project's next.config doesn't add them).`,
        impact: "The full barrel (often hundreds of modules) is resolved on every build/dev compile and can ship to the client whole — slow builds and heavier bundles.",
        fix: "Upgrade Next to ≥ 13.5 (the default optimizePackageImports list covers these), or add the packages to `experimental.optimizePackageImports`, or import per-subpath.",
        value: 3,
        ease: 3,
        safety: 4,
      }),
    );
  }
  return findings;
}

// --- D1. Manual Google Fonts stylesheet [LOW] ------------------------------------

function detectManualFontLink(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    forEachJsxElement(sf, (el) => {
      if (el.tagName.getText(sf) !== "link") return;
      let href: string | undefined;
      let rel: string | undefined;
      for (const attr of el.attributes.properties) {
        if (!ts.isJsxAttribute(attr) || !attr.initializer || !ts.isStringLiteral(attr.initializer)) continue;
        const name = attr.name.getText(sf);
        if (name === "href") href = attr.initializer.text;
        if (name === "rel") rel = attr.initializer.text;
      }
      if (!href || !href.includes("fonts.googleapis.com") || rel !== "stylesheet") return;
      findings.push(
        makeFinding(nextId, {
          title: "Web font loaded via manual <link> instead of next/font",
          severity: "Low",
          confidence: "Likely",
          taxonomy: "M7 — Manual font stylesheet",
          location: loc(path, sf, el),
          evidence: `\`<link rel="stylesheet" href="${href.slice(0, 60)}…">\` — a render-blocking third-party stylesheet fetched at runtime.`,
          impact: "Extra connection + blocking CSS on every cold visit, and FOUT/layout shift (CLS) when the font swaps in.",
          fix: "Use `next/font/google` — fonts are self-hosted at build time with `size-adjust` fallbacks, removing the runtime request and the shift.",
          value: 2,
          ease: 4,
          safety: 5,
        }),
      );
    });
  }
  return findings;
}

// --- D2. fetch() in middleware — every-request network hop [PERF] ----------------

function detectMiddlewareFetch(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (!/(^|\/)middleware\.ts$/.test(path)) continue;
    let hit: ts.CallExpression | undefined;
    const visit = (n: ts.Node) => {
      if (hit) return;
      if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "fetch") {
        hit = n;
        return;
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
    if (!hit) continue;
    findings.push(
      makeFinding(nextId, {
        title: "Network fetch inside middleware — runs on every matched request",
        severity: "Perf",
        confidence: "Review",
        taxonomy: "M7 — Fetch in middleware hot path",
        location: loc(path, sf, hit),
        evidence: `\`${hit.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` in ${path} — middleware executes before every matched request, so this round-trip is added to each of them.`,
        impact: "A serial network hop on the critical path of every page/API hit it matches — site-wide added latency (and a hard dependency on the remote's uptime).",
        fix: "Verify locally what you can (e.g. JWT signature check instead of an introspection call), cache the remote answer, or narrow the `matcher` to the routes that truly need it.",
        value: 4,
        ease: 3,
        safety: 4,
      }),
    );
  }
  return findings;
}

// --- E1. Blocking sync I/O in a request handler [PERF] ----------------------------

const SYNC_CALL = /^(readFileSync|readdirSync|writeFileSync|appendFileSync|statSync|execSync|execFileSync|spawnSync|pbkdf2Sync|scryptSync|generateKeyPairSync|gzipSync|gunzipSync|deflateSync|inflateSync|brotliCompressSync|brotliDecompressSync)$/;
const HANDLER_PATH = /(\/route\.tsx?$)|((^|\/)pages\/api\/)/;

function detectSyncIoInHandler(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (!HANDLER_PATH.test(path)) continue;
    // Only flag calls inside a function body — module-scope sync reads run once at cold
    // start (an accepted pattern), not per request.
    const visit = (n: ts.Node, inFunction: boolean) => {
      if (inFunction && ts.isCallExpression(n)) {
        const callee = n.expression;
        const name = ts.isPropertyAccessExpression(callee) ? callee.name.text : ts.isIdentifier(callee) ? callee.text : "";
        if (SYNC_CALL.test(name)) {
          findings.push(
            makeFinding(nextId, {
              title: `Blocking \`${name}\` on the request path`,
              severity: "Perf",
              confidence: "Likely",
              taxonomy: "M7 — Blocking sync I/O in request handler",
              location: loc(path, sf, n),
              evidence: `\`${n.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` runs inside a request handler in ${path} — it blocks the event loop for its full duration.`,
              impact: "While it runs, the process serves nothing else — one slow call stalls every concurrent request on that instance; CPU-bound sync crypto is the classic tail-latency source.",
              fix: `Use the async form (\`${name.replace(/Sync$/, "")}\`) or hoist a run-once read to module scope.`,
              value: 4,
              ease: 4,
              safety: 4,
            }),
          );
        }
      }
      const enters = ts.isFunctionDeclaration(n) || ts.isArrowFunction(n) || ts.isFunctionExpression(n) || ts.isMethodDeclaration(n);
      ts.forEachChild(n, (c) => visit(c, inFunction || enters));
    };
    visit(sf, false);
  }
  return findings;
}

// --- E2. JSON deep-clone [LOW] ------------------------------------------------------

function detectJsonDeepClone(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    const visit = (n: ts.Node) => {
      if (
        ts.isCallExpression(n) &&
        ts.isPropertyAccessExpression(n.expression) &&
        n.expression.name.text === "parse" &&
        n.expression.expression.getText(sf) === "JSON"
      ) {
        const arg = n.arguments[0];
        if (
          arg &&
          ts.isCallExpression(arg) &&
          ts.isPropertyAccessExpression(arg.expression) &&
          arg.expression.name.text === "stringify" &&
          arg.expression.expression.getText(sf) === "JSON"
        ) {
          findings.push(
            makeFinding(nextId, {
              title: "Deep clone via JSON.parse(JSON.stringify(…))",
              severity: "Low",
              confidence: "Likely",
              taxonomy: "M7 — JSON deep-clone",
              location: loc(path, sf, n),
              evidence: `\`${n.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` — serializes the whole object graph to a string and re-parses it just to copy it.`,
              impact: "2× full serialization cost per clone (hurts in proportion to object size and call frequency), and silently drops Dates, Maps, undefined, and functions.",
              fix: "Use `structuredClone(obj)` (built into Node 17+/all modern browsers), or copy only the fields being changed.",
              value: 2,
              ease: 5,
              safety: 4,
            }),
          );
        }
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return findings;
}

// --- Orchestrator --------------------------------------------------------------------

/**
 * Runs all M7 code-level performance checks over the given source set and returns
 * Finding[] (src/findings.ts). Pass the project's full relevant .ts/.tsx source set plus
 * its next.config/babel config files — the React Compiler gate reads the config to decide
 * whether the manual-memo classes are real findings or informational.
 */
export function detectPerfCodeFindings(files: SourceInput[]): Finding[] {
  const compilerOn = reactCompilerEnabled(files);
  const sources = new Map(
    files.filter((f) => /\.(ts|tsx|jsx|mjs)$/.test(f.path)).map((f) => [f.path, parse(f.path, f.text)]),
  );
  let n = 0;
  const nextId: NextId = () => `M7C-${String(++n).padStart(2, "0")}`;

  return [
    ...detectUnresolvableCompilerFlag(files, nextId),
    ...detectContextValueLiteral(sources, nextId, compilerOn),
    ...detectInlinePropLiterals(sources, nextId, compilerOn),
    ...detectRawImgElement(sources, nextId),
    ...detectIndexAsKey(sources, nextId),
    ...detectSortInJsx(sources, nextId),
    ...detectStateSprawl(sources, nextId),
    ...detectAwaitInLoop(sources, nextId),
    ...detectUnboundedSelect(sources, nextId),
    ...detectClientFetchEffect(sources, nextId),
    ...detectWholeLibraryImport(sources, nextId),
    ...detectHeavyClientImport(sources, nextId),
    ...detectUnoptimizedBarrelImports(files, sources, nextId),
    ...detectManualFontLink(sources, nextId),
    ...detectMiddlewareFetch(sources, nextId),
    ...detectSyncIoInHandler(sources, nextId),
    ...detectJsonDeepClone(sources, nextId),
  ];
}
