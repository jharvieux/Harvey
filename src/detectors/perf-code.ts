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

// True when the target enables React Compiler (next.config `reactCompiler: true|{...}` under
// experimental or top-level, or babel-plugin-react-compiler in a babel config). Auto-memoization
// then covers the manual-memo classes below, so they report as Info instead of Perf/Low.
export function reactCompilerEnabled(files: SourceInput[]): boolean {
  for (const f of files) {
    const base = f.path.split("/").pop() ?? "";
    if (/^next\.config\.(js|mjs|cjs|ts)$/.test(base) && /reactCompiler\s*:\s*(true|\{)/.test(f.text)) return true;
    if (/^(\.babelrc|\.babelrc\.json|babel\.config\.(js|json|mjs|cjs))$/.test(base) && f.text.includes("react-compiler")) return true;
  }
  return false;
}

const COMPILER_NOTE =
  " React Compiler is enabled in this project's config, so this shape is auto-memoized at build time — reported as informational only.";

// --- A1. Context value recreated every render [PERF] ------------------------

function detectContextValueLiteral(sources: Map<string, ts.SourceFile>, nextId: NextId, compilerOn: boolean): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    forEachJsxElement(sf, (el) => {
      const tagText = el.tagName.getText(sf);
      if (!isContextTag(tagText)) return;
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

function detectInlinePropLiterals(sources: Map<string, ts.SourceFile>, nextId: NextId, compilerOn: boolean): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    const hits: { attr: ts.JsxAttribute; tagText: string }[] = [];
    forEachJsxElement(sf, (el) => {
      const tagText = el.tagName.getText(sf);
      if (!isComponentTag(tagText)) return; // DOM elements don't re-render as components
      for (const attr of el.attributes.properties) {
        if (!ts.isJsxAttribute(attr)) continue;
        if (isContextTag(tagText) && attr.name.getText(sf) === "value") continue; // A1 owns that shape
        const expr = jsxAttrExpression(attr);
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

function detectRawImgElement(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    const hits: (ts.JsxOpeningElement | ts.JsxSelfClosingElement)[] = [];
    forEachJsxElement(sf, (el) => {
      if (el.tagName.getText(sf) === "img") hits.push(el);
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

function detectIndexAsKey(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    const visit = (node: ts.Node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === "map"
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

function detectAwaitInLoop(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    const visit = (node: ts.Node) => {
      if (ts.isForOfStatement(node) || ts.isForInStatement(node) || ts.isForStatement(node)) {
        if (ts.isForOfStatement(node) && node.awaitModifier) {
          // `for await … of` consumes an async stream — sequential by design.
        } else {
          const loopVars = loopBindingNames(node);
          const assigned = collectAssignedNames(node.statement);
          const awaits = collectAwaits(node.statement);
          // The N+1 signature: a per-item await (references the loop binding) whose input
          // doesn't depend on state carried across iterations.
          const perItem = awaits.find((a) => referencesAny(a.expression, loopVars) && !referencesAny(a.expression, assigned));
          if (perItem) {
            findings.push(
              makeFinding(nextId, {
                title: "Per-item await inside a loop — serial N+1 round-trips",
                severity: "Perf",
                confidence: "Likely",
                taxonomy: "M7 — Await in loop (N+1)",
                location: loc(path, sf, perItem),
                evidence: `\`${perItem.getText(sf).slice(0, 100)}\` runs once per iteration and each iteration's input is independent of the previous one — n items cost n serial round-trips.`,
                impact: "Latency scales linearly with collection size (100 rows ≈ 100 sequential network/DB round-trips on this path).",
                fix: "Batch into one query (`.in(…)` / a join / an RPC) or run iterations concurrently with `Promise.all` (bounded if n can be large).",
                value: 4,
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

// --- B2. Unbounded select — no limit/pagination [PERF] --------------------------

const CHAIN_BOUNDS = new Set(["limit", "range", "single", "maybeSingle", "csv"]);

function detectUnboundedSelect(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    const visit = (node: ts.Node) => {
      // Only inspect the outermost call of a chain so one query flags once.
      if (ts.isCallExpression(node) && !(node.parent && ts.isPropertyAccessExpression(node.parent))) {
        const names = callChainNames(node);
        if (names.includes("from") && names.includes("select") && !names.some((n) => CHAIN_BOUNDS.has(n))) {
          const selectArg = findSelectArg(node);
          if (selectArg === undefined || selectArg === "*") {
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
    ...detectContextValueLiteral(sources, nextId, compilerOn),
    ...detectInlinePropLiterals(sources, nextId, compilerOn),
    ...detectRawImgElement(sources, nextId),
    ...detectIndexAsKey(sources, nextId),
    ...detectSortInJsx(sources, nextId),
    ...detectStateSprawl(sources, nextId),
    ...detectAwaitInLoop(sources, nextId),
    ...detectUnboundedSelect(sources, nextId),
    ...detectWholeLibraryImport(sources, nextId),
    ...detectHeavyClientImport(sources, nextId),
    ...detectManualFontLink(sources, nextId),
    ...detectMiddlewareFetch(sources, nextId),
    ...detectSyncIoInHandler(sources, nextId),
    ...detectJsonDeepClone(sources, nextId),
  ];
}
