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
import { isViteTooling, type TargetFramework } from "../scan/framework-detect.js";
import { buildImportGraph, collectPathAliases, importClosure } from "./app-router.js";
import { callChainNames, leadingDirective, loc, parse, type NextId, type SourceInput } from "./common.js";
import { SOURCE_FILE } from "./load-sources.js";

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
    // Defaults to "review" (below): every M7 code detector here is a heuristic, never
    // ~100%-precision, so review is the conservative floor. It must never reach the calibration
    // scorer untiered — an untiered finding silently mis-scores, so scoreEntry fails loud (#327).
    precisionTier?: Finding["precisionTier"];
  },
): Finding {
  return { id: nextId(), status: "Open", category: "Performance", precisionTier: "review", ...input };
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
// experimental or top-level, or babel-plugin-react-compiler in a babel config).
//
// #248: the micro-render classes (context-value literal, inline literal prop, index-as-key) are
// EMITTED ONLY when this is true, and suppressed entirely otherwise. #230 measured them ~0% real
// as work items; with the compiler ON they at least document shapes the compiler is auto-fixing
// (Info), but with it OFF they were a pure FP tail (proposit 11 / saas-lite 19 / boxyhq 12 on the
// external corpus) counted at Perf/Low. A variable/env-derived flag is NOT treated as "on" here —
// see reactCompilerFlag above and detectUnresolvableCompilerFlag, which surfaces that case
// (and the suppression it implies) instead of silently assuming false.
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
      impact: "The micro-render manual-memo classes (context value / inline literal props / index-as-key) are only reported when the compiler is confirmed ON (#248 — measured ~0% real as work items without it), so with this flag unresolvable they are suppressed the same as compiler-off. This watch row is the disclosure that the flag itself could not be read, not a graded finding.",
      fix: "Confirm the resolved value of this flag for the deployed build (check the variable/env var's actual value); if it resolves to true, re-run the scan with the literal so the compiler-covered shapes are reported informationally.",
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
  if (!compilerOn) return []; // #248: without the compiler this class measured ~0% real — suppressed, not counted
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
  if (!compilerOn) return []; // #248: without the compiler this class measured ~0% real — suppressed, not counted
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

// --- Shared: which React is this? ---------------------------------------------

// React 18 shipped AUTOMATIC BATCHING (2022): N setter calls in one handler, effect, timeout or
// promise continuation collapse into ONE render. Any finding whose cost model is "each setter
// costs a render" is asserting a mechanism React removed — see detectStateSprawl (#1475).
// Returns undefined when no manifest declares react at all; callers must not read that as < 18.
function reactMajorVersion(files: SourceInput[]): number | undefined {
  let best: number | undefined;
  for (const f of files) {
    if (!/(^|\/)package\.json$/.test(f.path)) continue;
    let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; peerDependencies?: Record<string, string> };
    try {
      pkg = JSON.parse(f.text) as typeof pkg;
    } catch {
      continue;
    }
    const range = pkg.dependencies?.react ?? pkg.devDependencies?.react ?? pkg.peerDependencies?.react;
    // `^18.3.1`, `~19.0.0`, `>=18`, `18.x`. A tag (`latest`, `canary`, a workspace/catalog ref)
    // yields no major and is left undefined rather than guessed at.
    const m = range === undefined ? null : /(\d+)/.exec(range);
    if (!m) continue;
    const major = Number(m[1]);
    if (best === undefined || major < best) best = major; // a monorepo's OLDEST react is the binding one
  }
  return best;
}

// --- Shared: what code is this, and who can reach it? -------------------------
//
// Three questions three separate classes kept answering by hand, each with its own path
// blocklist, and each wrong in the field for the same reason (#1476/#1479, MEASURED 2026-07-28
// over the pinned external corpus):
//
//   (a) is this file APPLICATION code at all, or a dev CLI / seeder / CI script / scaffolding
//       template? — devToolingModules
//   (b) can a REQUEST reach it? — requestReachableModules (#1344, below)
//   (c) can a CLIENT BUNDLE reach it? — clientReachableModules
//
// Each returns `undefined` when the tree gives it nothing to answer with, and every caller
// treats undefined as "could not evaluate" rather than as a negative answer — an UNAVAILABLE
// signal reading as a clean one is the fail-quiet this module's own coverage rows exist to
// prevent (#1344's rule, applied to two more questions).

// Paths that are dev/ops tooling by location. Superset of #1203's NON_REQUEST_PATH (which is
// still used on its own for the sync-I/O tier's narrower question). MEASURED 2026-07-28: the
// `generators/templates` and `ci/` arms are saas-lite's plop scaffolding and carbon's SST deploy
// script, both graded false as request-path perf by #1261's triage.
const DEV_TOOLING_PATH =
  /(^|\/)(scripts|bin|migrations?|seeds?|__tests__|__mocks__|e2e|cypress|codemods?|\.storybook)\/|(^|\/)(turbo\/)?generators\/|(^|\/)ci\/|(^|\/)seeds?\.[cm]?[jt]s$|\.(test|spec)\.[cm]?[jt]sx?$|\.config\.[cm]?[jt]sx?$/;

// A file path a package.json runs as a SCRIPT is dev/ops tooling, and no path pattern can say so:
// boxyhq's `delete-team.js` sits at the repo root and is an interactive `readline` admin CLI wired
// to `npm run delete-team`; its `prisma.seed` runs `ts-node ./prisma/seed.ts`. Both were graded
// request-path N+1 (#1476). Production lifecycle scripts are excluded by name — `npm start` on a
// custom `server.js` really is the request path — and any file a request entry point can reach is
// removed by the caller regardless, so a script alias over live server code stays visible here.
const PRODUCTION_SCRIPT = /^(start|serve|preview|prod|production)/;
const SCRIPT_FILE_TOKEN = /(?:^|[\s'"=])(\.{0,2}\/?[\w.@/-]+\.[cm]?[jt]sx?)(?=$|[\s'"&|;])/g;

function scriptReferencedFiles(files: SourceInput[]): Set<string> {
  const out = new Set<string>();
  for (const f of files) {
    if (!/(^|\/)package\.json$/.test(f.path)) continue;
    const dir = f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/") + 1) : "";
    let pkg: { scripts?: Record<string, string>; bin?: string | Record<string, string>; prisma?: { seed?: string } };
    try {
      pkg = JSON.parse(f.text) as typeof pkg;
    } catch {
      continue; // an unparseable manifest answers nothing; the path arm above still applies
    }
    const commands: string[] = [];
    for (const [name, cmd] of Object.entries(pkg.scripts ?? {})) if (!PRODUCTION_SCRIPT.test(name)) commands.push(cmd);
    if (typeof pkg.bin === "string") commands.push(pkg.bin);
    else for (const v of Object.values(pkg.bin ?? {})) commands.push(v);
    if (pkg.prisma?.seed) commands.push(pkg.prisma.seed);
    for (const cmd of commands) {
      for (const m of cmd.matchAll(SCRIPT_FILE_TOKEN)) {
        const rel = m[1]!.replace(/^\.\//, "");
        if (rel.startsWith("../") || rel.includes("node_modules")) continue;
        out.add(dir + rel);
      }
    }
  }
  return out;
}

// Modules that are dev/ops tooling: the path arm, plus every module in the import closure of a
// package.json-script entry point. Always returns a set (the path arm needs no roots), so callers
// have no undefined case here — the reachability questions below are the ones that can be
// unanswerable.
export function devToolingModules(files: SourceInput[], sources: Map<string, ts.SourceFile>): Set<string> {
  const allPaths = new Set(sources.keys());
  const tooling = new Set<string>([...allPaths].filter((p) => DEV_TOOLING_PATH.test(p)));
  const scriptRoots = [...scriptReferencedFiles(files)].filter((p) => allPaths.has(p));
  if (scriptRoots.length > 0) {
    const graph = buildImportGraph(sources, allPaths, collectPathAliases(files));
    for (const p of importClosure(scriptRoots, graph)) tooling.add(p);
  }
  return tooling;
}

// Entry points a CLIENT BUNDLE is built from: every `'use client'` module, the Next route files
// whose subtree renders in the browser, and a Vite/RR7/Angular browser entry. A `pages/api/` file
// is a server route, not a client entry, and `_document` never ships.
//
// This set is deliberately used only as POSITIVE evidence (see serverOnlyModules). Framework
// routing is not an import edge — React Router 7 discovers routes through `routes.ts`, Angular
// through decorators — so a module absent from this closure has NOT been shown to be server-side,
// only to be unreachable by a static import walk. Reading absence as "server" deleted 14 real
// carbon rows in an intermediate build of this change (monaco/three in packages/viewer, reachable
// only through RR7's route config), which is the same shape as a guard that works only when the
// value is a literal.
const CLIENT_ENTRY_PATH = /(^|\/)app\/.*\/(page|layout|template|default|error|loading|not-found)\.[cm]?[jt]sx?$|(^|\/)entry\.client\.[cm]?[jt]sx?$/;
const SERVER_ONLY_PAGE = /(^|\/)pages\/(api\/|_document\.)/;
const NEXT_PAGES_PATH = /(^|\/)pages\/[^/]*\.[cm]?[jt]sx$/;
// A bare `main.ts` is NOT a client entry by its name — ghostfolio's `apps/api/src/main.ts` is the
// NestJS bootstrap and `apps/client/src/main.ts` is the Angular one, and admitting both on the
// filename made the whole API tree read as client-reachable. The discriminator is the UI runtime
// the module imports, and it is applied to EVERY module, not only a bootstrap: framework routing
// hides component trees from a static walk (Angular `loadComponent: () => import(…)`, RR7's
// `routes.ts`), so seeding the closure from every UI-framework module is what keeps a shared
// helper the client also uses out of the server-only set. MEASURED 2026-07-28: with bootstraps
// alone, ghostfolio's libs/common/calculation-helper.ts scored server-only while libs/ui's
// treemap-chart.component.ts imports it — a wrong claim, in the direction that matters.
//
// The bias here is deliberate and one-way: a client entry set that is too WIDE shrinks the
// server-only set and leaves findings with their original wording, while one that is too narrow
// asserts "no visitor downloads this" about code a visitor downloads.
const UI_FRAMEWORK_IMPORT = /^(react|react-dom(\/.*)?|preact|@angular\/(core|common|platform-browser.*)|vue|svelte|solid-js(\/.*)?)$/;

function importsUiFramework(sf: ts.SourceFile): boolean {
  return sf.statements.some(
    (s) => ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier) && UI_FRAMEWORK_IMPORT.test(s.moduleSpecifier.text),
  );
}

function clientReachableModules(files: SourceInput[], sources: Map<string, ts.SourceFile>, tooling: Set<string>): Set<string> | undefined {
  const allPaths = new Set(sources.keys());
  const entries = [...allPaths].filter((p) => {
    if (SERVER_ONLY_PAGE.test(p) || tooling.has(p)) return false;
    const sf = sources.get(p)!;
    return CLIENT_ENTRY_PATH.test(p) || NEXT_PAGES_PATH.test(p) || leadingDirective(sf) === "use client" || importsUiFramework(sf);
  });
  if (entries.length === 0) return undefined;
  const graph = buildImportGraph(sources, allPaths, collectPathAliases(files));
  return importClosure(entries, graph);
}

// Modules with POSITIVE evidence on both sides: a request entry point reaches them (#1344's
// existing walk, which is what makes them server code) and no client entry does. Absence of
// client-reachability alone is not evidence — that is why both maps must exist and both must
// answer. MEASURED 2026-07-28 on ghostfolio: 55 of its 59 whole-library rows are NestJS services
// a controller imports and no browser entry does; an earlier absence-only version of this test
// reported the same 55 while actually classifying them off an accidental `pages/` path match.
// Runtimes that exist only on a server. A module importing one is server code no matter what the
// import graph could or could not walk — which is the point: `resolveImport` does not follow a
// WORKSPACE PACKAGE specifier (#1353), so in a monorepo the client closure is INCOMPLETE, and a
// test that reads "absent from the client closure" as "server" is wrong exactly where monorepos
// are. MEASURED 2026-07-28 on documenso: 9 modules under `packages/lib/universal/field-renderer/`
// are imported by `apps/remix/app/components/**` through `@documenso/lib/...` and scored
// server-only on closure evidence alone. Requiring the module to name a server runtime ITSELF is
// evidence no missing graph edge can fake.
const SERVER_RUNTIME_IMPORT = /^(node:|@nestjs\/|next\/server$|server-only$|express$|fastify$|koa$|@fastify\/|nodemailer$|ioredis$|bullmq$|bull$)/;

function importsServerRuntime(sf: ts.SourceFile): boolean {
  if (leadingDirective(sf) === "use server") return true;
  return sf.statements.some(
    (s) => ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier) && SERVER_RUNTIME_IMPORT.test(s.moduleSpecifier.text),
  );
}

function serverOnlyModules(files: SourceInput[], sources: Map<string, ts.SourceFile>, tooling: Set<string>): Set<string> | undefined {
  const requestReached = requestReachableModules(files, sources);
  const clientReached = clientReachableModules(files, sources, tooling);
  if (requestReached === undefined || clientReached === undefined) return undefined;
  // Three independent conditions, and all three must hold: a request reaches it, no client entry
  // does, and it names a server runtime of its own. The UI-framework exclusion is the fourth —
  // REQUEST_ENTRY_PATH carries Next's `pages/api/` convention, and ghostfolio's Angular client
  // happens to keep a page AT `apps/client/src/app/pages/api/`.
  return new Set(
    [...requestReached.keys()].filter((p) => {
      const sf = sources.get(p)!;
      return !clientReached.has(p) && importsServerRuntime(sf) && !importsUiFramework(sf);
    }),
  );
}

// --- A3. Raw <img> instead of next/image [PERF] — one per file ---------------

// A `src` that's a data:/blob: URI (or `URL.createObjectURL(...)`) — a client-generated,
// one-shot image (MFA QR code in a dialog, an authenticated in-memory blob preview) that
// `next/image` can't optimize anyway since there's no remote URL for it to fetch/resize
// (#230 dogfood FP).
const ONE_SHOT_IMG_SRC = /^(data|blob):/;
// Client-runtime value reads. A src bound from one of these is not knowable before render — it is
// the same one-shot image the guard above already exempts, reached through a binding instead of a
// literal (#1477). `useState` covers proposit's authenticated-image.tsx (a runtime-signed Storage
// URL held in state); the form reads cover saas-lite's MFA QR dialog, which is the case this
// guard's OWN comment cites as its motivating example and which it nevertheless fired on.
const RUNTIME_SRC_READ = /^(useState|getValues|watch|createObjectURL)$/;

// The component-parameter arm's fan-out bound: a src threaded through one prop hop is resolved,
// a chain of them is not. Two hops has never occurred in the corpus; the depth is here so the
// walk terminates, not because a third hop is known to be absent.
const SRC_RESOLVE_DEPTH = 2;

function srcAttrExpression(el: ts.JsxOpeningElement | ts.JsxSelfClosingElement, sf: ts.SourceFile): ts.Expression | undefined {
  for (const attr of el.attributes.properties) {
    if (ts.isJsxAttribute(attr) && attr.name.getText(sf) === "src") return jsxAttrExpression(attr) ?? attr.initializer;
  }
  return undefined;
}

// The function-like that lexically encloses `node`, plus the name it is declared under — needed to
// find the JSX call sites that supply a component's `src` prop.
function enclosingComponent(node: ts.Node): { fn: ts.SignatureDeclaration; name: string } | undefined {
  for (let cur: ts.Node | undefined = node; cur; cur = cur.parent) {
    if (ts.isFunctionDeclaration(cur) && cur.name) return { fn: cur, name: cur.name.text };
    if ((ts.isArrowFunction(cur) || ts.isFunctionExpression(cur)) && ts.isVariableDeclaration(cur.parent) && ts.isIdentifier(cur.parent.name)) {
      return { fn: cur, name: cur.parent.name.text };
    }
  }
  return undefined;
}

function bindsParameterNamed(fn: ts.SignatureDeclaration, name: string): boolean {
  return fn.parameters.some((p) => {
    if (ts.isIdentifier(p.name)) return p.name.text === name;
    if (!ts.isObjectBindingPattern(p.name)) return false;
    return p.name.elements.some((e) => ts.isIdentifier(e.name) && e.name.text === name);
  });
}

// True when `expr` is (or resolves to) a client-runtime one-shot image source. #1477: the original
// guard inspected only a string literal or a template head, so ONE level of indirection defeated
// it — the same shape as an auth-gate resolver that accepts a discarded boolean. It now follows an
// identifier to its local binding, and a component parameter to the `src` prop its call sites pass.
function isOneShotSrcExpression(expr: ts.Expression, sf: ts.SourceFile, depth: number): boolean {
  if (depth <= 0) return false;
  if (ts.isParenthesizedExpression(expr)) return isOneShotSrcExpression(expr.expression, sf, depth);
  if (ts.isJsxExpression(expr) && expr.expression) return isOneShotSrcExpression(expr.expression, sf, depth);
  if (ts.isStringLiteralLike(expr)) return ONE_SHOT_IMG_SRC.test(expr.text);
  if (ts.isTemplateExpression(expr)) return ONE_SHOT_IMG_SRC.test(expr.head.text);
  if (ts.isCallExpression(expr)) {
    const callee = expr.expression;
    const name = ts.isPropertyAccessExpression(callee) ? callee.name.text : ts.isIdentifier(callee) ? callee.text : "";
    return RUNTIME_SRC_READ.test(name);
  }
  // A conditional/`??` src is one-shot only if BOTH arms are — otherwise a real static asset in
  // one arm would be cleared by a runtime value in the other.
  if (ts.isConditionalExpression(expr)) {
    return isOneShotSrcExpression(expr.whenTrue, sf, depth) && isOneShotSrcExpression(expr.whenFalse, sf, depth);
  }
  if (!ts.isIdentifier(expr)) return false;
  const name = expr.text;

  let resolved = false;
  const findBinding = (n: ts.Node) => {
    if (resolved) return;
    // `const [imageUrl, setImageUrl] = useState(...)` — the src is client state.
    if (ts.isVariableDeclaration(n) && n.initializer) {
      if (ts.isArrayBindingPattern(n.name) && n.name.elements.some((e) => ts.isBindingElement(e) && ts.isIdentifier(e.name) && e.name.text === name)) {
        if (isOneShotSrcExpression(n.initializer, sf, depth - 1)) resolved = true;
        return;
      }
      if (ts.isIdentifier(n.name) && n.name.text === name && isOneShotSrcExpression(n.initializer, sf, depth - 1)) {
        resolved = true;
        return;
      }
    }
    ts.forEachChild(n, findBinding);
  };
  findBinding(sf);
  if (resolved) return true;

  // The parameter arm: `function QrImage({ src }) { return <img src={src} /> }` rendered as
  // `<QrImage src={form.getValues('qrCode')} />`. The value lives at the call site, not here.
  const owner = enclosingComponent(expr);
  if (!owner || !bindsParameterNamed(owner.fn, name)) return false;
  let viaCallSite = false;
  forEachJsxElement(sf, (el) => {
    if (viaCallSite || el.tagName.getText(sf) !== owner.name) return;
    const passed = srcAttrExpression(el, sf);
    if (passed && isOneShotSrcExpression(passed, sf, depth - 1)) viaCallSite = true;
  });
  return viaCallSite;
}

function isOneShotImgSrc(el: ts.JsxOpeningElement | ts.JsxSelfClosingElement, sf: ts.SourceFile): boolean {
  const expr = srcAttrExpression(el, sf);
  return expr !== undefined && isOneShotSrcExpression(expr, sf, SRC_RESOLVE_DEPTH);
}

// #1477: an SVG is passed through unoptimized by every image pipeline this class recommends —
// `next/image` requires `dangerouslyAllowSVG` to touch one, and `vite-imagetools` emits nothing
// for one. So the finding's stated cost ("served at original size/format", "unoptimized bytes")
// does not hold for an SVG src, and the class is narrowed off them. MEASURED 2026-07-28: both of
// subscription-payments' graded M7 rows — the target the corpus pins AS its false-positive floor
// — were `<img src="/vercel.svg">` in a footer/logo cloud.
const SVG_SRC = /\.svg(\?|#|$)/i;

function isSvgImgSrc(el: ts.JsxOpeningElement | ts.JsxSelfClosingElement, sf: ts.SourceFile): boolean {
  let expr = srcAttrExpression(el, sf);
  while (expr && ts.isParenthesizedExpression(expr)) expr = expr.expression;
  if (!expr) return false;
  if (ts.isStringLiteralLike(expr)) return SVG_SRC.test(expr.text);
  // `src={"/carbon-mark-light.svg"}` and `src={`${base}/logo.svg`}` — the extension is still static.
  if (ts.isTemplateExpression(expr)) return SVG_SRC.test(expr.templateSpans.at(-1)?.literal.text ?? "");
  if (ts.isNoSubstitutionTemplateLiteral(expr)) return SVG_SRC.test(expr.text);
  return false;
}

function detectRawImgElement(sources: Map<string, ts.SourceFile>, nextId: NextId, isVite: boolean): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (isRenderOnce(path, sf)) continue; // email/PDF templates render once — re-render classes don't apply
    if (sf.text.includes("@next/next/no-img-element")) continue; // the codebase already adjudicated its <img>s via an explicit eslint-disable
    const hits: (ts.JsxOpeningElement | ts.JsxSelfClosingElement)[] = [];
    let svgSkipped = 0;
    forEachJsxElement(sf, (el) => {
      if (el.tagName.getText(sf) !== "img" || isOneShotImgSrc(el, sf)) return;
      if (isSvgImgSrc(el, sf)) {
        svgSkipped++;
        return;
      }
      hits.push(el);
    });
    const first = hits[0];
    if (!first) continue;
    const svgNote = svgSkipped === 0 ? "" : ` ${svgSkipped} further \`<img>\` in this file ${svgSkipped === 1 ? "has" : "have"} an \`.svg\` src and ${svgSkipped === 1 ? "is" : "are"} not counted — no image pipeline re-encodes an SVG, so the bytes/format claim cannot apply to ${svgSkipped === 1 ? "it" : "them"} (setting \`width\`/\`height\` on ${svgSkipped === 1 ? "it" : "them"} still avoids CLS).`;
    findings.push(
      makeFinding(nextId, {
        title: isVite
          ? `Raw <img> without dimensions or lazy-loading (${hits.length}× in ${path})`
          : `Raw <img> instead of next/image (${hits.length}× in ${path})`,
        severity: "Perf",
        confidence: "Likely",
        // #1480: the taxonomy string used to name next/image unconditionally, so a React
        // Router / Vite client read "instead of next/image" in any grouping keyed on taxonomy
        // even though #872's isVite branch had already produced the right title and fix.
        taxonomy: isVite ? "M7 — Raw <img> without dimensions or lazy-loading" : "M7 — Raw <img> instead of next/image",
        location: loc(path, sf, first),
        evidence: `\`${first.getText(sf).slice(0, 80)}\` — served at original size/format with no lazy-loading or srcset, and no reserved layout box.${svgNote}`,
        impact: "Slower LCP (unoptimized bytes, no priority hints) and CLS from late-loading unsized images.",
        fix: isVite
          ? "Set explicit `width`/`height` (reserves the layout box, prevents CLS) and `loading=\"lazy\"` `decoding=\"async\"` on below-the-fold images; for build-time responsive/optimized formats use `vite-imagetools` (an `<img srcset>` per size)."
          : "Use `next/image` (automatic resizing, modern formats, lazy-load, layout reservation); add `priority` on the LCP image.",
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

// #248: part of the micro-render tail — emitted only when React Compiler is on. Unlike the two
// literal-prop classes above the compiler does NOT auto-fix key identity, so when it does emit it
// keeps its Low severity rather than the Info demotion; the gate is precision-driven (the class
// measured ~0% real on the corpus without the compiler), not a compiler-covers-it demotion.
function detectIndexAsKey(sources: Map<string, ts.SourceFile>, nextId: NextId, compilerOn: boolean): Finding[] {
  if (!compilerOn) return [];
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

// #816: sorting a hardcoded list (or a spread copy of one) in JSX re-sorts a fixed handful of
// items per render — the cost never scales with data. Same static-list + SCREAMING_SNAKE
// exemptions as detectIndexAsKey/detectNestedLoopJoin.
function isStaticSortReceiver(sf: ts.SourceFile, recv: ts.Expression): boolean {
  if (ts.isArrayLiteralExpression(recv)) {
    return recv.elements.every((el) => !ts.isSpreadElement(el) || isStaticSortReceiver(sf, el.expression));
  }
  if (ts.isIdentifier(recv)) return /^[A-Z][A-Z0-9_]*$/.test(recv.text) || isStaticListSource(sf, recv);
  return false;
}

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
            (n.expression.name.text === "sort" || n.expression.name.text === "toSorted") &&
            !isStaticSortReceiver(sf, n.expression.expression) // hardcoded lists never scale (#816)
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

// #1475 — the class's own evidence sentence was false on every target in the pinned corpus.
// It read "every setter triggers a full re-render of this (evidently large) component", which
// tells a client that N setters in one handler cost N renders. React >= 18's automatic batching
// collapses them into one; MEASURED 2026-07-28, the corpus's React pins are 19.1.0 / 19.2.1 /
// 19.2.3 / 18.3.1, and the class scored 0 of 7 in the field triage — the only M7 class at 0%.
//
// The observation that survives is a MAINTAINABILITY one: a component owning this many
// independent slices is hard to reason about, and any one of them re-renders the whole thing.
// So on React >= 18 (and where no react version is declared — the modern default, never assumed
// older) the class emits that claim at Info, joining the Missing-hook-dependencies precedent
// (#230 demoted a class rather than dropping it) — the signal still ships in the deliverable and
// leaves the graded count. On React < 18 the original per-setter render cost is real, so the row
// stays counted, with the batching boundary named rather than implied.
const AUTOMATIC_BATCHING_MAJOR = 18;

function detectStateSprawl(sources: Map<string, ts.SourceFile>, nextId: NextId, reactMajor: number | undefined): Finding[] {
  const batched = reactMajor === undefined || reactMajor >= AUTOMATIC_BATCHING_MAJOR;
  const versionSaid = reactMajor === undefined ? "no manifest in the scanned tree declares a react version, so the modern default is assumed" : `this project declares react ${reactMajor}`;
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
            severity: batched ? "Info" : "Low",
            confidence: "Review",
            taxonomy: "M7 — State sprawl",
            location: loc(path, sf, fn),
            evidence: batched
              ? `${name} declares ${count} separate useState hooks — ${count} independent slices for one component to own, and a change to any one of them re-renders the whole component. This is a MAINTAINABILITY reading, not a render-count one: ${versionSaid}, and React ${AUTOMATIC_BATCHING_MAJOR}+ automatic batching collapses simultaneous setter calls into a single render, so the number of hooks is not a number of renders.`
              : `${name} declares ${count} separate useState hooks, and ${versionSaid} — below React ${AUTOMATIC_BATCHING_MAJOR}, setter calls outside a React event handler are NOT batched, so a handler touching several slices really does render once per setter.`,
            impact: batched
              ? "Interlocking state updates are hard to reason about and easy to leave inconsistent; a symptom the component owns too much. No render-count cost is claimed — automatic batching removed it."
              : "Repeated full re-renders per interaction, plus interlocking state updates; a symptom the component owns too much.",
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

// #1480: two loop shapes where "parallelise this with Promise.all" is the wrong advice — the loop
// is sequential ON PURPOSE, the same family as the chunked-batch exemption above where the shape
// IS the fix, not the bug. MEASURED 2026-07-28 on inbox-zero:
//
//   (a) a CAP: `for (const email of participantEmails) { if (allThreads.length >= maxThreads)
//       break; … await … }` (gather-context.ts:132) — the exit guards the loop and runs BEFORE the
//       awaited call, so parallelising would fetch past the cap the code exists to enforce;
//   (b) a SEARCH: `for (let p = start; p <= 65535; p++) { … if (!await isFree(p)) continue;
//       return { port: p } }` (setup-ports.ts:112) — the loop stops at the first hit and returns
//       IT, so there is no n-item workload to parallelise at all.
//
// The discriminator is deliberately narrow, because "the body contains a break or return" is not
// it: boxyhq's pages/api/auth/sso/verify.ts:148 queries SSO existence per team and returns early
// only in the exceptional multiple-matches branch, downstream of the await — a real request-path
// N+1 that the broad form silently deleted (caught by before/after on the pinned corpus, 2026-07-28).
// So a cap must PRECEDE the await, and a search's return must carry the loop's own binding.
function isSequentialByDesign(body: ts.Node, perItemAwait: ts.AwaitExpression, loopVars: Set<string>): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if ((ts.isBreakStatement(n) || ts.isReturnStatement(n)) && n.pos < perItemAwait.pos) {
      found = true; // (a) a cap/guard the loop checks before doing the work
      return;
    }
    if (ts.isReturnStatement(n) && n.expression && referencesAny(n.expression, loopVars)) {
      found = true; // (b) the loop returns the item it was searching for
      return;
    }
    // A nested loop's break belongs to that loop; a nested function's return is its own.
    if (
      ts.isForOfStatement(n) ||
      ts.isForInStatement(n) ||
      ts.isForStatement(n) ||
      ts.isWhileStatement(n) ||
      ts.isDoStatement(n) ||
      ts.isSwitchStatement(n) ||
      ts.isFunctionDeclaration(n) ||
      ts.isArrowFunction(n) ||
      ts.isFunctionExpression(n)
    ) {
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(body);
  return found;
}

// User-facing request path (routes, pages, actions) vs background/batch (workers, jobs,
// scripts, lib helpers only jobs call). Both are real costs, but only the former is
// user-visible latency — the confidence tier and impact wording reflect that.
const REQUEST_PATH = /(^|\/)(app|pages)\//;

function detectAwaitInLoop(sources: Map<string, ts.SourceFile>, nextId: NextId, tooling: Set<string>): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (tooling.has(path)) continue; // #1476: a dev CLI / seeder / CI script / generator makes no request-path latency claim
    const hits: ts.AwaitExpression[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isForOfStatement(node) || ts.isForInStatement(node) || ts.isForStatement(node)) {
        const streaming = ts.isForOfStatement(node) && node.awaitModifier; // `for await … of` is sequential by design
        const chunked = ts.isForStatement(node) && isBatchChunkLoop(node);
        // #816: a loop over a hardcoded/const-literal list is bounded by the source code, not by
        // tenant/user data — a fixed handful of sequential awaits forever, never N+1.
        const staticList = ts.isForOfStatement(node) && isStaticListSource(sf, node.expression);
        if (!streaming && !chunked && !staticList) {
          const loopVars = loopBindingNames(node);
          const assigned = collectAssignedNames(node.statement);
          const awaits = collectAwaits(node.statement);
          // The N+1 signature: a per-item await (references the loop binding) whose input
          // doesn't depend on state carried across iterations.
          const perItem = awaits.find((a) => referencesAny(a.expression, loopVars) && !referencesAny(a.expression, assigned));
          if (perItem && !isSequentialByDesign(node.statement, perItem, loopVars)) hits.push(perItem); // #1480
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

// #1478 — a house-style pagination wrapper. carbon paginates through
// `setGenericQueryFilters(query, args, …)` (apps/erp/app/utils/query.ts:137, a `.range()` on the
// query it was handed), so every caller reads as unbounded to a check that only looks at the
// chain it can see. Same callee-resolution shape #964/#1263 already applied to M9's route-action
// validation, applied to M7: collect the functions in the scanned tree that apply a bound to a
// PARAMETER, then clear a query that is passed to one of them.
const PARAM_BOUND_METHOD = /^(range|limit|single|maybeSingle)$/;

function appliesBoundToParameter(fn: ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression): boolean {
  const params = new Set<string>();
  for (const p of fn.parameters) if (ts.isIdentifier(p.name)) params.add(p.name.text);
  if (params.size === 0 || !fn.body) return false;
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && PARAM_BOUND_METHOD.test(n.expression.name.text)) {
      // The receiver may be the parameter itself or a re-assignment of it (`query = query.eq(…)`),
      // so a bare identifier match on the chain root is what decides it.
      let root: ts.Expression = n.expression.expression;
      while (ts.isCallExpression(root) && ts.isPropertyAccessExpression(root.expression)) root = root.expression.expression;
      if (ts.isIdentifier(root) && params.has(root.text)) {
        found = true;
        return;
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(fn.body);
  return found;
}

function paginatingHelperNames(sources: Map<string, ts.SourceFile>): Set<string> {
  const names = new Set<string>();
  for (const sf of sources.values()) {
    const visit = (n: ts.Node) => {
      if (ts.isFunctionDeclaration(n) && n.name && appliesBoundToParameter(n)) names.add(n.name.text);
      if (
        (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) &&
        ts.isVariableDeclaration(n.parent) &&
        ts.isIdentifier(n.parent.name) &&
        appliesBoundToParameter(n)
      ) {
        names.add(n.parent.name.text);
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return names;
}

// The name the unbounded chain is bound to, if any: `let query = client.from(…).select(…)`.
function chainBindingName(chainRoot: ts.CallExpression): string | undefined {
  const parent = chainRoot.parent;
  if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  if (ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(parent.left)) return parent.left.text;
  return undefined;
}

function enclosingBody(node: ts.Node): ts.Node {
  for (let cur: ts.Node | undefined = node.parent; cur; cur = cur.parent) {
    if (ts.isFunctionDeclaration(cur) || ts.isArrowFunction(cur) || ts.isFunctionExpression(cur) || ts.isMethodDeclaration(cur)) return cur;
  }
  return node.getSourceFile();
}

// True when the bound query is later handed to a helper that pages it.
function boundedByHelper(chainRoot: ts.CallExpression, helpers: Set<string>): boolean {
  const name = chainBindingName(chainRoot);
  if (name === undefined || helpers.size === 0) return false;
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && helpers.has(n.expression.text)) {
      if (n.arguments.some((a) => ts.isIdentifier(a) && a.text === name)) {
        found = true;
        return;
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(enclosingBody(chainRoot));
  return found;
}

function detectUnboundedSelect(sources: Map<string, ts.SourceFile>, nextId: NextId, tooling: Set<string>): Finding[] {
  const findings: Finding[] = [];
  const helpers = paginatingHelperNames(sources);
  for (const [path, sf] of sources) {
    if (tooling.has(path)) continue; // #1476
    const visit = (node: ts.Node) => {
      // Only inspect the outermost call of a chain so one query flags once.
      if (ts.isCallExpression(node) && !(node.parent && ts.isPropertyAccessExpression(node.parent))) {
        const names = callChainNames(node);
        if (names.includes("from") && names.includes("select") && !names.some((n) => CHAIN_BOUNDS.has(n)) && !hasPkEqFilter(node) && !boundedByHelper(node, helpers)) {
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

// `.eq("id", …)` is a primary-key point lookup — at most one row regardless of table size, the
// same bounded shape as `.in("id", [...])` and `.single()`. Deliberately ONLY the literal column
// name "id": `.eq("org_id", …)`/`.eq("user_id", …)` are tenant/user scoping filters whose result
// still grows with that tenant's data, so they stay flagged (#816).
function hasPkEqFilter(chainRoot: ts.CallExpression): boolean {
  let cur: ts.Expression = chainRoot;
  while (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
    if (cur.expression.name.text === "eq") {
      const col = cur.arguments[0];
      if (col && ts.isStringLiteralLike(col) && col.text === "id") return true;
    }
    cur = cur.expression.expression;
  }
  return false;
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

function detectClientFetchEffect(sources: Map<string, ts.SourceFile>, nextId: NextId, isVite: boolean): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    // On Next the "fix" is a Server Component fetch, so only `'use client'` files are the bug. A
    // Vite SPA has no server-render path — every module is client — so the directive never appears
    // and every useEffect fetch is in scope (#577).
    if (!isVite && leadingDirective(sf) !== "use client") continue;
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
        evidence: `\`${first.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` runs on mount inside useEffect in a ${isVite ? "client component (Vite SPA)" : "'use client' component"}${hits.length > 1 ? ` (first of ${hits.length})` : ""} — the data round-trip starts only after the JS bundle downloads, parses, and hydrates, with no caching or request de-duplication.`,
        impact: isVite
          ? "A serial network waterfall (HTML → JS → data) plus a loading spinner on every visit; concurrent mounts of the component each refetch with no caching or de-duplication."
          : "A serial network waterfall (HTML → JS → data) plus a loading spinner on every visit; concurrent mounts of the component each refetch. A Server Component fetch ships the data in the initial HTML; a cache hook de-dupes on the client.",
        fix: isVite
          ? "Move the read behind a cache-aware hook (useSWR / React Query / a route loader) instead of raw fetch-in-effect, so requests are cached, de-duplicated, and revalidated across mounts."
          : "Fetch in a Server Component (or route loader) and pass the data down; if it must stay client-side (third-party API, live widget), use a cache-aware hook (useSWR / React Query) instead of raw fetch-in-effect.",
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

// #1479: a Vite `?url`/`?raw`/`?inline` suffix yields the ASSET (a URL string, the file's text),
// not the module — `import workerSrc from "pdfjs-dist/build/pdf.worker.min.mjs?url"` emits the
// worker as a separate asset and pulls nothing into the importing chunk. `?worker` likewise
// compiles to its own chunk. So a suffixed specifier is not an import of that library at all.
const ASSET_QUERY_SUFFIX = /\?(url|raw|inline|worker|sharedworker|no-inline)\b/;

function detectWholeLibraryImport(sources: Map<string, ts.SourceFile>, nextId: NextId, serverOnly: Set<string> | undefined): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      const spec = stmt.moduleSpecifier.text;
      if (ASSET_QUERY_SUFFIX.test(spec)) continue;
      const isNamespace = !!stmt.importClause?.namedBindings && ts.isNamespaceImport(stmt.importClause.namedBindings);
      const alternative = WHOLE_LIB[spec] ?? (BARREL_NAMESPACE.has(spec) && isNamespace ? `named imports (\`import { x } from "${spec}"\`) so the barrel can be tree-shaken/optimized` : undefined);
      if (!alternative) continue;
      // #1479: the class's stated cost is BUNDLE weight ("dead code in the bundle … parse/execute
      // cost on every visitor"), and it never tested that the module reaches a bundle. MEASURED
      // 2026-07-28: 27 of ghostfolio's 59 rows are in `apps/api`, a NestJS server that ships no JS
      // to a visitor at all. The claim is re-worded rather than suppressed — a server module still
      // pays resident memory and cold-start parse for a library it uses one function from, which
      // is a real if smaller cost, and suppressing would trade a false positive for a false
      // negative on every server-side barrel import.
      const isServerOnly = serverOnly?.has(path) === true;
      findings.push(
        makeFinding(nextId, {
          title: isServerOnly ? `Whole-library import of ${spec} (server-only module)` : `Whole-library import of ${spec}`,
          severity: isServerOnly ? "Low" : "Perf",
          confidence: isServerOnly ? "Review" : "Likely",
          taxonomy: "M7 — Whole-library import",
          location: loc(path, sf, stmt),
          evidence:
            `\`${stmt.getText(sf).slice(0, 100)}\` — ${spec in WHOLE_LIB ? `${spec} is a CJS package, so any import form pulls the entire library into the bundle` : "a namespace import defeats tree-shaking of this barrel"}.` +
            (isServerOnly
              ? " A request entry point in this tree imports this module and no client entry point does, so it is server-side — the visitor-bundle cost stated by this class does NOT apply to it."
              : " Whether this module reaches a client chunk was not established: framework routing is not an import edge, so a static walk cannot prove the negative."),
          impact: isServerOnly
            ? "Server-side only: resident memory and cold-start parse for a library one function is used from. No first-load JS cost — a visitor never downloads this module."
            : "Tens to hundreds of KB of dead code in the bundle that imports it — worst when it lands in a client chunk (parse/execute cost on every visitor).",
          fix: `Switch to ${alternative}.`,
          value: isServerOnly ? 2 : 3,
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
  // #1479: `?url`/`?raw`/`?worker` yields the asset, not the module — the library is never pulled
  // into the importing chunk. MEASURED 2026-07-28 on carbon's apps/erp/app/entry.client.tsx:1,
  // `import workerSrc from "pdfjs-dist/build/pdf.worker.min.mjs?url"`, graded false.
  if (ASSET_QUERY_SUFFIX.test(spec)) return undefined;
  if (HEAVY_CLIENT_LIBS.has(spec)) return spec;
  for (const lib of HEAVY_CLIENT_LIBS) {
    if (spec.startsWith(`${lib}/`)) return lib;
  }
  return undefined;
}

function detectHeavyClientImport(
  sources: Map<string, ts.SourceFile>,
  nextId: NextId,
  isVite: boolean,
  serverOnly: Set<string> | undefined,
): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    // A Vite SPA emits no `'use client'` directive — the whole bundle IS the client, so a static
    // heavy import in ANY module lands in first-load JS (#577). On Next, only Client Components do.
    if (!isVite && leadingDirective(sf) !== "use client") continue;
    // #1479: "every module ships to the client" is true of a Vite SPA's app tree, not of every
    // file in a Vite MONOREPO, which also holds server modules and deploy scripts. Only a module
    // with positive server evidence on both sides is dropped — requiring positive CLIENT
    // reachability instead deleted 14 real carbon rows, because RR7 routes are not import edges.
    if (serverOnly?.has(path) === true) continue;
    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      const lib = heavyLibOf(stmt.moduleSpecifier.text);
      if (!lib) continue;
      findings.push(
        makeFinding(nextId, {
          title: isVite
            ? `Heavy library ${lib} statically imported into the client bundle`
            : `Heavy library ${lib} statically imported in a 'use client' module`,
          severity: "Perf",
          confidence: "Likely",
          taxonomy: "M7 — Heavy import in client bundle",
          location: loc(path, sf, stmt),
          evidence: `\`${stmt.getText(sf).slice(0, 100)}\` — ${lib} is a known-heavy package and ${isVite ? "this is a Vite SPA where every module ships to the client" : "this file is a Client Component"}, so it loads in the route's first-load JS even before the feature is used.`,
          impact: "Hundreds of KB (or more) of JS downloaded, parsed, and executed on first paint for a feature the user may never open.",
          fix: isVite
            ? `Load the component that needs ${lib} with \`React.lazy(() => import(...))\` behind \`<Suspense>\` (a dynamic \`import()\`) so its chunk is fetched on demand instead of in the entry bundle.`
            : `Load the component that needs ${lib} with \`next/dynamic\` (client-only, \`ssr: false\` if appropriate) so the chunk loads on demand.`,
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

function detectManualFontLink(sources: Map<string, ts.SourceFile>, nextId: NextId, isVite: boolean): Finding[] {
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
          title: isVite
            ? "Web font loaded via a render-blocking <link> stylesheet"
            : "Web font loaded via manual <link> instead of next/font",
          severity: "Low",
          confidence: "Likely",
          taxonomy: "M7 — Manual font stylesheet",
          location: loc(path, sf, el),
          evidence: `\`<link rel="stylesheet" href="${href.slice(0, 60)}…">\` — a render-blocking third-party stylesheet fetched at runtime.`,
          impact: "Extra connection + blocking CSS on every cold visit, and FOUT/layout shift (CLS) when the font swaps in.",
          fix: isVite
            ? "Self-host the font with `@fontsource/<family>` (or `@fontsource-variable/*`) imported in your entry module — removes the runtime Google Fonts request and the swap; add `font-display: swap` and a `size-adjust` fallback to cut CLS."
            : "Use `next/font/google` — fonts are self-hosted at build time with `size-adjust` fallbacks, removing the runtime request and the shift.",
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
    if (!/(^|\/)middleware\.[cm]?[jt]sx?$/.test(path)) continue;
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
const HANDLER_PATH = /(\/route\.[cm]?[jt]sx?$)|((^|\/)pages\/api\/)/;
// #1203: files that are never on a request path regardless of what they export — build/tooling
// scripts, config files, migrations/seeds, tests. Excluded from the broader (non-route-file)
// tier below so cold-start/dev-time code doesn't get flagged as a request-path blocker.
const NON_REQUEST_PATH = /(^|\/)(scripts|bin|migrations?|seeds?|__tests__|__mocks__)\/|\.(test|spec)\.[cm]?[jt]sx?$|\.config\.[cm]?[jt]sx?$/;
// #1344: the entry points a request actually enters through. HANDLER_PATH is the Next.js subset the
// "Likely" tier keys on; a Remix/RR7/Nest/Express app has none of those files, so the reachability
// roots below are deliberately wider — otherwise the whole generic tier goes silent on every
// non-Next target, which is a fail-quiet, not a precision fix.
const REQUEST_ENTRY_PATH = /(\/route\.[cm]?[jt]sx?$)|((^|\/)(pages\/api|app\/api|routes?|controllers?|handlers?)\/)|(\.(server|route|controller|resolver|handler)\.[cm]?[jt]sx?$)|((^|\/)middleware\.[cm]?[jt]sx?$)/;

function isExportedFunctionLike(n: ts.Node): boolean {
  if (ts.isFunctionDeclaration(n)) return !!n.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
  if (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) {
    const decl = n.parent;
    const stmt = ts.isVariableDeclaration(decl) ? decl.parent.parent : undefined;
    return !!stmt && ts.isVariableStatement(stmt) && !!stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
  }
  return false;
}

// #1344: #1203's generic tier flagged "an exported function anywhere that is not a tooling path",
// which on the pinned external corpus was 86% wrong — MEASURED 2026-07-27 across six repos, 51 of
// 59 new hits were in CLI packages, code generators, dev harnesses and test utilities that no
// server process ever loads (inbox-zero packages/cli ×15, carbon packages/{dev,checks,harness} ×31,
// saas-lite turbo/generators ×2, ghostfolio *-test-utils ×1, rallly apps/landing blog loader ×2).
// A path blocklist can never enumerate that; the question it was standing in for is reachability,
// which the import graph can answer. So the generic tier now requires the module to be transitively
// imported by a request entry point, and the finding NAMES that entry point instead of disclaiming
// that it proved nothing. The cost is recorded, not hidden: resolveImport cannot follow a WORKSPACE
// PACKAGE specifier, so a shared monorepo package is unreachable from the app's routes as far as
// this gate can tell — rallly packages/utils pbkdf2Sync and two documenso rows go silent. #1353.
// A tree with no request entry point at all cannot answer the reachability question either way, and
// an UNAVAILABLE signal must not read as a negative one — that is the fail-quiet this module's own
// coverage rows exist to prevent. So the filter applies only when there is something to be reachable
// FROM; otherwise the tier keeps #1203's behaviour and says in the evidence that it could not check.
function requestReachableModules(files: SourceInput[], sources: Map<string, ts.SourceFile>): Map<string, string> | undefined {
  const allPaths = new Set(sources.keys());
  const entries = [...allPaths].filter((p) => REQUEST_ENTRY_PATH.test(p));
  if (entries.length === 0) return undefined;
  const graph = buildImportGraph(sources, allPaths, collectPathAliases(files));
  const reached = new Map<string, string>();
  for (const entry of entries) {
    for (const p of importClosure([entry], graph)) if (!reached.has(p)) reached.set(p, entry);
  }
  return reached;
}

function detectSyncIoInHandler(files: SourceInput[], sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const reachedFrom = requestReachableModules(files, sources);
  for (const [path, sf] of sources) {
    const onHandlerPath = HANDLER_PATH.test(path);
    if (!onHandlerPath && NON_REQUEST_PATH.test(path)) continue;
    const entry = reachedFrom?.get(path);
    if (!onHandlerPath && reachedFrom !== undefined && entry === undefined) continue;
    // Only flag calls inside a function body — module-scope sync reads run once at cold
    // start (an accepted pattern), not per request.
    const visit = (n: ts.Node, inFunction: boolean, inExportedFn: boolean) => {
      // #1203: on a recognised handler file, any function body counts (existing behavior). Off
      // one, only an EXPORTED function's own sync call counts — a private/unexported helper is
      // far less likely to sit on a live call path, and this is the only proxy available
      // without cross-file call-graph reachability.
      const onCandidatePath = onHandlerPath ? inFunction : inExportedFn;
      if (onCandidatePath && ts.isCallExpression(n)) {
        const callee = n.expression;
        const name = ts.isPropertyAccessExpression(callee) ? callee.name.text : ts.isIdentifier(callee) ? callee.text : "";
        if (SYNC_CALL.test(name)) {
          findings.push(
            makeFinding(nextId, {
              title: `Blocking \`${name}\` on the request path`,
              severity: "Perf",
              confidence: onHandlerPath ? "Likely" : "Review",
              taxonomy: "M7 — Blocking sync I/O in request handler",
              location: loc(path, sf, n),
              evidence: onHandlerPath
                ? `\`${n.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` runs inside a request handler in ${path} — it blocks the event loop for its full duration.`
                : `\`${n.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` blocks the event loop for its full duration and runs inside an exported function in ${path}. ${
                    entry === undefined
                      ? "The scanned tree contains no request entry point (no route/handler/controller file), so reachability could not be evaluated at all and this flags on the call shape alone"
                      : `The request entry point ${entry} imports it (transitively), so the MODULE is reachable from a request, but this exported function's own invocation from the handler was not traced (no call-graph analysis)`
                  } — confirm reachability before treating it as a live request-path stall.`,
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
      // OR-propagate like inFunction: once true it must stay true for every descendant, not just
      // the immediate function-like node — recomputing from `enters` alone at each recursion
      // step (rather than carrying the incoming flag forward) silently reset it back to false one
      // level down (#1203 self-review caught this before it shipped).
      const nextInExportedFn = inExportedFn || (enters && isExportedFunctionLike(n));
      ts.forEachChild(n, (c) => visit(c, inFunction || enters, nextInExportedFn));
    };
    visit(sf, false, false);
  }
  return findings;
}

// --- E2. JSON deep-clone [LOW] ------------------------------------------------------

// #1480: `JSON.parse(JSON.stringify(x))` inside the `props` object returned by
// getServerSideProps/getStaticProps is the DOCUMENTED Next.js idiom for making non-JSON values
// (Prisma `Date`s, Decimals) serializable across the server→client props boundary. It is a
// required serialization step, not a copy — and `structuredClone`, this class's recommendation,
// would not fix it, it would break it (a structured clone still carries Dates, which is exactly
// what Next refuses). Sibling of #816's module-scope exemption. MEASURED 2026-07-28 on boxyhq's
// pages/teams/switch.tsx:65.
const PROPS_FUNCTION = /^get(ServerSide|Static)Props$/;

function isNextPropsSerialization(node: ts.Node): boolean {
  let inPropsObject = false;
  for (let cur: ts.Node | undefined = node; cur; cur = cur.parent) {
    if (ts.isPropertyAssignment(cur) && ts.isIdentifier(cur.name) && cur.name.text === "props") inPropsObject = true;
    if (ts.isFunctionDeclaration(cur) && cur.name && PROPS_FUNCTION.test(cur.name.text)) return inPropsObject;
    if ((ts.isArrowFunction(cur) || ts.isFunctionExpression(cur)) && ts.isVariableDeclaration(cur.parent) && ts.isIdentifier(cur.parent.name)) {
      return inPropsObject && PROPS_FUNCTION.test(cur.parent.name.text);
    }
  }
  return false;
}

function detectJsonDeepClone(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    // Only flag clones inside a function body — a module-scope clone runs once at cold start,
    // the same accepted run-once pattern detectSyncIoInHandler exempts (#816).
    const visit = (n: ts.Node, inFunction: boolean) => {
      if (
        inFunction &&
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
          arg.expression.expression.getText(sf) === "JSON" &&
          !isNextPropsSerialization(n)
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
      const enters = ts.isFunctionDeclaration(n) || ts.isArrowFunction(n) || ts.isFunctionExpression(n) || ts.isMethodDeclaration(n);
      ts.forEachChild(n, (c) => visit(c, inFunction || enters));
    };
    visit(sf, false);
  }
  return findings;
}

// --- E3. Nested-loop join over scaling collections [PERF] — one per file --------------

// The accidental O(n·m) join (#385): a per-item linear scan (`.find`/`.some`/`.includes`/…) over
// a SECOND collection inside a loop over the first, where a Map/Set built once would do — the
// "forgot to build a lookup" shape AI-generated enrichment code defaults to. FP-heavy by nature
// (a scan over a small bounded array is fine regardless of shape), so every guard below narrows
// to the shape where both collections plausibly scale with data, and the confidence stays Review:
//   - the inner receiver must be LOOP-INVARIANT (an outer-scope identifier, not the outer item's
//     own field or something re-derived per iteration — per-row `p.tags.find(…)` is normal);
//   - the inner probe must reference the outer loop's item (a join, not two unrelated loops that
//     happen to nest);
//   - hardcoded/const-literal lists are exempt on BOTH sides (same isStaticListSource exemption
//     as detectIndexAsKey — a status enum or nav list never scales), and so are SCREAMING_SNAKE
//     receivers: isStaticListSource can't see across module boundaries, and an all-caps
//     identifier is the convention for exactly those imported config constants (measured on this
//     repo's own source: FREE_TIER_EXPECTATIONS, a hardcoded cross-file list, was the one hit
//     the literal check missed);
//   - `.includes`/`.indexOf` exist on strings too, so the value forms additionally require
//     in-file evidence the receiver is an array (array type annotation, array literal, or an
//     array-producing initializer) — `query.includes(name)` over a string must not fire.

const OUTER_LOOP_METHODS = new Set(["map", "filter", "forEach", "flatMap"]);
const INNER_SCAN_CALLBACK = new Set(["find", "findIndex", "some", "filter"]); // callback forms — receiver is array-like by construction
const INNER_SCAN_VALUE = new Set(["includes", "indexOf"]); // value forms — strings have these too
const ARRAY_PRODUCER = new Set(["map", "filter", "concat", "flat", "flatMap", "slice", "from", "split"]);

function isArrayIshType(type: ts.TypeNode | undefined): boolean {
  if (!type) return false;
  if (ts.isArrayTypeNode(type)) return true;
  return ts.isTypeReferenceNode(type) && ts.isIdentifier(type.typeName) && /^(Readonly)?Array$/.test(type.typeName.text);
}

function hasArrayEvidence(sf: ts.SourceFile, name: string): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if ((ts.isVariableDeclaration(n) || ts.isParameter(n)) && ts.isIdentifier(n.name) && n.name.text === name) {
      if (isArrayIshType(n.type)) {
        found = true;
        return;
      }
      if (ts.isVariableDeclaration(n) && n.initializer) {
        const init = n.initializer;
        if (
          ts.isArrayLiteralExpression(init) ||
          (ts.isCallExpression(init) && ts.isPropertyAccessExpression(init.expression) && ARRAY_PRODUCER.has(init.expression.name.text))
        ) {
          found = true;
          return;
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return found;
}

function declaredWithin(scope: ts.Node, name: string): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (
      ((ts.isVariableDeclaration(n) || ts.isParameter(n)) && ts.isIdentifier(n.name) && n.name.text === name) ||
      (ts.isFunctionDeclaration(n) && n.name?.text === name)
    ) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(scope);
  return found;
}

function detectNestedLoopJoin(sources: Map<string, ts.SourceFile>, nextId: NextId, tooling: Set<string>): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (tooling.has(path)) continue; // #1476
    const hits: ts.CallExpression[] = [];

    const inspectLoop = (itemNames: Set<string>, declScope: ts.Node, body: ts.Node) => {
      const scan = (n: ts.Node) => {
        if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ts.isIdentifier(n.expression.expression)) {
          const method = n.expression.name.text;
          const recv = n.expression.expression;
          if (INNER_SCAN_CALLBACK.has(method) || INNER_SCAN_VALUE.has(method)) {
            const probe = n.arguments[0];
            if (
              probe !== undefined &&
              referencesAny(probe, itemNames) && // a join on the current item, not an unrelated nested loop
              !itemNames.has(recv.text) &&
              !declaredWithin(declScope, recv.text) && // loop-invariant: the same outer collection every pass
              !isStaticListSource(sf, recv) && // hardcoded lists never scale
              !/^[A-Z][A-Z0-9_]*$/.test(recv.text) && // SCREAMING_SNAKE = an (often imported) config constant
              (INNER_SCAN_CALLBACK.has(method) || hasArrayEvidence(sf, recv.text)) // value forms exist on strings
            ) {
              hits.push(n);
              return;
            }
          }
        }
        // Deeper function boundaries (a per-B callback, an event handler built per row) are not
        // this loop's per-iteration cost — a deeper nested loop is visited as its own outer loop.
        if (ts.isArrowFunction(n) || ts.isFunctionExpression(n) || ts.isFunctionDeclaration(n)) return;
        ts.forEachChild(n, scan);
      };
      scan(body);
    };

    const visit = (node: ts.Node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        OUTER_LOOP_METHODS.has(node.expression.name.text) &&
        !isStaticListSource(sf, node.expression.expression)
      ) {
        const cb = node.arguments[0];
        if (cb && (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb))) {
          const p0 = cb.parameters[0];
          if (p0 && ts.isIdentifier(p0.name)) inspectLoop(new Set([p0.name.text]), cb, cb.body);
        }
      }
      if (ts.isForOfStatement(node) && !isStaticListSource(sf, node.expression)) {
        const names = loopBindingNames(node);
        if (names.size > 0) inspectLoop(names, node.statement, node.statement);
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);

    const first = hits[0];
    if (!first) continue;
    findings.push(
      makeFinding(nextId, {
        title: `Nested-loop join — per-item linear scan over another collection (${hits.length}× in ${path})`,
        severity: "Perf",
        confidence: "Review",
        taxonomy: "M7 — Nested-loop join",
        location: loc(path, sf, first),
        evidence: `\`${first.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` runs once per item of the enclosing loop over a loop-invariant collection${hits.length > 1 ? ` (first of ${hits.length})` : ""} — O(n·m) comparisons where a lookup built once would be O(n+m).`,
        impact: "Cost multiplies: 1k items × 1k rows is a million comparisons per call. Only matters when BOTH collections scale with tenant/user data — a scan over a small bounded array is fine regardless of shape; confirm sizes before reporting.",
        fix: "Index the scanned collection once before the loop — `const byId = new Map(other.map(o => [o.id, o]))` (or a Set of keys) — and use `.get()`/`.has()` inside it.",
        value: 3,
        ease: 4,
        safety: 5,
      }),
    );
  }
  return findings;
}

// --- F1. Eager import.meta.glob [PERF] — Vite only --------------------------------
//
// `import.meta.glob("./x/*.js", { eager: true })` is a Vite build-time primitive that inlines
// every module the pattern matches directly into the importing chunk (the default, lazy, form
// returns a map of dynamic-import functions instead). At module top level that set lands in the
// entry chunk — the whole matched directory ships up front even if only one file is ever used.

function hasEagerTrue(opts: ts.ObjectLiteralExpression): boolean {
  return opts.properties.some(
    (p) =>
      ts.isPropertyAssignment(p) &&
      ts.isIdentifier(p.name) &&
      p.name.text === "eager" &&
      p.initializer.kind === ts.SyntaxKind.TrueKeyword,
  );
}

function detectImportMetaGlobEager(sources: Map<string, ts.SourceFile>, nextId: NextId, isVite: boolean): Finding[] {
  if (!isVite) return []; // `import.meta.glob` is a Vite-only build primitive
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    const hits: ts.CallExpression[] = [];
    const visit = (n: ts.Node) => {
      if (
        ts.isCallExpression(n) &&
        ts.isPropertyAccessExpression(n.expression) &&
        n.expression.name.text === "glob" &&
        ts.isMetaProperty(n.expression.expression) &&
        n.expression.expression.name.text === "meta"
      ) {
        const opts = n.arguments[1];
        if (opts && ts.isObjectLiteralExpression(opts) && hasEagerTrue(opts)) hits.push(n);
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
    const first = hits[0];
    if (!first) continue;
    findings.push(
      makeFinding(nextId, {
        title: `Eager import.meta.glob pulls every matched module into the chunk (${hits.length}× in ${path})`,
        severity: "Perf",
        confidence: "Likely",
        taxonomy: "M7 — Eager import.meta.glob",
        location: loc(path, sf, first),
        evidence: `\`${first.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` uses \`{ eager: true }\`${hits.length > 1 ? ` (first of ${hits.length})` : ""}, so Vite inlines every file the glob matches into this module's chunk at build time instead of code-splitting them behind dynamic import.`,
        impact: "Every module the pattern matches is bundled and executed up front — the whole set ships in the importing chunk (the entry chunk when this runs at module top level), regardless of which ones the user actually needs.",
        fix: "Drop `eager: true` (the default is lazy) and call the returned `() => import(...)` functions where each module is actually needed, so Vite code-splits them into separate on-demand chunks.",
        value: 3,
        ease: 4,
        safety: 4,
      }),
    );
  }
  return findings;
}

// --- F2. Route components statically imported instead of React.lazy [PERF] — Vite only -----
//
// On a Vite SPA there is no per-route framework code-splitting (Next's `app/`/`pages/` directory
// does it automatically). If every route's component is a plain top-level import, all of them ship
// in the entry chunk and the initial JS grows with the whole app. The fix is `React.lazy(() =>
// import("./Page"))` + `<Suspense>`, which emits one chunk per route fetched on navigation. Guarded
// to files that actually define react-router routes so a non-router `<Route>` never triggers it.

const REACT_ROUTER_SPECIFIER = /^react-router(-dom)?$/;

function isLazyCallee(expr: ts.Expression): boolean {
  if (ts.isIdentifier(expr)) return expr.text === "lazy";
  return ts.isPropertyAccessExpression(expr) && expr.name.text === "lazy";
}

function detectUnsplitRouteComponents(sources: Map<string, ts.SourceFile>, nextId: NextId, isVite: boolean): Finding[] {
  if (!isVite) return [];
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    let usesRouter = false;
    const staticImports = new Set<string>();
    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      if (REACT_ROUTER_SPECIFIER.test(stmt.moduleSpecifier.text)) usesRouter = true;
      const clause = stmt.importClause;
      if (!clause) continue;
      if (clause.name) staticImports.add(clause.name.text); // default import
      if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const el of clause.namedBindings.elements) staticImports.add(el.name.text);
      }
    }
    if (!usesRouter) continue;

    // Names bound to lazy(...) / React.lazy(...) are already code-split — exempt.
    const lazyNames = new Set<string>();
    const collectLazy = (n: ts.Node) => {
      if (
        ts.isVariableDeclaration(n) &&
        ts.isIdentifier(n.name) &&
        n.initializer &&
        ts.isCallExpression(n.initializer) &&
        isLazyCallee(n.initializer.expression)
      ) {
        lazyNames.add(n.name.text);
      }
      ts.forEachChild(n, collectLazy);
    };
    collectLazy(sf);

    const unsplit = new Set<string>();
    let firstEl: ts.JsxOpeningElement | ts.JsxSelfClosingElement | undefined;
    forEachJsxElement(sf, (el) => {
      if (el.tagName.getText(sf) !== "Route") return;
      for (const attr of el.attributes.properties) {
        if (!ts.isJsxAttribute(attr)) continue;
        const attrName = attr.name.getText(sf);
        let comp: string | undefined;
        if (attrName === "element") {
          const expr = jsxAttrExpression(attr);
          if (expr && (ts.isJsxElement(expr) || ts.isJsxSelfClosingElement(expr))) {
            comp = (ts.isJsxElement(expr) ? expr.openingElement : expr).tagName.getText(sf);
          }
        } else if (attrName === "component") {
          const expr = jsxAttrExpression(attr);
          if (expr && ts.isIdentifier(expr)) comp = expr.text;
        }
        if (comp && staticImports.has(comp) && !lazyNames.has(comp)) {
          unsplit.add(comp);
          firstEl ??= el;
        }
      }
    });
    if (unsplit.size === 0 || !firstEl) continue;
    const list = [...unsplit];
    findings.push(
      makeFinding(nextId, {
        title: `${list.length} route component${list.length === 1 ? "" : "s"} statically imported instead of React.lazy (${path})`,
        severity: "Perf",
        confidence: "Review",
        taxonomy: "M7 — Route not code-split",
        location: loc(path, sf, firstEl),
        evidence: `Route components eagerly imported and mounted without \`React.lazy(() => import(...))\`: ${list.slice(0, 8).join(", ")}${list.length > 8 ? ` … and ${list.length - 8} more` : ""} — all of them ship in the entry chunk instead of loading when their route is visited.`,
        impact: "Every route's code downloads on the first page load even though the user sees one route at a time — the SPA's initial JS grows with the whole app rather than the landing route. (A tiny app is fine; confirm the app has enough per-route weight to matter.)",
        fix: "Load route components with `React.lazy(() => import('./Page'))` and wrap the `<Routes>` in `<Suspense fallback={…}>`, so Vite emits one chunk per route fetched on navigation.",
        value: 3,
        ease: 3,
        safety: 4,
      }),
    );
  }
  return findings;
}

// --- Orchestrator --------------------------------------------------------------------

/**
 * Runs all M7 code-level performance checks over the given source set and returns
 * Finding[] (src/findings.ts). Pass the project's full relevant .ts/.tsx source set plus
 * its next.config/babel config files — the React Compiler gate reads the config to decide
 * whether the manual-memo classes are real findings or informational.
 *
 * `framework` (from src/scan/framework-detect.ts) switches the client-JS tiers to their Vite
 * shape (#577): on a Vite SPA every module is client, so the heavy-import and fetch-in-effect
 * checks drop the `'use client'` gate, the Vite-only glob/route-splitting checks turn on, and the
 * raw-<img>/font remediation text branches. Omitted or `next`/`other` → the Next behavior as before.
 */
export function detectPerfCodeFindings(files: SourceInput[], framework?: TargetFramework): Finding[] {
  const compilerOn = reactCompilerEnabled(files);
  // #872: every recognised non-Next framework is Vite-tooled, so they keep the Vite-shape tiers
  // they had when they all resolved to `vite` — the new values must not silently switch them to
  // Next-compiler assumptions.
  const isVite = isViteTooling(framework);
  const sources = new Map(
    // #1065: the loader's own filter, imported so the two can never drift apart.
    files.filter((f) => SOURCE_FILE.test(f.path)).map((f) => [f.path, parse(f.path, f.text)]),
  );
  let n = 0;
  const nextId: NextId = () => `M7C-${String(++n).padStart(2, "0")}`;
  // #1476/#1479: computed once and shared — three classes asked "is this application code a
  // request/bundle can reach?" and each answered it with its own path blocklist.
  const tooling = devToolingModules(files, sources);
  const serverOnly = serverOnlyModules(files, sources, tooling);

  return [
    ...detectUnresolvableCompilerFlag(files, nextId),
    ...detectContextValueLiteral(sources, nextId, compilerOn),
    ...detectInlinePropLiterals(sources, nextId, compilerOn),
    ...detectRawImgElement(sources, nextId, isVite),
    ...detectIndexAsKey(sources, nextId, compilerOn),
    ...detectSortInJsx(sources, nextId),
    ...detectStateSprawl(sources, nextId, reactMajorVersion(files)),
    ...detectAwaitInLoop(sources, nextId, tooling),
    ...detectUnboundedSelect(sources, nextId, tooling),
    ...detectClientFetchEffect(sources, nextId, isVite),
    ...detectWholeLibraryImport(sources, nextId, serverOnly),
    ...detectHeavyClientImport(sources, nextId, isVite, serverOnly),
    ...detectUnoptimizedBarrelImports(files, sources, nextId),
    ...detectManualFontLink(sources, nextId, isVite),
    ...detectImportMetaGlobEager(sources, nextId, isVite),
    ...detectUnsplitRouteComponents(sources, nextId, isVite),
    ...detectMiddlewareFetch(sources, nextId),
    ...detectSyncIoInHandler(files, sources, nextId),
    ...detectJsonDeepClone(sources, nextId),
    ...detectNestedLoopJoin(sources, nextId, tooling),
  ];
}
