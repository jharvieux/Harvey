// M9 — Next.js App Router boundary & rendering. Static AST checks over
// TypeScript/TSX source for the App-Router-specific security/perf surface
// generic tools miss (briefs/scan-extras.txt, M9 section). Shapes results as
// Finding[] (src/findings.ts) for §3 (security) / §3b (performance).
//
// Method: TypeScript compiler API (already a devDependency; no ts-morph in
// this repo). Cross-file resolution (server→client leak, server-only graph)
// follows relative imports, tsconfig/jsconfig `paths` aliases
// (`@/components/...`, per-config-scoped since #1353), and workspace package
// specifiers (`@acme/utils` → `packages/utils/src/index.ts`, #1353), falling
// back to the create-next-app `@/*`→root default when no config is present
// (#380). See docs/m9-app-router.md for full per-check limitations.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { workspacePackages } from "../workspaces.js";
import {
  FRAMEWORK_LABELS,
  isViteTooling,
  ORM_LABELS,
  rawSqlDriver,
  recogniseDataLayer,
  type TargetFramework,
  type TargetOrm,
  type WorkspaceFramework,
} from "../scan/framework-detect.js";
import type { BoundaryAdapter, M9Check, ServerMutation } from "./boundary-model.js";
import { notAssessedCheckNote } from "./boundary-model.js";
import { callChainNames, leadingDirective, loc, parse, type NextId, type SourceInput } from "./common.js";
import {
  AUTH_PATTERN,
  bindingNames,
  collectDbBoundNames,
  collectDerivedClientNames,
  collectParamRootNames,
  collectServiceClientNames,
  collectSessionBoundNames,
  hasOwnershipComparison,
  INSERT_OWNER_COLUMN,
  isServiceRooted,
  OWNERSHIP_COLUMN,
  rootIdentifier,
} from "./owner-id.js";
import { remixAdapter } from "./remix-adapter.js";
import { tanstackAdapter } from "./tanstack-adapter.js";

export type { SourceInput } from "./common.js";
// `validator(`/`.validator(`/`.inputValidator(` recognises chain-level input validation: TanStack
// Start's `createServerFn().validator(schema)` (#918) and the remix-validated-form / `@rvf` /
// `@carbon/form` idiom `validator(schema).validate(await request.formData())` (#964) — a BARE
// `validator(` call plus a `.validate(` invocation, neither of which the old dotted-only regex
// matched, so fully-validated RR7/Remix route actions (e.g. carbon's OAuth token endpoint) false-
// fired High. `\b(?:input)?validator\(` covers the bare and dotted forms; `.validate(` covers the
// schema `.validate(...)` call (yup/joi/@rvf). A real validation signal in any framework, additive
// and FP-safe for Next.
const VALIDATION_PATTERN = /\.safeParse\(|(?<!JSON)\.parse\(|\b(?:input)?validator\(|\.validate\(|\bzod\b|valibot|\byup\.|\bajv\b/i;
const MUTATION_PATTERN = /\.(insert|update|upsert|delete|rpc)\s*\(/;
const SECRET_ENV_PATTERN = /process\.env\.(?!NEXT_PUBLIC_)[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE_KEY|API_KEY|TOKEN)[A-Z0-9_]*/;
const DYNAMIC_API_PATTERN = /^(headers|cookies|noStore|unstable_noStore)$/;
const CACHE_SIGNAL_PATTERN = /unstable_cache|["']use cache["']|\brevalidate\s*[:=]/;
// A page under one of these route segments is auth/token-gated by construction (login, invite
// accept, password reset, OAuth callback, …) — always per-request, never a static/ISR candidate,
// so "no cache config" there is expected, not a smell (extends the #181 tightening).
const AUTH_OR_TOKEN_ROUTE_SEGMENT = /(^|\/)(login|signin|sign-in|signup|sign-up|register|reset-password|forgot-password|verify|invite|magic-link|callback|auth)(\/|$|\.)/i;

// App Router convention directory ("app/"); Pages Router ("pages/", excluding pages/api which
// coexists with App Router in hybrid apps). A project with ANY app/ file is treated as (at
// least partially) App Router — only a project with pages/ and NO app/ at all is Pages-only.
const APP_DIR_PATTERN = /(^|\/)app\//;
const PAGES_DIR_PATTERN = /(^|\/)pages\/(?!api\/)/;

// True when the source set has no `app/` directory but does have a `pages/` one — a Pages
// Router project, where App-Router-only checks (server-only guard, RSC leak, App Router
// rendering/caching primitives) don't apply and are guaranteed false positives if run anyway
// (#231: `server-only` fired on boxyhq/saas-starter-kit, a pure Pages Router app, where
// non-NEXT_PUBLIC_ env vars are already stripped from the client bundle by Next's build —
// the guard is moot there, not missing).
function isPagesRouterOnly(files: SourceInput[]): boolean {
  return !files.some((f) => APP_DIR_PATTERN.test(f.path)) && files.some((f) => PAGES_DIR_PATTERN.test(f.path));
}

// #1238: a whole row does not have to arrive through a Supabase/Drizzle `.from().select()` chain.
// An app on Prisma, or on a hand-rolled repository module, binds it from a MODEL READ —
// `await db.getUser(id)`, `await prisma.user.findUnique(…)` — and the server→client leak check was
// blind to every one of them, which is how the OWASP React fixture (P-OWASP-REACT-RSC-BOUNDARY)
// reported zero. Bounded on BOTH halves so this stays "a row read" rather than "any awaited call":
// the receiver's root must be a database handle by name, and the method a row-returning verb.
const DB_HANDLE = /^(db|prisma|orm|knex|sql|database)$|(Repo|Repository|Dao)$/;
const ROW_READ_VERB = /^(get|find|fetch|load|select|query|read)([A-Z]|$)/;

function isRowReadCall(node: ts.Expression): boolean {
  if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return false;
  if (!ROW_READ_VERB.test(node.expression.name.text)) return false;
  const recv = node.expression.expression;
  // `db.getUser(…)` and Prisma's `prisma.user.findUnique(…)` — one level of model in between.
  const root = ts.isIdentifier(recv) ? recv : ts.isPropertyAccessExpression(recv) && ts.isIdentifier(recv.expression) ? recv.expression : undefined;
  return root !== undefined && DB_HANDLE.test(root.text);
}

function isDbQueryChain(node: ts.Expression): boolean {
  const names = callChainNames(node);
  return (names.includes("from") && names.includes("select")) || isRowReadCall(node);
}

function isDbMutationChain(text: string): boolean {
  return MUTATION_PATTERN.test(text);
}

export function makeFinding(
  nextId: NextId,
  input: {
    title: string;
    severity: Finding["severity"];
    confidence: Finding["confidence"];
    category: "Security" | "Performance";
    taxonomy: string;
    location: string;
    evidence: string;
    impact: string;
    fix: string;
    value: number;
    ease: number;
    safety: number;
    // Defaults to "review" (below) — these AST heuristics are never ~100%-precision, so review is
    // the correct conservative floor. A check overrides it only to go LOWER-trust or to state its
    // tier explicitly; it must never reach the calibration scorer untiered, which silently
    // mis-scores (a positive → miss, a negative FP → invisible) — scoreEntry now fails loud (#327).
    precisionTier?: Finding["precisionTier"];
  },
): Finding {
  return { id: nextId(), status: "Open", precisionTier: "review", ...input };
}

// --- Server → Client data leak [HIGH] -------------------------------------

function normalizeRepoPath(p: string): string {
  const out: string[] = [];
  for (const part of p.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return out.join("/");
}

// #1065: .js/.jsx/.mjs/.cjs are candidates too — on a plain-JavaScript app every cross-file
// resolution (server→client leak, server-only guard) failed here before the extension was listed.
const MODULE_EXTS = [".tsx", ".ts", ".jsx", ".js", ".mjs", ".cjs"];
function candidatePaths(base: string): string[] {
  return [base, ...MODULE_EXTS.map((e) => `${base}${e}`), ...MODULE_EXTS.map((e) => `${base}/index${e}`)];
}

// A tsconfig/jsconfig `compilerOptions.paths` alias reduced to its literal specifier prefix
// (`@/*` → `@/`) and the repo-relative directory it maps to (`["./src/*"]` under baseUrl "." →
// `src`). Only wildcard (`*`) entries are modelled — the create-next-app convention and the
// overwhelmingly common real-world shape.
// Exported so other cross-file detectors (e.g. src/scan/service-role-literal.ts, #664) can reuse
// the same import-resolution logic instead of re-implementing it — "one implementation so the
// surfaces can't drift apart", same rationale as src/detectors/owner-id.ts.
export interface PathAlias {
  prefix: string;
  baseDir: string;
  // #1461: the directory of the tsconfig that declared this alias ("" = repo root). A MONOREPO
  // declares the same prefix once per workspace — carbon maps `~/*` in apps/erp, apps/mes,
  // apps/starter and apps/academy — so a specifier has to resolve against ITS OWN package's
  // mapping, not against whichever config happened to be parsed first.
  scope: string;
  /**
   * #1353: a workspace member's entry-module bases, tried when the specifier IS the package name
   * with no subpath. Present only on workspace-package aliases, which match EXACTLY (a tsconfig
   * alias like `@/` is a prefix and is never itself a whole specifier).
   */
  entryBases?: string[];
}

// Parse the source set's tsconfig/jsconfig for `paths` aliases (#380), plus one alias pair per
// workspace member package (#1353). ts.parseConfigFileTextToJson tolerates the comments/trailing
// commas tsconfig commonly carries. With no config paths in the set, fall back to Next.js's own
// `@/*`→root default rather than giving up — the vast majority of otherwise-unresolved specifiers
// are exactly that scaffolding default.
//
// Three independent monorepo failures were fixed here on 2026-07-28. They compose — one decides
// WHICH FILENAMES are read, one HOW MANY of them, one what a NON-tsconfig specifier resolves to.
// - #1479 widened the filename: an Nx repo keeps its `paths` map in `tsconfig.base.json` and ships
//   no root `tsconfig.json`, so ghostfolio's whole cross-file import graph was disconnected.
// - #1461 replaced "the shallowest config with `paths` wins, then stop reading" with per-config
//   scoping, measured on carbon (below).
// - #1353 added workspace PACKAGE specifiers, which no tsconfig declares at all: `@rallly/utils`
//   -> packages/utils, through that package's own `main`/`exports` (wildcards included). Without
//   it the graph stopped at the package boundary and #1344's reachability gate read a shared
//   package as unreachable from the app's routes.
//
// #1461: this used to stop at the SHALLOWEST config that declared any `paths` and return only its
// aliases. On a single-app repo that is the repo-root tsconfig and the rule is right; on a MONOREPO
// it silently picked one workspace and made every other workspace's aliased import unresolvable.
// MEASURED 2026-07-28 on crbnos/carbon's pin: the winner was `docs/tsconfig.json`, so `@/`→`docs`
// and `collections/` were the ONLY two aliases in the whole run, and every `~/…` specifier in
// apps/erp, apps/mes, apps/starter and apps/academy — the four workspaces that actually declare
// `~/*` — resolved to nothing. Every cross-file pass built on resolveImport (#1263's gate
// resolution, #1461's exit-inside-a-helper test, the import graph, service-role-literal) was
// therefore blind across most of that target, and read as "callee not resolvable" rather than
// failing loud. Now every config contributes, tagged with the directory that declared it, and
// resolveAliasedImport prefers the alias whose declaring package CONTAINS the importing file.
export function collectPathAliases(files: SourceInput[]): PathAlias[] {
  const configs = files
    .filter((f) => /(^|\/)(tsconfig|jsconfig)(\.[\w.-]+)?\.json$/.test(f.path))
    .sort((a, b) => a.path.split("/").length - b.path.split("/").length);
  const aliases: PathAlias[] = [];
  for (const cfg of configs) {
    const { config } = ts.parseConfigFileTextToJson(cfg.path, cfg.text);
    const opts = config?.compilerOptions;
    if (!opts?.paths) continue;
    const cfgDir = cfg.path.includes("/") ? cfg.path.slice(0, cfg.path.lastIndexOf("/")) : "";
    const baseUrl = typeof opts.baseUrl === "string" ? opts.baseUrl : "";
    for (const [key, targets] of Object.entries(opts.paths)) {
      const target = Array.isArray(targets) ? targets[0] : undefined;
      if (!key.endsWith("/*") || typeof target !== "string" || !target.endsWith("/*")) continue;
      aliases.push({ prefix: key.slice(0, -1), baseDir: normalizeRepoPath(`${cfgDir}/${baseUrl}/${target.slice(0, -1)}`), scope: cfgDir });
    }
  }
  if (aliases.length === 0) aliases.push({ prefix: "@/", baseDir: "", scope: "" });
  // #1353: workspace members last, at repo scope — a package name is valid from anywhere in the
  // tree, so it must not out-rank an enclosing package's own tsconfig alias.
  for (const pkg of workspacePackages(files)) {
    for (const sub of pkg.subpaths) aliases.push({ ...sub, scope: "" });
    aliases.push({ prefix: pkg.name, baseDir: pkg.dir, scope: "", entryBases: pkg.entryBases });
  }
  return aliases;
}

function resolveRelativeImport(fromPath: string, specifier: string, allPaths: Set<string>): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  const stack = fromPath.split("/").slice(0, -1);
  for (const part of specifier.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  return candidatePaths(stack.join("/")).find((c) => allPaths.has(c));
}

// #1461: an alias declared by the package that CONTAINS the importing file wins, deepest scope
// first; an alias from some other workspace is only a last resort. Keeping that fallback is
// deliberate — before this change one arbitrary package's aliases were applied repo-wide, so
// dropping it outright would un-resolve specifiers that resolve today.
function resolveAliasedImport(fromPath: string, specifier: string, allPaths: Set<string>, aliases: PathAlias[]): string | undefined {
  // 0 = declared by some other workspace; higher = a deeper enclosing package, which wins.
  const rank = (a: PathAlias) => (a.scope === "" || fromPath.startsWith(`${a.scope}/`) ? a.scope.length + 1 : 0);
  const ordered = [...aliases].sort((a, b) => rank(b) - rank(a));
  for (const { prefix, baseDir, entryBases } of ordered) {
    if (entryBases) {
      // #1353: a workspace package named EXACTLY, with no subpath — resolve to its own entry module.
      if (specifier !== prefix) continue;
      const hit = entryBases.flatMap(candidatePaths).find((c) => allPaths.has(c));
      if (hit) return hit;
      continue;
    }
    if (!specifier.startsWith(prefix)) continue;
    const rest = specifier.slice(prefix.length);
    const base = normalizeRepoPath(baseDir ? `${baseDir}/${rest}` : rest);
    const hit = candidatePaths(base).find((c) => allPaths.has(c));
    if (hit) return hit;
  }
  return undefined;
}

export function resolveImport(fromPath: string, specifier: string, allPaths: Set<string>, aliases: PathAlias[]): string | undefined {
  return resolveRelativeImport(fromPath, specifier, allPaths) ?? resolveAliasedImport(fromPath, specifier, allPaths, aliases);
}

// An object literal whose ONLY informative content is a spread of a raw-row name — `{...row}`,
// possibly with extra literal props. Spreading the whole row copies every field, so a binding of
// this shape is still a full-row leak (the narrowing the DTO fix requires is `{ name: row.name }`,
// not a spread). Returns the spread source name if the object spreads a tainted row.
export function objectSpreadsRawRow(expr: ts.Expression, rawRowNames: ReadonlySet<string>): boolean {
  return rowNameOf(expr, rawRowNames) !== undefined;
}

export function rowNameOf(expr: ts.Expression, rawRowNames: ReadonlySet<string>): string | undefined {
  if (!ts.isObjectLiteralExpression(expr)) return undefined;
  for (const p of expr.properties) {
    if (ts.isSpreadAssignment(p) && ts.isIdentifier(p.expression) && rawRowNames.has(p.expression.text)) return p.expression.text;
  }
  return undefined;
}

// Names bound to a raw Supabase query result, PLUS one hop of aliasing (#847): `const dto = row`
// and `const dto = {...row}` still ship the whole row, so a leak that maps the row into an
// intermediate before passing it must still flag. `const { name } = row` (a narrowing destructure)
// is deliberately NOT propagated — it projects, which is the safe shape. The propagation pass runs
// in source order, so a later alias of an earlier alias is also caught; direct bindings dominate.
// #1293: a query whose own `.select()` names its columns has ALREADY projected — the same "it
// projects, which is the safe shape" rule the comment above applies to `const { name } = row`, one
// step earlier. The leak finding's evidence asserts "every field on the row ships to the browser";
// against `.select("id, name, status")` that sentence is simply false, and all THREE of carbon's
// server→client-leak Highs were this shape (MEASURED 2026-07-28 on the pin: 4, 5 and 7 named
// columns). Only a literal column list counts — `*` anywhere (including an embed like
// `"*, plan:planId(name)"`), a computed argument, or no argument at all leaves the row raw, so this
// can only ever suppress on evidence that is present in the source.
function selectIsColumnNarrowed(chain: ts.Expression): boolean {
  for (let cur: ts.Expression = chain; ; ) {
    if (ts.isCallExpression(cur)) {
      if (ts.isPropertyAccessExpression(cur.expression) && cur.expression.name.text === "select") {
        const arg = cur.arguments[0];
        if (!arg) return false;
        const cols = ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg) ? arg.text : undefined;
        return cols !== undefined && cols.trim() !== "" && !cols.includes("*");
      }
      cur = cur.expression;
    } else if (ts.isPropertyAccessExpression(cur)) {
      cur = cur.expression;
    } else {
      return false;
    }
  }
}

export function collectRawRowNames(sf: ts.SourceFile): Set<string> {
  const rawRowNames = new Set<string>();
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const init = ts.isAwaitExpression(node.initializer) ? node.initializer.expression : node.initializer;
      if (ts.isCallExpression(init) && isDbQueryChain(init) && !selectIsColumnNarrowed(init)) {
        if (ts.isIdentifier(node.name)) {
          rawRowNames.add(node.name.text);
        } else if (ts.isObjectBindingPattern(node.name)) {
          for (const el of node.name.elements) {
            const propName = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : ts.isIdentifier(el.name) ? el.name.text : undefined;
            if (propName === "data" && ts.isIdentifier(el.name)) rawRowNames.add(el.name.text);
          }
        }
      } else if (ts.isIdentifier(node.name) && ((ts.isIdentifier(init) && rawRowNames.has(init.text)) || objectSpreadsRawRow(init, rawRowNames))) {
        rawRowNames.add(node.name.text); // one-hop alias: `const dto = row` / `const dto = {...row}`
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return rawRowNames;
}

function collectClientComponentImports(sf: ts.SourceFile, path: string, clientPaths: Set<string>, allPaths: Set<string>, aliases: PathAlias[]): Map<string, string> {
  const imports = new Map<string, string>();
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier) || !stmt.importClause) continue;
    const resolved = resolveImport(path, stmt.moduleSpecifier.text, allPaths, aliases);
    if (!resolved || !clientPaths.has(resolved)) continue;
    const clause = stmt.importClause;
    if (clause.name) imports.set(clause.name.text, resolved);
    if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const el of clause.namedBindings.elements) imports.set(el.name.text, resolved);
    }
  }
  return imports;
}

function detectServerClientLeak(sources: Map<string, ts.SourceFile>, nextId: NextId, aliases: PathAlias[]): Finding[] {
  const findings: Finding[] = [];
  const allPaths = new Set(sources.keys());
  const clientPaths = new Set([...sources].filter(([, sf]) => leadingDirective(sf) === "use client").map(([p]) => p));

  for (const [path, sf] of sources) {
    if (leadingDirective(sf) === "use client") continue;
    const clientImports = collectClientComponentImports(sf, path, clientPaths, allPaths, aliases);
    if (clientImports.size === 0) continue;
    const rawRowNames = collectRawRowNames(sf);
    if (rawRowNames.size === 0) continue;

    const flagAttr = (attr: ts.JsxSpreadAttribute | ts.JsxAttribute, tagName: string, exprText: string) => {
      findings.push(
        makeFinding(nextId, {
          title: `Full DB row passed to client component <${tagName}>`,
          severity: "High",
          confidence: "Likely",
          category: "Security",
          taxonomy: "M9 — Server→client data leak",
          location: loc(path, sf, attr),
          evidence: `\`${exprText}\` — a query result variable is passed whole into <${tagName} /> ('use client' at ${clientImports.get(tagName)}). Every field on it is serialized into the RSC payload sent to the browser.`,
          impact: "Any field on the row not rendered by the client (other-tenant data, secrets, hashes, internal flags) still ships to the browser and is readable in devtools/view-source.",
          fix: `Project the query result to an explicit minimal DTO (whitelist only the fields <${tagName} /> renders) before passing it as a prop.`,
          value: 5,
          ease: 3,
          safety: 4,
        }),
      );
    };

    const visit = (node: ts.Node) => {
      if (ts.isJsxSelfClosingElement(node) || ts.isJsxOpeningElement(node)) {
        const tagName = node.tagName.getText(sf);
        if (clientImports.has(tagName)) {
          for (const attr of node.attributes.properties) {
            if (ts.isJsxSpreadAttribute(attr) && ts.isIdentifier(attr.expression) && rawRowNames.has(attr.expression.text)) {
              flagAttr(attr, tagName, `{...${attr.expression.text}}`);
            } else if (ts.isJsxAttribute(attr) && attr.initializer && ts.isJsxExpression(attr.initializer) && attr.initializer.expression) {
              const inner = attr.initializer.expression;
              if (ts.isIdentifier(inner) && rawRowNames.has(inner.text)) {
                flagAttr(attr, tagName, `${attr.name.getText(sf)}={${inner.text}}`);
              } else if (objectSpreadsRawRow(inner, rawRowNames)) {
                // `data={{...row}}` — an inline object spreading the whole row still ships every field.
                flagAttr(attr, tagName, `${attr.name.getText(sf)}={{...${rowNameOf(inner, rawRowNames)}}}`);
              }
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

// --- Missing `server-only` guard [HIGH] ------------------------------------

const SERVER_ONLY_EXEMPT_PATTERN = /(^|\/)(route\.[cm]?[jt]sx?|middleware\.[cm]?[jt]sx?)$/;

function hasServerOnlyImport(sf: ts.SourceFile): boolean {
  return sf.statements.some((s) => ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier) && s.moduleSpecifier.text === "server-only");
}

function findSecretEnvAccess(sf: ts.SourceFile): ts.Node | undefined {
  let hit: ts.Node | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    if (ts.isPropertyAccessExpression(node) && SECRET_ENV_PATTERN.test(node.getText(sf))) {
      hit = node;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return hit;
}

// Every file the `roots` reach by following imports transitively, roots included. #231: a raw hit
// is only real when something on the entry side actually imports the module — every raw hit in the
// 6-repo triage was already shielded by the next/headers barrier or the 'use server' boundary
// because nothing imported it from client code at all. #1344 reuses the same closure from the
// server side, to answer "is this module reachable from a request handler at all".
export function importClosure(roots: Iterable<string>, importGraph: ReadonlyMap<string, string[]>): Set<string> {
  const reached = new Set<string>();
  const queue = [...roots];
  while (queue.length > 0) {
    const cur = queue.shift();
    if (cur === undefined || reached.has(cur)) continue;
    reached.add(cur);
    queue.push(...(importGraph.get(cur) ?? []));
  }
  return reached;
}

export function buildImportGraph(sources: Map<string, ts.SourceFile>, allPaths: Set<string>, aliases: PathAlias[]): Map<string, string[]> {
  const graph = new Map<string, string[]>();
  for (const [path, sf] of sources) {
    const edges: string[] = [];
    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      // #1461: a TYPE-ONLY import is erased at compile time and bundles nothing, so it is not an
      // edge any consumer of this graph should see. `import type { AppRouter } from "../routers"`
      // in a 'use client' tRPC provider is the canonical shape, and counting it made rallly's whole
      // server router tree "reachable from a Client Component" — 3 High `Missing server-only guard`
      // rows on modules no client bundle can ever reach (MEASURED 2026-07-28, found because #1461's
      // alias fix created the edge for the first time; before it, the specifier resolved to nothing
      // and the wrong answer was invisible). `collectValueImports` already skipped these; the graph
      // did not.
      if (stmt.importClause?.isTypeOnly) continue;
      const resolved = resolveImport(path, stmt.moduleSpecifier.text, allPaths, aliases);
      if (resolved) edges.push(resolved);
    }
    graph.set(path, edges);
  }
  return graph;
}

function detectMissingServerOnly(sources: Map<string, ts.SourceFile>, nextId: NextId, pagesRouterOnly: boolean, aliases: PathAlias[]): Finding[] {
  if (pagesRouterOnly) return []; // App-Router-only check (see isPagesRouterOnly)

  const findings: Finding[] = [];
  const allPaths = new Set(sources.keys());
  const clientPaths = new Set([...sources].filter(([, sf]) => leadingDirective(sf) === "use client").map(([p]) => p));
  // #1461: the walk must STOP at a server-exclusive boundary, for the same reason this loop below
  // skips such files as candidates. `import "server-only"` is a build-time poison pill — nothing
  // behind it can reach a client bundle — and a `"use server"` module compiles to an RPC endpoint,
  // so a Client Component importing it ships a reference, never the module body. Traversing THROUGH
  // them made every module a server action transitively touches "client-reachable": MEASURED on
  // rallly 2026-07-28, two High rows whose whole chain ran `create-api-key-button.tsx ('use client')
  // → actions.ts ('use server') → …`, which bundles nothing. Cutting the edges at the boundary
  // rather than filtering the result keeps the reason legible where the traversal happens.
  const opaque = (p: string): boolean => {
    const sf = sources.get(p);
    return sf !== undefined && !clientPaths.has(p) && (leadingDirective(sf) !== undefined || hasServerOnlyImport(sf));
  };
  const graph = buildImportGraph(sources, allPaths, aliases);
  const clientGraph = new Map([...graph].map(([p, deps]) => [p, opaque(p) ? [] : deps]));
  const reachedFromClient = importClosure(clientPaths, clientGraph);

  for (const [path, sf] of sources) {
    if (leadingDirective(sf) !== undefined) continue; // 'use client' can't hold secrets like this meaningfully; 'use server' modules are already server-exclusive by the Next compiler
    if (SERVER_ONLY_EXEMPT_PATTERN.test(path)) continue; // route handlers / middleware are already server-exclusive by Next.js routing convention
    if (hasServerOnlyImport(sf)) continue;
    const secretNode = findSecretEnvAccess(sf);
    if (!secretNode) continue;
    if (!reachedFromClient.has(path)) continue; // nothing on the client side imports this module — no bundling risk to guard against

    findings.push(
      makeFinding(nextId, {
        title: `Server-exclusive module missing 'server-only' guard`,
        severity: "High",
        confidence: "Likely",
        category: "Security",
        taxonomy: "M9 — Missing server-only guard",
        location: loc(path, sf, secretNode),
        evidence: `\`${secretNode.getText(sf)}\` is read here, but the file has no \`import "server-only"\` poison-pill.`,
        impact: "If this module is ever transitively imported from a Client Component, the secret is bundled into client-side JS with no build error.",
        fix: `Add \`import "server-only";\` as the first import in this file.`,
        value: 5,
        ease: 5,
        safety: 5,
      }),
    );
  }
  return findings;
}

// --- Server Actions: missing auth / missing validation [HIGH] -------------

interface ServerAction {
  name: string;
  node: ts.Node;
}

function bodyStartsWithUseServer(body: ts.Block | undefined): boolean {
  const first = body?.statements[0];
  return !!first && ts.isExpressionStatement(first) && ts.isStringLiteral(first.expression) && first.expression.text === "use server";
}

function collectServerActions(sf: ts.SourceFile): ServerAction[] {
  const fileLevel = leadingDirective(sf) === "use server";
  const actions: ServerAction[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.body && (fileLevel || bodyStartsWithUseServer(node.body))) {
      actions.push({ node, name: node.name?.text ?? "<anonymous>" });
    } else if (ts.isVariableDeclaration(node) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) {
      const fn = node.initializer;
      const body = ts.isBlock(fn.body) ? fn.body : undefined;
      if ((fileLevel || bodyStartsWithUseServer(body)) && ts.isIdentifier(node.name)) {
        actions.push({ node: fn, name: node.name.text });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return actions;
}

// --- Client-supplied owner id trusted by a server action [HIGH] ------------
//
// #221's mechanical half, WIDENED per #465 (operator ruling, 2026-07-17): a server action whose
// mutation's row identity comes from a value the CLIENT supplied. Three shapes fire:
//   1. AUTHENTICATED + ownership-column `.eq()` (the original #221 shape, any client): auth is
//      called and bound, yet `.eq("user_id", <argument>)` picks the row — authentication
//      without authorization.
//   2. SERVICE-ROLE bare-id: `.eq("id", <argument>)` on a mutating chain rooted in the
//      service/admin client (proposit's updateUserProfileAction). RLS is bypassed, so the
//      client-picked primary key is the entire row authorization.
//   3. SERVICE-ROLE insert-value: `.insert/.upsert({ <ownership column>: <argument> })`
//      (proposit's acceptInvitationAction / createOrganisationAction) — the client says who
//      the new row belongs to and nothing checks it.
// Shapes 2 and 3 fire with or without an in-body auth call; the service-role root is the
// precision boundary that lets the no-auth widening stay FP-safe: on the plain RLS client the
// same syntax is still row-gated by policies (proposit's updateOrganisationLogo is the measured
// near-miss and must stay silent — it draws the generic missing-auth finding instead).
//
// MEASURED against proposit (286 source files): pre-widening recall 0/3, 0 FP (#326/#465 —
// the three real instances matched neither old gate); post-widening re-measured in this change,
// see the PR for the numbers. Conservatism kept from the original: an auth call that BINDS
// nothing (`await requireUser()` / `await assertPermission(…)`) still suppresses every shape —
// a role-gate wrapper the AST can't see into may already authorize arbitrary-row writes.
//
// DEDUPE (#465): when a shape fires on an action with NO auth call at all, the generic
// "M1 — Server Action missing authorization check" would fire on the same site; this detector
// subsumes it (the evidence carries the no-auth fact), so one code defect stays one finding —
// detectAppRouterFindings passes the subsumed action nodes to
// detectServerActionAuthAndValidation, which skips its missing-auth finding for them.
//
// #221's items 2 and 3 are NOT one bucket, and stating them as one is what made this comment wrong
// (#1373, corrected 2026-07-31). Item 2 — trusting a client-supplied role, price, discount or trial
// length — ships MECHANICALLY at review tier today, in two single-file semgrep rules with none of
// the cross-file or business-context machinery this comment used to say the class requires:
// `harvey-client-trusted-role` (auth.yml, landed 77b57db 2026-07-19, two days AFTER this comment)
// covers the role member, and `harvey-client-trusted-price` (auth.yml, #1373) covers the price /
// discount / trial-length members, including the `"use server"` parameter spelling the one disclosed
// real-world instance actually has — `validate-source-recall --real` moved 0/3 -> 1/3 on it
// (MEASURED 2026-07-31). Item 3 — UI-only permission gates — is the part that genuinely still needs
// cross-file reasoning and stays semantic/paid-tier: see the B15 corpus entries and
// docs/design/corpus-roadmap-to-100.md §4a.
// Every finding here is `review`/`Likely`, never free-count: the AST proves the value's origin,
// not that authorization is absent from code it can't see.

interface ClientOwnerSite {
  column: string;
  node: ts.CallExpression;
  service: boolean; // the chain roots in the RLS-bypassing service/admin client
  verb: "eq" | "insert";
}

// A mutation site whose row identity comes from a client-rooted value (the three shapes above).
// Bare `.eq("id", …)` and insert-values are accepted only on service-rooted chains — on the RLS
// client that syntax is still row-gated by policies and flagging it would hit every ordinary
// RLS-delegated mutation.
function findClientOwnerSite(fn: ts.Node, sf: ts.SourceFile, clientNames: Set<string>, serviceNames: Set<string>): ClientOwnerSite | undefined {
  let hit: ClientOwnerSite | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const method = node.expression.name.text;
      if (method === "eq" && node.arguments.length === 2) {
        const [col, val] = node.arguments;
        if (col && val && ts.isStringLiteralLike(col)) {
          const service = isServiceRooted(node, serviceNames);
          if (OWNERSHIP_COLUMN.test(col.text) || (service && col.text === "id")) {
            const root = rootIdentifier(val);
            // The .eq() must sit on the mutating chain itself, not on a sibling read in the
            // same action — so test the enclosing statement, falling back to the chain alone.
            const stmt = ts.findAncestor(node, ts.isExpressionStatement) ?? ts.findAncestor(node, ts.isVariableStatement) ?? node;
            const stmtText = sf.text.slice(stmt.getStart(sf), stmt.getEnd());
            if (root && clientNames.has(root) && MUTATION_PATTERN.test(stmtText)) {
              hit = { column: col.text, node, service, verb: "eq" };
              return;
            }
          }
        }
      }
      if ((method === "insert" || method === "upsert") && node.arguments.length >= 1) {
        const arg = node.arguments[0];
        if (arg && ts.isObjectLiteralExpression(arg) && isServiceRooted(node, serviceNames)) {
          for (const prop of arg.properties) {
            if (!ts.isPropertyAssignment(prop)) continue;
            const name = ts.isIdentifier(prop.name) || ts.isStringLiteralLike(prop.name) ? prop.name.text : undefined;
            if (!name || !INSERT_OWNER_COLUMN.test(name)) continue;
            const root = rootIdentifier(prop.initializer);
            if (root && clientNames.has(root)) {
              hit = { column: name, node, service: true, verb: "insert" };
              return;
            }
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return hit;
}

interface ClientOwnerIdResult {
  findings: Finding[];
  // Actions with NO auth call where a shape fired — their generic missing-auth finding is
  // subsumed by the more specific finding here (one code defect, one finding).
  subsumedNoAuthActions: Set<ts.Node>;
}

// #1434: this detector tested AUTH_PATTERN against the action's RAW text, which is wrong twice
// over. It is the only remaining raw-text use of that pattern — its sibling
// detectServerActionAuthAndValidation blanks literals/comments (#845) and resolves callees
// (#1263) — and the divergence reached the client: an action gated by a house-style helper got a
// finding whose evidence read "makes no auth/session call at all", a false assertion about the
// client's code on the higher-severity of the two findings.
//
// The two uses of `hasAuth` here are SEPARABLE and the issue asked which one moves. Both do, and
// they move together, because the resolved form lands on the same policy the inline form
// already has: `collectSessionBoundNames` only ever binds off an initializer matching
// AUTH_PATTERN, so a gate reached through a callee binds NOTHING in the action body and therefore
// always hits the `auth called, nothing bound → stay silent` rule below. That is exactly what an
// inline `await requireUser()` gets today. So resolving the callee is a pure SUPPRESSION with no
// new policy — the #1263 property — and it makes the no-auth evidence sentence true by
// construction: it can now only be emitted when neither the body nor any resolvable helper
// authenticates.
function detectClientSuppliedOwnerId(
  sources: Map<string, ts.SourceFile>,
  nextId: NextId,
  mutationsFor: (path: string, sf: ts.SourceFile) => ServerMutation[],
  noun: string,
  aliases: PathAlias[],
): ClientOwnerIdResult {
  const findings: Finding[] = [];
  const subsumedNoAuthActions = new Set<ts.Node>();
  const gates = new GateResolver(sources, aliases);
  for (const [path, sf] of sources) {
    for (const action of mutationsFor(path, sf)) {
      const text = sf.text.slice(action.node.getStart(sf), action.node.getEnd());
      if (!isDbMutationChain(text)) continue;

      // Literals and comments blanked first (#845): a `// TODO: add auth` used to vouch for the
      // action here and silence it through the rule below — a false negative on the raw test.
      const inBodyAuth = AUTH_PATTERN.test(stripLiteralsAndComments(sf, action.node));
      const gate = inBodyAuth ? undefined : gates.gateIn(AUTH_PATTERN, path, action.node);
      const hasAuth = inBodyAuth || gate !== undefined;
      const sessionNames = collectSessionBoundNames(action.node, sf);
      // Auth was called but nothing was bound from it (`await requireUser()` for its throw, or
      // an `assertPermission(…)` role gate). Whether the client value is authorized then depends
      // on code this AST pass can't see — stay silent, for every shape.
      if (hasAuth && sessionNames.size === 0) continue;

      const paramRoots = collectParamRootNames(action.node);
      const clientNames = new Set([...paramRoots, ...collectDerivedClientNames(action.node, paramRoots)]);
      // Session precedence: `const session = await getServerSession(req)` is DERIVED from a
      // client root in the dataflow sense, but its value is server-verified — it must never
      // count as client-supplied.
      for (const s of sessionNames) clientNames.delete(s);
      if (clientNames.size === 0) continue;

      const serviceNames = collectServiceClientNames(action.node, sf);
      const site = findClientOwnerSite(action.node, sf, clientNames, serviceNames);
      if (!site) continue;
      // Without an in-body auth+session, only the service-role shapes are findings: on the RLS
      // client the missing-auth check owns the defect (RLS still gates the row).
      if (!hasAuth && !site.service) continue;
      // A comparison against the session OR a row the server fetched itself (a token-exchange
      // flow) is the authorization check — clear.
      const serverNames = new Set([...sessionNames, ...collectDbBoundNames(action.node)]);
      if (hasOwnershipComparison(action.node, serverNames, clientNames)) continue;

      const siteText = site.verb === "eq" ? `.eq("${site.column}", …)` : `.insert({ ${site.column}: … })`;
      const sessionName = [...sessionNames][0];
      if (!hasAuth) subsumedNoAuthActions.add(action.node);
      findings.push(
        makeFinding(nextId, {
          title:
            site.verb === "eq"
              ? `${noun} \`${action.name}\` mutates rows scoped by a client-supplied \`${site.column}\`${hasAuth ? "" : " with no auth check"}`
              : `${noun} \`${action.name}\` writes rows owned by a client-supplied \`${site.column}\`${hasAuth ? "" : " with no auth check"}`,
          severity: "High",
          confidence: "Likely",
          category: "Security",
          taxonomy: hasAuth ? "M1 — Client-supplied owner id trusted by authenticated action" : "M1 — Client-supplied owner id trusted by unauthenticated service-role action",
          location: loc(path, sf, site.node),
          evidence: hasAuth
            ? `\`${action.name}\` authenticates the caller (binding \`${sessionName}\`) but decides which row it writes with \`${siteText}\` on a value that comes from the action's own arguments, not from \`${sessionName}\`. No comparison between the two appears in the body.`
            // #1434: the old sentence read "makes no auth/session call at all … Nothing anywhere
            // checks the caller may touch that row" — two claims this check never established. It
            // reads the action's own body and, since #1263's resolver was wired in above, the body
            // of every helper it can resolve to a declaration in the scanned tree. A gate reached
            // only through a package import is still invisible, so the sentence states its bound
            // instead of asserting the universal.
            : `\`${action.name}\` runs on the service-role client (RLS bypassed) and decides which row it writes with \`${siteText}\` on a value from its own arguments, with no auth/session call in its body and none in any helper it calls that this pass could resolve to a declaration in the scanned tree. No check on the caller's right to that row was found in what it could read.`,
          impact:
            "The caller is never authorized for the row: any user can pass another user's/tenant's id and mutate (or take ownership of) their data. Schema validation does not close this — a well-formed id from the wrong tenant still passes.",
          fix: hasAuth
            ? `Derive the owner id from the session (e.g. \`${sessionName}.id\`), or explicitly compare the supplied id against the session's before mutating.`
            : `Authenticate the caller in the action body and derive the owner id from that session, or explicitly compare the supplied id against the session's before mutating.`,
          // Review, never free-count: the AST proves the value is client-rooted and that no
          // session-vs-client comparison exists IN THIS BODY — not that authorization is absent
          // from a wrapper/middleware it can't see. That residual is what triage is for.
          precisionTier: "review",
          value: 5,
          ease: 3,
          safety: 4,
        }),
      );
    }
  }
  return { findings, subsumedNoAuthActions };
}

// The action's source text with the INTERIOR of every string/template/regex literal and every
// comment blanked to spaces (positions preserved) (#845). AUTH_PATTERN/VALIDATION_PATTERN are text
// heuristics, so an `auth` in `// TODO: add auth` or a `.parse(` in a log string used to defeat
// them — a false negative — and a keyword in an unrelated string caused a false positive. Blanking
// literal/comment content first means only real code tokens can match. (Comments are stripped after
// literal interiors so a `//` inside a string is never mistaken for a comment start.)
function stripLiteralsAndComments(sf: ts.SourceFile, action: ts.Node): string {
  const start = action.getStart(sf);
  const chars = sf.text.slice(start, action.getEnd()).split("");
  const blank = (from: number, to: number) => {
    for (let i = from - start; i < to - start; i++) if (chars[i] !== "\n") chars[i] = " ";
  };
  const visit = (node: ts.Node) => {
    if (ts.isStringLiteralLike(node) || ts.isRegularExpressionLiteral(node)) {
      blank(node.getStart(sf), node.getEnd());
    } else if (ts.isTemplateExpression(node)) {
      blank(node.head.getStart(sf), node.head.getEnd());
      for (const span of node.templateSpans) blank(span.literal.getStart(sf), span.literal.getEnd());
    }
    ts.forEachChild(node, visit);
  };
  visit(action);
  return chars
    .join("")
    .replace(/\/\/[^\n]*/g, (m) => " ".repeat(m.length))
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));
}

// #1263: AUTH_PATTERN and VALIDATION_PATTERN are closed NAME lists tested against the action's own
// text, so a real gate with a house-style name — `await ensureMember(orgId)`, `sanitize(input)` —
// matched neither and the action was reported as missing auth/validation. A false positive on
// competent code. The fix recognises a gate by WHAT IT DOES: resolve each function the action calls
// to its declaration (same file, or an imported module already in the loaded source set) and re-test
// the pattern against THAT function's body, up to GATE_DEPTH hops of helper-calls-helper.
//
// It can only ever SUPPRESS. A callee that resolves to nothing — a node_modules import, a dynamic
// call, a method on an object this pass doesn't model — leaves the finding exactly as it was, so
// #857's false-negative half (literal/comment blanking) is untouched and no true positive is lost
// by narrowing. The helper's body is blanked the same way before matching, so a `// TODO: add auth`
// inside the HELPER does not vouch for it either.
//
// #1500: raised 2 -> 4, MEASURED against tanstack-com's real chain, not guessed. TanStack's
// `showcase`/`docFeedback` server functions gate through `requireModerateShowcases() ->
// requireCapability() -> getAuthGuards() -> createAuthGuards()`, and the real check
// (`authService.getCurrentUser(request)`) lives inside `createAuthGuards`'s body — 4 resolvable
// hops from the action, not 2. `getAuthGuards` itself only resolves at all because of the
// dynamic-import-wrapper and re-export fixes above; depth alone would not have been enough. Kept
// as ONE constant shared by gateIn (auth/validation) and throwingCallee (the waterfall guard,
// #1461) deliberately — re-measured together below rather than assumed independent, because they
// walk the same call graph and a regression in one would plausibly show in the other.
//
// The #1240 -> #1358 lesson (a NAME-keyed widening regressed silently) does not apply to raising
// this number the same way: this pass can only ever SUPPRESS a finding, never invent one, so the
// only failure mode is a real gate/exit reached one hop further out getting suppressed when it
// should not be — i.e. a FALSE NEGATIVE, not a false positive. `M9C-GATE-DEPTH-NEG` plants exactly
// that: a 4-hop chain of NON-gates (no helper anywhere in it denies or is consumed) that must still
// fire at depth 4, so a future widening that stops resolving real chains would go red here first.
const GATE_DEPTH = 4;

// Every function declared in a module, by the name a caller would use: `function f(){}`,
// `const f = () => {}`, `const f = function(){}`, and the `export default` form.
function collectDeclaredFunctions(sf: ts.SourceFile): Map<string, ts.Node> {
  const out = new Map<string, ts.Node>();
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name && !out.has(node.name.text)) {
      out.set(node.name.text, node);
    } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)) && !out.has(node.name.text)) {
      out.set(node.name.text, node.initializer);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

interface ImportedBinding {
  path: string;
  name: string;
}

// Local name → (module path, exported name) for every VALUE import whose module the scan loaded.
// A specifier that resolves outside the source set (a package) is absent, which is what keeps an
// unresolvable gate a finding rather than a silent pass. `import * as guards` records the local
// name against NAMESPACE_IMPORT, so `guards.ensureMember(…)` resolves through the module (#1439 —
// #1263's original false positive survived for that idiom).
const NAMESPACE_IMPORT = "*";

function collectValueImports(sf: ts.SourceFile, path: string, allPaths: Set<string>, aliases: PathAlias[]): Map<string, ImportedBinding> {
  const out = new Map<string, ImportedBinding>();
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier) || !stmt.importClause || stmt.importClause.isTypeOnly) continue;
    const resolved = resolveImport(path, stmt.moduleSpecifier.text, allPaths, aliases);
    if (!resolved) continue;
    const clause = stmt.importClause;
    if (clause.name) out.set(clause.name.text, { path: resolved, name: "default" });
    if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const el of clause.namedBindings.elements) {
        if (!el.isTypeOnly) out.set(el.name.text, { path: resolved, name: (el.propertyName ?? el.name).text });
      }
    }
    if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
      out.set(clause.namedBindings.name.text, { path: resolved, name: NAMESPACE_IMPORT });
    }
  }
  return out;
}

// Local name -> (module, exported name) for every value re-exported through a BARREL:
// `export { x [as y] } from "./m"`. #1500's real chain resolves `getAuthGuards` through
// `~/auth/index.server`, which does not declare it — it re-exports it from `./context.server`. A
// wildcard (`export * from`) or a re-export with no module specifier is out of scope: this can only
// ever SUPPRESS, so an unevaluated form leaves the finding standing rather than guessing.
function collectReExports(sf: ts.SourceFile, path: string, allPaths: Set<string>, aliases: PathAlias[]): Map<string, ImportedBinding> {
  const out = new Map<string, ImportedBinding>();
  for (const stmt of sf.statements) {
    if (!ts.isExportDeclaration(stmt) || stmt.isTypeOnly || !stmt.moduleSpecifier || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
    if (!stmt.exportClause || !ts.isNamedExports(stmt.exportClause)) continue;
    const resolved = resolveImport(path, stmt.moduleSpecifier.text, allPaths, aliases);
    if (!resolved) continue;
    for (const el of stmt.exportClause.elements) {
      if (!el.isTypeOnly) out.set(el.name.text, { path: resolved, name: (el.propertyName ?? el.name).text });
    }
  }
  return out;
}

// #1462: a gate is also reachable through a DYNAMIC import. TanStack/tanstack.com's `requireAdmin`
// reaches its real check through `const { getAuthenticatedUser } = await import('./auth.server-
// helpers')`; neither collectDeclaredFunctions nor collectValueImports (top-level
// `ImportDeclaration`s only) can see a binding introduced that way, so the hop-2 lookup failed and
// all 12 of that target's `missing authorization check` rows stood — every one a false positive
// (MEASURED 2026-07-28 by `detect-static` over the pin; the 12 were read against source).
//
// STRING-LITERAL SPECIFIERS ONLY, and that is the correct shape rather than a shortcut: this pass
// can only ever SUPPRESS, so a specifier it does not evaluate (`await import(spec)`, a computed
// template, a package name outside the loaded source set) leaves the finding standing. Reading
// "we could not see the module" as "there is a gate in it" is the failure mode #1263's
// suppression-only constraint exists to prevent. Both unresolvable shapes are planted as positives
// in the corpus fixture and must still fire.
//
// BOUND, STATED: bindings are collected per FILE, not per enclosing function — a dynamic import
// inside one function makes its names resolvable from any function in the same module. It can only
// suppress, and the shape that would need (two functions in one module binding the same local name,
// one of them to something matching the gate pattern) appears nowhere in this corpus.
function dynamicImportSpecifier(expr: ts.Expression): string | undefined {
  const call = ts.isAwaitExpression(expr) ? expr.expression : expr;
  if (!ts.isCallExpression(call) || call.expression.kind !== ts.SyntaxKind.ImportKeyword) return undefined;
  const arg = call.arguments[0];
  return arg && ts.isStringLiteral(arg) ? arg.text : undefined;
}

// #1500: TanStack/tanstack.com's real gate is not a direct `await import("literal")` at the call
// site — it's a HELPER that wraps one: `async function loadAuthServer() { return import('~/auth/
// index.server') }`, then `const { getAuthGuards } = await loadAuthServer()`. Neither the direct
// form above nor collectDeclaredFunctions sees that binding, so `getAuthGuards` (and everything
// reached through it) was unresolvable — one of the two independent causes of all 6 residual
// `M1 — server function missing authorization check` rows (MEASURED 2026-07-28/31, #1500).
//
// NARROW ON PURPOSE: the wrapper's body must be A THIN PASSTHROUGH — nothing but
// `return [await] import("literal")` (an arrow's expression body counts the same way). A wrapper
// that does anything else (env-gates the specifier, memoizes, wraps two imports) is not evaluated,
// and the finding it would have suppressed stays standing — this can only ever SUPPRESS, so an
// unevaluable wrapper shape must fail safe exactly like a computed `import(spec)` does above.
function dynamicImportWrapperSpecifier(fn: ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression): string | undefined {
  const body = fn.body;
  if (!body) return undefined;
  if (!ts.isBlock(body)) return dynamicImportSpecifier(body); // arrow expression body: `() => import("m")`
  const real = body.statements.filter((s) => !ts.isEmptyStatement(s));
  const only = real.length === 1 ? real[0] : undefined;
  return only && ts.isReturnStatement(only) && only.expression ? dynamicImportSpecifier(only.expression) : undefined;
}

// Local function name -> the literal specifier it wraps, for every dynamic-import-wrapper function
// DECLARED IN THIS FILE. A wrapper imported from elsewhere is out of scope (one more hop this pass
// does not take) and leaves any finding it would suppress standing.
function collectDynamicImportWrapperSpecifiers(sf: ts.SourceFile): Map<string, string> {
  const out = new Map<string, string>();
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name) {
      const spec = dynamicImportWrapperSpecifier(node);
      if (spec) out.set(node.name.text, spec);
    } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) {
      const spec = dynamicImportWrapperSpecifier(node.initializer);
      if (spec) out.set(node.name.text, spec);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

interface DynamicImports {
  /** `const { x: y } = await import("./m")` — local name -> (module, exported name). */
  named: Map<string, ImportedBinding>;
  /** `const m = await import("./m")` — local namespace name -> module path. */
  namespaces: Map<string, string>;
}

function collectDynamicImports(sf: ts.SourceFile, path: string, allPaths: Set<string>, aliases: PathAlias[]): DynamicImports {
  const named = new Map<string, ImportedBinding>();
  const namespaces = new Map<string, string>();
  const wrappers = collectDynamicImportWrapperSpecifiers(sf);
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      let specifier = dynamicImportSpecifier(node.initializer);
      if (specifier === undefined) {
        // #1500: `const { x } = await loadY()` where `loadY` is a wrapper collected above.
        const call = ts.isAwaitExpression(node.initializer) ? node.initializer.expression : node.initializer;
        if (ts.isCallExpression(call) && ts.isIdentifier(call.expression)) specifier = wrappers.get(call.expression.text);
      }
      const resolved = specifier === undefined ? undefined : resolveImport(path, specifier, allPaths, aliases);
      if (resolved) {
        if (ts.isIdentifier(node.name)) {
          namespaces.set(node.name.text, resolved);
        } else if (ts.isObjectBindingPattern(node.name)) {
          for (const el of node.name.elements) {
            if (el.dotDotDotToken || !ts.isIdentifier(el.name)) continue;
            const exported = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
            named.set(el.name.text, { path: resolved, name: exported });
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return { named, namespaces };
}

interface CallSite {
  /** the callee's own name: `ensureMember(x)` and `guards.ensureMember(x)` both yield "ensureMember" */
  name: string;
  /** the receiver of a property-access call — `guards` in `guards.ensureMember(x)` */
  qualifier?: string;
  node: ts.CallExpression;
}

function calledSites(fn: ts.Node): CallSite[] {
  const sites: CallSite[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      if (ts.isIdentifier(callee)) sites.push({ name: callee.text, node });
      else if (ts.isPropertyAccessExpression(callee)) {
        sites.push({ name: callee.name.text, qualifier: ts.isIdentifier(callee.expression) ? callee.expression.text : undefined, node });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return sites;
}

// #1439: matching the auth/validation pattern inside a helper's body says the helper LOOKS at the
// session; it does not say the helper can stop the mutation. Two shapes proved that at review: a
// logging helper whose body calls `getCurrentUser()` for the log line, and `const allowed = await
// canAccess(id)` whose result is never read. Both vouched for an action that enforced nothing.
//
// A helper counts as a gate when it can DENY on its own — it throws, or it calls a framework
// denial (`redirect`/`notFound`/`forbidden`) — or when the CALLER consumes what it returns. The
// consumption test is deliberately generous: only the two shapes that provably discard the result
// (a bare expression statement, and a binding never read again) fail it, so an unfamiliar idiom
// still suppresses.
const DENIAL_CALL = /^(redirect|permanentRedirect|notFound|forbidden|unauthorized)$/;

function canDeny(fn: ts.Node): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isThrowStatement(node)) found = true;
    else if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && DENIAL_CALL.test(node.expression.text)) found = true;
    else ts.forEachChild(node, visit);
  };
  visit(fn);
  return found;
}

/** Whether the action does anything with the call's result. `await f(x);` alone does not. */
function resultIsConsumed(call: ts.CallExpression, action: ts.Node): boolean {
  const value = ts.isAwaitExpression(call.parent) ? call.parent : call;
  const parent = value.parent;
  if (parent === undefined || ts.isExpressionStatement(parent)) return false;
  if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    // Read anywhere else in the action — a branch, an argument, the mutation itself.
    const name = parent.name.text;
    let reads = 0;
    const visit = (node: ts.Node) => {
      if (ts.isIdentifier(node) && node.text === name && node !== parent.name) reads += 1;
      ts.forEachChild(node, visit);
    };
    visit(action);
    return reads > 0;
  }
  return true;
}

// Resolves the action's callees and returns the name of the first one whose own body satisfies
// `pattern` — the gate, recognised without knowing what it is called.
class GateResolver {
  private readonly declared = new Map<string, Map<string, ts.Node>>();
  private readonly imports = new Map<string, Map<string, ImportedBinding>>();
  private readonly dynamic = new Map<string, DynamicImports>();
  private readonly reExports = new Map<string, Map<string, ImportedBinding>>();

  constructor(
    private readonly sources: Map<string, ts.SourceFile>,
    private readonly aliases: PathAlias[],
  ) {}

  private declaredIn(path: string): Map<string, ts.Node> {
    let hit = this.declared.get(path);
    if (!hit) {
      const sf = this.sources.get(path);
      hit = sf ? collectDeclaredFunctions(sf) : new Map();
      this.declared.set(path, hit);
    }
    return hit;
  }

  private importsIn(path: string): Map<string, ImportedBinding> {
    let hit = this.imports.get(path);
    if (!hit) {
      const sf = this.sources.get(path);
      // A static `import { x } from …` wins over a dynamic binding of the same local name: the
      // static one is the module-scope binding, the dynamic one is function-local.
      hit = sf ? new Map([...this.dynamicIn(path).named, ...collectValueImports(sf, path, new Set(this.sources.keys()), this.aliases)]) : new Map();
      this.imports.set(path, hit);
    }
    return hit;
  }

  private dynamicIn(path: string): DynamicImports {
    let hit = this.dynamic.get(path);
    if (!hit) {
      const sf = this.sources.get(path);
      hit = sf ? collectDynamicImports(sf, path, new Set(this.sources.keys()), this.aliases) : { named: new Map(), namespaces: new Map() };
      this.dynamic.set(path, hit);
    }
    return hit;
  }

  private reExportsIn(path: string): Map<string, ImportedBinding> {
    let hit = this.reExports.get(path);
    if (!hit) {
      const sf = this.sources.get(path);
      hit = sf ? collectReExports(sf, path, new Set(this.sources.keys()), this.aliases) : new Map();
      this.reExports.set(path, hit);
    }
    return hit;
  }

  // A name declared in `path` directly, or reached by exactly one hop of `export { name } from
  // "./barrel"` (#1500: `~/auth/index.server` re-exports `getAuthGuards` rather than declaring it).
  // Bounded to one hop on purpose — a barrel re-exporting from another barrel is a shape this pass
  // does not evaluate, and stays unresolvable rather than chasing an unbounded chain.
  private declaredOrReExported(path: string, name: string): { path: string; node: ts.Node } | undefined {
    const direct = this.declaredIn(path).get(name);
    if (direct) return { path, node: direct };
    const reExported = this.reExportsIn(path).get(name);
    if (!reExported) return undefined;
    const target = this.declaredIn(reExported.path).get(reExported.name);
    return target ? { path: reExported.path, node: target } : undefined;
  }

  private resolve(path: string, site: CallSite): { path: string; node: ts.Node } | undefined {
    if (site.qualifier !== undefined) {
      // #1462: a namespace bound by a dynamic import — `const m = await import("./auth")` — resolves
      // against THAT module, exactly like the static namespace form below.
      const dynamic = this.dynamicIn(path).namespaces.get(site.qualifier);
      if (dynamic !== undefined) return this.declaredOrReExported(dynamic, site.name);
      // `guards.ensureMember(…)` — only a namespace import resolves; a method on a runtime object
      // (`supabase.auth.getUser()`) has no declaration in this tree and stays unresolvable.
      const ns = this.importsIn(path).get(site.qualifier);
      if (ns?.name !== NAMESPACE_IMPORT) return undefined;
      return this.declaredOrReExported(ns.path, site.name);
    }
    const local = this.declaredIn(path).get(site.name);
    if (local) return { path, node: local };
    const imported = this.importsIn(path).get(site.name);
    if (!imported || imported.name === NAMESPACE_IMPORT) return undefined;
    return this.declaredOrReExported(imported.path, imported.name);
  }

  // The first callee, within GATE_DEPTH hops, whose own declaration satisfies `matches`.
  private firstCallee(
    path: string,
    fn: ts.Node,
    matches: (sf: ts.SourceFile, node: ts.Node, site: CallSite, caller: ts.Node) => boolean,
    depth: number,
    seen: Set<string>,
  ): string | undefined {
    if (depth <= 0) return undefined;
    for (const site of calledSites(fn)) {
      const key = `${path}#${site.qualifier ?? ""}#${site.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const hit = this.resolve(path, site);
      if (!hit || hit.node === fn) continue; // a same-named self-call resolves to the frame already open one level up — re-testing it can never match (we only got here because it didn't) and would burn a depth level and pre-seed `seen` with names the OUTER loop has not reached yet, starving a real hop further out. #1500's tanstack chain hits this exactly: `requireCapability` calls `getAuthGuards().requireCapability(...)`, an unrelated method that happens to share its enclosing function's own name.
      const sf = this.sources.get(hit.path);
      if (sf && matches(sf, hit.node, site, fn)) return site.name;
      if (this.firstCallee(hit.path, hit.node, matches, depth - 1, seen)) return site.name;
    }
    return undefined;
  }

  gateIn(pattern: RegExp, path: string, fn: ts.Node, depth = GATE_DEPTH, seen = new Set<string>()): string | undefined {
    // #1439: matching the pattern is not enough — the helper must be able to deny, or the caller
    // must consume what it returns. A logger that reads the session, and a boolean nobody looks
    // at, are not gates.
    return this.firstCallee(
      path,
      fn,
      (sf, node, site, caller) => pattern.test(stripLiteralsAndComments(sf, node)) && (canDeny(node) || resultIsConsumed(site.node, caller)),
      depth,
      seen,
    );
  }

  // #1461: the first resolvable callee that can stop its caller. `canDeny` (#1439) already means
  // exactly that — a `throw`, or a redirect()/notFound()/forbidden() call — so it is reused here
  // rather than re-implemented. Deliberately not "the callee contains a return": a return leaves
  // only THAT helper and control carries straight on to the next query, so counting it would
  // suppress every pair whose intervening statement calls any value-returning helper.
  throwingCallee(path: string, stmt: ts.Node): string | undefined {
    return this.firstCallee(path, stmt, (_sf, node) => canDeny(node), GATE_DEPTH, new Set<string>());
  }
}

function detectServerActionAuthAndValidation(
  sources: Map<string, ts.SourceFile>,
  nextId: NextId,
  subsumedNoAuthActions: ReadonlySet<ts.Node>,
  mutationsFor: (path: string, sf: ts.SourceFile) => ServerMutation[],
  noun: string,
  aliases: PathAlias[],
): Finding[] {
  const findings: Finding[] = [];
  const gates = new GateResolver(sources, aliases);
  for (const [path, sf] of sources) {
    for (const action of mutationsFor(path, sf)) {
      const text = stripLiteralsAndComments(sf, action.node);
      if (!isDbMutationChain(text)) continue; // scope to mutating actions per the brief

      // The client-supplied-owner-id detector already fired on this no-auth action with a
      // strictly more specific finding (its evidence carries the no-auth fact) — one code
      // defect, one finding (#465).
      if (!AUTH_PATTERN.test(text) && !gates.gateIn(AUTH_PATTERN, path, action.node) && !subsumedNoAuthActions.has(action.node)) {
        findings.push(
          makeFinding(nextId, {
            title: `${noun} \`${action.name}\` mutates data with no visible auth check`,
            severity: "High",
            confidence: "Likely",
            category: "Security",
            // Routed to the M1 authorization/client-input-trust class (#221), not scored as
            // M9 rendering — a server mutation with no auth check is a broken-function-level-authz
            // finding, the same class as the other three instances #221 catalogs.
            taxonomy: `M1 — ${noun} missing authorization check`,
            location: loc(path, sf, action.node),
            evidence: `\`${action.name}\` is a ${noun} that calls insert/update/upsert/delete/rpc with no session/authority check found in its body, and none in any helper it calls that this pass could resolve to a declaration in the scanned tree (#1263 — a gate reached only through a package import stays invisible here).`,
            impact: `${noun}s are public POST endpoints — invocable directly with a crafted request regardless of which page normally calls them. Anyone can trigger this mutation.`,
            fix: "Verify the caller's session/tenant before the DB call (e.g. `auth.getUser()` + a tenant-scoped `.eq(...)`, or a shared `requireUser()`/`assertPermission()` gate).",
            value: 5,
            ease: 3,
            safety: 4,
          }),
        );
      }

      if (!VALIDATION_PATTERN.test(text) && !gates.gateIn(VALIDATION_PATTERN, path, action.node)) {
        findings.push(
          makeFinding(nextId, {
            title: `${noun} \`${action.name}\` has no input schema validation`,
            severity: "High",
            confidence: "Likely",
            category: "Security",
            taxonomy: `M9 — ${noun} missing input validation`,
            location: loc(path, sf, action.node),
            evidence: `\`${action.name}\` reads its arguments/formData straight into a DB mutation with no Zod/valibot (or similar) \`.parse\`/\`.safeParse\` call found in its body, and none in any helper it calls that this pass could resolve to a declaration in the scanned tree (#1263 — a validator reached only through a package import stays invisible here).`,
            impact: "Unvalidated input is type-unsafe and injectable, and any id/tenant field on it is trusted from the client.",
            fix: "Parse the action's input through a schema (Zod/valibot) before using any field in the DB call.",
            value: 4,
            ease: 3,
            safety: 4,
          }),
        );
      }
    }
  }
  return findings;
}

// --- Unsafe / missing cache config [MED] — best-effort ---------------------

function detectUnsafeCacheConfig(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (leadingDirective(sf) !== undefined) continue;
    // page/layout only — these are what the Full Route Cache actually treats
    // as static/ISR candidates, and the fix text (unstable_cache/"use cache")
    // is the real remediation for them. Route Handlers (route.ts) use a
    // different caching surface (route segment config / Cache-Control) and,
    // on the ATC dogfood, were 225 of 230 hits here — almost all admin or
    // mutation endpoints that were never cache candidates (#181).
    if (!/\/(page|layout)\.[cm]?[jt]sx?$/.test(path)) continue;
    const text = sf.text;
    if (!(/\.from\(\s*["'`]/.test(text) && /\.select\(/.test(text))) continue;
    if (CACHE_SIGNAL_PATTERN.test(text)) continue;
    // Reading a dynamic API (cookies()/headers()/searchParams/...) makes the
    // route dynamic by construction — "no cache config" is expected there,
    // not a smell. detectAccidentalDynamicRendering already flags the read
    // itself; don't also flag the file for lacking a cache config it can't
    // meaningfully have.
    if (readsDynamicApi(sf)) continue;
    // #231: every real-world hit here was an auth page, a theme cookie, or a token-gated
    // viewer — legitimately per-request, never a static/ISR candidate. Suppress when the page
    // itself checks the caller's session/auth, or sits on a login/reset/invite/callback route.
    if (AUTH_PATTERN.test(text)) continue;
    if (AUTH_OR_TOKEN_ROUTE_SEGMENT.test(path)) continue;

    findings.push(
      makeFinding(nextId, {
        title: `Data-fetching route with no cache configuration`,
        severity: "Medium",
        confidence: "Review",
        category: "Performance",
        taxonomy: "M9 — Unsafe/missing cache config",
        location: path,
        evidence: `${path} queries the DB with no \`unstable_cache\`, \`"use cache"\`, or \`revalidate\` found anywhere in the file — best-effort file-level heuristic, not proof the fetch is uncached (data may be cached upstream).`,
        impact: "Every request may re-run the query, or (the opposite failure) an ad-hoc cache could bleed per-tenant data across users if added without a per-key tag.",
        fix: "Confirm intentionally: either wrap the read in `unstable_cache`/`\"use cache\"` with an explicit tag, or mark the route dynamic on purpose.",
        value: 3,
        ease: 3,
        safety: 4,
      }),
    );
  }
  return findings;
}

// --- Cross-user cache bleed [HIGH] (#1051) ----------------------------------
//
// briefs/audit-modules.md requires M9 to flag BOTH cache failure modes: a missing cache config AND
// a cache configuration that lets one user's rendered content bleed to another. Only the first was
// implemented — and detectUnsafeCacheConfig above treats ANY cache signal as evidence of
// correctness (CACHE_SIGNAL_PATTERN → `continue`) and any auth read as evidence the route is
// per-request. So the bleed case was suppressed by the very directive that causes it and the scan
// reported clean. This check is the other half; the two are complementary, not alternatives.
//
// Three statically adjudicable shapes:
//   (a) `unstable_cache(cb, keyParts, opts)` whose cached work is per-user — it takes a user/tenant
//       identifier, or reads the caller's session inside the cached function — while the cache
//       IDENTITY (key parts + `tags`) carries no per-user component. One global entry: whoever
//       populates it first has their rows served to every other user.
//   (b) a `"use cache"` scope that resolves the caller's identity INSIDE itself. That scope is keyed
//       on its ARGUMENTS, so the identity arriving as a parameter is the CORRECT shape (and is not
//       flagged); an auth read within the cached body is invisible to the key, and bleeds.
//   (c) an auth-gated Route Handler / middleware returning `Cache-Control: public` or `s-maxage`
//       with no `private`/`no-store` — the shared CDN caches an authenticated response.
// Unlike the three Supabase-shaped data-layer checks this one keys on the auth + cache signals
// rather than `.from().select()`, so it runs on any data layer.

// A parameter name that declares the cached result varies per identity (`userId`, `tenantId`, `org`).
const PER_USER_PARAM = /^(user|owner|tenant|account|org|organisation|organization|customer|workspace|member|profile|viewer)(_?id)?$/i;
// Deliberately loose: this runs over the cache KEY, where a match is evidence of CORRECT per-user
// scoping. Matching too readily suppresses a finding, which is the safe direction for precision.
const PER_USER_KEY_TOKEN = /user|owner|tenant|account|org|member|customer|workspace|profile|viewer|session/i;
const CACHE_CONTROL_HEADER = /["'`]cache-control["'`]\s*[:,]\s*["'`]([^"'`]+)["'`]/gi;
const SHARED_CACHE_VALUE = /\b(public|s-maxage)\b/i;
const PRIVATE_CACHE_VALUE = /\b(private|no-store|no-cache)\b/i;
const RESPONSE_BUILDING_FILE = /(^|\/)(route\.[cm]?[jt]sx?|middleware\.[cm]?[jt]sx?)$/;

function unstableCacheCalls(sf: ts.SourceFile): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const name = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : undefined;
      if (name === "unstable_cache") out.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

function hasUseCacheDirective(stmts: readonly ts.Statement[]): boolean {
  const first = stmts[0];
  return !!first && ts.isExpressionStatement(first) && ts.isStringLiteral(first.expression) && first.expression.text === "use cache";
}

// Scopes rendered by the Next `"use cache"` directive — the whole module, or an individual function.
function useCacheScopes(sf: ts.SourceFile): ts.Node[] {
  if (hasUseCacheDirective(sf.statements)) return [sf];
  const out: ts.Node[] = [];
  const visit = (node: ts.Node) => {
    const body =
      ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node) ? node.body : undefined;
    if (body && ts.isBlock(body) && hasUseCacheDirective(body.statements)) out.push(node);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

// Why this cached callback's result differs per user, or undefined if nothing says it does.
function perUserCachedWork(cb: ts.FunctionExpression | ts.ArrowFunction, sf: ts.SourceFile): string | undefined {
  const param = cb.parameters.map((p) => p.name).find((n): n is ts.Identifier => ts.isIdentifier(n) && PER_USER_PARAM.test(n.text));
  if (param) return `takes the per-user argument \`${param.text}\``;
  if (AUTH_PATTERN.test(cb.getText(sf))) return "reads the caller's session inside the cached function";
  return undefined;
}

function detectCrossUserCacheBleed(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const opaque: string[] = [];

  for (const [path, sf] of sources) {
    if (leadingDirective(sf) === "use client") continue;

    for (const call of unstableCacheCalls(sf)) {
      const cb = call.arguments[0];
      if (!cb || !(ts.isArrowFunction(cb) || ts.isFunctionExpression(cb))) {
        if (cb) opaque.push(loc(path, sf, call));
        continue;
      }
      const why = perUserCachedWork(cb, sf);
      if (!why) continue;
      const identity = call.arguments
        .slice(1)
        .map((a) => a.getText(sf))
        .join(" ");
      if (PER_USER_KEY_TOKEN.test(identity)) continue;

      findings.push(
        makeFinding(nextId, {
          title: `Per-user data cached under a shared cache key`,
          severity: "High",
          confidence: "Review",
          category: "Security",
          taxonomy: "M9 — Cross-user cache bleed",
          location: loc(path, sf, call),
          evidence: `This \`unstable_cache(...)\` ${why}, but its cache key/tags (${identity || "none supplied"}) contain no per-user component — every caller reads and writes the same entry.`,
          impact: "One user's rows are served to every other user from the Data Cache: whoever populates the entry first defines what everyone sees, for the whole revalidate window. Cross-user data disclosure, not a stale-content bug.",
          fix: "Put the identity in the cache key AND the tags — `unstable_cache(fn, [\"orders\", userId], { tags: [`orders-${userId}`] })` — or don't cache a per-user read at all.",
          value: 5,
          ease: 4,
          safety: 4,
        }),
      );
    }

    for (const scope of useCacheScopes(sf)) {
      if (!AUTH_PATTERN.test(scope.getText(sf))) continue;
      findings.push(
        makeFinding(nextId, {
          title: `\`"use cache"\` scope reads the caller's session`,
          severity: "High",
          confidence: "Review",
          category: "Security",
          taxonomy: "M9 — Cross-user cache bleed",
          location: loc(path, sf, scope),
          evidence: `This \`"use cache"\` scope resolves the caller's identity inside the cached function. A cached scope is keyed on its ARGUMENTS, so an identity read within it is invisible to the key — one entry is shared across users.`,
          impact: "The first caller's authenticated result is cached and replayed to every other user for the cache lifetime — cross-user data disclosure.",
          fix: "Resolve the session OUTSIDE the cached scope and pass the identity in as an argument (so it becomes part of the key), or drop `\"use cache\"` from this function.",
          value: 5,
          ease: 4,
          safety: 4,
        }),
      );
    }

    if (!RESPONSE_BUILDING_FILE.test(path)) continue;
    if (!AUTH_PATTERN.test(sf.text) && !readsDynamicApi(sf)) continue;
    for (const m of sf.text.matchAll(CACHE_CONTROL_HEADER)) {
      const value = m[1] ?? "";
      if (!SHARED_CACHE_VALUE.test(value) || PRIVATE_CACHE_VALUE.test(value)) continue;
      findings.push(
        makeFinding(nextId, {
          title: `Authenticated response sent with a shared \`Cache-Control\``,
          severity: "High",
          confidence: "Review",
          category: "Security",
          taxonomy: "M9 — Cross-user cache bleed",
          location: path,
          evidence: `${path} resolves the caller's session (or reads cookies/headers) and returns \`Cache-Control: ${value}\` — a shared-cache directive with no \`private\`/\`no-store\`.`,
          impact: "The CDN and any intermediary caches store one user's authenticated response and serve it to the next requester of the same URL — the textbook cross-user cache bleed.",
          fix: "Send `Cache-Control: private, no-store` (or `no-cache`) on any authenticated response; keep `public`/`s-maxage` for genuinely anonymous ones.",
          value: 5,
          ease: 5,
          safety: 5,
        }),
      );
    }
  }

  // The one shape this check cannot adjudicate: `unstable_cache(importedFn, …)`, where the cached
  // work lives in another module and neither its session reads nor its per-user parameters are
  // visible here. Disclosed rather than dropped, so its absence isn't read as "assessed and clean".
  if (opaque.length) {
    findings.push({
      id: nextId(),
      title: `M9 not assessed — cross-user cache bleed on ${opaque.length} \`unstable_cache\` call(s) with a non-inline callback`,
      severity: "Info",
      confidence: "N/A",
      category: "Security",
      taxonomy: "M9 — Cross-user cache bleed — not assessed",
      location: opaque.join(", "),
      status: "Open",
      evidence: `These \`unstable_cache(...)\` calls pass a callback the file does not define inline, so whether the cached work is per-user is not decidable from this file. ASSUMED-undecidable at file scope; falsifiable by re-running this detector once it resolves imported callbacks across modules.`,
      impact: "These cache sites were NOT assessed for cross-user bleed. Recorded explicitly so the absence reads as 'not assessed here', not 'assessed and clean' — the fail-loud coverage guard.",
      fix: "None — informational. Check by hand that each cached function's key includes the identity its result depends on.",
      value: 1,
      ease: 5,
      safety: 5,
      precisionTier: "high",
    });
  }
  return findings;
}

// --- Data-fetching waterfalls [MED] — best-effort ---------------------------

// All local binding names introduced by a declaration (handles plain
// identifiers and `{ data: x }`-style destructuring) — used to check whether
// a later statement actually depends on this one, not just to display it.
function boundNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  if (ts.isObjectBindingPattern(name)) {
    return name.elements.filter((el): el is ts.BindingElement & { name: ts.Identifier } => ts.isIdentifier(el.name)).map((el) => el.name.text);
  }
  return [];
}

interface AwaitedDbDeclaration {
  displayName: string;
  boundNames: string[];
  node: ts.VariableStatement;
  text: string;
  /** Index in the enclosing block — the statements between two queries carry the dependence. */
  index: number;
}

function findAwaitedDbDeclarations(block: ts.Block, sf: ts.SourceFile): AwaitedDbDeclaration[] {
  const out: AwaitedDbDeclaration[] = [];
  block.statements.forEach((stmt, index) => {
    if (!ts.isVariableStatement(stmt) || stmt.declarationList.declarations.length !== 1) return;
    const decl = stmt.declarationList.declarations[0];
    if (!decl?.initializer || !ts.isAwaitExpression(decl.initializer)) return;
    const call = decl.initializer.expression;
    if (!ts.isCallExpression(call) || !isDbQueryChain(call)) return;
    const names = boundNames(decl.name);
    out.push({ displayName: names[0] ?? decl.name.getText(sf), boundNames: names, node: stmt, text: stmt.getText(sf), index });
  });
  return out;
}

// #1344: the dependence between two queries is often laundered through an intermediate binding —
// `const ids = [...new Set(memberships.map(m => m.organizationId))]` sits between the two, and the
// second query filters on `ids`, never on `memberships`. Comparing only the FIRST query's bound
// names against the second statement's text called that pair independent and told the client to
// run in parallel two queries where the second cannot even be built without the first's result
// (MEASURED on inbox-zero apps/web/utils/organizations/ownership.ts:43, 2026-07-27). So the taint
// propagates forward through every intervening statement that reads it — the same one-hop-alias
// reasoning collectRawRowNames already applies to row leaks, generalised to any number of hops.
function mentionsIdentifier(text: string, name: string): boolean {
  // Whole-identifier match: propagating taint on a bare substring lets a short binding like `t`
  // mark every later statement as dependent and silence the whole class.
  return new RegExp(`(?<![A-Za-z0-9_$])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![A-Za-z0-9_$])`).test(text);
}

// #1292: a guard on the FIRST result that can leave the function before the second query runs —
// `if (!company) return null`, `if (error) throw new Error(…)`, `if (!row) notFound()` — is a
// dependency even though no value flows. `Promise.all` hoists the second query above the guard, so
// it executes on inputs the sequential code never reaches: on carbon one such pair issues a
// compensating DELETE on the failure path. MEASURED on the pinned carbon clone 2026-07-28 (see the
// PR): 40 waterfall rows before, and the guarded shape is the largest remaining sub-class.
//
// What a guard DOES to control flow decides whether the pair is sequential, and there are two
// answers, not one (#1438/#1441):
//
//   DIVERTS — a `return`, or a `break`/`continue` bound to a loop OUTSIDE this statement: the
//     second query never runs on that path. A real dependency.
//   ABORTS  — a `throw` only (including Remix's `throw redirect(…)`): the request ends. Nothing
//     downstream observes the second query's result, so hoisting a READ above it costs one wasted
//     round-trip on the failure path and changes no behaviour. Not a dependency, provided BOTH
//     queries are reads — see mutatingChain.
//
// #1438: the old test counted ANY `Break`/`Continue` node. One belonging to a `switch` or an inner
// loop INSIDE the intervening statement does not leave the function and does not skip the second
// query, so it suppressed a genuinely parallelisable pair. A labelled `break outer` is only local
// when `outer:` is itself declared inside this statement.
type GuardEffect = "none" | "aborts" | "diverts";

function guardEffect(stmt: ts.Statement): GuardEffect {
  let diverts = false;
  let aborts = false;
  const visit = (node: ts.Node, loopDepth: number, labels: ReadonlySet<string>) => {
    if (diverts) return;
    if (ts.isReturnStatement(node)) diverts = true;
    else if (ts.isThrowStatement(node)) aborts = true;
    else if (ts.isBreakStatement(node) || ts.isContinueStatement(node)) {
      const label = node.label?.text;
      if (label === undefined ? loopDepth === 0 : !labels.has(label)) diverts = true;
    }
    // A nested function's own `return` returns from THAT function, not from this one.
    if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)) return;
    const opensLoop =
      ts.isSwitchStatement(node) || ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node);
    const nextLabels = ts.isLabeledStatement(node) ? new Set([...labels, node.label.text]) : labels;
    ts.forEachChild(node, (c) => visit(c, loopDepth + (opensLoop ? 1 : 0), nextLabels));
  };
  visit(stmt, 0, new Set());
  return diverts ? "diverts" : aborts ? "aborts" : "none";
}

// #1461: #1292's exit test is SYNTACTIC — it reads a `return`/`throw`/`break` written in the
// intervening statement itself, so an exit that happens INSIDE a called guard is invisible. On
// carbon's pin, `await requireUnlocked({ isLocked: isMaintenanceDispatchLocked(dispatchForLock.data
// ?.status), … })` reads the first result and does stop the function, but its `throw redirect(…)`
// lives one hop out. Resolving the callee and re-testing (the #1263 move) classifies it the SAME
// WAY the identical exit written inline would be classified — an abort, not a divert — so it flows
// through #1438's relaxation and #1441's write rule unchanged rather than getting its own carve-out.
// #1441: `isDbQueryChain` accepts `.from("receipt").update({…}).select("id")` — a WRITE. Hoisting
// one of those above an aborting guard is exactly the bug the #1292 suppression exists to prevent
// (MEASURED on the pinned carbon clone 2026-07-28: apps/erp/app/routes/x+/receipt+/$receiptId.post
// .tsx:172 flips a receipt to Pending under a `throw redirect` guard that rejects voided receipts).
// So the abort relaxation applies only when NEITHER query mutates.
function mutatingChain(decl: AwaitedDbDeclaration): boolean {
  return MUTATION_PATTERN.test(decl.text);
}

/** Why a pair is not reported, or undefined when it is independent and fires. */
type PairDependency = "dataflow" | "guard-diverts" | "guard-aborts-over-write";

interface PairVerdict {
  reason: PairDependency | undefined;
  // #1484: an aborting guard was seen and excused ONLY because both statements are reads (#1441's
  // relaxation) — true even though the pair still fires as independent. Lets the caller disclose
  // the error-PRECEDENCE change the relaxation makes: sequentially the guard's own throw always
  // wins (the second query never runs); under Promise.all a rejection from the second query can
  // surface first, and on a data layer that REJECTS on error (Prisma, a raw driver) rather than
  // returning an error object (Supabase's `.error`), the caller can see a different error.
  abortRelaxedForReads: boolean;
}

function dependsOnPriorQuery(
  block: ts.Block,
  sf: ts.SourceFile,
  cur: AwaitedDbDeclaration,
  next: AwaitedDbDeclaration,
  path: string,
  gates: GateResolver,
): PairVerdict {
  // The direct test keeps its original substring form so this change can only ever SUPPRESS a pair,
  // never make a previously-suppressed one fire; the names reached by propagation are matched as
  // whole identifiers, so a short intermediate binding cannot swallow the class.
  if (cur.boundNames.some((n) => next.text.includes(n))) return { reason: "dataflow", abortRelaxedForReads: false };
  const eitherWrites = mutatingChain(cur) || mutatingChain(next);
  const tainted = new Set(cur.boundNames);
  const reads = (text: string): boolean => [...tainted].some((n) => mentionsIdentifier(text, n));
  let abortedOverWrite = false;
  let abortRelaxedForReads = false;
  for (let i = cur.index + 1; i < next.index; i++) {
    const stmt = block.statements[i];
    if (stmt === undefined || !reads(stmt.getText(sf))) continue;
    // #1461: an exit inside a resolvable callee counts as the same effect the inline form would
    // have. `canDeny` (#1439) already means exactly "this helper can stop its caller" — a `throw`,
    // or a redirect()/notFound() call — so it is reused rather than re-implemented. Deliberately
    // NOT "the callee contains a return": a return leaves only THAT helper and control carries on
    // to the next query. carbon's own sibling guards make the distinction concrete —
    // `requireUnlocked` ends in `throw redirect(…)`, while `requireUnlockedBulk` RETURNS an error
    // object and its callers write `if (lockedError) return lockedError;`, which guardEffect
    // already sees inline.
    const effect = guardEffect(stmt) === "none" && gates.throwingCallee(path, stmt) !== undefined ? "aborts" : guardEffect(stmt);
    if (effect === "diverts") return { reason: "guard-diverts", abortRelaxedForReads: false }; // a guard on the first result — reordering changes behaviour
    // An aborting guard over a write stays a dependency, but the walk continues: a LATER statement
    // may divert, or launder the first result into a binding the second query reads, and either of
    // those is the stronger reason to suppress. Returning here would hide it (MEASURED 2026-07-28:
    // 3 of the 13 abort-guarded pairs on the pinned corpus are caught by a later statement).
    if (effect === "aborts") {
      if (eitherWrites) abortedOverWrite = true;
      else abortRelaxedForReads = true;
    }
    if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) for (const n of boundNames(d.name)) tainted.add(n);
    }
  }
  if (reads(next.text)) return { reason: "dataflow", abortRelaxedForReads: false };
  return { reason: abortedOverWrite ? "guard-aborts-over-write" : undefined, abortRelaxedForReads };
}

// #1081: how many additional independent-pair locations a waterfall finding cites by name — the
// pair count itself is always exact, this only bounds how long the evidence string gets.
const MAX_EXTRA_PAIRS_SHOWN = 4;

function detectDataFetchingWaterfalls(
  sources: Map<string, ts.SourceFile>,
  nextId: NextId,
  isClientContext: (sf: ts.SourceFile) => boolean = (sf) => leadingDirective(sf) === "use client",
  aliases: PathAlias[] = [],
): Finding[] {
  const findings: Finding[] = [];
  let pairsExamined = 0;
  let excludedByDivertingGuard = 0;
  let excludedByAbortOverWrite = 0;
  const gates = new GateResolver(sources, aliases);
  for (const [path, sf] of sources) {
    if (isClientContext(sf)) continue;

    const visit = (node: ts.Node) => {
      if ((ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)) && node.body && ts.isBlock(node.body)) {
        const decls = findAwaitedDbDeclarations(node.body, sf);
        // #1081: collect EVERY independent pair in this function instead of stopping at the first —
        // one finding per function is still the right amount of signal (the fix, "wrap the whole
        // function's queries in Promise.all", already covers every pair), but the dropped pairs need
        // to survive into the evidence rather than vanish with no count.
        const independentPairs: { cur: AwaitedDbDeclaration; next: AwaitedDbDeclaration; abortRelaxedForReads: boolean }[] = [];
        for (let i = 0; i < decls.length - 1; i++) {
          const cur = decls[i];
          const next = decls[i + 1];
          if (!cur || !next) continue;
          pairsExamined += 1;
          // depends on the prior result, directly or through an intermediate — legitimately sequential
          const verdict = dependsOnPriorQuery(node.body, sf, cur, next, path, gates);
          if (verdict.reason === "guard-diverts") excludedByDivertingGuard += 1;
          if (verdict.reason === "guard-aborts-over-write") excludedByAbortOverWrite += 1;
          if (verdict.reason !== undefined) continue;
          independentPairs.push({ cur, next, abortRelaxedForReads: verdict.abortRelaxedForReads });
        }
        if (independentPairs.length > 0) {
          const first = independentPairs[0]!;
          const extraPairs = independentPairs.slice(1, 1 + MAX_EXTRA_PAIRS_SHOWN).map((p) => `\`${p.cur.displayName}\`/\`${p.next.displayName}\` (${loc(path, sf, p.next.node)})`);
          const overflow = independentPairs.length > 1 + MAX_EXTRA_PAIRS_SHOWN ? `, +${independentPairs.length - 1 - MAX_EXTRA_PAIRS_SHOWN} more` : "";
          const countNote =
            independentPairs.length > 1
              ? ` (first of ${independentPairs.length} such pairs in this function; the rest: ${extraPairs.join(", ")}${overflow})`
              : "";
          // #1484: the FIRST pair's own status decides whether the error-precedence caveat is owed
          // — it is the pair this finding's own location/evidence names, so a caveat about the OTHER
          // pairs in countNote would be citing evidence not present in the finding's own text.
          const errorPrecedenceCaveat = first.abortRelaxedForReads
            ? " An error-only guard between them was excused here because both statements read (#1441) — sequentially that guard's own error always surfaces first; under `Promise.all` a rejection from the second query can surface instead, which matters on a data layer that REJECTS on error (Prisma, a raw driver) rather than returning an error object (Supabase's `.error`)."
            : "";
          findings.push(
            makeFinding(nextId, {
              title: `Sequential DB queries with no visible dependency could run in parallel`,
              severity: "Medium",
              confidence: "Review",
              category: "Performance",
              taxonomy: "M9 — Data-fetching waterfall",
              location: loc(path, sf, first.next.node),
              // #1292: the old wording asserted "neither's query depends on the other's result" — a
              // claim about the code this check never established. What it establishes is narrower:
              // no name bound by the first (or derived from it through the intervening statements)
              // is read by the second, and nothing between them guards on the first. Say that, plus
              // the bound on what the check reads, rather than asserting independence and then
              // recommending a reorder that would break the code if the assertion is wrong.
              evidence: `\`${first.cur.displayName}\` (${loc(path, sf, first.cur.node)}) and \`${first.next.displayName}\` (${loc(path, sf, first.next.node)}) are awaited one after the other, and no dataflow from the first into the second was found — the second's query does not read the first's binding or anything derived from it in this block, and no guard between them exits on the first's result. A dependency carried outside this block (through shared mutable state, a side effect, or a helper call) would not be visible to this check.${countNote}${errorPrecedenceCaveat}`,
              impact: "Each await that does not need the previous result serializes a network round-trip that could run concurrently, adding latency (and, compounded across requests, DB load) on every render.",
              fix: first.abortRelaxedForReads
                ? `Confirm the two are order-independent, then combine into \`Promise.all([...])\` (or a single joined query/RPC) so the round-trips overlap. On a rejecting data layer, also confirm the guard's own error is still what the caller sees — e.g. use \`Promise.allSettled\` and surface the guard's error explicitly rather than whichever promise rejects first.`
                : `Confirm the two are order-independent, then combine into \`Promise.all([...])\` (or a single joined query/RPC) so the round-trips overlap.`,
              value: 3,
              ease: 4,
              safety: 4,
            }),
          );
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return [...findings, ...waterfallScopeNote(nextId, pairsExamined, excludedByDivertingGuard, excludedByAbortOverWrite)];
}

// The disclosure half of #1292 (#1441). The guard rule above is a deliberate precision trade: a
// whole class of adjacent-query pair is set aside by policy, and until now nothing in the
// deliverable said so. On the pinned mvp-boilerplate clone that took the target's only counted M9
// finding away and left a report a client reads as a clean M9 result — the exact shape CLAUDE.md
// names as worse than a wrong status. The class is now COUNTED on every target that has adjacent
// query pairs at all, so a zero-finding M9 waterfall result carries its own population.
function waterfallScopeNote(nextId: NextId, pairsExamined: number, diverted: number, abortedOverWrite: number): Finding[] {
  const excluded = diverted + abortedOverWrite;
  // Nothing was set aside — there is no limitation to disclose, and a "0 excluded" row on every
  // target would dilute the family into a status line.
  if (excluded === 0) return [];
  return [
    {
      id: nextId(),
      title: `M9 partially assessed — data-fetching waterfall (${excluded} of ${pairsExamined} adjacent query pair${pairsExamined === 1 ? "" : "s"} excluded by policy)`,
      severity: "Info",
      confidence: "N/A",
      category: "Performance",
      taxonomy: "M9 — Data-fetching waterfall — scope",
      location: "(whole target)",
      status: "Open",
      evidence: `${pairsExamined} adjacent awaited-query pair${pairsExamined === 1 ? " was" : "s were"} examined for parallelisability. ${excluded} ${excluded === 1 ? "was EXCLUDED BY POLICY and is" : "were EXCLUDED BY POLICY and are"} therefore absent from the findings above, in two classes: (1) ${diverted} pair${diverted === 1 ? " is" : "s are"} separated by a guard on the first result that can leave the function — a \`return\`, or a \`break\`/\`continue\` bound to an enclosing loop. \`Promise.all\` hoists the second query above that guard, so it would execute on requests the sequential code never reaches; on this corpus such a pair has issued a duplicate invitation, a compensating DELETE and an update on an unverified row, so the class is suppressed rather than reported. (2) ${abortedOverWrite} pair${abortedOverWrite === 1 ? " is" : "s are"} separated by an error-only guard (a \`throw\`, including \`throw redirect(…)\`) where one of the two statements WRITES — the read-only case is reported normally, but hoisting a write above its guard is a behaviour change, not a latency win. Neither class was judged individually: each is set aside as a whole.`,
      impact: "These pairs were NOT assessed for parallelisability — the trade buys precision on a Review-tier performance class at a known cost in recall. Recorded with its population so a zero-finding waterfall result reads as 'a class was set aside', never as 'nothing to find here' — the fail-loud coverage guard.",
      fix: "None — informational. To recover the excluded pairs by hand, look for two adjacent awaited queries with a guard between them: where the guard only aborts the request and both statements are reads, `Promise.all` is usually safe.",
      value: 1,
      ease: 5,
      safety: 5,
      precisionTier: "high",
    },
  ];
}

// --- Accidental dynamic rendering [MED] — best-effort -----------------------

function findDefaultExportFunction(sf: ts.SourceFile): ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression | undefined {
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword)) {
      return stmt;
    }
    if (ts.isExportAssignment(stmt) && (ts.isArrowFunction(stmt.expression) || ts.isFunctionExpression(stmt.expression))) {
      return stmt.expression;
    }
  }
  return undefined;
}

function findSearchParamsParamName(fn: ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression): string | undefined {
  const param = fn.parameters[0];
  if (!param || !ts.isObjectBindingPattern(param.name)) return undefined;
  for (const el of param.name.elements) {
    const propName = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : ts.isIdentifier(el.name) ? el.name.text : undefined;
    if (propName === "searchParams" && ts.isIdentifier(el.name)) return el.name.text;
  }
  return undefined;
}

// True if `name` is read from directly (property/element access, awaited, or
// destructured) rather than merely forwarded whole as a prop/argument.
function isReadDirectly(root: ts.Node, sf: ts.SourceFile, name: string): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name) found = true;
    else if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name) found = true;
    else if (ts.isAwaitExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name) found = true;
    else if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.initializer &&
      ((ts.isIdentifier(node.initializer) && node.initializer.text === name) ||
        (ts.isAwaitExpression(node.initializer) && ts.isIdentifier(node.initializer.expression) && node.initializer.expression.text === name))
    ) {
      found = true;
    }
    if (!found) ts.forEachChild(node, visit);
  };
  visit(root);
  return found;
}

function findDynamicApiCall(sf: ts.SourceFile): ts.CallExpression | undefined {
  let hit: ts.CallExpression | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && DYNAMIC_API_PATTERN.test(node.expression.text)) {
      hit = node;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return hit;
}

// True if the file reads any API that forces dynamic rendering by itself
// (cookies()/headers()/noStore()/unstable_noStore(), or a top-level
// `searchParams` read) — same primitives detectAccidentalDynamicRendering
// flags below. Shared so detectUnsafeCacheConfig doesn't also flag a route
// that's dynamic by construction for lacking a cache config it can't have.
function readsDynamicApi(sf: ts.SourceFile): boolean {
  if (findDynamicApiCall(sf)) return true;
  const defaultFn = findDefaultExportFunction(sf);
  if (!defaultFn) return false;
  const spName = findSearchParamsParamName(defaultFn);
  if (!spName) return false;
  const body = defaultFn.body;
  return !!body && isReadDirectly(body, sf, spName);
}

function detectAccidentalDynamicRendering(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (leadingDirective(sf) === "use client") continue;
    if (!/\/(page|layout)\.[cm]?[jt]sx?$/.test(path)) continue;

    const dynamicCall = findDynamicApiCall(sf);
    if (dynamicCall) {
      const fnName = (dynamicCall.expression as ts.Identifier).text;
      findings.push(
        makeFinding(nextId, {
          title: `\`${fnName}()\` read in ${/\/layout\.[cm]?[jt]sx?$/.test(path) ? "a layout" : "a page"} — forces dynamic rendering`,
          severity: "Medium",
          confidence: "Review",
          category: "Performance",
          taxonomy: "M9 — Accidental dynamic rendering",
          location: loc(path, sf, dynamicCall),
          evidence: `\`${fnName}()\` is called in this route module, which opts the whole route out of static rendering — every hit re-renders server-side and re-runs its data fetches.`,
          impact: "Otherwise-cacheable pages become full per-request SSR, adding latency and repeated DB/compute cost on every hit.",
          fix: `Push the \`${fnName}()\` read down to a leaf component (ideally isolated behind a \`<Suspense>\` boundary) instead of calling it at the route's top level.`,
          value: 3,
          ease: 3,
          safety: 4,
        }),
      );
      continue;
    }

    const defaultFn = findDefaultExportFunction(sf);
    if (!defaultFn) continue;
    const spName = findSearchParamsParamName(defaultFn);
    if (!spName) continue;
    const body = defaultFn.body;
    if (!body || !isReadDirectly(body, sf, spName)) continue;

    findings.push(
      makeFinding(nextId, {
        title: `\`searchParams\` read directly in the route's top-level component`,
        severity: "Medium",
        confidence: "Review",
        category: "Performance",
        taxonomy: "M9 — Accidental dynamic rendering",
        location: path,
        evidence: `${path} destructures \`searchParams\` and reads a field off it directly in the top-level component, rather than only forwarding the object to a leaf component.`,
        impact: "Reading searchParams anywhere in the tree forces the whole route to server-render per request, defeating static/ISR on an otherwise-cacheable page.",
        fix: "Forward `searchParams` unread to a leaf component (ideally behind `<Suspense>`) and read the field there instead.",
        value: 3,
        ease: 3,
        safety: 4,
      }),
    );
  }
  return findings;
}

// --- SSR-only browser API misuse [LOW] -------------------------------------
//
// `window`/`document`/`localStorage`/`sessionStorage`/`navigator` referenced on a path that
// runs during SSR → "ReferenceError: window is not defined" or a hydration mismatch (#381,
// briefs/scan-extras.txt M9 "SSR-ONLY API MISUSE"). App Router components server-render by
// default, so the read fires on the server unless it is deferred to the browser. The two
// standard SSR-safe idioms are the FP boundary and must stay silent:
//   - inside a useEffect/useLayoutEffect callback or an event handler (browser-only, deferred),
//   - guarded by `typeof window !== "undefined"` (or any browser global).
const BROWSER_GLOBALS = new Set(["window", "document", "localStorage", "sessionStorage", "navigator"]);
const TYPEOF_GUARD = /typeof\s+(window|document|localStorage|sessionStorage|navigator)\b/;
// Optional-chaining a browser global (`window?.x`, `document?.foo`) is the author's explicit signal
// that the global may be absent — treated as an SSR guard, same as `typeof` (#964). Matched both on
// the access itself and on an enclosing `if (window?.x)` condition.
const OPTIONAL_CHAIN_GUARD = /\b(window|document|localStorage|sessionStorage|navigator)\?\./;

// Names bound anywhere in the file (imports, params, variable/function/class declarations). If a
// browser-global name is also a local binding, the access is not the DOM global — skip it, so an
// app with a variable named `document` (a DB record, say) isn't flagged. Conservative by design.
function fileDeclaredNames(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  const visit = (node: ts.Node) => {
    // #1293: a DESTRUCTURED binding counts too. Reading only `isIdentifier(node.name)` missed
    // `({ bucket, document }: Props)` and `const { data: document } = await …` — both bind
    // `document` to something that is not the DOM, and carbon's pinned tree carries 14 such rows
    // (a `DocumentType` prop and a loader's query result). The comment above already claimed this
    // case was skipped; only the identifier-shaped half was implemented.
    if (ts.isVariableDeclaration(node) || ts.isParameter(node)) bindingNames(node.name, names);
    else if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) && node.name) names.add(node.name.text);
    else if (ts.isImportClause(node) && node.name) names.add(node.name.text);
    else if (ts.isImportSpecifier(node)) names.add(node.name.text);
    else if (ts.isNamespaceImport(node)) names.add(node.name.text);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return names;
}

function isFunctionScope(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

// Whether the access is on the synchronous SSR render path. The nearest enclosing function tells
// deferred (effect/handler/callback — browser-only) from render-path code:
//   0 enclosing functions → module top-level: runs during SSR on import → on path.
//   1, and it's a free function / arrow IN A JSX MODULE (.tsx/.jsx) → a component or module-level
//     helper render body → on path.
//   1, but the file is a non-JSX .ts/.js module → a plain util/service function, not a component
//     render body (a component needs JSX, so it can't live here) → off path. At carbon's scale the
//     old "any free function is a render body" heuristic false-fired on 59 non-component `.ts`
//     utilities (#964); only module-top-level code in such a file runs during SSR unconditionally.
//   1, but it's a CLASS MEMBER (method/accessor/ctor) → not the App Router render path but an
//     OO/framework lifecycle method (e.g. a Lexical node's client-only `createDOM`) → off path.
//   ≥2 → nested in a deferred closure (effect callback, event handler) → off path.
// #1293: route-module exports Remix / React Router 7 run ONLY in the browser. `clientLoader` and
// `clientAction` are the framework's own name for "this never executes on the server", and an
// `entry.client.*` module is the client entry by convention. Flagging a browser global there
// inverts the framework contract: on carbon's pinned tree 59 of 108 rows in this class were
// `window.clientCache` inside a `clientAction`, plus 3 in `entry.client.tsx` — 62 of 108, every one
// correct code. MEASURED 2026-07-28 by `detect-static` over the pin (see external-corpus.ts).
const CLIENT_ONLY_ROUTE_EXPORTS = new Set(["clientLoader", "clientAction"]);

// #1276: TanStack Start marks client-only code by WRAPPER, not by export name —
// `createClientOnlyFn(fn)` and `createIsomorphicFn().client(fn)` are the framework's own statement
// that the body never runs on the server. FOUND BY RUNNING the adapter against a real target
// (TanStack/tanstack.com, pinned below): 6 of its 18 residual rows in this class were inside one of
// these two wrappers, a shape no fixture we authored contained.
function isClientOnlyWrapperArg(fn: ts.Node): boolean {
  const call = fn.parent;
  if (!ts.isCallExpression(call) || !call.arguments.includes(fn as ts.Expression)) return false;
  const callee = call.expression;
  if (ts.isIdentifier(callee) && callee.text === "createClientOnlyFn") return true;
  return ts.isPropertyAccessExpression(callee) && callee.name.text === "client" && /createIsomorphicFn/.test(callee.expression.getText());
}

function isClientOnlyRouteExport(fn: ts.Node): boolean {
  if (isClientOnlyWrapperArg(fn)) return true;
  if (ts.isFunctionDeclaration(fn)) return fn.name !== undefined && CLIENT_ONLY_ROUTE_EXPORTS.has(fn.name.text);
  const decl = fn.parent;
  return (
    (ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) &&
    ts.isVariableDeclaration(decl) &&
    ts.isIdentifier(decl.name) &&
    CLIENT_ONLY_ROUTE_EXPORTS.has(decl.name.text)
  );
}

// #1460: #964 suppressed this check for functions in non-JSX `.ts`/`.js` modules, on the reasoning
// that a component requires JSX and therefore lives elsewhere. That reasoning is about the MODULE — the
// identical plain helper written in a `.tsx` file went on being reported as "read in a component's
// render body", which it is not. MEASURED 2026-07-28 by `detect-static` over two pins: the rule
// clears 6 of carbon's 26 residual rows in this class and 8 of tanstack.com's 12. #1460 itself put
// carbon's family at 23 of 26; classifying every residual row by its enclosing function says
// otherwise — most of the rest are component render bodies or the separate `isBrowser ? window.x`
// house-guard family. The corrected split is recorded in carbon's external-corpus.ts note.
//
// The naive form of the fix — "a lowercase-named module-level function with no JSX in its body is
// off the render path" — LOSES TRUE POSITIVES: a helper called from a component's render body
// really does run during SSR. So the suppression is conditioned on the helper's CALL SITES, and it
// is deliberately ASYMMETRIC in two ways, both of which keep recall:
//   - NO in-file call site → stays flagged. The helper is exported and this pass reads in-file
//     call sites only, so silence here would be a guess rather than a measurement.
//   - ONE in-file call site on the render path → stays flagged. Every call site has to be off the
//     path before the read is.
// A call site inside a sibling module-level helper resolves recursively (that helper's own call
// sites decide it); mutual recursion terminates by treating a re-entered helper as still on path.
const CALL_SITES = new WeakMap<ts.SourceFile, Map<string, ts.CallExpression[]>>();

function callSitesIn(sf: ts.SourceFile): Map<string, ts.CallExpression[]> {
  let hit = CALL_SITES.get(sf);
  if (hit) return hit;
  hit = new Map();
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      const list = hit.get(node.expression.text);
      if (list) list.push(node);
      else hit.set(node.expression.text, [node]);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  CALL_SITES.set(sf, hit);
  return hit;
}

// The name a caller would use for a module-level `function f(){}` / `const f = () => {}`.
function moduleHelperName(fn: ts.Node): string | undefined {
  if (ts.isFunctionDeclaration(fn)) return fn.name?.text;
  const decl = fn.parent;
  return (ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && ts.isVariableDeclaration(decl) && ts.isIdentifier(decl.name) ? decl.name.text : undefined;
}

function containsJsx(fn: ts.Node): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node) || ts.isJsxFragment(node)) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return found;
}

// #1502: the population #1460's OWN rule deliberately leaves flagged. A helper's in-file call
// sites can only ever CLEAR it (the #1263 property) — a helper whose callers are outside what this
// pass reads must stay flagged, because silence there would be a guess, not a measurement. That
// "must stay flagged" case has two shapes:
//   - an EXPORTED helper whose callers live in OTHER modules — resolved below via the import
//     graph, DIRECTLY or through ONE hop of re-export barrel (`export { x } from "./barrel"`,
//     #1500's shape reused here). Bounded to one hop on the same reasoning #1500's
//     `declaredOrReExported` states: a barrel re-exporting from another barrel is a shape this pass
//     does not evaluate, and an unresolved chain stays flagged rather than guessed at.
//     MEASURED, RE-MEASURED 2026-07-31 on the pinned carbon/tanstack-com trees: the mechanism is
//     real and corpus-proven (`M9C-SSRXFILE-POS`/`-NEG`), but it clears NEITHER target's own
//     residual row. carbon's `slash-command.tsx:106` (`handleCommandNavigation`) needs TWO barrel
//     hops, not one — `packages/tiptap/src/index.ts` re-exports it from `./extensions`, which
//     re-exports it from `./slash-command` — one hop past this bound, so it correctly stays
//     flagged rather than the mechanism silently widening to reach it. tanstack-com's 4 residual
//     rows are the untriaged component-render-body family #1460's own baseline note names, not
//     this shape, and are unaffected either way.
//   - a helper passed as a VALUE, never called at all (`useSyncExternalStore(subscribe, …)`,
//     `addEventListener("x", handler)`) — a DIFFERENT question (is a *reference* site the same
//     evidence as a *call* site?) that this pass does NOT attempt. Conflating the two is how a rule
//     starts accepting a discarded value as evidence of anything, so a bare reference stays outside
//     `callSitesIn`'s vocabulary and such a helper stays flagged. MEASURED population: 2 of carbon's
//     20 residual rows (`useCustomerPreview.tsx:18/19`, both the same `subscribe` helper).
function isExportedModuleHelper(fn: ts.Node): boolean {
  if (ts.isFunctionDeclaration(fn)) return fn.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
  const decl = fn.parent;
  if (!ts.isVariableDeclaration(decl)) return false;
  const stmt = ts.findAncestor(decl, ts.isVariableStatement);
  return stmt?.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
}

// Precomputed once per `detectSsrBrowserApiMisuse` run (not per helper): which files import a
// given path, so a call-site search never re-walks the whole graph per candidate. `undefined`
// (the default everywhere except that one entry point) keeps every OTHER caller of
// `isOnSsrRenderPath`/`isOffPathModuleHelper` — including the unit-fixture-driven tests — on the
// pre-#1502 in-file-only behaviour with zero risk of the cross-file path changing their answer.
interface SsrCrossFileContext {
  sources: ReadonlyMap<string, ts.SourceFile>;
  allPaths: ReadonlySet<string>;
  aliases: PathAlias[];
  importedBy: ReadonlyMap<string, string[]>;
  // `${declaringPath}#${exportedName}` -> every barrel path that re-exports it (#1500's `export
  // { x } from "./barrel"` shape, one hop) — precomputed ONCE per run, not per candidate helper, so
  // a target with thousands of files doesn't re-scan them per unresolved-in-file helper.
  barrelsFor: ReadonlyMap<string, string[]>;
}

function buildSsrCrossFileContext(sources: ReadonlyMap<string, ts.SourceFile>, allPaths: ReadonlySet<string>, aliases: PathAlias[]): SsrCrossFileContext {
  const allPathsSet = new Set(allPaths);
  const graph = buildImportGraph(new Map(sources), allPathsSet, aliases);
  const importedBy = new Map<string, string[]>();
  for (const [importer, edges] of graph) {
    for (const target of edges) {
      const list = importedBy.get(target);
      if (list) list.push(importer);
      else importedBy.set(target, [importer]);
    }
  }
  const barrelsFor = new Map<string, string[]>();
  for (const [barrelPath, barrelSf] of sources) {
    for (const [, binding] of collectReExports(barrelSf, barrelPath, allPathsSet, aliases)) {
      const key = `${binding.path}#${binding.name}`;
      const list = barrelsFor.get(key);
      if (list) list.push(barrelPath);
      else barrelsFor.set(key, [barrelPath]);
    }
  }
  return { sources, allPaths, aliases, importedBy, barrelsFor };
}

// Every call site, in every OTHER module that imports `path` (directly, or through a re-export
// barrel) and binds `exportedName` by value, to the LOCAL name that import uses (so a renamed
// import — `import { foo as bar }` — still resolves). A module that imports but never calls the
// name contributes nothing, which is the same "no evidence either way" outcome as an in-file zero.
function crossFileCallSites(path: string, exportedName: string, ctx: SsrCrossFileContext): { node: ts.CallExpression; sf: ts.SourceFile }[] {
  const out: { node: ts.CallExpression; sf: ts.SourceFile }[] = [];
  const viaPaths = [path, ...(ctx.barrelsFor.get(`${path}#${exportedName}`) ?? [])];
  for (const viaPath of viaPaths) {
    for (const importerPath of ctx.importedBy.get(viaPath) ?? []) {
      const importerSf = ctx.sources.get(importerPath);
      if (!importerSf) continue;
      const imports = collectValueImports(importerSf, importerPath, new Set(ctx.allPaths), ctx.aliases);
      for (const [localName, binding] of imports) {
        if (binding.path !== viaPath || binding.name !== exportedName) continue;
        for (const node of callSitesIn(importerSf).get(localName) ?? []) out.push({ node, sf: importerSf });
      }
    }
  }
  return out;
}

function isOffPathModuleHelper(fn: ts.Node, sf: ts.SourceFile, seen: Set<ts.Node>, ctx: SsrCrossFileContext | undefined, path: string | undefined): boolean {
  if (seen.has(fn)) return false;
  const name = moduleHelperName(fn);
  if (name === undefined || !/^[_a-z]/.test(name)) return false; // a component is capitalised
  if (containsJsx(fn)) return false; // it renders — a component whatever it is called
  // A recursive self-call says nothing about who reaches the helper from outside.
  const inFileSites = (callSitesIn(sf).get(name) ?? []).filter((site) => !ts.findAncestor(site, (a) => a === fn));
  const next = new Set(seen).add(fn);
  if (inFileSites.length > 0) return inFileSites.every((site) => !isOnSsrRenderPath(site, sf, ctx, next));
  // No in-file caller. Unresolvable (no cross-file context, or the helper isn't exported) stays
  // flagged — the #1263 property this whole rule already relies on.
  if (!ctx || path === undefined || !isExportedModuleHelper(fn)) return false;
  const crossSites = crossFileCallSites(path, name, ctx);
  if (crossSites.length === 0) return false; // no consumer found anywhere in the scanned tree
  return crossSites.every(({ node, sf: callerSf }) => !isOnSsrRenderPath(node, callerSf, ctx, next));
}

function isOnSsrRenderPath(node: ts.Node, sf: ts.SourceFile, ctx: SsrCrossFileContext | undefined = undefined, seen: Set<ts.Node> = new Set()): boolean {
  if (/(^|\/)entry\.client\.[jt]sx?$/.test(sf.fileName)) return false;
  const fns: ts.Node[] = [];
  for (let cur = node.parent; cur; cur = cur.parent) {
    if (isFunctionScope(cur)) fns.push(cur);
  }
  if (fns.some(isClientOnlyRouteExport)) return false;
  if (fns.length >= 2) return false;
  const nearest = fns[0];
  if (nearest) {
    if (ts.isMethodDeclaration(nearest) || ts.isConstructorDeclaration(nearest) || ts.isGetAccessorDeclaration(nearest) || ts.isSetAccessorDeclaration(nearest)) {
      return false;
    }
    if (!/\.[jt]sx$/.test(sf.fileName)) return false;
    if (isOffPathModuleHelper(nearest, sf, seen, ctx, findSourcePath(sf, ctx))) return false;
  }
  return true;
}

// `sf.fileName` is the loaded path (see `parse` in common.ts) — a thin lookup, kept as its own
// function only so `isOnSsrRenderPath` reads as "the path", not an inline reverse-map dance.
function findSourcePath(sf: ts.SourceFile, ctx: SsrCrossFileContext | undefined): string | undefined {
  return ctx?.sources.has(sf.fileName) ? sf.fileName : undefined;
}

// Where the read sits, for the finding's own evidence. #1460: a module-level helper that survives
// the call-site test is NOT "a component's render body" — it is a helper something on the render
// path calls — and saying so is the difference between evidence a reader can check and evidence
// that asserts the wrong thing about the code (the #1293 correction, applied to this string).
function ssrReadSite(node: ts.Node): string {
  const nearest = ts.findAncestor(node.parent, isFunctionScope);
  if (!nearest) return "at module top level";
  const name = moduleHelperName(nearest);
  return name !== undefined && /^[_a-z]/.test(name) && !containsJsx(nearest)
    ? `in \`${name}\`, a module-level helper reached from the render path`
    : "in a component's render body";
}

// True when a browser-global guard gates this node — an enclosing `if`, ternary, or `&&`/`||` whose
// condition/left operand tests a browser global via `typeof` or optional chaining (`window?.x`).
// The two standard SSR-safe guards.
// #1293: an EARLY-RETURN guard is a preceding sibling, not an ancestor —
// `if (typeof window === "undefined") return null;` followed by the read. Walking only ancestors
// missed it, and the finding's own evidence asserts no such guard exists, so the row was not merely
// noisy but wrong on its face. Only a guard that EXITS counts (return/throw); a guarded `if` with a
// fall-through body says nothing about the code after it.
function precedingGuardExits(node: ts.Node, sf: ts.SourceFile, guards: (text: string) => boolean): boolean {
  for (let cur: ts.Node = node; cur.parent; cur = cur.parent) {
    const parent = cur.parent;
    if (!ts.isBlock(parent) && !ts.isSourceFile(parent)) continue;
    for (const stmt of parent.statements) {
      if (stmt.getStart(sf) >= cur.getStart(sf)) break;
      if (!ts.isIfStatement(stmt) || !guards(stmt.expression.getText(sf))) continue;
      const body = stmt.thenStatement;
      const exits = (s: ts.Statement): boolean =>
        ts.isReturnStatement(s) || ts.isThrowStatement(s) || (ts.isBlock(s) && s.statements.some(exits));
      if (exits(body)) return true;
    }
  }
  return false;
}

function isSsrGuarded(node: ts.Node, sf: ts.SourceFile): boolean {
  const guards = (text: string) => TYPEOF_GUARD.test(text) || OPTIONAL_CHAIN_GUARD.test(text);
  if (precedingGuardExits(node, sf, guards)) return true;
  for (let cur = node.parent; cur; cur = cur.parent) {
    if (ts.isIfStatement(cur) && guards(cur.expression.getText(sf))) return true;
    if (ts.isConditionalExpression(cur) && guards(cur.condition.getText(sf))) return true;
    if (
      ts.isBinaryExpression(cur) &&
      (cur.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken || cur.operatorToken.kind === ts.SyntaxKind.BarBarToken) &&
      guards(cur.left.getText(sf))
    ) {
      return true;
    }
  }
  return false;
}

function detectSsrBrowserApiMisuse(sources: Map<string, ts.SourceFile>, nextId: NextId, aliases: PathAlias[] = []): Finding[] {
  const findings: Finding[] = [];
  const ctx = buildSsrCrossFileContext(sources, new Set(sources.keys()), aliases);
  for (const [path, sf] of sources) {
    const declared = fileDeclaredNames(sf);
    const visit = (node: ts.Node) => {
      const onGlobal =
        (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) &&
        ts.isIdentifier(node.expression) &&
        BROWSER_GLOBALS.has(node.expression.text) &&
        !declared.has(node.expression.text);
      if (onGlobal) {
        const global = (node.expression as ts.Identifier).text;
        // An optional-chained access (`window?.x`) is itself a guard — the author signalled the
        // global may be absent, so it never throws a bare ReferenceError shape we flag (#964).
        const optionalChained = (node as ts.PropertyAccessExpression | ts.ElementAccessExpression).questionDotToken !== undefined;
        if (!optionalChained && isOnSsrRenderPath(node, sf, ctx) && !isSsrGuarded(node, sf)) {
          const readSite = ssrReadSite(node);
          findings.push(
            makeFinding(nextId, {
              title: `\`${global}\` read on the SSR render path`,
              severity: "Low",
              confidence: "Review",
              category: "Performance",
              taxonomy: "M9 — SSR-only API misuse",
              location: loc(path, sf, node),
              evidence: `\`${node.getText(sf)}\` is read ${readSite}, not inside a useEffect callback, an event handler, or a \`typeof ${global} !== "undefined"\` guard — so it executes during server-side rendering.`,
              impact: `Browser globals are undefined on the server: this throws "${global} is not defined" on first render, or hydration-mismatches when the server and client HTML disagree.`,
              fix: `Move the read into a \`useEffect\`/event handler (client-only), or guard it with \`typeof ${global} !== "undefined"\`; make the component a Client Component if it genuinely needs the browser.`,
              value: 3,
              ease: 4,
              safety: 4,
            }),
          );
          return; // one finding per access; don't descend into an already-flagged expression
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return findings;
}

// --- Non-SSR SPA coverage note ------------------------------------------------
//
// Every M9 check is Next.js-App-Router-specific — SSR-by-default browser-API misuse, the RSC
// server→client boundary, Server Actions, `server-only`, the Full Route Cache. A Vite/SPA export
// has none of these: the whole bundle IS the client, there is no SSR render path, no `"use server"`
// action, no `app/` route cache. Running the family there produces false-premise findings (the
// live nocode-rescue miss: `localStorage` reads flagged as "SSR render path" misuse on a Vite SPA
// that has no SSR — #575). So on a confirmed non-SSR SPA we SUPPRESS the whole M9 pass and emit
// this one explicit N/A note instead — fail loud: the absence of M9 findings must read as "not
// applicable here", never as "assessed and clean" (the coverage-guard principle in CLAUDE.md).
// `scope` is "(whole target)" for a single-app Vite target, or a workspace-relative dir
// ("apps/web") for one Vite workspace of a monorepo whose other workspaces still run the pass (#597).
function nonSsrSpaCoverageNote(nextId: NextId, framework: TargetFramework, scope: string): Finding {
  const isWorkspace = scope !== "(whole target)";
  const subject = isWorkspace ? `Workspace \`${scope}\`` : "Target";
  return {
    id: nextId(),
    title: isWorkspace ? `M9 N/A — non-SSR SPA workspace (${scope})` : "M9 N/A — non-SSR SPA",
    severity: "Info",
    confidence: "N/A",
    category: "Performance",
    taxonomy: "M9 — Not applicable (non-Next SPA)",
    location: scope,
    status: "Open",
    evidence: `${subject} framework detected as \`${framework}\` — a non-Next single-page app. M9's App Router checks (SSR browser-API misuse, server→client leak, \`server-only\` guard, Server Action auth/validation, cache/dynamic-rendering) all assume Next.js server-rendering by default and do not apply: a Vite/SPA build has no SSR render path, no Server Actions, and no RSC server→client boundary.`,
    impact: "M9 App Router coverage is not applicable to this scope. Recorded explicitly so the absence of M9 findings reads as 'not applicable here', not 'assessed and clean'.",
    fix: "None — informational. If this target is in fact a Next.js app, verify framework detection (its `vite.config` / package.json `next` dependency).",
    value: 1,
    ease: 5,
    safety: 5,
    precisionTier: "high",
  };
}

// --- Recognised-but-unsupported framework coverage note (#872) ----------------
//
// Remix / React Router 7 / TanStack Start / Astro / SvelteKit / Nuxt all have a boundary and
// rendering model of their own, and none of it is the one M9 reads. Before #872 they resolved to
// `vite` (if they declared it) or `other` — and `other` ran the whole Next-shaped pass over them,
// producing false-premise findings, while their actual surface went unassessed AND unmentioned.
// Suppress the pass and say so, naming the framework: the report must never let `other` read as
// "analysed and clean" (the coverage-guard principle in CLAUDE.md).
function unsupportedFrameworkNote(nextId: NextId, framework: TargetFramework, scope: string): Finding {
  const label = FRAMEWORK_LABELS[framework];
  const subject = scope === "(whole target)" ? "Target" : `Workspace \`${scope}\``;
  return {
    id: nextId(),
    title: `M9 not assessed — ${label} (framework not supported)`,
    severity: "Info",
    confidence: "N/A",
    category: "Performance",
    taxonomy: "M9 — Not assessed (framework unsupported)",
    location: scope,
    status: "Open",
    evidence: `${subject} framework detected as ${label}. Every M9 check is Next.js App Router-specific — the RSC server→client boundary, \`"use server"\` actions, the \`server-only\` guard, route segment config and the Full Route Cache. ${label} has its own routing, data-loading and boundary model that none of these detectors reads, so the pass was SUPPRESSED rather than run (running it would produce false-premise findings, the #575 failure).`,
    impact: `Boundary/rendering coverage for this scope is missing, not clean: ${label}'s own data-loading and boundary surface was not analysed. Recorded explicitly so the absence of M9 findings reads as "not assessed here".`,
    fix: `None — informational. Review ${label}'s server/client boundary and data-loading by hand; if this target is in fact a Next.js app, verify framework detection (its package.json \`next\` dependency / next.config).`,
    value: 1,
    ease: 5,
    safety: 5,
    precisionTier: "high",
  };
}

// What M9 emits for a scope it cannot analyse: the Vite/SPA path keeps its own note plus the one
// SPA-specific check that DOES apply there (#627); every other recognised framework gets the
// not-assessed row alone.
function unanalysableFramework(files: SourceInput[], nextId: NextId, framework: TargetFramework, scope: string): Finding[] {
  if (framework !== "vite") return [unsupportedFrameworkNote(nextId, framework, scope)];
  return [nonSsrSpaCoverageNote(nextId, framework, scope), ...detectSpaRootErrorBoundary(files, nextId, scope)];
}

// --- SPA root error-boundary absence [LOW] — Vite/SPA resilience (#627) -------
//
// A Vite/SPA entry mounts the React root (`createRoot(el).render(<App/>)`, or the React 17
// `ReactDOM.render(<App/>, el)`) with no error boundary anywhere in the app. Unlike a Next app —
// which has a framework-level boundary (`error.tsx`) — a bare SPA has none, so an unhandled render
// error unmounts the whole tree and blanks the screen. Runs ONLY on the Vite/SPA scope the rest of
// the M9 pass is suppressed on (this entry-mount + no-boundary shape is SPA-specific).
//
// Precision (absence detection errs toward silence): fires only when the scope has a root-mount AND
// no error boundary of any recognised form — a hand-rolled boundary class (componentDidCatch /
// getDerivedStateFromError), a `react-error-boundary` import, a `<…ErrorBoundary>` element, or a
// `withErrorBoundary` wrapper. Any boundary present anywhere in the scope suppresses the finding,
// even one that doesn't demonstrably wrap the root — a false negative is preferable to flagging an
// app that already has a boundary.
const ERROR_BOUNDARY_LIFECYCLE = /^(componentDidCatch|getDerivedStateFromError)$/;

function isCreateRootCall(node: ts.Expression): boolean {
  return (
    ts.isCallExpression(node) &&
    ((ts.isIdentifier(node.expression) && node.expression.text === "createRoot") ||
      (ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "createRoot"))
  );
}

function isJsxNode(node: ts.Node): boolean {
  return ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node) || ts.isJsxFragment(node);
}

// The root-mount call: `createRoot(...).render(<jsx>)` (React 18) or `ReactDOM.render(<jsx>, el)`
// (React 17). A JSX first argument is what separates a React root mount from any other `.render()`.
function findSpaRootMount(sf: ts.SourceFile): ts.Node | undefined {
  let hit: ts.Node | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "render") {
      const receiver = node.expression.expression;
      const firstArg = node.arguments[0];
      if (firstArg && isJsxNode(firstArg)) {
        if (isCreateRootCall(receiver)) hit = node;
        else if (ts.isIdentifier(receiver) && /^ReactDOM?$/i.test(receiver.text) && node.arguments.length >= 2) hit = node;
      }
      if (hit) return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return hit;
}

function fileHasErrorBoundary(sf: ts.SourceFile): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && node.moduleSpecifier.text === "react-error-boundary") {
      found = true;
    } else if (ts.isClassLike(node) && node.members.some((m) => m.name !== undefined && ts.isIdentifier(m.name) && ERROR_BOUNDARY_LIFECYCLE.test(m.name.text))) {
      found = true;
    } else if ((ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) && /ErrorBoundary$/.test(node.tagName.getText(sf))) {
      found = true;
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const name = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : undefined;
      if (name === "withErrorBoundary") found = true;
    }
    if (!found) ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

function detectSpaRootErrorBoundary(files: SourceInput[], nextId: NextId, scope: string): Finding[] {
  const sources = files.map((f) => ({ path: f.path, sf: parse(f.path, f.text) }));
  if (sources.some(({ sf }) => fileHasErrorBoundary(sf))) return [];
  for (const { path, sf } of sources) {
    const mount = findSpaRootMount(sf);
    if (!mount) continue;
    const where = scope === "(whole target)" ? "this SPA" : `workspace \`${scope}\``;
    return [
      {
        id: nextId(),
        title: "SPA mounts its root with no top-level error boundary",
        severity: "Low",
        confidence: "Review",
        category: "Reliability",
        taxonomy: "M9 — SPA missing root error boundary",
        location: loc(path, sf, mount),
        status: "Open",
        evidence: `${path} mounts the React root here, and no error boundary (an error-boundary class, a react-error-boundary import, an <ErrorBoundary> element, or a withErrorBoundary wrapper) appears anywhere in ${where}. A Vite/SPA build has no framework-level boundary (no Next.js error.tsx) to fall back on.`,
        impact: "An unhandled error thrown while rendering any component unmounts the whole React tree and leaves the user a blank white screen, with no fallback UI and no recovery path.",
        fix: "Wrap the mounted root (or the top-level <App/>) in a React error boundary that renders a fallback UI.",
        precisionTier: "review",
        value: 3,
        ease: 4,
        safety: 5,
      },
    ];
  }
  return [];
}

// --- Unbounded / self-calling route or edge fn [MED] (#843) -----------------
//
// The M9 brief's "UNBOUNDED / SELF-CALLING ROUTE OR EDGE FN" surface (briefs/scan-extras.txt): an
// API route / edge function whose handler either loops forever or fetches its own URL → runaway
// compute, cost, and timeouts. Two precise AST shapes, both scoped to server request handlers
// (route.ts(x), pages/api, middleware.ts, or any file declaring `runtime = "edge"`):
//   1. UNBOUNDED LOOP: `while (true)` / `while (1)` / `for (;;)` / `do … while (true)` whose body
//      contains NO break/return/throw anywhere — a loop that provably never terminates. A break in
//      a NESTED loop wouldn't terminate the outer one, so counting any break/return/throw as
//      "bounded" only ever errs toward SILENCE (a false negative), never a false positive.
//   2. SELF-REFERENTIAL FETCH: `fetch(…)` whose argument subtree reads the incoming request's own
//      URL (`request.url` / `req.url` / `.nextUrl`) — the handler calling back into itself.
// #1262 adds the brief's THIRD item, uncapped retry/fan-out, as two more AST shapes plus a
// disclosure row for what neither reaches (detectUncappedRetryFanOut / uncappedRetryScopeNote
// below). The comment this replaced called that item "past a precise mechanical rule" and left it
// out of the report entirely — the technical claim was never tested and the report said nothing.
const ROUTE_HANDLER_FILE = /(^|\/)(route\.[cm]?[jt]sx?|middleware\.[cm]?[jt]sx?)$|(^|\/)pages\/api\//;

function declaresEdgeRuntime(sf: ts.SourceFile): boolean {
  for (const stmt of sf.statements) {
    if (!ts.isVariableStatement(stmt) || !stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
    for (const decl of stmt.declarationList.declarations) {
      if (ts.isIdentifier(decl.name) && decl.name.text === "runtime" && decl.initializer && ts.isStringLiteral(decl.initializer) && decl.initializer.text === "edge") {
        return true;
      }
    }
  }
  return false;
}

function isRouteOrEdgeHandler(path: string, sf: ts.SourceFile): boolean {
  return ROUTE_HANDLER_FILE.test(path) || declaresEdgeRuntime(sf);
}

function isTruthyLiteral(expr: ts.Expression): boolean {
  return expr.kind === ts.SyntaxKind.TrueKeyword || (ts.isNumericLiteral(expr) && expr.text !== "0");
}

// An always-true loop header: `while (true)` / `while (1)` / `do … while (true)` / `for (;;)`
// (or `for (…; ; …)` — an omitted condition). The header is the whole story; the body decides
// whether it is actually unbounded (bodyHasEscape below).
function isAlwaysTrueLoop(node: ts.Node): node is ts.WhileStatement | ts.DoStatement | ts.ForStatement {
  if ((ts.isWhileStatement(node) || ts.isDoStatement(node)) && isTruthyLiteral(node.expression)) return true;
  return ts.isForStatement(node) && node.condition === undefined;
}

// Any break/return/throw anywhere in the subtree. A conservative over-count: a break belonging to
// a nested loop doesn't terminate this one, so treating it as an escape only suppresses findings.
function bodyHasEscape(body: ts.Node): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isBreakStatement(node) || ts.isReturnStatement(node) || ts.isThrowStatement(node)) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(body);
  return found;
}

// A fetch(…) whose argument subtree reads the request's own URL — `request.url`, `req.url`, or
// anything off `.nextUrl`. That is the handler calling back into its own route.
function isSelfReferentialFetch(node: ts.CallExpression): boolean {
  if (!ts.isIdentifier(node.expression) || node.expression.text !== "fetch") return false;
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isPropertyAccessExpression(n)) {
      if (n.name.text === "nextUrl") found = true;
      else if (n.name.text === "url" && ts.isIdentifier(n.expression) && /^req(uest)?$/.test(n.expression.text)) found = true;
    }
    if (!found) ts.forEachChild(n, visit);
  };
  for (const arg of node.arguments) visit(arg);
  return found;
}

function detectUnboundedRouteOrEdge(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (!isRouteOrEdgeHandler(path, sf)) continue;

    const visit = (node: ts.Node) => {
      if (isAlwaysTrueLoop(node) && !bodyHasEscape(node.statement)) {
        findings.push(
          makeFinding(nextId, {
            title: `Unbounded loop in a route/edge handler`,
            severity: "Medium",
            confidence: "Likely",
            category: "Performance",
            taxonomy: "M9 — Unbounded/self-calling route or edge fn",
            location: loc(path, sf, node),
            evidence: `\`${node.getText(sf).slice(0, 60).replace(/\s+/g, " ")}…\` never terminates — its body has no \`break\`, \`return\`, or \`throw\`. Route/edge handlers run per request under a wall-clock limit.`,
            impact: "The handler spins until the platform kills it (timeout/OOM), burning compute on every request and never returning a response — a self-inflicted denial of service and a runaway bill.",
            fix: "Add a terminating condition (a counter/pagination bound, a `break`, or a timeout) so the loop provably ends.",
            value: 4,
            ease: 3,
            safety: 4,
          }),
        );
      }
      if (ts.isCallExpression(node) && isSelfReferentialFetch(node)) {
        findings.push(
          makeFinding(nextId, {
            title: `Route/edge handler fetches its own request URL`,
            severity: "Medium",
            confidence: "Likely",
            category: "Performance",
            taxonomy: "M9 — Unbounded/self-calling route or edge fn",
            location: loc(path, sf, node),
            evidence: `\`${node.getText(sf).slice(0, 80).replace(/\s+/g, " ")}\` fetches the incoming request's own URL from inside the handler — the route calls back into itself.`,
            impact: "Each invocation triggers another invocation: an unbounded recursive fan-out that multiplies compute and cost with every hop until the platform's concurrency or timeout limit trips.",
            fix: "Call the underlying function/data source directly instead of re-fetching this route's own URL; if a redirect/proxy is intended, target a different endpoint.",
            value: 4,
            ease: 3,
            safety: 4,
          }),
        );
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return findings;
}

// --- Uncapped retry / fan-out [MED] (#843 remainder, #1262) -----------------
//
// The M9 brief's third "unbounded route" item. #857 shipped the other two and recorded this one's
// absence in a source comment only, so a client's report said nothing about it either way. Two AST
// shapes, both scoped to the same route/edge handlers the sibling check uses:
//
//   1. UNCAPPED RETRY — a loop that re-issues a network/DB call on failure (an outbound call plus a
//      `catch` in the same loop body) whose attempt count has no resolvable cap: `while (true)`, or
//      a `for` whose bound is a value from the request rather than a literal/const. The bounded
//      forms (`i < 3`, `i < MAX_RETRIES` where MAX_RETRIES is a numeric const, `i < rows.length`)
//      resolve and stay silent.
//   2. UNCAPPED FAN-OUT — `Promise.all(xs.map(…))` (or allSettled) whose callback issues an
//      outbound call and whose `xs` roots in the REQUEST (a handler parameter, a parsed body, a
//      query param), with no `.slice(…)` bound and no length guard. One request then buys the
//      client N concurrent outbound calls.
//
// What these two do NOT reach is disclosed by uncappedRetryScopeNote below, with counts — see it
// for the bound. Both shapes require an outbound call in the loop/callback, so an in-memory loop is
// never a finding.

const RETRY_LIBRARY = /^(p-retry|async-retry|retry|axios-retry|exponential-backoff|promise-retry|cockatiel|p-limit|bottleneck)$/;

// An outbound call: `fetch(…)` or a DB query chain. The unit that makes a loop or a fan-out cost
// something per iteration.
function hasOutboundCall(node: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isCallExpression(n) && ((ts.isIdentifier(n.expression) && n.expression.text === "fetch") || isDbQueryChain(n))) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

function hasCatch(node: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isCatchClause(n)) {
      found = true;
      return;
    }
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "catch") {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

// Numeric constants declared anywhere in the file, so `for (let i = 0; i < MAX_RETRIES; i++)` with
// `const MAX_RETRIES = 3` reads as capped.
function numericConstNames(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && ts.isNumericLiteral(node.initializer)) {
      names.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return names;
}

// Whether a loop header carries a bound this pass can resolve: a comparison against a numeric
// literal, a numeric const, or a `.length`. `&&` is capped if EITHER side caps (either one ends the
// loop); `||` only if BOTH do (the loop runs while either holds).
function conditionIsCapped(cond: ts.Expression, consts: ReadonlySet<string>): boolean {
  if (!ts.isBinaryExpression(cond)) return false;
  if (cond.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) return conditionIsCapped(cond.left, consts) || conditionIsCapped(cond.right, consts);
  if (cond.operatorToken.kind === ts.SyntaxKind.BarBarToken) return conditionIsCapped(cond.left, consts) && conditionIsCapped(cond.right, consts);
  const bound = cond.right;
  if (ts.isNumericLiteral(bound)) return true;
  if (ts.isIdentifier(bound) && consts.has(bound.text)) return true;
  return ts.isPropertyAccessExpression(bound) && bound.name.text === "length";
}

// Whether a loop's attempt count is bounded by something this pass can see. Anything that is not a
// recognised loop header is treated as CAPPED — the shape must be proven unbounded to fire.
//
// #1440: this used to accept only a LITERAL-true while-condition, so the canonical uncapped retry —
// `while (!done) { try { await fetch(url) } catch {} }` — was never assessed at all, and was not
// named in the scope row either. A while/do condition now resolves exactly as a `for` condition
// does. The header is all this reads: a loop bounded by a counter the BODY updates reads as
// uncapped, which is the fail-loud direction and is stated in the finding's own evidence.
function retryLoopIsUncapped(node: ts.Node, consts: ReadonlySet<string>): boolean {
  if (ts.isWhileStatement(node) || ts.isDoStatement(node)) {
    return isTruthyLiteral(node.expression) || !conditionIsCapped(node.expression, consts);
  }
  if (!ts.isForStatement(node)) return false;
  const cond = node.condition;
  if (cond === undefined) return true; // `for (;;)`
  return !conditionIsCapped(cond, consts);
}

// Names whose value comes from the incoming request: the handler's own parameters, and anything
// bound from a request read (`await request.json()`, `req.body`, `searchParams.get(…)`, `params`).
// Deliberately narrow — the fan-out shape fires only on a collection the CLIENT sizes.
const REQUEST_READ = /\breq(uest)?\b|\bsearchParams\b|\bparams\b|\.body\b|\bformData\b/;

function collectRequestDerivedNames(fn: ts.Node, sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  for (const p of (fn as ts.SignatureDeclarationBase).parameters ?? []) {
    if (ts.isIdentifier(p.name)) names.add(p.name.text);
    else if (ts.isObjectBindingPattern(p.name)) for (const el of p.name.elements) if (ts.isIdentifier(el.name)) names.add(el.name.text);
  }
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const text = node.initializer.getText(sf);
      const root = ts.isExpression(node.initializer) ? rootIdentifier(node.initializer) : undefined;
      if (REQUEST_READ.test(text) || (root !== undefined && names.has(root))) {
        if (ts.isIdentifier(node.name)) names.add(node.name.text);
        else if (ts.isObjectBindingPattern(node.name)) for (const el of node.name.elements) if (ts.isIdentifier(el.name)) names.add(el.name.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return names;
}

interface FanOut {
  node: ts.CallExpression;
  collection: string;
}

// `Promise.all(xs.map(cb))` / `Promise.allSettled(...)` where cb makes an outbound call. Returns the
// collection's root name so the caller can ask whether the CLIENT controls its length.
function asFanOut(node: ts.Node): FanOut | undefined {
  if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return undefined;
  if (!/^(all|allSettled)$/.test(node.expression.name.text)) return undefined;
  if (!ts.isIdentifier(node.expression.expression) || node.expression.expression.text !== "Promise") return undefined;
  const arg = node.arguments[0];
  if (!arg || !ts.isCallExpression(arg) || !ts.isPropertyAccessExpression(arg.expression) || !/^(map|flatMap)$/.test(arg.expression.name.text)) return undefined;
  const cb = arg.arguments[0];
  if (!cb || !hasOutboundCall(cb)) return undefined;
  const receiver = arg.expression.expression;
  // A `.slice(…)`/`.splice(…)` anywhere in the receiver chain IS the cap — the shape is bounded.
  if (/\.(slice|splice)\s*\(/.test(receiver.getText())) return undefined;
  const collection = rootIdentifier(receiver);
  return collection === undefined ? undefined : { node, collection };
}

function enclosingHandler(node: ts.Node): ts.Node | undefined {
  return ts.findAncestor(node, (a) => ts.isFunctionDeclaration(a) || ts.isFunctionExpression(a) || ts.isArrowFunction(a) || ts.isMethodDeclaration(a)) ?? undefined;
}

function detectUncappedRetryFanOut(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (!isRouteOrEdgeHandler(path, sf)) continue;
    const consts = numericConstNames(sf);

    const visit = (node: ts.Node) => {
      if ((ts.isForStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) && hasOutboundCall(node.statement) && hasCatch(node.statement) && retryLoopIsUncapped(node, consts)) {
        findings.push(
          makeFinding(nextId, {
            title: `Retry loop with no attempt cap in a route/edge handler`,
            severity: "Medium",
            confidence: "Likely",
            category: "Performance",
            taxonomy: "M9 — Uncapped retry/fan-out",
            location: loc(path, sf, node),
            evidence: `\`${node.getText(sf).slice(0, 70).replace(/\s+/g, " ")}…\` re-issues an outbound call after catching a failure, and its attempt count resolves to no literal or constant bound in this file — the loop header is \`${(ts.isForStatement(node) ? node.condition?.getText(sf) : node.expression.getText(sf)) ?? "(none)"}\`. Scope of this check: it reads the loop HEADER only, so a counter or flag the body updates on each attempt could still bound this loop and this rule would not see it (#1440).`,
            impact: "A dependency that is down or rate-limiting turns every request into an unbounded retry storm: the handler holds its slot until the platform timeout, amplifies load onto the failing dependency, and multiplies the bill exactly when the system is least healthy.",
            fix: "Cap the attempts with a literal/const maximum and back off between them (or delegate to a retry helper configured with a maxAttempts).",
            value: 4,
            ease: 4,
            safety: 4,
          }),
        );
      }
      const fanOut = asFanOut(node);
      if (fanOut) {
        const handler = enclosingHandler(node);
        const requestDerived = handler ? collectRequestDerivedNames(handler, sf) : new Set<string>();
        if (requestDerived.has(fanOut.collection)) {
          findings.push(
            makeFinding(nextId, {
              title: `Request-sized fan-out of outbound calls in a route/edge handler`,
              severity: "Medium",
              confidence: "Likely",
              category: "Performance",
              taxonomy: "M9 — Uncapped retry/fan-out",
              location: loc(path, sf, node),
              evidence: `\`${node.getText(sf).slice(0, 80).replace(/\s+/g, " ")}\` issues one outbound call per element of \`${fanOut.collection}\`, which comes from the incoming request, with no \`.slice(…)\`/\`.splice(…)\` bound on the mapped expression. Scope of this check: it reads the mapped expression only, so a length check or early return elsewhere in the handler would also bound the fan-out and this rule cannot see one.`,
              impact: "The caller chooses how many outbound calls one request makes: a large array multiplies compute, connections and third-party spend per request, and is a ready-made amplification vector against both this service and whatever it calls.",
              fix: "Validate the collection's length against a maximum before the map (rejecting oversized input), and/or bound concurrency with a limiter and chunk the work.",
              value: 4,
              ease: 4,
              safety: 4,
            }),
          );
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return findings;
}

// The disclosure half of #1262. The two shapes above are what a precise AST rule reaches; the
// sub-shapes it does not are named here WITH THEIR COUNT ON THIS TARGET, so the row carries a
// measured population rather than a hypothetical bound, and its absence from the report can never
// read as "assessed and clean". Emitted whenever the target has route/edge handlers at all.
//
// #1440 audited this list for exhaustiveness and found it was not: the canonical
// `while (!done) { try { await fetch(url) } catch {} }` was neither detected NOR named here, so the
// row read as complete while omitting a class — the failure the disclosure family exists to
// prevent, occurring inside a disclosure row. That class is now DETECTED (retryLoopIsUncapped), and
// the bound it leaves behind — a loop bounded in the BODY rather than the header — is named as (4)
// with its count, in the direction it errs.
function uncappedRetryScopeNote(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  let handlers = 0;
  let retryLibFiles = 0;
  let unscopedFanOuts = 0;
  let headerOnlyBounds = 0;
  for (const [path, sf] of sources) {
    if (!isRouteOrEdgeHandler(path, sf)) continue;
    handlers += 1;
    const consts = numericConstNames(sf);
    const importsRetryLib = sf.statements.some((s) => ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier) && RETRY_LIBRARY.test(s.moduleSpecifier.text));
    if (importsRetryLib) retryLibFiles += 1;
    const visit = (node: ts.Node) => {
      const fanOut = asFanOut(node);
      if (fanOut) {
        const handler = enclosingHandler(node);
        const requestDerived = handler ? collectRequestDerivedNames(handler, sf) : new Set<string>();
        if (!requestDerived.has(fanOut.collection)) unscopedFanOuts += 1;
      }
      // The retry loops REPORTED above whose header is not a literal-true — the ones whose real cap,
      // if any, would live in the body this pass does not read.
      if (
        (ts.isForStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) &&
        hasOutboundCall(node.statement) &&
        hasCatch(node.statement) &&
        retryLoopIsUncapped(node, consts) &&
        !isAlwaysTrueLoop(node)
      ) {
        headerOnlyBounds += 1;
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  if (handlers === 0) return [];
  return [
    {
      id: nextId(),
      title: `M9 partially assessed — uncapped retry/fan-out (${handlers} route/edge handler${handlers === 1 ? "" : "s"})`,
      severity: "Info",
      confidence: "N/A",
      category: "Performance",
      taxonomy: "M9 — Uncapped retry/fan-out — scope",
      location: "(whole target)",
      status: "Open",
      evidence: `${handlers} route/edge handler${handlers === 1 ? " was" : "s were"} checked for two uncapped shapes: a retry loop whose attempt count resolves to no literal/const bound in its header (\`while (true)\`, \`while (!done)\`, \`for (let i = 0; i < attempts; i++)\` alike), and a \`Promise.all(xs.map(…))\` fan-out over a request-sized collection. FOUR sub-shapes were NOT fully assessed, counted here on this target: (1) retries delegated to a retry/backoff/concurrency library, whose cap lives in a config object this pass does not read — ${retryLibFiles} handler file${retryLibFiles === 1 ? " imports" : "s import"} one; (2) fan-out over a collection this pass could not tie to the request (typically a DB read of unbounded size) — ${unscopedFanOuts} such site${unscopedFanOuts === 1 ? "" : "s"}, left unflagged to hold precision; (3) retry by RECURSION (a helper calling itself on failure) rather than by a loop — no loop node exists to bound, and no count is available for it; (4) a loop whose real cap lives in the BODY (a counter incremented then \`break\`-ed on, a flag the catch sets) rather than in the header — this pass reads the header only, so it errs LOUD and reports such a loop as uncapped: ${headerOnlyBounds} of the retry loops reported above ${headerOnlyBounds === 1 ? "has" : "have"} a non-literal header and may carry a body-side bound.`,
      impact: "These four sub-shapes are not fully assessed on this target. Recorded explicitly with their counts so the absence of a retry/fan-out finding reads as 'partially assessed', not 'assessed and clean' — the fail-loud coverage guard.",
      fix: "None — informational. Review the counted sites by hand: confirm each library retry declares a maximum-attempts option, each unscoped fan-out runs over a collection whose size the service controls, and each header-unbounded loop reported above really does terminate on the failure path.",
      value: 1,
      ease: 5,
      safety: 5,
      precisionTier: "high",
    },
  ];
}

// --- Route segment config & missing Suspense [MED] (#846) -------------------
//
// Next.js route segment config (`export const dynamic / revalidate / fetchCache / runtime`) governs
// how a route renders and caches. Two failure modes carry real correctness/security weight:
//   (a) `dynamic = "force-static"` on a route that reads auth/session or a dynamic API — the
//       personalized page is frozen into the static cache and served to everyone (stale, and a
//       cross-user isolation bug), or would build-error on the dynamic read.
//   (b) contradictory config — `force-dynamic` with a positive `revalidate` (revalidate is dead),
//       or `force-static` with `revalidate = 0` (force-static caches forever) — a config whose two
//       halves cancel, so the author's intent is silently not what ships.
// Separately, a page that reads a dynamic API and fetches data with NO `<Suspense>` boundary
// forgoes streaming/PPR: the whole route blocks on the dynamic work instead of streaming a static
// shell first.
const ROUTE_SEGMENT_FILE = /\/(page|layout|route)\.[cm]?[jt]sx?$/;

interface SegmentConfig {
  dynamic?: string;
  dynamicNode?: ts.Node;
  revalidate?: number | "false";
  revalidateNode?: ts.Node;
}

function collectSegmentConfig(sf: ts.SourceFile): SegmentConfig {
  const cfg: SegmentConfig = {};
  for (const stmt of sf.statements) {
    if (!ts.isVariableStatement(stmt) || !stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
    for (const decl of stmt.declarationList.declarations) {
      if (!ts.isIdentifier(decl.name) || !decl.initializer) continue;
      if (decl.name.text === "dynamic" && ts.isStringLiteral(decl.initializer)) {
        cfg.dynamic = decl.initializer.text;
        cfg.dynamicNode = decl.initializer;
      } else if (decl.name.text === "revalidate") {
        if (ts.isNumericLiteral(decl.initializer)) {
          cfg.revalidate = Number(decl.initializer.text);
          cfg.revalidateNode = decl.initializer;
        } else if (decl.initializer.kind === ts.SyntaxKind.FalseKeyword) {
          cfg.revalidate = "false";
          cfg.revalidateNode = decl.initializer;
        }
      }
    }
  }
  return cfg;
}

function detectRouteSegmentConfig(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (leadingDirective(sf) === "use client") continue;
    if (!ROUTE_SEGMENT_FILE.test(path)) continue;
    const cfg = collectSegmentConfig(sf);
    if (cfg.dynamic === undefined && cfg.revalidate === undefined) continue;

    if (cfg.dynamic === "force-static") {
      const dyn = readsDynamicApi(sf);
      const authed = AUTH_PATTERN.test(sf.text);
      if (dyn || authed) {
        const why = dyn ? "reads a dynamic API (cookies/headers/searchParams)" : "checks the caller's session/auth";
        findings.push(
          makeFinding(nextId, {
            title: `\`dynamic = "force-static"\` on a route that ${dyn ? "reads dynamic data" : "is auth-gated"}`,
            severity: "High",
            confidence: "Review",
            category: "Security",
            taxonomy: "M9 — Unsafe route segment config",
            location: loc(path, sf, cfg.dynamicNode ?? sf),
            evidence: `This route sets \`export const dynamic = "force-static"\` yet ${why}. Force-static renders once at build and serves the same cached HTML to every request.`,
            impact: "A personalized/auth-scoped page is frozen into the static cache and served to all users — stale at best, one user's data leaking to others at worst — or the build errors on the dynamic read.",
            fix: `Remove \`force-static\` (let the route render dynamically), or if the page really is public and static, stop reading the per-request/auth data here.`,
            value: 5,
            ease: 4,
            safety: 4,
          }),
        );
      }
    }

    const conflict =
      cfg.dynamic === "force-dynamic" && typeof cfg.revalidate === "number" && cfg.revalidate > 0
        ? `\`dynamic = "force-dynamic"\` never caches, so \`revalidate = ${cfg.revalidate}\` is dead config`
        : cfg.dynamic === "force-static" && cfg.revalidate === 0
          ? `\`dynamic = "force-static"\` caches indefinitely, so \`revalidate = 0\` (always revalidate) is contradictory`
          : undefined;
    if (conflict) {
      findings.push(
        makeFinding(nextId, {
          title: `Conflicting route segment config (\`dynamic\` vs \`revalidate\`)`,
          severity: "Medium",
          confidence: "Review",
          category: "Performance",
          taxonomy: "M9 — Conflicting route segment config",
          location: loc(path, sf, cfg.revalidateNode ?? cfg.dynamicNode ?? sf),
          evidence: `${conflict} — the two settings cancel, so this route does not render/cache the way the config reads.`,
          impact: "The route's actual caching behaviour is not what the config states, so a perf/freshness decision is silently ineffective.",
          fix: "Keep the setting that expresses the intent and remove the one it overrides.",
          value: 3,
          ease: 5,
          safety: 5,
        }),
      );
    }
  }
  return findings;
}

function fileHasSuspense(sf: ts.SourceFile): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
      const tag = node.tagName.getText(sf);
      if (tag === "Suspense" || tag.endsWith(".Suspense")) found = true;
    }
    if (!found) ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

function hasAsyncDataFetch(sf: ts.SourceFile): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isAwaitExpression(node) && ts.isCallExpression(node.expression)) {
      const call = node.expression;
      if (isDbQueryChain(call) || (ts.isIdentifier(call.expression) && call.expression.text === "fetch")) found = true;
    }
    if (!found) ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

function detectMissingSuspenseBoundary(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (leadingDirective(sf) === "use client") continue;
    if (!/\/(page|layout)\.[cm]?[jt]sx?$/.test(path)) continue;
    // Only meaningful when a dynamic read AND real async data-fetching coexist with no boundary —
    // that's the case where a static shell could stream while the dynamic data resolves.
    if (!readsDynamicApi(sf) || !hasAsyncDataFetch(sf) || fileHasSuspense(sf)) continue;

    findings.push(
      makeFinding(nextId, {
        title: `Dynamic read + data fetch with no <Suspense> boundary`,
        severity: "Low",
        confidence: "Review",
        category: "Performance",
        taxonomy: "M9 — Missing Suspense boundary",
        location: path,
        evidence: `${path} reads a dynamic API and awaits data yet renders no \`<Suspense>\` boundary — the whole route blocks on the dynamic work instead of streaming a static shell first.`,
        impact: "Without a Suspense boundary the route can't partially prerender or stream: the user waits for all server data before seeing anything, and the static parts can't be cached separately.",
        fix: "Wrap the dynamic-data subtree in a `<Suspense fallback={…}>` boundary so the static shell renders immediately and the dynamic part streams in.",
        value: 3,
        ease: 3,
        safety: 5,
      }),
    );
  }
  return findings;
}

// --- Non-Supabase data-layer coverage (#844) --------------------------------
//
// The three data-layer checks — server→client leak, unsafe/missing cache config, data-fetching
// waterfall — key on Supabase call shapes (`.from().select()`, `.insert/.update/.upsert/.delete/
// .rpc`). On a Prisma/Drizzle/raw-SQL target those shapes never appear, so the checks find nothing
// AND say nothing — a silent third of M9 gone on the Prisma support Harvey now advertises (#756).
// When the data layer is a recognized non-Supabase ORM we skip those three checks and emit one
// explicit "not assessed — ORM/data-layer unsupported" row each, so the absence reads as a
// disclosed limitation, not a clean bill of health (the coverage-guard principle in CLAUDE.md).
//
// `orm` (from detectOrm) names the layer; callers that don't detect one fall back to the same
// dependency-list recogniser. A genuinely unknown/no-DB target draws nothing — the note fires only
// on a POSITIVELY identified non-Supabase data access, never on a plain app that simply has no
// queries. A raw-SQL target (node-postgres/postgres.js and friends, no ORM at all) is that same
// positive signal via its declared driver dependency — the #861 remainder of #844.
const DATA_LAYER_CHECKS: { taxonomy: string; check: string }[] = [
  { taxonomy: "M9 — Server→client data leak", check: "server→client data leak (full DB row passed to a Client Component)" },
  { taxonomy: "M9 — Unsafe/missing cache config", check: "unsafe/missing cache config on data-fetching routes" },
  { taxonomy: "M9 — Data-fetching waterfall", check: "data-fetching waterfall (independent sequential queries)" },
];

function nonSupabaseDataLayer(orm: TargetOrm | undefined, files: SourceInput[]): string | undefined {
  const pkg = files.find((f) => /(^|\/)package\.json$/.test(f.path))?.text;
  // With no detected `orm` (tests/legacy callers) fall back to the dependency list, which resolves
  // Supabase ahead of everything else exactly as detectOrm does — a Supabase app that also ships
  // `pg`/Drizzle keeps its real Supabase-shaped checks instead of trading them for a not-assessed row.
  const layer = orm && orm !== "unknown" ? orm : recogniseDataLayer(pkg);
  if (layer === "supabase" || layer === "unknown") return undefined;
  if (layer === "raw-sql") {
    const driver = rawSqlDriver(pkg);
    return driver ? `raw SQL (${driver})` : ORM_LABELS["raw-sql"];
  }
  return ORM_LABELS[layer];
}

function dataLayerNotAssessed(nextId: NextId, layer: string): Finding[] {
  return DATA_LAYER_CHECKS.map(({ taxonomy, check }) => ({
    id: nextId(),
    title: `M9 not assessed — ${check} (data layer: ${layer})`,
    severity: "Info" as const,
    confidence: "N/A" as const,
    category: "Performance" as const,
    taxonomy: `${taxonomy} — not assessed`,
    location: "(whole target)",
    status: "Open" as const,
    evidence: `This check recognizes Supabase call shapes (\`.from().select()\`, \`.insert/.update/.upsert/.delete/.rpc\`), but the target's data layer is \`${layer}\`. It was NOT assessed rather than reported clean — a Prisma/Drizzle/raw-SQL query is invisible to the current Supabase-shaped matcher.`,
    impact: "This M9 data-layer surface is unassessed on this target. Recorded explicitly so its absence reads as 'not assessed here', not 'assessed and clean' — the fail-loud coverage guard.",
    fix: `None — informational. Manual review still applies; native ${layer} support for this check is tracked follow-up.`,
    value: 1,
    ease: 5,
    safety: 5,
    precisionTier: "high" as const,
  }));
}

// The Next.js App Router adapter — the boundary model's original and reference implementation
// (#916). Its markers ARE the Next literals the module was built on: a client context is a
// `"use client"` module, a server mutation is a `"use server"` function (collectServerActions), and
// a server→client crossing is a raw row passed as a JSX prop into an imported Client Component. It
// supports every check, so runBoundaryPass over it reproduces the pre-refactor Next output exactly.
const NEXT_CHECKS: readonly M9Check[] = [
  "server-client-leak",
  "server-mutation-authz",
  "server-mutation-validation",
  "client-owner-id",
  "ssr-browser-api",
  "data-waterfall",
  "missing-server-only",
  "accidental-dynamic",
  "cache-config",
  "cache-bleed",
  "route-segment-config",
  "missing-suspense",
  "unbounded-route",
  "uncapped-retry",
];

const nextAdapter: BoundaryAdapter = {
  framework: "next",
  label: FRAMEWORK_LABELS.next,
  supports: new Set(NEXT_CHECKS),
  mutationNoun: "Server Action",
  isClientContext: (sf) => leadingDirective(sf) === "use client",
  detectServerClientLeak: (sources, nextId, files) => detectServerClientLeak(sources, nextId, collectPathAliases(files)),
  serverMutations: (_path, sf) => collectServerActions(sf),
};

// The generic boundary pass: runs each M9 check the adapter's `supports` set enables, expressed
// against the adapter's markers rather than Next literals, and discloses every check the adapter
// does NOT implement as a not-assessed row naming it (fail loud). For the Next adapter (supports
// all) this is behaviour-identical to the pre-#916 runAppRouterPass.
function runBoundaryPass(adapter: BoundaryAdapter, files: SourceInput[], nextId: NextId, orm?: TargetOrm, scope = "(whole target)"): Finding[] {
  const sources = new Map(files.map((f) => [f.path, parse(f.path, f.text)]));
  const pagesRouterOnly = isPagesRouterOnly(files);
  const otherDataLayer = nonSupabaseDataLayer(orm, files);
  const S = adapter.supports;
  const mutations = (path: string, sf: ts.SourceFile) => adapter.serverMutations(path, sf);

  // Owner-id runs first: its subsumed-action set feeds the missing-auth dedupe (#465).
  const ownerId = S.has("client-owner-id")
    ? detectClientSuppliedOwnerId(sources, nextId, mutations, adapter.mutationNoun, collectPathAliases(files))
    : { findings: [] as Finding[], subsumedNoAuthActions: new Set<ts.Node>() };

  // The three Supabase-shaped data-layer checks run only on a Supabase/unknown data layer; on a
  // recognized non-Supabase ORM they are replaced by explicit not-assessed rows (#844).
  const dataLayer = otherDataLayer
    ? dataLayerNotAssessed(nextId, otherDataLayer)
    : [
        ...(S.has("server-client-leak") ? adapter.detectServerClientLeak(sources, nextId, files) : []),
        ...(S.has("cache-config") ? detectUnsafeCacheConfig(sources, nextId) : []),
        ...(S.has("data-waterfall") ? detectDataFetchingWaterfalls(sources, nextId, adapter.isClientContext, collectPathAliases(files)) : []),
      ];

  const out: Finding[] = [
    ...dataLayer,
    ...(S.has("missing-server-only") ? detectMissingServerOnly(sources, nextId, pagesRouterOnly, collectPathAliases(files)) : []),
    ...(S.has("server-mutation-authz") || S.has("server-mutation-validation")
      ? detectServerActionAuthAndValidation(sources, nextId, ownerId.subsumedNoAuthActions, mutations, adapter.mutationNoun, collectPathAliases(files))
      : []),
    ...ownerId.findings,
    // Not ORM-gated with the three data-layer checks above: it keys on the auth + cache signals,
    // not on Supabase call shapes, so it stays live on a Prisma/Drizzle/raw-SQL target.
    ...(S.has("cache-bleed") ? detectCrossUserCacheBleed(sources, nextId) : []),
    ...(S.has("accidental-dynamic") ? detectAccidentalDynamicRendering(sources, nextId) : []),
    ...(S.has("ssr-browser-api") ? detectSsrBrowserApiMisuse(sources, nextId, collectPathAliases(files)) : []),
    ...(S.has("unbounded-route") ? detectUnboundedRouteOrEdge(sources, nextId) : []),
    ...(S.has("uncapped-retry") ? [...detectUncappedRetryFanOut(sources, nextId), ...uncappedRetryScopeNote(sources, nextId)] : []),
    ...(S.has("route-segment-config") ? detectRouteSegmentConfig(sources, nextId) : []),
    ...(S.has("missing-suspense") ? detectMissingSuspenseBoundary(sources, nextId) : []),
  ];

  // Disclose every check this framework's adapter does not implement — partial coverage is stated,
  // never silently upgraded to full (the coverage guard).
  for (const c of NEXT_CHECKS) if (!S.has(c)) out.push(notAssessedCheckNote(nextId, adapter, c, scope));
  return out;
}

// --- Orchestrator ------------------------------------------------------------

/**
 * Runs all M9 App Router checks over the given source set and returns
 * Finding[] (src/findings.ts). `files` should be a project's full set of
 * relevant .ts/.tsx sources — the server→client leak check needs sibling
 * files to resolve which imported components are Client Components.
 *
 * `framework` (from src/scan/framework-detect.ts) gates the whole pass: on a Vite/SPA target the
 * App-Router surface does not exist, so the App-Router family is suppressed to a single N/A
 * coverage note (#575), plus the one SPA-specific resilience check that DOES apply there — the
 * missing-root-error-boundary detector (#627). Remix, React Router 7 and TanStack Start route to
 * their own boundary-model adapters (#916/#917/#918): the portable checks (server→client leak,
 * server-mutation authz + input-validation, client-owner-id, SSR misuse, waterfall) run, and every
 * check the adapter does not implement is disclosed as a not-assessed row naming it. Astro,
 * SvelteKit and Nuxt have no adapter yet and stay suppressed with a not-assessed note (#872) —
 * `other` must never mean "analysed and clean". Omitted (tests/legacy callers) or `next`/`other` →
 * run the full Next pass.
 *
 * `nonNextWorkspaces` (workspace dir + its framework, e.g. `[{ rel: "apps/web", framework: "vite" }]`)
 * makes the gate monorepo-aware (#597): at a monorepo root the root's own verdict is `other`
 * (vite.config lives in the app dir), so the whole-target short-circuit never fires and the SSR
 * family false-fires on that app's files. Files under any of these prefixes are suppressed (one
 * coverage note per workspace, plus the #627 root-error-boundary check on a Vite workspace's files),
 * and the full pass runs over the remaining files — a genuine Next workspace in the same monorepo is
 * unaffected. Empty (single-app targets, tests) → behaves exactly as before.
 *
 * `orm` (from src/scan/framework-detect.ts `detectOrm`) gates the three Supabase-shaped data-layer
 * checks (server→client leak, cache config, waterfall): on a recognized non-Supabase data layer
 * (Prisma/Drizzle/Kysely) they are replaced by explicit not-assessed rows rather than silently
 * finding nothing (#844). Omitted/`unknown`/`supabase` → run those checks as before.
 */
export function detectAppRouterFindings(
  files: SourceInput[],
  framework?: TargetFramework,
  nonNextWorkspaces: WorkspaceFramework[] = [],
  orm?: TargetOrm,
): Finding[] {
  let n = 0;
  const nextId: NextId = () => `M9-${String(++n).padStart(2, "0")}`;
  const inScope = (w: WorkspaceFramework) => (f: SourceInput) => f.path === w.rel || f.path.startsWith(`${w.rel}/`);

  if (isViteTooling(framework)) {
    const adapter = selectAdapter(framework!);
    if (adapter) return runBoundaryPass(adapter, files, nextId, orm);
    return unanalysableFramework(files, nextId, framework!, "(whole target)");
  }

  const active = nonNextWorkspaces.filter((w) => files.some(inScope(w)));
  const workspaceNotes = active.flatMap((w) => unanalysableFramework(files.filter(inScope(w)), nextId, w.framework, w.rel));
  const scoped = active.length ? files.filter((f) => !active.some((w) => inScope(w)(f))) : files;

  return [...workspaceNotes, ...runBoundaryPass(nextAdapter, scoped, nextId, orm)];
}

// The non-Next boundary-model adapters (#917/#918). Remix and React Router 7 share one adapter
// (RR7 absorbed Remix's loader/action model); TanStack Start has its own (`createServerFn`). Astro,
// SvelteKit and Nuxt have no adapter yet → undefined → the #872 not-assessed note.
function selectAdapter(framework: TargetFramework): BoundaryAdapter | undefined {
  switch (framework) {
    case "remix":
    case "react-router":
      return remixAdapter(framework);
    case "tanstack-start":
      return tanstackAdapter;
    default:
      return undefined;
  }
}
