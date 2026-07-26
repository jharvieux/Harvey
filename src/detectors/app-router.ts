// M9 — Next.js App Router boundary & rendering. Static AST checks over
// TypeScript/TSX source for the App-Router-specific security/perf surface
// generic tools miss (briefs/scan-extras.txt, M9 section). Shapes results as
// Finding[] (src/findings.ts) for §3 (security) / §3b (performance).
//
// Method: TypeScript compiler API (already a devDependency; no ts-morph in
// this repo). Cross-file resolution (server→client leak, server-only graph)
// follows both relative imports and tsconfig/jsconfig `paths` aliases
// (`@/components/...`), falling back to the create-next-app `@/*`→root default
// when no config is present (#380). See docs/m9-app-router.md for full
// per-check limitations.

import ts from "typescript";
import type { Finding } from "../findings.js";
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

function isDbQueryChain(node: ts.Expression): boolean {
  const names = callChainNames(node);
  return names.includes("from") && names.includes("select");
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

function candidatePaths(base: string): string[] {
  return [base, `${base}.tsx`, `${base}.ts`, `${base}/index.tsx`, `${base}/index.ts`];
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
}

// Parse the source set's tsconfig/jsconfig for `paths` aliases (#380). The shallowest config in
// the set wins (the repo-root tsconfig defines the app-wide alias); ts.parseConfigFileTextToJson
// tolerates the comments/trailing commas tsconfig commonly carries. With no config paths in the
// set, fall back to Next.js's own `@/*`→root default rather than giving up — the vast majority of
// otherwise-unresolved specifiers are exactly that scaffolding default.
export function collectPathAliases(files: SourceInput[]): PathAlias[] {
  const configs = files
    .filter((f) => /(^|\/)(tsconfig|jsconfig)\.json$/.test(f.path))
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
      aliases.push({ prefix: key.slice(0, -1), baseDir: normalizeRepoPath(`${cfgDir}/${baseUrl}/${target.slice(0, -1)}`) });
    }
    if (aliases.length > 0) break;
  }
  if (aliases.length === 0) aliases.push({ prefix: "@/", baseDir: "" });
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

function resolveAliasedImport(specifier: string, allPaths: Set<string>, aliases: PathAlias[]): string | undefined {
  for (const { prefix, baseDir } of aliases) {
    if (!specifier.startsWith(prefix)) continue;
    const rest = specifier.slice(prefix.length);
    const base = normalizeRepoPath(baseDir ? `${baseDir}/${rest}` : rest);
    const hit = candidatePaths(base).find((c) => allPaths.has(c));
    if (hit) return hit;
  }
  return undefined;
}

export function resolveImport(fromPath: string, specifier: string, allPaths: Set<string>, aliases: PathAlias[]): string | undefined {
  return resolveRelativeImport(fromPath, specifier, allPaths) ?? resolveAliasedImport(specifier, allPaths, aliases);
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
export function collectRawRowNames(sf: ts.SourceFile): Set<string> {
  const rawRowNames = new Set<string>();
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const init = ts.isAwaitExpression(node.initializer) ? node.initializer.expression : node.initializer;
      if (ts.isCallExpression(init) && isDbQueryChain(init)) {
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

const SERVER_ONLY_EXEMPT_PATTERN = /(^|\/)(route\.tsx?|middleware\.ts)$/;

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

// Whether some 'use client' file, following relative imports transitively, actually reaches
// `targetPath` — the real bundling risk the server-only guard defends against. #231: every
// raw hit in the 6-repo triage was already shielded by the next/headers barrier or the 'use
// server' boundary because nothing imported the module from client code at all; only a real
// import path from a Client Component makes the missing guard an actual finding.
function hasRealClientImportPath(targetPath: string, importGraph: ReadonlyMap<string, string[]>, clientPaths: ReadonlySet<string>): boolean {
  const visited = new Set<string>();
  const queue = [...clientPaths];
  while (queue.length > 0) {
    const cur = queue.shift();
    if (cur === undefined || visited.has(cur)) continue;
    if (cur === targetPath) return true;
    visited.add(cur);
    queue.push(...(importGraph.get(cur) ?? []));
  }
  return false;
}

function buildImportGraph(sources: Map<string, ts.SourceFile>, allPaths: Set<string>, aliases: PathAlias[]): Map<string, string[]> {
  const graph = new Map<string, string[]>();
  for (const [path, sf] of sources) {
    const edges: string[] = [];
    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
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
  const importGraph = buildImportGraph(sources, allPaths, aliases);

  for (const [path, sf] of sources) {
    if (leadingDirective(sf) !== undefined) continue; // 'use client' can't hold secrets like this meaningfully; 'use server' modules are already server-exclusive by the Next compiler
    if (SERVER_ONLY_EXEMPT_PATTERN.test(path)) continue; // route handlers / middleware are already server-exclusive by Next.js routing convention
    if (hasServerOnlyImport(sf)) continue;
    const secretNode = findSecretEnvAccess(sf);
    if (!secretNode) continue;
    if (!hasRealClientImportPath(path, importGraph, clientPaths)) continue; // nothing on the client side imports this module — no bundling risk to guard against

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
// The broad class (#221's items 2 and 3 — trusting client-supplied prices/roles/trials, and
// UI-only permission gates) still needs cross-file and business-context reasoning and stays
// semantic/paid-tier: see the B15 corpus entries and docs/design/corpus-roadmap-to-100.md §4a.
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

function detectClientSuppliedOwnerId(
  sources: Map<string, ts.SourceFile>,
  nextId: NextId,
  mutationsFor: (path: string, sf: ts.SourceFile) => ServerMutation[],
  noun: string,
): ClientOwnerIdResult {
  const findings: Finding[] = [];
  const subsumedNoAuthActions = new Set<ts.Node>();
  for (const [path, sf] of sources) {
    for (const action of mutationsFor(path, sf)) {
      const text = sf.text.slice(action.node.getStart(sf), action.node.getEnd());
      if (!isDbMutationChain(text)) continue;

      const hasAuth = AUTH_PATTERN.test(text);
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
            : `\`${action.name}\` makes no auth/session call at all and runs on the service-role client (RLS bypassed), deciding which row it writes with \`${siteText}\` on a value from its own arguments. Nothing anywhere checks the caller may touch that row.`,
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

function detectServerActionAuthAndValidation(
  sources: Map<string, ts.SourceFile>,
  nextId: NextId,
  subsumedNoAuthActions: ReadonlySet<ts.Node>,
  mutationsFor: (path: string, sf: ts.SourceFile) => ServerMutation[],
  noun: string,
): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    for (const action of mutationsFor(path, sf)) {
      const text = stripLiteralsAndComments(sf, action.node);
      if (!isDbMutationChain(text)) continue; // scope to mutating actions per the brief

      // The client-supplied-owner-id detector already fired on this no-auth action with a
      // strictly more specific finding (its evidence carries the no-auth fact) — one code
      // defect, one finding (#465).
      if (!AUTH_PATTERN.test(text) && !subsumedNoAuthActions.has(action.node)) {
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
            evidence: `\`${action.name}\` is a ${noun} that calls insert/update/upsert/delete/rpc with no session/authority check found in its body.`,
            impact: `${noun}s are public POST endpoints — invocable directly with a crafted request regardless of which page normally calls them. Anyone can trigger this mutation.`,
            fix: "Verify the caller's session/tenant before the DB call (e.g. `auth.getUser()` + a tenant-scoped `.eq(...)`, or a shared `requireUser()`/`assertPermission()` gate).",
            value: 5,
            ease: 3,
            safety: 4,
          }),
        );
      }

      if (!VALIDATION_PATTERN.test(text)) {
        findings.push(
          makeFinding(nextId, {
            title: `${noun} \`${action.name}\` has no input schema validation`,
            severity: "High",
            confidence: "Likely",
            category: "Security",
            taxonomy: `M9 — ${noun} missing input validation`,
            location: loc(path, sf, action.node),
            evidence: `\`${action.name}\` reads its arguments/formData straight into a DB mutation with no Zod/valibot (or similar) \`.parse\`/\`.safeParse\` call found in its body.`,
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
    if (!/\/(page|layout)\.tsx?$/.test(path)) continue;
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
const RESPONSE_BUILDING_FILE = /(^|\/)(route\.tsx?|middleware\.tsx?)$/;

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
}

function findAwaitedDbDeclarations(block: ts.Block, sf: ts.SourceFile): AwaitedDbDeclaration[] {
  const out: AwaitedDbDeclaration[] = [];
  for (const stmt of block.statements) {
    if (!ts.isVariableStatement(stmt) || stmt.declarationList.declarations.length !== 1) continue;
    const decl = stmt.declarationList.declarations[0];
    if (!decl?.initializer || !ts.isAwaitExpression(decl.initializer)) continue;
    const call = decl.initializer.expression;
    if (!ts.isCallExpression(call) || !isDbQueryChain(call)) continue;
    const names = boundNames(decl.name);
    out.push({ displayName: names[0] ?? decl.name.getText(sf), boundNames: names, node: stmt, text: stmt.getText(sf) });
  }
  return out;
}

function detectDataFetchingWaterfalls(
  sources: Map<string, ts.SourceFile>,
  nextId: NextId,
  isClientContext: (sf: ts.SourceFile) => boolean = (sf) => leadingDirective(sf) === "use client",
): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (isClientContext(sf)) continue;

    const visit = (node: ts.Node) => {
      if ((ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)) && node.body && ts.isBlock(node.body)) {
        const decls = findAwaitedDbDeclarations(node.body, sf);
        for (let i = 0; i < decls.length - 1; i++) {
          const cur = decls[i];
          const next = decls[i + 1];
          if (!cur || !next) continue;
          if (cur.boundNames.some((n) => next.text.includes(n))) continue; // depends on the prior result — legitimately sequential
          findings.push(
            makeFinding(nextId, {
              title: `Independent sequential DB queries could run in parallel`,
              severity: "Medium",
              confidence: "Review",
              category: "Performance",
              taxonomy: "M9 — Data-fetching waterfall",
              location: loc(path, sf, next.node),
              evidence: `\`${cur.displayName}\` (${loc(path, sf, cur.node)}) and \`${next.displayName}\` (${loc(path, sf, next.node)}) are awaited sequentially and neither's query depends on the other's result.`,
              impact: "Each unrelated await serializes a network round-trip that could run concurrently, adding latency (and, compounded across requests, DB load) on every render.",
              fix: `Combine into \`Promise.all([...])\` (or a single joined query/RPC) so the round-trips overlap.`,
              value: 3,
              ease: 4,
              safety: 4,
            }),
          );
          break; // one finding per function is enough signal without piling on noise
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return findings;
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
    if (!/\/(page|layout)\.tsx?$/.test(path)) continue;

    const dynamicCall = findDynamicApiCall(sf);
    if (dynamicCall) {
      const fnName = (dynamicCall.expression as ts.Identifier).text;
      findings.push(
        makeFinding(nextId, {
          title: `\`${fnName}()\` read in ${path.endsWith("layout.tsx") ? "a layout" : "a page"} — forces dynamic rendering`,
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
    if ((ts.isVariableDeclaration(node) || ts.isParameter(node)) && ts.isIdentifier(node.name)) names.add(node.name.text);
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
function isOnSsrRenderPath(node: ts.Node, sf: ts.SourceFile): boolean {
  const fns: ts.Node[] = [];
  for (let cur = node.parent; cur; cur = cur.parent) {
    if (isFunctionScope(cur)) fns.push(cur);
  }
  if (fns.length >= 2) return false;
  const nearest = fns[0];
  if (nearest) {
    if (ts.isMethodDeclaration(nearest) || ts.isConstructorDeclaration(nearest) || ts.isGetAccessorDeclaration(nearest) || ts.isSetAccessorDeclaration(nearest)) {
      return false;
    }
    if (!/\.[jt]sx$/.test(sf.fileName)) return false;
  }
  return true;
}

// True when a browser-global guard gates this node — an enclosing `if`, ternary, or `&&`/`||` whose
// condition/left operand tests a browser global via `typeof` or optional chaining (`window?.x`).
// The two standard SSR-safe guards.
function isSsrGuarded(node: ts.Node, sf: ts.SourceFile): boolean {
  const guards = (text: string) => TYPEOF_GUARD.test(text) || OPTIONAL_CHAIN_GUARD.test(text);
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

function detectSsrBrowserApiMisuse(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
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
        if (!optionalChained && isOnSsrRenderPath(node, sf) && !isSsrGuarded(node, sf)) {
          const atModuleTop = !ts.findAncestor(node.parent, isFunctionScope);
          findings.push(
            makeFinding(nextId, {
              title: `\`${global}\` read on the SSR render path`,
              severity: "Low",
              confidence: "Review",
              category: "Performance",
              taxonomy: "M9 — SSR-only API misuse",
              location: loc(path, sf, node),
              evidence: `\`${node.getText(sf)}\` is read ${atModuleTop ? "at module top level" : "in a component's render body"}, not inside a useEffect callback, an event handler, or a \`typeof ${global} !== "undefined"\` guard — so it executes during server-side rendering.`,
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
// Uncapped retry/fan-out (the third brief item) needs loop-bound + call-count reasoning past a
// precise mechanical rule and stays semantic/paid-tier — the two shapes above cover the
// mechanically-decidable core so the surface is no longer a silent gap.
const ROUTE_HANDLER_FILE = /(^|\/)(route\.tsx?|middleware\.ts)$|(^|\/)pages\/api\//;

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
const ROUTE_SEGMENT_FILE = /\/(page|layout|route)\.tsx?$/;

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
    if (!/\/(page|layout)\.tsx?$/.test(path)) continue;
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
    ? detectClientSuppliedOwnerId(sources, nextId, mutations, adapter.mutationNoun)
    : { findings: [] as Finding[], subsumedNoAuthActions: new Set<ts.Node>() };

  // The three Supabase-shaped data-layer checks run only on a Supabase/unknown data layer; on a
  // recognized non-Supabase ORM they are replaced by explicit not-assessed rows (#844).
  const dataLayer = otherDataLayer
    ? dataLayerNotAssessed(nextId, otherDataLayer)
    : [
        ...(S.has("server-client-leak") ? adapter.detectServerClientLeak(sources, nextId, files) : []),
        ...(S.has("cache-config") ? detectUnsafeCacheConfig(sources, nextId) : []),
        ...(S.has("data-waterfall") ? detectDataFetchingWaterfalls(sources, nextId, adapter.isClientContext) : []),
      ];

  const out: Finding[] = [
    ...dataLayer,
    ...(S.has("missing-server-only") ? detectMissingServerOnly(sources, nextId, pagesRouterOnly, collectPathAliases(files)) : []),
    ...(S.has("server-mutation-authz") || S.has("server-mutation-validation")
      ? detectServerActionAuthAndValidation(sources, nextId, ownerId.subsumedNoAuthActions, mutations, adapter.mutationNoun)
      : []),
    ...ownerId.findings,
    // Not ORM-gated with the three data-layer checks above: it keys on the auth + cache signals,
    // not on Supabase call shapes, so it stays live on a Prisma/Drizzle/raw-SQL target.
    ...(S.has("cache-bleed") ? detectCrossUserCacheBleed(sources, nextId) : []),
    ...(S.has("accidental-dynamic") ? detectAccidentalDynamicRendering(sources, nextId) : []),
    ...(S.has("ssr-browser-api") ? detectSsrBrowserApiMisuse(sources, nextId) : []),
    ...(S.has("unbounded-route") ? detectUnboundedRouteOrEdge(sources, nextId) : []),
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
