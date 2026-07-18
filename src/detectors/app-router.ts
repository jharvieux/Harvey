// M9 — Next.js App Router boundary & rendering. Static AST checks over
// TypeScript/TSX source for the App-Router-specific security/perf surface
// generic tools miss (docs/scan-extras.txt, M9 section). Shapes results as
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
import type { TargetFramework } from "../scan/framework-detect.js";
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

export type { SourceInput } from "./common.js";
const VALIDATION_PATTERN = /\.safeParse\(|(?<!JSON)\.parse\(|\bzod\b|valibot|\byup\.|\bajv\b/i;
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

function makeFinding(
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
interface PathAlias {
  prefix: string;
  baseDir: string;
}

// Parse the source set's tsconfig/jsconfig for `paths` aliases (#380). The shallowest config in
// the set wins (the repo-root tsconfig defines the app-wide alias); ts.parseConfigFileTextToJson
// tolerates the comments/trailing commas tsconfig commonly carries. With no config paths in the
// set, fall back to Next.js's own `@/*`→root default rather than giving up — the vast majority of
// otherwise-unresolved specifiers are exactly that scaffolding default.
function collectPathAliases(files: SourceInput[]): PathAlias[] {
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

function resolveImport(fromPath: string, specifier: string, allPaths: Set<string>, aliases: PathAlias[]): string | undefined {
  return resolveRelativeImport(fromPath, specifier, allPaths) ?? resolveAliasedImport(specifier, allPaths, aliases);
}

function collectRawRowNames(sf: ts.SourceFile): Set<string> {
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
            } else if (
              ts.isJsxAttribute(attr) &&
              attr.initializer &&
              ts.isJsxExpression(attr.initializer) &&
              attr.initializer.expression &&
              ts.isIdentifier(attr.initializer.expression) &&
              rawRowNames.has(attr.initializer.expression.text)
            ) {
              flagAttr(attr, tagName, `${attr.name.getText(sf)}={${attr.initializer.expression.text}}`);
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

function detectClientSuppliedOwnerId(sources: Map<string, ts.SourceFile>, nextId: NextId): ClientOwnerIdResult {
  const findings: Finding[] = [];
  const subsumedNoAuthActions = new Set<ts.Node>();
  for (const [path, sf] of sources) {
    for (const action of collectServerActions(sf)) {
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
              ? `Server Action \`${action.name}\` mutates rows scoped by a client-supplied \`${site.column}\`${hasAuth ? "" : " with no auth check"}`
              : `Server Action \`${action.name}\` writes rows owned by a client-supplied \`${site.column}\`${hasAuth ? "" : " with no auth check"}`,
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

function detectServerActionAuthAndValidation(sources: Map<string, ts.SourceFile>, nextId: NextId, subsumedNoAuthActions: ReadonlySet<ts.Node>): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    for (const action of collectServerActions(sf)) {
      const text = sf.text.slice(action.node.getStart(sf), action.node.getEnd());
      if (!isDbMutationChain(text)) continue; // scope to mutating actions per the brief

      // The client-supplied-owner-id detector already fired on this no-auth action with a
      // strictly more specific finding (its evidence carries the no-auth fact) — one code
      // defect, one finding (#465).
      if (!AUTH_PATTERN.test(text) && !subsumedNoAuthActions.has(action.node)) {
        findings.push(
          makeFinding(nextId, {
            title: `Server Action \`${action.name}\` mutates data with no visible auth check`,
            severity: "High",
            confidence: "Likely",
            category: "Security",
            // Routed to the M1 authorization/client-input-trust class (#221), not scored as
            // M9 rendering — a Server Action with no auth check is a broken-function-level-authz
            // finding, the same class as the other three instances #221 catalogs.
            taxonomy: "M1 — Server Action missing authorization check",
            location: loc(path, sf, action.node),
            evidence: `\`${action.name}\` is a Server Action ('use server') that calls insert/update/upsert/delete/rpc with no session/authority check found in its body.`,
            impact: "Server Actions are public POST endpoints — invocable directly with a crafted request regardless of which page normally calls them. Anyone can trigger this mutation.",
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
            title: `Server Action \`${action.name}\` has no input schema validation`,
            severity: "High",
            confidence: "Likely",
            category: "Security",
            taxonomy: "M9 — Server Action missing input validation",
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

function detectDataFetchingWaterfalls(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (leadingDirective(sf) === "use client") continue;

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
// docs/scan-extras.txt M9 "SSR-ONLY API MISUSE"). App Router components server-render by
// default, so the read fires on the server unless it is deferred to the browser. The two
// standard SSR-safe idioms are the FP boundary and must stay silent:
//   - inside a useEffect/useLayoutEffect callback or an event handler (browser-only, deferred),
//   - guarded by `typeof window !== "undefined"` (or any browser global).
const BROWSER_GLOBALS = new Set(["window", "document", "localStorage", "sessionStorage", "navigator"]);
const TYPEOF_GUARD = /typeof\s+(window|document|localStorage|sessionStorage|navigator)\b/;

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
//   0 enclosing functions → module top-level: runs during SSR → on path.
//   1, and it's a free function / arrow → a component or module-level helper render body → on path.
//   1, but it's a CLASS MEMBER (method/accessor/ctor) → not the App Router render path but an
//     OO/framework lifecycle method (e.g. a Lexical node's client-only `createDOM`) → off path.
//   ≥2 → nested in a deferred closure (effect callback, event handler) → off path.
function isOnSsrRenderPath(node: ts.Node): boolean {
  const fns: ts.Node[] = [];
  for (let cur = node.parent; cur; cur = cur.parent) {
    if (isFunctionScope(cur)) fns.push(cur);
  }
  if (fns.length >= 2) return false;
  const nearest = fns[0];
  if (nearest && (ts.isMethodDeclaration(nearest) || ts.isConstructorDeclaration(nearest) || ts.isGetAccessorDeclaration(nearest) || ts.isSetAccessorDeclaration(nearest))) {
    return false;
  }
  return true;
}

// True when a `typeof <global>` check gates this node — an enclosing `if`, ternary, or `&&`/`||`
// whose condition/left operand tests a browser global. The standard SSR-safe guard.
function isTypeofGuarded(node: ts.Node, sf: ts.SourceFile): boolean {
  for (let cur = node.parent; cur; cur = cur.parent) {
    if (ts.isIfStatement(cur) && TYPEOF_GUARD.test(cur.expression.getText(sf))) return true;
    if (ts.isConditionalExpression(cur) && TYPEOF_GUARD.test(cur.condition.getText(sf))) return true;
    if (
      ts.isBinaryExpression(cur) &&
      (cur.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken || cur.operatorToken.kind === ts.SyntaxKind.BarBarToken) &&
      TYPEOF_GUARD.test(cur.left.getText(sf))
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
        if (isOnSsrRenderPath(node) && !isTypeofGuarded(node, sf)) {
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
function nonSsrSpaCoverageNote(nextId: NextId, framework: TargetFramework): Finding {
  return {
    id: nextId(),
    title: "M9 N/A — non-SSR SPA",
    severity: "Info",
    confidence: "N/A",
    category: "Performance",
    taxonomy: "M9 — Not applicable (non-Next SPA)",
    location: "(whole target)",
    status: "Open",
    evidence: `Target framework detected as \`${framework}\` — a non-Next single-page app. M9's App Router checks (SSR browser-API misuse, server→client leak, \`server-only\` guard, Server Action auth/validation, cache/dynamic-rendering) all assume Next.js server-rendering by default and do not apply: a Vite/SPA build has no SSR render path, no Server Actions, and no RSC server→client boundary.`,
    impact: "M9 App Router coverage is not applicable to this target. Recorded explicitly so the absence of M9 findings reads as 'not applicable here', not 'assessed and clean'.",
    fix: "None — informational. If this target is in fact a Next.js app, verify framework detection (its `vite.config` / package.json `next` dependency).",
    value: 1,
    ease: 5,
    safety: 5,
    precisionTier: "high",
  };
}

// --- Orchestrator ------------------------------------------------------------

/**
 * Runs all M9 App Router checks over the given source set and returns
 * Finding[] (src/findings.ts). `files` should be a project's full set of
 * relevant .ts/.tsx sources — the server→client leak check needs sibling
 * files to resolve which imported components are Client Components.
 *
 * `framework` (from src/scan/framework-detect.ts) gates the whole pass: on a Vite/SPA target the
 * App-Router surface does not exist, so M9 is suppressed to a single N/A coverage note (#575).
 * Omitted (tests/legacy callers) or `next`/`other` → run the full pass as before.
 */
export function detectAppRouterFindings(files: SourceInput[], framework?: TargetFramework): Finding[] {
  let n = 0;
  const nextId: NextId = () => `M9-${String(++n).padStart(2, "0")}`;

  if (framework === "vite") return [nonSsrSpaCoverageNote(nextId, framework)];

  const sources = new Map(files.map((f) => [f.path, parse(f.path, f.text)]));
  const pagesRouterOnly = isPagesRouterOnly(files);
  const aliases = collectPathAliases(files);

  // Owner-id runs first: its subsumed-action set feeds the missing-auth dedupe (#465).
  const ownerId = detectClientSuppliedOwnerId(sources, nextId);
  return [
    ...detectServerClientLeak(sources, nextId, aliases),
    ...detectMissingServerOnly(sources, nextId, pagesRouterOnly, aliases),
    ...detectServerActionAuthAndValidation(sources, nextId, ownerId.subsumedNoAuthActions),
    ...ownerId.findings,
    ...detectUnsafeCacheConfig(sources, nextId),
    ...detectDataFetchingWaterfalls(sources, nextId),
    ...detectAccidentalDynamicRendering(sources, nextId),
    ...detectSsrBrowserApiMisuse(sources, nextId),
  ];
}
