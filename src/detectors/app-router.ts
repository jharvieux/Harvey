// M9 — Next.js App Router boundary & rendering. Static AST checks over
// TypeScript/TSX source for the App-Router-specific security/perf surface
// generic tools miss (docs/scan-extras.txt, M9 section). Shapes results as
// Finding[] (src/findings.ts) for §3 (security) / §3b (performance).
//
// Method: TypeScript compiler API (already a devDependency; no ts-morph in
// this repo). Cross-file resolution (server→client leak) only follows
// relative imports — path-aliased imports (`@/components/...`) aren't
// resolved. See docs/m9-app-router.md for full per-check limitations.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { callChainNames, leadingDirective, loc, parse, type NextId, type SourceInput } from "./common.js";

export type { SourceInput } from "./common.js";

const AUTH_PATTERN =
  /auth\.(uid|getUser|getSession)|getServerSession|getCurrentUser|requireAuth|requireUser|requireSession|assertPermission|assertAuthorized|checkAuth|verifySession|auth\(\)/i;
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

function resolveRelativeImport(fromPath: string, specifier: string, allPaths: Set<string>): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  const fromDir = fromPath.split("/").slice(0, -1);
  const stack = [...fromDir];
  for (const part of specifier.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  const base = stack.join("/");
  const candidates = [base, `${base}.tsx`, `${base}.ts`, `${base}/index.tsx`, `${base}/index.ts`];
  return candidates.find((c) => allPaths.has(c));
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

function collectClientComponentImports(sf: ts.SourceFile, path: string, clientPaths: Set<string>, allPaths: Set<string>): Map<string, string> {
  const imports = new Map<string, string>();
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier) || !stmt.importClause) continue;
    const resolved = resolveRelativeImport(path, stmt.moduleSpecifier.text, allPaths);
    if (!resolved || !clientPaths.has(resolved)) continue;
    const clause = stmt.importClause;
    if (clause.name) imports.set(clause.name.text, resolved);
    if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const el of clause.namedBindings.elements) imports.set(el.name.text, resolved);
    }
  }
  return imports;
}

function detectServerClientLeak(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const allPaths = new Set(sources.keys());
  const clientPaths = new Set([...sources].filter(([, sf]) => leadingDirective(sf) === "use client").map(([p]) => p));

  for (const [path, sf] of sources) {
    if (leadingDirective(sf) === "use client") continue;
    const clientImports = collectClientComponentImports(sf, path, clientPaths, allPaths);
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

function buildImportGraph(sources: Map<string, ts.SourceFile>, allPaths: Set<string>): Map<string, string[]> {
  const graph = new Map<string, string[]>();
  for (const [path, sf] of sources) {
    const edges: string[] = [];
    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      const resolved = resolveRelativeImport(path, stmt.moduleSpecifier.text, allPaths);
      if (resolved) edges.push(resolved);
    }
    graph.set(path, edges);
  }
  return graph;
}

function detectMissingServerOnly(sources: Map<string, ts.SourceFile>, nextId: NextId, pagesRouterOnly: boolean): Finding[] {
  if (pagesRouterOnly) return []; // App-Router-only check (see isPagesRouterOnly)

  const findings: Finding[] = [];
  const allPaths = new Set(sources.keys());
  const clientPaths = new Set([...sources].filter(([, sf]) => leadingDirective(sf) === "use client").map(([p]) => p));
  const importGraph = buildImportGraph(sources, allPaths);

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

// --- Client-supplied owner id trusted by an authenticated action [HIGH] ----
//
// #221's narrow, mechanical half. The three proposit instances share one shape the
// missing-auth check above is blind to BY CONSTRUCTION: auth IS called, so AUTH_PATTERN
// is satisfied and nothing fires — yet the mutation is scoped by an owner id the CLIENT
// supplied, so the session is authenticated but never actually authorizes the row.
//
// Deliberately narrow (docs/fp-rules.txt: a finding must be evidence-backed). All four
// must hold: an ownership-column `.eq()` (never bare `id`), on a mutating chain, whose
// value roots in a PARAMETER of the action rather than in the session binding, and with
// no explicit ownership comparison anywhere in the body. The broad class (#221's items 2
// and 3 — trusting client-supplied prices/roles/trials, and UI-only permission gates) needs
// cross-file and business-context reasoning and stays semantic/paid-tier: see the B15
// corpus entries and docs/design/corpus-roadmap-to-100.md §4a.
//
// PRECISION IS UNMEASURED AGAINST A REAL TARGET (#221). The dogfood repos can't measure it:
// ATC and AoP contain zero 'use server' files, so this check has no surface there and its
// silence on them says nothing about its FP rate. Precision is currently pinned only by the
// corpus pair + the near-miss negatives in app-router.test.ts — i.e. by shapes we chose. That
// is why every finding here is `review`/`Likely`, never free-count. Validating it against
// proposit (the codebase the class was found in) is tracked in the #221 follow-up.
const OWNERSHIP_COLUMN = /^(user|owner|tenant|account|org|organisation|organization|customer|workspace|member|profile|created_by|author)(_id)?$/i;

// Every identifier a binding introduces: `user` → {user}; `{ data: { user } }` → {user}.
function bindingNames(name: ts.BindingName, into: Set<string>): void {
  if (ts.isIdentifier(name)) {
    into.add(name.text);
  } else if (ts.isObjectBindingPattern(name)) {
    for (const el of name.elements) bindingNames(el.name, into);
  }
}

// Names bound from an auth/session call — `const user = await getCurrentUser()`,
// `const { data: { user } } = await supabase.auth.getUser()`. A value rooted in one of
// these is server-derived and therefore trustworthy to scope a mutation by.
function collectSessionBoundNames(fn: ts.Node, sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const init = ts.isAwaitExpression(node.initializer) ? node.initializer.expression : node.initializer;
      if (AUTH_PATTERN.test(sf.text.slice(init.getStart(sf), init.getEnd()))) bindingNames(node.name, names);
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return names;
}

function collectParamRootNames(fn: ts.Node): Set<string> {
  const names = new Set<string>();
  for (const p of (fn as ts.SignatureDeclarationBase).parameters ?? []) bindingNames(p.name, names);
  return names;
}

// The identifier a property-access chain roots in: `input.userId` → "input", `userId` → "userId".
function rootIdentifier(expr: ts.Expression): string | undefined {
  let cur: ts.Expression = expr;
  while (ts.isPropertyAccessExpression(cur)) cur = cur.expression;
  return ts.isIdentifier(cur) ? cur.text : undefined;
}

// Names bound by destructuring a param root (`const { userId } = input`) or aliasing one
// (`const uid = input.userId`) — still client-supplied, just one hop from the parameter.
function collectDerivedClientNames(fn: ts.Node, clientRoots: Set<string>): Set<string> {
  const derived = new Set<string>();
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isExpression(node.initializer)) {
      const init = ts.isAwaitExpression(node.initializer) ? node.initializer.expression : node.initializer;
      // `Schema.parse(input)` keeps the client's values — validation is not authorization.
      const source = ts.isCallExpression(init) ? (init.arguments[0] ?? init.expression) : init;
      const root = ts.isExpression(source) ? rootIdentifier(source) : undefined;
      if (root && clientRoots.has(root)) bindingNames(node.name, derived);
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return derived;
}

// An explicit ownership comparison between a session-derived value and a client-supplied one
// (`if (currentUser.id !== accountId) throw`) IS the authorization check — the action is
// guarded even though the .eq() reads a client value.
function hasOwnershipComparison(fn: ts.Node, sessionNames: Set<string>, clientNames: Set<string>): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      const isEquality =
        op === ts.SyntaxKind.EqualsEqualsToken ||
        op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        op === ts.SyntaxKind.ExclamationEqualsToken ||
        op === ts.SyntaxKind.ExclamationEqualsEqualsToken;
      if (isEquality) {
        const left = rootIdentifier(node.left);
        const right = rootIdentifier(node.right);
        const sides = [left, right];
        if (sides.some((s) => s && sessionNames.has(s)) && sides.some((s) => s && clientNames.has(s))) {
          found = true;
          return;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return found;
}

interface ClientOwnerEq {
  column: string;
  node: ts.CallExpression;
}

// An `.eq("<ownership column>", <client-rooted value>)` sitting on a mutating chain.
function findClientOwnerEq(fn: ts.Node, sf: ts.SourceFile, clientNames: Set<string>): ClientOwnerEq | undefined {
  let hit: ClientOwnerEq | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "eq" && node.arguments.length === 2) {
      const [col, val] = node.arguments;
      if (col && val && ts.isStringLiteralLike(col) && OWNERSHIP_COLUMN.test(col.text)) {
        const root = rootIdentifier(val);
        // The .eq() must sit on the mutating chain itself, not on a sibling read in the
        // same action — so test the enclosing statement, falling back to the chain alone.
        const stmt = ts.findAncestor(node, ts.isExpressionStatement) ?? ts.findAncestor(node, ts.isVariableStatement) ?? node;
        const stmtText = sf.text.slice(stmt.getStart(sf), stmt.getEnd());
        if (root && clientNames.has(root) && MUTATION_PATTERN.test(stmtText)) {
          hit = { column: col.text, node };
          return;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return hit;
}

function detectClientSuppliedOwnerId(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    for (const action of collectServerActions(sf)) {
      const text = sf.text.slice(action.node.getStart(sf), action.node.getEnd());
      if (!isDbMutationChain(text)) continue;
      // No auth at all is the OTHER finding (missing authorization check) — don't double-report.
      if (!AUTH_PATTERN.test(text)) continue;

      const sessionNames = collectSessionBoundNames(action.node, sf);
      // Auth was called but nothing was bound from it (`await requireUser()` for its throw).
      // Whether the .eq() value is authorized then depends on code this AST pass can't see.
      if (sessionNames.size === 0) continue;

      const paramRoots = collectParamRootNames(action.node);
      const clientNames = new Set([...paramRoots, ...collectDerivedClientNames(action.node, paramRoots)]);
      if (clientNames.size === 0) continue;

      const eq = findClientOwnerEq(action.node, sf, clientNames);
      if (!eq) continue;
      if (hasOwnershipComparison(action.node, sessionNames, clientNames)) continue;

      const sessionName = [...sessionNames][0];
      findings.push(
        makeFinding(nextId, {
          title: `Server Action \`${action.name}\` mutates rows scoped by a client-supplied \`${eq.column}\``,
          severity: "High",
          confidence: "Likely",
          category: "Security",
          taxonomy: "M1 — Client-supplied owner id trusted by authenticated action",
          location: loc(path, sf, eq.node),
          evidence: `\`${action.name}\` authenticates the caller (binding \`${sessionName}\`) but scopes its mutation with \`.eq("${eq.column}", …)\` on a value that comes from the action's own arguments, not from \`${sessionName}\`. No comparison between the two appears in the body.`,
          impact: "The caller is authenticated but never authorized for the row: any signed-in user can pass another user's/tenant's id and mutate their data. Schema validation does not close this — a well-formed id from the wrong tenant still passes.",
          fix: `Derive the owner id from the session (\`.eq("${eq.column}", ${sessionName}.id)\`), or explicitly compare the supplied id against the session's before mutating.`,
          // Review, never free-count: the AST proves the .eq() value is client-rooted and that no
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
  return findings;
}

function detectServerActionAuthAndValidation(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    for (const action of collectServerActions(sf)) {
      const text = sf.text.slice(action.node.getStart(sf), action.node.getEnd());
      if (!isDbMutationChain(text)) continue; // scope to mutating actions per the brief

      if (!AUTH_PATTERN.test(text)) {
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

// --- Orchestrator ------------------------------------------------------------

/**
 * Runs all M9 App Router checks over the given source set and returns
 * Finding[] (src/findings.ts). `files` should be a project's full set of
 * relevant .ts/.tsx sources — the server→client leak check needs sibling
 * files to resolve which imported components are Client Components.
 */
export function detectAppRouterFindings(files: SourceInput[]): Finding[] {
  const sources = new Map(files.map((f) => [f.path, parse(f.path, f.text)]));
  const pagesRouterOnly = isPagesRouterOnly(files);
  let n = 0;
  const nextId: NextId = () => `M9-${String(++n).padStart(2, "0")}`;

  return [
    ...detectServerClientLeak(sources, nextId),
    ...detectMissingServerOnly(sources, nextId, pagesRouterOnly),
    ...detectServerActionAuthAndValidation(sources, nextId),
    ...detectClientSuppliedOwnerId(sources, nextId),
    ...detectUnsafeCacheConfig(sources, nextId),
    ...detectDataFetchingWaterfalls(sources, nextId),
    ...detectAccidentalDynamicRendering(sources, nextId),
  ];
}
