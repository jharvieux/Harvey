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

export interface SourceInput {
  /** Repo-relative path, e.g. "app/dashboard/page.tsx". Used for import resolution and location. */
  path: string;
  text: string;
}

const AUTH_PATTERN =
  /auth\.(uid|getUser|getSession)|getServerSession|getCurrentUser|requireAuth|requireUser|requireSession|assertPermission|assertAuthorized|checkAuth|verifySession|auth\(\)/i;
const VALIDATION_PATTERN = /\.safeParse\(|(?<!JSON)\.parse\(|\bzod\b|valibot|\byup\.|\bajv\b/i;
const MUTATION_PATTERN = /\.(insert|update|upsert|delete|rpc)\s*\(/;
const SECRET_ENV_PATTERN = /process\.env\.(?!NEXT_PUBLIC_)[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE_KEY|API_KEY|TOKEN)[A-Z0-9_]*/;
const DYNAMIC_API_PATTERN = /^(headers|cookies|noStore|unstable_noStore)$/;
const CACHE_SIGNAL_PATTERN = /unstable_cache|["']use cache["']|\brevalidate\s*[:=]/;

type NextId = () => string;

function isTsxPath(path: string): boolean {
  return path.endsWith(".tsx") || path.endsWith(".jsx");
}

function parse(path: string, text: string): ts.SourceFile {
  return ts.createSourceFile(
    path,
    text,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    isTsxPath(path) ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
}

function leadingDirective(sf: ts.SourceFile): "use client" | "use server" | undefined {
  const first = sf.statements[0];
  if (first && ts.isExpressionStatement(first) && ts.isStringLiteral(first.expression)) {
    if (first.expression.text === "use client") return "use client";
    if (first.expression.text === "use server") return "use server";
  }
  return undefined;
}

function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

function loc(path: string, sf: ts.SourceFile, node: ts.Node): string {
  return `${path}:${lineOf(sf, node)}`;
}

// Walks a call chain (e.g. `supabase.from("x").select("y").single()`) and
// collects the method names invoked, innermost first.
function callChainNames(node: ts.Expression): string[] {
  const names: string[] = [];
  let cur: ts.Expression = node;
  while (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
    names.push(cur.expression.name.text);
    cur = cur.expression.expression;
  }
  return names;
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
  },
): Finding {
  return { id: nextId(), status: "Open", ...input };
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

function detectMissingServerOnly(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (leadingDirective(sf) !== undefined) continue; // 'use client' can't hold secrets like this meaningfully; 'use server' modules are already server-exclusive by the Next compiler
    if (SERVER_ONLY_EXEMPT_PATTERN.test(path)) continue; // route handlers / middleware are already server-exclusive by Next.js routing convention
    if (hasServerOnlyImport(sf)) continue;
    const secretNode = findSecretEnvAccess(sf);
    if (!secretNode) continue;

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
            taxonomy: "M9 — Server Action missing auth",
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
    if (!/\/(page|layout|route)\.tsx?$/.test(path)) continue;
    const text = sf.text;
    if (!(/\.from\(\s*["'`]/.test(text) && /\.select\(/.test(text))) continue;
    if (CACHE_SIGNAL_PATTERN.test(text)) continue;

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
  let n = 0;
  const nextId: NextId = () => `M9-${String(++n).padStart(2, "0")}`;

  return [
    ...detectServerClientLeak(sources, nextId),
    ...detectMissingServerOnly(sources, nextId),
    ...detectServerActionAuthAndValidation(sources, nextId),
    ...detectUnsafeCacheConfig(sources, nextId),
    ...detectDataFetchingWaterfalls(sources, nextId),
    ...detectAccidentalDynamicRendering(sources, nextId),
  ];
}
