// #1267 — the route → handler → query chain, ACROSS a file boundary. The complement of
// src/scan/bola-owner.ts, which requires "a pages/api file whose DEFAULT-EXPORTED handler is
// analyzable IN THIS FILE" — so the moment the handler delegates to `getOrderForUser(orderId)` in a
// repository module, the class goes dark. That split is the normal shape in any codebase with a
// data-access layer, and it is precisely the "middleware admits the route, the handler trusts the
// caller, the repository issues an unscoped query" chain docs/free-tier-scope.md describes.
//
// WHY THIS EXISTS AT ALL, recorded because the reason it did not is the interesting part. #873
// recommended building this and PR #1186 then filed the class as permanently paid, under a heading
// that borrowed impossibility's register. What #915 measured is that SEMGREP OSS does not follow taint out of a
// function — an engine limit, not a limit on Harvey's own AST layer, which had `resolveImport` /
// `buildImportGraph` (#380) at the time and has since shipped src/scan/ssrf-wrapper.ts: a
// cross-file, import-resolving, route → helper → sink detector for the SSRF sink. This module is the
// same construction for the ownership-scoped-query sink, and stands in the same relationship to
// bola-owner.ts that ssrf-wrapper.ts stands in to harvey-ssrf-fetch.
//
// NON-OVERLAP IS STRUCTURAL, not a filter. bola-owner.ts fires only when the `.eq()` is in the
// handler file; this fires only when it is in an imported module. No call site can produce both,
// so this never re-reports a row bola-owner already produced (#1062's masking shape reached through
// a second detector rather than a producer seam). The other neighbour is src/scan/pg-idor.ts, which
// is the NAME-heuristic form of the same intuition — an Express handler calling a curated
// `find…ById` shape — and never reads the callee at all; the two are related the way
// harvey-ssrf-fetch's curated wrapper-name list is related to ssrf-wrapper.ts.
//
// SCOPE, stated here and in the finding's own impact text so its silence is not read as a clean
// bill of health:
//   - ONE hop. `route → repository` is resolved; `route → service → repository` is not.
//   - The callee must be an EXPORTED function declaration or arrow const in the resolved module,
//     with the request-rooted value arriving as a named parameter. A method on an exported class,
//     or a re-export, is not resolved.
//   - The query must run on a SERVICE/ADMIN-rooted client, the same gate bola-owner.ts uses: on the
//     RLS client the row is still policy-gated, so an unscoped query there is not by itself a bug.
//   - The handler must AUTHENTICATE — an unauthenticated route is the missing-auth class and
//     harvey-route-noauth owns it. Firing here would double-count it.
//   - An ownership comparison in EITHER the handler or the callee clears the site, but a comparison
//     performed in a third module is not seen.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { callChainNames, loc, parse, type SourceInput } from "../detectors/common.js";
import { collectPathAliases, resolveImport } from "../detectors/app-router.js";
import {
  collectDbBoundNames,
  collectDerivedClientNames,
  collectParamRootNames,
  collectServiceClientNames,
  collectSessionBoundNames,
  hasOwnershipComparison,
  isServiceRooted,
  OWNERSHIP_COLUMN,
  rootIdentifier,
} from "../detectors/owner-id.js";
import { mechanicalFinding } from "./common.js";
import type { PathScopedClass } from "./path-scope.js";

const HANDLER_FILE = /(^|\/)(pages\/api\/.+|app\/.*route)\.(ts|tsx|js|jsx|mjs|cjs)$/;
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;

function isBolaCrossFileHandlerPath(path: string): boolean {
  return SOURCE_EXT.test(path) && HANDLER_FILE.test(path);
}

export function bolaCrossFileHandlerFiles(files: readonly SourceInput[]): SourceInput[] {
  return files.filter((file) => isBolaCrossFileHandlerPath(file.path));
}

export const BOLA_CROSS_FILE_PATH_SCOPE_CLASSES: readonly PathScopedClass[] = [
  {
    rowId: "M1-PATHSCOPE-BOLA-CROSS-FILE-00",
    detector: "bola-cross-file",
    classId: "Object-level authorization gap across a module boundary",
    ownerFile: "src/scan/bola-cross-file.ts",
    selectorSymbol: "bolaCrossFileHandlerFiles",
    convention: "Pages Router API modules and App Router `route.*` handlers",
    select: bolaCrossFileHandlerFiles,
    classes: "an authenticated route passing a request-rooted owner id into an imported service-role query",
  },
];

type Fn = ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression | ts.MethodDeclaration;

function isFn(node: ts.Node): node is Fn {
  return ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node) || ts.isMethodDeclaration(node);
}

// Every request-handling function in the module: the Pages Router default export, and the App
// Router's named METHOD exports (GET/POST/…). Taking all exported functions rather than only the
// default is what lets one detector cover both routers.
function handlerFunctions(sf: ts.SourceFile): Fn[] {
  const out: Fn[] = [];
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.body && ts.getModifiers(stmt)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) out.push(stmt);
    if (ts.isExportAssignment(stmt) && !stmt.isExportEquals && isFn(stmt.expression)) out.push(stmt.expression);
    if (ts.isVariableStatement(stmt) && ts.getModifiers(stmt)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) {
      for (const d of stmt.declarationList.declarations) if (d.initializer && isFn(d.initializer)) out.push(d.initializer);
    }
  }
  return out;
}

// local binding name -> resolved module path, for value imports only.
function importedBindings(path: string, sf: ts.SourceFile, allPaths: Set<string>, aliases: ReturnType<typeof collectPathAliases>): Map<string, string> {
  const out = new Map<string, string>();
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier) || stmt.importClause?.isTypeOnly) continue;
    const resolved = resolveImport(path, stmt.moduleSpecifier.text, allPaths, aliases);
    if (!resolved) continue;
    const named = stmt.importClause?.namedBindings;
    if (named && ts.isNamedImports(named)) {
      for (const el of named.elements) if (!el.isTypeOnly) out.set(el.name.text, resolved);
    }
    if (stmt.importClause?.name) out.set(stmt.importClause.name.text, resolved);
  }
  return out;
}

interface ExportedFn {
  fn: Fn;
  params: string[];
}

function exportedFunctions(sf: ts.SourceFile): Map<string, ExportedFn> {
  const out = new Map<string, ExportedFn>();
  const params = (fn: Fn) => fn.parameters.map((p) => (ts.isIdentifier(p.name) ? p.name.text : "")).filter(Boolean);
  for (const stmt of sf.statements) {
    const exported = ts.canHaveModifiers(stmt) && ts.getModifiers(stmt)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (!exported) continue;
    if (ts.isFunctionDeclaration(stmt) && stmt.name && stmt.body) out.set(stmt.name.text, { fn: stmt, params: params(stmt) });
    if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.initializer && isFn(d.initializer)) out.set(d.name.text, { fn: d.initializer, params: params(d.initializer) });
      }
    }
  }
  return out;
}

interface Site {
  column: string;
  node: ts.CallExpression;
}

// `.eq("<ownership column>", <name>)` on a service-rooted `.from()` chain, where <name> is one of
// the callee's own parameters — i.e. the value the route handed it.
function unscopedQuery(fn: ts.Node, scopedBy: ReadonlySet<string>, serviceNames: ReadonlySet<string>): Site | undefined {
  let hit: Site | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "eq" && node.arguments.length === 2) {
      const [col, val] = node.arguments;
      if (col && val && ts.isStringLiteralLike(col) && OWNERSHIP_COLUMN.test(col.text)) {
        const root = rootIdentifier(val);
        if (root && scopedBy.has(root) && callChainNames(node).includes("from") && isServiceRooted(node, serviceNames)) {
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

interface CrossCall {
  calleeName: string;
  module: string;
  argIndex: number;
  node: ts.CallExpression;
}

// A call to an IMPORTED binding, passing a request-rooted value.
function crossFileCalls(handler: Fn, imports: ReadonlyMap<string, string>, clientNames: ReadonlySet<string>): CrossCall[] {
  const out: CrossCall[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      const module = imports.get(node.expression.text);
      if (module) {
        node.arguments.forEach((arg, i) => {
          const root = rootIdentifier(arg);
          if (root && clientNames.has(root)) out.push({ calleeName: (node.expression as ts.Identifier).text, module, argIndex: i, node });
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(handler);
  return out;
}

function detectFile(path: string, sf: ts.SourceFile, sources: Map<string, ts.SourceFile>, allPaths: Set<string>, aliases: ReturnType<typeof collectPathAliases>): Finding[] {
  const imports = importedBindings(path, sf, allPaths, aliases);
  if (imports.size === 0) return [];

  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const handler of handlerFunctions(sf)) {
    const sessionNames = collectSessionBoundNames(handler, sf);
    if (sessionNames.size === 0) continue; // unauthenticated surface — harvey-route-noauth owns it

    const paramRoots = collectParamRootNames(handler);
    const clientNames = new Set([...paramRoots, ...collectDerivedClientNames(handler, paramRoots)]);
    for (const s of sessionNames) clientNames.delete(s);
    if (clientNames.size === 0) continue;

    const serverNames = new Set([...sessionNames, ...collectDbBoundNames(handler)]);
    if (hasOwnershipComparison(handler, serverNames, clientNames)) continue;

    for (const call of crossFileCalls(handler, imports, clientNames)) {
      const calleeSf = sources.get(call.module);
      if (!calleeSf) continue;
      const exported = exportedFunctions(calleeSf).get(call.calleeName);
      const param = exported?.params[call.argIndex];
      if (!exported || !param) continue;

      const serviceNames = collectServiceClientNames(exported.fn, calleeSf);
      const site = unscopedQuery(exported.fn, new Set([param]), serviceNames);
      if (!site) continue;
      // An ownership comparison inside the CALLEE is authorization too, and it is where a
      // repository that does its own checking would put it. Its server side is the callee's OTHER
      // parameters plus anything it fetched itself: `listOrders(tenantId, session)` comparing
      // `tenantId !== session.tenantId` is the idiomatic repository-level check, and without the
      // other parameters in serverNames it read as unguarded (MEASURED 2026-07-31 on
      // N-BOLA-CROSS-FILE-CHECKED, which fired before this line counted them).
      const calleeServerNames = new Set([...exported.params.filter((p) => p !== param), ...collectDbBoundNames(exported.fn)]);
      if (hasOwnershipComparison(exported.fn, calleeServerNames, new Set([param]))) continue;

      const key = `${path}:${call.calleeName}:${site.column}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const sessionName = [...sessionNames][0];
      findings.push(
        mechanicalFinding({
          id: `AUTH-bola-cross-file-${call.calleeName}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}`,
          title: `${path} — authenticated route hands a client-supplied id to \`${call.calleeName}()\`, which scopes its query by it`,
          severity: "High",
          category: "Broken access control",
          taxonomy: "Object-level authorization gap across a module boundary",
          // The CALL SITE in the handler, not the far-end query: that is the line a reader has to
          // change, and the evidence names the callee's file and parameter for the other end.
          location: loc(path, sf, call.node),
          evidence: `Heuristic "bola-cross-file": the handler authenticates the caller (binding \`${sessionName}\`) and passes a request-rooted value to \`${call.calleeName}()\`, imported from \`${call.module}\`, whose parameter \`${param}\` reaches \`.eq("${site.column}", ${param})\` on a service-role \`.from()\` chain — with no comparison against \`${sessionName}\` in either function.`,
          impact: `The caller is authenticated but never authorized for the object: any signed-in user can name another tenant's or user's ${site.column} and the repository will return those rows, because the service-role client bypasses RLS and this scoping is the only gate. SCOPE: one import hop only (route → repository, not route → service → repository); the callee must be an exported function or arrow const taking the value as a named parameter; and an ownership comparison performed in a THIRD module is not seen, so confirm no such check runs before treating this as unmitigated.`,
          fix: `Pass the verified session identity into \`${call.calleeName}()\` and scope on that, or compare the request's ${site.column} against \`${sessionName}\`'s and reject a mismatch — in the repository, so every caller inherits the check.`,
          precisionTier: "review",
          cwe: ["CWE-639: Authorization Bypass Through User-Controlled Key"],
          owasp: ["A01:2021 - Broken Access Control"],
        }),
      );
    }
  }
  return findings;
}

export function detectBolaCrossFileFindings(files: SourceInput[]): Finding[] {
  const parsed = files.filter((f) => SOURCE_EXT.test(f.path));
  const sources = new Map(parsed.map((f) => [f.path, parse(f.path, f.text)]));
  const allPaths = new Set(sources.keys());
  const aliases = collectPathAliases(files);
  return [...sources]
    .filter(([path]) => isBolaCrossFileHandlerPath(path))
    .flatMap(([path, sf]) => detectFile(path, sf, sources, allPaths, aliases));
}
