// #433 P-BOLA-BODY-OWNER — object-level authorization gap (BOLA, OWASP API1) on the Pages
// Router API surface: a handler that DOES authenticate the caller yet scopes a service-role DB
// query to an ownership column fed from the request object — `req.body.tenantId` picks WHOSE
// rows come back, and no comparison against the verified session appears in the body. The
// Server Action side of the same class lives in src/detectors/app-router.ts
// (detectClientSuppliedOwnerId); the dataflow helpers are shared (src/detectors/owner-id.ts).
// This pass runs in runMechanicalScan so the class is scored by the live calibration gate, and
// walks its own tree (the counter-race precedent) because runMechanicalScan hands it no
// SourceInput[]. Its original reason — "loadSources() excludes plain .js" — stopped being true on
// 2026-07-25 (#1065).
//
// Gates — each is a deliberate precision boundary:
//   - a pages/api file whose DEFAULT-EXPORTED handler is analyzable in this file;
//   - a session/auth value is BOUND in the body. An unauthenticated handler is the
//     missing-auth/IDOR class (harvey-route-noauth and the semantic tier own it — firing here
//     would double-count it, and would swallow P-MW-SOLE-AUTHZ, which #1366 re-ruled on 2026-07-31
//     from "by-design LLM-tier" to a MEASURED GAP — outstanding work, not a boundary);
//   - an `.eq("<ownership column>", <request-rooted value>)` on a `.from(…)` chain rooted in
//     the service/admin client. On the RLS client the query is still row-gated by policies;
//     bare `.eq("id", …)` is excluded (that is the IDOR-by-primary-key class, not this one);
//   - no equality comparison between the request value and a session- or DB-derived value
//     (such a comparison IS the authorization check).
// Review tier, never free-count: the AST proves the scoping value's origin, not that
// authorization is absent from a wrapper it can't see.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { callChainNames, loc, parse, type SourceInput } from "../detectors/common.js";
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
import { NON_SHIPPING_FILE, NON_SHIPPING_PATH } from "./prisma-tenant-scope.js";
import { mechanicalFinding, walkSourceFiles } from "./common.js";

const PAGES_API_FILE = /(^|\/)pages\/api\/.+\.(ts|tsx|js|jsx|mjs|cjs)$/;

type HandlerFn = ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression;

// The default-exported handler — Next.js routes everything through it, so it is the one
// function whose parameters are the request. Covers `export default async function handler`,
// `export default (req, res) => …`, and `export default handler` naming a same-file function.
function defaultExportedHandler(sf: ts.SourceFile): HandlerFn | undefined {
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.body && stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword)) return stmt;
    if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) {
      const expr = stmt.expression;
      if (ts.isArrowFunction(expr) || ts.isFunctionExpression(expr)) return expr;
      if (ts.isIdentifier(expr)) {
        for (const s of sf.statements) {
          if (ts.isFunctionDeclaration(s) && s.body && s.name?.text === expr.text) return s;
          if (ts.isVariableStatement(s)) {
            for (const d of s.declarationList.declarations) {
              if (ts.isIdentifier(d.name) && d.name.text === expr.text && d.initializer && (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))) return d.initializer;
            }
          }
        }
      }
    }
  }
  return undefined;
}

interface BolaSite {
  column: string;
  node: ts.CallExpression;
}

function findBolaSite(fn: ts.Node, clientNames: Set<string>, serviceNames: Set<string>): BolaSite | undefined {
  let hit: BolaSite | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "eq" && node.arguments.length === 2) {
      const [col, val] = node.arguments;
      if (col && val && ts.isStringLiteralLike(col) && OWNERSHIP_COLUMN.test(col.text)) {
        const root = rootIdentifier(val);
        if (root && clientNames.has(root) && callChainNames(node).includes("from") && isServiceRooted(node, serviceNames)) {
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

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const handler = defaultExportedHandler(sf);
  if (!handler) return [];

  const sessionNames = collectSessionBoundNames(handler, sf);
  if (sessionNames.size === 0) return []; // unauthenticated surface — a different class owns it

  const paramRoots = collectParamRootNames(handler);
  const clientNames = new Set([...paramRoots, ...collectDerivedClientNames(handler, paramRoots)]);
  // Session precedence: `const session = await getServerSession(req)` is DERIVED from a client
  // root in the dataflow sense, but its value is server-verified — never client-supplied.
  for (const s of sessionNames) clientNames.delete(s);
  if (clientNames.size === 0) return [];

  const serviceNames = collectServiceClientNames(handler, sf);
  const site = findBolaSite(handler, clientNames, serviceNames);
  if (!site) return [];

  const serverNames = new Set([...sessionNames, ...collectDbBoundNames(handler)]);
  if (hasOwnershipComparison(handler, serverNames, clientNames)) return [];

  const sessionName = [...sessionNames][0];
  return [
    mechanicalFinding({
      id: `AUTH-bola-body-owner-${path.replace(/[^a-zA-Z0-9]+/g, "-")}`,
      title: `${path} — authenticated handler queries rows scoped by a client-supplied \`${site.column}\``,
      severity: "High",
      category: "Broken access control",
      taxonomy: "Object-level authorization gap: client-supplied owner id scopes the query",
      location: loc(path, sf, site.node),
      evidence: `Heuristic "bola-body-owner": the handler authenticates the caller (binding \`${sessionName}\`) yet scopes its service-role query with \`.eq("${site.column}", …)\` on a value rooted in the request object, with no comparison against \`${sessionName}\` in the body.`,
      impact: "The caller is authenticated but never authorized for the object: any signed-in user can put another tenant's/user's id in the request and read (or write) that tenant's rows — the service-role client bypasses RLS, so this scoping is the only gate.",
      fix: `Scope the query to the verified session (e.g. \`.eq("${site.column}", ${sessionName}.user.${site.column === "tenant_id" ? "tenantId" : "id"})\`), or explicitly compare the request's id against the session's and reject mismatches.`,
      precisionTier: "review",
    }),
  ];
}

// #1269: the `pages/api/` prefix is not itself a shipping guarantee — a Next.js example app or an
// e2e fixture tree carries the same segment (`examples/next-app/pages/api/…`, `e2e/pages/api/…`),
// and MEASURED 2026-07-31 this detector fires identically there and at `pages/api/invoice.js`.
export function detectBolaOwnerFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => PAGES_API_FILE.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

export function scanBolaOwner(projectDir: string): Finding[] {
  return detectBolaOwnerFindings(walkSourceFiles(projectDir));
}
