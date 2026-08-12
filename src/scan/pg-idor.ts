// #663 (M1 #614 follow-up) — Express + pg repo-function IDOR (OWASP API1: broken object-level
// authorization). An authenticated handler (the body reads req.user / req.session.user
// somewhere — the caller's identity is available) passes a client-supplied id
// (req.params.$K / req.query.$K) straight into a name-gated "read one row by id" repo function,
// with no comparison ANYWHERE in the body between the caller's identity and anything else. Any
// signed-in user can substitute another user's id and read that row.
//
// Precision gates, each deliberate:
//   - the sink function name must match a curated read-by-id shape (find|get|fetch|load ...
//     By(Id|Pk)) — matching ANY `$FN(req.params.$K)` broadly would fire on every id-parameterized
//     call (validation, logging, safe owner-scoped reads already gated elsewhere), per #663;
//   - the enclosing function must look like an Express handler (req/request AND res/response
//     parameters) — the plain-Express surface #614 targeted, not an arbitrary function;
//   - an authenticated context must exist (req.user/session.user read somewhere) — an
//     unauthenticated surface is the missing-auth class (harvey-route-noauth), not this one;
//   - NO equality comparison anywhere in the body has req.user/session.user on either side. This
//     fails SAFE, not tight: a role check unrelated to object ownership also clears the finding
//     (a false negative, not a false positive) — a single-file AST pass can't tell "the id was
//     compared against the owner" from "identity was checked for something else".
// Review tier, never free-count: the AST proves the call shape and the same-body absence of a
// comparison, not that authorization is absent from a wrapper it can't see (same posture as
// src/scan/bola-owner.ts, the Supabase-scoped sibling of this class).

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { NON_SHIPPING_FILE, NON_SHIPPING_PATH } from "./prisma-tenant-scope.js";
import { mechanicalFinding } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const READ_BY_ID_FN = /^(find|get|fetch|load)[A-Za-z0-9_]*By(Id|Pk)$/i;
const REQ_IDENTITY_PATTERN = /^(req|request)\.(user|session\.user)\b/;
const REQ_SOURCE_PROP = new Set(["params", "query"]);

type HandlerFn = ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression;

function isExpressHandler(fn: HandlerFn): boolean {
  const names = ((fn as ts.SignatureDeclarationBase).parameters ?? [])
    .map((p) => (ts.isIdentifier(p.name) ? p.name.text : ""));
  const hasReq = names.some((n) => n === "req" || n === "request");
  const hasRes = names.some((n) => n === "res" || n === "response");
  return hasReq && hasRes;
}

function collectHandlers(sf: ts.SourceFile): HandlerFn[] {
  const handlers: HandlerFn[] = [];
  const visit = (node: ts.Node) => {
    if ((ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)) && node.body && isExpressHandler(node)) {
      handlers.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return handlers;
}

function hasReqIdentityRead(fn: ts.Node, sf: ts.SourceFile): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isPropertyAccessExpression(node) && REQ_IDENTITY_PATTERN.test(node.getText(sf))) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return found;
}

function hasIdentityComparison(fn: ts.Node, sf: ts.SourceFile): boolean {
  const EQUALITY_OPS = new Set([
    ts.SyntaxKind.EqualsEqualsToken,
    ts.SyntaxKind.EqualsEqualsEqualsToken,
    ts.SyntaxKind.ExclamationEqualsToken,
    ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ]);
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isBinaryExpression(node) && EQUALITY_OPS.has(node.operatorToken.kind)) {
      if (REQ_IDENTITY_PATTERN.test(node.left.getText(sf)) || REQ_IDENTITY_PATTERN.test(node.right.getText(sf))) {
        found = true;
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return found;
}

interface IdorSite {
  node: ts.CallExpression;
  fnName: string;
  source: string;
  field: string;
}

function findIdorSite(fn: ts.Node): IdorSite | undefined {
  let hit: IdorSite | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && READ_BY_ID_FN.test(node.expression.text) && node.arguments.length >= 1) {
      const arg = node.arguments[0];
      if (
        arg &&
        ts.isPropertyAccessExpression(arg) &&
        ts.isPropertyAccessExpression(arg.expression) &&
        ts.isIdentifier(arg.expression.expression) &&
        (arg.expression.expression.text === "req" || arg.expression.expression.text === "request") &&
        REQ_SOURCE_PROP.has(arg.expression.name.text)
      ) {
        hit = { node, fnName: node.expression.text, source: arg.expression.name.text, field: arg.name.text };
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return hit;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  for (const handler of collectHandlers(sf)) {
    if (!hasReqIdentityRead(handler, sf)) continue; // unauthenticated surface — a different class owns it
    const site = findIdorSite(handler);
    if (!site) continue;
    if (hasIdentityComparison(handler, sf)) continue;

    findings.push(
      mechanicalFinding({
        id: `SEC-PG-IDOR-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${site.node.getStart(sf)}`,
        title: `${path} — authenticated handler passes a client-supplied id straight into ${site.fnName}(...)`,
        severity: "High",
        category: "Broken access control",
        taxonomy: "Object-level authorization gap: client-supplied id reaches a read-by-id repo function (pg-idor-repo-fn)",
        location: loc(path, sf, site.node),
        evidence: `Heuristic "pg-idor-repo-fn": the handler reads req.user/session.user (authenticated) yet calls ${site.fnName}(req.${site.source}.${site.field}) — a read-by-id repo function — with no comparison anywhere in the body between the caller's identity and anything else.`,
        impact: "The caller is authenticated but never authorized for the object: any signed-in user can substitute another user's id in the request and read that row via direct object reference.",
        fix: `Scope the lookup to the caller (e.g. ${site.fnName}(req.user.id)), or compare the fetched row's owner against req.user.id and reject mismatches before returning it.`,
        precisionTier: "review",
      }),
    );
  }
  return findings;
}

// #1269: same non-shipping exclusion prisma-tenant-scope carries since #896. A route-handler shape
// in a `tests/`, `e2e/`, `examples/` or `docs/` path is a fixture setting up a case, not an
// authorization gap, and briefs/fp-rules.txt already rules that code out of scope. MEASURED
// 2026-07-31: this detector read 631 non-shipping files across the three pinned clones and, with
// the shape planted, fires identically at `tests/orders.test.js` and `src/lib/orders.js`.
export function detectPgIdorFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}
