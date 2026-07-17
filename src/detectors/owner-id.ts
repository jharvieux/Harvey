// Shared dataflow helpers for the client-supplied-owner-id class (#221/#465/#433). Two
// detectors reason about the same three facts — where a scoping value ROOTS (a client
// argument/request object vs. the session vs. a row the server itself fetched), whether the DB
// chain runs on the RLS-bypassing service/admin client, and whether the body ever compares the
// client id against a server-derived one (which IS the authorization check):
//   - src/detectors/app-router.ts detectClientSuppliedOwnerId — the Server Action surface;
//   - src/scan/bola-owner.ts — the pages/api handler surface (runs in runMechanicalScan).
// One implementation so the two surfaces can't drift apart on what "client-supplied" means.

import ts from "typescript";
import { callChainNames } from "./common.js";

export const AUTH_PATTERN =
  /auth\.(uid|getUser|getSession)|getServerSession|getCurrentUser|requireAuth|requireUser|requireSession|assertPermission|assertAuthorized|checkAuth|verifySession|auth\(\)/i;

export const OWNERSHIP_COLUMN = /^(user|owner|tenant|account|org|organisation|organization|customer|workspace|member|profile|created_by|author)(_id)?$/i;

// The subset that names a row's owning IDENTITY, for the INSERT-value shape (#465): a client
// choosing `user_id` on a new row is claiming who owns it. The container columns (org/tenant/
// workspace/…) are deliberately excluded there — "which org am I acting in" is routinely a
// legitimate client choice on an insert, and flagging it would hit every membership/join flow.
export const INSERT_OWNER_COLUMN = /^(user|owner|member|customer|created_by|author)(_id)?$/i;

// Chain roots that mark the RLS-bypassing client (`admin.from(…)`, `supabaseService.from(…)`,
// `createServiceClient().from(…)`). A name heuristic, deliberately: the factory call and the
// conventional binding names both carry the word, and a miss here fails SAFE (the detector
// stays quiet and the class falls back to the RLS-delegation assumption).
const SERVICE_CLIENT_NAME = /(admin|service)/i;

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
// these is server-derived and therefore trustworthy to scope a query by.
export function collectSessionBoundNames(fn: ts.Node, sf: ts.SourceFile): Set<string> {
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

export function collectParamRootNames(fn: ts.Node): Set<string> {
  const names = new Set<string>();
  for (const p of (fn as ts.SignatureDeclarationBase).parameters ?? []) bindingNames(p.name, names);
  return names;
}

// The identifier a property-access chain roots in: `input.userId` → "input", `userId` → "userId".
export function rootIdentifier(expr: ts.Expression): string | undefined {
  let cur: ts.Expression = expr;
  while (ts.isPropertyAccessExpression(cur)) cur = cur.expression;
  return ts.isIdentifier(cur) ? cur.text : undefined;
}

// Names bound by destructuring a client root (`const { userId } = input`) or aliasing one
// (`const uid = input.userId`) — still client-supplied, just one hop from the parameter.
export function collectDerivedClientNames(fn: ts.Node, clientRoots: Set<string>): Set<string> {
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

// Names bound from a DB read in the same body (`const { data: invitation } = await
// svc.from("organisation_invitations").select(…)…`). A row the server fetched itself is a
// server-verified value: comparing the client id against one of its fields (a token-exchange
// flow) is an authorization decision, same as comparing against the session.
export function collectDbBoundNames(fn: ts.Node): Set<string> {
  const names = new Set<string>();
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const init = ts.isAwaitExpression(node.initializer) ? node.initializer.expression : node.initializer;
      if (ts.isCallExpression(init) && callChainNames(init).includes("from")) bindingNames(node.name, names);
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return names;
}

// An explicit ownership comparison between a server-derived value (session or fetched row) and
// a client-supplied one (`if (currentUser.id !== accountId) throw`) IS the authorization
// check — the body is guarded even though the query reads a client value.
export function hasOwnershipComparison(fn: ts.Node, serverNames: Set<string>, clientNames: Set<string>): boolean {
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
        if (sides.some((s) => s && serverNames.has(s)) && sides.some((s) => s && clientNames.has(s))) {
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

// The identifier a full call chain roots in, descending through calls, member accesses, awaits
// and parens: `admin.from("x").select().eq(…)` → "admin"; `createServiceClient().from(…)` →
// "createServiceClient".
function chainRootName(expr: ts.Expression): string | undefined {
  let cur: ts.Expression = expr;
  for (;;) {
    if (ts.isCallExpression(cur) || ts.isPropertyAccessExpression(cur) || ts.isNonNullExpression(cur)) cur = cur.expression;
    else if (ts.isParenthesizedExpression(cur) || ts.isAwaitExpression(cur)) cur = cur.expression;
    else break;
  }
  return ts.isIdentifier(cur) ? cur.text : undefined;
}

// Names bound from a service-client factory in the body: `const svc = createServiceClient()`.
export function collectServiceClientNames(fn: ts.Node, sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const init = ts.isAwaitExpression(node.initializer) ? node.initializer.expression : node.initializer;
      if (ts.isCallExpression(init) && SERVICE_CLIENT_NAME.test(init.expression.getText(sf))) bindingNames(node.name, names);
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return names;
}

// Whether a DB call chain runs on the service/admin client — by root name (`admin`,
// `supabaseService`, an imported binding) or by a service-factory binding collected above.
export function isServiceRooted(expr: ts.Expression, serviceNames: ReadonlySet<string>): boolean {
  const root = chainRootName(expr);
  return root !== undefined && (SERVICE_CLIENT_NAME.test(root) || serviceNames.has(root));
}
