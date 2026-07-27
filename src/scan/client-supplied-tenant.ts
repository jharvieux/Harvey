// #1194 CLIENT-SUPPLIED-TENANT — a tenant predicate that is PRESENT, correct-looking, and populated
// from the request. OWASP Multi-Tenant Application Security Cheat Sheet section 1, "Never trust
// client-supplied tenant IDs" / "Bind tenant context to authenticated user sessions"; found as a
// measured gap by that sheet's independent corpus (src/scan/calibration/owasp-multitenant.entries.ts,
// P-OWASP-MT-CLIENT-TENANT).
//
//   const body = await req.json();
//   return prisma.invoice.findMany({ where: { tenantId: body.tenantId } });
//
// WHY THE EXISTING DETECTORS ARE BLIND TO IT. prisma-tenant-scope.ts (#760) and
// drizzle-tenant-scope.ts (#901) both ask whether a tenant predicate EXISTS. Here it exists and
// names the right column, so both read the query as properly scoped. The defect is entirely in
// where the predicate's VALUE came from, which is a different question — and the more dangerous
// shape of the two, because a missing predicate looks wrong in review while this one looks right.
//
// Gates — this reports at HIGH tier, unlike its two siblings, and the difference is what the AST
// proves. They prove an ABSENCE (no tenant column here) and must stay review-tier because a wrapper
// or middleware they cannot see may supply the scope. This proves a PRESENCE: the request value
// reaches the tenant predicate along a chain of assignments in one function. There is no unseen
// middleware that makes `where: { tenantId: body.tenantId }` correct.
//   - the value must originate in a recognised REQUEST source (below) and reach the predicate
//     through same-function `const`/`let` bindings only — no cross-function or cross-file dataflow,
//     so an unseen helper is never assumed to be tainted;
//   - the predicate key must be a tenant/owner column (TENANT_SCOPE_COLUMN, shared with #760). A
//     `where: { id: body.id }` is the ordinary IDOR class those detectors and bola-owner.ts already
//     own, and is deliberately NOT reported here;
//   - a same-function comparison of the tainted binding against a session-derived value clears it —
//     `if (body.tenantId !== session.user.tenantId) throw` is the sheet's own remedy.
//
// DELIBERATELY NOT A CLEARING GUARD: membership checks (`allowedTenants.includes(body.tenantId)`).
// Existence in a list is not ownership by the caller, so clearing on it would silently drop real
// findings — the #989 lesson that a guard model must be justified by an adversarial positive, not
// merely by a negative it quiets. Such a call still reports.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding, walkSourceFiles } from "./common.js";
import { COMPARISON_OPS } from "./drizzle-tenant-scope.js";
import {
  NON_SHIPPING_FILE,
  NON_SHIPPING_PATH,
  SOURCE_EXT,
  TENANT_SCOPE_COLUMN,
  prismaModelCall,
} from "./prisma-tenant-scope.js";

// The request object, by conventional name. Node/Express and the Next.js Request/NextRequest
// handler signatures all bind it to one of these.
const REQUEST_OBJECT = /^(req|request|nextreq|nextrequest)$/i;

// Its attacker-controlled bags. `headers` and `cookies` are included on #984's precedent (it added
// them as taint sources to the semgrep rules for exactly this reason) — a tenant id read from a
// header or an unsigned cookie is client-supplied in the sense the sheet means.
const REQUEST_BAG = /^(body|query|params|cookies|headers|searchparams|nexturl)$/i;

// `await req.json()` / `req.formData()` / `req.text()` — the Web-Request way to reach the body.
const REQUEST_PARSER = /^(json|formdata|text)$/i;

// Receivers whose `.get(...)` returns a caller-supplied string: `searchParams.get("org")`,
// `formData.get("tenant")`, `url.searchParams.get(...)`, `req.headers.get(...)`.
const GETTER_RECEIVER = /^(searchparams|formdata|querystring|headers|cookies)$/i;

// A session/verified-identity expression, for the clearing guard only. Matched against printed
// source, so it deliberately admits `session.user.tenantId`, `auth().orgId`, `ctx.session.…`,
// `locals.user.…`, `claims.tenant_id`.
const SESSION_EXPR = /\b(session|auth|authorize|currentuser|current_user|getuser|claims|jwt|locals|principal|viewer|membership)\b/i;

const EQUALITY = new Set([
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
]);

// Strip the wrappers that carry a value through unchanged. `??`/`||` take the LEFT side because
// `searchParams.get("org") ?? ""` is still the caller's value whenever the caller supplies one.
function unwrap(node: ts.Expression): ts.Expression {
  if (ts.isParenthesizedExpression(node) || ts.isAwaitExpression(node) || ts.isNonNullExpression(node)) {
    return unwrap(node.expression);
  }
  if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node)) return unwrap(node.expression);
  if (
    ts.isBinaryExpression(node) &&
    (node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken || node.operatorToken.kind === ts.SyntaxKind.BarBarToken)
  ) {
    return unwrap(node.left);
  }
  // String(x) / Number(x) / x.trim() etc. re-type the value; they do not authenticate it.
  if (ts.isCallExpression(node)) {
    if (ts.isIdentifier(node.expression) && /^(string|number|parseint|parsefloat)$/i.test(node.expression.text) && node.arguments[0]) {
      return unwrap(node.arguments[0]);
    }
    if (ts.isPropertyAccessExpression(node.expression) && /^(trim|tolowercase|touppercase|tostring)$/i.test(node.expression.name.text)) {
      return unwrap(node.expression.expression);
    }
  }
  return node;
}

function isRequestObject(node: ts.Expression): boolean {
  return ts.isIdentifier(node) && REQUEST_OBJECT.test(node.text);
}

// `searchParams` / `formData` / `req.headers` / `url.searchParams` — the receivers whose `.get()`
// hands back a caller-supplied string.
function isGetterReceiver(node: ts.Expression): boolean {
  const n = unwrap(node);
  if (ts.isIdentifier(n)) return GETTER_RECEIVER.test(n.text);
  if (ts.isPropertyAccessExpression(n)) return GETTER_RECEIVER.test(n.name.text);
  return false;
}

// The dotted names of a property/element-access chain, outermost last, or undefined if the chain
// does not bottom out in an identifier.
function accessChain(node: ts.Expression): string[] | undefined {
  const names: string[] = [];
  let current: ts.Expression = node;
  for (;;) {
    if (ts.isPropertyAccessExpression(current)) {
      names.unshift(current.name.text);
      current = current.expression;
    } else if (ts.isElementAccessExpression(current)) {
      names.unshift(ts.isStringLiteralLike(current.argumentExpression) ? current.argumentExpression.text : "[…]");
      current = current.expression;
    } else if (ts.isIdentifier(current)) {
      names.unshift(current.text);
      return names;
    } else {
      return undefined;
    }
  }
}

// A recognised request source, described in the deliverable's words, or undefined.
function requestSource(expr: ts.Expression): string | undefined {
  const e = unwrap(expr);

  if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression)) {
    const method = e.expression.name.text;
    const receiver = unwrap(e.expression.expression);
    if (REQUEST_PARSER.test(method) && isRequestObject(receiver)) return `${receiver.getText()}.${method}()`;
    if (method === "get" && isGetterReceiver(receiver)) {
      const key = e.arguments[0] && ts.isStringLiteralLike(e.arguments[0]) ? `"${(e.arguments[0] as ts.StringLiteralLike).text}"` : "…";
      const chain = accessChain(receiver);
      return `${chain ? chain.join(".") : "searchParams"}.get(${key})`;
    }
    return undefined;
  }

  if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) {
    const chain = accessChain(e);
    const [root, bag] = chain ?? [];
    if (!chain || root === undefined || bag === undefined) return undefined;
    // `req.body.tenantId` — the request object then one of its bags.
    if (REQUEST_OBJECT.test(root) && REQUEST_BAG.test(bag)) return chain.join(".");
    // A bare `searchParams`/`params` binding destructured out of the handler signature.
    if (GETTER_RECEIVER.test(root)) return chain.join(".");
    return undefined;
  }

  return undefined;
}

// Same-function taint: which local bindings hold a request-derived value, and which source each
// traces back to. Two passes so `const body = await req.json()` followed by
// `const tenant = body.tenantId` resolves regardless of declaration order within the function.
function taintedBindings(fn: ts.Node): Map<string, string> {
  const tainted = new Map<string, string>();

  const sourceOf = (expr: ts.Expression): string | undefined => {
    const direct = requestSource(expr);
    if (direct) return direct;
    const root = accessChain(unwrap(expr))?.[0];
    return root === undefined ? undefined : tainted.get(root);
  };

  const bind = (name: ts.BindingName, source: string) => {
    if (ts.isIdentifier(name)) {
      tainted.set(name.text, source);
    } else if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      for (const el of name.elements) if (ts.isBindingElement(el)) bind(el.name, source);
    }
  };

  for (let pass = 0; pass < 2; pass++) {
    const visit = (n: ts.Node) => {
      if (ts.isVariableDeclaration(n) && n.initializer) {
        const source = sourceOf(n.initializer);
        if (source) bind(n.name, source);
      }
      ts.forEachChild(n, visit);
    };
    visit(fn);
  }
  return tainted;
}

// Is this expression the request value, directly or through a tainted local?
function taintOf(expr: ts.Expression, tainted: Map<string, string>): { source: string; root: string } | undefined {
  const direct = requestSource(expr);
  const root = accessChain(unwrap(expr))?.[0];
  if (direct) return { source: direct, root: root ?? direct };
  const carried = root === undefined ? undefined : tainted.get(root);
  if (root !== undefined && carried !== undefined) return { source: carried, root };
  return undefined;
}

// The sheet's own remedy, and the one thing that makes a client-supplied tenant id safe: the
// function compares it against the verified session before using it. Membership checks are
// deliberately not accepted here — see the header.
function comparedAgainstSession(fn: ts.Node, sf: ts.SourceFile, root: string): boolean {
  const mentionsRoot = new RegExp(`\\b${root.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isBinaryExpression(n) && EQUALITY.has(n.operatorToken.kind)) {
      const left = n.left.getText(sf);
      const right = n.right.getText(sf);
      if ((mentionsRoot.test(left) && SESSION_EXPR.test(right)) || (mentionsRoot.test(right) && SESSION_EXPR.test(left))) {
        found = true;
        return;
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(fn);
  return found;
}

function propertyKeyName(prop: ts.ObjectLiteralElementLike): string | undefined {
  if (
    (ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop)) &&
    prop.name &&
    (ts.isIdentifier(prop.name) || ts.isStringLiteralLike(prop.name))
  ) {
    return prop.name.text;
  }
  return undefined;
}

// The expression a `where` property scopes on. Shorthand (`where: { workspaceId }` after
// `const { workspaceId } = await req.json()`) is the SAME defect written shorter, and reading only
// PropertyAssignment.initializer would have missed it — the destructuring idiom is the common one
// in Next.js route handlers.
function propertyValue(prop: ts.ObjectLiteralElementLike): ts.Expression | undefined {
  if (ts.isPropertyAssignment(prop)) return prop.initializer;
  if (ts.isShorthandPropertyAssignment(prop)) return prop.name;
  return undefined;
}

interface Hit {
  node: ts.Node;
  column: string;
  source: string;
  root: string;
  sink: string;
}

// Prisma: `<client>.<model>.<verb>({ where: { <tenantColumn>: <request value> } })`, descending
// through nested objects and AND/OR arrays so a scope buried under a relation still counts.
function prismaHits(call: ts.CallExpression, tainted: Map<string, string>): Hit[] {
  const shape = prismaModelCall(call);
  const arg = call.arguments[0];
  if (!shape || !arg || !ts.isObjectLiteralExpression(arg)) return [];
  const whereProp = arg.properties.find((p) => propertyKeyName(p) === "where");
  if (!whereProp || !ts.isPropertyAssignment(whereProp)) return [];

  const hits: Hit[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isObjectLiteralExpression(n)) {
      for (const prop of n.properties) {
        const key = propertyKeyName(prop);
        const value = propertyValue(prop);
        if (!key || !value || !TENANT_SCOPE_COLUMN.test(key)) continue;
        const taint = taintOf(value, tainted);
        if (taint) hits.push({ node: prop, column: key, source: taint.source, root: taint.root, sink: `prisma.${shape.model}.${shape.verb}` });
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(whereProp.initializer);
  return hits;
}

// Query-builder idiom (Drizzle and anything sharing its operator vocabulary):
// `.where(eq(table.<tenantColumn>, <request value>))`, recursing through `and`/`or`/`not`.
function builderHits(whereCall: ts.CallExpression, tainted: Map<string, string>): Hit[] {
  const hits: Hit[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && COMPARISON_OPS.has(n.expression.text.toLowerCase())) {
      const col = n.arguments[0];
      const value = n.arguments[1];
      if (col && value && ts.isPropertyAccessExpression(col) && TENANT_SCOPE_COLUMN.test(col.name.text)) {
        const taint = taintOf(value, tainted);
        if (taint) {
          hits.push({ node: n, column: col.name.text, source: taint.source, root: taint.root, sink: `.where(${n.expression.text}(…))` });
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  for (const a of whereCall.arguments) visit(a);
  return hits;
}

function isFunctionLike(n: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(n) ||
    ts.isFunctionExpression(n) ||
    ts.isArrowFunction(n) ||
    ts.isMethodDeclaration(n) ||
    ts.isConstructorDeclaration(n)
  );
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];

  // Taint never crosses a function boundary downward from a sibling: for each query, the scope
  // chain is its own enclosing functions, outermost first. Bindings merge along that chain (an
  // arrow callback sees its handler's `const body = await req.json()`), while a request read in
  // some UNRELATED function of the same file contributes nothing. The guard is searched over the
  // outermost enclosing function — the handler — because that is where a session comparison sits.
  const chainOf = (node: ts.Node): ts.Node[] => {
    const chain: ts.Node[] = [];
    for (let n: ts.Node | undefined = node; n; n = n.parent) if (isFunctionLike(n)) chain.unshift(n);
    return chain.length > 0 ? chain : [sf];
  };

  const bindingsFor = new Map<ts.Node, Map<string, string>>();
  const taintFor = (chain: ts.Node[]): Map<string, string> => {
    const merged = new Map<string, string>();
    for (const scope of chain) {
      let own = bindingsFor.get(scope);
      if (!own) {
        own = taintedBindings(scope);
        bindingsFor.set(scope, own);
      }
      for (const [k, v] of own) merged.set(k, v);
    }
    return merged;
  };

  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n)) {
      const chain = chainOf(n);
      // No early-out on an empty binding map: `where: { organizationId: req.body.orgId }` reads the
      // request inline and declares nothing, so a "are there any tainted locals?" gate would have
      // skipped the most direct form of the defect.
      const tainted = taintFor(chain);
      const hits =
        ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "where"
          ? builderHits(n, tainted)
          : prismaHits(n, tainted);
      for (const hit of hits) {
        if (comparedAgainstSession(chain[0] ?? sf, sf, hit.root)) continue;
        const start = hit.node.getStart(sf);
        findings.push(
            mechanicalFinding({
              id: `AUTH-client-supplied-tenant-${hit.column}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${start}`,
              title: `${path} — tenant scope \`${hit.column}\` is populated from the request (\`${hit.source}\`)`,
              severity: "High",
              category: "Broken access control",
              taxonomy: "Object-level authorization gap: tenant predicate populated from the request",
              location: loc(path, sf, hit.node),
              evidence: `Heuristic "client-supplied-tenant": \`${hit.sink}\` scopes on \`${hit.column}\`, and that value traces to \`${hit.source}\` through same-function assignments. The query carries a tenant predicate and looks correctly scoped; the caller chooses which tenant it selects.`,
              impact:
                "The tenant discriminator is attacker-controlled, so the isolation gate is set by the request it is supposed to constrain: any authenticated caller reads or mutates another tenant's rows by editing one field. Because the predicate is present and names the right column, this passes code review and every detector that checks whether a tenant filter exists.",
              fix: `Derive \`${hit.column}\` from the verified session on the server (\`session.user.${hit.column}\` / the JWT claim), never from the request. If the caller must name a tenant — a multi-tenant admin or account switcher — compare the supplied value against the session's tenant membership and reject a mismatch before the query runs.`,
            precisionTier: "high",
          }),
        );
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

export function detectClientSuppliedTenantFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

export function scanClientSuppliedTenant(projectDir: string): Finding[] {
  return detectClientSuppliedTenantFindings(walkSourceFiles(projectDir));
}
