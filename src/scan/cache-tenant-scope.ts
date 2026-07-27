// #1196 CACHE-TENANT-SCOPE — a cache key derived from the resource id alone, with no tenant
// discriminator, in a function that otherwise has one to hand. OWASP Multi-Tenant Application
// Security Cheat Sheet section 4 ("Prefix all cache keys with tenant identifier", "Use separate
// cache namespaces") — one of the sheet's five headline risks ("Shared Resource Poisoning"). Found
// as a measured gap by that sheet's independent corpus (owasp-multitenant.entries.ts,
// P-OWASP-MT-CACHE-KEY).
//
//   export async function getDashboard(tenantId: string, boardId: string) {
//     const cached = await cache.get(`dashboard:${boardId}`);
//     ...
//     await cache.set(`dashboard:${boardId}`, JSON.stringify(fresh));
//   }
//
// The first tenant to populate `dashboard:${boardId}` serves its rows to every other tenant asking
// for the same resource id.
//
// FP DISCIPLINE — this is the whole problem (per the issue). A tenant-agnostic cache is entirely
// legitimate for genuinely global data (feature flags, a published catalogue, static config), so a
// bare "cache key has no tenant variable" rule would fire on every cache in every codebase. Narrowed
// two ways:
//   1. only functions that ALREADY HAVE a tenant/org-like parameter in scope are considered — a
//      cache with no tenant context at all is not this bug, it may be intentionally global;
//   2. only a GET/SET PAIR sharing the identical key expression (the read-through-cache idiom the
//      fixture and its negative both use) counts, not a bare .set() — a one-off cache write without
//      a matching read is a different, weaker signal this detector deliberately leaves alone.
// The key's tenant coverage is checked by NAME, not full taint: does the tenant parameter's
// identifier appear anywhere in the key expression's printed text (directly, or through a `const
// key = …` binding resolved in the same function)? That is what the negative fixture requires
// (`t:${tenantId}:dashboard:${boardId}`) and what the positive fixture fails.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding, walkSourceFiles } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

// Narrower than TENANT_SCOPE_COLUMN (prisma-tenant-scope.ts): deliberately excludes user/owner/
// member/author, which are ordinary per-user cache keys and not the cross-TENANT class this sheet
// section is about.
const TENANT_PARAM_NAME = /^(tenant|org|organi[sz]ation|workspace|account|company)(_?id)?$/i;

// A cache-like receiver — the object the .get/.set is called on.
const CACHE_RECEIVER = /cache|redis|kv|memcache/i;

function isFunctionLike(n: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(n) ||
    ts.isFunctionExpression(n) ||
    ts.isArrowFunction(n) ||
    ts.isMethodDeclaration(n) ||
    ts.isConstructorDeclaration(n)
  );
}

// Parameter names (including destructured object params) that read like a tenant discriminator.
function tenantParamNames(fn: ts.SignatureDeclaration): string[] {
  const names: string[] = [];
  const collect = (name: ts.BindingName) => {
    if (ts.isIdentifier(name)) {
      if (TENANT_PARAM_NAME.test(name.text)) names.push(name.text);
    } else if (ts.isObjectBindingPattern(name)) {
      for (const el of name.elements) if (ts.isBindingElement(el)) collect(el.name);
    }
  };
  for (const p of fn.parameters) collect(p.name);
  return names;
}

// `const key = …` bindings declared directly in the function body, so a key built once and reused
// for both .get and .set resolves to the same expression.
function localKeyBindings(fn: ts.Node): Map<string, ts.Expression> {
  const bindings = new Map<string, ts.Expression>();
  const visit = (n: ts.Node) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
      bindings.set(n.name.text, n.initializer);
    }
    if (!isFunctionLike(n) || n === fn) ts.forEachChild(n, visit);
  };
  ts.forEachChild(fn, visit);
  return bindings;
}

function resolveKeyExpr(expr: ts.Expression, bindings: Map<string, ts.Expression>): ts.Expression {
  return ts.isIdentifier(expr) && bindings.has(expr.text) ? bindings.get(expr.text)! : expr;
}

function mentionsAny(expr: ts.Expression, sf: ts.SourceFile, names: string[]): boolean {
  const text = expr.getText(sf);
  return names.some((n) => new RegExp(`\\b${n}\\b`).test(text));
}

// A `.get`/`.set` call on a cache-like receiver, keyed by its FIRST argument.
function cacheCall(node: ts.CallExpression): { method: "get" | "set"; key: ts.Expression } | undefined {
  if (!ts.isPropertyAccessExpression(node.expression)) return undefined;
  const method = node.expression.name.text;
  if (method !== "get" && method !== "set") return undefined;
  const receiver = node.expression.expression;
  const receiverName = ts.isIdentifier(receiver) ? receiver.text : ts.isPropertyAccessExpression(receiver) ? receiver.name.text : undefined;
  if (!receiverName || !CACHE_RECEIVER.test(receiverName)) return undefined;
  const key = node.arguments[0];
  return key ? { method, key } : undefined;
}

function detectFunction(fn: ts.SignatureDeclaration & ts.Node, sf: ts.SourceFile, path: string): Finding[] {
  const tenantParams = tenantParamNames(fn);
  if (tenantParams.length === 0) return [];

  const bindings = localKeyBindings(fn);
  const gets: { key: ts.Expression; text: string; node: ts.CallExpression }[] = [];
  const sets: { key: ts.Expression; text: string; node: ts.CallExpression }[] = [];

  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n)) {
      const call = cacheCall(n);
      if (call) {
        const resolved = resolveKeyExpr(call.key, bindings);
        const entry = { key: resolved, text: resolved.getText(sf), node: n };
        (call.method === "get" ? gets : sets).push(entry);
      }
    }
    if (!isFunctionLike(n) || n === fn) ts.forEachChild(n, visit);
  };
  ts.forEachChild(fn, visit);

  const findings: Finding[] = [];
  for (const set of sets) {
    if (mentionsAny(set.key, sf, tenantParams)) continue;
    const pairedGet = gets.find((g) => g.text === set.text);
    if (!pairedGet) continue; // read-through pair required — see FP DISCIPLINE above
    findings.push(
      mechanicalFinding({
        id: `CACHE-key-no-tenant-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${set.node.getStart(sf)}`,
        title: `${path} — cache key has no tenant discriminator, though \`${tenantParams[0]}\` is in scope`,
        severity: "Medium",
        category: "Broken access control",
        taxonomy: "Cache key without a tenant discriminator (cross-tenant cache poisoning)",
        location: loc(path, sf, set.node),
        evidence: `Heuristic "cache-tenant-scope" matched a .get/.set read-through cache pair keyed on \`${set.text}\`, which does not mention the in-scope tenant parameter \`${tenantParams[0]}\`.`,
        impact:
          "The first tenant to populate this cache entry serves its rows to every other tenant that requests the same resource id — OWASP's 'Shared Resource Poisoning' risk.",
        fix: `Prefix the cache key with the tenant discriminator, e.g. \`t:\${${tenantParams[0]}}:...\`, or use a per-tenant cache namespace.`,
        precisionTier: "review",
      }),
    );
  }
  return findings;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const visit = (n: ts.Node) => {
    if (isFunctionLike(n)) {
      findings.push(...detectFunction(n as ts.SignatureDeclaration & ts.Node, sf, path));
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

export function detectCacheTenantScopeFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

export function scanCacheTenantScope(projectDir: string): Finding[] {
  return detectCacheTenantScopeFindings(walkSourceFiles(projectDir));
}
