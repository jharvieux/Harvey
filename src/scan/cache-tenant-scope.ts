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
//   1. only functions that ALREADY HAVE a tenant/org-like identifier in scope are considered — a
//      cache with no tenant context at all is not this bug, it may be intentionally global. "In
//      scope" means parameter, local binding, or tenant-named property (#1362 — it meant PARAMETER
//      only until then, which made the idiomatic App Router spelling invisible); the sites this
//      declines to judge are counted and disclosed by CACHE-SCOPE-00 rather than left silent;
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

// Tenant-discriminator identifiers IN SCOPE in this function — not only its parameters.
//
// #1362: the gate used to be "a tenant/org-like PARAMETER", which is narrower than this detector's
// own stated intent ("only functions that ALREADY HAVE a tenant/org-like parameter in scope") and
// narrower than the shape most App Router code has. MEASURED 2026-07-27 on four spellings of one
// defect: only `getDashboard(tenantId, boardId)` fired; `const { tenantId } = await getSession()`
// and `session: { tenantId }` were both silent, and neither narrowing was recorded anywhere. Three
// sources now qualify a function:
//   1. parameters, including destructured object patterns (the original);
//   2. LOCAL bindings — `const { tenantId } = await getSession()`, `const orgId = ctx.orgId`;
//   3. a tenant-named PROPERTY reached off any base — `session.tenantId`, `ctx.workspaceId`. This is
//      the general form of the issue's narrower suggestion (qualify a `session`/`ctx`/`auth`-named
//      parameter): the base's name is not what makes the value a tenant discriminator, the property
//      name is, and going by the property also covers `req.auth.orgId` and `locals.user.tenantId`
//      without a hard-coded list of blessed base names. Decision recorded here rather than left
//      implicit, per the issue's "record the decision either way".
// Only the NAME is collected, because the key check is textual: `t:${session.tenantId}:…` contains
// `tenantId`, so a key built from the same property mentions it and clears the finding.
function tenantNamesInScope(fn: ts.SignatureDeclaration & ts.Node): string[] {
  const names = new Set<string>();
  const collect = (name: ts.BindingName) => {
    if (ts.isIdentifier(name)) {
      if (TENANT_PARAM_NAME.test(name.text)) names.add(name.text);
    } else if (ts.isObjectBindingPattern(name)) {
      for (const el of name.elements) if (ts.isBindingElement(el)) collect(el.name);
    }
  };
  for (const p of fn.parameters) collect(p.name);

  const visit = (n: ts.Node) => {
    if (ts.isVariableDeclaration(n)) collect(n.name);
    if (ts.isPropertyAccessExpression(n) && TENANT_PARAM_NAME.test(n.name.text)) names.add(n.name.text);
    if (!isFunctionLike(n) || n === fn) ts.forEachChild(n, visit);
  };
  ts.forEachChild(fn, visit);
  return [...names];
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

// #1362: what this detector DECLINED to consider, so the bound is countable rather than only
// commented. `unscoped` = a read-through cache pair in a function with no tenant identifier in scope
// at all; `writeOnly` = a `.set()` with no paired `.get()` (the deliberate #1196 narrowing).
interface CacheScopeCensus {
  unscoped: number;
  writeOnly: number;
}

function detectFunction(
  fn: ts.SignatureDeclaration & ts.Node,
  sf: ts.SourceFile,
  path: string,
  census: CacheScopeCensus,
): Finding[] {
  const tenantParams = tenantNamesInScope(fn);
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
    const pairedGet = gets.find((g) => g.text === set.text);
    if (!pairedGet) {
      census.writeOnly++; // read-through pair required — see FP DISCIPLINE above
      continue;
    }
    if (tenantParams.length === 0) {
      census.unscoped++;
      continue;
    }
    if (mentionsAny(set.key, sf, tenantParams)) continue;
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

function detectFile(path: string, sf: ts.SourceFile, census: CacheScopeCensus): Finding[] {
  const findings: Finding[] = [];
  const visit = (n: ts.Node) => {
    if (isFunctionLike(n)) {
      findings.push(...detectFunction(n as ts.SignatureDeclaration & ts.Node, sf, path, census));
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

// #1362, the coverage-guard rule applied at detector level: a codebase whose caches this heuristic
// declined to judge must not read as a codebase with no cache problems. Emitted only when the
// population is NON-ZERO — a limit with a population of zero is a guess, not a limit — so a target
// with no declined cache site gets no row.
function cacheScopeDisclosure(census: CacheScopeCensus): Finding[] {
  const total = census.unscoped + census.writeOnly;
  if (total === 0) return [];
  return [
    {
      id: "CACHE-SCOPE-00",
      title: `${total} cache site${total === 1 ? "" : "s"} not judged for tenant scoping`,
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
      taxonomy: "Coverage — cache sites outside the tenant-scope heuristic's bounds",
      location: "(repo-wide)",
      status: "Open",
      evidence:
        `The cache-tenant-scope heuristic (CACHE-key-no-tenant) judged neither of these classes. ` +
        `${census.unscoped} read-through cache get/set pair${census.unscoped === 1 ? "" : "s"} sit in a function with no ` +
        `tenant/org/workspace-named identifier in scope — as a parameter, a local binding, or a property such as ` +
        `\`session.tenantId\` — so the heuristic cannot tell an intentionally global cache from one whose tenant ` +
        `context is reached through a name it does not recognise. ${census.writeOnly} cache write${census.writeOnly === 1 ? " has" : "s have"} ` +
        `no paired read on the same key, which #1196 deliberately leaves alone as a weaker signal.`,
      impact:
        "Cross-tenant cache poisoning in these sites was neither confirmed nor ruled out. Zero CACHE-key-no-tenant findings on this codebase is not a statement that every cache is correctly scoped.",
      fix: "Review these cache sites by hand for a tenant discriminator in the key, or declare the app's tenant identifier naming so the heuristic can recognise it.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}

export function detectCacheTenantScopeFindings(files: SourceInput[]): Finding[] {
  const census: CacheScopeCensus = { unscoped: 0, writeOnly: 0 };
  const findings = files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text), census));
  return [...findings, ...cacheScopeDisclosure(census)];
}

export function scanCacheTenantScope(projectDir: string): Finding[] {
  return detectCacheTenantScopeFindings(walkSourceFiles(projectDir));
}
