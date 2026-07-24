// M9 — TanStack Start boundary adapter (#918).
//
// TanStack Start's server boundary is a different shape from Remix's loader/action: a directly
// callable server entry point is `createServerFn({ method }).validator(schema).handler(async ({ data
// }) => …)` (verified against the current docs 2026-07-24 — `.validator()` is the input-validation
// step, `.handler()` holds the server logic and receives `{ data }`). Plain `.ts`/`.tsx`, so the
// compiler-API machinery parses it unchanged; only the convention is new.
//
// Implemented on the boundary model:
//   - server→client leak — a full DB row RETURNED from a `createServerFn` handler (the resolved
//     value is serialised to the client caller), reusing returnedRawRow (boundary-leak.ts).
//   - server-function authz + input-validation — run by the shared checks over the WHOLE
//     `createServerFn(...)` chain, so the chain-level `.validator()` counts as validation and the
//     handler-body auth/mutation are seen. Framework-true noun: "server function".
//   - SSR browser-API misuse and data-fetching waterfall — the framework-agnostic detectors reused.
// Not implemented (disclosed as not-assessed rows): client-owner-id (a typed-arg refinement that
// needs the handler's own params, out of scope here), `server-only`, route-segment/cache/
// dynamic-rendering config, `<Suspense>`, and the route.ts handler convention.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { collectRawRowNames, makeFinding } from "./app-router.js";
import type { BoundaryAdapter, M9Check, ServerMutation } from "./boundary-model.js";
import { frameworkLabel } from "./boundary-model.js";
import { returnedRawRow, returnExpressions } from "./boundary-leak.js";
import { loc, type NextId } from "./common.js";

const TANSTACK_SUPPORTS: readonly M9Check[] = [
  "server-client-leak",
  "server-mutation-authz",
  "server-mutation-validation",
  "ssr-browser-api",
  "data-waterfall",
];

function isTanstackClient(sf: ts.SourceFile): boolean {
  return /\.client\.[jt]sx?$/.test(sf.fileName);
}

// A call chain roots in `createServerFn(...)` — descend the callee chain through `.validator()` /
// `.middleware()` / `.handler()` etc. until the base `createServerFn(...)` call.
function rootsInCreateServerFn(expr: ts.Expression): boolean {
  let cur: ts.Expression = expr;
  for (;;) {
    if (ts.isCallExpression(cur)) {
      if (ts.isIdentifier(cur.expression) && cur.expression.text === "createServerFn") return true;
      cur = cur.expression;
    } else if (ts.isPropertyAccessExpression(cur)) {
      cur = cur.expression;
    } else {
      return false;
    }
  }
}

// The `export const name = createServerFn()...` the chain is bound to.
function enclosingConstName(node: ts.Node): string | undefined {
  const decl = ts.findAncestor(node, ts.isVariableDeclaration);
  return decl && ts.isIdentifier(decl.name) ? decl.name.text : undefined;
}

interface ServerFnChain {
  name: string;
  chainNode: ts.CallExpression; // the whole createServerFn(...)....handler(...) call
  handler: ts.ArrowFunction | ts.FunctionExpression | undefined;
}

function collectServerFns(sf: ts.SourceFile): ServerFnChain[] {
  const out: ServerFnChain[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "handler" &&
      rootsInCreateServerFn(node.expression.expression)
    ) {
      const arg = node.arguments[0];
      const handler = arg && (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) ? arg : undefined;
      out.push({ name: enclosingConstName(node) ?? "<serverFn>", chainNode: node, handler });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

function detectServerFnLeak(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (isTanstackClient(sf)) continue;
    const chains = collectServerFns(sf);
    if (chains.length === 0) continue;
    const rawRowNames = collectRawRowNames(sf);
    if (rawRowNames.size === 0) continue;

    for (const { name, handler } of chains) {
      const body = handler?.body;
      if (!body) continue;
      const returns = ts.isBlock(body) ? returnExpressions(body) : ts.isExpression(body) ? [body] : [];
      for (const ret of returns) {
        const hit = returnedRawRow(ret, rawRowNames);
        if (!hit) continue;
        findings.push(
          makeFinding(nextId, {
            title: `Full DB row returned from a TanStack server function to the client`,
            severity: "High",
            confidence: "Likely",
            category: "Security",
            taxonomy: "M9 — Server→client data leak",
            location: loc(path, sf, ret),
            evidence: `\`${name}\` returns \`${hit.name}\` (a query-result row)${hit.field ? ` as the \`${hit.field}\` field` : ""}. A \`createServerFn\` handler's resolved value is serialised to every client caller, so every field on the row ships to the browser.`,
            impact: "Any field on the row the UI does not render (other-tenant data, secrets, hashes, internal flags) still reaches the browser and is readable in devtools/view-source.",
            fix: `Project the row to an explicit minimal DTO (whitelist only the fields the caller renders) before returning it from the server function.`,
            value: 5,
            ease: 3,
            safety: 4,
          }),
        );
        break; // one leak finding per server function
      }
    }
  }
  return findings;
}

export const tanstackAdapter: BoundaryAdapter = {
  framework: "tanstack-start",
  label: frameworkLabel("tanstack-start"),
  supports: new Set(TANSTACK_SUPPORTS),
  mutationNoun: "server function",
  isClientContext: isTanstackClient,
  detectServerClientLeak: (sources, nextId) => detectServerFnLeak(sources, nextId),
  serverMutations: (_path, sf): ServerMutation[] =>
    isTanstackClient(sf) ? [] : collectServerFns(sf).map(({ name, chainNode }) => ({ name, node: chainNode })),
};
