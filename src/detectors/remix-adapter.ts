// M9 — Remix / React Router 7 boundary adapter (#917).
//
// RR7 absorbed Remix's data model, so one adapter serves both: a route module exports a `loader`
// (server read, its return serialised to the client via `useLoaderData`) and/or an `action` (server
// mutation, the direct analogue of a Next Server Action). Both are plain `.ts`/`.tsx`, so the
// existing compiler-API machinery parses them unchanged — only the conventions are new.
//
// Implemented on the boundary model:
//   - server→client leak — a full DB row RETURNED from a `loader` (Next's leak is a prop; here it
//     is the return value), reusing returnedRawRow (boundary-leak.ts).
//   - server-mutation authz + input-validation — run by the shared checks over the exported
//     `action`, with the framework-true noun "route action".
//   - SSR browser-API misuse and data-fetching waterfall — the framework-agnostic detectors reused
//     as-is (a loader's sequential awaits are a waterfall; window on a Remix render path throws in SSR).
// Not implemented (disclosed as not-assessed rows): the Next-specific client-owner-id typed-arg
// refinement, `server-only`, route-segment/cache/dynamic-rendering config, `<Suspense>`, and the
// route.ts handler convention — none has a shared Remix analogue in this pass.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { collectRawRowNames, makeFinding } from "./app-router.js";
import type { BoundaryAdapter, M9Check, ServerMutation } from "./boundary-model.js";
import { frameworkLabel } from "./boundary-model.js";
import { returnedRawRow, returnExpressions } from "./boundary-leak.js";
import { loc, type NextId } from "./common.js";
import type { TargetFramework } from "../scan/framework-detect.js";

const REMIX_SUPPORTS: readonly M9Check[] = [
  "server-client-leak",
  "server-mutation-authz",
  "server-mutation-validation",
  "ssr-browser-api",
  "data-waterfall",
];

// A `.client.ts(x)` module is Remix's browser-only file convention — its code never runs on the
// server, so the waterfall check (server-side sequential awaits) must skip it. Universal route
// modules (the common case) are treated as server context, where loaders/actions live.
function isRemixClient(sf: ts.SourceFile): boolean {
  return /\.client\.[jt]sx?$/.test(sf.fileName);
}

// The exported `loader` / `action` function node, whether declared as `export async function
// loader(){}` or `export const loader = async () => {}`. RR7's `clientLoader`/`clientAction` run on
// the browser and are deliberately NOT collected here — they are not the server boundary.
function exportedRouteFn(sf: ts.SourceFile, name: "loader" | "action"): ts.Node | undefined {
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name?.text === name && stmt.body && hasExport(stmt)) return stmt;
    if (ts.isVariableStatement(stmt) && hasExport(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (ts.isIdentifier(decl.name) && decl.name.text === name && decl.initializer && (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))) {
          return decl.initializer;
        }
      }
    }
  }
  return undefined;
}

function hasExport(node: ts.FunctionDeclaration | ts.VariableStatement): boolean {
  return node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
}

function fnBody(fn: ts.Node): ts.Node | undefined {
  return (fn as ts.FunctionLikeDeclaration).body;
}

function detectRemixLoaderLeak(sources: Map<string, ts.SourceFile>, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    if (isRemixClient(sf)) continue;
    const loader = exportedRouteFn(sf, "loader");
    if (!loader) continue;
    const body = fnBody(loader);
    if (!body) continue;
    const rawRowNames = collectRawRowNames(sf);
    if (rawRowNames.size === 0) continue;

    const returns = ts.isBlock(body) ? returnExpressions(body) : ts.isExpression(body) ? [body] : [];
    for (const ret of returns) {
      const hit = returnedRawRow(ret, rawRowNames);
      if (!hit) continue;
      findings.push(
        makeFinding(nextId, {
          title: `Full DB row returned from a Remix loader to the client`,
          severity: "High",
          confidence: "Likely",
          category: "Security",
          taxonomy: "M9 — Server→client data leak",
          location: loc(path, sf, ret),
          evidence: `\`${hit.name}\` (a query-result row) is returned ${hit.field ? `as the \`${hit.field}\` field of ` : ""}the loader's value. Everything \`useLoaderData()\` receives is serialised into the client HTML/payload, so every field on the row ships to the browser.`,
          impact: "Any field on the row the UI does not render (other-tenant data, secrets, hashes, internal flags) still reaches the browser and is readable in devtools/view-source.",
          fix: `Project the row to an explicit minimal DTO (whitelist only the fields the route renders) before returning it from the loader.`,
          value: 5,
          ease: 3,
          safety: 4,
        }),
      );
      break; // one leak finding per loader is enough signal
    }
  }
  return findings;
}

export function remixAdapter(framework: TargetFramework): BoundaryAdapter {
  return {
    framework,
    label: frameworkLabel(framework),
    supports: new Set(REMIX_SUPPORTS),
    mutationNoun: "route action",
    isClientContext: isRemixClient,
    detectServerClientLeak: (sources, nextId) => detectRemixLoaderLeak(sources, nextId),
    serverMutations: (_path, sf): ServerMutation[] => {
      if (isRemixClient(sf)) return [];
      const action = exportedRouteFn(sf, "action");
      return action ? [{ name: "action", node: action }] : [];
    },
  };
}
