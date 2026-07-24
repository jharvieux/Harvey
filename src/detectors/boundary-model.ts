// M9 — framework-agnostic server→client boundary model (#916).
//
// Every M9 check used to key on Next.js App Router literals (`app/`, `"use client"`, `"use server"`,
// `export const dynamic`). But most of the checks are not Next-specific defects — the highest-value
// one, a full DB row crossing the server→client boundary and serialising into the client payload,
// exists identically in every SSR framework under a different NAME. What is framework-specific is
// only the MARKER that identifies the boundary.
//
// This module factors that marker set out of the conventions. A `BoundaryAdapter` supplies, per
// framework:
//   - what marks a CLIENT context (code that ships to the browser) — `isClientContext`,
//   - the server→client CROSSINGS whose value serialises to the client — `detectServerClientLeak`,
//   - the server MUTATION entry points (Next Server Action / Remix `action` / TanStack
//     `createServerFn`) — `serverMutations`,
//   - the human NOUN those entry points carry in findings — `mutationNoun`,
//   - which checks the adapter actually implements — `supports`.
// The shared checks (server→client leak, server-mutation authz + input-validation, client-supplied
// owner id, SSR browser-API misuse, data-fetching waterfall) are then expressed against the
// abstraction, and each adapter's Next/Remix/TanStack literals live only in its own implementation.
//
// A check an adapter does NOT implement is disclosed as an explicit not-assessed row naming the
// check (notAssessedCheckNote) — never silently dropped (the coverage-guard principle in CLAUDE.md).

import type ts from "typescript";
import type { Finding } from "../findings.js";
import { FRAMEWORK_LABELS, type TargetFramework } from "../scan/framework-detect.js";
import type { NextId, SourceInput } from "./common.js";

// The M9 check surface, named once so an adapter can declare which it implements and the pass can
// emit a not-assessed row for each it does not. The first six port on concept across SSR
// frameworks; the rest are Next App-Router-specific (route segment / cache / dynamic-rendering
// config, the Full Route Cache, Next's `server-only` poison-pill, `<Suspense>`/PPR, the route.ts
// handler convention) and stay Next-only until a framework grows a genuine analogue.
export type M9Check =
  | "server-client-leak"
  | "server-mutation-authz"
  | "server-mutation-validation"
  | "client-owner-id"
  | "ssr-browser-api"
  | "data-waterfall"
  | "missing-server-only"
  | "accidental-dynamic"
  | "cache-config"
  | "route-segment-config"
  | "missing-suspense"
  | "unbounded-route";

// One server mutation entry point: the function node plus the name to show. Next's `"use server"`
// function, Remix/RR7's exported `action`, and TanStack's `createServerFn(...).handler(fn)` all
// reduce to this shape, so the authz/validation/owner-id checks run over it framework-blind.
export interface ServerMutation {
  name: string;
  node: ts.Node;
}

export interface BoundaryAdapter {
  framework: TargetFramework;
  label: string;
  // The checks this adapter implements. A check absent here draws a not-assessed row.
  supports: ReadonlySet<M9Check>;
  // The human noun a server mutation carries in this framework's findings ("Server Action",
  // "route action", "server function"). Keeps the shared authz/validation finding text framework-true.
  mutationNoun: string;
  // Marks a client context — a module whose code ships to the browser (Next `"use client"`).
  isClientContext(sf: ts.SourceFile): boolean;
  // Server→client leak findings for the whole source set (the crossing collector is
  // framework-specific: Next reads JSX prop-passing to imported Client Components, Remix/TanStack
  // read the `loader` / server-function RETURN value).
  detectServerClientLeak(sources: Map<string, ts.SourceFile>, nextId: NextId, files: SourceInput[]): Finding[];
  // The server mutation entry points declared in one file.
  serverMutations(path: string, sf: ts.SourceFile): ServerMutation[];
}

// Human-readable one-liner per check, for the not-assessed rows. Names what would have been
// assessed, so its absence reads as a disclosed limitation, not a clean bill of health.
const CHECK_LABELS: Record<M9Check, string> = {
  "server-client-leak": "server→client data leak (full DB row serialised to the client)",
  "server-mutation-authz": "server mutation missing authorization",
  "server-mutation-validation": "server mutation missing input validation",
  "client-owner-id": "client-supplied owner id trusted by a server mutation",
  "ssr-browser-api": "SSR-only browser-API misuse (window/document on the render path)",
  "data-waterfall": "data-fetching waterfall (independent sequential queries)",
  "missing-server-only": "server-only module guard",
  "accidental-dynamic": "accidental dynamic rendering",
  "cache-config": "unsafe/missing cache config",
  "route-segment-config": "route segment config (dynamic/revalidate)",
  "missing-suspense": "missing Suspense/streaming boundary",
  "unbounded-route": "unbounded/self-calling route or edge fn",
};

// A row disclosing that `check` was NOT assessed for `adapter`'s framework — emitted for every
// check the adapter does not implement, so partial coverage is stated, never silently upgraded to
// full. `scope` is "(whole target)" or a workspace-relative dir.
export function notAssessedCheckNote(nextId: NextId, adapter: BoundaryAdapter, check: M9Check, scope: string): Finding {
  const label = adapter.label;
  const subject = scope === "(whole target)" ? "Target" : `Workspace \`${scope}\``;
  const checkLabel = CHECK_LABELS[check];
  return {
    id: nextId(),
    title: `M9 not assessed — ${checkLabel} (${label})`,
    severity: "Info",
    confidence: "N/A",
    category: "Performance",
    taxonomy: `M9 — ${checkLabel} — not assessed (${label})`,
    location: scope,
    status: "Open",
    evidence: `${subject} framework detected as ${label}, which IS analysed on the boundary model, but the "${checkLabel}" check has no ${label} implementation — Next's marker for it (route segment / cache / dynamic-rendering config, the \`server-only\` poison-pill, \`<Suspense>\`, or the \`route.ts\` handler convention) has no shared analogue here.`,
    impact: `This M9 surface is unassessed on this scope. Recorded explicitly so its absence reads as "not assessed here", not "assessed and clean" — the fail-loud coverage guard.`,
    fix: `None — informational. Review this surface for ${label} by hand; native ${label} support for this check is tracked follow-up.`,
    value: 1,
    ease: 5,
    safety: 5,
    precisionTier: "high",
  };
}

// Convenience: FRAMEWORK_LABELS re-export so adapter files need one import for their label.
export function frameworkLabel(framework: TargetFramework): string {
  return FRAMEWORK_LABELS[framework];
}
