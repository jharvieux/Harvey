// #848 — M9 per-check calibration corpus. Before this, only the client-supplied-owner-id class
// (m9-authz.entries.ts) had scored corpus entries; the other nine M9 checks were pinned solely by
// the synthetic fixtures in src/detectors/app-router.test.ts, so no scored corpus stood behind the
// bulk of the module and "measure, don't recall" could not produce an M9 recall number.
//
// These entries bind ONE positive + ONE negative per check to the SAME committed fixtures the
// detector's own suite uses (src/detectors/__fixtures__/<check>/{positive,negative}) — so the
// answer key can't drift from what the scanner emits, and no new files land in the scanned
// calibration target (which would ripple through knip/dup/dry-run). The live scoring lives in
// calibration.test.ts's "#848 M9 per-check corpus" block: each check's fixture dir is loaded,
// path-prefixed to a globally-unique location (`m9-corpus/<check>/<kind>`), run through
// detectAppRouterFindings, and scored with scoreEntry. The prefix keeps every location distinct so
// the whole-corpus ambiguity guard (buildCoverageMatrix over CORPUS) stays clean.
//
// Like m9-authz.entries.ts these carry module: "M9": the findings come from the static-detect AST
// pass, not runMechanicalScan, so validate-calibration.ts excludes them from its M1 score and the
// per-module census counts them instead. Every positive is `review` tier — the M9 AST heuristics
// are never free-count (makeFinding defaults to "review").

import type { CorpusEntry } from "./types.js";

export const m9CheckEntries: CorpusEntry[] = [
  {
    id: "M9C-LEAK-POS",
    kind: "positive",
    cls: "full DB row passed whole as a prop to a Client Component",
    module: "M9",
    location: "m9-corpus/leak/positive",
    match: ["Server→client data leak"],
    expectedTier: "review",
    note: "server-client-leak/positive: a Server Component passes an entire query-result row into a 'use client' <UserCard />, serializing every field into the RSC payload. Detected by detectServerClientLeak.",
  },
  {
    id: "M9C-LEAK-NEG",
    kind: "negative",
    cls: "narrowed/projected prop passed to the same Client Component",
    module: "M9",
    location: "m9-corpus/leak/negative",
    match: ["Server→client data leak"],
    note: "server-client-leak/negative: the page passes a narrowed field (row.name), not the whole row — the safe projection shape, so nothing fires.",
  },
  {
    id: "M9C-SERVERONLY-POS",
    kind: "positive",
    cls: "server-exclusive secret module missing the 'server-only' guard, reachable from a client file",
    module: "M9",
    location: "m9-corpus/serveronly/positive",
    match: ["Missing server-only guard"],
    expectedTier: "review",
    note: "missing-server-only/positive: lib/admin-client.ts reads a service-role secret, has no `import 'server-only'`, and a 'use client' widget really imports it. Detected by detectMissingServerOnly.",
  },
  {
    id: "M9C-SERVERONLY-NEG",
    kind: "negative",
    cls: "secret module with the guard present / not client-reachable / no secret",
    module: "M9",
    location: "m9-corpus/serveronly/negative",
    match: ["Missing server-only guard"],
    note: "missing-server-only/negative: the guard present, the route-handler exemption, a module with no secret, and a secret nothing on the client imports — all four non-findings.",
  },
  {
    id: "M9C-ACTION-AUTH-POS",
    kind: "positive",
    cls: "Server Action mutating data with no visible auth check",
    module: "M9",
    location: "m9-corpus/action-auth/positive",
    match: ["Server Action missing authorization"],
    expectedTier: "review",
    note: "server-action-auth/positive: a 'use server' action calls a mutation with no session/authority check in its body (routed to the M1 authorization class). Detected by detectServerActionAuthAndValidation.",
  },
  {
    id: "M9C-ACTION-AUTH-NEG",
    kind: "negative",
    cls: "Server Action that checks the caller's session before mutating",
    module: "M9",
    location: "m9-corpus/action-auth/negative",
    match: ["Server Action missing authorization"],
    note: "server-action-auth/negative: the same action once it authenticates and scopes the mutation to the session — no missing-auth finding.",
  },
  {
    id: "M9C-ACTION-VAL-POS",
    kind: "positive",
    cls: "Server Action reading input into a mutation with no schema validation",
    module: "M9",
    location: "m9-corpus/action-validation/positive",
    match: ["Server Action missing input validation"],
    expectedTier: "review",
    note: "server-action-validation/positive: a mutating action reads formData straight into the DB with no Zod/valibot parse. Detected by detectServerActionAuthAndValidation.",
  },
  {
    id: "M9C-ACTION-VAL-NEG",
    kind: "negative",
    cls: "Server Action whose input is parsed through a schema",
    module: "M9",
    location: "m9-corpus/action-validation/negative",
    match: ["Server Action missing input validation"],
    note: "server-action-validation/negative: the same action once its input is validated through a Zod schema — nothing fires.",
  },
  {
    id: "M9C-CACHE-POS",
    kind: "positive",
    cls: "data-fetching page/layout with no cache configuration",
    module: "M9",
    location: "m9-corpus/cache/positive",
    match: ["Unsafe/missing cache config"],
    expectedTier: "review",
    note: "cache-config/positive: a page queries the DB with no unstable_cache/'use cache'/revalidate signal anywhere. Best-effort review-tier heuristic, detectUnsafeCacheConfig.",
  },
  {
    id: "M9C-CACHE-NEG",
    kind: "negative",
    cls: "page that wraps the read in unstable_cache",
    module: "M9",
    location: "m9-corpus/cache/negative",
    match: ["Unsafe/missing cache config"],
    note: "cache-config/negative: the same page once the read is wrapped in unstable_cache — the cache signal suppresses the finding.",
  },
  {
    id: "M9C-WATERFALL-POS",
    kind: "positive",
    cls: "independent sequential DB awaits that could run in parallel",
    module: "M9",
    location: "m9-corpus/waterfall/positive",
    match: ["Data-fetching waterfall"],
    expectedTier: "review",
    note: "waterfall/positive: two independent awaited queries back-to-back in an async Server Component. Detected by detectDataFetchingWaterfalls.",
  },
  {
    id: "M9C-WATERFALL-NEG",
    kind: "negative",
    cls: "the same queries combined with Promise.all",
    module: "M9",
    location: "m9-corpus/waterfall/negative",
    match: ["Data-fetching waterfall"],
    note: "waterfall/negative: the two queries combined with Promise.all — concurrent, so nothing fires.",
  },
  {
    id: "M9C-DYNAMIC-POS",
    kind: "positive",
    cls: "searchParams read directly in the route's top-level component (forces dynamic SSR)",
    module: "M9",
    location: "m9-corpus/dynamic/positive",
    match: ["Accidental dynamic rendering"],
    expectedTier: "review",
    note: "dynamic-rendering/positive: the page reads a searchParams field directly at the top level, opting the whole route out of static/ISR. Detected by detectAccidentalDynamicRendering.",
  },
  {
    id: "M9C-DYNAMIC-NEG",
    kind: "negative",
    cls: "searchParams only forwarded to a Suspense-wrapped leaf",
    module: "M9",
    location: "m9-corpus/dynamic/negative",
    match: ["Accidental dynamic rendering"],
    note: "dynamic-rendering/negative: the page forwards searchParams unread to a leaf — the safe shape, nothing fires.",
  },
  {
    id: "M9C-SSR-POS",
    kind: "positive",
    cls: "browser global read on the SSR render path",
    module: "M9",
    location: "m9-corpus/ssr/positive",
    match: ["SSR-only API misuse"],
    expectedTier: "review",
    note: "ssr-browser-api/positive: a Server Component reads window.innerWidth directly in its render body — undefined during SSR. Detected by detectSsrBrowserApiMisuse.",
  },
  {
    id: "M9C-SSR-NEG",
    kind: "negative",
    cls: "browser global read guarded by a typeof check",
    module: "M9",
    location: "m9-corpus/ssr/negative",
    match: ["SSR-only API misuse"],
    note: "ssr-browser-api/negative-typeof: the read is guarded by `typeof window !== 'undefined'` — the standard SSR-safe idiom, nothing fires.",
  },
  {
    id: "M9C-SPA-BOUNDARY-POS",
    kind: "positive",
    cls: "Vite/SPA entry mounts the root with no error boundary anywhere",
    module: "M9",
    location: "m9-corpus/spa/positive",
    match: ["SPA missing root error boundary"],
    expectedTier: "review",
    note: "spa-error-boundary/positive (scored with framework 'vite'): main.tsx mounts the React root and no error boundary of any form appears in the SPA. Detected by detectSpaRootErrorBoundary.",
  },
  {
    id: "M9C-SPA-BOUNDARY-NEG",
    kind: "negative",
    cls: "Vite/SPA that already wraps the root in an error boundary",
    module: "M9",
    location: "m9-corpus/spa/negative",
    match: ["SPA missing root error boundary"],
    note: "spa-error-boundary/negative-has-boundary (framework 'vite'): the SPA imports react-error-boundary around the root — nothing fires.",
  },
];
