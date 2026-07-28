// #848 — M9 per-check calibration corpus. Before this, only the client-supplied-owner-id class
// (m9-authz.entries.ts) had scored corpus entries; the other M9 checks were pinned solely by
// the synthetic fixtures in src/detectors/app-router.test.ts, so no scored corpus stood behind the
// bulk of the module and "measure, don't recall" could not produce an M9 recall number. #848 seeded
// nine pairs; #1047 seeded the four checks #846/#843 landed afterwards plus the #1051 cache-bleed
// check, so every M9 check the detector can emit is now scored.
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

  // #1047 — the four checks #846/#843 added after #848 seeded the nine above. They were pinned only
  // by inline-source assertions in app-router.test.ts, so a regression in any of them was invisible
  // to the corpus gate while docs/m9-app-router.md claimed full coverage. Each now has the same
  // committed-fixture-backed pos/neg pair as the rest.
  {
    id: "M9C-SEGMENT-POS",
    kind: "positive",
    cls: "force-static route segment config on a route that reads per-request/auth data",
    module: "M9",
    location: "m9-corpus/segment/positive",
    match: ["Unsafe route segment config"],
    expectedTier: "review",
    note: "route-segment-config/positive: `export const dynamic = 'force-static'` on a page that reads the session cookie — the personalized render is frozen into the static cache. Detected by detectRouteSegmentConfig.",
  },
  {
    id: "M9C-SEGMENT-NEG",
    kind: "negative",
    cls: "force-static on a genuinely public page with no per-request data",
    module: "M9",
    location: "m9-corpus/segment/negative",
    match: ["Unsafe route segment config"],
    note: "route-segment-config/negative: the same directive on a static About page — the correct use of force-static, so nothing fires.",
  },
  {
    id: "M9C-SEGMENT-CONFLICT-POS",
    kind: "positive",
    cls: "route segment config whose two halves cancel (force-dynamic + positive revalidate)",
    module: "M9",
    location: "m9-corpus/segment-conflict/positive",
    match: ["Conflicting route segment config"],
    expectedTier: "review",
    note: "route-segment-conflict/positive: `force-dynamic` never caches, so `revalidate = 3600` is dead config — the route does not render the way the config reads. Detected by detectRouteSegmentConfig.",
  },
  {
    id: "M9C-SEGMENT-CONFLICT-NEG",
    kind: "negative",
    cls: "coherent revalidate-only config",
    module: "M9",
    location: "m9-corpus/segment-conflict/negative",
    match: ["Conflicting route segment config"],
    note: "route-segment-conflict/negative: `revalidate = 60` alone, with no `dynamic` export to contradict it — nothing fires.",
  },
  {
    id: "M9C-SUSPENSE-POS",
    kind: "positive",
    cls: "dynamic read plus async data fetch with no Suspense/streaming boundary",
    module: "M9",
    location: "m9-corpus/suspense/positive",
    match: ["Missing Suspense boundary"],
    expectedTier: "review",
    note: "missing-suspense/positive: the page reads cookies() and awaits a fetch with no <Suspense> anywhere — the whole route blocks instead of streaming a shell. Detected by detectMissingSuspenseBoundary.",
  },
  {
    id: "M9C-SUSPENSE-NEG",
    kind: "negative",
    cls: "the same route with the dynamic subtree wrapped in a boundary",
    module: "M9",
    location: "m9-corpus/suspense/negative",
    match: ["Missing Suspense boundary"],
    note: "missing-suspense/negative: the identical page once its subtree sits inside <Suspense fallback={null}> — nothing fires.",
  },
  {
    id: "M9C-UNBOUNDED-POS",
    kind: "positive",
    cls: "route handler loop with no break/return/throw",
    module: "M9",
    location: "m9-corpus/unbounded/positive",
    match: ["Unbounded/self-calling route or edge fn"],
    expectedTier: "review",
    note: "unbounded-route/positive: `while (true)` with no escape in app/api/sync/route.ts — the request never completes. Detected by detectUnboundedRouteOrEdge.",
  },
  {
    id: "M9C-UNBOUNDED-NEG",
    kind: "negative",
    cls: "the same loop shape bounded by an explicit break",
    module: "M9",
    location: "m9-corpus/unbounded/negative",
    match: ["Unbounded/self-calling route or edge fn"],
    note: "unbounded-route/negative: `while (true)` with `if (n > 10) break` — the FP boundary for this check, nothing fires.",
  },

  // #1051 — the second cache failure mode briefs/audit-modules.md requires (a present-but-shared
  // cache directive over per-user data), which the missing-config check above actively suppressed.
  {
    id: "M9C-CACHE-BLEED-POS",
    kind: "positive",
    cls: "per-user data served from a shared cache entry (cross-user cache bleed)",
    module: "M9",
    location: "m9-corpus/cache-bleed/positive",
    match: ["Cross-user cache bleed"],
    expectedTier: "review",
    note: "cache-bleed/positive: three shapes — unstable_cache over a per-user read with a global key, a `use cache` scope that resolves the session inside itself, and an authenticated route handler returning `Cache-Control: public, s-maxage`. Detected by detectCrossUserCacheBleed.",
  },
  {
    id: "M9C-CACHE-BLEED-NEG",
    kind: "negative",
    cls: "per-user caching done correctly (identity in the key) plus a genuinely public cached read",
    module: "M9",
    location: "m9-corpus/cache-bleed/negative",
    match: ["Cross-user cache bleed"],
    note: "cache-bleed/negative: the identity in both the key parts and the tag, a `use cache` function taking the identity as an argument, a `private, no-store` authenticated response, and an anonymous public endpoint — the precision boundary for this check.",
  },

  // #1263 — the auth/validation gates were matched by a closed NAME list, so a real gate called
  // `ensureMember(...)`/`sanitize(...)` read as missing. The fix resolves callees and re-tests the
  // pattern against the helper's own body, so each of these two pairs is scored the opposite way
  // round from the #848 pair above it: the NEGATIVE is the house-style gate that must now clear,
  // and the POSITIVE is a house-style helper that performs no check and must still fire — the
  // control that stops "calls something" from becoming "is gated".
  {
    id: "M9C-AUTH-HELPER-POS",
    kind: "positive",
    cls: "Server Action whose only helper call performs no authorization check",
    module: "M9",
    location: "m9-corpus/action-auth-helper/positive",
    match: ["Server Action missing authorization"],
    expectedTier: "review",
    note: "server-action-helper-gate/positive: the action calls `normaliseOrgId(...)`, a helper that only reshapes a string. Callee resolution must not treat any helper call as a gate — still flagged.",
  },
  {
    id: "M9C-AUTH-HELPER-NEG",
    kind: "negative",
    cls: "Server Action gated by a house-style helper (`ensureMember`) whose body reads the session",
    module: "M9",
    location: "m9-corpus/action-auth-helper/negative",
    match: ["Server Action missing authorization"],
    note: "server-action-helper-gate/negative: `await ensureMember(orgId)` resolves to a helper that calls `supabase.auth.getUser()` and checks membership. The #1263 false positive — nothing must fire.",
  },
  {
    id: "M9C-VAL-HELPER-POS",
    kind: "positive",
    cls: "Server Action whose only input helper performs no schema validation",
    module: "M9",
    location: "m9-corpus/action-validation-helper/positive",
    match: ["Server Action missing input validation"],
    expectedTier: "review",
    note: "server-action-helper-validator/positive: the action routes its input through `squash(...)`, which only trims whitespace. Still unvalidated, still flagged.",
  },
  {
    id: "M9C-VAL-HELPER-NEG",
    kind: "negative",
    cls: "Server Action validated by a house-style helper (`sanitize`) whose body parses a schema",
    module: "M9",
    location: "m9-corpus/action-validation-helper/negative",
    match: ["Server Action missing input validation"],
    note: "server-action-helper-validator/negative: `sanitize(raw)` resolves to a helper that runs `BioSchema.parse(raw)`. The #1263 false positive — nothing must fire.",
  },

  // #1292 — the waterfall check called two queries independent when no VALUE flowed between them,
  // ignoring an intervening guard that exits on the first result. Promise.all hoists the second
  // query above that guard, so the recommended fix changed behaviour. Same inversion as above: the
  // negative is the guarded pair that must now clear, the positive the intervening-read-that-does-
  // not-escape that must still fire.
  {
    id: "M9C-WATERFALL-GUARD-POS",
    kind: "positive",
    cls: "sequential queries with an intervening statement that reads the first result but cannot exit",
    module: "M9",
    location: "m9-corpus/waterfall-guard/positive",
    match: ["Data-fetching waterfall"],
    expectedTier: "review",
    note: "waterfall-guard/positive: a `console.log(teams…)` sits between the two awaits. Control flow reaches the second query either way, so the pair is still a genuine waterfall — suppressing on any intervening mention would lose it.",
  },
  {
    id: "M9C-WATERFALL-GUARD-NEG",
    kind: "negative",
    cls: "sequential queries with an early return on the first result between them",
    module: "M9",
    location: "m9-corpus/waterfall-guard/negative",
    match: ["Data-fetching waterfall"],
    note: "waterfall-guard/negative: `if (!team) return …` between the two awaits. No value flows, but parallelising runs the second query on a request the sequential code never reaches — the #1292 false positive.",
  },

  // #1262 — the brief's third unbounded-route shape, which #857 left undetected AND undisclosed.
  {
    id: "M9C-RETRY-POS",
    kind: "positive",
    cls: "route handler with a request-sized retry count and a request-sized outbound fan-out",
    module: "M9",
    location: "m9-corpus/uncapped-retry/positive",
    match: ["Uncapped retry/fan-out"],
    expectedTier: "review",
    note: "uncapped-retry/positive: `for (let i = 0; i < attempts; i++)` around a caught `fetch`, plus `Promise.all(ids.map(… fetch …))` over an array from the request body. Detected by detectUncappedRetryFanOut.",
  },
  {
    id: "M9C-RETRY-NEG",
    kind: "negative",
    cls: "the same two shapes with a constant attempt cap and a sliced fan-out",
    module: "M9",
    location: "m9-corpus/uncapped-retry/negative",
    match: ["Uncapped retry/fan-out"],
    note: "uncapped-retry/negative: `i < MAX_ATTEMPTS` (a numeric const this pass resolves) and `ids.slice(0, MAX_FANOUT).map(…)` — the precision boundary, nothing fires.",
  },

  // #1293 — four FP shapes MEASURED on carbon's pinned tree, not imagined: 82 of that target's 108
  // SSR-only rows and ALL THREE of its server→client-leak Highs. Scored the #1263 way round — the
  // NEGATIVE carries the shape that used to false-fire, the POSITIVE the near-identical shape that
  // must still fire — so a fix that over-suppresses fails here rather than going quiet.
  {
    id: "M9C-SSR-CLIENTROUTE-POS",
    kind: "positive",
    cls: "browser global read in a route module's default-export component",
    module: "M9",
    location: "m9-corpus/ssr-client-route/positive",
    match: ["SSR-only API misuse"],
    expectedTier: "review",
    note: "ssr-client-route/positive: the same `window.clientCache` read, in the route's DEFAULT-EXPORT component instead of `clientAction` — genuinely on the SSR path, so file-level suppression would lose it.",
  },
  {
    id: "M9C-SSR-CLIENTROUTE-NEG",
    kind: "negative",
    cls: "browser global read inside a client-only route export (clientLoader/clientAction)",
    module: "M9",
    location: "m9-corpus/ssr-client-route/negative",
    match: ["SSR-only API misuse"],
    note: "ssr-client-route/negative: `window.clientCache` inside `clientAction`, a route export React Router 7 / Remix run only in the browser — 59 of carbon's 108 rows in this class.",
  },
  {
    id: "M9C-SSR-SHADOW-POS",
    kind: "positive",
    cls: "browser global read with no local binding of that name in the file",
    module: "M9",
    location: "m9-corpus/ssr-shadowed-global/positive",
    match: ["SSR-only API misuse"],
    expectedTier: "review",
    note: "ssr-shadowed-global/positive: `document.title` in a render body with nothing named `document` bound in the file — the real DOM global.",
  },
  {
    id: "M9C-SSR-SHADOW-NEG",
    kind: "negative",
    cls: "browser-global name bound by a destructured parameter, so the access is not the DOM",
    module: "M9",
    location: "m9-corpus/ssr-shadowed-global/negative",
    match: ["SSR-only API misuse"],
    note: "ssr-shadowed-global/negative: `({ bucket, document })` binds `document` to an app record. The shadowing rule existed but read only the identifier-shaped binding — 14 of carbon's 108 rows.",
  },
  {
    id: "M9C-SSR-EARLYRET-POS",
    kind: "positive",
    cls: "browser global read in a render body with no guard above it",
    module: "M9",
    location: "m9-corpus/ssr-early-return/positive",
    match: ["SSR-only API misuse"],
    expectedTier: "review",
    note: "ssr-early-return/positive: `window.location.origin` with no preceding guard — reached during SSR, must still fire.",
  },
  {
    id: "M9C-SSR-EARLYRET-NEG",
    kind: "negative",
    cls: "browser global read after an early-return typeof guard in the same block",
    module: "M9",
    location: "m9-corpus/ssr-early-return/negative",
    match: ["SSR-only API misuse"],
    note: "ssr-early-return/negative: `if (typeof window === \"undefined\") return null;` as a preceding SIBLING, which the ancestor-only guard walk could not see.",
  },
  {
    id: "M9C-LEAK-NARROWED-POS",
    kind: "positive",
    cls: "select('*') row handed whole to a Client Component",
    module: "M9",
    location: "m9-corpus/leak-narrowed-select/positive",
    match: ["Server→client data leak"],
    expectedTier: "review",
    note: "leak-narrowed-select/positive: `select(\"*\")` really does ship every column — the boundary the narrowed negative is measured against.",
  },
  {
    id: "M9C-LEAK-NARROWED-NEG",
    kind: "negative",
    cls: "row from a column-narrowed select handed to a Client Component",
    module: "M9",
    location: "m9-corpus/leak-narrowed-select/negative",
    match: ["Server→client data leak"],
    note: "leak-narrowed-select/negative: `select(\"id, name\")` already projected, so the finding's own 'every field on the row ships to the browser' is false — all three of carbon's leak Highs.",
  },

  // #1276 — the one FP family that came from RUNNING the TanStack adapter against a real target
  // rather than from a fixture we authored. See the tanstack-com entry in external-corpus.ts.
  {
    id: "M9C-TANSTACK-CLIENTONLY-POS",
    kind: "positive",
    cls: "browser global read in a render body of a TanStack Start module, unwrapped",
    module: "M9",
    location: "m9-corpus/tanstack-client-only/positive",
    match: ["SSR-only API misuse"],
    expectedTier: "review",
    note: "tanstack-client-only/positive: the same localStorage/document reads with no client-only wrapper — on the SSR path, so suppressing on the wrapper's mere presence in the file would fail here.",
  },
  {
    id: "M9C-TANSTACK-CLIENTONLY-NEG",
    kind: "negative",
    cls: "browser global read inside createClientOnlyFn / createIsomorphicFn().client",
    module: "M9",
    location: "m9-corpus/tanstack-client-only/negative",
    match: ["SSR-only API misuse"],
    note: "tanstack-client-only/negative: TanStack Start's own markers for 'never runs on the server' — 6 of tanstack.com's 18 residual rows in this class (MEASURED 2026-07-28: 18 -> 12).",
  },
];
