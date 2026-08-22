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
    id: "M9C-SERVERONLY-BASEURL-POS",
    kind: "positive",
    cls: "client-reachable secret module imported only through a tsconfig baseUrl bare specifier",
    module: "M9",
    location: "m9-corpus/serveronly-baseurl/positive",
    match: ["Missing server-only guard"],
    expectedTier: "review",
    note: "missing-server-only-baseurl/positive: a 'use client' page reaches lib/secrets.ts only through the bare `lib/secrets` specifier and a root `baseUrl: \".\"`. This is the scored production-seam guard for #1812: removing baseUrl resolution disconnects the secret module and misses the finding.",
  },
  {
    id: "M9C-SERVERONLY-BASEURL-NEG",
    kind: "negative",
    cls: "declared third-party bare package with no loaded baseUrl-local candidate remains external",
    module: "M9",
    location: "m9-corpus/serveronly-baseurl/negative",
    match: ["Missing server-only guard"],
    note: "missing-server-only-baseurl/negative: the client imports the declared `lib-secrets` package while an unused secret module sits at the near-miss path lib/secrets.ts. With no loaded `lib-secrets` candidate, the package stays outside the source graph and the local secret must not become client-reachable.",
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
  //
  // #1484: this used to be ONE bundled `cache-bleed` pair carrying all THREE shapes in its
  // positive (its own note said so: "three shapes"), sharing one `match` key — so the corpus row
  // stayed green with two of the three shapes reverted, mitigated only by a `toHaveLength(3)`
  // assertion in the DETECTOR suite (app-router.test.ts), not the corpus row that names each
  // shape. Split into three independent pairs, each with its own dedicated negative.
  {
    id: "M9C-CACHE-BLEED-UNSTABLE-POS",
    kind: "positive",
    cls: "unstable_cache over a per-user read with a global (non-per-user) key",
    module: "M9",
    location: "m9-corpus/cache-bleed-unstable-cache/positive",
    match: ["Cross-user cache bleed"],
    expectedTier: "review",
    note: "cache-bleed-unstable-cache/positive: `unstable_cache(async (userId) => …, [\"orders\"], …)` — the key carries no per-user component, so the first caller's orders are served to everyone. Detected by detectCrossUserCacheBleed.",
  },
  {
    id: "M9C-CACHE-BLEED-UNSTABLE-NEG",
    kind: "negative",
    cls: "unstable_cache over a genuinely anonymous read (no session, nothing per-user)",
    module: "M9",
    location: "m9-corpus/cache-bleed-unstable-cache/negative",
    match: ["Cross-user cache bleed"],
    note: "cache-bleed-unstable-cache/negative: a public plans list with no session read anywhere — a shared cache key and a public Cache-Control are both correct here. Nothing must fire.",
  },
  {
    id: "M9C-CACHE-BLEED-USECACHE-POS",
    kind: "positive",
    cls: "`\"use cache\"` scope that resolves the caller's session INSIDE itself",
    module: "M9",
    location: "m9-corpus/cache-bleed-use-cache/positive",
    match: ["Cross-user cache bleed"],
    expectedTier: "review",
    note: "cache-bleed-use-cache/positive: a `\"use cache\"` function is keyed on its ARGUMENTS — reading the session inside it is invisible to that key, so one cache entry is shared across every user. Detected by detectCrossUserCacheBleed.",
  },
  {
    id: "M9C-CACHE-BLEED-USECACHE-NEG",
    kind: "negative",
    cls: "`\"use cache\"` scope whose identity arrives as an ARGUMENT (the correct shape)",
    module: "M9",
    location: "m9-corpus/cache-bleed-use-cache/negative",
    match: ["Cross-user cache bleed"],
    note: "cache-bleed-use-cache/negative: the identical `\"use cache\"` shape, but the caller passes the user id in and no session read happens inside the cached function. Nothing must fire.",
  },
  {
    id: "M9C-CACHE-BLEED-CACHECONTROL-POS",
    kind: "positive",
    cls: "authenticated route handler returning a shared `Cache-Control: public, s-maxage`",
    module: "M9",
    location: "m9-corpus/cache-bleed-cache-control/positive",
    match: ["Cross-user cache bleed"],
    expectedTier: "review",
    note: "cache-bleed-cache-control/positive: an authenticated response handed to the shared CDN cache — the next requester of this URL gets the previous user's invoices. Detected by detectCrossUserCacheBleed.",
  },
  {
    id: "M9C-CACHE-BLEED-CACHECONTROL-NEG",
    kind: "negative",
    cls: "the identical authenticated response marked `private, no-store`",
    module: "M9",
    location: "m9-corpus/cache-bleed-cache-control/negative",
    match: ["Cross-user cache bleed"],
    note: "cache-bleed-cache-control/negative: the same authenticated response, correctly marked uncacheable by any shared cache. Nothing must fire.",
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

  // #1438 — #1292's escape rule counted ANY `break`/`continue` node, so one belonging to an
  // intervening `switch` or inner loop — which leaves neither the function nor the path to the
  // second query — suppressed a genuinely parallelisable pair. Scored the same way round as the
  // #1292 pair above: the POSITIVE is the shape that must fire again, the NEGATIVE the escape that
  // must still suppress, so a fix that switches the rule off rather than narrowing it goes red.
  //
  // #1484: this pair used to be ONE bundled `waterfall-escape` fixture carrying both the switch and
  // loop shapes in one positive, so its `match` key (satisfied by any one finding) would stay green
  // with half the fix reverted — mitigated only by an assertion in the DETECTOR suite
  // (app-router.test.ts), not by the corpus row that names the shape. Split into two independent
  // pairs, each proven by reverting ONE shape and watching its OWN row (not the detector suite) go
  // red — see the calibration.test.ts "catches each check" reversion in the PR that landed this.
  {
    id: "M9C-WATERFALL-ESCAPE-SWITCH-POS",
    kind: "positive",
    cls: "sequential queries with an intervening switch `break` that belongs to the switch, not the function",
    module: "M9",
    location: "m9-corpus/waterfall-escape-switch/positive",
    match: ["Data-fetching waterfall"],
    expectedTier: "review",
    note: "waterfall-escape-switch/positive: a `switch` whose case `break` belongs to the switch. The intervening statement reads the first result; it does not skip the second query, so the pair is a real waterfall.",
  },
  {
    id: "M9C-WATERFALL-ESCAPE-SWITCH-NEG",
    kind: "negative",
    cls: "sequential queries with a `return` inside an intervening switch case",
    module: "M9",
    location: "m9-corpus/waterfall-escape-switch/negative",
    match: ["Data-fetching waterfall"],
    note: "waterfall-escape-switch/negative: `case \"archived\": return null` inside the same switch shape. #1438 narrowed the rule for break/continue, it did not switch escapes off — a `return` still leaves the function, so this pair stays a dependency.",
  },
  {
    id: "M9C-WATERFALL-ESCAPE-LOOP-POS",
    kind: "positive",
    cls: "sequential queries with an intervening inner-loop `break` that belongs to the loop, not the function",
    module: "M9",
    location: "m9-corpus/waterfall-escape-loop/positive",
    match: ["Data-fetching waterfall"],
    expectedTier: "review",
    note: "waterfall-escape-loop/positive: a `for` whose `break` belongs to that loop. The intervening statement reads the first result; it does not skip the second query, so the pair is a real waterfall.",
  },
  {
    id: "M9C-WATERFALL-ESCAPE-LOOP-NEG",
    kind: "negative",
    cls: "sequential queries with a `return` inside an intervening for loop",
    module: "M9",
    location: "m9-corpus/waterfall-escape-loop/negative",
    match: ["Data-fetching waterfall"],
    note: "waterfall-escape-loop/negative: a `return` inside the `for` loop. #1438 narrowed the rule for break/continue, it did not switch escapes off — a `return` still leaves the function, so this pair stays a dependency.",
  },

  // #1441 — the #1292 suppression is one rule covering two different control-flow facts. A guard
  // that DIVERTS (return/break) skips the second query; a guard that only ABORTS (throw, including
  // `throw redirect(…)`) ends the request, and nothing downstream sees the second query's result.
  // The abort case is a recall loss when both statements are reads — and a real bug when either
  // writes, which is why the negative here is a WRITE under an aborting guard.
  {
    id: "M9C-WATERFALL-ABORT-POS",
    kind: "positive",
    cls: "sequential READS separated by an error-only guard that ends the request",
    module: "M9",
    location: "m9-corpus/waterfall-abort/positive",
    match: ["Data-fetching waterfall"],
    expectedTier: "review",
    note: "waterfall-abort/positive: `if (!price) throw` between an independent prices read and a subscriptions read — the pinned mvp-boilerplate shape whose suppression took that target's only counted M9 finding away. Hoisting the second read above the throw costs one wasted round-trip on the failure path and changes no behaviour.",
  },
  {
    id: "M9C-WATERFALL-ABORT-NEG",
    kind: "negative",
    cls: "an error-only guard where the second statement WRITES (`.from(x).update(…).select(…)`)",
    module: "M9",
    location: "m9-corpus/waterfall-abort/negative",
    match: ["Data-fetching waterfall"],
    note: "waterfall-abort/negative: a `throw` guard rejecting voided receipts, followed by an `.update({status:'Pending'}).select('id')` that satisfies isDbQueryChain but is a WRITE. Parallelising would post a voided receipt — the reason the abort relaxation is gated on both statements being reads. From the pinned carbon clone.",
  },

  // #1439 — #1263's callee resolution accepted any resolved helper whose BODY matched the auth
  // pattern. Matching the pattern says the helper looks at the session; it does not say the helper
  // can stop the mutation. Same inversion again: the positives are helpers that enforce nothing and
  // must still fire, the negative the real gate reached through the import idiom #1263 missed.
  //
  // #1484: this pair used to be ONE bundled `action-gate-strength` fixture carrying both the
  // logger and discarded-boolean shapes in one positive, so its `match` key would stay green with
  // half the fix reverted — mitigated only by an assertion in the DETECTOR suite, not the corpus
  // row that names the shape. Split into two independent pairs, each with its own negative.
  {
    id: "M9C-GATE-STRENGTH-LOGGER-POS",
    kind: "positive",
    cls: "Server Action vouched for by a logger that reads the session but cannot deny",
    module: "M9",
    location: "m9-corpus/action-gate-strength-logger/positive",
    match: ["Server Action missing authorization"],
    expectedTier: "review",
    note: "action-gate-strength-logger/positive: `auditLog(...)` calls getCurrentUser() for a log line and cannot deny. Not a gate — the action must still be flagged.",
  },
  {
    id: "M9C-GATE-STRENGTH-LOGGER-NEG",
    kind: "negative",
    cls: "Server Action gated through a NAMESPACE import (`import * as guards; await guards.ensureMember(id)`)",
    module: "M9",
    location: "m9-corpus/action-gate-strength-logger/negative",
    match: ["Server Action missing authorization"],
    note: "action-gate-strength-logger/negative: the same real `ensureMember` gate as server-action-helper-gate, imported as a namespace — the idiom #1263's collectValueImports did not model, so its own false positive survived for it. Nothing must fire.",
  },
  {
    id: "M9C-GATE-STRENGTH-DISCARDED-POS",
    kind: "positive",
    cls: "Server Action vouched for by a boolean gate whose result is discarded",
    module: "M9",
    location: "m9-corpus/action-gate-strength-discarded/positive",
    match: ["Server Action missing authorization"],
    expectedTier: "review",
    note: "action-gate-strength-discarded/positive: `const allowed = await canAccess(id)` is never read. Not a gate — the action must still be flagged.",
  },
  {
    id: "M9C-GATE-STRENGTH-DISCARDED-NEG",
    kind: "negative",
    cls: "Server Action gated through a NAMESPACE import, same real gate as the logger family's negative",
    module: "M9",
    location: "m9-corpus/action-gate-strength-discarded/negative",
    match: ["Server Action missing authorization"],
    note: "action-gate-strength-discarded/negative: the same real `ensureMember` gate, imported as a namespace. Nothing must fire.",
  },

  // #1262 — the brief's third unbounded-route shape, which #857 left undetected AND undisclosed.
  //
  // #1484: this used to be ONE bundled `uncapped-retry` pair carrying BOTH the retry-loop and
  // fan-out shapes in its positive, sharing one taxonomy ("M9 — Uncapped retry/fan-out") and one
  // `match` key — with NO per-shape lock anywhere, not even in the detector suite. MEASURED
  // 2026-07-31: gutting `asFanOut` entirely (`return undefined` unconditionally) left this entry
  // GREEN, because the retry-loop finding alone satisfied the key. Split into two independent
  // pairs so a regression in either shape fails the row that names it.
  {
    id: "M9C-RETRY-LOOP-POS",
    kind: "positive",
    cls: "route handler with a request-sized retry count",
    module: "M9",
    location: "m9-corpus/uncapped-retry-loop/positive",
    match: ["Uncapped retry/fan-out"],
    expectedTier: "review",
    note: "uncapped-retry-loop/positive: `for (let i = 0; i < attempts; i++)` around a caught `fetch`, where `attempts` comes from the request body. Detected by detectUncappedRetryFanOut.",
  },
  {
    id: "M9C-RETRY-LOOP-NEG",
    kind: "negative",
    cls: "the same retry loop with a constant attempt cap",
    module: "M9",
    location: "m9-corpus/uncapped-retry-loop/negative",
    match: ["Uncapped retry/fan-out"],
    note: "uncapped-retry-loop/negative: `i < MAX_ATTEMPTS` — a numeric const this pass resolves. Nothing fires.",
  },
  {
    id: "M9C-FANOUT-POS",
    kind: "positive",
    cls: "route handler with a request-sized outbound fan-out",
    module: "M9",
    location: "m9-corpus/uncapped-fanout/positive",
    match: ["Uncapped retry/fan-out"],
    expectedTier: "review",
    note: "uncapped-fanout/positive: `Promise.all(ids.map(… fetch …))` over an array from the request body, with no `.slice(…)` bound. Detected by detectUncappedRetryFanOut.",
  },
  {
    id: "M9C-FANOUT-NEG",
    kind: "negative",
    cls: "the same fan-out sliced to a fixed window before the map",
    module: "M9",
    location: "m9-corpus/uncapped-fanout/negative",
    match: ["Uncapped retry/fan-out"],
    note: "uncapped-fanout/negative: `ids.slice(0, MAX_FANOUT).map(…)` — the precision boundary, nothing fires.",
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
    note: "tanstack-client-only/positive: the same localStorage/document reads with no client-only wrapper — on the SSR path, so suppressing on the wrapper's mere presence in the file would fail here. #1718: this row matches TWO findings (the `localStorage` read at theme.tsx:5 and the `document` read at :6) under one `match` key, which #1484's criterion 3 flags as a masking shape. RULED, 2026-08-01, as an ACCEPTED EXCEPTION to that rule with a named substitute guard rather than a fixture split: unlike #1484's five, these are not two independently-regressable code paths — both findings come from the SAME mechanism (isOnSsrRenderPath plus the #1276 client-only-wrapper check) applied to two adjacent reads in one unwrapped function, so no change can regress one without the other. The narrower risk #1718 identifies is real and IS guarded: BROWSER_GLOBALS is a shared Set of five names, and narrowing it for ONE name (dropping `document`, keeping `localStorage`) would leave this row green on the survivor. `both browser globals in the TanStack fixture are named individually (#1718)` in calibration.test.ts asserts a finding for EACH global by name, so that narrowing reds the corpus venue. MEASURED both directions 2026-08-01: green as shipped; removing `\"document\"` from BROWSER_GLOBALS fails that test alone, while M9C-TANSTACK-CLIENTONLY-POS itself still passes — which is exactly the masking this exception is allowed only because the substitute closes.",
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

  // #1440 — #1262 shipped the retry check accepting only a LITERAL-true while-condition, so the
  // canonical `while (!done) { try { await fetch(url) } catch {} }` was never assessed, and was not
  // among the sub-shapes its own scope row names as unassessed. A while/do header now resolves
  // exactly as a `for` header does.
  {
    id: "M9C-RETRY-WHILE-POS",
    kind: "positive",
    cls: "route handler retrying inside `while (<non-literal>)` with a swallowing catch",
    module: "M9",
    location: "m9-corpus/uncapped-retry-while/positive",
    match: ["Uncapped retry/fan-out"],
    expectedTier: "review",
    note: "uncapped-retry-while/positive: `while (!done)` around a caught `fetch` whose catch never sets `done`. The header carries no resolvable bound, so the loop is reported as uncapped.",
  },
  {
    id: "M9C-RETRY-WHILE-NEG",
    kind: "negative",
    cls: "the same while-loop retry with an attempt counter compared against a numeric constant",
    module: "M9",
    location: "m9-corpus/uncapped-retry-while/negative",
    match: ["Uncapped retry/fan-out"],
    note: "uncapped-retry-while/negative: `while (attempts < MAX_ATTEMPTS)` — a numeric const this pass resolves, so the header carries a bound. The precision boundary for the widened while rule, nothing fires.",
  },

  // #1462/#1460/#1461 — the three residual FP families #1293's and #1276's triage left open, each
  // scored the #1263 way round: the NEGATIVE carries the shape that used to false-fire, the POSITIVE
  // the near-identical shape that must still fire, so a fix that over-suppresses fails here.
  // #1484 criterion 3, second pass: the bundled `action-dynamic-gate` positive carried FOUR
  // relevant findings under one `match` key and passed on any one of them — MEASURED, scoring it
  // with `renameB`+`renameC` deleted still read `pass=true`, and so did scoring it with only
  // `renameA` left. Its own note and its detector-test comment both already said "passes on any one
  // of them", so this was a documented hole, not a discovered one. The four shapes regress at four
  // DISTINCT code points, which is what makes this a split rather than an accepted exception:
  //   named     — collectDynamicImports' `named` map / GateResolver's identifier arm
  //   namespace — collectDynamicImports' `namespaces` map / GateResolver's `site.qualifier` arm
  //   computed  — the `specifier === undefined` branch (fail-safe half)
  //   package   — the `if (resolved)` guard (fail-safe half)
  // The two fail-safe rows are the ones worth the fixtures: their regression is "unresolvable read
  // as gated", a SILENT FALSE NEGATIVE on real code, and under the bundled entry it left the row
  // green on its two resolvable siblings.
  {
    id: "M9C-DYNGATE-NAMED-POS",
    kind: "positive",
    cls: "server mutation whose destructured dynamically-imported callee resolves, to a helper that checks nothing",
    module: "M9",
    location: "m9-corpus/action-dynamic-gate-named/positive",
    match: ["missing authorization"],
    expectedTier: "review",
    note: "server-action-dynamic-gate-named/positive: `const { normaliseOrgId } = await import('../lib/format')` — it resolves, and what it resolves to only reshapes a string. Resolving a dynamic import must not turn 'awaits SOMETHING it imported dynamically' into 'is gated'.",
  },
  {
    id: "M9C-DYNGATE-NAMED-NEG",
    kind: "negative",
    cls: "server mutation behind a gate reached through a destructured dynamic `await import()`",
    module: "M9",
    location: "m9-corpus/action-dynamic-gate-named/negative",
    match: ["missing authorization"],
    note: "server-action-dynamic-gate-named/negative: `requireAdmin()` binds its real check with `const { getAuthenticatedUser } = await import('./auth-helpers')`. All 12 of TanStack/tanstack.com's High rows in this class were read against source and 6 are exactly this shape (MEASURED 2026-07-28) — the other 6 are a longer gate chain, scored by the action-gate-depth pair.",
  },
  {
    id: "M9C-DYNGATE-NS-POS",
    kind: "positive",
    cls: "server mutation whose namespace-bound dynamically-imported callee resolves, to a helper that checks nothing",
    module: "M9",
    location: "m9-corpus/action-dynamic-gate-namespace/positive",
    match: ["missing authorization"],
    expectedTier: "review",
    note: "server-action-dynamic-gate-namespace/positive: `const format = await import('../lib/format')` then `format.normaliseOrgId(…)`. Separate from the destructured row next door because it regresses at a separate code point — `namespaces` rather than `named` in collectDynamicImports, and GateResolver's `site.qualifier` arm rather than its identifier arm.",
  },
  {
    id: "M9C-DYNGATE-NS-NEG",
    kind: "negative",
    cls: "server mutation behind a gate reached through a namespace-bound dynamic `await import()`",
    module: "M9",
    location: "m9-corpus/action-dynamic-gate-namespace/negative",
    match: ["missing authorization"],
    note: "server-action-dynamic-gate-namespace/negative: `const roles = await import('../lib/roles')` then `roles.requireAdmin()`, the same real gate the destructured negative uses, reached through the namespace arm. The one variable against its own positive is whether what resolves actually checks anything.",
  },
  {
    id: "M9C-DYNGATE-COMPUTED-POS",
    kind: "positive",
    cls: "server mutation whose gate is bound through a dynamic import with a COMPUTED specifier, so the module goes unidentified",
    module: "M9",
    location: "m9-corpus/action-dynamic-gate-computed/positive",
    match: ["missing authorization"],
    expectedTier: "review",
    note: "server-action-dynamic-gate-computed/positive: the FAIL-SAFE half. `const specifier = process.env.GATE_MODULE ?? '../lib/roles'; const { requireAdmin } = await import(specifier)`. STRONGER than the bundled version this replaces, deliberately: the fallback names a module that DOES export a real gate and is present in this fixture's own tree, so the ONLY reason the row still fires is that the specifier is unevaluable. A fail-open at the `specifier === undefined` branch of collectDynamicImports reds this row alone. Nor may a future pass const-fold the `??` — `process.env.GATE_MODULE` decides the real module at runtime, so folding to the fallback would vouch for a module that may never load.",
  },
  {
    id: "M9C-DYNGATE-COMPUTED-NEG",
    kind: "negative",
    cls: "the same action with the specifier written as a plain string literal, so the module resolves",
    module: "M9",
    location: "m9-corpus/action-dynamic-gate-computed/negative",
    match: ["missing authorization"],
    note: "server-action-dynamic-gate-computed/negative: byte-for-byte its positive with ONE variable flipped — `await import('../lib/roles')` instead of `await import(specifier)`. Same module, same gate, same call, same mutation. The precision boundary the computed positive sits just outside of.",
  },
  {
    id: "M9C-DYNGATE-PACKAGE-POS",
    kind: "positive",
    cls: "server mutation whose gate is bound through a dynamic import of a package outside the loaded source set",
    module: "M9",
    location: "m9-corpus/action-dynamic-gate-package/positive",
    match: ["missing authorization"],
    expectedTier: "review",
    note: "server-action-dynamic-gate-package/positive: the other FAIL-SAFE half, and a DIFFERENT code point from the computed row — the specifier IS a string literal, so it evaluates; it is `resolveImport` that returns nothing. Strengthened the same way: `../lib/roles` exports a real gate named `requireAdmin` and sits in this fixture's own tree, so the pass must not reach for a same-named export it was not pointed at. A fail-open at the `if (resolved)` guard reds this row alone.",
  },
  {
    id: "M9C-DYNGATE-PACKAGE-NEG",
    kind: "negative",
    cls: "the same action with the specifier naming the in-tree relative module instead of a package",
    module: "M9",
    location: "m9-corpus/action-dynamic-gate-package/negative",
    match: ["missing authorization"],
    note: "server-action-dynamic-gate-package/negative: byte-for-byte its positive with ONE variable flipped — `'../lib/roles'` instead of `'@vendor/org-utils'`. Same binding, same gate, same mutation. The precision boundary the package positive sits just outside of.",
  },
  // #1500 — #1462's own residual: the OTHER 6 of TanStack/tanstack.com's 12 missing-auth rows,
  // whose real check sits 4 resolvable hops out (not 2) and one hop is bound only through a
  // helper-wrapped dynamic import PLUS a re-export barrel, neither of which #1462's resolver
  // followed. Scored the same #1263 way round as the pair above.
  {
    id: "M9C-GATEDEPTH-POS",
    kind: "positive",
    cls: "server mutation behind a 4-hop chain (wrapper + barrel, both resolvable) in which no hop checks or denies anything",
    module: "M9",
    location: "m9-corpus/action-gate-depth/positive",
    match: ["missing authorization"],
    expectedTier: "review",
    note: "action-gate-depth/positive: the adversarial control — every hop resolves (same wrapper/barrel shapes as the negative) but the chain bottoms out in a `console.log`, so raising GATE_DEPTH and following the wrapper/barrel must not manufacture a suppression where nothing actually gates.",
  },
  {
    id: "M9C-GATEDEPTH-NEG",
    kind: "negative",
    cls: "server mutation gated 4 hops out through a helper-wrapped dynamic import and a re-export barrel",
    module: "M9",
    location: "m9-corpus/action-gate-depth/negative",
    match: ["missing authorization"],
    note: "action-gate-depth/negative: mirrors TanStack/tanstack.com's real chain — action -> requireModerate -> requireCapability -> (wrapper) getAuthGuards -> (barrel re-export) -> createGuards, where the real check lives. requireCapability also calls a method of the same name on the object `getAuthGuards()` returns — a same-named self-call that, unresolved, burns a depth level chasing itself. MEASURED 2026-07-31 by `pnpm exec tsx src/cli/static-detect.ts <clone-of-6b61f4d>`: 6 of tanstack-com's 6 residual `M1 — server function missing authorization check` rows cleared, 0 rows moved anywhere else in the 687-finding baseline (before/after diff exact).",
  },
  {
    id: "M9C-SSRHELPER-POS",
    kind: "positive",
    cls: "browser global in a module-level helper the component's render body calls",
    module: "M9",
    location: "m9-corpus/ssr-module-helper/positive",
    match: ["SSR-only API misuse"],
    expectedTier: "review",
    note: "ssr-module-helper/positive: the same lowercase, JSX-free, module-level helper as the negative — but called from the render body, so it does run during SSR. The naive form of #1460's fix (suppress on the helper's own shape) loses this row; only the CALL SITES separate the pair.",
  },
  {
    id: "M9C-SSRHELPER-NEG",
    kind: "negative",
    cls: "browser global in a module-level helper called only from a useEffect",
    module: "M9",
    location: "m9-corpus/ssr-module-helper/negative",
    match: ["SSR-only API misuse"],
    note: "ssr-module-helper/negative: `triggerDownload` in a `.tsx` file, called once, from inside a useEffect. #964 already suppresses the identical helper in a `.ts` module. MEASURED 2026-07-28: 6 of carbon's 26 residual rows and 8 of tanstack.com's 12.",
  },
  // #1502 — #1460's own residual: an EXPORTED helper with NO in-file call site. #1460's rule alone
  // leaves it flagged (its callers sit outside what that in-file-only rule reads); the caller is
  // resolved cross-file through the import graph here. Scored the #1263 way round.
  {
    id: "M9C-SSRXFILE-POS",
    kind: "positive",
    cls: "exported module-level helper, no in-file caller, called from ANOTHER module's render body",
    module: "M9",
    location: "m9-corpus/ssr-cross-file-helper/positive",
    match: ["SSR-only API misuse"],
    expectedTier: "review",
    note: "ssr-cross-file-helper/positive: `handleCommandNavigation`, exported from lib/helper.tsx with zero in-file call sites — the real shape MEASURED on carbon's `slash-command.tsx:106` (#1502). Its only caller lives in app/component.tsx, a bare call in the component's own render body. Cross-file resolution must still find it and still flag it.",
  },
  {
    id: "M9C-SSRXFILE-NEG",
    kind: "negative",
    cls: "exported module-level helper, no in-file caller, called from ANOTHER module's useEffect only",
    module: "M9",
    location: "m9-corpus/ssr-cross-file-helper/negative",
    match: ["SSR-only API misuse"],
    note: "ssr-cross-file-helper/negative: the identical no-in-file-caller helper, but its sole cross-file caller (app/component.tsx) is deferred behind a useEffect. Proves the cross-file resolution does not just clear every unreachable-in-file helper — it re-tests the SAME render-path rule at the caller's own site.",
  },
  {
    id: "M9C-WATERFALL-HELPER-POS",
    kind: "positive",
    cls: "sequential queries whose intervening statement calls a helper that returns but cannot exit",
    module: "M9",
    location: "m9-corpus/waterfall-helper-exit/positive",
    match: ["Data-fetching waterfall"],
    expectedTier: "review",
    note: "waterfall-helper-exit/positive: `describeStatus(dispatch?.status)` reads the first result and its helper contains `return`, but a return leaves only THAT helper — control reaches the second query either way, so the pair is a genuine waterfall. This is why #1461 counts a callee's `throw` and not its `return`.",
  },
  {
    id: "M9C-WATERFALL-HELPER-NEG",
    kind: "negative",
    cls: "sequential queries over a write whose intervening guard exits inside the helper it calls",
    module: "M9",
    location: "m9-corpus/waterfall-helper-exit/negative",
    match: ["Data-fetching waterfall"],
    note: "waterfall-helper-exit/negative: `await requireUnlocked({ isLocked: … })` — the `throw redirect(…)` is one hop out, where #1292's syntactic test cannot see it. Scored INSIDE #1438/#1441's model: the second query is a write, so #1441's abort-over-write rule applies. A read/read version would legitimately still fire under #1438's relaxation and would prove nothing about whether the exit inside the helper was seen.",
  },

  // #1434 — #1263's residual. detectClientSuppliedOwnerId was the LAST raw-text AUTH_PATTERN test
  // in the pass, so a house-style gate was invisible to it and its evidence told the client the
  // action "makes no auth/session call at all" — on the higher-severity of the two findings. Same
  // inversion as the pairs above: the NEGATIVE is the gated action that must now clear, the
  // POSITIVE the near-identical action whose helper enforces nothing.
  //
  // #1484: this used to be ONE bundled `owner-id-helper-gate` pair carrying BOTH #1434 shapes in
  // its positive, so its `match` key would stay green with half the fix reverted — mitigated only
  // by a `toHaveLength(2)` assertion in the DETECTOR suite, not the corpus row that names each
  // shape (the fixture's own old note said so explicitly). Split into two independent pairs.
  {
    id: "M9C-OWNER-GATE-LOGGER-POS",
    kind: "positive",
    cls: "service-role action writing a client-supplied owner id, vouched for only by a logger",
    module: "M9",
    location: "m9-corpus/owner-id-helper-gate-logger/positive",
    match: ["Client-supplied owner id"],
    expectedTier: "review",
    note: "owner-id-helper-gate-logger/positive: `updateUserProfile`'s only helper is `auditLog`, which reads the session for a log line, cannot deny and whose result is discarded (#1439's strength test, reused here). Must still fire.",
  },
  {
    id: "M9C-OWNER-GATE-LOGGER-NEG",
    kind: "negative",
    cls: "service-role action writing a client-supplied owner id behind a house-style gate that throws",
    module: "M9",
    location: "m9-corpus/owner-id-helper-gate-logger/negative",
    match: ["Client-supplied owner id"],
    note: "owner-id-helper-gate-logger/negative: P-SVC-NOAUTH-BARE-ID's exact shape plus `await ensureMember(userId)`, which resolves to a helper that reads the session and throws. Silence here is the same answer an inline `await requireUser()` already gets — auth called, nothing bound — so resolving the callee adds no policy, it applies the existing one to a form the raw-text test could not see.",
  },
  {
    id: "M9C-OWNER-GATE-COMMENT-POS",
    kind: "positive",
    cls: "service-role action writing a client-supplied owner id, vouched for only by a comment",
    module: "M9",
    location: "m9-corpus/owner-id-helper-gate-comment/positive",
    match: ["Client-supplied owner id"],
    expectedTier: "review",
    note: "owner-id-helper-gate-comment/positive: `updateUserEmail` carries `// TODO: requireUser() before shipping`, which the raw-text test read as a real auth call and silenced — a false negative, not just false evidence. Must still fire.",
  },
  {
    id: "M9C-OWNER-GATE-COMMENT-NEG",
    kind: "negative",
    cls: "the identical shape with a REAL inline `await requireUser()` call, not a comment",
    module: "M9",
    location: "m9-corpus/owner-id-helper-gate-comment/negative",
    match: ["Client-supplied owner id"],
    note: "owner-id-helper-gate-comment/negative: `requireUser()` is a real call in the body, not a word inside a comment. Silence here is the same 'auth called, nothing bound' verdict an inline call already gets — proves the literal/comment blanking (#845's fix, applied here) is what separates this from the positive, not a coincidence of wording.",
  },
];
