// #1295 — the negatives #984's guardrail was reported as satisfied without. #984 added `req.headers`
// / `headers()` to the shared request-taint source block with the rule "route to the review tier
// where a header is plausibly trusted. Do NOT let it introduce free-count FPs", and closed on a
// measured zero-FP result. The measurement could not have seen the hole: NO corpus entry anywhere
// read a header into a sink, so "202 negatives cleared" was a statement about parameterization
// negatives only, and the gate could not tell HANDLED from NEVER EXERCISED.
//
// The pair below is the discrimination itself, so it fails in both directions: widening the
// platform-header set to arbitrary custom names loses P-GATEWAY-HEADER-SINK's free count, and
// removing the routing entirely fails N-PLATFORM-HEADER-SINK on a free-count hit.

import type { CorpusEntry } from "./types.js";

export const b27HeaderTrustEntries: CorpusEntry[] = [
  {
    id: "N-PLATFORM-HEADER-SINK",
    kind: "negative",
    cls: "platform/proxy-set header reaching a sink — review tier, never the free count",
    location: "header-platform-realip",
    note: "#1295: lib/header-platform-realip.js reads `req.headers['x-real-ip']` into `exec()`. The rule (harvey-command-injection) still MATCHES at ERROR + HIGH — this entry is not about the rule staying silent, it is about the TIER the finding lands at. platformHeaderTrusted (src/scan/header-trust.ts) demotes it to review because the only request-derived value on the line is a header whose canonical producer is the edge, and states that routing reason on the finding. MEASURED 2026-07-30: free-count before #1295, review after.",
    // The first two are the point of the entry — the SAME rules that free-counted this shape before
    // #1295, now recorded as landing at review. The third is the registry pack's own generic
    // child_process lint, which fires on any `exec()` regardless of taint and is unrelated to header
    // trust; recorded so the ratchet's report stays exhaustive rather than partly suppressed.
    reviewTierHits: [
      "src.scan.rules.semgrep.harvey-command-injection",
      "src.scan.rules.semgrep.harvey-lib-command-injection",
      "javascript.lang.security.detect-child-process.detect-child-process",
    ],
  },
  {
    id: "P-GATEWAY-HEADER-SINK",
    kind: "positive",
    cls: "gateway-injected identity header interpolated into raw SQL",
    location: "header-gateway-tenant.js",
    match: ["sql-injection"],
    expectedTier: "high",
    note: "#1295's third option, taken as an explicit DECISION rather than left implicit: a spoofable `x-tenant-id` keeps free-count severity. `x-vercel-ip-*` and `cf-connecting-ip` are names a documented edge sets; `x-tenant-id` is an arbitrary custom header, and a static scan reads a gateway-injected one exactly like one the client invented. The deployment that matters is the one where nothing injects it. This entry is the scope control for N-PLATFORM-HEADER-SINK above — it proves the demotion is keyed on the header NAME LIST and not on 'the taint came from a header'.",
  },
];
