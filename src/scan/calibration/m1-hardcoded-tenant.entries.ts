import type { CorpusEntry } from "./types.js";

const ROOT = "m1-hardcoded-tenant";

// M1 rows deliberately omit `module`: validate-calibration's live mechanical venue scores the
// untagged M1 corpus against runMechanicalScan output. Tagging them M1 would exclude them.
export const m1HardcodedTenantEntries: CorpusEntry[] = [
  {
    id: "M1-HC-TENANT-P-REQUEST",
    kind: "positive",
    cls: "Hardcoded tenant identifier at a request boundary",
    location: `${ROOT}/request-positive.ts`,
    match: ["hardcoded tenant identifier at client/request boundary"],
    expectedTier: "review",
    expectedSeverity: "High",
    note: "A request header embeds a tenant identifier literal. M1 must bind tenant identity to authenticated/session context at the trusted server boundary rather than leaving this caller-visible constant in place.",
  },
  {
    id: "M1-HC-TENANT-N-REQUEST-SESSION",
    kind: "negative",
    cls: "Request tenant identity derived from authenticated session context",
    location: `${ROOT}/request-negative.ts`,
    note: "The identical request header is populated from the authenticated session parameter, so no tenant literal exists to classify.",
  },
  {
    id: "M1-HC-TENANT-P-CLIENT",
    kind: "positive",
    cls: "Hardcoded tenant identifier at a client boundary",
    location: `${ROOT}/client-positive.tsx`,
    match: ["hardcoded tenant identifier at client/request boundary"],
    expectedTier: "review",
    expectedSeverity: "High",
    note: "A browser client constructor embeds one tenant identifier. The review-tier M1 row must be disjoint from M5's deployment/provider families.",
  },
  {
    id: "M1-HC-TENANT-N-CLIENT-SESSION",
    kind: "negative",
    cls: "Client constructor receives session-derived tenant identity",
    location: `${ROOT}/client-negative.tsx`,
    note: "The paired client constructor receives tenantId from session context rather than a literal; the source-only classifier makes no dynamic-flow claim.",
  },
];
