// M3 batch (#72, spec §M3) — hotspot analysis (vitals: churn×complexity, truck-factor, coupling).
// Everything below scores against `src/__fixtures__/vitals-report.json` (used by
// hotspot-scan.test.ts), which since #1146 is a REAL `vitals 0.2.0 report --json` capture — no
// longer a hand-written fixture. It is produced by src/__fixtures__/vitals-recapture/seed.py, which
// builds a throwaway git repo + `.vitals` provenance DB whose history makes the tool emit every
// planted relationship below (see the fixture's `_note` and the sibling PROVENANCE.md). The values
// in these entries follow the capture, not the reverse.
//
// Per the locked product decision + spec discipline: a hotspot RANK is an ordering over a
// continuous score, not a true/false finding — there is no M3 precision number, and these entries
// must never be read as one. Only the three DETERMINISTIC BOOLEAN sub-signals (truck-factor-1,
// co-change coupling edge, AI-authored+high-churn — spec-72 §M3, #369) are modeled here as
// CorpusEntry positives/negatives, because — unlike a rank — "is this file truck-factor-1",
// "are these two files coupled", and "is this file AI-provenance-logged with churn label HIGH"
// are true/false facts, scored the same way every other module's facts are
// (src/hotspot-scan.ts::toFactFindings -> buildCoverageMatrix). module: "M3" keeps them out of
// validate-calibration.ts's `module === undefined` filter, same as M7/M8/M10.
//
// M3-P-HOTSPOT (the planted churn×complexity hotspot) and M3-N-CHURN-TRIVIAL (the high-churn/
// trivial-complexity file that must NOT rank top-K) are DELIBERATELY NOT modeled as CorpusEntry
// rows — a rank/top-K membership check isn't a location match against a Finding, it's a separate
// ordering assertion. That check lives directly in hotspot-scan.test.ts's "M3 top-K ordering gate"
// block (rankHotspots/topKFiles against the same fixture), never through buildCoverageMatrix.

import type { CorpusEntry } from "./types.js";

export const m3Entries: CorpusEntry[] = [
  // --- Boolean sub-signal POSITIVES (must be caught as facts) ---
  {
    module: "M3",
    id: "M3-P-TRUCK1",
    kind: "positive",
    cls: "Truck-factor-1 (sole-author) file",
    location: "core/billing.ts",
    match: ["truck-factor-1"],
    expectedTier: "high",
    note: "core/billing.ts is committed only by one seeded author (alice) in the real-schema vitals fixture (knowledge_risk truck_factor: 1). toFactFindings emits a Knowledge risk (truck-factor-1) Finding at location core/billing.ts.",
  },
  {
    module: "M3",
    id: "M3-P-COUPLING",
    kind: "positive",
    cls: "Co-change coupling edge",
    location: "core/a.ts <> core/b.ts",
    match: ["co-change"],
    expectedTier: "high",
    note: "core/a.ts and core/b.ts are always committed together in the real-schema vitals fixture (a coupling edge in the top-level coupling array). toFactFindings emits a Coupling (co-change) Finding at location 'core/a.ts <> core/b.ts'.",
  },
  {
    module: "M3",
    id: "M3-P-AIPROV",
    kind: "positive",
    cls: "AI-authored + high-churn file (provenance-logged)",
    location: "core/checkout.ts",
    match: ["ai provenance"],
    expectedTier: "high",
    note: "core/checkout.ts is in provenance.ai_files (vitals hook log) AND carries churn_label HIGH in the real-schema vitals fixture. toFactFindings emits an AI provenance (AI-authored, high-churn) Finding at location core/checkout.ts (#369).",
  },

  // --- Boolean sub-signal NEGATIVES (must NOT be flagged) ---
  {
    module: "M3",
    id: "M3-N-MULTIAUTHOR",
    kind: "negative",
    cls: "Multi-author file — must NOT be flagged truck-factor-1",
    location: "core/reporting.ts",
    note: "core/reporting.ts is committed by 3 distinct seeded authors, no one of whom holds >50% of its commits, so vitals computes truck_factor 2 for it. vitals' knowledge_risk list only carries truck_factor ≤ 1 files (vitals_cli.py), so reporting.ts is absent from it entirely — truckFactorOneFiles never names it and toFactFindings emits nothing for it, clearing the negative check. (The pre-#1146 hand-written fixture claimed truck_factor 3, which real vitals never produces for 3 equal authors — top-2 cover 66% → truck_factor 2.)",
  },
  {
    module: "M3",
    id: "M3-N-AIPROV-STABLE",
    kind: "negative",
    cls: "AI-authored but low-churn file — must NOT be flagged AI-provenance",
    location: "lib/stable.ts",
    note: "lib/stable.ts IS in provenance.ai_files but its churn_label is LOW in the real-schema vitals fixture — the #369 finding requires the conjunction (AI-authored AND high churn), so toFactFindings emits nothing for it.",
  },
  {
    module: "M3",
    id: "M3-N-AIPROV-HUMAN",
    kind: "negative",
    cls: "High-churn but human-authored file — must NOT be flagged AI-provenance",
    location: "generated/schema.gen.ts",
    note: "generated/schema.gen.ts carries churn_label HIGH but is NOT in provenance.ai_files in the real-schema vitals fixture — high churn alone must never read as AI attribution, so toFactFindings emits nothing for it. (Distinct from M3-N-CHURN-TRIVIAL, the top-K ordering assertion on this same file, which stays in hotspot-scan.test.ts and is deliberately not a CorpusEntry.)",
  },
];
