// M3 batch (#72, spec §M3) — hotspot analysis (vitals: churn×complexity, truck-factor, coupling).
// Design + fixture, NOT a live gate: `vitals`/`vitals_cli.py` is not runnable in this environment
// and its `--json` schema is undocumented in this repo (see src/hotspot-scan.ts's header for the
// full accounting, and issue #94 for the deferred live capture that must land before this is
// trusted). Everything below scores against an ASSUMED-schema fixture in hotspot-scan.test.ts,
// not a real vitals run.
//
// Per the locked product decision + spec discipline: a hotspot RANK is an ordering over a
// continuous score, not a true/false finding — there is no M3 precision number, and these entries
// must never be read as one. Only the two DETERMINISTIC BOOLEAN sub-signals (truck-factor-1,
// co-change coupling edge) are modeled here as CorpusEntry positives/negatives, because — unlike
// a rank — "is this file truck-factor-1" and "are these two files coupled" are true/false facts,
// scored the same way every other module's facts are (src/hotspot-scan.ts::toFactFindings ->
// buildCoverageMatrix). module: "M3" keeps them out of validate-calibration.ts's
// `module === undefined` filter, same as M7/M8/M10.
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
    expectedTier: "high",
    note: "core/billing.ts is committed only by one seeded author (alice) in the assumed vitals fixture. toFactFindings emits a Knowledge risk (truck-factor-1) Finding at location core/billing.ts.",
  },
  {
    module: "M3",
    id: "M3-P-COUPLING",
    kind: "positive",
    cls: "Co-change coupling edge",
    location: "core/a.ts <> core/b.ts",
    expectedTier: "high",
    note: "core/a.ts and core/b.ts are always committed together in the assumed vitals fixture. toFactFindings emits a Coupling (co-change) Finding at location 'core/a.ts <> core/b.ts'.",
  },

  // --- Boolean sub-signal NEGATIVE (must NOT be flagged) ---
  {
    module: "M3",
    id: "M3-N-MULTIAUTHOR",
    kind: "negative",
    cls: "Multi-author file — must NOT be flagged truck-factor-1",
    location: "core/reporting.ts",
    note: "core/reporting.ts is committed by 3 distinct seeded authors in the assumed vitals fixture (truckFactor1: false) — toFactFindings emits nothing for it, so it must clear the negative check.",
  },
];
