import { describe, expect, it } from "vitest";
import { couplingEdges, rankHotspots, toFactFindings, topKFiles, truckFactorOneFiles, type VitalsReport } from "./hotspot-scan.js";
import { buildCoverageMatrix } from "./scan/calibration.js";
import { m3Entries } from "./scan/calibration/m3.entries.js";

// ASSUMED-schema fixture (see hotspot-scan.ts's header) standing in for a `vitals_cli.py report
// --json` capture — NOT a real vitals run. Shaped to plant every M3 corpus fixture from
// docs/design/spec-72-crossmodule-corpus.md §M3:
//   - core/checkout.ts    M3-P-HOTSPOT      high churn + high complexity -> highest ROI, top-K
//   - generated/schema.gen.ts  M3-N-CHURN-TRIVIAL  highest CHURN but trivial complexity -> low ROI, must NOT be top-K
//   - core/billing.ts     M3-P-TRUCK1       sole-author -> truckFactor1: true
//   - core/reporting.ts   M3-N-MULTIAUTHOR  3 seeded authors -> truckFactor1: false
//   - core/a.ts / core/b.ts  M3-P-COUPLING  always co-committed -> a coupling edge
//   - lib/stable.ts       (not a corpus fixture) low churn/complexity, rounds out the ranking
const report: VitalsReport = {
  hotspots: [
    { file: "core/checkout.ts", health: 3.1, churn: 38, complexity: 61, roi: 92 },
    { file: "generated/schema.gen.ts", health: 6.0, churn: 55, complexity: 4, roi: 8 },
    { file: "core/billing.ts", health: 5.0, churn: 20, complexity: 30, roi: 40, truckFactor1: true, soleAuthor: "alice" },
    { file: "core/reporting.ts", health: 5.5, churn: 18, complexity: 25, roi: 35, truckFactor1: false },
    { file: "core/a.ts", health: 6.5, churn: 12, complexity: 15, roi: 30, coChanges: ["core/b.ts"] },
    { file: "core/b.ts", health: 6.6, churn: 11, complexity: 14, roi: 28, coChanges: ["core/a.ts"] },
    { file: "lib/stable.ts", health: 8.5, churn: 3, complexity: 5, roi: 5 },
  ],
};

describe("M3 top-K ordering gate (regression check, NOT a precision measure)", () => {
  it("ranks the planted churn×complexity hotspot (M3-P-HOTSPOT) in the top-3", () => {
    expect(topKFiles(report, 3)).toContain("core/checkout.ts");
  });

  it("does NOT rank the high-churn/trivial-complexity lookalike (M3-N-CHURN-TRIVIAL) in the top-3, despite it having the highest raw churn in the fixture", () => {
    const top3 = topKFiles(report, 3);
    const maxChurnFile = [...report.hotspots].sort((a, b) => b.churn - a.churn)[0]?.file;
    expect(maxChurnFile).toBe("generated/schema.gen.ts"); // sanity: it really is the highest-churn row
    expect(top3).not.toContain("generated/schema.gen.ts");
  });

  it("is a stable ordering across repeated calls (reproducibility, not a one-off sort)", () => {
    expect(topKFiles(report, 3)).toEqual(topKFiles(report, 3));
  });

  it("ranks worst-first by ROI", () => {
    const ranked = rankHotspots(report);
    expect(ranked[0]?.file).toBe("core/checkout.ts");
    for (let i = 1; i < ranked.length; i++) {
      expect(ranked[i - 1]!.roi).toBeGreaterThanOrEqual(ranked[i]!.roi);
    }
  });
});

describe("M3 boolean sub-signals (deterministic facts, scored like any other module)", () => {
  it("flags exactly the sole-author file as truck-factor-1", () => {
    expect(truckFactorOneFiles(report)).toEqual(["core/billing.ts"]);
  });

  it("does not flag the multi-author lookalike as truck-factor-1", () => {
    expect(truckFactorOneFiles(report)).not.toContain("core/reporting.ts");
  });

  it("derives one deduped coupling edge for the always-co-committed pair", () => {
    const edges = couplingEdges(report);
    expect(edges).toEqual([{ a: "core/a.ts", b: "core/b.ts" }]);
  });

  it("scores the M3 boolean-fact corpus entries clean through the shared calibration harness", () => {
    const findings = toFactFindings(report);
    const matrix = buildCoverageMatrix(findings, m3Entries);
    expect(matrix.ok).toBe(true);
    expect(matrix.positivesCaught).toBe(matrix.positivesTotal); // M3-P-TRUCK1, M3-P-COUPLING
    expect(matrix.negativesCleared).toBe(matrix.negativesTotal); // M3-N-MULTIAUTHOR
  });
});
