import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { aiProvenanceFiles, couplingEdges, rankHotspots, toFactFindings, topKFiles, truckFactorOneFiles, type VitalsReport } from "./hotspot-scan.js";
import { buildCoverageMatrix } from "./scan/calibration.js";
import { m3Entries } from "./scan/calibration/m3.entries.js";

// REAL-schema fixture (see hotspot-scan.ts's header) — synthetic paths/values, verified field
// shape from a live `vitals 0.2.0 report --json` capture (issue #94). Plants every M3 corpus
// fixture from docs/design/spec-72-crossmodule-corpus.md §M3:
//   - core/checkout.ts    M3-P-HOTSPOT      high churn + high complexity -> highest risk_score, top-K
//   - generated/schema.gen.ts  M3-N-CHURN-TRIVIAL  highest raw churn but trivial complexity -> low risk_score, must NOT be top-K
//   - core/billing.ts     M3-P-TRUCK1       sole-author -> truck_factor: 1 in knowledge_risk
//   - core/reporting.ts   M3-N-MULTIAUTHOR  3 seeded authors -> truck_factor: 3, must not be flagged
//   - core/a.ts / core/b.ts  M3-P-COUPLING  always co-committed -> one coupling edge
//   - core/checkout.ts    M3-P-AIPROV       also in provenance.ai_files + churn HIGH -> AI finding (#369)
//   - lib/stable.ts       M3-N-AIPROV-STABLE  in provenance.ai_files but churn LOW, must NOT be flagged
//   - generated/schema.gen.ts  M3-N-AIPROV-HUMAN  churn HIGH but human-authored, must NOT be flagged
const report: VitalsReport = JSON.parse(
  readFileSync(new URL("./__fixtures__/vitals-report.json", import.meta.url), "utf8"),
) as VitalsReport;

describe("M3 top-K ordering gate (regression check, NOT a precision measure)", () => {
  it("ranks the planted churn×complexity hotspot (M3-P-HOTSPOT) in the top-3", () => {
    expect(topKFiles(report, 3)).toContain("core/checkout.ts");
  });

  it("does NOT rank the high-churn/trivial-complexity lookalike (M3-N-CHURN-TRIVIAL) in the top-3, despite it having the highest raw churn in the fixture", () => {
    const top3 = topKFiles(report, 3);
    const maxChurnFile = [...report.hotspots].sort((a, b) => b.churn_data.changes - a.churn_data.changes)[0]?.file_path;
    expect(maxChurnFile).toBe("generated/schema.gen.ts"); // sanity: it really is the highest-churn row
    expect(top3).not.toContain("generated/schema.gen.ts");
  });

  it("is a stable ordering across repeated calls (reproducibility, not a one-off sort)", () => {
    expect(topKFiles(report, 3)).toEqual(topKFiles(report, 3));
  });

  it("ranks worst-first by risk_score", () => {
    const ranked = rankHotspots(report);
    expect(ranked[0]?.file_path).toBe("core/checkout.ts");
    for (let i = 1; i < ranked.length; i++) {
      expect(ranked[i - 1]!.risk_score).toBeGreaterThanOrEqual(ranked[i]!.risk_score);
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
    expect(matrix.positivesCaught).toBe(matrix.positivesTotal); // M3-P-TRUCK1, M3-P-COUPLING, M3-P-AIPROV
    expect(matrix.negativesCleared).toBe(matrix.negativesTotal); // M3-N-MULTIAUTHOR, M3-N-AIPROV-STABLE, M3-N-AIPROV-HUMAN
  });
});

describe("M3 AI-provenance sub-signal (#369 — spec-72 §M3's third boolean fact)", () => {
  it("extracts the AI-authored files the provenance log attributes", () => {
    expect(aiProvenanceFiles(report)).toEqual(["core/checkout.ts", "lib/stable.ts"]);
  });

  it("returns nothing when vitals reports no provenance data — the real { has_data: false } shape carries no ai_files key", () => {
    expect(aiProvenanceFiles({ ...report, provenance: { has_data: false } })).toEqual([]);
  });

  it("tolerates a capture without the provenance key (pre-0.2.0) instead of crashing", () => {
    const withoutProvenance: VitalsReport = { hotspots: report.hotspots, coupling: report.coupling, knowledge_risk: report.knowledge_risk };
    expect(aiProvenanceFiles(withoutProvenance)).toEqual([]);
  });

  it("emits the finding only for the AI-authored AND high-churn conjunction", () => {
    const ids = toFactFindings(report).map((f) => f.id);
    // core/checkout.ts: in ai_files AND churn_label HIGH -> flagged.
    expect(ids).toContain("M3-AIPROV-core/checkout.ts");
    // lib/stable.ts: in ai_files but churn LOW -> AI attribution alone is not the finding.
    expect(ids).not.toContain("M3-AIPROV-lib/stable.ts");
    // generated/schema.gen.ts: churn HIGH but human-authored -> churn alone is not AI attribution.
    expect(ids).not.toContain("M3-AIPROV-generated/schema.gen.ts");
  });
});
