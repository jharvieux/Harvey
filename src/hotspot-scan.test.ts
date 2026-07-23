import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Finding } from "./findings.js";
import { aiProvenanceFiles, buildFallbackReport, classifyChurn, complexityProxy, couplingEdges, crossReferenceHotspots, enrichFindingsWithHotspots, rankHotspots, toFactFindings, topKFiles, truckFactorOneFiles, type VitalsReport } from "./hotspot-scan.js";
import { summarizeMutationReport, type StrykerReport } from "./mutation-scan.js";
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

const planted = (id: string, location: string, note?: string): Finding => ({
  id,
  title: id,
  severity: "High",
  confidence: "Confirmed",
  category: "Security",
  taxonomy: "test",
  location,
  status: "Open",
  evidence: "planted",
  impact: "planted",
  fix: "planted",
  value: 4,
  ease: 4,
  safety: 4,
  note,
});

describe("M3 cross-reference against other modules' findings (#363)", () => {
  // core/checkout.ts is top-3 by risk_score in the fixture; lib/stable.ts is not.
  const onHotspot = planted("M1-RLS-01", "core/checkout.ts:42");
  const offHotspot = planted("M7-N1-01", "lib/stable.ts:10");

  it("annotates and front-orders a finding whose location sits on a top-K hotspot", () => {
    const { findings, hotspotFindingIds } = crossReferenceHotspots([offHotspot, onHotspot], report, 3);
    expect(hotspotFindingIds).toEqual(["M1-RLS-01"]);
    expect(findings.map((f) => f.id)).toEqual(["M1-RLS-01", "M7-N1-01"]); // hotspot first
    expect(findings[0]?.note).toMatch(/top remediation priority/i);
    expect(findings[0]?.note).toContain("core/checkout.ts");
    expect(findings[1]?.note).toBeUndefined();
  });

  it("preserves an existing note instead of overwriting the auditor's words", () => {
    const { findings } = crossReferenceHotspots([planted("M9-01", "core/checkout.ts:7", "operator note")], report, 3);
    expect(findings[0]?.note).toMatch(/^operator note /);
    expect(findings[0]?.note).toMatch(/hotspot/);
  });

  it("never alters severity or the BFTB inputs — the cross-reference reorders, it does not regrade", () => {
    const { findings } = crossReferenceHotspots([onHotspot], report, 3);
    expect(findings[0]).toMatchObject({ severity: "High", value: 4, ease: 4, safety: 4 });
    expect(onHotspot.note).toBeUndefined(); // input not mutated
  });

  // #515: the shared enrichment applied at assembly to EVERY module's findings.
  it("tags a finding on a top-K hotspot with onHotspot + 1-based hotspotRank, leaving others clean", () => {
    const top = topKFiles(report, 3);
    const enriched = enrichFindingsWithHotspots(
      [planted("M7-01", "lib/stable.ts:10"), planted("M6-01", top[0] + ":5")],
      top,
    );
    const onHot = enriched.find((f) => f.id === "M6-01");
    expect(onHot?.onHotspot).toBe(true);
    expect(onHot?.hotspotRank).toBe(1);
    const offHot = enriched.find((f) => f.id === "M7-01");
    expect(offHot?.onHotspot).toBeUndefined();
    expect(offHot?.hotspotRank).toBeUndefined();
  });

  it("never mutates the input findings or their grading inputs", () => {
    const input = planted("M4-01", topKFiles(report, 3)[0] + ":1");
    const [out] = enrichFindingsWithHotspots([input], topKFiles(report, 3));
    expect(input.onHotspot).toBeUndefined(); // input untouched
    expect(out).toMatchObject({ severity: "High", value: 4, ease: 4, safety: 4 });
  });

  it("feeds M8 directly: topKFiles output is consumable as summarizeMutationReport's hotspot list", () => {
    const stryker: StrykerReport = {
      files: {
        "core/checkout.ts": { mutants: [{ id: "1", mutatorName: "BooleanLiteral", status: "Survived", location: { start: { line: 1, column: 1 }, end: { line: 1, column: 2 } } }] },
        "lib/stable.ts": { mutants: [{ id: "2", mutatorName: "BooleanLiteral", status: "Survived", location: { start: { line: 1, column: 1 }, end: { line: 1, column: 2 } } }] },
      },
    };
    const summary = summarizeMutationReport(stryker, topKFiles(report, 3));
    expect(summary.survivingMutants.find((m) => m.file === "core/checkout.ts")?.hotspot).toBe(true);
    expect(summary.survivingMutants.find((m) => m.file === "lib/stable.ts")?.hotspot).toBe(false);
    expect(summary.survivingMutants[0]?.file).toBe("core/checkout.ts"); // hotspot survivor sorts first
  });
});

// #807: the reduced Harvey-side tier — the churn×complexity ranking computed WITHOUT vitals, for a
// cold sandbox / fresh repo. These are the pure transforms; the CLI's git/fs gathering is the thin
// I/O wrapper.
describe("M3 reduced tier (#807, vitals-unavailable fallback)", () => {
  it("classifyChurn mirrors vitals 0.2.0 thresholds (≤2 LOW, ≤8 MED, else HIGH)", () => {
    expect([1, 2].map(classifyChurn)).toEqual(["LOW", "LOW"]);
    expect([3, 8].map(classifyChurn)).toEqual(["MED", "MED"]);
    expect([9, 40].map(classifyChurn)).toEqual(["HIGH", "HIGH"]);
  });

  it("complexityProxy separates a branchy file from a flat one", () => {
    const gnarly = "function f(x){ if(x){ for(;;){ while(x){} } } return x && x || 0; }";
    const flat = "export const x = 1;";
    expect(complexityProxy(gnarly)).toBeGreaterThan(complexityProxy(flat));
    expect(complexityProxy(flat)).toBe(1); // base 1, no branches
  });

  it("ranks by churn×complexity and drops sub-gate files (churn<2 or zero complexity)", () => {
    const r = buildFallbackReport([
      { file_path: "hot.ts", changes: 6, complexity: 7 }, // 42
      { file_path: "warm.ts", changes: 3, complexity: 2 }, // 6
      { file_path: "rare.ts", changes: 1, complexity: 9 }, // dropped: churn<2
      { file_path: "trivial.ts", changes: 9, complexity: 0 }, // dropped: no complexity
    ]);
    expect(r.hotspots.map((h) => h.file_path)).toEqual(["hot.ts", "warm.ts"]);
    expect(r.hotspots[0]?.risk_score).toBe(42);
    expect(r.hotspots[0]?.churn_label).toBe("MED");
  });

  it("emits NO coupling / knowledge-risk sub-signals — reduced tier invents no facts", () => {
    const r = buildFallbackReport([{ file_path: "a.ts", changes: 5, complexity: 4 }]);
    expect(r.coupling).toEqual([]);
    expect(r.knowledge_risk).toEqual([]);
    expect(toFactFindings(r)).toEqual([]); // no truck-factor/coupling/AI-prov findings fabricated
  });

  it("caps the ranking at topN", () => {
    const files = Array.from({ length: 20 }, (_, i) => ({ file_path: `f${i}.ts`, changes: i + 2, complexity: 2 }));
    expect(buildFallbackReport(files, 5).hotspots).toHaveLength(5);
  });
});
