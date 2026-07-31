import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { findFreshPass, ranFromPass, writePassArtifact } from "./audit-pass-artifact.js";
import type { RunContext } from "./audit-runner.js";
import type { Finding } from "./findings.js";
import { aiProvenanceFiles, buildFallbackReport, buildM3PassArtifact, capScopeFinding, classifyChurn, complexityProxy, couplingEdges, crossReferenceHotspots, enrichFindingsWithHotspots, fallbackQualifyingCount, isUnranked, knowledgeRiskNotAssessed, rankHotspots, toFactFindings, topKFiles, trendFindings, truckFactorOneFiles, vitalsScope, type VitalsReport } from "./hotspot-scan.js";
import { summarizeMutationReport, type StrykerReport } from "./mutation-scan.js";
import { buildCoverageMatrix } from "./scan/calibration.js";
import { m3Entries } from "./scan/calibration/m3.entries.js";

// REAL `vitals 0.2.0 report --json` capture (see hotspot-scan.ts's header). Since #1146 this is
// genuine tool output, produced by src/__fixtures__/vitals-recapture/seed.py from a purpose-seeded
// git repo + `.vitals` provenance DB — NOT a hand-written fixture. The seed makes vitals emit every
// M3 corpus fixture from docs/design/spec-72-crossmodule-corpus.md §M3:
//   - core/checkout.ts    M3-P-HOTSPOT      high churn + high complexity -> highest risk_score, top-K
//   - generated/schema.gen.ts  M3-N-CHURN-TRIVIAL  highest RAW churn but low complexity -> lower risk_score, must NOT be top-K
//   - core/billing.ts     M3-P-TRUCK1       sole-author -> truck_factor: 1 in knowledge_risk
//   - core/reporting.ts   M3-N-MULTIAUTHOR  3 balanced authors -> truck_factor 2, absent from knowledge_risk, must not be flagged
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

  it("emits NO coupling / knowledge-risk sub-signals — reduced tier invents no facts, but says so", () => {
    const r = buildFallbackReport([{ file_path: "a.ts", changes: 5, complexity: 4 }]);
    expect(r.coupling).toEqual([]);
    expect(r.knowledge_risk).toEqual([]);
    const findings = toFactFindings(r);
    // #1112 tightened this from "emits nothing" to "emits no FACT": the reduced tier's inability to
    // assess knowledge risk is cause (c) of M3-KNOWLEDGE-00, and a silent absence is the thing the
    // disclosure family exists to prevent. What must still hold is that no truck-factor / coupling /
    // AI-provenance FINDING is fabricated from a report that measured none.
    expect(findings.map((f) => f.id)).toEqual(["M3-KNOWLEDGE-00"]);
    expect(findings[0]?.confidence).toBe("N/A");
  });

  it("caps the ranking at topN", () => {
    const files = Array.from({ length: 20 }, (_, i) => ({ file_path: `f${i}.ts`, changes: i + 2, complexity: 2 }));
    expect(buildFallbackReport(files, 5).hotspots).toHaveLength(5);
  });

  // #1075 point 4: buildFallbackReport's own .slice(0, topN) happens before the caller ever sees the
  // report, so the post-slice hotspots.length alone can't tell the CLI how many files actually
  // qualified — fallbackQualifyingCount exposes the pre-slice count from the same filter.
  it("fallbackQualifyingCount reports the PRE-slice qualifying total, independent of topN", () => {
    const files = Array.from({ length: 20 }, (_, i) => ({ file_path: `f${i}.ts`, changes: i + 2, complexity: 2 }));
    expect(fallbackQualifyingCount(files)).toBe(20);
    expect(buildFallbackReport(files, 5).hotspots).toHaveLength(5); // same input, capped view
  });

  it("fallbackQualifyingCount applies the same churn/complexity gate as buildFallbackReport", () => {
    const files = [
      { file_path: "hot.ts", changes: 6, complexity: 7 },
      { file_path: "rare.ts", changes: 1, complexity: 9 }, // below churn gate
      { file_path: "trivial.ts", changes: 9, complexity: 0 }, // no complexity
    ];
    expect(fallbackQualifyingCount(files)).toBe(1);
  });
});

// #1075 point 1: vitals' own "complexity-only" mode (no git in the target) sets churn=0 for every
// file, so every hotspot's risk_score is EXACTLY 0.0 — the resulting "ranking" is filesystem-walk
// order, and previously nothing stopped enrichFindingsWithHotspots/crossReferenceHotspots from
// stamping "top remediation priority" onto other modules' findings based on that arbitrary order.
// This is the one bug in the #1064 class that INVENTS a signal rather than losing one.
describe("M3 unranked reports are never used for cross-module enrichment (#1075)", () => {
  const complexityOnlyReport: VitalsReport = {
    mode: "complexity-only",
    hotspots: [
      { file_path: "z.ts", health: 5, role: "core", centrality: 0, churn_data: { changes: 0, lines_added: 0, lines_removed: 0, author_count: 0, last_change: "" }, churn_label: "LOW", complexity_score: 12, coupling_strength: 0, changes: 0, risk_score: 0 },
      { file_path: "a.ts", health: 5, role: "core", centrality: 0, churn_data: { changes: 0, lines_added: 0, lines_removed: 0, author_count: 0, last_change: "" }, churn_label: "LOW", complexity_score: 3, coupling_strength: 0, changes: 0, risk_score: 0 },
    ],
    coupling: [],
    knowledge_risk: [],
  };

  it("isUnranked is true when every risk_score is 0 and hotspots is non-empty", () => {
    expect(isUnranked(complexityOnlyReport)).toBe(true);
  });

  it("isUnranked is false for a genuinely-ranked report (varying risk_score)", () => {
    expect(isUnranked(report)).toBe(false); // the module-level #94 fixture — real varying scores
  });

  it("isUnranked is false for a genuinely EMPTY hotspots list — that's a different, already-disclosed case", () => {
    expect(isUnranked({ hotspots: [], coupling: [], knowledge_risk: [] })).toBe(false);
  });

  it("crossReferenceHotspots no-ops entirely against an unranked report — no finding is stamped 'top remediation priority'", () => {
    const finding = planted("M1-RLS-01", "z.ts:1"); // z.ts is filesystem-walk-order "first" — NOT a real hotspot
    const { findings, hotspotFindingIds } = crossReferenceHotspots([finding], complexityOnlyReport, 3);
    expect(hotspotFindingIds).toEqual([]);
    expect(findings[0]?.note).toBeUndefined();
    expect(findings).toEqual([finding]); // untouched, not even reordered
  });

  it("crossReferenceHotspots still fires normally against a genuinely-ranked report (regression check)", () => {
    const { hotspotFindingIds } = crossReferenceHotspots([planted("M1-RLS-01", "core/checkout.ts:1")], report, 3);
    expect(hotspotFindingIds).toEqual(["M1-RLS-01"]);
  });
});

// #1075 point 2: trends/overall_health were declared nowhere in VitalsReport and never read — the
// single most actionable M3 signal for a repeat engagement ("health moved from 6.2 to 5.8, driven by
// these files"), silently dropped even though vitals_cli.py always serializes it.
describe("M3 trend findings (#1075)", () => {
  it("emits nothing when trends is null (first-ever run — no prior snapshot, not a gap)", () => {
    expect(trendFindings({ ...report, trends: null })).toEqual([]);
  });

  it("emits nothing when trends has no degrading files", () => {
    expect(trendFindings({ ...report, trends: { previous_overall: 6, previous_timestamp: 0, days_since: 7, overall_delta: 0.3, degrading: [], improving: [] } })).toEqual([]);
  });

  it("emits one grouped finding naming the worst-degrading file and the overall delta", () => {
    const withTrend: VitalsReport = {
      ...report,
      trends: {
        previous_overall: 6.2,
        previous_timestamp: 1735689600,
        days_since: 14,
        overall_delta: -0.4,
        degrading: [
          { file_path: "core/checkout.ts", previous: 5.0, current: 3.1, delta: -1.9 },
          { file_path: "core/billing.ts", previous: 6.0, current: 5.4, delta: -0.6 },
        ],
        improving: [],
      },
    };
    const findings = trendFindings(withTrend);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("M3-TREND-00");
    expect(findings[0]?.location).toBe("core/checkout.ts"); // worst delta
    expect(findings[0]?.evidence).toContain("core/checkout.ts");
    expect(findings[0]?.evidence).toContain("core/billing.ts");
    expect(findings[0]?.title).toContain("2 files");
  });

  it("is included in toFactFindings' output", () => {
    const withTrend: VitalsReport = {
      ...report,
      trends: { previous_overall: 6, previous_timestamp: 0, days_since: 1, overall_delta: -0.6, degrading: [{ file_path: "x.ts", previous: 6, current: 5.4, delta: -0.6 }], improving: [] },
    };
    expect(toFactFindings(withTrend).map((f) => f.id)).toContain("M3-TREND-00");
  });

  it("does not appear in the calibration corpus fixture (trends: null there — regression check)", () => {
    expect(report.trends).toBeNull();
    expect(toFactFindings(report).map((f) => f.id)).not.toContain("M3-TREND-00");
  });
});

// #1112 — the issue asked for a plant that cannot decay; the measurement said the plant decays on a
// TWO-YEAR clock (not the 90-day churn window it was filed on) and, more importantly, that its
// failure was indistinguishable from a detector regression. These pin the disclosure that separates
// the two, because "GONE M3" carries a standing instruction never to rebaseline — so the row that
// says WHY is the thing keeping that instruction honest.
describe("M3 knowledge-risk disclosure (#1112)", () => {
  // #1448: a REAL vitals run — vitals_cli.py:238-245 only ever puts truck_factor<=1 rows into
  // `knowledge_risk`, so once the early return above has passed (no truck-factor-1 file), that
  // array is NECESSARILY empty on every real capture, clean or not. `cleanRun` is that real shape:
  // the scored population (file_health, same 7 files as the captured fixture) is non-empty and git
  // was present — this is what "the signal ran and genuinely found nothing" looks like on real
  // vitals output, and per #1448's acceptance it must reach the MEASURED branch.
  const cleanRun: VitalsReport = { ...report, knowledge_risk: [] };
  // Three shapes that must all stay NOT-assessed, because none of them proves authorship was read:
  //   `starved`  — nothing at all to go on (reduced tier / hand-built pre-#1290 capture).
  //   `decayed`  — the 800-day repo MEASURED in hotspot-scan.ts's own header comment: the churn gate
  //                is exhausted (file_health {}) so vitals' knowledge population fell back to
  //                source_files[:50], while `files_analyzed` still counts every TRACKED file. That
  //                count is a `git ls-files` census, independent of the two-year authorship window,
  //                so it can be large while zero authorship rows came back.
  //   `noGit`    — complexity-only mode: get_knowledge_distribution is never called (it lives inside
  //                vitals_cli.py's has_git branch) yet file_health is still populated, so a bare
  //                population count would read "measured clean" off a run that computed no
  //                authorship whatsoever.
  const starved: VitalsReport = { ...report, knowledge_risk: [], file_health: {}, files_analyzed: undefined };
  const decayed: VitalsReport = { ...report, knowledge_risk: [], file_health: {}, files_analyzed: 1792 };
  const noGit: VitalsReport = { ...report, knowledge_risk: [], mode: "complexity-only" };

  it("stays silent while a truck-factor-1 file exists — no row alongside the finding it would explain", () => {
    expect(truckFactorOneFiles(report).length).toBeGreaterThan(0);
    expect(knowledgeRiskNotAssessed(report)).toEqual([]);
    expect(toFactFindings(report).map((f) => f.id)).not.toContain("M3-KNOWLEDGE-00");
  });

  it("distinguishes 'analysed and found none' from 'nothing to analyse' — reachable both ways from REAL vitals shapes", () => {
    const measured = knowledgeRiskNotAssessed(cleanRun)[0];
    expect(measured?.title).toContain("analysed across 7");
    expect(measured?.confidence).toBe("Confirmed");
    expect(measured?.impact).toContain("None");
    expect(measured?.evidence).toContain("7 of the 7 file(s) it scored");

    const unmeasured = knowledgeRiskNotAssessed(starved)[0];
    expect(unmeasured?.title).toContain("NOT assessed");
    expect(unmeasured?.confidence).toBe("N/A");
    expect(unmeasured?.impact).toContain("NOT evidence the knowledge is well distributed");
  });

  // The regression control for #1448's own fix. Keying the split off a population that FALLS BACK to
  // `files_analyzed` made the 800-day repo — the one this row exists for — report "authorship
  // analysed across 50 files / Confirmed" off a tracked-file census that never touched git history.
  // Both shapes below have a nonzero file count and zero read authorship.
  it("stays NOT-assessed when the file count survives an exhausted churn gate or a git-less run", () => {
    for (const [name, shape] of [
      ["decayed (churn gate exhausted, 1792 files still tracked)", decayed],
      ["complexity-only (no git, so authorship never ran)", noGit],
    ] as const) {
      const row = knowledgeRiskNotAssessed(shape)[0];
      expect(row, name).toBeDefined();
      expect(row?.title, name).toContain("NOT assessed");
      expect(row?.confidence, name).toBe("N/A");
      expect(row?.evidence, name).toContain("cannot confirm the authorship analysis had anything to read");
    }
    // ...while the scored population it is derived from is genuinely large, so the row is not
    // passing by accident on an empty report.
    expect(decayed.files_analyzed).toBe(1792);
    expect(Object.keys(noGit.file_health ?? {})).toHaveLength(7);
  });

  it("names what vitals actually READ when its 50-file knowledge slice binds, not the scored total", () => {
    // vitals_cli.py:132 slices code_files[:50], so on the 314-scored-file shape MEASURED against this
    // repo the row may claim 50 — never 314. A capped population stated as a census is the same
    // over-claim in miniature as the one this whole row exists to prevent.
    const wide: VitalsReport = {
      ...report,
      knowledge_risk: [],
      file_health: Object.fromEntries(Array.from({ length: 314 }, (_, i) => [`src/f${i}.ts`, 5])),
    };
    const row = knowledgeRiskNotAssessed(wide)[0];
    expect(row?.confidence).toBe("Confirmed");
    expect(row?.title).toContain("analysed across 50 files");
    expect(row?.evidence).toContain("50 of the 314 file(s) it scored");
    expect(row?.evidence).toContain("first 50 scored files");
  });

  it("names the TWO-YEAR authorship horizon, not the 90-day churn window", () => {
    // The correction #1112 turned on: MEASURED 2026-07-26, a repo whose newest commit is 200 days
    // old still emits both truck-factor rows (vitals_cli.py:131 falls back to all tracked source
    // files); at 800 days they are gone (git_analysis.py:260, --since=2.years.ago). A reader sent
    // after the churn window would look in the wrong place.
    const evidence = knowledgeRiskNotAssessed(starved)[0]?.evidence ?? "";
    expect(evidence).toContain("TWO YEARS");
    expect(evidence).toContain("NOT the 90-day churn window");
  });

  it("carries a taxonomy the conservation gate's M3 plant cannot match", () => {
    // The gate matches M3 on `Knowledge risk (truck-factor-1)`. If this row shared that taxonomy it
    // would satisfy the plant while the plant was gone — a disclosure that hides the thing it
    // discloses. Checked on both branches since #1448 made both reachable.
    expect(knowledgeRiskNotAssessed(cleanRun)[0]?.taxonomy).not.toBe("Knowledge risk (truck-factor-1)");
    expect(knowledgeRiskNotAssessed(starved)[0]?.taxonomy).not.toBe("Knowledge risk (truck-factor-1)");
    expect(knowledgeRiskNotAssessed(decayed)[0]?.taxonomy).not.toBe("Knowledge risk (truck-factor-1)");
  });

  it("does not disturb the M3 corpus scoring", () => {
    const matrix = buildCoverageMatrix(toFactFindings(report), m3Entries);
    expect(matrix.ok).toBe(true);
    expect(matrix.negativesCleared).toBe(matrix.negativesTotal);
  });
});

// #1364: the M3 pass artifact src/cli/hotspot-scan.ts writes with --artifacts-dir.
describe("buildM3PassArtifact + write → derive round trip (#1364)", () => {
  const dir = mkdtempSync(join(tmpdir(), "harvey-m3-pass-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("names which tier produced the findings in its summary, since the artifact schema has no tier field", () => {
    const findings = toFactFindings(report);
    const full = buildM3PassArtifact({ targetDir: "/t", findings, hotspots: ["core/checkout.ts"], rankedCount: 3, tier: "full", generatedAt: "2026-07-27T00:00:00Z" });
    expect(full.summary).toContain("full vitals");
    const reduced = buildM3PassArtifact({ targetDir: "/t", findings: [], hotspots: [], rankedCount: 0, tier: "reduced", generatedAt: "2026-07-27T00:00:00Z" });
    expect(reduced.summary).toContain("reduced tier");
    const unranked = buildM3PassArtifact({ targetDir: "/t", findings: [], hotspots: [], rankedCount: 5, tier: "unranked", generatedAt: "2026-07-27T00:00:00Z" });
    expect(unranked.summary).toContain("unranked");
  });

  it("a written M3 pass artifact is read back fresh and derives ran, findings and hotspots intact", () => {
    const findings = toFactFindings(report);
    const built = buildM3PassArtifact({
      targetDir: "/engagement/target",
      findings,
      hotspots: ["core/checkout.ts"],
      rankedCount: 3,
      tier: "full",
      generatedAt: "2026-07-27T00:00:00Z",
    });
    const path = writePassArtifact(dir, built);
    expect(path).toBe(join(dir, "M3.pass.json"));

    const ctx: RunContext = {
      targetDir: "/engagement/target",
      env: { connected: false, dynamic: false, llm: false },
      exec: () => ({ ok: true, output: "" }),
      exists: (p) => existsSync(p),
      artifactsDir: dir,
      readArtifact: (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : undefined),
      now: Date.parse("2026-07-27T12:00:00Z"),
    };
    const fresh = findFreshPass(ctx, "M3");
    expect(fresh.fresh).toBe(true);
    if (fresh.fresh) {
      expect(fresh.artifact.hotspots).toEqual(["core/checkout.ts"]);
      const ran = ranFromPass(fresh.artifact, "mech");
      expect(ran.status).toBe("ran");
      expect(ran.findings).toEqual(findings);
    }
  });
});

// #1290 — #1075 disclosed vitals' caps as "capped at the top 5 pairs / the first 50 source files"
// with no denominator, so 50-of-52 and 50-of-1792 read identically. Both denominators were derivable;
// one of them was already sitting unread in the payload Harvey parses.
describe("M3 input-scope disclosure (#1290)", () => {
  // The MEASURED shape from a live `vitals_cli.py report --json` run against this repo, 2026-07-28:
  // file_health 314 scored files, files_analyzed 1792 tracked source files, coupling and hotspots
  // both sliced (5 of 10, 10 of 314). The committed fixture misses a scored-vs-tracked mix-up
  // because it happens to have 7 and 7, and its coupling list of 1 never reaches the cap at all.
  const wideScope = (over: Partial<VitalsReport> = {}): VitalsReport => ({
    ...report,
    file_health: Object.fromEntries(Array.from({ length: 314 }, (_, i) => [`src/f${i}.ts`, 5])),
    files_analyzed: 1792,
    coupling: Array.from({ length: 5 }, (_, i) => ({ file_a: `src/a${i}.ts`, file_b: `src/b${i}.ts`, co_changes: 4, coupling_strength: 0.9, total_a: 5, total_b: 5 })),
    ...over,
  });

  it("reads both denominators off the real committed capture — the payload already carried them", () => {
    // Guards the #1290 root cause directly: #1075 widened VitalsReport for `mode`/`trends`/
    // `overall_health` while `files_analyzed` sat in the very same JSON, undeclared and unread.
    const raw = JSON.parse(readFileSync(new URL("./__fixtures__/vitals-report.json", import.meta.url), "utf8")) as Record<string, unknown>;
    expect(raw["files_analyzed"]).toBe(7);
    expect(Object.keys(raw["file_health"] as object)).toHaveLength(7);
    expect(vitalsScope(report)).toEqual({ scored: 7, tracked: 7, knowledgePopulation: 7 });
  });

  it("the truck-factor denominator is the SCORED file count, not the tracked one", () => {
    // vitals_cli.py:132 slices `code_files[:50]`, and code_files is what file_health is keyed by.
    // files_analyzed is len(source_files) — 5.7x wider on this repo. Reporting "50 of 1792" would
    // replace #1075's hedge with a second false claim, which is what this asserts against.
    expect(vitalsScope(wideScope()).knowledgePopulation).toBe(314);
    const evidence = capScopeFinding(wideScope(), 10, "").evidence;
    expect(evidence).toContain("showing 50 of 314 churning source files with structural complexity");
    expect(evidence).not.toContain("50 of 1792");
  });

  it("falls back to the tracked count only in vitals' own empty-code_files branch", () => {
    // `code_files[:50] if code_files else source_files[:50]` — the #1112 case, where nothing cleared
    // the churn+complexity gate and knowledge analysis runs over all tracked source files instead.
    expect(vitalsScope(wideScope({ file_health: {} })).knowledgePopulation).toBe(1792);
    expect(capScopeFinding(wideScope({ file_health: {} }), 10, "").evidence).toContain("showing 50 of 1792 tracked source files");
  });

  it("states the true pre-cap coupling total the plugin's own function returns", () => {
    expect(capScopeFinding(wideScope(), 10, "").evidence).toContain("Co-change coupling: showing 5 of 10 coupled file pairs");
  });

  it("says a cap did NOT bind rather than implying a cut", () => {
    const small = wideScope({ file_health: { "a.ts": 5, "b.ts": 6 }, hotspots: report.hotspots.slice(0, 2), coupling: report.coupling.slice(0, 1) });
    const evidence = capScopeFinding(small, 1, "").evidence;
    expect(evidence).toContain("all 2 files vitals scored (vitals' cap of 10 did not bind)");
    expect(evidence).toContain("all 1 coupled file pair (vitals' cap of 5 did not bind)");
    expect(capScopeFinding(small, 1, "").confidence).toBe("Confirmed");
  });

  it("an underivable denominator is named as underivable WITH its reason, never substituted", () => {
    // The silent-omission shape this whole row exists to prevent: a 5-row coupling list with no
    // total must not read as "5 coupled pairs exist".
    const f = capScopeFinding(wideScope(), undefined, "the report was supplied pre-captured via --report");
    expect(f.evidence).toContain("exactly vitals' cap of 5 — the true total is NOT derivable here (the report was supplied pre-captured via --report)");
    expect(f.confidence).toBe("N/A");
    expect(f.title).toContain("1 of 3 totals could not be derived");
    expect(f.fix).toContain("Re-run M3 live");
  });

  it("is a disclosure row, never a free-count hit against a calibration negative", () => {
    // Mirrors M3-KNOWLEDGE-00: no precisionTier, so a widened scope row can never light a benign
    // fixture the way #1251/#1198 were found.
    const f = capScopeFinding(wideScope(), 10, "");
    expect(f.precisionTier).toBeUndefined();
    expect(f.severity).toBe("Info");
    // Every M3 negative still clears with the scope row in the finding set: it lights no fixture.
    const matrix = buildCoverageMatrix([f], m3Entries);
    expect(matrix.rows.filter((r) => r.kind === "negative" && (r.highFlagged || r.reviewFlagged))).toEqual([]);
    expect(matrix.negativesCleared).toBe(matrix.negativesTotal);
  });
});
