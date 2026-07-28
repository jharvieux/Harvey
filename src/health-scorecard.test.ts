import { describe, expect, it } from "vitest";
import { buildHealthScorecard, densityScore, duplicationScore, riskBandOf, rollupExamples, EXAMPLES_SHOWN, type PiiTableBand, type ScorecardInput } from "./health-scorecard.js";
import type { Finding } from "./findings.js";

// A target with nothing detectable in it, so each test controls exactly one dimension.
const EMPTY_SOURCE = [{ path: "app/page.tsx", text: "export default function Page() {\n  return null;\n}\n" }];

function input(over: Partial<ScorecardInput> = {}): ScorecardInput {
  return {
    m1: { grade: "B", score: 80, gradedCount: 1, indicatorCount: 0 },
    sources: EMPTY_SOURCE,
    kloc: 10,
    handrolledClasses: 0,
    handrolledTotal: 0,
    ...over,
  };
}

describe("health scorecard — the #1305 per-dimension decomposition", () => {
  it("emits a row for every module M1–M10, in order, whatever ran", () => {
    const s = buildHealthScorecard(input());
    expect(s.dimensions.map((d) => d.module)).toEqual(["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"]);
  });

  it("gives every unassessed dimension a reason AND the tier that would answer it", () => {
    // The whole defect #1305 records is a scope limitation that is stated nowhere a reader looks. A
    // not-assessed row with no reason would reproduce it one level down.
    const unassessed = buildHealthScorecard(input()).dimensions.filter((d) => d.status === "not-assessed");
    expect(unassessed.length).toBeGreaterThan(0);
    for (const d of unassessed) {
      expect(d.reason, `${d.module} must say why`).toBeTruthy();
      expect(d.needs, `${d.module} must name the tier that answers it`).toBeTruthy();
      expect(d.grade, `${d.module} must not carry a letter it did not earn`).toBeUndefined();
    }
  });

  it("names the unrun modules in the scope sentence — the sentence that was missing from the rendered output", () => {
    const s = buildHealthScorecard(input());
    for (const m of s.unassessedModules) expect(s.scopeSentence).toContain(m);
    expect(s.scopeSentence).toContain("NOT run");
    expect(s.scopeSentence).toContain("NOT evidence");
  });

  it("composes the health grade from graded dimensions ONLY — an unrun module is never scored as clean", () => {
    // M4 absent (not measurable) must not pull the mean toward 100 or toward 0; it must be out of it.
    const withoutM4 = buildHealthScorecard(input({ duplicationGap: "jscpd unavailable" }));
    const graded = withoutM4.dimensions.filter((d) => d.status === "graded");
    expect(graded.map((d) => d.module)).not.toContain("M4");
    const mean = Math.round(graded.reduce((sum, d) => sum + (d.score ?? 0), 0) / graded.length);
    expect(withoutM4.score).toBe(mean);
    expect(withoutM4.composition).toContain(`${graded.length} graded dimension`);
  });

  it("weights every graded dimension equally — security is one dimension, not the subject", () => {
    // The correction's core claim. A catastrophic M1 must not be able to drive the whole health
    // grade to F on its own when four other dimensions are clean.
    const s = buildHealthScorecard(
      input({ m1: { grade: "F", score: 0, gradedCount: 40, indicatorCount: 3 }, duplication: { percentage: 0, duplicatedLines: 0, totalLines: 5000 } }),
    );
    const m1 = s.dimensions.find((d) => d.module === "M1")!;
    expect(m1.score).toBe(0);
    expect(s.score).toBeGreaterThan(60);
    expect(s.grade).not.toBe("F");
  });

  it("keeps a dimension's coverage-disclosure rows out of its defect count", () => {
    // A "— not assessed" row (confidence N/A) is a statement about what the detector could not read.
    // Counting it as a defect would penalise a target for Harvey's blind spot.
    const s = buildHealthScorecard(input({ kloc: 1 }));
    const m9 = s.dimensions.find((d) => d.module === "M9")!;
    expect(m9.status).toBe("graded");
    expect(m9.count).toBe(0);
  });

  it("grades M4 on the measured duplication percentage and prints the raw fact with it", () => {
    const s = buildHealthScorecard(input({ duplication: { percentage: 12, duplicatedLines: 1200, totalLines: 10000 } }));
    const m4 = s.dimensions.find((d) => d.module === "M4")!;
    expect(m4.status).toBe("graded");
    expect(m4.grade).toBe("D");
    expect(m4.measure).toContain("12%");
    expect(m4.scope).toContain("A ≤ 2%");
  });

  it("discloses WHY duplication was not measured rather than reporting a clean 0%", () => {
    const s = buildHealthScorecard(input({ duplicationGap: "the duplication pass did not complete within 60s and was stopped" }));
    const m4 = s.dimensions.find((d) => d.module === "M4")!;
    expect(m4.status).toBe("not-assessed");
    expect(m4.reason).toContain("did not complete within 60s");
    expect(m4.score).toBeUndefined();
  });

  it("reports M10 as a risk band, never a letter — protection is a live-database question", () => {
    const s = buildHealthScorecard(input({ pii: { tables: 4, columns: 19 } }));
    const m10 = s.dimensions.find((d) => d.module === "M10")!;
    expect(m10.status).toBe("risk-band");
    expect(m10.grade).toBeUndefined();
    expect(m10.band).toBeDefined();
    expect(m10.measure).toContain("4 table(s)");
    expect(s.gradedModules).not.toContain("M10");
  });

  it("tells 'no sensitive data' apart from 'no schema to read'", () => {
    const noSchema = buildHealthScorecard(input()).dimensions.find((d) => d.module === "M10")!;
    expect(noSchema.status).toBe("not-assessed");
    expect(noSchema.reason).toContain("No schema");

    const cleanSchema = buildHealthScorecard(input({ pii: { tables: 0, columns: 0 } })).dimensions.find((d) => d.module === "M10")!;
    expect(cleanSchema.status).toBe("risk-band");
    expect(cleanSchema.band).toBe("Low");
    expect(cleanSchema.measure).toContain("0 table(s)");
  });

  it("keeps M1's severity-weighted grade verbatim rather than re-grading it on density", () => {
    // #244/#996 pinned M1's curve (one verified Critical is an F). The scorecard must not quietly
    // re-scale it — that would silently retire promises other tests hold.
    const m1 = buildHealthScorecard(input({ m1: { grade: "F", score: 50, gradedCount: 1, indicatorCount: 0 } })).dimensions.find((d) => d.module === "M1")!;
    expect(m1.grade).toBe("F");
    expect(m1.score).toBe(50);
    expect(m1.scope).toContain("one verified Critical is an F");
  });
});

describe("the shared grade curve", () => {
  it("puts density band edges exactly on the published letter boundaries", () => {
    expect(densityScore(0, 10)).toBe(100);
    expect(densityScore(10, 10)).toBe(90); // 1.0 per kloc — the A/B edge
    expect(densityScore(25, 10)).toBe(80); // 2.5 — B/C
    expect(densityScore(50, 10)).toBe(70); // 5.0 — C/D
    expect(densityScore(100, 10)).toBe(60); // 10.0 — D/F
    expect(densityScore(200, 10)).toBeLessThan(60);
  });

  it("puts duplication band edges on the same boundaries and floors at zero", () => {
    expect(duplicationScore(0)).toBe(100);
    expect(duplicationScore(2)).toBe(90);
    expect(duplicationScore(5)).toBe(80);
    expect(duplicationScore(20)).toBe(60);
    expect(duplicationScore(100)).toBe(0);
  });

  it("cannot score an empty codebase as failing", () => {
    expect(densityScore(0, 0)).toBe(100);
  });
});

describe("M8 — 'no tests' is itself a gradable finding (the correction's third bullet)", () => {
  const withTests = [...EMPTY_SOURCE, { path: "app/page.test.tsx", text: "it('works', () => {});\n" }];

  it("grades a target with no test files at all as F, with no execution involved", () => {
    const m8 = buildHealthScorecard(input()).dimensions.find((d) => d.module === "M8")!;
    expect(m8.status).toBe("graded");
    expect(m8.grade).toBe("F");
    expect(m8.score).toBe(0);
    expect(m8.measure).toContain("no test or spec files found");
  });

  it("calls out a declared test script with nothing behind it — the loudest form of it", () => {
    const m8 = buildHealthScorecard(input({ testRunnerDeclared: true })).dimensions.find((d) => d.module === "M8")!;
    expect(m8.measure).toContain("despite a test script being declared");
    expect(m8.score).toBe(0);
  });

  it("reports PRESENT tests as an indicator, never a letter — existing is not passing", () => {
    // The over-reach this tier exists to avoid: a letter here would read as a quality verdict on a
    // suite nobody ran. Presence is a fact; quality is a connected-tier claim.
    const m8 = buildHealthScorecard(input({ sources: withTests })).dimensions.find((d) => d.module === "M8")!;
    expect(m8.status).toBe("indicator-only");
    expect(m8.grade).toBeUndefined();
    expect(m8.measure).toContain("1 test/spec file(s)");
    expect(m8.scope).toContain("not a statement that they pass");
  });

  it("puts a no-tests F into the composition, and an indicator out of it", () => {
    expect(buildHealthScorecard(input()).gradedModules).toContain("M8");
    expect(buildHealthScorecard(input({ sources: withTests })).gradedModules).not.toContain("M8");
  });
});

describe("the product/test split — the scorecard owns it so no caller can get it wrong", () => {
  it("keeps test files out of the M5/M7/M9 densities while counting them for M8", () => {
    // Every other consumer of these detectors filters NON_PRODUCT first (src/cli/static-detect.ts,
    // detector-rerun.ts, handrolled-frequency.ts). A finding in a test file is not an audit finding,
    // so grading a target on its own tests would both inflate the count and punish having tests.
    const slopInTest = "export function f(a) { return 1; }\n".repeat(3);
    const onlyTests = [{ path: "app/thing.test.ts", text: slopInTest }];
    const s = buildHealthScorecard(input({ sources: onlyTests, kloc: 0.1 }));
    for (const m of ["M5", "M7", "M9"]) {
      expect(s.dimensions.find((d) => d.module === m)!.count, `${m} counted a test file`).toBe(0);
    }
    expect(s.dimensions.find((d) => d.module === "M8")!.status).toBe("indicator-only");
  });
});

// ── Operator ruling 2026-07-28 (a): M10 is a Low/Medium/High/Critical EXPOSURE band ────────────
const band = (severity: string, over: Partial<PiiTableBand> = {}): PiiTableBand => ({
  table: `t_${severity}`,
  severity,
  categories: ["PII"],
  columns: 3,
  ...over,
});

describe("M10 risk band — exposure surface, never a protection verdict", () => {
  it("takes the highest per-table sensitivity as the band", () => {
    expect(riskBandOf({ tables: 2, columns: 6, tableBands: [band("Low"), band("High")] }).band).toBe("High");
    expect(riskBandOf({ tables: 2, columns: 6, tableBands: [band("Low"), band("Medium")] }).band).toBe("Medium");
  });

  it("raises the band one step on volume — the operator's third named input", () => {
    const bands = Array.from({ length: 12 }, (_, i) => band("Medium", { table: `t${i}` }));
    const r = riskBandOf({ tables: 12, columns: 36, tableBands: bands });
    expect(r.band).toBe("High");
    expect(r.derivation).toContain("raises the band one step");
  });

  it("never escalates past Critical, and says so truthfully instead of claiming the volume was low", () => {
    // The bug this pins: an at-ceiling band took the "below the threshold" branch and printed a
    // sentence that was simply false about the target's own table count.
    const bands = Array.from({ length: 18 }, (_, i) => band(i === 0 ? "Critical" : "Low", { table: `t${i}` }));
    const r = riskBandOf({ tables: 18, columns: 40, tableBands: bands });
    expect(r.band).toBe("Critical");
    expect(r.derivation).toContain("at or above the 10-table volume threshold");
    expect(r.derivation).not.toContain("below the 10-table volume threshold");
  });

  it("rates a schema with no classified columns Low, and says why", () => {
    const r = riskBandOf({ tables: 0, columns: 40, tableBands: [] });
    expect(r.band).toBe("Low");
    expect(r.derivation).toContain("No table in your schema");
  });

  it("states in the output what the band does NOT mean", () => {
    // A client must not read `Critical` as "you have been breached" or `Low` as "your PII is safe".
    const m10 = buildHealthScorecard(input({ pii: { tables: 3, columns: 9, tableBands: [band("Critical")] } })).dimensions.find((d) => d.module === "M10")!;
    expect(m10.bandCaveat).toContain("NOT a statement that your data has been");
    expect(m10.bandCaveat).toContain("NOT a verdict on your access controls");
    expect(m10.bandCaveat).toMatch(/`Low` band does NOT mean your data is protected/);
    expect(m10.bandDerivation).toBeTruthy();
  });

  it("sits beside the letter grades and is never averaged into them", () => {
    const clean = buildHealthScorecard(input({ duplication: { percentage: 0, duplicatedLines: 0, totalLines: 9000 } }));
    const withCritical = buildHealthScorecard(
      input({ duplication: { percentage: 0, duplicatedLines: 0, totalLines: 9000 }, pii: { tables: 3, columns: 9, tableBands: [band("Critical")] } }),
    );
    expect(withCritical.dimensions.find((d) => d.module === "M10")!.band).toBe("Critical");
    expect(withCritical.score).toBe(clean.score); // a Critical band moved the composite by nothing
    expect(withCritical.gradedModules).not.toContain("M10");
    expect(withCritical.scopeSentence).toContain("Critical data-exposure rating");
  });
});

// ── Operator ruling 2026-07-28 (b): 5 examples per dimension, as a DISCLOSED rollup ────────────
const f = (taxonomy: string, location: string): Finding => ({
  id: `${taxonomy}-${location}`, title: `${taxonomy} title`, severity: "Low", confidence: "Confirmed",
  category: "c", taxonomy, location, status: "Open", evidence: "e", impact: "i", fix: "x",
  value: 1, ease: 1, safety: 1,
});

describe("the evidence cap is a DISCLOSED ROLLUP, not a truncation", () => {
  const many = [
    ...Array.from({ length: 23 }, (_, i) => f("shape-a", `a${i}.ts:1`)),
    ...Array.from({ length: 10 }, (_, i) => f("shape-b", `b${i}.ts:1`)),
    ...Array.from({ length: 6 }, (_, i) => f(`shape-c${i}`, `c${i}.ts:1`)),
    ...Array.from({ length: 8 }, (_, i) => f(`shape-d${i}`, `d${i}.ts:1`)),
  ];

  it("shows at most 5 shapes but reports the TRUE totals beside them", () => {
    const r = rollupExamples(many);
    expect(r.examples).toHaveLength(EXAMPLES_SHOWN);
    expect(r.totalFindings).toBe(47); // 23 + 10 + 6 + 8 — the real number, not the shown one
    expect(r.totalShapes).toBe(16);
    expect(r.capped).toBe(true);
    expect(r.hiddenShapes + r.examples.length).toBe(r.totalShapes);
    expect(r.hiddenFindings + r.examples.reduce((sum, e) => sum + e.occurrences, 0)).toBe(r.totalFindings);
  });

  it("collapses duplicates to ONE row carrying its real count", () => {
    const r = rollupExamples(many);
    const a = r.examples.find((e) => e.shape === "shape-a")!;
    expect(a.occurrences).toBe(23); // not 1, and not 5
    expect(r.examples.filter((e) => e.shape === "shape-a")).toHaveLength(1);
  });

  it("says it is showing everything when there is nothing to hide, rather than padding", () => {
    const r = rollupExamples([f("only", "x.ts:1"), f("only", "y.ts:2")]);
    expect(r.capped).toBe(false);
    expect(r.totalShapes).toBe(1);
    expect(r.hiddenShapes).toBe(0);
    expect(r.examples[0]!.occurrences).toBe(2);
  });

  it("orders by frequency so the cap keeps the shapes that matter most, deterministically", () => {
    expect(rollupExamples(many).examples.map((e) => e.occurrences)).toEqual([23, 10, 1, 1, 1]);
    expect(rollupExamples([...many].reverse()).examples.map((e) => e.shape)).toEqual(rollupExamples(many).examples.map((e) => e.shape));
  });

  it("GRADES ON THE FULL SET, never on the five shown rows — the easiest way to get this wrong", () => {
    // 47 findings in 1k lines is F-territory; the same dimension scored on the 5 SHOWN rows would
    // read as an A. If these two ever agree, the grade has started following the truncated view.
    const dim = buildHealthScorecard(input({ m1: { grade: "A", score: 100, gradedCount: 47, indicatorCount: 0, findings: many } })).dimensions.find(
      (d) => d.module === "M1",
    )!;
    expect(dim.evidence!.totalFindings).toBe(47);
    expect(dim.evidence!.examples).toHaveLength(EXAMPLES_SHOWN);
    // M1's own grade is passed through verbatim, so assert the density path directly too:
    expect(densityScore(47, 1)).toBeLessThan(densityScore(EXAMPLES_SHOWN, 1));
    expect(densityScore(47, 1)).toBeLessThan(60);
  });

  it("fails if the cap is ever applied silently — the true total must survive into the row", () => {
    // The regression this exists for: someone slices the list and the totals slice with it, so the
    // report says "5 findings" when 47 exist. That reads as a clean bill of health.
    const dim = buildHealthScorecard(input({ m1: { grade: "F", score: 0, gradedCount: 47, indicatorCount: 0, findings: many } })).dimensions.find(
      (d) => d.module === "M1",
    )!;
    const e = dim.evidence!;
    expect(e.totalFindings).toBeGreaterThan(e.examples.length);
    expect(e.totalShapes).toBeGreaterThan(e.examples.length);
    expect(e.capped).toBe(true);
    expect(e.hiddenFindings).toBeGreaterThan(0);
  });

  it("caps M5/M7/M9 the same way, from the same full set the density was computed on", () => {
    const slop = Array.from({ length: 30 }, (_, i) => ({ path: `lib/f${i}.ts`, text: "export function g(a) { return 1; }\n" }));
    const s = buildHealthScorecard(input({ sources: slop, kloc: 1 }));
    for (const m of ["M5", "M7", "M9"]) {
      const d = s.dimensions.find((x) => x.module === m)!;
      expect(d.evidence, `${m} must disclose its evidence rollup`).toBeDefined();
      expect(d.evidence!.examples.length).toBeLessThanOrEqual(EXAMPLES_SHOWN);
      expect(d.evidence!.totalFindings).toBe(d.count);
    }
  });
});
