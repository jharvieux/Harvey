import { describe, expect, it } from "vitest";
import { buildHealthScorecard, densityScore, duplicationScore, type ScorecardInput } from "./health-scorecard.js";

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

  it("reports M10 as an inventory, never a letter — protection is a live-database question", () => {
    const s = buildHealthScorecard(input({ pii: { tables: 4, columns: 19 } }));
    const m10 = s.dimensions.find((d) => d.module === "M10")!;
    expect(m10.status).toBe("indicator-only");
    expect(m10.grade).toBeUndefined();
    expect(m10.measure).toContain("4 table(s)");
    expect(s.gradedModules).not.toContain("M10");
  });

  it("tells 'no sensitive data' apart from 'no schema to read'", () => {
    const noSchema = buildHealthScorecard(input()).dimensions.find((d) => d.module === "M10")!;
    expect(noSchema.status).toBe("not-assessed");
    expect(noSchema.reason).toContain("No schema");

    const cleanSchema = buildHealthScorecard(input({ pii: { tables: 0, columns: 0 } })).dimensions.find((d) => d.module === "M10")!;
    expect(cleanSchema.status).toBe("indicator-only");
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
