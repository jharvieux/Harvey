import { describe, expect, it } from "vitest";
import { type BugDetection, type GroundTruthBug, scoreCoverage, summarizeCoverage } from "./coverage-scorecard.js";

function bug(overrides: Partial<GroundTruthBug> & { detection: BugDetection | null }): GroundTruthBug {
  return {
    id: "TEST-BUG",
    severity: "High",
    location: "pages/api/test.js:1",
    expectedModule: "Semgrep",
    ...overrides,
  };
}

describe("scoreCoverage", () => {
  it("scores requires-live-run when the detecting tier didn't run (detection === null)", () => {
    const [scored] = scoreCoverage([bug({ id: "B1", detection: null })]);
    expect(scored!.status).toBe("requires-live-run");
    // Never guesses a verdict for a tier that didn't run — the note says so, not "missed".
    expect(scored!.note).toContain("did not execute");
  });

  it("scores caught when the caller's resolved detection says caught, carrying the note through", () => {
    const [scored] = scoreCoverage([bug({ id: "SQLI", detection: { caught: true, tier: "high", note: "via corpus P-SQLI-CONCAT" } })]);
    expect(scored!.status).toBe("caught");
    expect(scored!.note).toBe("via corpus P-SQLI-CONCAT");
  });

  it("scores missed when detection is resolved but not caught — the interesting case, not a crash", () => {
    const [scored] = scoreCoverage([bug({ id: "REPLAY", detection: { caught: false, note: "accepted no-rule gap" } })]);
    expect(scored!.status).toBe("missed");
    expect(scored!.note).toBe("accepted no-rule gap");
  });

  // #342: the matched finding's tier rides through onto the ScoredBug so a high-precision assert and
  // a review-tier surfacing are distinguishable in the scorecard without reading prose.
  it("records the detection tier — high asserts, review is surfaced for a human", () => {
    const asserted = scoreCoverage([bug({ id: "SQLI", detection: { caught: true, tier: "high", note: "x" } })])[0]!;
    expect(asserted.tier).toBe("high");

    const surfaced = scoreCoverage([bug({ id: "RLS-AUTH-ROLE", detection: { caught: true, tier: "review", note: "x" } })])[0]!;
    expect(surfaced.status).toBe("caught");
    expect(surfaced.tier).toBe("review");
  });
});

describe("summarizeCoverage", () => {
  it("splits caught into asserted vs surfaced-for-review so a review catch is never a claimed verdict (#342)", () => {
    const scored = scoreCoverage([
      bug({ id: "A", detection: null }),
      bug({ id: "B", detection: { caught: false, note: "missed" } }),
      bug({ id: "C-HIGH", detection: { caught: true, tier: "high", note: "asserted" } }),
      bug({ id: "D-REVIEW", detection: { caught: true, tier: "review", note: "surfaced" } }),
    ]);
    expect(summarizeCoverage(scored)).toEqual({
      asserted: 1,
      "surfaced-for-review": 1,
      missed: 1,
      "requires-live-run": 1,
    });
  });

  it("counts an untiered catch as surfaced-for-review, never asserted — the conservative direction", () => {
    const scored = scoreCoverage([bug({ id: "U", detection: { caught: true, note: "untiered" } })]);
    expect(summarizeCoverage(scored)).toEqual({ asserted: 0, "surfaced-for-review": 1, missed: 0, "requires-live-run": 0 });
  });
});
