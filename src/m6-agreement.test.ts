import { describe, expect, it } from "vitest";
import {
  compareReviewerPasses,
  parseReviewerPass,
  renderAgreementReport,
  type ReviewerPass,
} from "./m6-agreement.js";

const passA: ReviewerPass = {
  reviewer: "reviewer-a",
  target: "targets/calibration/simplify",
  verdicts: [
    { file: "debounce.ts", verdict: "flag", replacement: "lodash-es debounce" },
    { file: "depdrop.ts", verdict: "spare", reason: "WHY comment records a deliberate dep-drop" },
    { file: "framework-adapter.ts", verdict: "spare", reason: "SupportedStorage contract" },
  ],
};

const passB: ReviewerPass = {
  reviewer: "reviewer-b",
  target: "targets/calibration/simplify",
  verdicts: [
    { file: "debounce.ts", verdict: "flag", replacement: "lodash-es debounce" },
    { file: "depdrop.ts", verdict: "spare" },
    { file: "framework-adapter.ts", verdict: "flag", confidence: "low", reason: "duplicates @supabase/ssr" },
    { file: "reconcile.ts", verdict: "spare" },
  ],
};

describe("parseReviewerPass", () => {
  it("round-trips a valid pass", () => {
    const parsed = parseReviewerPass(JSON.parse(JSON.stringify(passA)), "a.json");
    expect(parsed.reviewer).toBe("reviewer-a");
    expect(parsed.verdicts).toHaveLength(3);
    expect(parsed.verdicts[1]).toMatchObject({ file: "depdrop.ts", verdict: "spare" });
  });

  it("rejects an anonymous pass — independence is unprovable without a reviewer id", () => {
    expect(() => parseReviewerPass({ verdicts: passA.verdicts }, "a.json")).toThrow(/reviewer/);
  });

  it("rejects a verdict that is neither flag nor spare", () => {
    expect(() =>
      parseReviewerPass({ reviewer: "r", verdicts: [{ file: "x.ts", verdict: "maybe" }] }, "a.json"),
    ).toThrow(/"flag" or "spare"/);
  });

  it("rejects duplicate file rows — one verdict per file", () => {
    expect(() =>
      parseReviewerPass(
        { reviewer: "r", verdicts: [{ file: "x.ts", verdict: "flag" }, { file: "x.ts", verdict: "spare" }] },
        "a.json",
      ),
    ).toThrow(/more than once/);
  });

  it("rejects an empty verdict list rather than reporting vacuous agreement", () => {
    expect(() => parseReviewerPass({ reviewer: "r", verdicts: [] }, "a.json")).toThrow(/non-empty/);
  });
});

describe("compareReviewerPasses", () => {
  it("counts agreements and isolates the split for adjudication", () => {
    const report = compareReviewerPasses(passA, passB);
    expect(report.compared).toBe(3);
    expect(report.agreed).toBe(2);
    expect(report.bothFlag).toEqual(["debounce.ts"]);
    expect(report.bothSpare).toEqual(["depdrop.ts"]);
    expect(report.splits).toHaveLength(1);
    expect(report.splits[0]?.file).toBe("framework-adapter.ts");
    // The split carries BOTH reviewers' arguments — that is what the adjudicator triages.
    expect(report.splits[0]?.verdicts[0]?.reason).toMatch(/SupportedStorage/);
    expect(report.splits[0]?.verdicts[1]?.confidence).toBe("low");
  });

  it("lists a file reviewed by only one pass instead of silently dropping it", () => {
    const report = compareReviewerPasses(passA, passB);
    expect(report.onlyA).toEqual([]);
    expect(report.onlyB).toEqual(["reconcile.ts"]);
    // Uncompared files must never inflate the agreement rate.
    expect(report.compared + report.onlyB.length).toBe(passB.verdicts.length);
  });

  it("refuses a self-comparison — two passes with the same reviewer id are not independent", () => {
    expect(() => compareReviewerPasses(passA, { ...passB, reviewer: "reviewer-a" })).toThrow(/INDEPENDENT/);
  });

  it("refuses to compare passes over different targets", () => {
    expect(() => compareReviewerPasses(passA, { ...passB, target: "some/other/dir" })).toThrow(/different targets/);
  });
});

describe("renderAgreementReport", () => {
  it("states the measured rate, routes splits to a human, and forbids the precision framing", () => {
    const out = renderAgreementReport(compareReviewerPasses(passA, passB));
    expect(out).toContain("agreed 2/3");
    expect(out).toMatch(/human adjudicator/);
    expect(out).toContain("framework-adapter.ts");
    expect(out).toMatch(/never quote it as M6 precision/);
    expect(out).toMatch(/reconcile\.ts/); // the uncompared file is visible, not absent
  });

  it("says so explicitly when there are no splits", () => {
    const unanimous: ReviewerPass = { ...passB, verdicts: passB.verdicts.filter((v) => v.file !== "framework-adapter.ts") };
    const out = renderAgreementReport(compareReviewerPasses(passA, unanimous));
    expect(out).toMatch(/no splits/);
  });
});
