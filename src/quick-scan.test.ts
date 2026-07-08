import { describe, expect, it } from "vitest";
import type { Finding, PrecisionTier, Severity } from "./findings.js";
import { mechanicalFinding } from "./scan/common.js";
import { buildQuickScanReport, computeGrade, pickSample, selectFreeFindings } from "./quick-scan.js";

function finding(id: string, severity: Severity, precisionTier: PrecisionTier, over: Partial<Finding> = {}): Finding {
  return {
    ...mechanicalFinding({
      id,
      title: `title ${id}`,
      severity,
      category: over.category ?? "Secret exposure",
      taxonomy: "t",
      location: `src/${id}.ts:1`,
      evidence: "e",
      impact: `risk ${id}`,
      fix: `fix ${id}`,
      precisionTier,
    }),
    ...over,
  };
}

describe("trust boundary — precision-tier gating", () => {
  it("keeps only high-precision findings out of a mixed set", () => {
    const findings = [finding("A", "Critical", "high"), finding("B", "High", "review")];
    expect(selectFreeFindings(findings).map((f) => f.id)).toEqual(["A"]);
  });

  it("a review-tier finding never reaches the free count, categories, or grade", () => {
    // One verified Low (score 97 → A) plus a heuristic 'Critical' that must be ignored.
    const report = buildQuickScanReport([
      finding("low", "Low", "high"),
      finding("noise", "Critical", "review", { category: "Leftover auth" }),
    ]);
    expect(report.total).toBe(1);
    expect(report.countsBySeverity.Critical).toBe(0);
    expect(report.categories).toEqual([{ category: "Secret exposure", count: 1 }]);
    expect(report.grade).toBe("A"); // the review 'Critical' did not tank the grade
    expect(report.reviewTierExcluded).toBe(1);
  });
});

describe("free/gated split", () => {
  const findings = [finding("A", "Critical", "high"), finding("B", "High", "high")];

  it("free (locked) withholds the fix for every finding except the teaser", () => {
    const report = buildQuickScanReport(findings);
    expect(report.locked).toBe(true);
    expect(report.findings.every((f) => f.fix === undefined)).toBe(true);
    expect(report.sample?.fix).toBe("fix A");
    expect(report.gated.length).toBeGreaterThan(0);
  });

  it("unlocked reveals the fix for every finding", () => {
    const report = buildQuickScanReport(findings, { unlocked: true });
    expect(report.locked).toBe(false);
    expect(report.findings.every((f) => typeof f.fix === "string")).toBe(true);
    expect(report.gated).toEqual([]);
  });

  it("never gates the location — every finding is located in the free path", () => {
    const report = buildQuickScanReport(findings);
    expect(report.findings.every((f) => f.location.length > 0)).toBe(true);
    expect(report.findings.map((f) => f.risk)).toEqual(["risk A", "risk B"]); // diagnosis shown
  });
});

describe("teaser selection", () => {
  it("reveals the most severe finding, deterministic id tiebreak", () => {
    const sample = pickSample([finding("z", "High", "high"), finding("a", "Critical", "high"), finding("m", "Critical", "high")]);
    expect(sample?.id).toBe("a"); // Critical over High; 'a' before 'm'
  });

  it("is null for a clean scan", () => {
    expect(pickSample([])).toBeNull();
  });
});

describe("grade computation", () => {
  it("clean scan is A / 100", () => {
    expect(computeGrade([])).toEqual({ grade: "A", score: 100 });
  });

  it("a single verified Critical fails the repo", () => {
    expect(computeGrade([finding("c", "Critical", "high")])).toEqual({ grade: "F", score: 50 });
  });

  it("one High is a B, two Highs a D", () => {
    expect(computeGrade([finding("h", "High", "high")]).grade).toBe("B");
    expect(computeGrade([finding("h1", "High", "high"), finding("h2", "High", "high")]).grade).toBe("D");
  });

  it("score floors at 0, never negative", () => {
    const many = Array.from({ length: 5 }, (_, i) => finding(`c${i}`, "Critical", "high"));
    expect(computeGrade(many)).toEqual({ grade: "F", score: 0 });
  });
});

describe("clean scan report", () => {
  it("has no findings, no teaser, grade A", () => {
    const report = buildQuickScanReport([finding("noise", "High", "review")]);
    expect(report.total).toBe(0);
    expect(report.sample).toBeNull();
    expect(report.grade).toBe("A");
    expect(report.reviewTierExcluded).toBe(1);
  });
});
