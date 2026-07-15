import { describe, expect, it } from "vitest";
import type { Finding, PrecisionTier, Severity } from "./findings.js";
import { mechanicalFinding } from "./scan/common.js";
import { buildQuickScanReport, computeGrade, pickSample, selectFreeFindings, selectGradedFindings, selectIndicators } from "./quick-scan.js";

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

// #213/#227 — the free grade must reflect what we can actually stand behind. A dependency version
// falling in a CVE range is an exact match on the version, not proof of a vulnerability.
const cve = (id: string, severity: Severity): Finding => finding(id, severity, "high", { category: "Dependency CVE" });

describe("dependency-CVE version matches do not drive the grade (#213)", () => {
  it("excludes them from the graded set while keeping the verified-secret finding", () => {
    const graded = selectGradedFindings([cve("dep", "Critical"), finding("secret", "Low", "high")]);
    expect(graded.map((f) => f.id)).toEqual(["secret"]);
  });

  it("two CVE 'Criticals' and a High cannot produce an F — the sweep's exact inversion", () => {
    // supabase-multi-tenant-starter's free report: F (0/100) on 2 Critical + 1 High, all
    // next@14.2.0 version matches, while its real cross-tenant Critical went unmentioned.
    const report = buildQuickScanReport([cve("c1", "Critical"), cve("c2", "Critical"), cve("h1", "High")]);
    expect(report.grade).toBe("A");
    expect(report.score).toBe(100);
    expect(report.total).toBe(0);
    expect(report.countsBySeverity.Critical).toBe(0);
  });

  it("reports them in full rather than hiding them — seen, located, just not graded", () => {
    const report = buildQuickScanReport([cve("dep", "Critical")]);
    expect(report.informational.map((f) => f.id)).toEqual(["dep"]);
    expect(report.informational[0]?.location).toBe("src/dep.ts:1");
  });

  it("keeps the remediation gated on a CVE like any other finding, and revealed on unlock", () => {
    expect(buildQuickScanReport([cve("dep", "Critical")]).informational[0]?.fix).toBeUndefined();
    expect(buildQuickScanReport([cve("dep", "Critical")], { unlocked: true }).informational[0]?.fix).toBe("fix dep");
  });

  it("never picks an ungraded CVE as the teaser over a real graded finding", () => {
    const report = buildQuickScanReport([cve("aaa-dep", "Critical"), finding("zzz-secret", "Low", "high")]);
    expect(report.sample?.id).toBe("zzz-secret"); // Critical CVE loses to a graded Low
  });

  it("a real Critical still fails the repo — the grade is not simply defanged", () => {
    expect(buildQuickScanReport([finding("srv-key", "Critical", "high")]).grade).toBe("F");
  });
});

// #260 — the category exclusion is a default, not the actual test. A finding that carries its own
// confirmed-exploitability claim grades despite living in a non-grading category.
describe("exploitabilityVerified overrides the category default (#260)", () => {
  it("a Dependency CVE finding marked exploitabilityVerified grades like any other", () => {
    const verified = cve("confirmed-rce", "Critical");
    verified.exploitabilityVerified = true;
    const graded = selectGradedFindings([verified, cve("dep", "Critical")]);
    expect(graded.map((f) => f.id)).toEqual(["confirmed-rce"]);
  });

  it("moves the grade and can be picked as the teaser once verified", () => {
    const verified = cve("confirmed-rce", "Critical");
    verified.exploitabilityVerified = true;
    const report = buildQuickScanReport([verified]);
    expect(report.grade).toBe("F");
    expect(report.total).toBe(1);
    expect(report.sample?.id).toBe("confirmed-rce");
  });

  it("an unmarked CVE in the same batch stays informational, not graded", () => {
    const verified = cve("confirmed-rce", "Critical");
    verified.exploitabilityVerified = true;
    const report = buildQuickScanReport([verified, cve("still-just-a-match", "Critical")]);
    expect(report.total).toBe(1);
    expect(report.informational.map((f) => f.id)).toEqual(["still-just-a-match"]);
  });
});

// #220/#227 — source-tier tenant-isolation signals. Silence about a probable cross-tenant hole
// is the worse failure, so these surface loudly; but static shape isn't proof, so they never grade.
const indicator = (id: string): Finding => finding(id, "Critical", "review", { category: "Multi-tenant security" });

describe("RLS/authz indicators are surfaced but never graded (#220)", () => {
  it("selects review-tier multi-tenant findings, leaving other review noise out", () => {
    const picked = selectIndicators([indicator("rls"), finding("noise", "Critical", "review", { category: "Leftover auth" })]);
    expect(picked.map((f) => f.id)).toEqual(["rls"]);
  });

  it("a Critical indicator does not move the grade, and is not the teaser", () => {
    const report = buildQuickScanReport([indicator("rls"), finding("dep", "Low", "high")]);
    expect(report.grade).toBe("A");
    expect(report.total).toBe(1);
    expect(report.indicators.map((f) => f.id)).toEqual(["rls"]);
    expect(report.sample?.id).toBe("dep");
  });

  it("is not silently swept into the 'excluded signals' tally — it's shown, not withheld", () => {
    const report = buildQuickScanReport([indicator("rls"), finding("other", "High", "review", { category: "Leftover auth" })]);
    expect(report.indicators).toHaveLength(1);
    expect(report.reviewTierExcluded).toBe(1); // the leftover-auth noise only
  });
});

describe("two-part headline — grade never travels as a security verdict (#227)", () => {
  it("annotates even a clean A with its scope and the risk disclosure", () => {
    const report = buildQuickScanReport([]);
    expect(report.grade).toBe("A");
    expect(report.gradeScope).toContain("hygiene only");
    expect(report.riskDisclosure).toContain("NOT assessed");
  });

  it("the calibration invariant: a sound repo's grade stays clean while a real Critical is still raised loudly", () => {
    // #227's corpus check — the free output must never contradict the deep-scan verdict.
    const sound = buildQuickScanReport([cve("next-cve", "Critical")]);
    expect(sound.grade).not.toBe("F");
    expect(sound.indicators).toEqual([]);

    const risky = buildQuickScanReport([cve("next-cve", "Critical"), indicator("self-join")]);
    expect(risky.indicators).toHaveLength(1);
    expect(risky.gradeScope).toContain("deep scan");
    expect(risky.riskDisclosure).toContain("indicators");
  });
});
