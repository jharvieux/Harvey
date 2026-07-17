import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { validateFindings } from "./findings.js";
import {
  lighthouseUnavailableFinding,
  parseLighthouseFindings,
  type LighthouseResult,
} from "./lighthouse.js";

// A real-schema (trimmed) Lighthouse result: poor LCP (4.8s), poor TBT (720ms), needs-improvement
// CLS (0.24), performance score 0.42. Mirrors what the lighthouse Node API returns as `.lhr`.
const poor: LighthouseResult = JSON.parse(
  readFileSync(new URL("./__fixtures__/lighthouse-report.json", import.meta.url), "utf8"),
) as LighthouseResult;

const good: LighthouseResult = {
  finalDisplayedUrl: "http://localhost:3000/",
  categories: { performance: { score: 0.97 } },
  audits: {
    "largest-contentful-paint": { numericValue: 1800 },
    "total-blocking-time": { numericValue: 90 },
    "cumulative-layout-shift": { numericValue: 0.02 },
  },
};

describe("parseLighthouseFindings", () => {
  it("emits one finding per failing metric plus the overall score, ids M7L-01… in order", () => {
    const findings = parseLighthouseFindings([{ route: "/dashboard", result: poor }]);
    expect(findings.map((f) => f.taxonomy)).toEqual([
      'M7 — LCP over Core Web Vitals "Good" threshold',
      'M7 — TBT over Core Web Vitals "Good" threshold',
      'M7 — CLS over Core Web Vitals "Good" threshold',
      "M7 — Lighthouse performance score below Good",
    ]);
    expect(findings.map((f) => f.id)).toEqual(["M7L-01", "M7L-02", "M7L-03", "M7L-04"]);
  });

  it("scores a Poor-bucket metric as Perf and a needs-improvement one as Low", () => {
    const findings = parseLighthouseFindings([{ route: "/dashboard", result: poor }]);
    const byTax = (t: string) => findings.find((f) => f.taxonomy.startsWith(t));
    expect(byTax("M7 — LCP")?.severity).toBe("Perf"); // 4.8s ≥ 4.0s poorMin
    expect(byTax("M7 — TBT")?.severity).toBe("Perf"); // 720ms ≥ 600ms poorMin
    expect(byTax("M7 — CLS")?.severity).toBe("Low"); // 0.24 > 0.1 good but < 0.25 poorMin
    expect(byTax("M7 — Lighthouse performance score")?.severity).toBe("Perf"); // 0.42 < 0.5 poor
  });

  it("produces no findings when every metric is within Google's Good thresholds", () => {
    expect(parseLighthouseFindings([{ route: "/", result: good }])).toEqual([]);
  });

  it("does not flag a metric exactly at the Good threshold (strict >)", () => {
    const atThreshold: LighthouseResult = {
      categories: { performance: { score: 0.9 } },
      audits: { "largest-contentful-paint": { numericValue: 2500 }, "cumulative-layout-shift": { numericValue: 0.1 } },
    };
    expect(parseLighthouseFindings([{ route: "/", result: atThreshold }])).toEqual([]);
  });

  it("groups a metric across pages worst-first, with the failing-page count in the title", () => {
    const other: LighthouseResult = {
      finalDisplayedUrl: "http://localhost:3000/settings",
      audits: { "largest-contentful-paint": { numericValue: 3200 } },
    };
    const findings = parseLighthouseFindings([
      { route: "/settings", result: other }, // LCP 3.2s
      { route: "/dashboard", result: poor }, // LCP 4.8s — worse
    ]);
    const lcp = findings.find((f) => f.taxonomy.startsWith("M7 — LCP"));
    expect(lcp?.title).toContain("2 pages");
    expect(lcp?.location).toBe("/dashboard"); // worst page
    expect(lcp?.evidence.indexOf("/dashboard")).toBeLessThan(lcp!.evidence.indexOf("/settings"));
  });

  it("skips metrics a run did not record rather than treating a missing audit as 0", () => {
    const partial: LighthouseResult = { audits: { "largest-contentful-paint": { numericValue: 5000 } } };
    const findings = parseLighthouseFindings([{ route: "/", result: partial }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.taxonomy).toContain("LCP");
  });

  it("emits schema-valid findings", () => {
    const findings = parseLighthouseFindings([{ route: "/dashboard", result: poor }]);
    const doc = { meta: validMeta(), findings };
    expect(validateFindings(doc).errors).toEqual([]);
  });
});

describe("lighthouseUnavailableFinding", () => {
  it("records the reason as a fail-loud disclosure finding, not a silent skip", () => {
    const f = lighthouseUnavailableFinding("next build failed: exit 1");
    expect(f.taxonomy).toBe("M7 — Core Web Vitals not measured");
    expect(f.evidence).toContain("next build failed: exit 1");
    expect(f.confidence).toBe("N/A");
    expect(validateFindings({ meta: validMeta(), findings: [f] }).errors).toEqual([]);
  });
});

function validMeta() {
  return {
    client: "t", subtitle: "t", date: "t", commit: "t", auditor: "t", confidential: true,
    overallHealth: 5, tenantIsolation: "t", authModel: "t", headline: "t", scope: "t",
    methodology: "t", outOfScope: "t",
  };
}
