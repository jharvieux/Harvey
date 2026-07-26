import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { validateFindings } from "./findings.js";
import {
  lighthouseRunErrorReason,
  lighthouseScopeDisclosureFinding,
  lighthouseUnavailableFinding,
  parseLighthouseFindings,
  serveCommand,
  type LighthouseResult,
} from "./lighthouse.js";

// REAL Lighthouse 13.4.0 capture (live run, 2026-07-26, #1130) — poor LCP (4.7s), poor TBT
// (3,150ms), poor CLS (0.595), performance score 0.32. Replaced the prior hand-written synthetic
// fixture (the highest-risk #1063 row in FIXTURE-INVENTORY.md); see the fixture's own _note for
// how it was captured. Every value below is byte-for-byte as Lighthouse emitted it.
const poor: LighthouseResult = JSON.parse(
  readFileSync(new URL("./__fixtures__/lighthouse-report.json", import.meta.url), "utf8"),
) as LighthouseResult;

// REAL Lighthouse 13.4.0 capture (2026-07-25, NO_FCP on a blank page) — the only live-captured
// scoreDisplayMode:"error" audit shape available (#1074's acceptance criteria: not hand-written).
// See the fixture's own _note for provenance and why this is committed even though, under the
// current CLI, a page this broken never reaches parseLighthouseFindings (its category score is
// also null, so lighthouseRunErrorReason already catches it upstream).
const errored: LighthouseResult = JSON.parse(
  readFileSync(new URL("./__fixtures__/lighthouse-report-errored.json", import.meta.url), "utf8"),
) as LighthouseResult;

// REAL Lighthouse 13.4.0 capture (2026-07-25) of the unused-css-rules audit's details/metricSavings
// opportunity shape.
const opportunityAudit = JSON.parse(
  readFileSync(new URL("./__fixtures__/lighthouse-opportunity-audit.json", import.meta.url), "utf8"),
) as NonNullable<LighthouseResult["audits"]>[string];

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

  it("scores every Poor-bucket metric of the real capture as Perf", () => {
    const findings = parseLighthouseFindings([{ route: "/dashboard", result: poor }]);
    const byTax = (t: string) => findings.find((f) => f.taxonomy.startsWith(t));
    expect(byTax("M7 — LCP")?.severity).toBe("Perf"); // 4.7s ≥ 4.0s poorMin
    expect(byTax("M7 — TBT")?.severity).toBe("Perf"); // 3,150ms ≥ 600ms poorMin
    expect(byTax("M7 — CLS")?.severity).toBe("Perf"); // 0.595 ≥ 0.25 poorMin
    expect(byTax("M7 — Lighthouse performance score")?.severity).toBe("Perf"); // 0.32 < 0.5 poor
  });

  it("scores a needs-improvement metric (past Good, short of Poor) as Low", () => {
    const needsImprovement: LighthouseResult = {
      categories: { performance: { score: 0.7 } }, // < 0.9 good, ≥ 0.5 poor -> Low
      audits: { "cumulative-layout-shift": { numericValue: 0.15 } }, // > 0.1 good, < 0.25 poorMin -> Low
    };
    const findings = parseLighthouseFindings([{ route: "/", result: needsImprovement }]);
    expect(findings.find((f) => f.taxonomy.startsWith("M7 — CLS"))?.severity).toBe("Low");
    expect(findings.find((f) => f.taxonomy.startsWith("M7 — Lighthouse performance score"))?.severity).toBe("Low");
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

// #1074 point 1: an errored audit (scoreDisplayMode: "error", no numericValue) previously vanished
// through metricFinding's `typeof p.value === "number"` filter with no else branch — read as "no
// page failed this metric", i.e. a clean pass. It must instead surface as its own disclosure.
describe("parseLighthouseFindings — errored audit is disclosed, never read as a clean pass (#1074)", () => {
  it("does NOT return a clean [] when every metric audit on a page errored", () => {
    const findings = parseLighthouseFindings([{ route: "/", result: errored }]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it("emits a NOT-measured disclosure per metric, naming the Lighthouse error", () => {
    const findings = parseLighthouseFindings([{ route: "/", result: errored }]);
    const lcpNotMeasured = findings.find((f) => f.taxonomy === "M7 — LCP not measured (Lighthouse audit error)");
    expect(lcpNotMeasured).toBeDefined();
    expect(lcpNotMeasured?.confidence).toBe("N/A");
    expect(lcpNotMeasured?.evidence).toContain("NO_FCP");
    expect(lcpNotMeasured?.title).not.toMatch(/good|within/i); // never phrased as a pass
  });

  it("does not ALSO emit the ordinary threshold finding for a metric that errored (no numericValue to compare)", () => {
    const findings = parseLighthouseFindings([{ route: "/", result: errored }]);
    expect(findings.find((f) => f.taxonomy === 'M7 — LCP over Core Web Vitals "Good" threshold')).toBeUndefined();
  });

  it("still reports the ordinary threshold finding for a metric that erred on one page but genuinely failed on another", () => {
    const mixed = parseLighthouseFindings([
      { route: "/broken", result: errored },
      { route: "/dashboard", result: poor }, // LCP 4.8s, genuinely measured and failing
    ]);
    expect(mixed.find((f) => f.taxonomy === 'M7 — LCP over Core Web Vitals "Good" threshold')?.location).toBe("/dashboard");
    expect(mixed.find((f) => f.taxonomy === "M7 — LCP not measured (Lighthouse audit error)")?.location).toBe("/broken");
  });

  it("emits schema-valid findings for the errored-audit disclosure", () => {
    const findings = parseLighthouseFindings([{ route: "/", result: errored }]);
    expect(validateFindings({ meta: validMeta(), findings }).errors).toEqual([]);
  });
});

// #1074 point 2: Lighthouse's own runWarnings (redirect, extension interference, throttling
// disabled, unresponsive page) were discarded even under a "Confirmed" finding.
describe("parseLighthouseFindings — runWarnings surfaced in evidence (#1074)", () => {
  it("appends a page's run warnings to a metric finding that names that page", () => {
    const warned: LighthouseResult = {
      finalDisplayedUrl: "http://localhost:3000/dashboard",
      categories: { performance: { score: 0.42 } },
      audits: { "largest-contentful-paint": { numericValue: 4800 } },
      runWarnings: ["The page may not be loading as expected because your test URL (http://localhost:3000/dashboard) was redirected"],
    };
    const findings = parseLighthouseFindings([{ route: "/dashboard", result: warned }]);
    const lcp = findings.find((f) => f.taxonomy.startsWith("M7 — LCP"));
    expect(lcp?.evidence).toContain("redirected");
  });

  it("adds nothing when a page carries no run warnings (the real clean-run shape: [])", () => {
    const findings = parseLighthouseFindings([{ route: "/dashboard", result: poor }]);
    const lcp = findings.find((f) => f.taxonomy.startsWith("M7 — LCP"));
    expect(lcp?.evidence).not.toContain("run warnings");
  });
});

// #1074 point 3: the opportunity/remediation layer (audits[].details.items, .overallSavings*) named
// the specific offending resources; Harvey read none of it, so `fix` was always the same constant
// prose regardless of what Lighthouse actually found.
describe("parseLighthouseFindings — opportunity findings name Lighthouse's own resources (#1074)", () => {
  it("emits an opportunity finding carrying the real named resource and its savings", () => {
    const withOpportunity: LighthouseResult = {
      finalDisplayedUrl: "http://localhost:3000/",
      categories: { performance: { score: 0.9 } },
      audits: { "unused-css-rules": opportunityAudit },
    };
    const findings = parseLighthouseFindings([{ route: "/", result: withOpportunity }]);
    const opp = findings.find((f) => f.taxonomy === "M7 — Lighthouse opportunity: Unused CSS");
    expect(opp).toBeDefined();
    expect(opp?.evidence).toContain("big.css"); // the specific resource Lighthouse named
    expect(opp?.fix).toContain("big.css"); // fix text is the named resource, not boilerplate
    expect(opp?.confidence).toBe("Confirmed");
  });

  it("emits nothing for an opportunity audit with no items (nothing to fix)", () => {
    const clean: LighthouseResult = {
      categories: { performance: { score: 0.97 } },
      audits: { "unused-css-rules": { score: 1, scoreDisplayMode: "metricSavings", details: { type: "opportunity", items: [] } } },
    };
    expect(parseLighthouseFindings([{ route: "/", result: clean }]).find((f) => f.taxonomy.includes("opportunity"))).toBeUndefined();
  });
});

describe("lighthouseScopeDisclosureFinding (#1074 point 4 — onlyCategories: [\"performance\"] is undisclosed)", () => {
  it("names the three unassessed categories and is schema-valid", () => {
    const f = lighthouseScopeDisclosureFinding();
    expect(f.id).toBe("M7-SCOPE-00");
    expect(f.confidence).toBe("N/A");
    expect(f.evidence).toMatch(/accessibility/i);
    expect(f.evidence).toMatch(/best-practices/i);
    expect(f.evidence).toMatch(/SEO/i);
    expect(validateFindings({ meta: validMeta(), findings: [f] }).errors).toEqual([]);
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

describe("lighthouseRunErrorReason", () => {
  it("reports a runtimeError (NO_FCP) so the CLI discloses instead of reading it as clean", () => {
    const erroredRun: LighthouseResult = {
      categories: { performance: { score: null } },
      audits: {},
      runtimeError: { code: "NO_FCP", message: "The page did not paint any content." },
    };
    expect(lighthouseRunErrorReason(erroredRun)).toBe("NO_FCP — The page did not paint any content.");
  });

  it("reports a null/absent performance score as unmeasured", () => {
    expect(lighthouseRunErrorReason({ categories: { performance: { score: null } } })).toBe(
      "the run produced no performance score",
    );
    expect(lighthouseRunErrorReason({ audits: {} })).toBe("the run produced no performance score");
  });

  it("returns undefined for a genuinely measured run (numeric score)", () => {
    expect(lighthouseRunErrorReason(good)).toBeUndefined();
  });
});

describe("serveCommand (#577) — Vite has no `start`, its build is served by `vite preview`", () => {
  it("uses `npm run preview -- --port` for a Vite target", () => {
    expect(serveCommand("vite", 3000)).toEqual({
      args: ["run", "preview", "--", "--port", "3000"],
      label: "npm run preview -- --port 3000",
    });
  });

  it("uses `npm run start -- -p` for Next and for unknown/other targets", () => {
    expect(serveCommand("next", 4000).args).toEqual(["run", "start", "--", "-p", "4000"]);
    expect(serveCommand("other", 4000).args).toEqual(["run", "start", "--", "-p", "4000"]);
  });
});

function validMeta() {
  return {
    client: "t", subtitle: "t", date: "t", commit: "t", auditor: "t", confidential: true,
    overallHealth: 5, tenantIsolation: "t", authModel: "t", headline: "t", scope: "t",
    methodology: "t", outOfScope: "t",
  };
}
