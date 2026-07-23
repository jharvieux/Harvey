// Corpus aggregation over synthetic engagement documents (#726). Proves the two load-bearing
// disciplines hold: anonymization (no client identity leaks into the summary) and the honest
// denominator (a module-gated stat counts only apps whose ledger shows that module ran).

import { describe, expect, it } from "vitest";
import type { CoverageRow, Finding, FindingsDocument, Severity } from "./findings.js";
import { aggregateCorpus, type CorpusSummary, renderSummaryText } from "./corpus-aggregate.js";

function finding(severity: Severity, taxonomy: string, title = "t"): Finding {
  return {
    id: "F-01",
    title,
    severity,
    confidence: "Confirmed",
    category: "General",
    taxonomy,
    location: "x.ts",
    status: "open",
    evidence: "e",
    impact: "i",
    fix: "f",
    value: 3,
    ease: 3,
    safety: 3,
  };
}

function m1Ran(): CoverageRow[] {
  return [{ module: "M1", name: "Multi-tenant security", status: "ran" }];
}

function m1NotRun(): CoverageRow[] {
  return [{ module: "M1", name: "Multi-tenant security", status: "requires-live-run", reason: "no connected DB" }];
}

function doc(client: string, findings: Finding[], coverage?: CoverageRow[]): FindingsDocument {
  return {
    meta: {
      client,
      subtitle: "",
      date: "",
      commit: "",
      auditor: "",
      confidential: true,
      overallHealth: 5,
      tenantIsolation: "",
      authModel: "",
      headline: "",
      scope: "",
      methodology: "",
      outOfScope: "",
    },
    findings,
    coverage,
  };
}

describe("aggregateCorpus", () => {
  it("counts apps with a Critical/High finding over the whole corpus", () => {
    const s: CorpusSummary = aggregateCorpus([
      doc("acme", [finding("Critical", "auth_rls_initplan")], m1Ran()),
      doc("beta", [finding("Low", "M5 — Unused import")], m1Ran()),
      doc("gamma", [finding("High", "IDOR")], m1Ran()),
    ]);
    const stat = s.stats.find((x) => x.key === "high_severity")!;
    expect(stat.numerator).toBe(2);
    expect(stat.denominator).toBe(3);
    expect(stat.pct).toBe(67);
  });

  it("gates the cross-tenant stat's denominator on M1 having run", () => {
    const s = aggregateCorpus([
      doc("acme", [finding("Critical", "Cross-tenant read via RLS")], m1Ran()), // counts, M1 ran
      doc("beta", [finding("Critical", "Cross-tenant read via RLS")], m1NotRun()), // excluded: M1 not run
      doc("gamma", [finding("Low", "M5 — Unused import")], m1Ran()), // M1 ran, no cross-tenant
    ]);
    const stat = s.stats.find((x) => x.key === "cross_tenant_exposure")!;
    expect(stat.denominator).toBe(2); // only the two apps where M1 ran
    expect(stat.numerator).toBe(1);
    expect(stat.pct).toBe(50);
    expect(stat.gatedBy).toBe("M1");
  });

  it("a Critical finding that is NOT tenant-isolation does not count as cross-tenant", () => {
    const s = aggregateCorpus([doc("acme", [finding("Critical", "Known-vulnerable dependency")], m1Ran())]);
    expect(s.stats.find((x) => x.key === "cross_tenant_exposure")!.numerator).toBe(0);
  });

  it("excludes ledger-less apps from module-gated denominators and says so in a caveat", () => {
    const s = aggregateCorpus([
      doc("acme", [finding("Critical", "Cross-tenant RLS")], m1Ran()),
      doc("beta", [finding("Critical", "Cross-tenant RLS")]), // no coverage ledger
    ]);
    const stat = s.stats.find((x) => x.key === "cross_tenant_exposure")!;
    expect(stat.denominator).toBe(1);
    expect(s.caveats.some((c) => c.includes("no coverage ledger"))).toBe(true);
    // ...but both apps still count in the whole-corpus severity totals.
    expect(s.severityTotals.Critical).toBe(2);
  });

  it("reports null pct (never divide-by-zero) when M1 ran on no app", () => {
    const s = aggregateCorpus([doc("acme", [finding("Critical", "Cross-tenant RLS")], m1NotRun())]);
    const stat = s.stats.find((x) => x.key === "cross_tenant_exposure")!;
    expect(stat.denominator).toBe(0);
    expect(stat.pct).toBeNull();
    expect(stat.headline).toContain("not computable");
  });

  it("ranks the most prevalent finding classes by number of apps affected", () => {
    const s = aggregateCorpus([
      doc("a", [finding("High", "IDOR"), finding("Low", "Dead code")], m1Ran()),
      doc("b", [finding("High", "IDOR")], m1Ran()),
      doc("c", [finding("High", "IDOR"), finding("Low", "Dead code")], m1Ran()),
    ]);
    expect(s.topTaxonomies[0]).toEqual({ taxonomy: "IDOR", apps: 3 });
  });

  it("computes module coverage across the corpus", () => {
    const s = aggregateCorpus([
      doc("a", [], m1Ran()),
      doc("b", [], m1NotRun()),
    ]);
    const m1 = s.moduleCoverage.find((m) => m.module === "M1")!;
    expect(m1.appsRan).toBe(1);
    expect(m1.appsTotal).toBe(2);
    expect(s.moduleCoverage).toHaveLength(10);
  });
});

describe("anonymization", () => {
  it("never carries a client name into the summary or its rendered text", () => {
    const s = aggregateCorpus([doc("SecretClientName Inc", [finding("Critical", "Cross-tenant RLS")], m1Ran())]);
    const serialized = JSON.stringify(s) + renderSummaryText(s);
    expect(serialized).not.toContain("SecretClientName");
    expect(s.anonymized).toBe(true);
  });
});

describe("renderSummaryText", () => {
  it("emits headline stats and the disclosure gate reminder", () => {
    const s = aggregateCorpus([doc("a", [finding("Critical", "Cross-tenant RLS")], m1Ran())], {
      now: new Date("2026-07-22T00:00:00Z"),
    });
    const text = renderSummaryText(s);
    expect(text).toContain("Headline statistics");
    expect(text).toContain("responsible disclosure");
    expect(text).toContain("2026-07-22");
  });
});
