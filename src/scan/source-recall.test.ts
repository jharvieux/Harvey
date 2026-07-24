import { describe, expect, it } from "vitest";
import { CORPUS, mechanicalCorpus } from "./calibration.js";
import { SOURCE_TIER_IDS, assertSourceTierResolvable, scoreSourceRecall, sourceTierCorpus } from "./source-recall.js";
import type { Finding } from "../findings.js";

// The live 38/39 recall number is measured by the CLI against real semgrep output
// (validate-source-recall.ts, #945) — the same offline/binary split calibration.test.ts uses. This
// suite proves the answer-key integrity and the scoring wiring, which is what CI can hold without
// binaries.

describe("source-recall answer key (#945)", () => {
  it("every listed id resolves to a unique M1-mechanical corpus entry (fail-loud on drift)", () => {
    expect(() => assertSourceTierResolvable()).not.toThrow();
  });

  it("selects exactly the listed ids, all mechanical, none module-tagged", () => {
    const subset = sourceTierCorpus();
    expect(subset).toHaveLength(SOURCE_TIER_IDS.length);
    const ids = new Set(SOURCE_TIER_IDS);
    for (const e of subset) {
      expect(ids.has(e.id)).toBe(true);
      expect(e.module).toBeUndefined(); // in runMechanicalScan's slice
    }
  });

  // Drift forcing-function (repo's pinned-count discipline): the source-tier population is pinned so
  // adding/removing an id from the answer key is a conscious edit, never a silent denominator change.
  it("has the pinned positive/negative split", () => {
    const subset = sourceTierCorpus();
    expect(subset.filter((e) => e.kind === "positive")).toHaveLength(39);
    expect(subset.filter((e) => e.kind === "negative")).toHaveLength(31);
  });

  // NON-BLENDING (#868 caveat): the source-detector answer key must not absorb the SCA/secret/
  // config/header/crypto tiers — that blend is exactly what would make this number masquerade as
  // something broader. Spot-check that representative excluded-tier positives are NOT in the set.
  it("excludes the SCA/secret/config/header tiers (no blend)", () => {
    const excluded = ["P-NEXTCONFIG-ENV-SECRET", "P-NPM-TOKEN-COMMITTED", "P-GCP-SA-JSON", "P-SLACK-WEBHOOK-URL", "P-NO-RATE-LIMIT", "P-ROUTE-NOAUTH", "P-PUBLIC-BUCKET"];
    for (const id of excluded) expect(SOURCE_TIER_IDS).not.toContain(id);
    // and every excluded id above is a real corpus entry (so the assertion is meaningful, not a typo passing vacuously)
    const corpusIds = new Set(mechanicalCorpus(CORPUS).map((e) => e.id));
    for (const id of excluded) expect(corpusIds.has(id)).toBe(true);
  });
});

function finding(over: Partial<Finding>): Finding {
  return {
    id: "F", title: "", severity: "High", confidence: "Confirmed", category: "", taxonomy: "",
    location: "", status: "Open", evidence: "", impact: "", fix: "", value: 3, ease: 3, safety: 3,
    mechanical: true, ...over,
  } as Finding;
}

describe("source-recall scoring (#945)", () => {
  it("scores caught positives, uncaught gaps, and free-count FPs like the shared model", () => {
    // A caught positive (SQLi), a positive left uncaught (command injection), and a benign negative
    // wrongly flagged at high (a free-count false positive).
    const findings: Finding[] = [
      finding({ location: "targets/calibration/pages/api/search.js", title: "sql injection", precisionTier: "high" }),
      finding({ location: "targets/calibration/pages/api/list.js", title: "parameterized query looks like sqli", precisionTier: "high" }),
    ];
    const m = scoreSourceRecall(findings);
    const row = (id: string) => m.rows.find((r) => r.id === id)!;
    expect(row("P-SQLI-CONCAT").pass).toBe(true); // caught
    expect(row("P-CMD-INJECTION").pass).toBe(false); // uncaught -> recall gap
    expect(row("N-PARAM-QUERY").pass).toBe(false); // high-tier hit on a benign lookalike -> FP
    expect(m.positivesTotal).toBe(39);
    expect(m.positivesCaught).toBeGreaterThanOrEqual(1);
  });
});
