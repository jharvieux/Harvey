import { describe, expect, it } from "vitest";
import { CORPUS, mechanicalCorpus } from "./calibration.js";
import {
  M9_SOURCE_TIER_IDS,
  SOURCE_TIER_IDS,
  assertM9SourceTierResolvable,
  assertSourceTierResolvable,
  m9SourceTierCorpus,
  scoreM9SourceRecall,
  scoreSourceRecall,
  sourceTierCorpus,
} from "./source-recall.js";
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

// #1011 — server-client-leak + client-side-authz folded into their OWN "M9 source-code (non-taint)"
// tier, kept separate from SOURCE_TIER_IDS's taint-only definition above (so assertSourceTierResolvable
// and the 39/31 planted split it pins are untouched by this addition).
describe("M9 source-code (non-taint) tier (#1011)", () => {
  it("resolves against the whole corpus, spanning a module-tagged and a module-less entry", () => {
    expect(() => assertM9SourceTierResolvable()).not.toThrow();
  });

  it("selects exactly the listed ids: server-client-leak (M9-tagged) + client-side-authz (mechanical)", () => {
    const subset = m9SourceTierCorpus();
    expect(subset).toHaveLength(M9_SOURCE_TIER_IDS.length);
    const ids = new Set(subset.map((e) => e.id));
    expect(ids).toEqual(new Set(M9_SOURCE_TIER_IDS));
    // server-client-leak is module-tagged M9 (scored by the M9 AST pass, outside runMechanicalScan)
    expect(subset.find((e) => e.id === "M9C-LEAK-POS")?.module).toBe("M9");
    // client-side-authz carries NO module tag (already inside mechanicalCorpus/runMechanicalScan)
    expect(subset.find((e) => e.id === "P-CLIENT-AUTHZ-STORAGE")?.module).toBeUndefined();
  });

  it("stays out of SOURCE_TIER_IDS (never blended into the taint-only tier)", () => {
    for (const id of M9_SOURCE_TIER_IDS) expect(SOURCE_TIER_IDS).not.toContain(id);
  });

  it("scores a caught server-client-leak positive and a caught client-side-authz positive", () => {
    const findings: Finding[] = [
      finding({ location: "m9-corpus/leak/positive/page.tsx", title: "Server→client data leak", precisionTier: "review" }),
      finding({ location: "src/components/AdminGateStorage.tsx", title: "client-side-authz gate", precisionTier: "review" }),
    ];
    const m = scoreM9SourceRecall(findings);
    const row = (id: string) => m.rows.find((r) => r.id === id)!;
    expect(row("M9C-LEAK-POS").pass).toBe(true);
    expect(row("P-CLIENT-AUTHZ-STORAGE").pass).toBe(true);
    expect(row("M9C-LEAK-NEG").pass).toBe(true); // no finding relevant to it -> cleared
    expect(m.positivesTotal).toBe(3);
    expect(m.negativesTotal).toBe(2);
  });
});
