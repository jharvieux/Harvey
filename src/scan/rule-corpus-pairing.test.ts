import { describe, expect, it } from "vitest";
import { committedScanFindings, freeCountCoverage, harveySemgrepRules, ruleCorpusPairings, type SemgrepRule } from "./rule-corpus-pairing.js";
import { CORPUS } from "./calibration.js";
import type { Finding } from "../findings.js";

describe("#1301 rule ↔ corpus pairing (a rule may not enter the free count unvalidated)", () => {
  it("every harvey-* semgrep rule is claimed by a positive it caught and a benign twin it stayed silent on", () => {
    const pairings = ruleCorpusPairings();
    expect(pairings.length).toBeGreaterThan(100);
    expect(pairings.filter((p) => p.unpaired).map((p) => `${p.rule}: ${p.unpaired}`)).toEqual([]);
  });

  it("NEGATIVE CONTROL — an unpaired rule fails the check, in each of the three ways a rule can be unpaired", () => {
    const findings = committedScanFindings();
    const real = harveySemgrepRules().find((r) => r.id === "harvey-redos-literal")!;

    // (1) a brand-new rule shipped with no fixture at all.
    const invented: SemgrepRule = { id: "harvey-invented", file: "invented.yml", taxonomy: "src.scan.rules.semgrep.harvey-invented" };
    expect(ruleCorpusPairings([invented], findings)[0]?.unpaired).toMatch(/fires on nothing/);

    // (2) a rule that fires, but no positive entry scores it — the corpus would not notice it dying.
    const orphan: Finding = { ...findings[0]!, taxonomy: invented.taxonomy, location: "src/nowhere/orphan.ts:1" };
    expect(ruleCorpusPairings([invented], [...findings, orphan])[0]?.unpaired).toMatch(/no POSITIVE corpus entry/);

    // (3) a paired rule that starts firing on the only benign twin it has.
    const clean = ruleCorpusPairings([real], findings)[0]!;
    expect(clean.unpaired).toBeUndefined();
    const soleTwin = CORPUS.filter((e) => e.kind === "positive" || e.id === clean.twin!.entry);
    expect(ruleCorpusPairings([real], findings, soleTwin)[0]?.unpaired).toBeUndefined();
    const onTwin: Finding = { ...findings[0]!, taxonomy: real.taxonomy, location: `${clean.twin!.fixture}:1` };
    expect(ruleCorpusPairings([real], [...findings, onTwin], soleTwin)[0]?.unpaired).toMatch(/also carries a hit from this rule/);
  });

  it("resolves a rule that renames its taxonomy via metadata.harveyTaxonomy, which keying on the id alone would score as never firing", () => {
    const overridden = harveySemgrepRules().filter((r) => r.taxonomy !== `src.scan.rules.semgrep.${r.id}`);
    expect(overridden.length).toBeGreaterThan(0);
    for (const r of overridden) expect(ruleCorpusPairings([r], committedScanFindings(), CORPUS)[0]?.positives.length).toBeGreaterThan(0);
  });
});

// #1414 — the gate above covers `harvey-*` semgrep rules. `precisionTier: "high"` does not. These
// hold the difference to a MEASURED number, and prove the per-rule prototype can actually withhold
// something, so "it drops zero today" reads as a measurement rather than as dead code.
describe("#1414 free-count coverage of the pairing gate, and the per-rule gate prototype", () => {
  it("MEASURES the share of the free count the pairing gate does not reach — it is not 100%", () => {
    const c = freeCountCoverage();
    expect(c.highTier).toBeGreaterThan(100);
    expect(c.coveredByPairingGate + c.outsidePairingGate).toBe(c.highTier);
    // The claim #1301 shipped — that an unvalidated rule never reaches a client's grade — is false for a
    // third of this population, and this is the assertion that keeps that fact from being
    // re-forgotten. It fails the day someone widens the gate to cover everything — which would be
    // good news, and should be a deliberate edit here rather than a silent one.
    expect(c.outsidePairingGate).toBeGreaterThan(0);
    expect(c.outsideTaxonomies).toContain("Committed credential");
    // A secret scanner, an AST detector and a dependency check are all in the uncovered set, so the
    // gap is structural (several engines), not one stray taxonomy.
    expect(c.outsideTaxonomies.length).toBeGreaterThan(5);
  });

  it("the per-rule gate withholds nothing today, because the build gate keeps the unpaired set empty", () => {
    expect(ruleCorpusPairings().filter((p) => p.unpaired)).toEqual([]);
    expect(freeCountCoverage().droppedByPerRuleGate).toEqual([]);
  });

  it("NEGATIVE CONTROL — the per-rule gate DOES withhold an unpaired rule's findings", () => {
    // Without this, "drops 0" is indistinguishable from a filter that drops nothing ever.
    const findings = committedScanFindings();
    const invented: SemgrepRule = { id: "harvey-invented-1414", file: "invented.yml", taxonomy: "src.scan.rules.semgrep.harvey-invented-1414" };
    const hit: Finding = { ...findings.find((f) => f.precisionTier === "high")!, id: "INVENTED-1", taxonomy: invented.taxonomy };
    const rules = [...harveySemgrepRules(), invented];
    const withHit = [...findings, hit];
    const c = freeCountCoverage(withHit, rules, ruleCorpusPairings(rules, withHit));
    expect(c.droppedByPerRuleGate).toEqual(["INVENTED-1"]);
    // ...and the same finding is NOT in the uncovered set, because its rule IS enumerated — the two
    // measurements answer different questions and must not collapse into one.
    expect(c.outsideTaxonomies).not.toContain(invented.taxonomy);
  });
});
