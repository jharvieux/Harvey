import { describe, expect, it } from "vitest";
import { committedScanFindings, harveySemgrepRules, ruleCorpusPairings, type SemgrepRule } from "./rule-corpus-pairing.js";
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
