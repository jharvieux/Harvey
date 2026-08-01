import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { committedScanFindings, freeCountCoverage, freeCountOutsideUnits, harveySemgrepRules, pairUnits, ruleCorpusPairings, TWIN_BACKLOG, UNSCORED_OUTSIDE_UNITS, type SemgrepRule } from "./rule-corpus-pairing.js";
import { CORPUS } from "./calibration.js";
import type { Finding } from "../findings.js";

describe("#1301 rule ↔ corpus pairing (a rule may not enter the free count unvalidated)", () => {
  it("every harvey-* semgrep rule is claimed by a positive it caught — the half that is fatal", () => {
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
    expect(clean.twinless).toBeUndefined();
    const soleTwin = CORPUS.filter((e) => e.kind === "positive" || e.id === clean.twin!.entry);
    expect(ruleCorpusPairings([real], findings, soleTwin)[0]?.twinless).toBeUndefined();
    const onTwin: Finding = { ...findings[0]!, taxonomy: real.taxonomy, location: `${clean.twin!.fixture}:1` };
    expect(ruleCorpusPairings([real], [...findings, onTwin], soleTwin)[0]?.twinless).toMatch(/also carries a hit from this rule/);
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

  // #1676: the total was already measured; the SPLIT is what makes it actionable, and what makes a
  // brand-new engine entering the free count visible instead of absorbed into one percentage.
  it("names WHICH engines the uncovered share comes from, not just how big it is", () => {
    const byEngine = freeCountCoverage().byEngine;
    expect(byEngine.length).toBeGreaterThan(2);
    expect(byEngine.reduce((n, e) => n + e.findings, 0)).toBe(freeCountCoverage().outsidePairingGate);
    expect(byEngine.map((e) => e.engine)).toContain("secret scanners (gitleaks/trufflehog)");
    expect(byEngine.map((e) => e.engine)).toContain("dependency / supply-chain / licence checks");
  });

  it("NEGATIVE CONTROL — the per-rule gate DOES withhold an unpaired rule's findings", () => {
    // Without this, "drops 0" is indistinguishable from a filter that drops nothing ever.
    const findings = committedScanFindings();
    const invented: SemgrepRule = { id: "harvey-invented-1414", file: "invented.yml", taxonomy: "src.scan.rules.semgrep.harvey-invented-1414" };
    // #1676: the location matters. This used to reuse the first high-tier finding's location
    // (`[source] .env:9`), which IS scored by P-ENV-COMMITTED — so the rule read as unpaired only
    // because the old empty-string `stem` made its own fixture its only twin candidate. Once that
    // collision was fixed the rule reads as twinless-but-positively-claimed, a DIFFERENT state that
    // is correctly not withheld. Plant it where no corpus positive scores it, which is what
    // "unvalidated" is meant to mean.
    const hit: Finding = { ...findings.find((f) => f.precisionTier === "high")!, id: "INVENTED-1", taxonomy: invented.taxonomy, location: "src/nowhere/orphan-1414.ts:1" };
    const rules = [...harveySemgrepRules(), invented];
    const withHit = [...findings, hit];
    const c = freeCountCoverage(withHit, rules, ruleCorpusPairings(rules, withHit));
    expect(c.droppedByPerRuleGate).toEqual(["INVENTED-1"]);
    // ...and the same finding is NOT in the uncovered set, because its rule IS enumerated — the two
    // measurements answer different questions and must not collapse into one.
    expect(c.outsideTaxonomies).not.toContain(invented.taxonomy);
  });
});

// #1676 — the pairing-equivalent gate for the engines OUTSIDE `harvey-*`, and the ratchet over the
// negative half that fixing `.npmrc` exposed.
//
// #1414's stated reason for stopping at a measurement was that these engines have "different notions
// of positive and benign twin, and none of them is a rule id you can pair against a corpus row".
// Re-tested: false of the predicate as written. `pairUnits` keys on taxonomy and derives twins from
// fixture names; only the ENUMERATION was semgrep-shaped.
describe("#1676 outside-engine pairing, and the twin ratchet", () => {
  const outside = (): ReturnType<typeof pairUnits> => pairUnits(freeCountOutsideUnits());

  it("pairs the outside engines with the SAME predicate, and every one of them is either paired or disclosed", () => {
    const rows = outside();
    expect(rows.length).toBeGreaterThan(10);
    // Nothing is silently unaccounted: a row is paired, on the twin backlog, or on the unscored list.
    const unscored = new Set(UNSCORED_OUTSIDE_UNITS.map((u) => u.unit));
    const backlog = new Set(TWIN_BACKLOG);
    const unaccounted = rows.filter((r) => (r.unpaired && !unscored.has(r.rule)) || (r.twinless && !backlog.has(r.rule)));
    expect(unaccounted.map((r) => `${r.rule}: ${r.unpaired ?? r.twinless}`)).toEqual([]);
    // ...and the gate is not vacuous: some outside units genuinely pair on both halves today.
    expect(rows.filter((r) => r.twin !== undefined).length).toBeGreaterThan(0);
  });

  it("holds every UNSCORED_OUTSIDE_UNITS row to a real reason, and a row that gained a positive fails as STALE", () => {
    const rows = outside();
    for (const u of UNSCORED_OUTSIDE_UNITS) {
      expect(u.reason, u.unit).toMatch(/MEASURED \d{4}-\d{2}-\d{2}/);
      // The stale direction: an entry here claims nothing scores this taxonomy. If something does
      // now, the disclosure is a lie and must be deleted rather than left standing.
      expect(rows.find((r) => r.rule === u.unit)?.unpaired, `${u.unit} now HAS a scoring positive`).toBeDefined();
    }
  });

  // The ratchet, in both directions. A green list that can only ever be read is not a gate.
  it("TWIN_BACKLOG can only shrink — every id on it is still twinless, and nothing twinless is off it", () => {
    const rows = [...ruleCorpusPairings(), ...outside()];
    const twinless = new Set(rows.filter((r) => r.twinless).map((r) => r.rule));
    expect([...twinless].filter((id) => !TWIN_BACKLOG.includes(id)).sort()).toEqual([]);
    expect(TWIN_BACKLOG.filter((id) => !twinless.has(id)).sort()).toEqual([]);
    // The population, stated beside the list so its size is part of the assertion.
    expect(TWIN_BACKLOG.length).toBe(twinless.size);
  });

  // #1676's core finding, re-derived rather than asserted from a comment: the OLD `stem` mapped a
  // bare dotfile to "", and "" is a prefix of every string, so `.npmrc` was a candidate twin for
  // every rule and passed the silence half for all of them. This is the guard against reintroducing
  // that — it fails if any tracked calibration fixture reduces to an empty stem under the shipped
  // regex.
  it("EMPTY_STEM_IS_A_UNIVERSAL_TWIN — no calibration fixture reduces to the empty string", () => {
    const shippedStem = (p: string): string => p.replace(/(?<=[^/])\.[a-z]+$/i, "");
    const tracked = execFileSync("git", ["ls-files", "targets/calibration"], { encoding: "utf8" }).trim().split("\n");
    expect(tracked.length).toBeGreaterThan(100);
    expect(tracked.filter((f) => shippedStem(f.replace(/^targets\/calibration\//, "")) === "")).toEqual([]);
    // ...and the OLD regex DID produce one, so this guard has a subject rather than a population of zero.
    const oldStem = (p: string): string => p.replace(/\.[a-z]+$/i, "");
    const oldEmpty = tracked.filter((f) => oldStem(f.replace(/^targets\/calibration\//, "")) === "");
    // `.npmrc` is the one that mattered: the only empty-stem file tracked under a NEGATIVE entry's
    // location (N-NPM-TOKEN-ENV), which is what made it a candidate twin for every rule at all.
    expect(oldEmpty).toContain("targets/calibration/.npmrc");
  });
});
