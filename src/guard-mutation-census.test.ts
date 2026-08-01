// #1738 criterion 5 — prove the reporter itself can fire.
//
// The census exists to name a guard nothing can kill. Fed only healthy input it would print "none"
// forever and be indistinguishable from a census that reads nothing at all. So it is scored against
// two REAL committed Stryker 9.6.1 captures (src/scan/__fixtures__/stryker/, #1100) with known
// answers: the planted vacuous fixture, where the answer is "all 12 mutants survived", and the
// calibration fixture, where two files have genuine kills.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { formatGuardCensus, guardMutationCensus, guardSetIsFullyAccounted, NOT_MUTATED } from "./guard-mutation-census.js";
import type { StrykerMutant, StrykerReport } from "./mutation-scan.js";

const capture = (name: string): StrykerReport => JSON.parse(readFileSync(new URL(`./scan/__fixtures__/stryker/${name}`, import.meta.url), "utf8")) as StrykerReport;

const mutant = (status: StrykerMutant["status"], id: string): StrykerMutant => ({
  id,
  mutatorName: "ConditionalExpression",
  location: { start: { line: 1, column: 1 }, end: { line: 1, column: 9 } },
  status,
});

describe("guardMutationCensus (#1738)", () => {
  it("FIRES on the planted vacuous fixture — the real capture whose answer is 'nothing kills anything'", () => {
    const census = guardMutationCensus(capture("stryker-9.6.1-m8-vacuous.json"));
    expect(census.zeroKill.map((r) => r.file)).toEqual(["vacuous.ts"]);
    expect(census.zeroKill[0]).toMatchObject({ mutants: 12, killed: 0, survived: 10, noCoverage: 2, score: 0 });
    expect(census.unscored).toEqual([]);
  });

  it("does NOT fire on the calibration capture, where both files have genuine kills", () => {
    const census = guardMutationCensus(capture("stryker-9.6.1-m8-calibration.json"));
    expect(census.zeroKill).toEqual([]);
    expect(census.totalKilled).toBe(19);
    // discount.ts (9 of 15) sorts before authz.ts (10 of 10): worst guard first is the whole point
    // of the ordering, because the top of the list is what a reader acts on.
    expect(census.rows.map((r) => r.file)).toEqual(["discount.ts", "authz.ts"]);
  });

  it("separates 'nothing killed it' from 'nothing scored it' — a zero Stryker never measured is not evidence", () => {
    // The #1065 shape reached through mutation testing: a file whose mutants all failed to compile
    // reports 0 killed exactly like a file nothing can kill. Reading the first as the second would
    // manufacture the finding this tool exists to make honest.
    const census = guardMutationCensus({
      files: {
        "src/never-compiled.ts": { mutants: [mutant("CompileError", "a"), mutant("Ignored", "b")] },
        "src/genuinely-unguarded.ts": { mutants: [mutant("Survived", "c"), mutant("NoCoverage", "d")] },
      },
    });
    expect(census.zeroKill.map((r) => r.file)).toEqual(["src/genuinely-unguarded.ts"]);
    expect(census.unscored.map((r) => r.file)).toEqual(["src/never-compiled.ts"]);
  });

  it("reports the unscored set out loud rather than dropping it", () => {
    const out = formatGuardCensus(
      guardMutationCensus({ files: { "src/never-compiled.ts": { mutants: [mutant("CompileError", "a")] } } }),
    );
    expect(out).toContain("NOT EVIDENCE");
    expect(out).toContain("src/never-compiled.ts");
    expect(out).toContain("a measurement that did not happen");
  });

  it("prints the zero-kill population and says, in the output, that it never fails the build", () => {
    const out = formatGuardCensus(guardMutationCensus(capture("stryker-9.6.1-m8-vacuous.json")));
    expect(out).toContain("GUARDS WITH ZERO KILLED MUTANTS");
    expect(out).toContain("vacuous.ts: 12 scorable mutant(s), 0 killed");
    // The operator ruling travels with the tool. A reader who sees only the census must not have to
    // guess whether a red number here blocks anything.
    expect(out).toContain("REPORT ONLY");
    expect(out).toContain("separate, later decision");
  });

  it("says 'none' explicitly when nothing qualifies — an absent row cannot be argued with", () => {
    expect(formatGuardCensus(guardMutationCensus(capture("stryker-9.6.1-m8-calibration.json")))).toContain("(none — every scored guard");
  });

  it("reports the mutants nothing disproved, not only the extreme case", () => {
    const out = formatGuardCensus(guardMutationCensus(capture("stryker-9.6.1-m8-calibration.json")));
    // 6 of 25 in that capture. A census that printed only "0 guards with zero kills" would call
    // this file clean.
    expect(out).toContain("MUTANTS NOTHING DISPROVED: 6 of 25");
  });
});

// #1738 criterion 1, enforced rather than asserted in prose: the declared guard set and what the
// Stryker config actually mutates have to stay reconciled. Dropping a file from `mutate` to make a
// run finish is exactly how a guard leaves the census while the census keeps printing a clean
// number — the silent-omission shape, reached through a config file.
describe("every declared guard is either mutated or disclosed (#1738)", () => {
  const config = JSON.parse(readFileSync(new URL("../stryker.guards.config.json", import.meta.url), "utf8")) as { mutate: string[] };

  it("the config's mutate list and NOT_MUTATED partition GUARD_SET", () => {
    const { missing, doubleBooked } = guardSetIsFullyAccounted(config.mutate);
    expect(missing, "these declared guards are neither mutated nor recorded in NOT_MUTATED, so they left the census silently").toEqual([]);
    expect(doubleBooked, "these are both mutated and recorded as unmutatable — one of the two claims is stale").toEqual([]);
  });

  it("NEGATIVE CONTROL: dropping a guard from mutate without recording why is caught", () => {
    expect(guardSetIsFullyAccounted(config.mutate.filter((f) => f !== "src/ci-liveness.ts")).missing).toEqual(["src/ci-liveness.ts"]);
    expect(guardSetIsFullyAccounted([...config.mutate, "src/recorded-reasons.ts"]).doubleBooked).toEqual(["src/recorded-reasons.ts"]);
  });

  it("every NOT_MUTATED reason names what was actually run, not an intuition", () => {
    for (const [file, why] of Object.entries(NOT_MUTATED)) {
      expect(why, `${file}'s NOT_MUTATED reason is not provenance-tagged`).toMatch(/MEASURED|TRIED/);
      expect(why, `${file}'s NOT_MUTATED reason carries no falsifier`).toContain("Falsifier:");
    }
  });
});
