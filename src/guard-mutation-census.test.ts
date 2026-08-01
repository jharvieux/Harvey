// #1738 criterion 5 — prove the reporter itself can fire.
//
// The census exists to name a guard nothing can kill. Fed only healthy input it would print "none"
// forever and be indistinguishable from a census that reads nothing at all. So it is scored against
// two REAL committed Stryker 9.6.1 captures (src/scan/__fixtures__/stryker/, #1100) with known
// answers: the planted vacuous fixture, where the answer is "all 12 mutants survived", and the
// calibration fixture, where two files have genuine kills.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { formatGuardCensus, guardMutationCensus } from "./guard-mutation-census.js";
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
});
