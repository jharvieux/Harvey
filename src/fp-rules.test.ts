// #1302/#1412 — briefs/fp-rules.txt is functional tool input: the `/triage` step appends it verbatim
// to the verifier's exclusion rules. The presence-based carve-out is the ONLY thing standing between
// a committed credential and the built-in dead-code exclusion, and #1302's whole history is a
// limitation that was written down somewhere a future engagement never read (a runbook line that did
// not survive a skill upgrade). So the carve-out gets a test: it may be reworded, but the test fails
// if it silently loses a class or stops naming the exclusions it overrides.
//
// #1412 IS THE SECOND HALF, AND THE REASON THE FIRST WAS NOT ENOUGH. Every assertion below the
// PRESENCE_CLASSES block used to be of the form "this phrase is present", which a brief REWORDED
// INTO USELESSNESS still satisfies: keep every noun, turn every directive into advice, and the
// section stops being tool input while the suite stays green. `carveOutDefects` replaces presence
// with a CONTRACT — the section must be directive, exhaustive, and must still contradict the
// exclusions it overrides — and USELESSNESS_MUTATIONS is the measured proof that it is sensitive to
// rewording and not merely to deletion: each mutation keeps the section's vocabulary and changes only
// its force, and each one must make the contract fail.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const FP_RULES = readFileSync(fileURLToPath(new URL("../briefs/fp-rules.txt", import.meta.url)), "utf8");

// The section the triage verifier reads for this override, isolated so a match cannot be satisfied
// by wording that happens to appear elsewhere in the brief.
function presenceSection(): string {
  const start = FP_RULES.indexOf("## Reachability is the WRONG test for presence-based classes");
  expect(start, "briefs/fp-rules.txt no longer carries the presence-based carve-out (#1302)").toBeGreaterThan(-1);
  const next = FP_RULES.indexOf("\n## ", start + 1);
  return FP_RULES.slice(start, next === -1 ? undefined : next);
}

// The contract, as four properties a REWORDING can break without deleting anything.
//
// (1) DIRECTIVE, not advisory. An LLM reading "you may cite the dead-code exclusion" has been told
//     the opposite of the rule. So the two overrides and the call-site waiver must each appear as a
//     prohibition, and the section must carry no hedging modal on them.
// (2) EXHAUSTIVE and NON-GENERALIZING. The four classes are the whole scope; a section that names
//     them without saying the list does not generalize invites the verifier to widen it, which is
//     the failure mode arm C exists to detect.
// (3) The verdict rule must still EXCLUDE the call path, not merely mention it.
// (4) Reachability must stay decisive for everything else, or the narrowing is not a narrowing.
const HEDGE = /\b(may|might|consider|generally|usually|typically|where appropriate|at your discretion|if in doubt|prefer to|it is suggested)\b/i;

function carveOutDefects(section: string): string[] {
  const defects: string[] = [];
  const classes: [string, RegExp][] = [
    ["hardcoded credential in any committed file", /hardcoded credential.*in any committed file/s],
    ["a real credential in a sample/template file", /REAL credential committed to a sample\/template file/],
    ["a credential in build output/bundle/lockfile", /committed build output, a bundle, or a lockfile/],
    ["a credential in git history only", /git history that no longer exists in the working tree/],
  ];
  for (const [label, pattern] of classes) {
    if (!pattern.test(section)) defects.push(`presence class no longer named: ${label}`);
  }

  // (1) The three directives, each required in its prohibitive form.
  const directives: [string, RegExp][] = [
    ["overrides the test/dead/example-code exclusion", /do NOT cite the test\/dead\/example-code exclusion/],
    ["overrides the missing-hardening-with-no-exploit-path exclusion", /missing-hardening-with-no-exploit-path exclusion/],
    ["waives the call-site requirement", /do NOT require a caller or a first call-site link/],
  ];
  for (const [label, pattern] of directives) {
    if (!pattern.test(section)) defects.push(`directive lost its prohibitive form: ${label}`);
  }
  // ...and no hedging modal anywhere on a `do NOT` line, which is how a directive becomes advice
  // while keeping its words.
  for (const l of section.split("\n").filter((l) => /do NOT|never/i.test(l))) {
    if (HEDGE.test(l)) defects.push(`hedged directive — an LLM reads this as optional: "${l.trim()}"`);
  }

  // (2) The scope statement. Without it the four classes read as examples.
  if (!/does NOT generalize to\s+other finding types/s.test(section)) {
    defects.push("the class list no longer declares itself exhaustive/non-generalizing — a verifier may widen it");
  }

  // (3) The verdict rule must exclude the call path, not merely mention one.
  if (!/never on whether a call path reaches it/.test(section)) {
    defects.push("the verdict rule no longer excludes the call path — reachability is back in the decision");
  }

  // (4) The narrowing must still be a narrowing (arm C's property, stated in the brief itself).
  if (!/unexploitable crash in dead code.*still a false positive/s.test(section)) {
    defects.push("reachability is no longer decisive for non-presence classes — this stopped being a narrowing");
  }
  return defects;
}

describe("briefs/fp-rules.txt presence-based carve-out (#1302)", () => {
  it("the committed carve-out satisfies the whole contract", () => {
    expect(carveOutDefects(presenceSection())).toEqual([]);
  });

  it("keeps the exhaustive class list — dropping one silently re-opens #53", () => {
    // #53: a reachability heuristic deciding a class whose question is not reachability. Kept as its
    // own assertion (not folded into the contract above) because losing a CLASS and losing the
    // section's FORCE are different regressions and should not report as one failure.
    const section = presenceSection();
    for (const cls of ["in any committed file", "REAL credential committed to a sample/template file", "committed build output, a bundle, or a lockfile", "git history that no longer exists in the working tree"]) {
      expect(section, cls).toContain(cls);
    }
  });

  it("does not disturb the placeholder-secret exemption it sits next to", () => {
    // A carve-out that swallowed this would turn every `.env.example` into a Critical.
    expect(FP_RULES).toMatch(/PLACEHOLDER SECRETS IN SAMPLE FILES ARE NOT FINDINGS/);
    expect(presenceSection()).toMatch(/exempts PLACEHOLDERS/);
  });
});

// #1412 criterion 1 + criterion 4, as one block: the negative controls ARE the evidence that the
// check above is reword-sensitive. Every mutation below preserves the section's vocabulary — no
// class name is removed, no heading is deleted — and changes only whether the section still
// instructs. A check that survived any of them would be measuring presence, which is what the
// shipped one did.
describe("#1412 NEGATIVE CONTROLS — a brief reworded into uselessness fails, not just a deleted one", () => {
  const MUTATIONS: [string, (s: string) => string][] = [
    ["the dead-code override becomes permission", (s) => s.replace("do NOT cite the test/dead/example-code exclusion", "you may cite the test/dead/example-code exclusion")],
    ["the call-site waiver becomes advice", (s) => s.replace("do NOT require a caller or a first call-site link", "you may consider whether to require a caller or a first call-site link")],
    ["a hedge is inserted into an intact directive", (s) => s.replace("do NOT require a caller", "generally do NOT require a caller")],
    ["the verdict rule readmits the call path", (s) => s.replace("never on whether a call path reaches it", "and also on whether a call path reaches it")],
    ["the class list stops being exhaustive", (s) => s.replace(/does NOT generalize to\s+other finding types/s, "is illustrative and extends to other finding types")],
    ["the narrowing stops being a narrowing", (s) => s.replace(/unexploitable crash in dead code/, "unexploitable crash in live code")],
  ];

  it.each(MUTATIONS)("%s", (_label, mutate) => {
    const original = presenceSection();
    const reworded = mutate(original);
    // The mutation must actually apply — a no-op replace would make this pass vacuously, which is
    // the exact defect the block exists to rule out.
    expect(reworded, "mutation did not apply — the brief's wording moved, update the mutation").not.toBe(original);
    expect(carveOutDefects(reworded).length).toBeGreaterThan(0);
  });

  it("a mutation that only changes prose the contract does not depend on still PASSES", () => {
    // The other direction: the contract must not be so brittle that any edit fails it, or it becomes
    // a reason not to improve the brief. Rewriting the dated measurement paragraph changes nothing.
    const rewritten = presenceSection().replace(/RECORDED 2026-07-09 \(#53\)/, "First recorded on 2026-07-09 (#53)");
    expect(rewritten).not.toBe(presenceSection());
    expect(carveOutDefects(rewritten)).toEqual([]);
  });
});
