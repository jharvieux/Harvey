// #1302 — briefs/fp-rules.txt is functional tool input: the `/triage` step appends it verbatim to
// the verifier's exclusion rules. The presence-based carve-out is the ONLY thing standing between a
// committed credential and the built-in dead-code exclusion, and #1302's whole history is a
// limitation that was written down somewhere a future engagement never read (a runbook line that
// did not survive a skill upgrade). So the carve-out gets a test: it may be reworded, but it cannot
// silently lose a class or stop naming the exclusions it overrides.

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

describe("briefs/fp-rules.txt presence-based carve-out (#1302)", () => {
  // Each entry is a harm that exists on commit, not on execution. Dropping one silently re-opens
  // #53: a reachability heuristic deciding a class whose question is not reachability.
  const PRESENCE_CLASSES: [string, RegExp][] = [
    ["hardcoded credential in any committed file", /hardcoded credential.*in any committed file/s],
    ["a real credential in a sample/template file", /REAL credential committed to a sample\/template file/],
    ["a credential in build output/bundle/lockfile", /committed build output, a bundle, or a lockfile/],
    ["a credential in git history only", /git history that no longer exists in the working tree/],
  ];

  it.each(PRESENCE_CLASSES)("names %s as presence-based", (_label, pattern) => {
    expect(presenceSection()).toMatch(pattern);
  });

  it("forbids the two exclusions that would otherwise drop a committed credential", () => {
    const section = presenceSection();
    expect(section).toMatch(/do NOT cite the test\/dead\/example-code exclusion/);
    expect(section).toMatch(/missing-hardening-with-no-exploit-path exclusion/);
  });

  it("waives the call-site requirement, which a presence-based finding can never satisfy", () => {
    // The verifier contract requires a FIRST_LINK call site and reachability from untrusted input.
    // A committed secret has neither by construction, so the carve-out has to say so explicitly.
    expect(presenceSection()).toMatch(/do NOT require a caller or a first call-site link/);
  });

  it("keeps reachability decisive for everything else, so the narrowing stays a narrowing", () => {
    expect(presenceSection()).toMatch(/unexploitable crash in dead code.*still a false positive/s);
  });

  it("does not disturb the placeholder-secret exemption it sits next to", () => {
    // A carve-out that swallowed this would turn every `.env.example` into a Critical.
    expect(FP_RULES).toMatch(/PLACEHOLDER SECRETS IN SAMPLE FILES ARE NOT FINDINGS/);
    expect(presenceSection()).toMatch(/exempts PLACEHOLDERS/);
  });
});
