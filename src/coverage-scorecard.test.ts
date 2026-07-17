import { describe, expect, it } from "vitest";
import { type GroundTruthBug, scoreCoverage, type ScorableFinding, summarizeCoverage } from "./coverage-scorecard.js";

function bug(overrides: Partial<GroundTruthBug>): GroundTruthBug {
  return {
    id: "TEST-BUG",
    severity: "High",
    location: "pages/api/test.js:1",
    expectedModule: "Semgrep",
    moduleRan: true,
    matches: () => false,
    ...overrides,
  };
}

describe("scoreCoverage", () => {
  it("scores requires-live-run when the expected module didn't run, regardless of findings", () => {
    const findings: ScorableFinding[] = [{ taxonomy: "anything", location: "anything" }];
    const bugs = [bug({ id: "B1", moduleRan: false, matches: () => true })];
    const [scored] = scoreCoverage(bugs, findings);
    expect(scored!.status).toBe("requires-live-run");
  });

  it("scores caught when the module ran and a finding matches", () => {
    const findings: ScorableFinding[] = [{ taxonomy: "sql-injection", location: "pages/api/search.js:9" }];
    const bugs = [bug({ id: "SQLI", location: "pages/api/search.js:9", matches: (f) => f.location.includes("search.js:9") })];
    const [scored] = scoreCoverage(bugs, findings);
    expect(scored!.status).toBe("caught");
  });

  // #342: a high-tier catch is an asserted verdict; a review-tier catch is a shape surfaced for a
  // human. The tier must ride through onto the ScoredBug so the two are distinguishable in the
  // scorecard without reading prose.
  it("records the matched finding's tier — high asserts, review is surfaced for a human", () => {
    const asserted = scoreCoverage(
      [bug({ id: "SQLI", matches: () => true })],
      [{ taxonomy: "sql-injection", location: "search.js:9", precisionTier: "high" }],
    )[0]!;
    expect(asserted.tier).toBe("high");
    expect(asserted.note).toContain("Asserted");

    const surfaced = scoreCoverage(
      [bug({ id: "RLS-AUTH-ROLE", matches: () => true })],
      [{ taxonomy: "M1 — Multi-tenant security", location: "rls.sql:38", precisionTier: "review" }],
    )[0]!;
    expect(surfaced.status).toBe("caught");
    expect(surfaced.tier).toBe("review");
    expect(surfaced.note).toContain("a human must still adjudicate");
  });

  // The #246 regression: `matches` used to receive taxonomy and location as separate strings, so a
  // predicate could not require both. COUNTER-RACE scored "caught" off /race/i matching the
  // dependency `braces@2.3.2` in a lockfile — a different file AND a different rule.
  it("lets a predicate require the right rule AND the right file, so a same-file or same-word finding is not a catch", () => {
    const findings: ScorableFinding[] = [
      { taxonomy: "Known-vulnerable dependency", location: "package-lock.json (braces@2.3.2)" },
      { taxonomy: "harvey-route-noauth", location: "pages/api/counter/increment.js:4" },
    ];
    const bugs = [bug({ id: "COUNTER-RACE", matches: (f) => /increment\.js/.test(f.location) && /race|atomic/i.test(f.taxonomy) })];
    const [scored] = scoreCoverage(bugs, findings);
    expect(scored!.status).toBe("missed");
  });

  it("scores missed when the module ran but no finding matches — the interesting case, not a crash", () => {
    const findings: ScorableFinding[] = [{ taxonomy: "unrelated-finding", location: "package.json" }];
    const bugs = [bug({ id: "REPLAY", matches: () => false })];
    const [scored] = scoreCoverage(bugs, findings);
    expect(scored!.status).toBe("missed");
  });

  it("never scores caught off a moduleRan:false bug even if a finding would otherwise match", () => {
    const findings: ScorableFinding[] = [{ taxonomy: "rls_disabled_in_public", location: "public.audit_logs" }];
    const bugs = [bug({ id: "RLS-DISABLED", moduleRan: false, matches: (f) => f.location.includes("audit_logs") })];
    const [scored] = scoreCoverage(bugs, findings);
    expect(scored!.status).toBe("requires-live-run");
  });
});

describe("summarizeCoverage", () => {
  it("splits caught into asserted vs surfaced-for-review so a review catch is never a claimed verdict (#342)", () => {
    const bugs = [
      bug({ id: "A", moduleRan: false }),
      bug({ id: "B", moduleRan: true, matches: () => false }),
      bug({ id: "C-HIGH", moduleRan: true, matches: (f) => f.location === "hi" }),
      bug({ id: "D-REVIEW", moduleRan: true, matches: (f) => f.location === "rev" }),
    ];
    const scored = scoreCoverage(bugs, [
      { taxonomy: "x", location: "hi", precisionTier: "high" },
      { taxonomy: "y", location: "rev", precisionTier: "review" },
    ]);
    expect(summarizeCoverage(scored)).toEqual({
      asserted: 1,
      "surfaced-for-review": 1,
      missed: 1,
      "requires-live-run": 1,
    });
  });

  it("counts an untiered catch as surfaced-for-review, never asserted — the conservative direction", () => {
    const scored = scoreCoverage([bug({ id: "U", matches: () => true })], [{ taxonomy: "x", location: "y" }]);
    expect(summarizeCoverage(scored)).toEqual({ asserted: 0, "surfaced-for-review": 1, missed: 0, "requires-live-run": 0 });
  });
});
