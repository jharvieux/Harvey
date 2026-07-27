// #1315/#1316. The CLI (src/cli/validate-acceptance.ts) proves the WIRING against live `gh`; this
// file proves the LOGIC, by seeding each violation shape and asserting the gate fails on it. A gate
// nobody has watched fail is not evidence that it can — the repo has shipped that twice (#1246's
// five falsifiers that exited non-zero on a shell redirect, #1287's four alert paths).

import { describe, expect, it } from "vitest";
import {
  checkAcceptance,
  evidenceProblems,
  formatAcceptance,
  parseAcceptanceCriteria,
  parseBody,
  SELFTEST_BODY,
  SELFTEST_LOOKUP,
  seedBareEvidence,
  seedDropDisposition,
  seedRemainder,
  selftestCases,
  type IssueLookup,
  type IssueRecord,
} from "./acceptance-conservation.js";

const issue = (over: Partial<IssueRecord> & { number: number }): IssueRecord => ({
  state: "OPEN",
  body: "## Acceptance\n- first\n- second\n",
  comments: [],
  ...over,
});

const lookupOf = (...records: IssueRecord[]): IssueLookup => (n) => records.find((r) => r.number === n);

const problems = (body: string, lookup: IssueLookup): string[] => {
  const r = checkAcceptance(body, lookup);
  return [
    ...r.parseErrors,
    ...r.issues.flatMap((i) => [...i.problems, ...i.criteria.flatMap((c) => c.problems)]),
    ...r.remainders.flatMap((rm) => rm.conditions.filter((c) => c.status === "fail").map((c) => `${c.name}: ${c.detail}`)),
  ];
};

const BOTH_MET = "Closes #10\n\nACCEPTANCE #10.1 met: `pnpm verify` — 25 files, 0 failures\nACCEPTANCE #10.2 met: src/foo.ts:12 now throws\n";

describe("parseAcceptanceCriteria", () => {
  it("reads the bullets of an ## Acceptance section and stops at the next heading", () => {
    const { criteria, source } = parseAcceptanceCriteria("intro\n\n## Acceptance\n- one\n- two\n\n## Scope note\n- not a criterion\n");
    expect(criteria.map((c) => c.text)).toEqual(["one", "two"]);
    expect(source).toBe("acceptance-section");
  });

  it("counts a nested bullet as elaboration of its parent, and REPORTS that it did", () => {
    const { criteria, nestedFolded } = parseAcceptanceCriteria("## Acceptance\n- one\n  - detail of one\n- two\n");
    expect(criteria).toHaveLength(2);
    expect(nestedFolded).toBe(1);
  });

  it("falls back to a checklist when the issue has no Acceptance heading", () => {
    const { criteria, source } = parseAcceptanceCriteria("Do the thing.\n\n- [ ] ship it\n- [x] test it\n");
    expect(criteria.map((c) => c.text)).toEqual(["ship it", "test it"]);
    expect(source).toBe("checklist");
  });

  it("reports NO criteria for an issue that is prose only — the case where closing-unmet is easiest", () => {
    expect(parseAcceptanceCriteria("Please make the scanner faster.").source).toBe("none");
  });
});

describe("closing-keyword detection", () => {
  it("is negation-blind exactly as GitHub is — `## Does NOT close #1206` still closes #1206", () => {
    expect(parseBody("## Does NOT close #1206\n").closes).toEqual([1206]);
  });

  it("reads every closing keyword form GitHub honours", () => {
    expect(parseBody("Closes #1\nfixed #2\nResolve #3\ncloses: #4\n").closes).toEqual([1, 2, 3, 4]);
  });

  it("does not treat a bare cross-reference as a close", () => {
    expect(parseBody("part of #7, refs #8\n").closes).toEqual([]);
  });

  it("discloses a closing reference it cannot resolve rather than dropping it", () => {
    const r = checkAcceptance("Closes other/repo#5\n", lookupOf());
    expect(r.unresolvableCloses).toEqual(["other/repo#5"]);
    expect(formatAcceptance(r)).toContain("NOT ASSESSED");
  });
});

describe("Gate 1 — every acceptance bullet is mapped", () => {
  it("passes a body that maps every bullet with evidence", () => {
    expect(checkAcceptance(BOTH_MET, lookupOf(issue({ number: 10 }))).ok).toBe(true);
  });

  it("NEGATIVE CONTROL: a dropped disposition leaves an UNMAPPED bullet and fails", () => {
    const seeded = seedDropDisposition(BOTH_MET);
    expect(seeded.dropped).toContain("#10.2");
    expect(problems(seeded.body, lookupOf(issue({ number: 10 })))).toEqual([expect.stringContaining("UNMAPPED")]);
  });

  it("NEGATIVE CONTROL: a bare `done` is an unmapped bullet with a label on it", () => {
    const seeded = seedBareEvidence(BOTH_MET);
    expect(problems(seeded.body, lookupOf(issue({ number: 10 })))).toEqual([expect.stringContaining("bare assertion")]);
  });

  it("refuses a criterion mapped twice — one bullet takes exactly one disposition", () => {
    const body = `${BOTH_MET}ACCEPTANCE #10.2 met: src/bar.ts:4 also covers it\n`;
    expect(problems(body, lookupOf(issue({ number: 10 })))).toEqual([expect.stringContaining("mapped 2 times")]);
  });

  it("refuses a disposition naming a criterion the issue does not state", () => {
    const body = `${BOTH_MET}ACCEPTANCE #10.3 met: \`pnpm verify\` green\n`;
    expect(problems(body, lookupOf(issue({ number: 10 })))).toEqual([expect.stringContaining("but #10 states 2")]);
  });

  it("reports a malformed ACCEPTANCE line instead of silently ignoring it", () => {
    const body = "Closes #10\n\nACCEPTANCE #10.1 done: whatever\nACCEPTANCE #10.2 met: src/foo.ts:1\n";
    expect(problems(body, lookupOf(issue({ number: 10 })))).toEqual([
      expect.stringContaining("malformed ACCEPTANCE line"),
      expect.stringContaining("UNMAPPED"),
    ]);
  });

  it("ignores the unfilled `#<issue>` placeholders the PR template leaves in the raw body", () => {
    const body = `${BOTH_MET}<!-- ACCEPTANCE #<issue>.<n> met: <evidence> -->\n`;
    expect(checkAcceptance(body, lookupOf(issue({ number: 10 }))).ok).toBe(true);
  });

  it("fails a closing keyword pointing at an issue that does not exist", () => {
    expect(problems("Closes #404\n", lookupOf())).toEqual([expect.stringContaining("#404 does not exist")]);
  });
});

describe("Gate 1 — an issue with no stated criteria", () => {
  const prose = issue({ number: 20, body: "Make the intake form stop 503ing." });

  it("fails rather than passing silently — an empty criteria set is not a met bar", () => {
    expect(problems("Closes #20\n", lookupOf(prose))).toEqual([expect.stringContaining("states no acceptance criteria")]);
  });

  it("passes when the PR declares what the bar was", () => {
    const body = "Closes #20\n\nACCEPTANCE #20 no-stated-criteria: the bar was the production form returning 200 to a live submission\n";
    expect(checkAcceptance(body, lookupOf(prose)).ok).toBe(true);
  });

  it("refuses the escape hatch on an issue that DOES state criteria", () => {
    const body = `${BOTH_MET}ACCEPTANCE #10 no-stated-criteria: there was no real bar here\n`;
    expect(problems(body, lookupOf(issue({ number: 10 })))).toEqual([expect.stringContaining("declares `no-stated-criteria` but the issue states 2")]);
  });
});

describe("Gate 1 — `relayed` requires the question to be on the issue", () => {
  const body = "Closes #30\n\nACCEPTANCE #30.1 relayed: needs an operator ruling on the supervised path\nACCEPTANCE #30.2 met: src/foo.ts:9\n";

  it("fails when the issue carries no question — a question only in the PR body is a question nobody was asked", () => {
    expect(problems(body, lookupOf(issue({ number: 30 })))).toEqual([expect.stringContaining("carries no comment containing a question")]);
  });

  it("passes when the question is recorded on the issue itself", () => {
    expect(checkAcceptance(body, lookupOf(issue({ number: 30, comments: ["Operator: may I edit the workflow file?"] }))).ok).toBe(true);
  });
});

describe("evidence, not assertion", () => {
  it("accepts a command, a file path, a quoted test name and a sha", () => {
    for (const detail of [
      "`pnpm exec tsx src/cli/validate-acceptance.ts --selftest` exits 0",
      "src/acceptance-conservation.ts:120",
      'the test "a dropped disposition leaves an UNMAPPED bullet"',
      "landed in 5304d8e, see the diff",
    ]) {
      expect(evidenceProblems(detail)).toEqual([]);
    }
  });

  it("rejects the assertions that closed issues in the audit", () => {
    for (const detail of ["done", "Done.", "verified", "yes", "implemented", "works"]) {
      expect(evidenceProblems(detail)).toHaveLength(1);
    }
  });

  it("rejects a long sentence that still points at nothing checkable", () => {
    expect(evidenceProblems("this was handled as part of the broader refactor")).toEqual([expect.stringContaining("names none of")]);
  });
});

describe("Gate 2 — remainder liveness", () => {
  const original = issue({ number: 40, body: "## Acceptance\n- one\n", comments: ["Remainder filed as #41."] });

  it("passes a split whose remainder exists, is OPEN and is cross-linked from the original", () => {
    const body = "Closes #40\n\nACCEPTANCE #40.1 split: #41\n";
    expect(checkAcceptance(body, lookupOf(original, issue({ number: 41 }))).ok).toBe(true);
  });

  it("NEGATIVE CONTROL: a remainder pointing at a CLOSED issue fails — the #715 → #161 shape", () => {
    const body = seedRemainder("Closes #40\n\nACCEPTANCE #40.1 met: src/foo.ts:1\n", 41);
    const closed = issue({ number: 41, state: "CLOSED" });
    expect(problems(body, lookupOf(original, closed))).toEqual([expect.stringContaining("is CLOSED")]);
  });

  it("NEGATIVE CONTROL: a remainder pointing at a nonexistent issue fails", () => {
    const body = seedRemainder("Closes #40\n\nACCEPTANCE #40.1 met: src/foo.ts:1\n", 9999);
    expect(problems(body, lookupOf(original))).toEqual([expect.stringContaining("#9999 does not exist")]);
  });

  it("fails when the original never cross-links the remainder — the deferral is discoverable only from the PR", () => {
    const body = "Closes #40\n\nACCEPTANCE #40.1 split: #41\n";
    const uncrosslinked = issue({ number: 40, body: "## Acceptance\n- one\n" });
    expect(problems(body, lookupOf(uncrosslinked, issue({ number: 41 })))).toEqual([expect.stringContaining("references #41")]);
  });

  it("reports ALL THREE conditions separately, not merely that one failed", () => {
    const body = "Closes #40\n\nACCEPTANCE #40.1 split: #41\n";
    const r = checkAcceptance(body, lookupOf(original, issue({ number: 41, state: "CLOSED" })));
    const conditions = r.remainders[0]!.conditions;
    expect(conditions.map((c) => [c.name, c.status])).toEqual([["exists", "pass"], ["open", "fail"], ["cross-linked", "pass"]]);
  });

  it("refuses a split that names no remainder at all — a split with no remainder is a deletion", () => {
    const body = "Closes #40\n\nACCEPTANCE #40.1 split: deferred for now\n";
    expect(problems(body, lookupOf(original))).toEqual([expect.stringContaining("names no remainder issue")]);
  });

  it("checks a bare `remainder:` line even on a PR that closes nothing, and does not invent an original", () => {
    const r = checkAcceptance("remainder: #41\n", lookupOf(issue({ number: 41, state: "CLOSED" })));
    expect(r.noop).toBe(false);
    expect(r.remainders[0]!.conditions.map((c) => c.status)).toEqual(["pass", "fail", "not-assessed"]);
  });
});

describe("the green no-op", () => {
  it("passes a PR that closes nothing and defers nothing — the gate must report on every PR", () => {
    const r = checkAcceptance("A docs tidy-up. Refs #12.\n", lookupOf());
    expect(r.noop).toBe(true);
    expect(r.ok).toBe(true);
    expect(formatAcceptance(r)).toContain("no closing keyword");
  });
});

describe("the hermetic self-test CI runs", () => {
  it("scores exactly as the CLI's --selftest asserts, so CI and `pnpm verify` share one fixture", () => {
    for (const c of selftestCases()) {
      expect(checkAcceptance(c.body, SELFTEST_LOOKUP).ok, c.name).toBe(c.expect === "pass");
    }
  });

  it("covers a healthy case and at least three distinct seeded violations", () => {
    const cases = selftestCases();
    expect(cases.filter((c) => c.expect === "pass")).toHaveLength(1);
    expect(cases.filter((c) => c.expect === "fail").length).toBeGreaterThanOrEqual(3);
  });
});

describe("the seeders fail loud rather than planting nothing", () => {
  it("throws when there is no disposition line to drop", () => {
    expect(() => seedDropDisposition("Closes #1\n")).toThrow(/no .*disposition line/);
  });

  it("throws when there is no `met` to hollow out", () => {
    expect(() => seedBareEvidence(SELFTEST_BODY.replace("met:", "split: #9002 —"))).toThrow(/no `met` disposition/);
  });
});
