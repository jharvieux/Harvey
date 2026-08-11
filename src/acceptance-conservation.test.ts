// #1315/#1316. The CLI (src/cli/validate-acceptance.ts) proves the WIRING against live `gh`; this
// file proves the LOGIC, by seeding each violation shape and asserting the gate fails on it. A gate
// nobody has watched fail is not evidence that it can — the repo has shipped that twice (#1246's
// five falsifiers that exited non-zero on a shell redirect, #1287's four alert paths).

import { describe, expect, it } from "vitest";
import {
  checkAcceptance,
  evidenceProblems,
  issueDoesNotExist,
  formatAcceptance,
  parseAcceptanceCriteria,
  parseBody,
  SELFTEST_BODY,
  SELFTEST_LOOKUP,
  SELFTEST_WORLD,
  seedBareEvidence,
  seedDropDisposition,
  seedRemainder,
  selftestCases,
  checkClosedIssue,
  closeActions,
  closeFailureComment,
  closeSelftestCases,
  formatClosedIssue,
  type IssueLookup,
  type IssueComment,
  type IssueRecord,
} from "./acceptance-conservation.js";

// `comments` takes plain strings here and is normalised, so the ~16 fixtures below stay readable
// after #1603 gave every comment a permalink for the superseding-bar flag to name.
const issue = (over: Partial<Omit<IssueRecord, "comments">> & { number: number; comments?: (string | IssueComment)[] }): IssueRecord => ({
  state: "OPEN",
  body: "## Acceptance\n- first\n- second\n",
  ...over,
  comments: (over.comments ?? []).map((c) => (typeof c === "string" ? { body: c, url: `https://example.invalid/#c${c.length}` } : c)),
});

/** Same-repo records only; the `crossRepo` lookup in "holds a cross-repo issue to its own acceptance criteria" is the one that distinguishes the repo. */
const lookupOf = (...records: IssueRecord[]): IssueLookup => (n, repo) => (repo ? undefined : records.find((r) => r.number === n));

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

  it("NEGATIVE CONTROL: a standalone bold line does NOT end the section — it used to drop the rest silently", () => {
    const { criteria, nestedFolded } = parseAcceptanceCriteria("## Acceptance\n- one\n\n**This one matters.**\n\n- two\n- three\n");
    expect(criteria.map((c) => c.text)).toEqual(["one", "two", "three"]);
    expect(nestedFolded).toBe(0);
  });

  it("NEGATIVE CONTROL: a `###` sub-heading does not end the section either", () => {
    expect(parseAcceptanceCriteria("## Acceptance\n- one\n\n### Sub\n\n- two\n- three\n").criteria).toHaveLength(3);
  });

  it("still ends the section at a heading AT OR ABOVE the acceptance heading's level", () => {
    expect(parseAcceptanceCriteria("### Acceptance\n- one\n\n## Scope\n- not a criterion\n").criteria).toHaveLength(1);
    expect(parseAcceptanceCriteria("# Acceptance\n- one\n\n# Scope\n- not a criterion\n").criteria).toHaveLength(1);
  });

  it("ends a BOLD acceptance heading at the next bold line — that convention has no levels to compare", () => {
    expect(parseAcceptanceCriteria("**Acceptance**\n- one\n\n**Scope note**\n- not a criterion\n").criteria).toHaveLength(1);
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
  const numbers = (body: string, repo?: string): number[] => parseBody(body, repo).closes.map((c) => c.number);

  it("is negation-blind exactly as GitHub is — `## Does NOT close #1206` still closes #1206", () => {
    expect(numbers("## Does NOT close #1206\n")).toEqual([1206]);
  });

  it("reads every closing keyword form GitHub honours", () => {
    expect(numbers("Closes #1\nfixed #2\nResolve #3\ncloses: #4\n")).toEqual([1, 2, 3, 4]);
  });

  it("does not treat a bare cross-reference as a close", () => {
    expect(numbers("part of #7, refs #8\n")).toEqual([]);
  });

  // The gate used to print `NOT ASSESSED` here. `gh issue view 2196 --repo OWASP/CheatSheetSeries`
  // exits 0 (measured 2026-07-27), so being repo-scoped was a property of the LOOKUP, not of the
  // reference — the #1320 bounds audit falsified the recorded limitation.
  it("resolves a cross-repo closing reference to its owner and number", () => {
    expect(parseBody("Closes other/repo#5\n").closes).toEqual([{ repo: "other/repo", number: 5, ref: "other/repo#5" }]);
  });

  it("resolves a URL-form closing reference", () => {
    expect(parseBody("Fixes https://github.com/other/repo/issues/9\n").closes)
      .toEqual([{ repo: "other/repo", number: 9, ref: "https://github.com/other/repo/issues/9" }]);
  });

  it("normalises a cross-repo form naming THIS repo, so one issue is not fetched and reported twice", () => {
    expect(parseBody("Closes #5\nalso closes owner/harvey#5\n", "owner/harvey").closes).toHaveLength(1);
  });

  it("holds a cross-repo issue to its own acceptance criteria", () => {
    const crossRepo: IssueLookup = (n, repo) =>
      repo === "other/repo" && n === 5 ? issue({ number: 5 }) : undefined;
    const r = checkAcceptance("Closes other/repo#5\n\nACCEPTANCE #5.1 met: src/foo.ts:12 now throws\n", crossRepo);
    expect(formatAcceptance(r)).toContain("other/repo#5");
    expect(problems("Closes other/repo#5\n", crossRepo)).toEqual([
      expect.stringContaining("UNMAPPED"),
      expect.stringContaining("UNMAPPED"),
    ]);
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

// #1753 — completing a relay used to CREATE a duplicate: the executor's `relayed` and the
// completing `met` are both live, the criterion maps twice, and clearing it took hand-neutralising
// the older line (three round trips on PR #1700). One lone `met`/`split` over one lone `relayed`
// is that flow working, so it resolves to the completing line; every other multiple mapping stays
// a duplicate, which is this rule's own failing direction.
describe("Gate 1 — completing a relay supersedes the `relayed` line (#1753)", () => {
  const relayedInComment = issue({
    number: 40,
    comments: ["Operator: may I apply the supervised edit? Proposed wording below.", "ACCEPTANCE #40.1 relayed: supervised path — the question is in the comment above"],
  });
  const completed = "Closes #40\n\nACCEPTANCE #40.1 met: src/foo.ts:9 now carries the ruled edit\nACCEPTANCE #40.2 met: src/bar.ts:4 covers it\n";

  it("passes a `met` recorded over an earlier `relayed`, and reports which line it retired", () => {
    const r = checkAcceptance(completed, lookupOf(relayedInComment));
    expect(r.ok).toBe(true);
    expect(r.issues[0]!.criteria[0]!.disposition).toBe("met");
    expect(r.issues[0]!.criteria[0]!.superseded).toEqual({
      venue: "#40 comment 2",
      line: 1,
      detail: expect.stringContaining("supervised path"),
      by: {
        venue: "the PR body",
        line: 3,
        disposition: "met",
        detail: expect.stringContaining("src/foo.ts:9"),
      },
    });
    const out = formatAcceptance(r);
    expect(out).toContain("RELAY COMPLETED (#1753)");
    expect(out).toContain("#40 comment 2, line 1");
  });

  it("passes a `split` over a `relayed` — both completions supersede", () => {
    const body = "Closes #40\n\nACCEPTANCE #40.1 split: #41\nACCEPTANCE #40.2 met: src/bar.ts:4 covers it\n";
    const withRemainder = lookupOf(
      issue({ number: 40, comments: [...relayedInComment.comments, "Remainder of the ruled half split out to #41."] }),
      issue({ number: 41, body: "Remainder of #40." }),
    );
    const r = checkAcceptance(body, withRemainder);
    expect(r.ok).toBe(true);
    expect(r.issues[0]!.criteria[0]!.disposition).toBe("split");
    expect(r.issues[0]!.criteria[0]!.superseded).toBeDefined();
  });

  // Direction is fixed by TYPE because the venues carry no comparable timestamps: whichever line
  // was written first, a `relayed` never displaces a `met`/`split`.
  it("resolves to the `met` in the REVERSE venue arrangement too — a `relayed` never wins over a completion", () => {
    const metInComment = issue({ number: 40, comments: ["Operator ruled: yes, apply it.", "ACCEPTANCE #40.1 met: src/foo.ts:9 now carries the ruled edit"] });
    const body = "Closes #40\n\nACCEPTANCE #40.1 relayed: asked on the issue — may I apply the edit?\nACCEPTANCE #40.2 met: src/bar.ts:4 covers it\n";
    const r = checkAcceptance(body, lookupOf(metInComment));
    expect(r.ok).toBe(true);
    expect(r.issues[0]!.criteria[0]!.disposition).toBe("met");
  });

  it("does not apply the question-on-the-issue rule to a superseded `relayed` — the relay is over", () => {
    // No comment on #40 contains a question mark, so a LONE `relayed` fails; superseded, it does not.
    const noQuestion = issue({ number: 40, comments: ["ACCEPTANCE #40.1 relayed: supervised path, wording proposed in the PR"] });
    expect(checkAcceptance(completed, lookupOf(noQuestion)).ok).toBe(true);
    const lone = "Closes #40\n\nACCEPTANCE #40.2 met: src/bar.ts:4 covers it\n";
    expect(problems(lone, lookupOf(noQuestion))).toEqual([expect.stringContaining("carries no comment containing a question")]);
  });

  it("NEGATIVE CONTROL: holds the superseding `met` to the evidence bar — completing a relay is not a free pass", () => {
    const bare = "Closes #40\n\nACCEPTANCE #40.1 met: done\nACCEPTANCE #40.2 met: src/bar.ts:4 covers it\n";
    expect(problems(bare, lookupOf(relayedInComment))).toEqual([expect.stringContaining("bare assertion")]);
  });

  it("NEGATIVE CONTROL: two `relayed` lines are a repeat paste, not a completion — still a duplicate", () => {
    const twice = "Closes #40\n\nACCEPTANCE #40.1 relayed: recorded a second time\nACCEPTANCE #40.2 met: src/bar.ts:4 covers it\n";
    expect(problems(twice, lookupOf(relayedInComment))).toEqual([expect.stringContaining("mapped 2 times")]);
  });

  it("NEGATIVE CONTROL: `met` over `met` still fails, and the duplicate message names the one exception", () => {
    const metTwice = issue({ number: 40, comments: ["ACCEPTANCE #40.1 met: src/foo.ts:9 also covers it"] });
    const p = problems(completed, lookupOf(metTwice));
    expect(p).toEqual([expect.stringContaining("mapped 2 times")]);
    expect(p[0]).toContain("COMPLETED RELAY");
  });

  it("NEGATIVE CONTROL: three lines — `relayed` plus two completions — are still a duplicate", () => {
    const three = issue({
      number: 40,
      comments: [...relayedInComment.comments, "ACCEPTANCE #40.1 met: src/foo.ts:9 also covers it"],
    });
    expect(problems(completed, lookupOf(three))).toEqual([expect.stringContaining("mapped 3 times")]);
  });
});

describe("Gate 1 — an operator can terminally disposition an unmet criterion (#1791)", () => {
  const relayedInComment = issue({
    number: 40,
    comments: [
      "Operator: may I apply the supervised edit? Proposed wording below.",
      "ACCEPTANCE #40.1 relayed: supervised path — the question is in the comment above",
    ],
  });
  const terminal = "Closes #40\n\nACCEPTANCE #40.1 ruled-unmet: operator @jharvieux — the supervised edit was declined and the criterion is retired\nACCEPTANCE #40.2 met: src/bar.ts:4 covers it\n";

  it("counts an attributed `ruled-unmet` as dispositioned and keeps the criterion explicitly NOT delivered", () => {
    const r = checkAcceptance(terminal, lookupOf(issue({ number: 40 })));
    expect(r.ok).toBe(true);
    expect(r.issues[0]!.criteria[0]!.disposition).toBe("ruled-unmet");
    expect(r.issues[0]!.criteria.filter((c) => c.disposition === "met")).toHaveLength(1);
    const out = formatAcceptance(r);
    expect(out).toContain("40.1 [ruled-unmet]");
    expect(out).toContain("explicitly NOT DELIVERED");
  });

  it("supersedes one earlier `relayed` and reports terminal retirement rather than completion", () => {
    const r = checkAcceptance(terminal, lookupOf(relayedInComment));
    expect(r.ok).toBe(true);
    expect(r.issues[0]!.criteria[0]!.superseded).toEqual({
      venue: "#40 comment 2",
      line: 1,
      detail: expect.stringContaining("supervised path"),
      by: {
        venue: "the PR body",
        line: 3,
        disposition: "ruled-unmet",
        detail: expect.stringContaining("operator @jharvieux"),
      },
    });
    const out = formatAcceptance(r);
    expect(out).toContain("RELAY TERMINATED AS RULED-UNMET (#1791)");
    expect(out).toContain("criterion remains NOT DELIVERED");
    expect(out).not.toContain("RELAY COMPLETED (#1753): this `ruled-unmet`");
  });

  it("NEGATIVE CONTROL: refuses a ruling with no machine-checkable operator attribution", () => {
    const body = terminal.replace("operator @jharvieux — ", "");
    expect(problems(body, lookupOf(relayedInComment))).toEqual([expect.stringContaining("operator @<login>")]);
  });

  it("NEGATIVE CONTROL: refuses an attributed ruling that says nothing substantive", () => {
    const body = terminal.replace("the supervised edit was declined and the criterion is retired", "no");
    expect(problems(body, lookupOf(relayedInComment))).toEqual([expect.stringContaining("ruling of 2 characters")]);
  });

  it("NEGATIVE CONTROL: does not let `ruled-unmet` silently win over a `met` without a relay", () => {
    const metInComment = issue({ number: 40, comments: ["ACCEPTANCE #40.1 met: src/foo.ts:9 already delivered it"] });
    expect(problems(terminal, lookupOf(metInComment))).toEqual([expect.stringContaining("mapped 2 times")]);
  });

  it("NEGATIVE CONTROL: three lines remain a duplicate even when one is the earlier relay", () => {
    const three = issue({
      number: 40,
      comments: [...relayedInComment.comments, "ACCEPTANCE #40.1 met: src/foo.ts:9 also delivered it"],
    });
    expect(problems(terminal, lookupOf(three))).toEqual([expect.stringContaining("mapped 3 times")]);
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

  it("NEGATIVE CONTROL: English words spelt in hex letters are not a commit sha", () => {
    // "defaced", "accede" and "facade" are drawn entirely from [a-f]; the shape used to accept them.
    expect(evidenceProblems("defaced accede facade nonsense words")).toEqual([expect.stringContaining("names none of")]);
  });

  it("NEGATIVE CONTROL: a long number is not a commit sha", () => {
    expect(evidenceProblems("run 90131391124 was green")).toEqual([expect.stringContaining("names none of")]);
  });

  it("still accepts a real sha, which mixes digits and hex letters", () => {
    expect(evidenceProblems("fixed in d57ab0a on main")).toEqual([]);
    expect(evidenceProblems("landed in 5304d8e, see the diff")).toEqual([]);
  });

  it("NEGATIVE CONTROL: backticking a phrase of plain English does not make it a command", () => {
    expect(evidenceProblems("I confirmed this by hand: `all good`")).toEqual([expect.stringContaining("names none of")]);
  });

  it("still accepts a backticked flag, path or identifier, and a two-word command by its name", () => {
    for (const detail of ["`--seed-bare-evidence` exits 1", "the fix is in `formatAcceptance`, see the diff", "`pnpm verify` — 25 files, 0 failures"]) {
      expect(evidenceProblems(detail)).toEqual([]);
    }
  });
});

// The gate shipped asserting it "cannot tell a real command from an invented one" — true only of
// the shapes it never checked. Measured over the last 60 merged PRs' `met` lines (#1320 bounds
// audit, 2026-07-27): 16/16 cited repo paths exist, 3/3 `pnpm <script>` names are real scripts,
// 6/9 quoted spans are real test titles, and `"it all looks great"` is none of them.
describe("evidence checked for TRUTH, not only shape", () => {
  const world = {
    topLevelEntries: new Set(["src", "docs"]),
    pathExists: (p: string) => ["src/acceptance-conservation.ts", "src/cli/validate-acceptance.ts", "src/scan/config.json"].includes(p),
    scripts: new Set(["verify", "validate-reasons"]),
    testNames: new Set(["a dropped disposition leaves an UNMAPPED bullet"]),
  };

  it("NEGATIVE CONTROL: a cited repo path that does not exist is evidence pointing at nothing", () => {
    expect(evidenceProblems("src/invented-module.ts:12 now throws", world)).toEqual([
      expect.stringContaining("does not exist in this checkout"),
    ]);
  });

  it("NEGATIVE CONTROL: `pnpm <script>` naming no script in package.json is an invented command", () => {
    expect(evidenceProblems("`pnpm validate-everything` — all green", world)).toEqual([
      expect.stringContaining("not a script in package.json"),
    ]);
  });

  it("NEGATIVE CONTROL: a quoted sentence is not a quoted test name once the suite can be asked", () => {
    expect(evidenceProblems('the reviewer said "it all looks great" about this', world)).toEqual([
      expect.stringContaining("names none of"),
    ]);
    // The doc's own example passes the shape-only floor, which is why it was disclosed as loose.
    expect(evidenceProblems('the reviewer said "it all looks great" about this')).toEqual([]);
  });

  it("accepts the real thing on all three: an existing path, a real script, a real test title", () => {
    for (const detail of [
      "src/acceptance-conservation.ts:120",
      "`pnpm verify` — 25 files, 0 failures",
      'the test "a dropped disposition leaves an UNMAPPED bullet"',
    ]) {
      expect(evidenceProblems(detail, world)).toEqual([]);
    }
  });

  // #1266's PR hit this for real: a `.json` citation was reported as pointing at a nonexistent
  // `.js` file, because FILE_PATH's extension alternation is first-match, not longest-match, and
  // `js` was listed before `json` (a prefix of it) — same risk for `ts`/`tsx`.
  it("NEGATIVE CONTROL (#1266): a cited .json path is not truncated to a nonexistent .js path", () => {
    expect(evidenceProblems("regenerated `src/scan/config.json`", world)).toEqual([]);
  });

  // #1400. Ordering fixed `.json` one pair at a time and left `.jsx` and `.mdx` truncating; the
  // `(?!\w)` boundary fixes the class. Both directions per extension on purpose: a fix that made
  // every `.json`/`.jsx` citation pass unconditionally would hide the check's actual job.
  describe("an extension that is a PREFIX of another is neither truncated nor waved through (#1400)", () => {
    const extWorld = {
      ...world,
      topLevelEntries: new Set(["src", "docs", "dry-run", "targets"]),
      pathExists: (p: string) =>
        [
          "dry-run/findings.json",
          "src/Panel.tsx",
          "targets/calibration/components/AdminPanel.jsx",
          "docs/design/ruling.mdx",
          "docs/design/ruling.md",
          "src/scan/rules.yaml",
          "src/scan/rules.yml",
        ].includes(p),
    };

    for (const [ext, real, fake] of [
      ["json", "dry-run/findings.json", "dry-run/invented.json"],
      ["tsx", "src/Panel.tsx", "src/Invented.tsx"],
      ["jsx", "targets/calibration/components/AdminPanel.jsx", "targets/calibration/components/Invented.jsx"],
      ["mdx", "docs/design/ruling.mdx", "docs/design/invented.mdx"],
      ["yaml", "src/scan/rules.yaml", "src/scan/invented.yaml"],
      ["yml", "src/scan/rules.yml", "src/scan/invented.yml"],
    ] as const) {
      it(`a real .${ext} citation passes and a fake one still fails`, () => {
        expect(evidenceProblems(`the file \`${real}\` carries the change`, extWorld), real).toEqual([]);
        expect(evidenceProblems(`the file \`${fake}\` carries the change`, extWorld), fake).toEqual([
          expect.stringContaining(`\`${fake}\`, which does not exist`),
        ]);
      });
    }
  });

  it("leaves a path outside this repo's top level alone rather than failing on a foreign tree", () => {
    expect(evidenceProblems("upstream/lib/parser.ts:44 is the culprit", world)).toEqual([]);
  });

  it("does not read `pnpm exec <binary>` as a script name", () => {
    expect(evidenceProblems("`pnpm exec tsx src/cli/validate-acceptance.ts --selftest` exits 0", world)).toEqual([]);
  });

  // The over-refusal these fix: the old shape read the next token after `pnpm` as a script name
  // whatever it was, so a correct workspace command was reported to its author as an invention.
  it("NEGATIVE CONTROL: a flag is not a script name, and a workspace command is not an invention", () => {
    for (const detail of [
      "`pnpm --filter site build` — 0 errors",
      "`pnpm -F site build` — 0 errors",
      "`pnpm -r build` across the workspace",
      "`pnpm i` then `pnpm verify` — green",
    ]) {
      expect(evidenceProblems(detail, world), detail).toEqual([]);
    }
  });

  it("NEGATIVE CONTROL: prose mentioning pnpm is not a script reference", () => {
    expect(evidenceProblems("ran pnpm and it worked, see src/acceptance-conservation.ts:1", world)).toEqual([]);
  });

  it("SCOPE CONTROL: a genuinely invented script inside backticks still fails", () => {
    expect(evidenceProblems("`pnpm --silent validate-everything` — all green", world)).toEqual([
      expect.stringContaining("not a script in package.json"),
    ]);
  });

  // 2 of the 9 quoted spans measured over the last 60 merged PRs are real titles truncated at the
  // title's em-dash; exact set membership scored both as misses.
  it("counts a quoted span that is a real test title truncated at the em-dash", () => {
    const truncating = { ...world, testNames: new Set(["NEGATIVE CONTROL: a remainder pointing at a CLOSED issue fails — the #715 → #161 shape"]) };
    expect(evidenceProblems('the test "NEGATIVE CONTROL: a remainder pointing at a CLOSED issue fails"', truncating)).toEqual([]);
  });

  it("NEGATIVE CONTROL: prefix tolerance does not accept a quote that no title starts with", () => {
    const truncating = { ...world, testNames: new Set(["NEGATIVE CONTROL: a remainder pointing at a CLOSED issue fails — the #715 → #161 shape"]) };
    expect(evidenceProblems('the reviewer said "a remainder pointing at a CLOSED issue"', truncating)).toEqual([
      expect.stringContaining("names none of"),
    ]);
  });
});

describe("a closing reference this gate cannot resolve is disclosed, not thrown", () => {
  const MALFORMED = "Closes https://github.com/orgs/acme/projects/1/issues/5\n";

  it("NEGATIVE CONTROL: an issue URL with extra path segments no longer kills the run", () => {
    expect(() => parseBody(MALFORMED)).not.toThrow();
    expect(parseBody(MALFORMED)).toMatchObject({ closes: [], unresolvedCloses: ["https://github.com/orgs/acme/projects/1/issues/5"] });
  });

  it("prints a NOT ASSESSED row rather than reporting a green no-op", () => {
    const r = checkAcceptance(MALFORMED, lookupOf());
    expect(r.noop).toBe(false);
    const out = formatAcceptance(r);
    expect(out).toContain("ℹ NOT ASSESSED  closing reference `https://github.com/orgs/acme/projects/1/issues/5`");
    expect(out).not.toContain("carries no closing keyword");
  });

  it("still resolves the three forms GitHub honours, so the disclosure is not a catch-all", () => {
    expect(parseBody("Closes #5\nFixes owner/repo#6\nResolves https://github.com/owner/repo/issues/7\n").unresolvedCloses).toEqual([]);
  });
});

// `undefined` from a lookup means DOES NOT EXIST. The cross-repo work widened the CLI's sentinel to
// `repository`, which reports a repo the token cannot READ as one that does not EXIST.
describe("issueDoesNotExist — the only gh failure that may become `does not exist`", () => {
  it("reads an issue that resolved to nothing", () => {
    expect(issueDoesNotExist("GraphQL: Could not resolve to an Issue with the number of 99999. (repository.issue)")).toBe(true);
  });

  it("NEGATIVE CONTROL: a repository that does not resolve is UNREADABLE, not absent", () => {
    expect(issueDoesNotExist("GraphQL: Could not resolve to a Repository with the name 'acme/private'. (repository)")).toBe(false);
  });

  it("NEGATIVE CONTROL: an auth failure is not an absent issue either", () => {
    expect(issueDoesNotExist("gh: To use GitHub CLI in a GitHub Actions workflow, set the GH_TOKEN environment variable")).toBe(false);
  });

  it("says so when no checkout was supplied, rather than looking like a verified run", () => {
    const r = checkAcceptance("Closes #10\n\nACCEPTANCE #10.1 met: src/nope.ts:1\nACCEPTANCE #10.2 met: src/nope.ts:2\n", lookupOf(issue({ number: 10 })));
    expect(r.evidenceVerified).toBe(false);
    expect(formatAcceptance(r)).toContain("checked for SHAPE only");
  });
});

describe("Gate 2 — remainder liveness", () => {
  const original = issue({ number: 40, body: "## Acceptance\n- one\n", comments: ["Remainder filed as #41."] });

  it("passes a split whose remainder exists, is OPEN and is cross-linked from the original", () => {
    const body = "Closes #40\n\nACCEPTANCE #40.1 split: #41\n";
    expect(checkAcceptance(body, lookupOf(original, issue({ number: 41 }))).ok).toBe(true);
  });

  it("ignores inline-quoted issue references when harvesting a split remainder (#1788)", () => {
    const quotedRule = issue({
      number: 40,
      body: "## Acceptance\n- one\n",
      comments: ["Remainder filed as #1900."],
    });
    const body = "Closes #40\n\nACCEPTANCE #40.1 split: quoted gate output `RELAY COMPLETED (#1753)`; remainder filed as #1900\n";
    const r = checkAcceptance(body, lookupOf(quotedRule, issue({ number: 1753, state: "CLOSED" }), issue({ number: 1900 })));

    expect(r.ok).toBe(true);
    expect(r.remainders.map((remainder) => remainder.remainder)).toEqual([1900]);
  });

  it("treats an inline-quoted #N with no prose target as a numberless split", () => {
    const body = "Closes #40\n\nACCEPTANCE #40.1 split: quoted gate output `RELAY COMPLETED (#1753)` only\n";

    expect(problems(body, lookupOf(original, issue({ number: 1753 })))).toEqual([
      expect.stringContaining("names no remainder issue"),
    ]);
  });

  it("NEGATIVE CONTROL: still checks a genuinely wrong prose split target", () => {
    const wrong = issue({ number: 40, body: "## Acceptance\n- one\n", comments: ["Remainder filed as #1900."] });
    const body = "Closes #40\n\nACCEPTANCE #40.1 split: quoted `#1753`; remainder filed as #1900\n";

    expect(problems(body, lookupOf(wrong, issue({ number: 1900, state: "CLOSED" })))).toEqual([
      expect.stringContaining("#1900 is CLOSED"),
    ]);
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

  // PINS THE DISCLOSED BOUND, and is the falsifier for the reason block beside `checkRemainder`:
  // when a rule lands that refuses the #1316 → #1260 shape, this test FAILS and the falsifier exits
  // 0, which is the signal the recorded bound has outlived its truth. Do not "fix" it by loosening
  // the assertion — replace it with the tighter rule's own control.
  it("a historical aside satisfies cross-linked — the bound Gate 2 discloses, pinned so it cannot change silently", () => {
    const aside = issue({ number: 40, body: "## Acceptance\n- one\n\nRecovered only by this audit, 16 days later, as #41.\n" });
    const r = checkAcceptance("Closes #40\n\nACCEPTANCE #40.1 split: #41\n", lookupOf(aside, issue({ number: 41 })));
    expect(r.remainders[0]!.conditions.find((c) => c.name === "cross-linked")!.status).toBe("pass");
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

  it("does not report a numberless split as `no split disposition` — that reads as nothing deferred", () => {
    const out = formatAcceptance(checkAcceptance("Closes #40\n\nACCEPTANCE #40.1 split: deferred for now\n", lookupOf(original)));
    expect(out).toContain("1 `split` disposition(s) name no issue number");
    expect(out).not.toContain("no `remainder:` line and no `split` disposition");
  });

  it("names the DEFERRAL as the failure when the only fault is a dead remainder", () => {
    const body = seedRemainder("Closes #40\n\nACCEPTANCE #40.1 met: src/foo.ts:1\n", 41);
    const out = formatAcceptance(checkAcceptance(body, lookupOf(original, issue({ number: 41, state: "CLOSED" }))));
    expect(out).toContain("a deferral points at an issue that is closed or does not exist");
    expect(out).not.toContain("a criterion this PR did not account for");
  });

  it("names BOTH halves when a criterion is unmapped and a remainder is dead", () => {
    const body = seedRemainder("Closes #40\n", 41);
    const out = formatAcceptance(checkAcceptance(body, lookupOf(original, issue({ number: 41, state: "CLOSED" }))));
    expect(out).toContain("a criterion this PR did not account for; and a deferral points at an issue");
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
    // A green run has to say WHY it was green: an unexplained pass is indistinguishable from a
    // check that did nothing because it was broken.
    expect(formatAcceptance(r)).toContain("Gate 1 (acceptance criteria, #1315): NO-OP");
    expect(formatAcceptance(r)).toContain("Gate 2 (remainder liveness, #1316): NO-OP");
  });

  it("states each gate's relevance separately — one may be in scope while the other is not", () => {
    const out = formatAcceptance(checkAcceptance(BOTH_MET, lookupOf(issue({ number: 10 }))));
    expect(out).toContain("Gate 1 (acceptance criteria, #1315): 1 closing reference(s) — #10.");
    expect(out).toContain("Gate 2 (remainder liveness, #1316): NO-OP");
  });
});

describe("the hermetic self-test CI runs", () => {
  it("scores exactly as the CLI's --selftest asserts, so CI and `pnpm verify` share one fixture", () => {
    for (const c of selftestCases()) {
      expect(checkAcceptance(c.body, SELFTEST_LOOKUP, undefined, SELFTEST_WORLD, c.extras).ok, c.name).toBe(c.expect === "pass");
    }
  });

  it("covers the healthy cases and at least three distinct seeded violations", () => {
    const cases = selftestCases();
    // Three passing cases: the healthy body, #1753's completed relay, and #1791's terminally ruled
    // relay — states pinned as deliberate because the gate once had no honest way to pass them.
    expect(cases.filter((c) => c.expect === "pass")).toHaveLength(3);
    expect(cases.filter((c) => c.expect === "fail").length).toBeGreaterThanOrEqual(3);
  });
});

// #1562. The PR-level check said "safe to merge" about a state that was not: dispositions in BOTH
// the PR body and an issue comment map every criterion twice, the close-time check reads every venue
// cumulatively and fails, the PR check read the body alone and passed. MEASURED 2026-07-30 — PRs
// #1517 and #1519 merged green and the close gate re-opened all four issues they closed (#1305,
// #825, #1469, #1280). A false negative in a merge gate is the most expensive kind: it surfaces
// after the merge.
describe("venue parity — a green PR check predicts the close-time verdict (#1562)", () => {
  const CRITERIA = "## Acceptance\n- first\n- second\n";
  const mapped = [
    "ACCEPTANCE #700.1 met: src/acceptance-conservation.ts now checks it",
    "ACCEPTANCE #700.2 met: src/acceptance-conservation.test.ts covers it",
  ];
  const PR_BODY = `Closes #700\n\n${mapped.join("\n")}\n`;
  const withComments = (...comments: string[]): IssueLookup =>
    lookupOf(issue({ number: 700, body: CRITERIA, comments }));

  it("REGRESSION: fails a PR whose dispositions are ALSO recorded as issue comments", () => {
    const lookup = withComments(...mapped);
    expect(checkAcceptance(PR_BODY, lookup).ok).toBe(false);
    // Naming BOTH venues is what makes the failure fixable before merge — a line number alone
    // leaves the author guessing which of two surfaces holds the copy to delete.
    expect(problems(PR_BODY, lookup)).toEqual([
      expect.stringContaining("#700.1 is mapped 2 times — the PR body, line 3; #700 comment 1, line 1"),
      expect.stringContaining("#700.2 is mapped 2 times — the PR body, line 4; #700 comment 2, line 1"),
    ]);
  });

  it("keeps PASSING a correct single-venue PR — parity tightened the check, it did not break it", () => {
    expect(checkAcceptance(PR_BODY, withComments("A prose comment that disposes of nothing.")).ok).toBe(true);
  });

  it("accounts for a criterion dispositioned ONLY in an issue comment, as the close path does", () => {
    expect(checkAcceptance("Closes #700\n", withComments(...mapped)).ok).toBe(true);
  });

  it("says which venues it read, so a duplicate does not appear from nowhere", () => {
    const out = formatAcceptance(checkAcceptance(PR_BODY, withComments(...mapped)));
    expect(out).toContain("3 venues supplied disposition lines and are read CUMULATIVELY — the PR body, #700 comment 1, #700 comment 2");
  });

  // The invariant itself, rather than one instance of it: whatever the arrangement of venues, the
  // two gates return the same verdict. This is what would have caught the defect.
  //
  // WHAT IT DOES NOT COVER (#1573): DIVERGENCE, not LOSS. Both paths now collect the issue's
  // comments at one point — the `for (const c of closes)` loop in checkAcceptance — so a regression
  // that deletes comment-reading removes it from BOTH sides and this assertion stays green. Loss is
  // guarded elsewhere, and MEASURED 2026-07-31 by deleting that loop: 7 tests fail, none of them
  // this one — "REGRESSION: fails a PR whose dispositions are ALSO recorded as issue comments",
  // "accounts for a criterion dispositioned ONLY in an issue comment, as the close path does",
  // "says which venues it read, so a duplicate does not appear from nowhere", "passes a bare click
  // whose dispositions are recorded as issue comments — the venue #1341 chose", "ignores a closing
  // keyword for another issue in the surfaces it reads", and both `--selftest` parity tests. Do not
  // read a green parity assertion as covering the venue set's existence.
  //
  // WIDENED for #1581: the arrangement space used to vary body/comment arrangements over ONE linked
  // PR, so an issue closed by TWO of them was outside the space and parity was broken there while
  // this assertion read green. Every arrangement now names the PR under test AND the full linked-PR
  // set, which is the state both gates actually see.
  it("PR verdict == close verdict, over every arrangement of the venues", () => {
    const other = (body: string): { ref: string; body: string } => ({ ref: "#901", body });
    const arrangements = [
      { name: "dispositions in the PR body only", body: PR_BODY, comments: [], others: [] },
      { name: "dispositions in the issue comments only", body: "Closes #700\n", comments: mapped, others: [] },
      { name: "dispositions in BOTH — the #1517 shape", body: PR_BODY, comments: mapped, others: [] },
      { name: "dispositions nowhere", body: "Closes #700\n", comments: [], others: [] },
      { name: "one criterion mapped, one left unaccounted", body: `Closes #700\n\n${mapped[0]}\n`, comments: [], others: [] },
      { name: "one in each venue — no duplicate, both accounted for", body: `Closes #700\n\n${mapped[0]}\n`, comments: [mapped[1]!], others: [] },
      // #1581's own shape and its neighbours.
      { name: "TWO linked PRs that both disposition every criterion", body: PR_BODY, comments: [], others: [other(PR_BODY)] },
      { name: "TWO linked PRs, one criterion each — no duplicate", body: `Closes #700\n\n${mapped[0]}\n`, comments: [], others: [other(`Closes #700\n\n${mapped[1]}\n`)] },
      { name: "TWO linked PRs, only the OTHER one dispositions anything", body: "Closes #700\n", comments: [], others: [other(PR_BODY)] },
      { name: "THREE linked PRs, the third duplicating a comment", body: `Closes #700\n\n${mapped[0]}\n`, comments: [mapped[1]!], others: [other("refs #700\n"), { ref: "#902", body: `refs #700\n\n${mapped[1]}\n` }] },
    ];
    for (const a of arrangements) {
      const lookup = lookupOf(issue({ number: 700, body: CRITERIA, comments: a.comments, linkedPrs: [{ ref: "#900", body: a.body }, ...a.others] }));
      const pr = checkAcceptance(a.body, lookup, undefined, undefined, { selfPr: "#900" }).ok;
      const close = checkClosedIssue({ issue: 700, authorIsBot: false }, lookup).ok;
      expect(pr, `${a.name}: PR check ${pr}, close check ${close}`).toBe(close);
    }
  });

  // NEGATIVE CONTROL for the invariant above: it must be able to fail. An arrangement where the two
  // genuinely differ has to be visible, or "they always agree" is a statement about the assertion.
  // It reproduces the PRE-FIX behaviour directly — the PR path reading only its own body, with the
  // other linked PR's venue withheld — so what it watches fail is the defect, not a stand-in.
  it("NEGATIVE CONTROL: the parity assertion fails when one path is fed a venue the other is not", () => {
    const both = lookupOf(issue({ number: 700, body: CRITERIA, linkedPrs: [{ ref: "#900", body: PR_BODY }, { ref: "#901", body: PR_BODY }] }));
    const prOnly = lookupOf(issue({ number: 700, body: CRITERIA }));
    expect(checkAcceptance(PR_BODY, prOnly).ok).toBe(true);
    expect(checkClosedIssue({ issue: 700, authorIsBot: false }, both).ok).toBe(false);
  });

  // #1581's live shape, stated as the defect rather than as an arrangement: two PRs closing one
  // issue, each carrying the same disposition lines. MEASURED 2026-07-31 before the fix — PR check
  // ok = true, close check ok = false.
  it("REGRESSION: fails a PR whose criterion is ALSO dispositioned by a second linked closing PR", () => {
    const lookup = lookupOf(issue({ number: 700, body: CRITERIA, linkedPrs: [{ ref: "#900", body: PR_BODY }, { ref: "#901", body: PR_BODY }] }));
    const r = checkAcceptance(PR_BODY, lookup, undefined, undefined, { selfPr: "#900" });
    expect(r.ok).toBe(false);
    expect(r.issues[0]!.criteria[0]!.problems[0]).toContain("#700.1 is mapped 2 times — the PR body, line 3; linked PR #901, line 3");
  });

  it("does not read the PR under test as its own linked venue — `selfPr` excludes it", () => {
    const lookup = lookupOf(issue({ number: 700, body: CRITERIA, linkedPrs: [{ ref: "#900", body: PR_BODY }] }));
    expect(checkAcceptance(PR_BODY, lookup, undefined, undefined, { selfPr: "#900" }).ok).toBe(true);
    // and without the exclusion the same state is a duplicate, so the filter is load-bearing
    expect(checkAcceptance(PR_BODY, lookup).ok).toBe(false);
  });

  // The other half of the same false negative, reached by a different route: GitHub closes on a
  // Development-sidebar link with no keyword in the body at all, so a body-only close set green-
  // no-ops on a PR that WILL close the issue.
  it("checks an issue GitHub records as closing that the body never mentions", () => {
    const lookup = withComments();
    const sidebar = "Refactors the seeder. refs #700\n";
    expect(checkAcceptance(sidebar, lookup).ok).toBe(true);
    const r = checkAcceptance(sidebar, lookup, undefined, undefined, { linkedCloses: [{ number: 700, ref: "#700" }] });
    expect(r.ok).toBe(false);
    expect(r.noop).toBe(false);
    expect(r.closes.map((c) => c.number)).toEqual([700]);
  });

  it("does not report a sidebar close twice when the body ALSO carries the keyword", () => {
    const r = checkAcceptance(PR_BODY, withComments(), undefined, undefined, { linkedCloses: [{ number: 700, ref: "#700" }] });
    expect(r.closes).toHaveLength(1);
    expect(r.ok).toBe(true);
  });
});

// #1565. The grammar is exact and the parser is line-by-line, so a near-miss read as ABSENT: the
// author was told the bullet was UNMAPPED rather than what was wrong with the line they wrote.
// Every shape here was hit by a real executor on 2026-07-30 and cost a CI round trip. Each test
// pins the SPECIFIC defect the message must name — it fails if the message degrades back to the
// generic "expected <grammar>", which is what the old one said for all four.
describe("a near-miss disposition line is reported as MALFORMED, naming the defect (#1565)", () => {
  const withLine = (line: string): string[] => problems(`Closes #10\n\n${line}\nACCEPTANCE #10.2 met: src/foo.ts:1\n`, lookupOf(issue({ number: 10 })));

  it("names the DASH when an em-dash stands where the grammar needs a colon", () => {
    const [first] = withLine("ACCEPTANCE #10.1 met — src/foo.ts:1 now throws");
    expect(first).toContain("separated from its evidence by a dash");
    expect(first).toContain("needs a COLON");
    // The correction, spelled out — this is what turns a rejection into a one-edit fix.
    expect(first).toContain("ACCEPTANCE #10.1 met: src/foo.ts:1 now throws");
  });

  it("names the same defect for an en-dash and a plain hyphen, which read identically to the parser", () => {
    for (const dash of ["–", "-"]) {
      expect(withLine(`ACCEPTANCE #10.1 met ${dash} src/foo.ts:1 now throws`)[0]).toContain("separated from its evidence by a dash");
    }
  });

  it("names the PARENTHETICAL between the verdict and the colon", () => {
    const [first] = withLine("ACCEPTANCE #10.1 met (this PR): src/foo.ts:1 now throws");
    expect(first).toContain("parenthetical sits between the verdict and the colon");
    expect(first).toContain("ACCEPTANCE #10.1 met: src/foo.ts:1 now throws");
    expect(first).toContain('fold "this PR" into the detail');
  });

  it("says `no-stated-criteria` is a WHOLE-ISSUE declaration when it is written per-criterion", () => {
    const [first] = withLine("ACCEPTANCE #10.1 no-stated-criteria: the bar was a green verify");
    expect(first).toContain("WHOLE-ISSUE declaration and takes no criterion number");
    expect(first).toContain("ACCEPTANCE #10 no-stated-criteria:");
    // And it must say the escape hatch does not apply here, or the author just deletes the `.1`.
    expect(first).toContain("only when the issue states no criteria at all");
  });

  it("names an unrecognised verdict word rather than reciting the grammar at it", () => {
    const [first] = withLine("ACCEPTANCE #10.1 done: src/foo.ts:1 now throws");
    expect(first).toContain("`done` is not a disposition");
    expect(first).toContain("`met`, `split`, `relayed` and `ruled-unmet`");
  });

  it("names an empty detail after the colon", () => {
    expect(withLine("ACCEPTANCE #10.1 met:")[0]).toContain("carries no detail after the colon");
  });

  // NEGATIVE CONTROL for the whole family: a WELL-FORMED line must not be diagnosed at all, or the
  // new messages would be firing on the population they exist to leave alone.
  it("NEGATIVE CONTROL: a well-formed disposition produces no malformed-line message", () => {
    expect(problems(BOTH_MET, lookupOf(issue({ number: 10 })))).toEqual([]);
  });
});

// #1696. Venues are read cumulatively and FOREVER, so a comment that QUOTES a disposition line —
// which is exactly what a bug report about a malformed one does, and what issue #1696's own first
// comment did — used to poison its venue permanently: the issue documenting a malformation could
// never again close green. A fence is quotation, not assertion.
describe("a fenced code block is quotation, not assertion (#1696)", () => {
  const ten = lookupOf(issue({ number: 10 }));

  it("does not read a malformed line quoted in a fence, so a bug report cannot poison its venue", () => {
    const body = "Closes #10\n\n```\nACCEPTANCE #10.1 met — quoted verbatim in a report about this exact defect\n```\n\nACCEPTANCE #10.1 met: src/foo.ts:1 now throws\nACCEPTANCE #10.2 met: src/foo.ts:1 now throws\n";
    expect(problems(body, ten)).toEqual([]);
  });

  it("CONTROL: the identical line outside the fence is still diagnosed", () => {
    const body = "Closes #10\n\nACCEPTANCE #10.1 met — quoted verbatim in a report about this exact defect\n\nACCEPTANCE #10.1 met: src/foo.ts:1 now throws\nACCEPTANCE #10.2 met: src/foo.ts:1 now throws\n";
    expect(problems(body, ten).some((p) => p.includes("malformed ACCEPTANCE line"))).toBe(true);
  });

  it("does not let a WELL-FORMED line quoted in a fence map a criterion, or an example would count as a claim", () => {
    const body = "Closes #10\n\n```\nACCEPTANCE #10.1 met: src/foo.ts:1 now throws\n```\n\nACCEPTANCE #10.2 met: src/foo.ts:1 now throws\n";
    expect(problems(body, ten).some((p) => p.includes("UNMAPPED"))).toBe(true);
  });
});

describe("evidence truncated at a line break says so (#1565)", () => {
  const wrapped = [
    "Closes #10",
    "",
    "ACCEPTANCE #10.1 met: the whole point of this change, argued at length,",
    "which is that `pnpm verify` passes and src/foo.ts:12 now throws",
    "ACCEPTANCE #10.2 met: src/foo.ts:12 now throws",
  ].join("\n");

  it("names the continuation line rather than reporting a mystery evidence failure", () => {
    const found = problems(wrapped, lookupOf(issue({ number: 10 })));
    expect(found.some((p) => p.includes("names none of"))).toBe(true);
    const hint = found.find((p) => p.includes("TRUNCATED AT A LINE BREAK"));
    expect(hint).toBeDefined();
    expect(hint).toContain("line 3 is read to its end and line 4");
    expect(hint).toContain("which is that `pnpm verify` passes");
    expect(hint).toContain("Put the whole disposition on one line");
  });

  // NEGATIVE CONTROL: the hint decorates a failure, it never creates one. A disposition whose FIRST
  // line already carries evidence is correct, wrap or no wrap, and must stay silent — otherwise
  // every PR body with prose after its last disposition would start reporting a defect.
  it("NEGATIVE CONTROL: says nothing when the first line already carries evidence", () => {
    const body = `${BOTH_MET}\nAnd some closing prose about the change.\n`;
    expect(problems(body, lookupOf(issue({ number: 10 })))).toEqual([]);
  });

  it("does not read the NEXT disposition as a continuation of the one above it", () => {
    const body = "Closes #10\n\nACCEPTANCE #10.1 met: all good\nACCEPTANCE #10.2 met: src/foo.ts:1\n";
    const found = problems(body, lookupOf(issue({ number: 10 })));
    expect(found.some((p) => p.includes("TRUNCATED AT A LINE BREAK"))).toBe(false);
  });
});

describe("an out-of-range criterion number prints the criteria the gate parsed (#1565)", () => {
  it("lists them, numbered, so the author can renumber against the parse and not the rendering", () => {
    const body = `${BOTH_MET}ACCEPTANCE #10.3 met: \`pnpm verify\` green\n`;
    const [first] = problems(body, lookupOf(issue({ number: 10, body: "## Acceptance\n- the first bar\n- the second bar\n" })));
    expect(first).toContain("but #10 states 2");
    expect(first).toContain("1. the first bar  |  2. the second bar");
    expect(first).toContain("POSITIONAL");
  });
});

// #1603. The bar #1595 was graded against had been replaced in a comment, and the gate reported
// `3/3 criteria dispositioned` against the body's superseded list. Every case below is drawn from
// the whole-population census (893 closed issues, 707 comments, 2026-07-31) rather than invented:
// the positives are two of the twelve real hits, the negatives are the shapes the filters had to
// learn to spare.
describe("a comment that moves the bar is FLAGGED, not graded (#1603)", () => {
  const REVISED = [
    "## Revised acceptance — collapse on EVIDENCE, not position",
    "",
    "Supersedes the acceptance in the body above.",
    "",
    "- [ ] `reconcile_duplicates` closes a sibling only on positive evidence.",
    "- [ ] The redirect comment must not assert more than was verified.",
    "- [ ] Prove it in both directions in `src/alert-issue-race.test.ts`.",
  ].join("\n");
  const flags = (...comments: string[]): string[] =>
    checkAcceptance(BOTH_MET, lookupOf(issue({ number: 10, comments })))
      .issues[0]!.supersedingComments.map((s) => s.heading);

  it("fires on the #1595 shape — an acceptance list under a prose-tailed heading", () => {
    expect(flags(REVISED)).toEqual(["Revised acceptance — collapse on EVIDENCE, not position"]);
  });

  it("fires on a bare unchecked checklist, the other convention this repo writes criteria in", () => {
    expect(flags("## Remaining acceptance\n\n- [ ] remove the line from llms.txt\n- [ ] remove the matrix row\n")).toHaveLength(1);
  });

  it("names the comment URL, which is the whole point — a label the reader cannot open is not a flag", () => {
    const r = checkAcceptance(BOTH_MET, lookupOf(issue({ number: 10, comments: [{ body: REVISED, url: "https://github.com/o/r/issues/10#issuecomment-5" }] })));
    expect(formatAcceptance(r)).toContain("https://github.com/o/r/issues/10#issuecomment-5");
    expect(formatAcceptance(r)).toContain("THE BAR MAY HAVE MOVED");
  });

  it("does NOT fail the gate — grading a heuristic read of prose is the decision #1603 declined", () => {
    expect(checkAcceptance(BOTH_MET, lookupOf(issue({ number: 10, comments: [REVISED] }))).ok).toBe(true);
  });

  // Bulleted on purpose. The unbulleted form of this comment is spared by the bullet count alone,
  // so a test using it passes with the disposition exclusion DELETED — measured 2026-07-31, that
  // exact mutation survived the first draft of this suite.
  it("NEGATIVE: spares a disposition record, which is every executor's closing comment", () => {
    expect(flags("## Acceptance, dispositioned\n\n- ACCEPTANCE #10.1 met: src/foo.ts:12 now throws\n- ACCEPTANCE #10.2 met: src/bar.ts:4 covers it\n")).toEqual([]);
  });

  it("NEGATIVE: spares a whole-issue `no-stated-criteria` declaration for the same reason", () => {
    expect(flags("## Acceptance\n\n- ACCEPTANCE #10 no-stated-criteria: the bar was a green corpus-drift run\n- and the run that proved it\n")).toEqual([]);
  });

  it("NEGATIVE: spares the close gate's own failure comment, which is posted under a HUMAN token here", () => {
    expect(flags(closeFailureComment(checkClosedIssue({ issue: 700, authorIsBot: false }, () => undefined)))).toEqual([]);
  });

  it("NEGATIVE: spares a completion report — an `## Acceptance` heading over bullets that already carry verdicts", () => {
    expect(flags("## Acceptance\n\n- [x] all six re-scanned, dated\n- [x] nothing unscannable was skipped\n")).toEqual([]);
  });

  it("NEGATIVE: spares a single bullet under an acceptance heading, which is prose about the existing bar", () => {
    expect(flags("### Acceptance criterion 2 is met independently of the ruling\n\n- `SB-DRIFT-00` is emitted once per connected run.\n")).toEqual([]);
  });

  it("NEGATIVE: does not let a LATER section's bullets rescue a report — the #1174 dilution", () => {
    expect(flags("## Acceptance\n\n- [x] all six re-scanned\n- [x] nothing skipped\n\n## Defects found\n\n- #1470\n- #1471\n- #1473\n")).toEqual([]);
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

// #1341 — the close path. Gate 1 reads PR bodies, and both of these close an issue with no PR body
// to read: a bare click touches no PR at all, and a Development-sidebar link closes on merge with no
// closing keyword in the body. Same rules, one more surface set.
describe("an issue that closes with no PR body to read (#1341)", () => {
  const CRITERIA = "## Acceptance\n- first\n- second\n";
  const closeLookup: IssueLookup = (n) => (n === 700 ? issue({ number: 700, body: CRITERIA }) : undefined);
  const bare = { issue: 700, authorIsBot: false };
  const mapped = [
    "ACCEPTANCE #700.1 met: src/acceptance-conservation.ts now checks it",
    "ACCEPTANCE #700.2 met: src/acceptance-conservation.test.ts covers it",
  ];
  /** Both venue kinds are read through the LOOKUP on both paths, which is what keeps the two in step. */
  const commented = (...comments: string[]): IssueLookup => (n) => (n === 700 ? issue({ number: 700, body: CRITERIA, comments }) : undefined);
  const linked = (...linkedPrs: { ref: string; body: string }[]): IssueLookup => (n) => (n === 700 ? issue({ number: 700, body: CRITERIA, linkedPrs }) : undefined);

  it("fails a BARE CLICK — no linked PR, no comment, and two criteria nobody accounted for", () => {
    const r = checkClosedIssue(bare, closeLookup);
    expect(r.ok).toBe(false);
    expect(r.contributed).toEqual([]);
    expect(formatClosedIssue(r)).toContain("a bare click");
  });

  it("passes a bare click whose dispositions are recorded as issue comments — the venue #1341 chose", () => {
    const r = checkClosedIssue(bare, commented(...mapped));
    expect(r.ok).toBe(true);
    expect(r.contributed).toEqual(["#700 comment 1", "#700 comment 2"]);
  });

  // The one that looks like a normal close and is not: GitHub acts on the sidebar link, so the issue
  // closes on merge while a body-reading gate sees a PR that closes nothing.
  it("fails a DEVELOPMENT-SIDEBAR close whose linked PR body carries no closing keyword and no dispositions", () => {
    const r = checkClosedIssue(bare, linked({ ref: "#800", body: "Refactors the seeder. refs #700" }));
    expect(r.ok).toBe(false);
    expect(r.surfacesRead).toEqual(["linked PR #800"]);
  });

  it("passes a sidebar close whose dispositions live in the linked PR's body, so nothing is written twice", () => {
    const r = checkClosedIssue(bare, linked({ ref: "#800", body: `refs #700\n\n${mapped.join("\n")}` }));
    expect(r.ok).toBe(true);
    expect(r.contributed).toEqual(["linked PR #800"]);
  });

  // Only disposition-bearing LINES cross over. A whole PR body would drag its other closing keywords
  // in and put unrelated issues on trial in a check scoped to one issue.
  it("ignores a closing keyword for another issue in the surfaces it reads", () => {
    const r = checkClosedIssue(bare, commented(`Closes #999 as well.\n${mapped.join("\n")}`));
    expect(r.ok).toBe(true);
    expect(r.report!.closes.map((c) => c.number)).toEqual([700]);
  });

  it("exempts a bot-opened issue, and says so rather than passing silently", () => {
    const r = checkClosedIssue({ ...bare, authorIsBot: true }, closeLookup);
    expect(r.ok).toBe(true);
    expect(formatClosedIssue(r)).toContain("NOT ASSESSED");
  });

  it("names both ways out in the comment it posts, so the failure is actionable where it lands", () => {
    const comment = closeFailureComment(checkClosedIssue(bare, closeLookup));
    expect(comment).toContain("ACCEPTANCE #700.<n>");
    expect(comment).toContain("close it through a PR whose body carries those lines");
  });

  it("scores exactly as the CLI's --selftest-close asserts, so CI and `pnpm verify` share one fixture", () => {
    for (const c of closeSelftestCases()) {
      expect(checkClosedIssue(c.input, c.lookup, undefined, SELFTEST_WORLD).ok, c.name).toBe(c.expect === "pass");
    }
  });

  // Both close paths, both directions. A control set that only ever proved one direction would leave
  // "the gate cannot fire" and "there was nothing to fire on" indistinguishable.
  it("covers each close path in both directions", () => {
    const names = closeSelftestCases().map((c) => `${c.name} ${c.expect}`);
    for (const path of ["BARE CLICK", "DEVELOPMENT SIDEBAR"]) {
      expect(names.filter((n) => n.includes(path) && n.endsWith("pass"))).toHaveLength(1);
      expect(names.filter((n) => n.includes(path) && n.endsWith("fail"))).toHaveLength(1);
    }
  });

  // #1696: the near-miss separator is the LIKELY defective input, and it used to reach a different
  // terminal state than the obviously-wrong one. The verdict half: it must FAIL the gate, and the
  // failure must name the exact line (#1645's diagnostic), never a bare UNMAPPED.
  it("fails a close whose disposition uses `met —` and names the malformed line, not just UNMAPPED", () => {
    const nearMiss = closeSelftestCases().find((c) => c.name.includes("near-miss"))!;
    const r = checkClosedIssue(nearMiss.input, nearMiss.lookup, undefined, SELFTEST_WORLD);
    expect(r.ok).toBe(false);
    const rendered = formatClosedIssue(r);
    expect(rendered).toContain("malformed ACCEPTANCE line");
    expect(rendered).toContain("ACCEPTANCE #9001.1 met —");
  });
});

// #1696 — ONE terminal state for a failed close. The divergence was never the parser: it was the
// "re-open once" rule, under which the terminal state depended on whether `acceptance-unaccounted`
// was already present. This is the failing direction for that rule's reintroduction.
describe("closeActions — a failed close has one terminal state (#1696)", () => {
  it("re-opens on failure whether or not the label is already present — the two must be identical", () => {
    expect(closeActions(false, true)).toEqual(closeActions(false, false));
    expect(closeActions(false, true)).toEqual({ comment: true, addLabel: true, reopen: true, removeLabel: false });
  });

  it("never re-opens a passing close, and removes the label only when it is present", () => {
    expect(closeActions(true, true)).toEqual({ comment: false, addLabel: false, reopen: false, removeLabel: true });
    expect(closeActions(true, false)).toEqual({ comment: false, addLabel: false, reopen: false, removeLabel: false });
  });
});
