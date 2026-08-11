// #1545. The rule under test is a JUDGEMENT — "a filed tracker is not a relay" — so the cases that
// matter are the ones drawn from real merged PR bodies, not invented ones. Every fixture below is
// quoted from a PR that actually merged, and the verdicts were checked against the live check on
// 2026-07-31 (`--pr 1481` fires; `--since-days 4` cleared #1456, #1381 and #1327).

import { describe, expect, it } from "vitest";
import {
  findSupervisedDeclines,
  judgeDecline,
  selftestCases,
  supervisedDeclineTriage,
  type IssueLike,
} from "./supervised-declines.js";

const lookupOf = (...issues: IssueLike[]) => (n: number): IssueLike | undefined => issues.find((i) => i.number === n);
const verdict = (body: string, lookup = lookupOf()): string[] =>
  findSupervisedDeclines(body).map((h) => judgeDecline(h, body, lookup).relay);

// Verbatim from PR #1481, line 211 — the instance #1545 is built on.
const PR_1481 = "**Relay — needs an operator decision, not doable here.** Wiring `pentest.ts --mode=coverage` into a venue is a `.github/workflows/` edit, which is supervised. It is disclosed in the row, tracked by #1483, and NOT done in this PR. Proposed wording for the operator, if approved: add a step to `heavy-cli` shard 3.";

describe("what counts as a supervised-path decline", () => {
  it("finds the decline in PR #1481's own words", () => {
    const hits = findSupervisedDeclines(PR_1481);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.issues).toContain(1483);
  });

  it("does not fire on a PR that MENTIONS a supervised path while editing it", () => {
    expect(findSupervisedDeclines("This PR edits `.github/workflows/ci.yml` to add a liveness drill under the operator's grant.")).toEqual([]);
  });

  it("reads the whole PARAGRAPH for the issue it names, not the one line", () => {
    const body = "`.github/workflows/` is supervised, so the wiring is not done in this PR.\nTracked by #1483.";
    expect(findSupervisedDeclines(body)[0]!.issues).toEqual([1483]);
  });
});

describe("exact-instance false-positive triage (#1821)", () => {
  it("records who triaged PR #1683 line 36 and why", () => {
    expect(supervisedDeclineTriage(1683, 36)).toMatchObject({
      triagedBy: "@jharvieux in #1821",
      reason: expect.stringContaining("shared-line decline signal attaches to the wrong file"),
    });
  });

  it("NEGATIVE CONTROL: the record does not widen to another line or PR", () => {
    expect(supervisedDeclineTriage(1683, 35)).toBeUndefined();
    expect(supervisedDeclineTriage(1684, 36)).toBeUndefined();
  });
});

describe("what counts as a relay", () => {
  it("REGRESSION: a filed tracking issue that asks the operator nothing is NOT a relay", () => {
    const tracker: IssueLike = { number: 1483, body: "A parity exemption's substitute gate is proven to EXIST, never to RUN.", comments: ["Related but not the same as #1311."] };
    expect(verdict(PR_1481, lookupOf(tracker))).toEqual(["none"]);
  });

  it("the SAME decline clears once a question is put to the operator on that issue", () => {
    const asked: IssueLike = { number: 1483, body: "A parity exemption's substitute gate.", comments: ["Operator: may I add a `--mode=coverage` step to heavy-cli shard 3?"] };
    expect(verdict(PR_1481, lookupOf(asked))).toEqual(["operator-ask"]);
  });

  // The first draft of the grant pattern cleared PR #1481 on the words "if approved:" followed by a
  // backtick — it read the ASK as the GRANT and silenced the case the check exists for.
  it("REGRESSION: `if approved:` is a conditional, not a grant", () => {
    expect(verdict(PR_1481)).toEqual(["none"]);
  });

  it("a quoted grant clears it", () => {
    const body = "Editing `.github/workflows/` is supervised and normally not done here; the operator's message reads: \"Workflow changes approved\".";
    expect(verdict(body)).toEqual(["quoted-grant"]);
  });

  // CLAUDE.md's own rule forbids a dispatched agent from editing it and prescribes the PR body as
  // the venue for the replacement wording. A check that flagged that would demand a doctrine breach.
  it("a CLAUDE.md drift reported WITH its replacement wording is the prescribed relay", () => {
    const body = "**CLAUDE.md (supervised — not edited).** One sentence is falsified by this PR. Proposed wording for the orchestrator: \"it reads FOUR as of 2026-07-31\".";
    expect(verdict(body)).toEqual(["orchestrator-report"]);
  });

  it("the same shape WITHOUT replacement wording is still unrelayed", () => {
    expect(verdict("**CLAUDE.md (supervised — not edited).** A sentence in it is falsified by this PR and I have not said which.")).toEqual(["none"]);
  });

  it("a supervised file CHECKED and found to need nothing is not a decline at all", () => {
    expect(verdict("**CLAUDE.md (supervised — not edited).** No sentence in it is falsified by this PR.")).toEqual(["nothing-owed"]);
  });

  // #1246's rule, one venue over: "I could not read it" and "it carries no ask" are different facts.
  it("an unreadable tracker is reported as unreadable, not folded in with 'asks nothing'", () => {
    const hit = findSupervisedDeclines(PR_1481)[0]!;
    expect(judgeDecline(hit, PR_1481, () => undefined).detail).toContain("could not be READ");
  });
});

describe("the hermetic self-test CI runs", () => {
  it("scores exactly as the CLI's --selftest asserts, so CI and `pnpm verify` share one fixture", () => {
    for (const c of selftestCases()) {
      const lookup = lookupOf(...c.issues);
      const flagged = findSupervisedDeclines(c.body).map((h) => judgeDecline(h, c.body, lookup)).some((v) => v.relay === "none");
      expect(flagged, c.name).toBe(c.expect === "flagged");
    }
  });

  it("covers both directions — a control set that only ever fired would prove nothing", () => {
    const cases = selftestCases();
    expect(cases.filter((c) => c.expect === "flagged").length).toBeGreaterThanOrEqual(3);
    expect(cases.filter((c) => c.expect === "clear").length).toBeGreaterThanOrEqual(3);
  });
});
