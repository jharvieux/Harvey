// #1545 — "X is a supervised path" is the repo's densest false-decline family.
//
// MEASURED by the #1378 PR-body audit (2026-07-30): 6 of the 9 defective claims in a seeded 40-PR
// sample were this one shape. A PR declines a deliverable with "that path is supervised". The
// sentence is true about the EXECUTOR'S EDIT PERMISSION and false about whether the work can be
// done, because the grant is routine and is routinely given — #1141 carries a verbatim "Workflow
// changed approved", #1205 promoted a check to required, #1216 moved a watch into CI. The decline
// is written in the same grammar as "this is impossible", so a reader cannot tell a permission ask
// from a capability bound, and by construction nobody exercises a path recorded as foreclosed.
//
// CLAUDE.md already carries the doctrine ("a supervised path produces a RELAY, not a silent
// close"). What was missing is a MEASUREMENT: nothing reads PR prose, and `validate-reasons` only
// reaches `REASON:` blocks. This module is that reader.
//
// THE RULE, chosen deliberately (#1545 criterion 2 asks for the choice to be recorded):
//
//   A supervised-path decline needs a RELAY ARTIFACT, and a filed tracking issue is NOT one.
//
// PR #1481 is the case that settles it. It declined a `.github/workflows/` edit, filed #1483, and
// #1483 is a work item — a well-written one — that asks the operator nothing. Four days later the
// work was still undone and twelve unrelated commits had edited `.github/workflows/`. A tracker
// records that work remains; a relay records that the person who can authorise it was asked. Only
// the second unblocks anything, which is why the doctrine says to write the question ON THE ISSUE
// with the exact wording proposed, "where the operator reads it, not in this PR body". So:
//
//   • QUOTED GRANT        — the PR body quotes the permission it was given.
//   • OPERATOR ASK        — the PR body names an issue that itself carries a question put to the
//                           operator, in its body or its comments.
//   • ORCHESTRATOR REPORT — the decline concerns CLAUDE.md or a supervised doc AND the paragraph
//                           carries the PROPOSED REPLACEMENT WORDING. This one is not a concession:
//                           CLAUDE.md's own rule is that a dispatched agent must never edit it,
//                           "even when the operator has granted CLAUDE.md changes for the session",
//                           and must instead "name the exact sentence and recommend the replacement
//                           wording, in your PR body AND your report to the supervisor". For that
//                           one path the PR body IS the prescribed venue, so a check that flagged it
//                           would be demanding a violation of the doctrine it enforces.
//   • anything else       — including "tracked by #N" where #N never asks — is an UNRELAYED DECLINE.
//
// And a paragraph that states NOTHING WAS OWED ("no sentence in it is falsified by this PR") is not
// a decline at all: it reports a check that was performed and came back empty. Counted separately
// rather than silently dropped, so the difference between "not flagged" and "not looked at" stays
// visible.
//
// This is deliberately the same shape as the `relayed` disposition in src/acceptance-conservation.ts
// ("#N carries no comment containing a question — record the question ON THE ISSUE"), one venue over.

/** The paths whose grant is routine, with what the record says about each. Named in the report, because "supervised" is being used as a synonym for "impossible" and the antidote is the counter-example. */
export const ROUTINELY_GRANTED: { path: string; evidence: string }[] = [
  { path: ".github/workflows/**", evidence: "granted repeatedly — #1141 records a verbatim \"Workflow changed approved\"; PR #276 shipped the workflow #241 had declined 11h09m earlier; 12 commits touched it in the 4 days after #1481 declined on it" },
  { path: "docs/**", evidence: "granted per session — PR #410 merged 140 seconds after #409 declared the same file undeditable, from the same session id" },
  { path: "package.json / pnpm-lock.yaml", evidence: "NEVER supervised at all (operator ruling 2026-07-27, CLAUDE.md). #426 and #556 both recorded it as a constraint; it did not exist, and the folk version blocked at least five separate pieces of work" },
];

const SUPERVISED_SIGNAL = /\bsupervised\b|\.github\/workflows|CLAUDE\.md|report-template\/findings/i;

// A decline, not a mention. "This PR edits .github/workflows/ci.yml" carries the path signal and
// declines nothing; the verb is what makes it a decline.
const DECLINE_SIGNAL = /\bnot done\b|\bnot doable\b|\bnot touched\b|\bnot changed\b|\bnot edited\b|\bnot performed\b|\bcannot (?:be )?(?:self-)?edit|\bcan't edit\b|\bleft (?:for|to) the (?:supervisor|operator|orchestrator)\b|\bdeliberately absent\b|\bnot (?:done|made|applied) (?:here|in this PR)\b|\bout of scope (?:here|for this PR)\b|\bnot in this PR\b|\bomitted here\b|\bskipped here\b/i;

/**
 * A grant the PR body QUOTES rather than asserts. The grant word must sit INSIDE a double-quoted
 * span, and backticks are deliberately excluded: these bodies are full of code spans, and the first
 * draft of this pattern — a grant word within 120 characters of any quote mark — read PR #1481's
 * "Proposed wording for the operator, **if approved**: add a step to `heavy-cli`…" as a grant and
 * cleared the very decline this check exists to catch (MEASURED 2026-07-31, `--pr 1481` exit 0).
 * A conditional is the opposite of a grant, so the conditional openers are refused explicitly.
 */
const QUOTED_GRANT = /["“]([^"“”\n]{0,200})["”]/g;
const GRANT_WORD = /\b(?:approved|granted|authorised|authorized|go-ahead|permission granted|you may)\b/i;
const CONDITIONAL = /\b(?:if|once|unless|when|pending|assuming)\s+(?:it is |this is |they are )?(?:approved|granted|authorised|authorized)\b/i;

function quotesAGrant(body: string): boolean {
  for (const m of body.matchAll(QUOTED_GRANT)) {
    const inner = m[1]!;
    if (GRANT_WORD.test(inner) && !CONDITIONAL.test(inner)) return true;
  }
  return false;
}

/** The replacement wording an orchestrator can apply — the deliverable CLAUDE.md's own rule asks for in the PR body. */
const PROPOSED_WORDING = /\bproposed (?:wording|replacement|text|sentence)\b|\brecommended (?:wording|replacement)\b|\breplacement wording\b|\bfor the orchestrator\b|\bfor (?:an|the) operator to apply\b/i;

/** A check that ran and came back empty is not a decline. Kept as its own verdict so "we looked and there was nothing" cannot be read as "we declined". */
const NOTHING_OWED = /\bno sentence\b[^\n]{0,80}\bfalsif/i;

/** A question PUT TO THE OPERATOR, as distinct from any question. A work item full of rhetorical questions is still not an ask. */
const OPERATOR_ASK = /\?/;
const OPERATOR_ADDRESS = /\boperator\b|\bapprov|\bgrant|\bpermission\b|\bruling\b|\bmay I\b|\bgo-ahead\b|\bauthoris|\bauthoriz/i;

export interface DeclineHit {
  /** 1-based line number in the PR body. */
  line: number;
  text: string;
  /** The block the line sits in — where "tracked by #N" and the proposed wording actually live. */
  paragraph: string;
  /** Issues this line (or the paragraph it sits in) names, which are where a relay would live. */
  issues: number[];
}

export interface IssueLike {
  number: number;
  body: string;
  comments: string[];
}

export interface DeclineVerdict {
  hit: DeclineHit;
  relay: "quoted-grant" | "operator-ask" | "orchestrator-report" | "nothing-owed" | "none";
  detail: string;
}

const ISSUE_REF = /#(\d{1,6})\b/g;

export function findSupervisedDeclines(body: string): DeclineHit[] {
  const lines = body.split("\n");
  return lines.flatMap((text, i) => {
    if (!SUPERVISED_SIGNAL.test(text) || !DECLINE_SIGNAL.test(text)) return [];
    // The paragraph, not the line: an executor routinely writes the decline on one line and
    // "tracked by #1483" on the next, and reading the line alone would report a relay that is
    // there as absent.
    const paragraph = paragraphAround(lines, i);
    return [{ line: i + 1, text: text.trim(), paragraph, issues: [...paragraph.matchAll(ISSUE_REF)].map((m) => Number(m[1])) }];
  });
}

function paragraphAround(lines: string[], i: number): string {
  let start = i;
  let end = i;
  while (start > 0 && lines[start - 1]!.trim() !== "") start--;
  while (end < lines.length - 1 && lines[end + 1]!.trim() !== "") end++;
  return lines.slice(start, end + 1).join("\n");
}

/**
 * `lookup` returning undefined means the issue could not be read. That is UNVERIFIABLE, not
 * "carries no ask" — the caller must not fold the two together, so it is reported in `detail`
 * rather than silently counted as a violation.
 */
export function judgeDecline(hit: DeclineHit, body: string, lookup: (issue: number) => IssueLike | undefined): DeclineVerdict {
  if (NOTHING_OWED.test(hit.paragraph)) return { hit, relay: "nothing-owed", detail: "reports a check that came back empty — nothing was declined" };
  if (quotesAGrant(body)) return { hit, relay: "quoted-grant", detail: "the PR body quotes the grant it was given" };
  if (PROPOSED_WORDING.test(hit.paragraph)) return { hit, relay: "orchestrator-report", detail: "carries the replacement wording for the orchestrator to apply — the venue CLAUDE.md's own rule prescribes" };
  const unreadable: number[] = [];
  for (const n of hit.issues) {
    const issue = lookup(n);
    if (!issue) {
      unreadable.push(n);
      continue;
    }
    const venues = [issue.body, ...issue.comments];
    const asked = venues.find((v) => v.split("\n").some((l) => OPERATOR_ASK.test(l) && OPERATOR_ADDRESS.test(l)));
    if (asked) return { hit, relay: "operator-ask", detail: `#${n} carries a question put to the operator` };
  }
  const named = hit.issues.length > 0 ? `named #${hit.issues.join(", #")}, none of which asks the operator anything` : "names no issue at all";
  return {
    hit,
    relay: "none",
    detail: unreadable.length > 0
      ? `${named}; #${unreadable.join(", #")} could not be READ, which is no measurement rather than a clean one`
      : named,
  };
}

/**
 * The hermetic negative control. A check that has only ever been seen reporting zero is
 * indistinguishable from one that cannot report anything — and this one scans real history, where
 * a quiet week is the normal result.
 *
 * The two live cases are kept as fixtures rather than fetched, so the control needs no network and
 * cannot go green because GitHub was slow.
 */
export function selftestCases(): { name: string; body: string; issues: IssueLike[]; expect: "flagged" | "clear" }[] {
  const declineBody = "**Relay — needs an operator decision, not doable here.** Wiring `pentest.ts --mode=coverage` into a venue is a `.github/workflows/` edit, which is supervised. It is disclosed in the row, tracked by #1483, and NOT done in this PR.";
  return [
    {
      name: "PR #1481's decline, with the tracker it filed — a tracker is not a relay",
      body: declineBody,
      issues: [{ number: 1483, body: "A parity exemption's substitute gate is proven to EXIST, never to RUN.\n\n## Acceptance\n1. A substitute gate declares WHERE it runs.", comments: ["Related but not the same as #1311."] }],
      expect: "flagged",
    },
    {
      name: "the same decline once the operator has actually been asked ON the issue",
      body: declineBody,
      issues: [{ number: 1483, body: "A parity exemption's substitute gate is proven to EXIST, never to RUN.", comments: ["Operator: may I add a `--mode=coverage` step to heavy-cli shard 3? Proposed wording is in the PR body."] }],
      expect: "clear",
    },
    {
      name: "a decline that quotes the grant it was given",
      body: "Editing `.github/workflows/` is supervised and normally not done here, but the operator's message for this batch reads: \"Workflow changes approved\".",
      issues: [],
      expect: "clear",
    },
    {
      name: "a PR that MENTIONS a supervised path without declining anything",
      body: "This PR edits `.github/workflows/ci.yml` to add a liveness drill under the operator's grant.",
      issues: [],
      expect: "clear",
    },
    {
      name: "#409's shape — a supervised-doc drift flagged and left, naming no issue",
      body: "Supervised-doc drift (cannot edit; flagging per doctrine) — `docs/design/m6-handrolled-catalogue.md` and CLAUDE.md both describe the old count. Not done in this PR.",
      issues: [],
      expect: "flagged",
    },
    {
      name: "a CLAUDE.md drift reported to the orchestrator WITH its replacement wording — the venue the doctrine prescribes",
      body: "**CLAUDE.md (supervised — not edited).** The sentence \"it read THREE until 2026-07-30\" is falsified by this PR. Proposed wording for the orchestrator: \"it reads FOUR as of 2026-07-31\".",
      issues: [],
      expect: "clear",
    },
    {
      name: "the same shape with NO replacement wording is still an unrelayed decline",
      body: "**CLAUDE.md (supervised — not edited).** A sentence in it is falsified by this PR and I have not said which.",
      issues: [],
      expect: "flagged",
    },
    {
      name: "a supervised file CHECKED and found to need nothing is not a decline",
      body: "**CLAUDE.md (supervised — not edited).** No sentence in it is falsified by this PR, and I checked the two this work touches.",
      issues: [],
      expect: "clear",
    },
    {
      name: "an unreadable tracker is reported, not counted clean",
      body: `${declineBody}\n\nTracked by #999999.`,
      issues: [],
      expect: "flagged",
    },
  ];
}
