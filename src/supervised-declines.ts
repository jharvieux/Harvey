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
// PR #1481 is the case that settles it. It declined a `.github/workflows/` edit and filed #1483,
// which was a work item — a well-written one — that asked the operator nothing. Four days later the
// work was still undone and twelve unrelated commits had edited `.github/workflows/`. A tracker
// records that work remains; a relay records that the person who can authorise it was asked. Only
// the second unblocks anything, which is why the doctrine says to write the question ON THE ISSUE
// with the exact wording proposed, "where the operator reads it, not in this PR body".
//
// THAT SENTENCE IS IN THE PAST TENSE ON PURPOSE, and the correction is itself the point. MEASURED
// 2026-07-31: #1483 has SINCE gained a "**RELAY — needs an operator ruling, and the reason it is not
// done here.**" comment, so `--pr 1481` now reports that decline as relayed. The check reads the
// issue's CURRENT state, which is the documented design (the prose moves after the merge, so there
// is no stable answer at merge time) — and it means the live example an earlier draft of this
// comment leaned on has since resolved. The RULE is unchanged and is what the hermetic self-test
// pins, using #1483 as it stood; a claim about a live issue is not a fixture.
//
// So:
//
//   • QUOTED GRANT        — the PR body quotes the permission it was given.
//   • OPERATOR ASK        — the PR body names an issue that itself carries a question put to the
//                           operator, in its body or its comments.
//   • ORCHESTRATOR REPORT — the decline concerns CLAUDE.md or a supervised doc AND the SECTION
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
// `permission to` / `have permission` are here because the FIRST vocabulary missed the plainest
// grant this repo has ever recorded. MEASURED 2026-07-31: PR #1614 quotes the operator verbatim —
// "you have permission to edit workflows, docs, and claude.md, and to deploy to prod" — and was
// reported as an UNRELAYED DECLINE, i.e. the check flagged the one body that did exactly what the
// doctrine asks. A grant word list that cannot read the word "permission" is not a bound, it is a bug.
const GRANT_WORD = /\b(?:approved|granted|authorised|authorized|go-ahead|permission granted|(?:have|has|has been given) permission|permission to|you may)\b/i;
const CONDITIONAL = /\b(?:if|once|unless|when|pending|assuming)\s+(?:it is |this is |they are )?(?:approved|granted|authorised|authorized)\b/i;

function quotesAGrant(body: string): boolean {
  for (const m of body.matchAll(QUOTED_GRANT)) {
    const inner = m[1]!;
    if (GRANT_WORD.test(inner) && !CONDITIONAL.test(inner)) return true;
  }
  return false;
}

/**
 * The replacement wording an orchestrator can apply — the deliverable CLAUDE.md's own rule asks for
 * in the PR body. `suggested`/`wording proposed` and the plurals are here because executors write
 * this sentence in whatever register they please and the first list read only two of them: MEASURED
 * 2026-07-31, PR #1458 ("Suggested addition"), #1442 ("Suggested replacement") and #1445 ("wording
 * proposed", "proposed replacements") all CARRIED the deliverable and were reported as unrelayed.
 */
const PROPOSED_WORDING = /\b(?:proposed|recommended|suggested) (?:wording|replacements?|text|sentence|addition)\b|\b(?:wording|replacement) (?:proposed|recommended|suggested)\b|\breplacement wording\b|\bfor the orchestrator\b|\bfor (?:an|the) operator to apply\b/i;

/**
 * The supervised paths whose deliverable IS prose an orchestrator can lift out of a PR body, so the
 * body is the prescribed venue rather than a dodge. CLAUDE.md's own rule says so in as many words;
 * `docs/**` is on the same sensitive-paths list for the same reason ("the venture's positioning,
 * specs and GTM strategy — human-owned IP"), and a proposed replacement paragraph for a doc is
 * exactly as applicable as one for CLAUDE.md.
 *
 * THE SCOPE IS STILL LOAD-BEARING, which is why this is a widening and not a removal. It stops short
 * of `.github/workflows/**` and `report-template/findings.*.json` on purpose: there the deliverable
 * is the EDIT, not a paragraph, so the relay the doctrine asks for is a question on the issue.
 * MEASURED 2026-07-31 that the line still holds — PR #1481's archetypal decline ("Wiring
 * `pentest.ts --mode=coverage` into a venue is a `.github/workflows/` edit, which is supervised …
 * Proposed wording for the operator, if approved") names no `.md` file and stays flagged, so the
 * exemption still does not clear the instance this check was built from.
 */
const SUPERVISED_PROSE = /CLAUDE\.md|\bdocs\/[\w./-]*\.md\b/i;

/**
 * A criterion recorded MET is not a decline, whatever verbs sit next to it. MEASURED 2026-07-31: PR
 * #1538's "**ACCEPTANCE #742.1 met:** … No real client data was fabricated or anonymised:
 * `report-template/findings.*.json` is supervised client data and was not touched" was reported as
 * an unrelayed decline, when it states the opposite — the criterion was DELIVERED, and the supervised
 * file being untouched is why that is true. Deliberately `met` only: `relayed` and `split` are
 * dispositions on work that did NOT ship, and those still have to answer this check.
 */
const MET_CRITERION = /\bACCEPTANCE #\d{1,6}\.\d+ met:/;

/** A check that ran and came back empty is not a decline. Kept as its own verdict so "we looked and there was nothing" is never reported as "we declined". */
const NOTHING_OWED = /\bno sentence\b[^\n]{0,80}\bfalsif/i;

/** A question PUT TO THE OPERATOR, as distinct from any question. A work item full of rhetorical questions is still not an ask. */
const OPERATOR_ASK = /\?/;
const OPERATOR_ADDRESS = /\boperator\b|\bapprov|\bgrant|\bpermission\b|\bruling\b|\bmay I\b|\bgo-ahead\b|\bauthoris|\bauthoriz/i;
/**
 * An ask can be unambiguous and carry no question mark, and requiring one made the check miss the
 * clearest relay in the sample. MEASURED 2026-07-31: PR #1445's decline names #1070, which is headed
 * "## This needs an operator ruling, not a mechanical fix", carries "Operator ruling recorded: build,
 * or retract" and a recorded ruling of its own — and was reported as "asks the operator nothing"
 * purely because no single LINE holds both a `?` and an operator word. These are the repo's own
 * fixed phrases for having asked, so they are read as the ask they are; a rhetorical question still
 * needs the `?`-plus-address pair above, which is what keeps a tracker full of them from qualifying.
 */
const OPERATOR_ASK_PHRASE = /\boperator question\b|\bneeds? (?:an? )?operator (?:ruling|decision)\b|\boperator (?:ruling|decision) (?:recorded|requested|needed|required)\b|\bawaiting[- ]decision\b|\basked the operator\b|\bput to the operator\b|\bfor the operator to decide\b/i;

interface DeclineHit {
  /** 1-based line number in the PR body. */
  line: number;
  text: string;
  /** The block the line sits in. Scoped tightly on purpose: it is what decides `met-criterion`, and a MET disposition elsewhere in the section must not clear a decline. */
  paragraph: string;
  /** The markdown section the line sits in — where "tracked by #N" and the proposed wording actually live. */
  section: string;
  /** Issues the section names, which are where a relay would live. */
  issues: number[];
}

export interface IssueLike {
  number: number;
  body: string;
  comments: string[];
}

interface SupervisedDeclineTriage {
  pr: number;
  line: number;
  triagedBy: string;
  reason: string;
}

/**
 * Exact-instance false-positive records. Detection stays unchanged: a body edit that moves the hit
 * to another line, or any new PR with the same prose, is unrecorded and fails until read itself.
 */
const SUPERVISED_DECLINE_TRIAGE: readonly SupervisedDeclineTriage[] = [
  {
    pr: 1683,
    line: 36,
    triagedBy: "@jharvieux in #1821",
    reason:
      "CLAUDE.md had no falsified sentence; the sentence says the two falsified claims live in other files and were corrected there, so the shared-line decline signal attaches to the wrong file",
  },
];

export function supervisedDeclineTriage(pr: number, line: number): SupervisedDeclineTriage | undefined {
  return SUPERVISED_DECLINE_TRIAGE.find((record) => record.pr === pr && record.line === line);
}

interface DeclineVerdict {
  hit: DeclineHit;
  relay: "quoted-grant" | "operator-ask" | "orchestrator-report" | "nothing-owed" | "met-criterion" | "none";
  detail: string;
}

const ISSUE_REF = /#(\d{1,6})\b/g;

export function findSupervisedDeclines(body: string): DeclineHit[] {
  const lines = body.split("\n");
  return lines.flatMap((text, i) => {
    if (!SUPERVISED_SIGNAL.test(text) || !DECLINE_SIGNAL.test(text)) return [];
    const section = sectionAround(lines, i);
    return [{ line: i + 1, text: text.trim(), paragraph: paragraphAround(lines, i), section, issues: [...section.matchAll(ISSUE_REF)].map((m) => Number(m[1])) }];
  });
}

function paragraphAround(lines: string[], i: number): string {
  let start = i;
  let end = i;
  while (start > 0 && lines[start - 1]!.trim() !== "") start--;
  while (end < lines.length - 1 && lines[end + 1]!.trim() !== "") end++;
  return lines.slice(start, end + 1).join("\n");
}

const HEADING = /^#{1,6}\s/;
/**
 * Bounded so a body with no headings at all cannot become one section — an unbounded window would
 * let any relay anywhere in the body clear any decline, which is the opposite failure to the one
 * below and just as silent.
 */
const SECTION_SPAN = 40;

/**
 * The SECTION, not the paragraph. THE PARAGRAPH WAS THE WRONG UNIT and it made the check cry wolf
 * on its own first scheduled window — MEASURED 2026-07-31, `--since-days 1` over 72 merged PRs
 * reported 4 unrelayed declines of which at least 3 were false. The dominant shape: executors write
 * the decline as a HEADING ("## CLAUDE.md sentence this PR falsifies (relay — NOT edited here)") and
 * the relay in the prose beneath it, so the hit's own paragraph is the heading alone and the
 * deliverable one blank line away read as absent. Live instances, every one carrying its relay:
 * #1662:101, #1233:95 (a "Recommended replacement:" six lines down that PROPOSED_WORDING already
 * matched), #1429:75, #1442:85, #1445:90, and #1458:48 whose "CLAUDE.md" sits in the heading ABOVE
 * the hit — which is why this walks both ways rather than only down.
 */
function sectionAround(lines: string[], i: number): string {
  let start = i;
  while (start > 0 && start > i - SECTION_SPAN && !HEADING.test(lines[start]!)) start--;
  let end = i;
  while (end < lines.length - 1 && end < i + SECTION_SPAN && !HEADING.test(lines[end + 1]!)) end++;
  return lines.slice(start, end + 1).join("\n");
}

/**
 * `lookup` returning undefined means the issue could not be read. That is UNVERIFIABLE, not
 * "carries no ask" — the caller must not fold the two together, so it is reported in `detail`
 * rather than silently counted as a violation.
 */
export function judgeDecline(hit: DeclineHit, body: string, lookup: (issue: number) => IssueLike | undefined): DeclineVerdict {
  // PARAGRAPH, not section, and deliberately narrower than the relay window below. "No sentence is
  // falsified" is a claim about ONE file, so reading it at section scope lets a clean report on
  // CLAUDE.md clear a live decline on a doc three paragraphs up — the #1062 masking shape, reached
  // through a widened window. MEASURED 2026-07-31 on PR #1490, where exactly that happened.
  if (NOTHING_OWED.test(hit.paragraph)) return { hit, relay: "nothing-owed", detail: "reports a check that came back empty — nothing was declined" };
  if (MET_CRITERION.test(hit.paragraph)) return { hit, relay: "met-criterion", detail: "sits inside an ACCEPTANCE … met disposition — the criterion was delivered, not declined" };
  if (quotesAGrant(body)) return { hit, relay: "quoted-grant", detail: "the PR body quotes the grant it was given" };
  if (SUPERVISED_PROSE.test(hit.section) && PROPOSED_WORDING.test(hit.section)) {
    return { hit, relay: "orchestrator-report", detail: "a supervised PROSE sentence reported with its replacement wording — the venue CLAUDE.md's own rule prescribes" };
  }
  const unreadable: number[] = [];
  for (const n of hit.issues) {
    const issue = lookup(n);
    if (!issue) {
      unreadable.push(n);
      continue;
    }
    const venues = [issue.body, ...issue.comments];
    const asked = venues.find((v) => OPERATOR_ASK_PHRASE.test(v) || v.split("\n").some((l) => OPERATOR_ASK.test(l) && OPERATOR_ADDRESS.test(l)));
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
 * never goes green because GitHub was slow.
 */
export function selftestCases(): { name: string; body: string; issues: IssueLike[]; expect: "flagged" | "clear" }[] {
  const declineBody = "**Relay — needs an operator decision, not doable here.** Wiring `pentest.ts --mode=coverage` into a venue is a `.github/workflows/` edit, which is supervised. It is disclosed in the row, tracked by #1483, and NOT done in this PR.";
  return [
    {
      name: "PR #1481's decline with the tracker it filed, #1483 AS IT STOOD — a tracker is not a relay",
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
    // #1545's first live window. Each of the four below reproduces a body that was flagged on
    // 2026-07-31 and should not have been, and each is paired with the shape that MUST still fire —
    // a rule relaxed without its negative control is how the check stops measuring anything.
    {
      name: "PR #1662's shape — the decline is the HEADING and the relay is the prose beneath it",
      body: "## CLAUDE.md sentence this PR falsifies (relay — NOT edited here)\n\nUnder \"Known gaps\", this sentence becomes false when this PR lands:\n\n> those three round-trips are proven at the LIBRARY level only\n\nRecommended replacement:\n\n> #1407 closed 2026-07-31: each wiring file's reversion turns it red.",
      issues: [],
      expect: "clear",
    },
    {
      name: "the same heading shape with no replacement wording anywhere in the section still fires",
      body: "## CLAUDE.md sentence this PR falsifies (relay — NOT edited here)\n\nUnder \"Known gaps\", this sentence becomes false when this PR lands:\n\n> those three round-trips are proven at the LIBRARY level only\n\nI have not written what it should say instead.",
      issues: [],
      expect: "flagged",
    },
    {
      name: "PR #1458's shape — the supervised file is named in the heading ABOVE the decline",
      body: "## CLAUDE.md — one sentence to consider\n\nNot edited (supervised). The \"Verify command\" section now also enforces the walk guard. Suggested addition after the `test-only-exports` sentence:\n\n> Since #1451 `pnpm verify` also enforces the directory-walk guard.",
      issues: [],
      expect: "clear",
    },
    {
      name: "PR #1614's shape — a verbatim operator grant, in the vocabulary the first word list could not read",
      body: "Operator grant in force this sweep, verbatim: \"you have permission to edit workflows, docs, and claude.md\". Branch protection was not granted, and the `.github/workflows/` change it would need is not done in this PR.",
      issues: [],
      expect: "clear",
    },
    {
      name: "PR #1538's shape — a criterion recorded MET, whose supervised file being untouched is why it is true",
      body: "**ACCEPTANCE #742.1 met:** the SYNTHETIC arm is taken and already true on `main`. No real client data was fabricated: `report-template/findings.*.json` is supervised client data and was not touched.",
      issues: [],
      expect: "clear",
    },
    {
      name: "a RELAYED disposition is not a met one — work that did not ship still answers this check",
      body: "**ACCEPTANCE #742.1 relayed:** rendering it needs a `report-template/findings.*.json` edit, which is supervised, and is not done in this PR.",
      issues: [],
      expect: "flagged",
    },
    {
      name: "PR #1481's archetype — a `.github/workflows/` edit is not prose an orchestrator can apply, so wording alone is no relay",
      body: "**Relay — needs an operator decision.** Wiring `pentest.ts --mode=coverage` into a venue is a `.github/workflows/` edit, which is supervised, and NOT done in this PR. Proposed wording for the operator, if approved: add a step to `heavy-cli` shard 3.",
      issues: [],
      expect: "flagged",
    },
    {
      name: "PR #1445's shape — the named issue asks in the repo's own fixed phrase, with no question mark",
      body: `${declineBody}\n\nExact current wording and proposed replacements are on #1483.`,
      issues: [{ number: 1483, body: "## This needs an operator ruling, not a mechanical fix\n\n- [ ] Operator ruling recorded: build, or retract", comments: [] }],
      expect: "clear",
    },
    {
      name: "a tracker that merely DISCUSSES the operator, with no ask and no question, is still not a relay",
      body: `${declineBody}\n\nExact current wording is on #1483.`,
      issues: [{ number: 1483, body: "A parity exemption's substitute gate is proven to EXIST, never to RUN. The operator ruling of 2026-07-25 already covers the adjacent case.", comments: [] }],
      expect: "flagged",
    },
    {
      name: "a clean report on ONE supervised file must not clear a live decline on another in the same section",
      body: "## Relays\n\n**`docs/m7-performance.md` (supervised — I have not edited it).** The table is out of date and is not changed here, and I have not written what it should say.\n\n**CLAUDE.md (supervised — not edited).** No sentence in it is falsified by this PR.",
      issues: [],
      expect: "flagged",
    },
    {
      name: "the same wording for a supervised DOC is a relay — the deliverable there IS the paragraph",
      body: "**`docs/m7-performance.md` (supervised — I have not edited it).** §2a's per-class limitation table predates this change set, and is not changed here. Proposed wording, for an operator to apply:\n\n> §2a covers the three classes the code-tier pass reads.",
      issues: [],
      expect: "clear",
    },
  ];
}
