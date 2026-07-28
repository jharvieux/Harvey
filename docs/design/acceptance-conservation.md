# Conservation of acceptance criteria (Gate 1 + Gate 2 of #1320)

`docs/design/conservation-of-findings.md` records the gate one layer down: a detector can work while
its finding never reaches the deliverable, so `validate-conservation` asserts `produced == delivered`.

**The issue tracker has the identical defect one layer up.** `Closes #N` fires on merge with nothing
verifying #N's acceptance criteria. Same shape, different layer: *stated is not met*. An audit of 562
closed issues on 2026-07-27 found ~60 closed with unmet criteria — and in almost every case **the
executor was honest in the PR body and the merge happened anyway**. #1206's PR body was headed
`## Does NOT close #1206`; two comments after the close still said the issue stayed open; it closed on
merge and the bug recurred in CI two hours later. #743's closing PR contained a section headed *"Why
this stays open (not 'Closes #743')"*. Honesty in a PR body is not a gate. This is the gate.

## The mechanism

`pnpm validate-acceptance --pr <n>` (`src/cli/validate-acceptance.ts`, logic in
`src/acceptance-conservation.ts`) reads the PR body, finds every closing keyword, and requires each
acceptance bullet of each issue it would close to be mapped to exactly one disposition:

| disposition | requires |
|---|---|
| `met` | evidence — a command, a `file.ts:line`, a quoted test name, or a commit sha |
| `split` | a remainder issue that **exists, is OPEN, and is cross-linked from the original** |
| `relayed` | a question recorded **as a comment on the issue**, not in the PR body |

An unmapped bullet fails. A `met` reading "done" fails — it is an unmapped bullet wearing a label.
An issue that states **no** criteria does not pass silently: it needs an explicit
`ACCEPTANCE #<issue> no-stated-criteria: <what the bar was>`, because that is where closing with an
unmet bar is easiest.

`relayed` is first-class because the audits found *"supervised path"* terminating issues rather than
producing a question, while **no executor has ever recorded "asked the operator, was refused"** and
grants are demonstrably routine (#1141 carries a verbatim *"Workflow changed approved"*). A blocker
the operator could clear must become a question, not a silent close.

### Gate 2 — remainder liveness (#1316)

`split` is worthless unless the remainder is alive, so every `remainder: #X` and every `split` target
is checked on three conditions **reported separately**: exists / OPEN / cross-linked from the
original. #715 deferred its live proof to #161, which had closed **nine minutes earlier** (verified
2026-07-27: #161 closed `2026-07-22T01:46:54Z`, #715 at `01:55:56Z`) — and #161's own closing comment
had deferred the same work back to #715. Each handed it to the other; both closed; the work vanished
for 16 days. That class **cannot be caught by reading the PR**: the deferral text is perfectly
correct, and only the target's state is wrong.

## Deliberate, disclosed bounds

This list is meant to be **complete**, and the file header of `src/acceptance-conservation.ts` points
here rather than restating a subset. Gate 4 (#1317) ships the rule that *a bound recorded in a comment
must appear in the finding it bounds*; a gate owes its own design doc the same.

**Every bound below was re-tested on 2026-07-27 by the #1320 bounds audit, which asked the only
question that matters about a list like this: is each one really a limitation?** Three were not, and
are struck through with the mechanism that replaced them. The audit's own standing rule applies to
what remains: a bound stated as an assertion closes the file, so an untested one is now a question.

- ~~The evidence check proves the **shape** of evidence, not its truth … it cannot tell a real
  command from an invented one.~~ **FALSIFIED 2026-07-27.** Three of the five shapes name something
  whose existence is a lookup, and the gate now performs it (`EvidenceWorld` in
  `src/acceptance-conservation.ts`): a cited repo-relative path is stat'd, a `pnpm <script>`
  reference is checked against `package.json`, and a quoted span counts as a test name only when the
  suite contains that title or a title begins with it.

  **The numbers, re-measured 2026-07-27 by replaying the gate's own parser and filters over the
  `met` lines of the last 60 merged PRs** — 11 such lines, across 2 PRs, because every other merged
  body predates the convention:
  **11** cited repo paths, **0** missing; **3/3** `pnpm <script>` names are real scripts; **8/9**
  quoted spans name a real test. The earlier *16/16* was the RAW `FILE_PATH` regex count before the
  gate's own "contains a `/` and its first segment is a top-level entry" filter — 17 raw matches
  today, 11 after it — so it counted foreign trees and bare filenames the gate deliberately never
  stats. Quote the filtered number; the conclusion (nothing invented, and an invention would show)
  is unchanged. The earlier *6/9* undercounted for a different reason: 6 quoted spans match a title
  exactly and **2 more are correct citations of real titles quoted by PREFIX**, truncated at the
  title's em-dash (`"NEGATIVE CONTROL: a remainder pointing at a CLOSED issue fails"`, whose title
  continues `— the #715 → #161 shape`). Exact set membership scored both as misses, so the check has
  been given prefix tolerance (`namesATest`) — a span counts when a title starts with it at a word
  boundary. The remaining one, the bare word `"cross-linked"`, is correctly not a test name.

  What survives is narrower and true: a `met` naming a command with no `pnpm` script (`node …`,
  `docker …`, a shell pipeline) is still checked for shape only, and no shape check reads a
  command's OUTPUT. The gate raises the floor; it is still not a reviewer.
- **The `pnpm` truth check reads only BACKTICKED spans, and never a flag** (added 2026-07-27 after
  the #1345 acceptance verifier found it over-refusing). The first shape was
  `` /\bpnpm\s+(?:run\s+)?([\w:-]+)/g ``, which read the token after `pnpm` as a script name whatever
  it was: it told the author of `` `pnpm --filter site build` `` that `pnpm --filter` "is not a
  script in package.json", and read the prose *"ran pnpm and it worked"* as an invented `pnpm and`. A
  false REJECT that denies a TRUE statement is the one failure this check must not produce — the
  claim of a truth pass is that an invention is separable from the real thing, and it stopped being
  separable the moment a correct command failed it. The cost of the fix, stated rather than left
  implicit: an **unbackticked** `pnpm verify` is no longer truth-checked (it still has to satisfy a
  shape), a `--filter`/`-r`/`-C` command is left unchecked because the script lives in another
  package's manifest this checkout does not read, and pnpm's own subcommands are passed through. All
  3 `pnpm <script>` references in the measured population are backticked, so the narrowing costs
  nothing there.
- **A closing reference whose form this gate cannot resolve gets a NOT ASSESSED row, and the run
  continues.** `Closes https://github.com/orgs/acme/projects/1/issues/5` has more than two path
  segments before `/issues/`; it used to THROW out of `closingRef`, killing the CLI with a Node
  stack trace at exit 1 (*"the gate failed"*) rather than its documented exit 2 (*"the gate could
  not run"*) — a crash where a disclosure belongs. It is now named in the output, and the Gate 1
  header says so rather than reporting *"no closing keyword"*, which would be false.
- **The shape-only `NOT ASSESSED` row is a property of the LIBRARY, not of the CLI.**
  `checkAcceptance` called without an `EvidenceWorld` says evidence was checked for shape only,
  rather than looking like a verified run. `validate-acceptance.ts` builds that world
  unconditionally out of the checkout it is running from, so the CLI never takes that branch: if
  `src/` or `package.json` were missing it would throw, not disclose. Do not read the row as a
  degraded-CLI mode; there is no flag that reaches it.
- **Per-shape looseness, and what the 2026-07-27 narrowing changed.** Three of the five shapes were
  found accepting plain prose; two were narrowed and one was left loose and has since been closed:
  - ~~**The quoted shape** accepts any 8+ characters between double quotes … Nothing mechanical
    distinguishes a quoted test name from a quoted sentence.~~ **FALSIFIED 2026-07-27** — the suite
    is a list of test names, so asking it is mechanical. A quoted span now counts as *a quoted test
    name* only when the suite contains that title; `"it all looks great"` does not, and a real test
    title does. A quote that is not a test name does not fail the line by itself — the line simply
    has to carry one of the other four shapes, which every `met` line measured already did. The
    original objection (*requiring a nearby word like "test" would reject a bare, correct test
    name*) was right about that mechanism and was generalised to all of them.
  - **The backticked shape** was `` `[^`]{4,}` ``, which accepted `` `all good` ``. It now requires the
    span to be a single token (a path, a flag, an identifier) **or** to contain a character English
    prose does not use, so a backticked English phrase no longer passes. A single backticked English
    *word* of 4+ characters still does, if the rest of the line pushes the line past 12 characters.
  - **The commit-sha shape** was `` \b[0-9a-f]{7,40}\b ``, which matched ordinary English —
    *defaced*, *accede*, *facade* are words spelt entirely in `[a-f]` — and any 7-digit number, so
    `run 90131391124 was green` read as a commit reference. It now requires the run to mix digits
    **and** hex letters. The cost: a short sha prefix that happens to be all digits or all `[a-f]`
    is no longer recognised as a sha. Cite it in backticks, or name the command, instead.
- **The gate rewards formatting in both directions, and errs toward refusing.** Good evidence phrased
  as plain prose is rejected — `measured: 5 of 5 criteria dispositioned, 0 unmapped` fails, and so
  does an unquoted test name. This is deliberate: a false ACCEPT lets an unmet criterion close an
  issue silently, which is the #1206 shape the gate exists for, while a false REJECT is loud, names
  every accepted shape in the error, and is fixed by adding backticks.
- Only bullets at the **shallowest indent** of the acceptance section are criteria. Deeper bullets
  read as elaboration — counted and reported in the output, never silently dropped.
- The section runs from the acceptance heading to the next heading **at or above its own level**. A
  standalone bold line (`**Like this.**`) and a deeper `###` sub-heading do **not** end it. They used
  to: `## Acceptance / - one / **This one matters.** / - two / - three` parsed as **one** criterion
  and reported nothing, so two bullets were dropped with no row in the output — silent omission inside
  the gate whose subject is silent omission. Measured against the 200 most recent issues on
  2026-07-27, 156 of which carry an acceptance section, the change moved **zero** of them; it closes a
  latent gap rather than reinterpreting real bodies. (Re-run the same afternoon by the bounds audit:
  **159** of 200 — the tracker moved by three issues in a day, which is the reason a stored number is
  not an argument's premise. `gh issue list --state all --limit 200` is the input.) The residual bound: a genuine sub-section under
  the acceptance heading now contributes its bullets as criteria, which fails LOUD rather than
  dropping them. When the acceptance heading is itself bold, the next bold line still ends it.
- **A green `cross-linked` row proves the remainder number is discoverable from the original — nothing
  more.** The condition is satisfied by **any** mention of that number anywhere in the original's body
  or comments, in any sentence. Demonstrated live on 2026-07-27: re-pointing #1316.3's `split` at
  #1260 — unrelated M2 work that #1316's body names only in a historical aside (*"Recovered only by
  this audit, 16 days later, as #1260"*) — satisfies exists, OPEN and cross-linked, and the gate
  prints `✓ cross-linked: #1316 references #1260` and exits 0. So a reader **can** conclude the
  number appears on the
  original and a human following the issue would see it; they **cannot** conclude the sentence around
  it describes this deferral, or that the remainder covers the split-out work.

  ~~Tightening it would mean parsing intent from prose.~~ **Mischaracterised — corrected
  2026-07-27.** The obvious tightening is not intent-parsing, it is *vocabulary*: require the mention
  to sit in a sentence carrying a deferral word. Measured against five real pairs, that rule is right
  on **3 of 5** — it correctly refuses the recorded false accept (#1316 → #1260, a historical aside)
  and correctly passes #1317 → #1330 and #1307 → #1328, but wrongly refuses #1317 → #1342, whose
  cross-link reads *"Gate 4a residual filed as #1342"* — deferral vocabulary the list did not happen
  to contain. That is the identical defect #1342 records against Gate 4's own `BOUND_MARKERS`: a
  check whose coverage turns on which words an engineer reached for. So the bound is real, and the
  reason is a **measured false-refusal rate**, not a category boundary. The open question, rather
  than an assertion: *is there a rule that refuses the #1260-style aside without depending on a
  vocabulary list?* Nobody has tested one.

  That bound is now a **registry block** beside `checkRemainder` in `src/acceptance-conservation.ts`,
  not doc prose — `pnpm validate-reasons --revalidate` re-runs its falsifier, which is the pinned
  test `a historical aside satisfies cross-linked` and exits 0 the day a tighter rule makes that test
  fail. Exercised in both directions 2026-07-27: exit 1 as committed, exit 0 with a deferral-word
  rule spliced into `checkRemainder`.

  The fifth pair was a live finding, not a hypothetical: **#1315 → #1341 failed the condition** —
  `gh issue view 1315` mentioned #1341 nowhere in its body or comments, so Gate 1's own remainder was
  not discoverable from the issue it was split out of. Fixed the same day by commenting the
  cross-link on #1315, so re-reading this paragraph will no longer reproduce it; the finding is
  recorded here because the shape (#715 → #161, one level up) is the point, not the row.
- The parser is **negation-blind, exactly as GitHub is**: `does not close #19` closes #19. A gate that
  read the negation would wave through the exact PR bodies the audit found. Re-verified 2026-07-27:
  `gh api repos/:owner/:repo/issues/1206/timeline` shows `closed 2026-07-27T12:00:24Z` on a PR whose
  body was headed *"## Does NOT close #1206"*. (It shows `reopened 2026-07-27T20:31:22Z` too, so a
  reader checking the issue today finds it OPEN — the close is in the timeline, not the state.)
- ~~A cross-repo or URL-form closing reference cannot be resolved by a repo-scoped lookup. It gets a
  named `NOT ASSESSED` row, not silence.~~ **FALSIFIED 2026-07-27** — near-circular, and the
  circularity was hiding a choice: the lookup was repo-scoped because it was written that way.
  `gh issue view 2196 --repo OWASP/CheatSheetSeries` exits 0, and so does the URL form (both run
  2026-07-27). `owner/repo#N` and `https://…/issues/N` now resolve to an owner and a number, are
  fetched with `--repo`, and are held to their own acceptance criteria; a cross-repo form naming
  *this* repo is normalised so one issue is not fetched twice. The `NOT ASSESSED` row is gone
  because there is nothing left unassessed. Population at the time of the change: **0** of the last
  60 merged PRs carried such a reference — the row was disclosing a limit nobody had hit, which is
  precisely how a false one survives.
- The gate reads the PR **body**. A criterion met by a bare click — closing the issue in the GitHub UI
  or from the Development sidebar, with no closing keyword to parse — never reaches it. Tracked as
  **#1341**; not addressed here.

  <!--
  REASON: does a Development-sidebar link close an issue on merge with no closing keyword in the PR body, so that the gate never runs against it?
  KIND: empirical
  PROVENANCE: ASSUMED 2026-07-27 — recorded in #1341 from reading GitHub's documented behaviour. Nobody has linked an issue by the sidebar and merged to watch what the gate does, which is the whole reason it is written here as a question.
  FALSIFIER: gh issue view 1341 --json state --jq .state > /tmp/harvey-1341.state 2>/dev/null || exit 127; grep -qix closed /tmp/harvey-1341.state && exit 0 || exit 1
  TOUCHES: src/acceptance-conservation.ts
  -->

  The falsifier above is deliberately weak and says so: it fires when **#1341 itself is closed**,
  which is the event that means somebody went and settled the question. There is no offline command
  that observes GitHub's merge-time close behaviour, and inventing one that re-tests nothing is the
  #1246 failure this convention exists to prevent.

  It shipped in a form that could never fire, and that is worth recording rather than quietly
  correcting: it read the state through `gh api …/issues/1341 --jq .state`, which returns lowercase
  `closed`, and tested it with a case-sensitive `grep -q CLOSED`. Exercised in both directions on
  2026-07-27 the broken form exits 1 against the OPEN #1341 **and** exits 1 against the CLOSED
  #1340 — so it sat inside a green `--revalidate` run re-testing nothing, which is the exact #1246
  shape this document's own bounds list cites. `gh issue view --json state` returns `CLOSED`
  uppercase; the `-i` makes the check independent of which of the two APIs answers. Every falsifier
  written for this program was then re-run against a state where its blocker is GONE, because one
  case-sensitivity bug getting through is evidence about the batch, not about the line.

## Negative control

`--selftest` scores a hermetic scenario (`SELFTEST_BODY` / `SELFTEST_ISSUES`): one healthy body that
must PASS and eight seeded violations — a dropped disposition, a `met` hollowed out to "done", a
remainder pointing at a CLOSED issue, a remainder pointing at one that does not exist, a `met` whose
only sha-shaped evidence is English words spelt in hex letters, an acceptance section whose
bullets sit below a standalone bold line, a `met` citing a repo path that does not exist, and a
`met` citing a `pnpm` script that is not in `package.json` — that must each FAIL. Count the cases
from `selftestCases()`, not from this sentence. It needs no network, so CI's proof
that the gate can fail does not depend on whichever PR is under test. `--seed-drop-disposition`,
`--seed-bare-evidence` and `--seed-remainder <n>` plant the first three into a real body, mirroring
`validate-conservation.ts`'s `--seed-*` flags; the last two are hand-written bodies, because a seeder
that mutates a healthy body can only plant what that body already contains. The same scenario is
scored by `src/acceptance-conservation.test.ts` under `pnpm verify`, so there is one fixture rather
than two that can drift apart.

Each of the three rules narrowed on 2026-07-27 was proven to fail in isolation by reverting the fix
and watching exactly its own control go red: the sha shape (`NEGATIVE CONTROL: English words spelt in
hex letters are not a commit sha`), the backtick shape (`NEGATIVE CONTROL: backticking a phrase of
plain English does not make it a command`) and the section parser (`NEGATIVE CONTROL: a standalone
bold line does NOT end the section`).

The four rules changed the same day by the #1345 acceptance verifier's findings carry their own,
each proven by reverting the fix and watching only that control redden: the `pnpm` over-refusal
(`NEGATIVE CONTROL: a flag is not a script name, and a workspace command is not an invention` and
`NEGATIVE CONTROL: prose mentioning pnpm is not a script reference`, with `SCOPE CONTROL: a
genuinely invented script inside backticks still fails` holding the other direction), prefix
tolerance (`NEGATIVE CONTROL: prefix tolerance does not accept a quote that no title starts with`),
the unresolvable closing reference (`NEGATIVE CONTROL: an issue URL with extra path segments no
longer kills the run`) and the lookup sentinel (`NEGATIVE CONTROL: a repository that does not
resolve is UNREADABLE, not absent`).

**Where this program's bounds live.** Every EMPIRICAL bound of the six gates is a registry block —
`REASON:`/`KIND:`/`PROVENANCE:`/`FALSIFIER:` — rather than prose here, so
`pnpm validate-reasons --revalidate` re-tests it on the daily cadence: the two Gate 4 bounds and the
semgrep-only scope in `src/disclosure-venue.ts`, Gate 3's `ignoreExportsUsedInFile` blind spot in
`src/test-only-exports.ts`, Gate 2's cross-linked condition beside `checkRemainder`, and #1341's
question above. Every one was exercised in BOTH directions on 2026-07-27 — run as committed, then
run again against a state where its blocker is gone — because a falsifier nobody has watched exit 0
is indistinguishable from one that cannot. The bounds that remain prose here are DECISIONAL (a rule
that errs toward refusing, an indent convention, negation-blindness): re-testing a product ruling by
command is a category error and the reason gate refuses it. Folding those into decisional blocks
with an `OWNER`/`DECISION` is the remainder, tracked as **#1349**.

Exit codes are three-valued on purpose: `0` pass or green no-op, `1` gate failed, `2` gate could not
run. A control that accepted any non-zero code would go green on exit 2 — the #1246 shape, where five
recorded falsifiers died on a shell input-redirect and were read as "the blocker still holds".

## Wiring

`.github/workflows/acceptance.yml`, job `acceptance`, check context
**`every closed issue's acceptance criteria are accounted for`**. No `paths:` filter and no job-level
`if:`, because a required context that never reports deadlocks every PR outside its filter (#1107).
The relevance test lives **inside the CLI** — a PR is in scope if its *body* carries a closing keyword
or a `remainder:` line, which no file diff can answer — so the short-circuit uses the same parser the
gate uses instead of a second copy in YAML that could disagree with it. `edited` is in the trigger
list because the input is the PR body.

### Scoping, and why both gates share one context

GitHub's required-checks list is **branch-level only** — there is no per-PR-type requirement — so all
the scoping has to live in the job's own relevance test. Each gate states its verdict on its own line,
first, every run:

```
● Gate 1 (acceptance criteria, #1315): 2 closing reference(s) — #1315, #1316.
○ Gate 2 (remainder liveness, #1316): NO-OP — no `remainder:` line and no `split` disposition …
```

Gate 1 is in scope iff the body carries a closing keyword; Gate 2 iff it declares a remainder or a
`split`. Either can no-op while the other runs. **An unexplained green is indistinguishable from a
check that did nothing because it was broken**, so a no-op always names its reason.

They share one job and one context deliberately. Splitting them would add a second required context
for a 16-second check, and would let a `split` disposition be accepted by a green Gate 1 while Gate 2
— the only thing that makes `split` mean anything — sat red on the same PR. They are one assertion.
