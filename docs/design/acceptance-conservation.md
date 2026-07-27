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

- The evidence check proves the **shape** of evidence, not its truth. It separates "done" from
  "`pnpm verify` — 25 files, 0 failures"; it cannot tell a real command from an invented one. It
  raises the floor; it is not a reviewer.
- **Per-shape looseness, and what the 2026-07-27 narrowing changed.** Three of the five shapes were
  found accepting plain prose; two were narrowed and one is deliberately left as it is:
  - **The quoted shape** accepts any 8+ characters between double quotes, so `"it all looks great"`
    passes as "a quoted test name". Nothing mechanical distinguishes a quoted test name from a quoted
    sentence, and requiring a nearby word like *test* would reject a bare, correct test name. Left
    loose on purpose.
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
  latent gap rather than reinterpreting real bodies. The residual bound: a genuine sub-section under
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
  it describes this deferral, or that the remainder covers the split-out work. Tightening it would
  mean parsing intent from prose, which is the judgement call this gate deliberately does not make.
- The parser is **negation-blind, exactly as GitHub is**: `does not close #19` closes #19. A gate that
  read the negation would wave through the exact PR bodies the audit found.
- A cross-repo or URL-form closing reference cannot be resolved by a repo-scoped lookup. It gets a
  named `NOT ASSESSED` row, not silence.
- The gate reads the PR **body**. A criterion met by a bare click — closing the issue in the GitHub UI
  or from the Development sidebar, with no closing keyword to parse — never reaches it. Tracked as
  **#1341**; not addressed here.

## Negative control

`--selftest` scores a hermetic scenario (`SELFTEST_BODY` / `SELFTEST_ISSUES`): one healthy body that
must PASS and six seeded violations — a dropped disposition, a `met` hollowed out to "done", a
remainder pointing at a CLOSED issue, a remainder pointing at one that does not exist, a `met` whose
only sha-shaped evidence is English words spelt in hex letters, and an acceptance section whose
bullets sit below a standalone bold line — that must each FAIL. It needs no network, so CI's proof
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
