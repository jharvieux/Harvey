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

- The evidence check proves the **shape** of evidence, not its truth. It separates "done" from
  "`pnpm verify` — 25 files, 0 failures"; it cannot tell a real command from an invented one. It
  raises the floor; it is not a reviewer.
- Only bullets at the **shallowest indent** of the acceptance section are criteria. Deeper bullets
  read as elaboration — counted and reported in the output, never silently dropped.
- The parser is **negation-blind, exactly as GitHub is**: `does not close #19` closes #19. A gate that
  read the negation would wave through the exact PR bodies the audit found.
- A cross-repo or URL-form closing reference cannot be resolved by a repo-scoped lookup. It gets a
  named `NOT ASSESSED` row, not silence.

## Negative control

`--selftest` scores a hermetic scenario (`SELFTEST_BODY` / `SELFTEST_ISSUES`): one healthy body that
must PASS and four seeded violations — a dropped disposition, a `met` hollowed out to "done", a
remainder pointing at a CLOSED issue, a remainder pointing at one that does not exist — that must
each FAIL. It needs no network, so CI's proof that the gate can fail does not depend on whichever PR
is under test. `--seed-drop-disposition`, `--seed-bare-evidence` and `--seed-remainder <n>` plant the
same violations into a real body, mirroring `validate-conservation.ts`'s `--seed-*` flags. The same
scenario is scored by `src/acceptance-conservation.test.ts` under `pnpm verify`, so there is one
fixture rather than two that can drift apart.

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
