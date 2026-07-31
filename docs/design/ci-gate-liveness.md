# CI gate liveness — a job that died must not read like a job that found nothing

## The incident

`corpus-drift` on `main` failed for days at **setup**: #1509's poisoned pipx cache meant `semgrep`
was absent, and the job died before it scored a single baseline. What it produced was
indistinguishable, to a reader, from "ran and found no drift".

In that window PR #1447 merged on three green required checks while the gate that measures its blast
radius **had never executed**. The cost, found only once the cache was fixed and the job could run:
653 M5-slop findings silently suppressed, and a live regression on `main`.

That is this repo's own central principle turned on its CI — CLAUDE.md's *"silent omission is worse
than a wrong status; an absent row never appears in a tally."*

## The rule

**A gate job must prove it reached its measuring phase before it is allowed to be green.**

This is not a new idea; it is `src/audit-runner.ts`'s `Examined` contract applied one level out. A
probe that reports `unitsExamined: 0` is rejected at normalization, because *"a probe that examined
nothing did not run, and must say so as `NotAssessed`"*. A CI gate is a probe over the repo, so it
gets the same treatment:

| state | verdict | job |
| --- | --- | --- |
| scored N > 0 units | `MEASURED` | green |
| short-circuited on purpose, with a reason | `DECLARED NO-OP` | green, and visibly not a scoring run |
| no record, or 0 units | `FAILED`, naming the phase | red |

The middle row carries as much weight as the last. A `paths:`-filtered **required** check deadlocks
every PR outside its filter (#1107), so those jobs run on every PR and short-circuit internally — and
a green short-circuit that looks like a green scoring run is the same defect one level down. The
no-op is therefore **declared**, with its reason, and the job summary says so in words a reader
will not mistake for a scored run.

## The mechanism

**`.github/actions/gate-liveness`** — one composite action, two modes.

- `mode: record` appends a line to a receipt file: `gate=<id> status=<measured|declared-no-op>
  units=<n> scope=<text>`. `units: 0` with `status: measured` is refused.
- `mode: assert` reads the receipt, requires a record for every id in `expect`, and writes a
  three-verdict table to the **job summary** as well as stdout.

The action's body is `gate-liveness.sh`, **pure bash, no toolchain**. The failure it exists to catch
is a job dying in setup — exactly when node, pnpm and tsx are unavailable. A liveness check that
needs the toolchain has nothing to say when the toolchain is what broke. It is a file rather than
inline YAML so `src/ci-liveness.test.ts` executes the real script; a TypeScript reimplementation
would only prove the reimplementation.

**`src/ci-liveness.ts`** is the producer side for the gate CLIs (`recordMeasured(gate, units,
scope)`), so a unit count is a real measurement rather than a number the workflow asserts about
itself. Off CI (no receipt path in the environment) it is silent apart from the zero-units throw, so
a local `pnpm corpus-drift` reads exactly as it did before.

The assert step runs on `always()` on purpose. A job that already failed is red either way; what the
step adds is the **name of the phase that never ran**, which is the whole difference between
"corpus-drift is red" and "corpus-drift never scored anything, so PR #1447 has no drift signal at
all".

## Coverage, and why a new gate does not quietly skip it

`.github/gate-liveness.json` is the registry. `src/ci-liveness.test.ts` (under `pnpm verify`)
enforces these against it:

1. **exhaustively over `.github/workflows/*.yml`**, every workflow is a registered gate or an
   `exempt` row — so a new workflow can only be CLASSIFIED, never omitted;
2. every registered gate id is both **asserted** by its workflow and **produced** by something (a
   `gate:` record step, or a `recordMeasured`/`recordDeclaredNoOp` call in a gate CLI) — a
   producer/asserter mismatch is a test failure, not a silently vacuous check;
3. every assert step is gated on `always()`;
4. every registered gate declares a `liveness_drill` dispatch input and carries a `provenBy` run or
   a `pendingProof` hatch (see the next section);
5. no alert step in a registered gate's workflow is reachable on a liveness drill — otherwise
   proving the guard raises a false alarm.

**#1568 replaced the discovery rule, and the replacement is the point.** It used to read "every
workflow that installs the mechanical binaries", a PROXY for "heavy enough to die in setup", chosen
because that is literally what #1509 broke. It left NINE workflows outside the registry by
construction — and, measured on adoption, two more that #1568's own list of nine did not think to
name (`semantic-freshness`, `site-ci`). A proxy does not become exhaustive by being widened; it has to be
replaced by it.

Registered as gates: `corpus-drift`; `conservation` (gate + negative controls); `dry-run-drift`
(regenerate + diff, as separate phases); `ci.yml`'s `heavy-cli` shards (tests + the
shard-conditional `calibration-gate`, `source-recall-gate` and `m2-coverage-gate`); `secbench`;
`free-recall`; `disclosure-venue` (gate 4 + gate 4b); `alert-paths` (label pass + its three seeded
controls); `acceptance`; `acceptance-close`; and `supervised-declines`.

`acceptance-close` is the sharpest of them. It runs on `issues: [closed]` — it answers to no PR, it
is on no schedule, and it raises no alarm. A run that dies in setup posts no comment, re-opens
nothing, and is indistinguishable from a close nobody had to object to. Nothing else in this repo
watches it.

`free-recall` is on the list because check (1) **fired for real** during the original work: #1185
landed the workflow on `main` mid-branch, the rebase brought it in, and `pnpm verify` went red naming
an unregistered gate job.

**An exemption is a claim, and it is machine-checked.** An `exempt` row asserts that a run which died
before scoring is DISTINGUISHABLE without a receipt. The test refuses that claim for any workflow
carrying a step gated on an in-job filter output or a matrix conditional — the #1107
filter-moved-in-job shape, which is exactly what turns a dead scoring phase green — and, for a
SCHEDULED exempt workflow, checks that the alert path its reason rests on actually exists in the
file. Each row states `measures` and `whyDistinguishable` separately, because "what it does" and
"why its silence is loud" are two claims and a single blob lets one carry the other.

Exempt today: `reasons-drift`, `corpus-m8`, `osv-staleness`, `owasp-ack-watch`,
`semantic-freshness`, `site-smoke` (each unconditional and alarmed on a scheduled failure) and
`site-ci` (reports on the PR that caused it).

Two gates deserve a note. **`heavy-cli`'s `expect` is matrix-dependent**, because three scored gates
ride inside `if: matrix.shard == N` — a condition that stopped matching would retire them in complete
silence, which is the shape #1301, #1288 and #1483 each found when those gates ran in no workflow at
all. And **conservation's negative controls get their own gate id**, because "the controls ran" is a
separate claim from "the gate ran": a gate nobody has watched fail is indistinguishable from a gate
with no failing direction at all.

## Proving it in both directions

Every registered gate carries a `liveness_drill` dispatch input. It breaks nothing — it **skips the
scoring step**, leaving a job every one of whose steps succeeds. The guard is then the only thing
that can turn it red, which is the strongest available demonstration: without it, that job is green
having measured nothing.

    gh workflow run "<workflow name>" -f liveness_drill=true

**The two drills are mutually exclusive by construction, and #1586's criterion 4 is why.** The alert
step fires on `failure() && workflow_dispatch`, so a liveness drill would have opened a REAL tracking
issue — a false alarm indistinguishable from a genuine failure. Each drill now switches the other's
machinery off: `alert_drill` skips the liveness assert (it fails on purpose before anything is
scored), `liveness_drill` skips the alert step. `src/ci-liveness.test.ts` enforces the second half.

**#1569 — every gate now records the run that proved it**, in a `provenBy` block mirroring
`.github/alert-paths.json`, because a path that has never fired reads exactly like one with no
failing direction (#1287's own finding). Eleven drills were dispatched on 2026-07-31; in every one
the gate-liveness assert was the ONLY failing step, with `GATE LIVENESS: FAILED` naming the gate ids
that never reached their measuring phase. `corpus-drift`'s drill additionally proved #1586's
criterion 4 in the other direction: shard 1 failed on the assert alone and the aggregate job carrying
the required context failed with it, so a shard that scored nothing never passes the aggregate.

`pendingProof` is the one disclosed way a gate may sit here unproven, and it is built to fail loud:
`why`, an OPEN `tracking` issue and `since` are all required, and it is mutually exclusive with
`provenBy` so a recorded proof REPLACES the hatch rather than sitting beside it.

The rule the hatch exists for was narrowed by measurement, twice. A `workflow_dispatch` INPUT need
only exist on the branch being dispatched (#1333, 2026-07-31) — but the workflow FILE must be on the
default branch, and that half reproduces: `gh api
repos/jharvieux/Harvey/actions/workflows/supervised-declines.yml/dispatches -f
ref=feature/sweep-ci-1545` returned **HTTP 404** on 2026-07-31 while ten sibling drills dispatched
from that same branch the same hour all ran. `supervised-declines` therefore lands with a
`pendingProof` tracked by #1688; every other gate is proven.

## Every new gate id, MEASURED on a real run (#1568 criterion 3)

Not "the step exists" — the receipt, with its unit count, off a real run. Every job below is from
PR #1697, and each workflow gets its OWN run id: there is no single "the PR's CI run" to cite, which
is how an earlier draft of this table came to name one (`30639911394`) that returns HTTP 404. The
run column is therefore per row, resolved from each job id via
`gh api repos/jharvieux/Harvey/actions/jobs/<job>`.

| gate id | units | job | run |
| --- | ---: | --- | --- |
| `disclosure-venue` | 113 semgrep rules | 91185487205 | 30639491696 |
| `conditional-scan` | 1 module with sibling scan paths | 91185487205 | 30639491696 |
| `alert-paths` | 15 alert paths across 18 workflows | 91185485326 | 30639491130 |
| `alert-paths-negative-controls` | 3 seeded controls | 91185485326 | 30639491130 |
| `acceptance-selftest` | 12 hermetic cases | 91185484982 | 30639491150 |
| `acceptance-pr` | 8 issues + remainders | 91185484982 | 30639491150 |
| `m2-coverage-gate` | 1 enumerated M2 target | 91185517613 | 30639491070 |
| `supervised-declines-selftest` | 9 hermetic cases | 91185487911 | 30639491925 |
| `acceptance-close-selftest` | 8 hermetic cases | — | 30640273614 |
| `acceptance-close` | 1 closed issue over 3 surfaces | — | 30640273614 |

`supervised-declines-selftest` scored **9** on that run and scores **17** after the precision fix
below; the run above is cited for what it measured on the day, not as the current count.

`supervised-declines` (the live scan) is the one id with no MEASURED run: it runs on no
`pull_request`, and its workflow cannot be dispatched until the file is on `main`. Tracked by #1688.

**The first attempt at this table failed, and the failure is the useful part.** All five newly-wired
jobs went RED on PR #1697's first run while scoring perfectly: `recordMeasured` writes nothing when
`HARVEY_LIVENESS_RECEIPT` is unset — it is silent off CI by design — while the bash asserter falls
back to `$RUNNER_TEMP`, so producer and asserter disagreed about the file. A liveness DRILL cannot
catch that, because a drill expects a red job. `src/ci-liveness.test.ts` now requires the job-level
env of every registered gate, and that rule is proven in both directions.

## What this deliberately does not do

- **It changes no required status check and does not touch branch protection.** Promoting
  `corpus-drift` to required is sequenced *after* this: making a 22-minute job required before you
  can tell "did not run" from "passed" makes the failure mode worse, not better.
- **It does not make the common path slower.** A file append and a file read; milliseconds.
- **It does not assert that a gate PASSED.** `MEASURED` means the phase ran and produced a number. A
  failing gate that reached its measuring phase records `MEASURED` and is red on its own merits —
  which is correct, and is why the conservation negative controls (which are *supposed* to exit
  non-zero) can be covered at all.

## What it does not yet cover

**The DECLARED NO-OP verdict has still not been observed on a live short-circuited job.** It is
proven by `src/ci-liveness.test.ts` against the real script, but every PR that touches this mechanism
also touches the paths those jobs filter on, so their in-job filters correctly report
`relevant=true`. The first docs-only PR after this lands will exercise it.

**`supervised-declines` is unproven in both of its paths** until its workflow file is on `main` —
see #1688, which carries the 404 that makes it unprovable before the merge.

**The exemption check is a floor, not a proof.** It refuses the one shape it can recognise — a
conditional scoring step — and takes the rest of `whyDistinguishable` on the prose. A workflow that
swallowed a failure some other way (`|| true` inside a multi-line `run:`, a `continue-on-error` on a
step the reason does not mention) would pass the check while its exemption was false.
