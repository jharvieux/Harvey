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
enforces three things against it:

1. every workflow that installs the mechanical binaries — the marker of a job heavy enough to die in
   setup — is registered or exempt **with a reason**;
2. every registered gate id is both **asserted** by its workflow and **produced** by something (a
   `gate:` record step, or a `recordMeasured` call in a gate CLI) — a producer/asserter mismatch is a
   test failure, not a silently vacuous check;
3. every assert step is gated on `always()`.

Registered today: `corpus-drift`, `conservation` (gate + negative controls), `dry-run-drift`
(regenerate + diff, as separate phases), `ci.yml`'s `heavy-cli` shards (tests + the shard-conditional
`calibration-gate` and `source-recall-gate`), `secbench`, and `free-recall`.

`free-recall` is on that list because check (1) **fired for real** during this work: #1185 landed the
workflow on `main` mid-branch, the rebase brought it in, and `pnpm verify` went red naming an
unregistered gate job. Wiring it took four lines — which is the point of preferring a working guard
over a disclosure row.

Two of those deserve a note. **`heavy-cli`'s `expect` is matrix-dependent**, because the calibration
gate rides inside `if: matrix.shard == 1` and the source-recall gate inside `if: matrix.shard == 2` —
a condition that stopped matching would retire the repo's scored recall gates in complete silence,
which is the shape #1301 and #1288 each found when those gates ran in no workflow at all. And
**conservation's negative controls get their own gate id**, because "the controls ran" is a separate
claim from "the gate ran": a gate nobody has watched fail is indistinguishable from a gate with no
failing direction at all.

## Proving it in both directions

Each wired workflow with a `workflow_dispatch` trigger carries a `liveness_drill` input. It does not
break anything — it **skips the scoring step**, leaving a job every one of whose steps succeeds. The
guard is then the only thing that can turn it red, which is the strongest available demonstration:
without it, that job is green having measured nothing.

    gh workflow run corpus-drift -f liveness_drill=true
    gh workflow run dry-run-drift -f liveness_drill=true
    gh workflow run conservation -f liveness_drill=true

As with `alert_drill` (#1287), a drill can only be dispatched against a workflow already on the
default branch, so the first proof of a newly-wired job happens on its PR instead.

## What this deliberately does not do

- **It changes no required status check and does not touch branch protection.** Promoting
  `corpus-drift` to required is sequenced *after* this: making a 22-minute job required before you
  can tell "did not run" from "passed" makes the failure mode worse, not better.
- **It does not make the common path slower.** A file append and a file read; milliseconds.
- **It does not assert that a gate PASSED.** `MEASURED` means the phase ran and produced a number. A
  failing gate that reached its measuring phase records `MEASURED` and is red on its own merits —
  which is correct, and is why the conservation negative controls (which are *supposed* to exit
  non-zero) can be covered at all.

## What it does not yet cover — two tracked bounds

**#1568 — nine gate workflows are outside the registry.** The registration trigger is "this workflow
installs the mechanical binaries", which is a proxy chosen because that is literally what #1509 broke,
not a statement that the rest are safe. `disclosure-venue`, `reasons-drift`, `acceptance`,
`acceptance-close`, `alert-paths`, `corpus-m8`, `osv-staleness`, `owasp-ack-watch` and `site-smoke`
are outside it, and several of them score something real — `reasons-drift` re-runs every empirical
falsifier, `corpus-m8` runs Stryker per target. #1568 replaces the proxy with a trigger that leaves
no gate out by construction.

**#1569 — no `liveness_drill` has been dispatched.** The guard is proven live in both directions on
`dry-run-drift` (run 30569627289 failing, run 30569498565 passing), but that failing proof lives in a
closed PR and a deleted branch rather than in a re-runnable command, and the `corpus-drift` /
`conservation` drills have never executed — a `workflow_dispatch` input does not exist until the
workflow is on the default branch. #1569 dispatches each one and records the proof run in
`.github/gate-liveness.json`, the way `.github/alert-paths.json` records `provenBy`, because a path
that has never fired reads exactly like one with no failing direction (#1287's own finding).

The **DECLARED NO-OP** verdict is likewise proven by `src/ci-liveness.test.ts` against the real
script, but has not yet been observed on a live short-circuited job: every PR that touches this
mechanism also touches the paths those jobs filter on, so their in-job filters correctly report
`relevant=true`. The first docs-only PR after this lands will exercise it.
