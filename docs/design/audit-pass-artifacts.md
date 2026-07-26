# Audit pass artifacts (#416)

The `#229` orchestrator (`pnpm exec tsx src/cli/run-audit.ts`) derives each module's coverage
status from evidence its probe gathered — never from a caller's assertion or a tier flag. But four
modules do their real work in passes that run *outside* the orchestrator process and leave nothing
it can observe:

| Module | Out-of-orchestrator pass | Prior honest status |
|--------|--------------------------|---------------------|
| **M1** | semantic (`/vuln-scan → /triage`) and live (`pnpm detect-deeper`) | `partial` (mechanical tier only) — #311 |
| **M2** | dynamic pen-test (`pentest.ts` against a stood-up two-tenant stack) | `requires-live-run` — #356 |
| **M3** | vitals capture (external `vitals_cli.py`) when it is not on PATH | `requires-live-run` — #314 |
| **M6** | the reviewed simplification verdict over the `simplify-scan` packet | `partial` (packet is not a verdict) — #351 |

Each of #311/#356/#351 deliberately *refused* to bank `ran` off the tier flag, because a flag is
intent, not evidence. This convention gives those passes a way to leave **evidence**: a dated
results artifact the probe can check.

Those four are the modules whose status an artifact can *decide*. Since **#1042 all ten modules
CONSUME a recorded pass** — the other six merge its findings and name it on their row without
claiming `ran`. See "How the probe uses it" below for the split.

## The artifact

Each pass writes one JSON file named `<module>.pass.json` (e.g. `M1.pass.json`) into the
engagement's **artifacts directory**, passed to the orchestrator as `--artifacts-dir <dir>`.

```jsonc
{
  "module": "M1",                       // the module this pass covered (must match the probe)
  "target": "/abs/path/to/target",      // the audited directory — must match run-audit's target
  "pass": "semantic",                   // "semantic" | "live" | "dynamic" | "vitals" | "verdict"
  "generatedAt": "2026-07-17T12:00:00Z",// ISO-8601; older than 30 days is stale
  "summary": "42 findings, 7 high",     // optional, surfaced in the coverage ledger detail
  "findings": [ /* report-schema Finding[] */ ],  // optional; flows into the engagement document
  "hotspotFocus": true,                 // optional (M1 semantic): was an M3 hotspot brief supplied?
  "hotspots": [ "core/checkout.ts" ]    // optional (M3 vitals): worst-first top-K ranking
}
```

The schema and the freshness window live in `src/audit-pass-artifact.ts`
(`PassArtifact`, `MAX_PASS_AGE_MS`).

`hotspots` (#530) is the M3 vitals pass's top-K hotspot ranking. When present, the M3 probe surfaces
it so the cross-module enrichment (#515 — every module's findings tagged `onHotspot`/`hotspotRank`)
fires in the common **vitals-off-PATH** flow, where M3 derives `ran` from this artifact rather than
an in-process capture. Record it with `pnpm record-pass --module M3 --pass vitals --hotspots
ranking.json …`, where `ranking.json` is a JSON array of file-path strings.

## How the probe uses it

`findFreshPass(ctx, module)` returns the artifact as fresh evidence **only** when all hold:

1. `--artifacts-dir` was supplied (no dir ⇒ the probe keeps its pre-#416 not-run status);
2. `<module>.pass.json` exists there;
3. its `module` matches the probe;
4. its `target` equals the audited directory (a pass over a *different* app is not evidence);
5. its `generatedAt` is within the freshness window (`MAX_PASS_AGE_MS`, 30 days).

If an artifact is **present but rejected** (stale, wrong target, malformed), the probe does **not**
silently ignore it — it falls back to its honest not-run status and appends the rejection reason, so
a stale pass fails loud rather than reading as a clean gap.

A fresh artifact **always** puts its `pass`/`generatedAt` in the ledger detail and its `findings`
(if any) into the engagement document — the same way a captured CLI's findings are collected (#312).
What it does to the module's **status** differs by module (#1042):

| Modules | What a fresh artifact does to the status |
|---|---|
| **M1, M2, M3, M6** (the four above) | Yields **`ran`** — the artifact *is* the module's missing tier. |
| **M7** | **Replaces** the `M7_LIGHTHOUSE_NOT_RUN` claim, which a recorded Lighthouse pass falsifies outright, and upgrades a `requires-live-run` to `partial`. Never `ran`. |
| **M4, M5, M8, M9, M10** | Findings merged, the pass **named on the row**, and a `requires-live-run` upgraded to `partial` because something demonstrably ran. Never `ran`. |

The six that do not read `ran` cover **one tier** of their module, and the orchestrator has no
evidence about the others — asserting `ran` there would break the #229 derive-don't-assert rule.

Before #1042 only M1/M2/M3/M6 called `findFreshPass` at all, while `record-pass` validated
`--module` against the full M1–M10 list and told the operator that module would derive `ran` from
the artifact. A recorded M7 Lighthouse pass was therefore accepted, written, and then silently
dropped: MEASURED 2026-07-25 on `targets/calibration`, the recorded finding was absent from
`--findings-out` and the M7 row still asserted Lighthouse "not run" — a confident negative claim
contradicted by evidence sitting in the directory `run-audit` had just read.

## What this is not

- It does **not** re-run the pass or verify the work is *correct* — it records that the pass *ran*
  for this target, recently. Correctness is the reviewer's/pentester's job.
- Target-match is by directory path today. Binding the artifact to the target's commit/hash (so a
  changed target invalidates a prior pass) is a natural tightening, tracked as a follow-up.
