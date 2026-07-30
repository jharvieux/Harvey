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
  "pass": "connected",                  // "semantic" | "live" | "connected" | "dynamic" | "vitals" | "verdict"
  "generatedAt": "2026-07-17T12:00:00Z",// ISO-8601; older than 30 days is stale
  "summary": "42 findings, 7 high",     // optional, surfaced in the coverage ledger detail
  "findings": [ /* report-schema Finding[] */ ],  // optional; flows into the engagement document
  "hotspotFocus": true,                 // optional (M1 semantic): was an M3 hotspot brief supplied?
  "hotspots": [ "core/checkout.ts" ],   // optional (M3 vitals): worst-first top-K ranking
  "priorPasses": [ /* the tiers this slot already held, newest first */ ]
}
```

### The slot ACCUMULATES — one file per module, every tier kept (#1522)

`<module>.pass.json` is **one slot per module, not one per tier**. Recording a second tier does not
replace the first: the new pass becomes the top-level one and the tiers it supersedes move into
`priorPasses`. Re-recording the SAME tier replaces that tier only — a re-run of the semantic pass is
a correction of the semantic pass, not a second one. `record-pass` prints what the slot holds after
each write. Everything the slot holds is evidence: the probe reads the findings of every pass whose
own `generatedAt` is fresh, and names any stale one on the row rather than passing over it.

Until #1522 the slot held exactly one pass, and M1 — the module with THREE out-of-orchestrator tiers
(semantic, live, connected) — silently lost one recording another. MEASURED 2026-07-30 before the
fix: `record-pass --module M1 --pass semantic` followed by `--pass connected` left a single
`M1.pass.json` whose `pass` read `connected`, the semantic pass's findings deleted, its `#502`
hotspot-focus warning gone, M2's drift evidence unreadable if recorded in the other order, and the
`validate-semantic` gate reporting the target unscored.

**Why accumulate rather than name the file per tier** (`M1.connected.pass.json`): `pass` is a
free-form string, and every reader reaches the filesystem through a narrowed `exists`/`readArtifact`
seam with no directory listing — so a per-tier filename would force each reader to GUESS a fixed set
of tier names, and a pass recorded under any other name would be written to a file nobody ever opens.
That is the silent-drop shape #1042 closed, re-created. Accumulating also keeps the newest pass where
every existing reader already looks, so no consumer had to change to keep working.

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
| **M2, M3, M6** | Yields **`ran`** — the artifact *is* the module's missing tier. |
| **M1** | Yields `ran` only when the slot holds a fresh pass for **all three** of M1's out-of-orchestrator tiers (semantic, live, connected). Short of that the row is `partial` and NAMES the tiers with no artifact (#1522) — recording one tier is not evidence the other two ran. |
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

## The write side — which passes emit their own artifact (#448/#1364)

#448 asked for passes to write their own artifact rather than depend on an operator remembering a
second, separate `record-pass` invocation after hand-extracting findings from stdout. Before #1364
only ONE pass did (`pnpm record-pass` itself is the generic manual path, not a self-emitter). As of
#1364:

| Pass | Self-emits its own `<module>.pass.json`? |
|---|---|
| M2 dynamic (`pentest.ts` → `dynamic-validate.ts` / `prisma-dynamic.ts`) | **yes** (pre-#1364) |
| M3 vitals (`pnpm exec tsx src/cli/hotspot-scan.ts --artifacts-dir <dir>`) | **yes** — writes `M3.pass.json` directly, findings + top-K hotspots + which of the three CLI tiers (full/reduced/unranked) produced them |
| M6 verdict (`pnpm exec tsx src/cli/m6-agreement.ts a.json b.json --target <dir> --artifacts-dir <dir>`) | **yes** — writes `M6.pass.json` from the UNANIMOUS-flag verdicts only (`toM6Findings`, `src/m6-agreement.ts`); a split is never auto-promoted, it still goes to the human adjudicator the agreement report already routes it to |
| M1 live (`pnpm detect-deeper --findings-out <file>`) | no — but no longer needs hand-extraction either: `--findings-out` writes the bare `Finding[]` `record-pass --findings` reads, so recording it is `detect-deeper --findings-out f.json` then `record-pass --module M1 --pass live --findings f.json --out <dir>`, no manual JSON surgery |
| M1 connected Supabase (`scan.ts --supabase <ref\|local> --migrations <dir> --out f.json`) | no — recorded with `record-pass --module M1 --pass connected --findings f.json --target <dir> --out <artifacts-dir>`; `--out` already writes the bare `Finding[]`, so no hand-extraction. It shares `M1.pass.json` with the semantic and live tiers, which ACCUMULATE rather than overwrite (see "The slot accumulates" above), and recording it leaves the un-run tiers named on M1's row (#1522) |
| M1 semantic (`/vuln-scan → /triage`) | no — see the recorded reason below |

### A second reader: M2's scope statement (#1280)

The connected pass's artifact is read by two consumers besides the M1 probe — this one, and
`loadSemanticPass` (`src/scan/semantic-corpus.ts`, the `validate-semantic` recall gate, which pulls
the SEMANTIC pass out of the same slot. Both now search the whole slot rather than its newest entry,
which is what makes the accumulation above reach them: #1522.)

`readDriftPassEvidence` (`src/scan/supabase-drift.ts`) looks for `SB-DRIFT-00` in a fresh,
target-matching `M1.pass.json`
and hands the answer to `buildScopeLedger`, so M2's scope disclosure can say whether
prod-vs-migration drift **was observed on this engagement** rather than pointing the reader at a row
elsewhere in the report. It uses the same `findFreshPass` freshness/target rules (narrowed to
`PassArtifactSource`), so a stale or wrong-target artifact is named as rejected, never dropped.

The four states the scope statement distinguishes, none of which is silence:

| What the artifacts dir holds | What M2's scope row says |
|---|---|
| a connected pass whose `SB-DRIFT-00` reports a comparison | drift **WAS OBSERVED** on this engagement, with the count of drift rows; the class leaves the not-assessed list |
| a connected pass whose `SB-DRIFT-00` is the not-assessed variant | **NOT** observed, naming that the pass ran without `--migrations`; the class stays not-assessed |
| a stale / wrong-target `M1.pass.json` | **NOT** observed, carrying `findFreshPass`'s rejection reason |
| no `M1.pass.json`, or a slot whose passes carry no `SB-DRIFT-00` at all (semantic/live only) | the standing wording — the class is not-assessed by M2 and points at the connected tier |

### Recorded reason: M1 semantic stays on the generic `record-pass` path

> REASON: the M1 semantic pass (/vuln-scan → /triage) has no CLI Harvey's own code invokes — it is a Claude Code skill pair run interactively, not a subprocess any src/cli/*.ts can shell out to — so there is no producer file to add a self-emit branch to, and `pnpm record-pass --module M1 --pass semantic --findings triage.json --out <dir>` (the pre-existing generic path, #448) stays the only way to record it.
> KIND: empirical
> PROVENANCE: TRIED 2026-07-28 — surveyed every production caller of buildPassArtifact (src/prisma-dynamic.ts, src/dynamic-validate.ts, src/hotspot-scan.ts, src/m6-agreement.ts, src/cli/record-pass.ts); none is, or could mechanically become, a semantic-pass self-emitter, because the pass itself has no CLI entry point to attach one to.
> FALSIFIER: grep -rl 'buildPassArtifact(' src --include='*.ts' | grep -vE 'record-pass\.ts|prisma-dynamic\.ts|dynamic-validate\.ts|hotspot-scan\.ts|m6-agreement\.ts|audit-pass-artifact\.ts|audit-conservation\.ts|\.test\.ts' | grep -q .
> TOUCHES: src/cli, src/audit-pass-artifact.ts

Exercised both directions 2026-07-28: exits 1 (non-zero) as committed; exits 0 against a planted
dummy `src/cli/` file that calls `buildPassArtifact` outside the five known producers, proving the
falsifier actually flips when the blocker is gone rather than being vacuously true or false.

## What this is not

- It does **not** re-run the pass or verify the work is *correct* — it records that the pass *ran*
  for this target, recently. Correctness is the reviewer's/pentester's job.
- Target-match is by directory path today. Binding the artifact to the target's commit/hash (so a
  changed target invalidates a prior pass) is a natural tightening, tracked as a follow-up.
