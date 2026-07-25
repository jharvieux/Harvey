# Fix pipeline — §8 calibration acceptance gate (issue #927)

Measured 2026-07-24 in the `feature/sweep-fixexec-927` worktree. This records what the §8 acceptance
gate (`docs/design/fix-implementation.md` §8) can and cannot check today, and what the offline
regression gate `src/fix/calibration-acceptance.test.ts` locks in. Precedent for the format:
`docs/design/vuln-seam-app-live-validation.md`.

## The stale blocker

`fix-implementation.md` §9 recorded the MVP acceptance run as *"deferred pending issue #9 (the
deliberately-broken calibration target), which does not exist in the repo yet."*

**Re-measured: `targets/calibration/` exists** (alongside `targets/vuln-seam-app/` and
`targets/prisma-xtenant-app/`), and it plants at least two of the §8 in-scope fix classes:

- Class 4 — `z.string().url()` on a stored/rendered URL field — `pages/api/redirect.js:9` (P-OPEN-REDIRECT).
- Class 3 — raw error-message egress — `pages/api/verbose.js:8` (P-VERBOSE-ERROR, `err.stack` echoed into the response).

The recorded blocker is gone. The gate was simply never run.

## What the gate CANNOT run end-to-end today (measured, not recalled)

The FULL §8 acceptance — *every in-scope planted class autonomously yields a green result whose
detector-after is clean; every out-of-scope planted bug yields a recommend-only downgrade with the
right reason* — cannot execute yet. Three concrete blockers:

1. **No implementer.** The implementer stage (#922) that turns a finding's prose `fix` into a
   `suggestedFix.diff` is unbuilt. Without it the pipeline has no diffs to execute, so "every planted
   class yields a green result" cannot be produced autonomously — the diffs have to be hand-authored.
2. **No detector-after re-run.** §8 clause 1 requires the detector that found the bug to no longer
   fire after the fix. The executing path (`verifySuggestedFix`) proves *apply-clean* + an optional
   *effect command*, not a scan-detector re-run (#924). "Detector-after clean" is therefore not
   checkable autonomously today.
3. **The corpus lives inside Harvey's own repo.** `targets/calibration/` is committed *inside* the
   Harvey repository (no nested `.git`). `executeFixDiff` refuses any target that shares Harvey's
   `--git-common-dir` (`assertNotHarveyItself`). Measured directly:

   ```
   executeFixDiff("CAL-REDIRECT", <diff>, { targetDir: "targets/calibration", ... })
   → THREW: refusing to execute a fix against Harvey's own repository (targets/calibration)
   ```

   The §8 run must first **materialize** `targets/calibration` into a standalone throwaway git repo.

## What the gate CAN check today, and now does (offline)

`src/fix/calibration-acceptance.test.ts` exercises the piece that landed with #885/#930 — the §3
rails + inert-diff verify transport (`src/fix/execute.ts`) — against the **real** planted calibration
source, materialized into a standalone repo:

- The calibration target and its planted class-4 source exist (kills the stale #9 blocker).
- `executeFixDiff` **refuses the in-place corpus** (`assertNotHarveyItself`) — blocker 3, locked so it
  can't rot into a silent "it ran".
- A mechanical class-4 fix (host-blind `z.string().url()` → host-allowlisted validator) for the real
  planted bug runs to **`diff-verified` with ZERO rail events** (§8 clause 3 on the clean path) and
  leaves the client tree untouched (inert).
- A fix diff touching a denylisted path (`.env`) is **`rails-blocked`** before any worktree.
- A fix diff over the engagement diff cap is **`rails-blocked`**.

This is the rails + transport proof on a target we own. It is NOT the full §8 acceptance.

## Update (2026-07-24, #957) — the FULL §2 gate now runs autonomously for a resolvable-detector class

Two of the three blockers above are cleared:

- **Blocker 2 (detector-after re-run) is gone.** #924 landed `rerunDetector` (`src/fix/detector-rerun.ts`).
  The acceptance now runs the FULL §2 contract, not just apply-clean.
- **Blocker 3 (corpus materialization) is gone.** `src/fix/materialize-calibration.ts` materializes the
  planted files into a standalone throwaway git repo `executeFixDiff` will accept, and captures the
  mechanical fix as a git-apply patch. `src/fix/acceptance.ts` `runFixAcceptance()` orchestrates
  execute (apply-clean + §3 rails) **and** `rerunDetector` (detector-after) into a single `green` verdict.

Measured (`src/fix/calibration-acceptance.test.ts`, 9 tests, offline, no external binary):

- The M5 "Unused parameter" planting (`app/api/ar-cors-reflected-safe/route.ts:8`) — the one §8 in-scope
  class whose detector `rerunDetector` resolves — reaches **GREEN**: the mechanical fix applies clean,
  zero rail events, and detector-after is clean. The gate genuinely discriminates: it FIRES on the
  unfixed source, and a no-op edit that leaves the param unused applies clean but is **not** green
  (detector-after still fires). This is the "detector-after gate actually re-runs" proof.
- The semgrep class-4 (open redirect) fix applies clean and clears the rails, but its detector-after is
  **`notRun`** — `rerunDetector` has no semgrep/M1 resolver — so it can never fake an autonomous green.
  Disclosed, not hidden.
- Clause 2: an RLS-off finding (out-of-scope category) is screened **recommend-only** via `intake`.

## Remainder (split of #957 → #1009)

Still not autonomous, and genuinely out of reach for a mechanical assembly:

- **Autonomous implementer diffs.** The fix diffs are still hand-authored in the acceptance (the
  mechanical before/after strings). #922 landed `producePlan` (no diff); the actual diff-*generating*
  implementer is an LLM/operator pass, not deterministic code — so "every planted class yields a green
  result the pipeline produced itself" is not met.
- ~~**Semgrep/M1 detector-after resolver.**~~ **CLOSED by #1012** — see the update below.
- **Plant classes 1/2/5 as before/after fix fixtures.** The scan corpus plants classes 3/4 cleanly; 1
  (zero-row-update `error: null`), 2 (unchecked Supabase mutation), 5 (`void`-prefixed async) are not
  enumerated as fix-pipeline before/after fixtures with a known mechanical fix.

## Update (2026-07-24, #1012/#1009) — the semgrep-detected §8 classes now run the same full gate

`rerunDetector` gained a second resolver family: a finding whose taxonomy names a **local `harvey-*`
semgrep rule** is verified by replaying that rule against the finding's own file (scoped exactly as
the AST path is). So the §8 classes the M1 mechanical tier detects are no longer stuck at `notRun`.

Measured (`src/fix/calibration-acceptance.test.ts`, offline except the `semgrep` binary; the
binary-dependent cases skip with a named reason when it is absent, matching `quick-scan.test.ts`):

| §8 class | Planted at | Mechanical fix that reaches GREEN |
|---|---|---|
| 4 — open redirect | `pages/api/redirect.js:18` (`harvey-open-redirect`) | request names a destination KEY (`z.enum`), every reachable target a literal |
| 3 — raw error egress | `pages/api/verbose.js:8` (`harvey-verbose-error`) | log the error server-side, return a generic message |
| SQLi (planted bug #4) | `pages/api/search.js:9` (`harvey-sql-injection-template`) | bind the tainted value as a query parameter instead of SQL text |

The gate still follows the DETECTOR, never the fix author's intent: a plausible-looking host-allowlist
`.refine()` on the redirect **does not** go green, because `harvey-open-redirect`'s taint path still
reaches the sink. Whether the rule is over-strict there is a detector question, tracked separately —
what §8 needs is that the gate reports what the detector says.

**What stays disclosed rather than scored** (the honesty half of the same change):

- A semgrep **registry-pack** rule (`p/owasp-top-ten` et al) is `notRun`: replaying it needs a network
  fetch, so only the local rule directory is replayable.
- A `harvey-*` rule id that no longer exists in `src/scan/rules/semgrep/` does not resolve — a deleted
  rule must not "stop firing" and read as a fixed bug.
- semgrep absent from PATH, the finding's file missing from the checkout, or source semgrep cannot
  parse are each `notRun` **with the reason**. Semgrep exits 0 on a syntax error with zero results,
  which read naively is indistinguishable from a clean file; `runSemgrepOnFile` surfaces it as a failure.

**Blocker re-measured, 2026-07-24:** §8 classes 1 (zero-row update returning `error: null`), 2
(unchecked Supabase mutation) and 5 (`void`-prefixed async) have **no detector anywhere in `src/`** —
no `harvey-*` semgrep rule, no AST engine (verified by `resolvesToDetector` returning false for all
three, locked as a test). Planting before/after fix fixtures for them would produce `notRun` rows, not
green ones: the detector has to exist first. That ordering is the remainder, not a fixture chore.
