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

## Remainder (split of #927)

Tracked in **#957**. To close out §8 autonomously:

- #922 implementer producing a `suggestedFix.diff` per planted §8 class.
- #924 detector-after re-run so clause 1's "detector-after clean" is checked, not just apply-clean.
- Confirm/plant §8 fix-calibration ground truth for classes 1 (zero-row-update `error: null`),
  2 (unchecked Supabase mutation) and 5 (`void`-prefixed async) — the scan corpus plants classes 3
  and 4 cleanly; 1/2/5 are not clearly enumerated as fix-pipeline before/after fixtures.
- A harness that materializes `targets/calibration` into a standalone repo for the run.
- Clause 2: out-of-scope planted bugs (RLS-off, `USING (true)`, service-role query building) →
  recommend-only downgrade with the right reason, exercised through intake/screening.
