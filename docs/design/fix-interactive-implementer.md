# The interactive fix-implementer (#1056)

`docs/design/fix-implementation.md` §8 asks the fix pipeline to turn an approved finding into an
actual code diff. The original shape called an LLM SDK to generate that diff. **Operator ruling
2026-07-26: no automated Anthropic SDK, no API key.** The diff is authored in the operator's own
interactive Claude session instead. So the implementer is split into two halves that bracket that
manual step — an **emit** half that produces a paste-ready prompt, and an **ingest** half that runs
the operator's resulting diff through the same safety rails an LLM's diff would have hit.

There is no LLM client anywhere in this path, and `package.json` gains no LLM dependency. The
untrusted-input posture is unchanged: the interactive diff is treated exactly as an LLM's was — it
must clear the rails, apply cleanly, AND make the detector stop firing before anything is delivered,
and what it produces is a **draft** PR the operator still reviews.

## The two commands

Both go through `src/cli/fix-interactive.ts` (`pnpm fix-interactive`). A finding is eligible only if
`intake()` screens it `auto` — the same gate as `fix-execute` (client-approved, Confirmed/Likely,
ease+safety ≥ 4, enabled category). Its `FixPlan` is produced here, so emit and ingest agree on scope.

### 1. Emit — produce the prompt

```
pnpm fix-interactive <findings.json> <manifest.json> --target <client-checkout> --finding <id> --interactive [--out <dir>]
```

Writes `<out>/<id>.fix-prompt.md` (default `fix-out/`). The prompt is **self-contained** — it assumes
no access to this repo — and carries:

- the finding (id, title, severity/category/confidence, detector taxonomy, location, evidence, impact);
- the intended change (the `FixPlan.approach`, i.e. the finding's prose fix);
- the current source of the in-scope file(s), read from the target checkout;
- the write rails: apply-against-baseline-commit, the path allowlist, the denylist, the diff cap,
  behavior-preserving / no-new-dependency;
- the **acceptance criterion**: the detector must STOP firing at the finding's location — applying
  cleanly is necessary but not sufficient;
- the exact `--apply-diff` command to hand the diff back.

The operator opens the prompt in an interactive Claude session, gets a unified diff, and saves it to a
file. No LLM is called by Harvey, no worktree is created, nothing is pushed.

### 2. Ingest — run the diff through the rails

```
pnpm fix-interactive <findings.json> <manifest.json> --target <client-checkout> --finding <id> --apply-diff <diff-file> [--base <branch>] [--live] [--out <dir>]
```

The diff is run through the EXISTING pieces, unchanged:

- `executeFixDiff` (`src/fix/execute.ts`) — the §3 path/size rails, then apply-clean against a
  disposable worktree cut at the pinned baseline, via `verifySuggestedFix`.
- the detector-after re-run (`rerunDetector`, `src/fix/detector-rerun.ts`) — rides inside that same
  worktree, so the fixed source both clears the apply gate and answers "does the detector still fire".
- `computeGreen` (`src/fix/verify.ts`) — decides green: an unrun detector or a still-firing detector
  is NOT green (fail loud), and no caller can assert green.
- `deliverFix` (`src/fix/transport.ts`) — reached only on green; opens a **draft** PR (`gh pr create
  --draft`), nothing more.

**A diff that applies but leaves the detector firing is REJECTED with a named reason and a non-zero
exit — no branch, no push, no PR.** A rails-blocked diff (denylisted path, over cap) is rejected the
same way, and the detector is reported not-run rather than silently treated as clean.

`--live` is required to actually push and open the draft PR; the default is dry-run (§3.1 rule 5 — the
first run of every engagement withholds all pushes), which reports GREEN and the branch it would use
but issues no network write.

## What was added vs. reused

- **Added:** `src/fix/interactive.ts` (`emitFixPrompt`, `ingestFixDiff`), `src/cli/fix-interactive.ts`,
  and one optional hook on `executeFixDiff` — `detectorAfter`, which applies the verified diff into the
  existing worktree and runs the finding's detector against it, so green is scored from one worktree
  pass rather than a second materialization.
- **Reused unchanged:** `verifySuggestedFix`, `rerunDetector`, `computeGreen`, `deliverFix` and the
  whole `rails.ts` sweep. The implementer composes them; it does not restate a single rail.

Proof: `src/fix/interactive.test.ts` runs the offline M5 (unused-parameter) class end-to-end — a
correct diff clears `computeGreen` and reaches the draft-PR transport (`--draft`, no merge/ready
call); a cosmetic diff that leaves the detector firing is rejected before any PR; a denylisted-path
diff is rails-blocked with the detector reported not-run.
