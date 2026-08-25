# Corpus drift relevance and remeasurement

`corpus-drift` is a population gate, not an example checker. A detector change that moves one
reported row may affect every pinned target reached by the same matching, loading, resolution,
reachability, or invocation mechanism. The gate may narrow a pull-request run only from executable
ownership evidence; uncertainty always expands to a full scan.

## The blast-radius rule

Classify a changed mechanism before editing a baseline:

- **Matching-only** changes alter a detector's predicate after its inputs are already loaded. Measure
  every registered producer/target pair that can invoke that predicate.
- **Resolution-affecting** changes alter loading, parsing, module or symbol resolution, reachability,
  target selection, scanner invocation, generated inputs, shared registry data, or execution
  provenance. Measure every consumer reachable through the changed input closure. Ambiguous changes
  are resolution-affecting.

For each affected target/module, classify observed movement as one of:

1. **Incomplete population** — the proven mechanism population was not fully measured. Finish the
   measurement before changing code or baselines.
2. **Precision fix** — the movement is intentionally more accurate. Update every affected baseline
   with the command, pin, count, and semantic provenance that reproduced it.
3. **Real regression** — the scanner became less correct. Fix the scanner and retain the baseline.
4. **Setup failure** — the scanner did not produce a comparable complete result. Repair setup and
   rerun; setup evidence never authorizes rebaselining.

Zero findings and “not named in the issue” are not valid exclusions. A target may be excluded only
when the receipt proves that the mechanism is not invoked there or is structurally not
applicable, and records the provenance and a falsifier for that claim. A shared resolver can
therefore select the entire corpus; that is a measured result, not a blanket policy.

## Executable ownership and target selection

The classifier builds its ownership receipt from production code, not from a second workflow map:

```bash
pnpm exec tsx src/cli/corpus-drift-relevance.ts ownership --out "$OWNERSHIP_JSON"
pnpm exec tsx src/cli/corpus-drift-relevance.ts classify \
  --root "$GITHUB_WORKSPACE" --base "$BASE_SHA" --head "$HEAD_SHA" \
  --ownership "$OWNERSHIP_JSON" --out "$RECEIPT_JSON"
```

The ownership generator joins:

- the nine ordered runtime consumers used by the source/mechanical corpus path;
- every live `EXTERNAL_CORPUS` target;
- live mechanical producer/phase ownership discovered from `MECHANICAL_REGISTRY`; and
- registered non-import inputs with explicit target selection, applicability, provenance, and
  falsifier fields.

For every consumer, the receipt records changed inputs, selected targets, applicability,
provenance, falsifier, and the final full-scan or declared-no-op decision. The classifier walks the
transitive TypeScript/JavaScript import closure at both exact commits and uses rename-aware Git
diffs. A client component does not by itself prove that a shared module is outside server rendering;
only the executable closure and registered applicability evidence can do that.

Any dirty checkout, mismatched checked-out head, unreachable commit/tree, unresolved import,
dynamic dependency, unknown changed input, malformed ownership receipt, or other incomplete proof
fails open to `full-scan`. A malformed CLI invocation or unreadable ownership input exits as a setup
error rather than manufacturing a green no-op.

The current-mechanical preparation adapter exposes one `preparedExecutionRoot` for execution and a
separate clean checkout receipt for Git provenance. The checkout is evidence only: it is never a
scanner or TruffleHog input.

## Hosted policy and liveness

Pull requests and merge-queue entries run the classifier. `full-scan` launches the complete pinned
population because current producer-to-replay equivalence is itself a whole-population assertion.
`declared-no-op` means **nothing assessed**: it records the closure digest and explanation, starts no
third-party corpus runner, and does not represent a zero-drift scan. Pushes to `main`, schedules, and
manual dispatches bypass the classifier and always run the full pinned population as the hosted
backstop.

For a focused local investigation, select a target explicitly:

```bash
pnpm corpus-drift --target <slug> --install
```

That command is diagnostic evidence about the selected target; it does not replace a required
blast-radius run when a shared mechanism reaches more targets.

## Historical evidence

The retained audit covers every baseline-mutating merge in the frozen first-parent population and
every merged pull request in the exact recent replay frame. Raw forge/API receipts, deterministic
chronology, classifications, commands, digests, and replay economics are committed under
[`docs/evidence/corpus-drift-remeasurement-history/`](../evidence/corpus-drift-remeasurement-history/).

Of 14 historical baseline-mutating merges, 12 had enough retained evidence for a disposition:
9 deliberate, 2 strictly gate-discovered, and 1 mixed. Thus 2/12 (16.7%) were strictly prompted by
the hosted gate and 3/12 (25%) involved gate discovery. Two rows remain unproven rather than being
forced into a favorable category. PR #1712 is the required negative control: the initial hosted run
failed on the real `rallly/M9` drift, the baseline repair followed, and the next run passed.

The recent replay retains 35 final pull requests, all 117 historical workflow heads, and all 129
attempts. The conservative classifier declared 3/35 final heads disjoint. Across attempts that
actually reached corpus execution, one superseded head would have avoided 55.0 gross runner-minutes
and 11.0 critical-path minutes. Those are gross historical observations, not a hosted net-savings
forecast: classifier/setup overhead is recorded separately and no unsupported net estimate is made.

These rates describe the frozen populations only. They are evidence that silent baseline edits are
a real failure mode, not a forecast of future pull requests.
