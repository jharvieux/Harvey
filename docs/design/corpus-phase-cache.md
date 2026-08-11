# Corpus mechanical phase cache

Issue #1864 reduces the required corpus gate's indivisible `carbon` floor without sampling a
target or weakening a baseline. The cache is an optimization of execution only: every target,
module, finding, disclosure row, and baseline assertion still flows through `corpus-drift`.

## Measured boundary

Local provenance is deliberately separate from CI provenance. On 2026-08-11, from the
pre-change `origin/main`, this command ran the real pinned `carbon` commit without `--install`:

```sh
pnpm corpus-drift --target carbon --json /tmp/harvey-1864-carbon-before.json
```

It took 274s total; the formerly opaque free-tier mechanical call took 202.9s (74.0%). The same
real target after phase instrumentation took 278s total, with mechanical work split into Semgrep
94.0s, dependency/advisory 63.9s, structural/AST 30.8s, secrets/history 11.7s,
normalization 2.3s, and configuration 0.3s. The run intentionally omitted `--install`, so its
M5-knip baseline drifted; that known setup difference is not a scanner or cache result and no
baseline was changed.

After the exact registry-YAML materialization was in place, the first candidate implementation's
fresh cold run took 272s and its warm successor took 127s (145s / 53.3% lower wall clock). The
mechanical portion fell from 200.5s to 54.5s: Semgrep, secrets/history, structural/AST, and
configuration were hits, while dependency/advisory (52.3s) and normalization (2.2s) were re-earned.
Both runs reproduced every scored corpus baseline except the same expected no-`--install` M5-knip
row. Review then falsified one of those four hits: TruffleHog uses `--only-verified`, whose provider
verification is live state and has no reproducible identity. The corrected implementation therefore
re-earns secrets/history too. The 272s/127s pair remains the measured history of the candidate, not
a performance claim for the corrected head; only the PR's real corrected-head workflow can supply
that evidence.

The pre-change CI wall-clock reference is corpus run `31539577747`: its `carbon` shard took
11m34s. A post-change CI run ID and its total runner-minute cost must come from the PR's real
three-shard `--install` run. Local single-target measurements do not honestly supply either
number; the PR supervisor records them after update-branch rather than projecting a local ratio.

## Cache contract

`runMechanicalScanDetailed` records exactly six typed phases. The registry is exhaustive at
compile time and the runner rejects a missing or duplicate phase at runtime.

| Phase | Reused? | Reproducible identity |
|---|---:|---|
| secrets/history | no | TruffleHog `--only-verified` consults live provider state with no reproducible response identity |
| dependency/advisory | no | OSV and npm registry responses have no immutable response identity on this path |
| Semgrep | yes | pinned commit/tree, exact downloaded registry YAML bytes, local rules, phase implementation closure, Semgrep version, dependency lock, scan options |
| configuration | yes | pinned commit/tree, implementation closure, Node version, dependency lock, scan options |
| structural/AST | yes | pinned commit/tree, detector implementation closure, Node version, dependency lock, scan options |
| normalization | no | cheap composition of this run's deterministic and live advisory outputs |

Semgrep's initial proposed identity (`semgrep show dump-config`) was rejected during the real
carbon measurement: consecutive resolutions were not byte-stable, and one exceeded the command's
output buffer. The shipped path downloads the registry YAML, hashes those exact bytes, writes them
under that content address, and passes those same local files to Semgrep. If registry materialization
fails, the phase logs `CACHE BYPASS` and runs without reuse.

Implementation identities are dependency closures discovered from the imports actually referenced
by each cacheable `runPhase` callback, followed transitively across relative imports. A new helper
joins its phase key automatically; an unresolved helper fails loud. Phase-specific closure keeps an
auth-guard helper edit on the Semgrep key, a Supabase/config helper on configuration, and a detector
helper on structural/AST, without falsely moving unrelated keys.

Artifacts are written atomically and contain schema version, phase, full content key, target
revision/tree, normalized findings, and positive examined-scope metadata. Every cached finding is
revalidated through the canonical `validateFindings` schema, not a smaller cache-local subset. A
missing artifact is a miss and executes the phase. A malformed, partial, zero-scope, or
wrong-identity artifact logs `CACHE REJECT`, is removed, and is recomputed. A scheduled or manually
dispatched workflow uses `--force-cold-cache`: it executes every deterministic phase and compares
the cold value with the restored artifact, failing on any findings or scope difference. A miss can
seed the next run but fails the current equivalence assertion; normal PR read/write runs are the
distinct seeding mode.

The Actions cache is transport, not trust. Per-shard rolling keys avoid matrix legs overwriting
one another; inner artifacts remain content addressed. The bare required context still gates on
the aggregate result of every shard and reports on every pull request, including declared no-op
changes.

## Falsifiers

The focused tests exercise both sides of every guard:

```sh
pnpm exec vitest run src/scan/mechanical-phase-cache.test.ts src/scan/mechanical-phase-identity.test.ts src/scan/mechanical.test.ts src/corpus-phase-cache-workflow.test.ts
```

They prove cold/warm finding and scope equivalence, full-schema corruption rejection and
recomputation, discovery-backed helper closure, phase-granular invalidation, all-cacheable-phase
target-pin invalidation, live advisory and live-provider secret non-reuse, forced-cold mismatch and
all-miss failure, cache-miss execution, the required-context aggregate, and the scheduled
forced-cold path.
