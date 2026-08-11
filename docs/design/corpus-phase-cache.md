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

After the exact registry-YAML materialization was in place, a fresh cold run took 272s and its
warm successor took 127s (145s / 53.3% lower wall clock). The mechanical portion fell from 200.5s
to 54.5s: Semgrep, secrets/history, structural/AST, and configuration were content-addressed hits,
while dependency/advisory (52.3s) and normalization (2.2s) were deliberately re-earned. Both runs
reproduced every scored corpus baseline except the same expected no-`--install` M5-knip row; the
focused real-mechanical fixture separately asserts complete cold/warm finding and scope equality.

The pre-change CI wall-clock reference is corpus run `31539577747`: its `carbon` shard took
11m34s. A post-change CI run ID and its total runner-minute cost must come from the PR's real
three-shard `--install` run. Local single-target measurements do not honestly supply either
number; the PR supervisor records them after update-branch rather than projecting a local ratio.

## Cache contract

`runMechanicalScanDetailed` records exactly six typed phases. The registry is exhaustive at
compile time and the runner rejects a missing or duplicate phase at runtime.

| Phase | Reused? | Reproducible identity |
|---|---:|---|
| secrets/history | yes | pinned commit/tree, phase implementation and gitleaks config, gitleaks and trufflehog versions, scan options |
| dependency/advisory | no | OSV and npm registry responses have no immutable response identity on this path |
| Semgrep | yes | pinned commit/tree, exact downloaded registry YAML bytes, local rules, phase implementation, Semgrep version, scan options |
| configuration | yes | pinned commit/tree, implementation closure, Node version, scan options |
| structural/AST | yes | pinned commit/tree, detector implementation closure, Node version, scan options |
| normalization | no | cheap composition of this run's deterministic and live advisory outputs |

Semgrep's initial proposed identity (`semgrep show dump-config`) was rejected during the real
carbon measurement: consecutive resolutions were not byte-stable, and one exceeded the command's
output buffer. The shipped path downloads the registry YAML, hashes those exact bytes, writes them
under that content address, and passes those same local files to Semgrep. If registry materialization
fails, the phase logs `CACHE BYPASS` and runs without reuse.

Artifacts are written atomically and contain schema version, phase, full content key, target
revision/tree, normalized findings, and positive examined-scope metadata. A missing artifact is a
miss and executes the phase. A malformed, partial, zero-scope, or wrong-identity artifact logs
`CACHE REJECT`, is removed, and is recomputed. A scheduled or manually dispatched workflow uses
`--force-cold-cache`: it executes every deterministic phase and compares the cold value with the
restored artifact, failing on any findings or scope difference.

The Actions cache is transport, not trust. Per-shard rolling keys avoid matrix legs overwriting
one another; inner artifacts remain content addressed. The bare required context still gates on
the aggregate result of every shard and reports on every pull request, including declared no-op
changes.

## Falsifiers

The focused tests exercise both sides of every guard:

```sh
pnpm exec vitest run src/scan/mechanical-phase-cache.test.ts src/scan/mechanical-phase-identity.test.ts src/scan/mechanical.test.ts src/corpus-phase-cache-workflow.test.ts
```

They prove cold/warm finding and scope equivalence, corruption rejection and recomputation,
Semgrep-only rule invalidation, structural implementation invalidation, all-phase target-pin
invalidation, live advisory non-reuse, forced-cold mismatch failure, cache-miss execution, the
required-context aggregate, and the scheduled forced-cold path.
