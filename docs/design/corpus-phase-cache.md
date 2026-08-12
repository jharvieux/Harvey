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

The first PR retry falsified the original identity contract before it could support that
performance claim. Run `31545576498` attempt 1 used Node `24.18.0` and wrote Semgrep,
configuration, and structural/AST keys beginning `182e38546022`, `9474383ad85a`, and
`d9b9b9b780b5`. Attempt 2 successfully restored that exact Actions cache, but `.nvmrc`'s major-only
`24` resolved to Node `24.19.0`; configuration and structural/AST moved to `3bb4c982aada` and
`4974b95b4151`. Semgrep independently re-downloaded live registry packs and moved to
`c6e8aba4e3f4`. The retry had zero deterministic hits and its 729s carbon shard remained slower
than the 694s pre-change reference. That is defect evidence, not corrected-head performance
evidence. `.nvmrc` is now exact, and criterion 6 remains pending a new cold/warm CI pair.

## Cache contract

`runMechanicalScanDetailed` records exactly six typed phases. The registry is exhaustive at
compile time and the runner rejects a missing or duplicate phase at runtime.

| Phase | Reused? | Reproducible identity |
|---|---:|---|
| secrets/history | no | TruffleHog `--only-verified` consults live provider state with no reproducible response identity |
| dependency/advisory | no | OSV and npm registry responses have no immutable response identity on this path |
| Semgrep | yes | pinned commit/tree, exact downloaded registry YAML bytes, local rules, phase implementation closure, Semgrep and Node versions, dependency lock, scan options |
| configuration | yes | pinned commit/tree, implementation closure, Node version, dependency lock, scan options |
| structural/AST | yes | pinned commit/tree, detector implementation closure, Node version, dependency lock, scan options |
| normalization | no | cheap composition of this run's deterministic and live advisory outputs |

Semgrep's initial proposed identity (`semgrep show dump-config`) was rejected during the real
carbon measurement: consecutive resolutions were not byte-stable, and one exceeded the command's
output buffer. On workflow attempt 1, the shipped path downloads the registry YAML, hashes those
exact bytes, writes them under that content address, atomically records a validated `current.json`
snapshot pointer, and passes those same local files to Semgrep. A GitHub retry restores and
revalidates that exact pointer and every pack byte instead of consulting the live registry again.
The retry requests attempt 1's exact Actions-cache key and requires `cache-hit=true`; an older
rolling-prefix fallback can still contribute independently content-addressed phase artifacts, but
its registry pointer is marked unavailable because it has no lineage to this run. If a retry's
exact snapshot is absent, malformed, incomplete, or hashes differently, Semgrep logs the reason
and becomes explicitly non-cacheable for that run; it never uses newly downloaded bytes under the
prior attempt's identity.

Implementation identities are dependency closures discovered from the imports actually referenced
by each cacheable `runPhase` callback, followed transitively across relative imports. A new helper
joins its phase key automatically; an unresolved helper fails loud. Phase-specific closure keeps an
auth-guard helper edit on the Semgrep key, a Supabase/config helper on configuration, and a detector
helper on structural/AST, without falsely moving unrelated keys.

Artifacts are written atomically and contain schema version, phase, full content key, target
revision/tree, normalized findings, positive examined-scope metadata, and the component digests
that formed the key: target revision, target tree, implementation closure, and each named external
input (`node`, `toolchain`, `options`, `registryPacks`, and scanner version). Implementation file
labels are repository-relative, so identical source in a different checkout path has the same
identity. A miss searches prior same-phase provenance and names the moving components (for example,
`identity changed: externalInputs.node`) rather than collapsing every cause to “no artifact.”
Every cached finding is
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

## Cross-run transport, scanner families, and deterministic PR state

The `corpus-phase-v4` transport carries a context-bound provenance manifest. Scheduled/manual runs
stay single-shard so they alone hold and save the complete clone tree. A main `push` also runs once
over every target, then saves that complete content-addressed phase directory under the shard 1, 2,
and 3 namespaces consumed by PR/merge runs. A PR may reuse its own run attempt but never another
PR's artifact. The key encodes platform, shard namespace, run, attempt, and head SHA; the validator
reconstructs that key from the manifest, checks the matched source key and current namespace, then
checks the source event/ref/SHA trust relationship before any inner artifact is read. Missing,
corrupt, forged, mismatched, or untrusted transport is deleted visibly.

Corpus source scanners write two independent artifacts: `detect-static` and mutation
`--detect-only`. Their keys cover the pinned target tree, discovered implementation closure,
Node/toolchain versions, and target configuration. Checkout roots are tokenized in stored findings
and rehydrated on read. On real Carbon, the cache reports 6,133 tracked target units rather than
walking installed dependencies.

`quality-scan` deliberately executes fresh on every corpus run. Its Knip pass can execute target
configuration and provider descendants from the prepared dependency tree, including files that no
package export or static entry closure names. A sound content identity therefore requires reading
the complete installed population. That work defeats this performance cache's purpose: BoxyHQ's
install measured 106,871 physical files / 1,037,440,676 bytes, and pinned Carbon on Linux arm64
measured 146,755 physical files / 2,136,592,208 bytes (202,298 logical files, 34,253 logical
directory visits, and 10,158 links). The hosted Linux x64 Carbon run observed 131,073 physical files
and failed before scoring. The runner now makes the uncached boundary visible, never creates a
`quality-scan` artifact family, and keeps forced-cold verification scoped to the two cacheable
scanners. #1871 remains open; a safe quality-cache design is grouped with #1872's queued dependency
preparation work.

Semgrep is partitioned into the six exact materialized registry packs and ten individual local YAML
files. Each family stores only the deterministic result/error/path/rule envelope (not profiling
timings), tokenizes both target and cache roots, and is independently keyed by its exact rule bytes.
The merge canonicalizes generated registry namespaces, deduplicates overlapping-pack matches, and
restores deterministic order. The scheduled forced-cold control re-executes every family and the
legacy monolithic scan; on the real pinned `saas-lite` target all family artifacts verified and the
normalized partition/monolith parity assertion passed. The command later exited 1 only for the
independent pre-existing M5 baseline movement (expected 38, measured 39); no baseline was changed.

The PR lane sets `HARVEY_CORPUS_EXTERNAL_STATE_MODE=snapshot`: OSV reads six committed, digested,
expiry-checked gzip snapshots through the current parser, secret candidates come from the exact
Gitleaks rules/version and pinned tree, and live registry/provider fallbacks are disabled. Schedule
and manual dispatch use `live-verify`, rerun OSV and provider verification, and fail on snapshot
drift. The default client scanner path sets neither mode and remains live.

The superseded three-scanner prototype's Carbon measurements with `--install` and snapshot state
were: legacy monolithic 444.57s wall; partitioned cold 327.27s; warm 58.68s; 24 MiB cache across 17
artifact files. Every run conserved
all 13 scored baseline/free-tier rows. A temporary edit to one local rule preserved unrelated
registry-family hits and limited Semgrep recomposition to 1.2s. The final exhaustive family repair
restored 531 Semgrep-derived rows that an early zero-applicable-pack abort had hidden; the parity
control, not the count baseline, caught that defect.

The focused tests exercise both sides of every guard:

```sh
pnpm exec vitest run src/scan/mechanical-phase-cache.test.ts src/scan/mechanical-phase-identity.test.ts src/scan/mechanical-phase-cross-process.test.ts src/scan/semgrep.test.ts src/scan/mechanical.test.ts src/corpus-phase-cache-workflow.test.ts
```

They prove cold/warm finding and scope equivalence, full-schema corruption rejection and
recomputation, discovery-backed helper closure, phase-granular invalidation, all-cacheable-phase
target-pin invalidation, live advisory and live-provider secret non-reuse, forced-cold mismatch and
all-miss failure, cache-miss execution, restored-registry validation/refusal, the required-context
aggregate, and the scheduled forced-cold path. The scanner cross-process guard creates two physical
Harvey checkout copies (only the tool installation is shared) and invokes the production corpus
scanner runner twice against matching tracked fixtures. `detect-static` and mutation `--detect-only`
must miss then hit one artifact directory. `quality-scan` must execute fresh both times; between
runs only an installed provider's untracked `config.js` changes, and the real M5-01 result must move
from `src/alternate.ts` to `src/index.ts` without creating a quality cache artifact.
