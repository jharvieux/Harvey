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
wrong-identity artifact logs `CACHE REJECT`, is removed, and is recomputed. A manual dispatch with
the explicit `force_cold_cache` input executes every deterministic phase and compares the cold
value with the restored artifact, failing on any findings or scope difference. A miss can seed the
next run but fails the current equivalence assertion; normal PR, scheduled, and main-push
read/write runs are the distinct seeding mode.

The Actions cache is transport, not trust. Per-shard rolling keys avoid matrix legs overwriting
one another; inner artifacts remain content addressed. The bare required context still gates on
the aggregate result of every shard and reports on every pull request, including declared no-op
changes.

## Falsifiers

## Cross-run transport, scanner families, and deterministic PR state

The `corpus-phase-run-v5` and `corpus-phase-main-v5` transports carry a context-bound provenance
manifest. Pull-request retries use their exact run family; a rolling-prefix lookup is restricted to
the trusted default-branch family, keeping a newer artifact from another PR separate from the main
seed. The key encodes family, platform, shard namespace, run,
attempt, and head SHA. The validator reconstructs that key, checks the matched source key/current
namespace, then checks the source event/ref/SHA trust relationship before any inner artifact is
read. Missing, corrupt, forged, mismatched, or untrusted transport is deleted visibly.

PRs, merge groups, and default-branch pushes all use three shards. Each successful main leg saves
only its corresponding trusted namespace, after successful scoring. This replaces the one-shard
main seeding shape. Scheduled/manual validation remains single-shard for canonical
scorecard and clone-cache lineage, but is warm by default; an explicit `force_cold_cache` dispatch
input exercises cold-versus-restored equivalence without making daily provider validation pay that
cost.

Every saved transport now carries a measured payload receipt. Authoring or restoring fails if the
tree contains any symlink, if the remeasured byte count differs, or if the payload exceeds 6 GiB.
That ceiling prevents the rejected 8.66 GiB combined prototype shape from recurring silently; the
authoritative measured rejected value was 9,082,124 KiB (`du -sk`). A pre-correction local Carbon
transport measured 2,149,804,255 bytes and zero links, but that is one shard rather than the
required all-shard cache-size measurement. `node_modules` is never transported.

Corpus scanners write three independent artifacts: `detect-static`, `quality-scan`, and mutation
`--detect-only`. Their keys cover the pinned target tree, discovered implementation closure,
Node/toolchain versions, and target configuration. Checkout roots are tokenized in stored findings
and rehydrated on read. On real Carbon, each cache reports 6,133 tracked target units.

`quality-scan` additionally requires a complete dependency-preparation receipt. Preparation is
keyed by the target pin/tree, lockfile and recursive install configuration, exact package-manager
version, Node/ABI, platform/architecture, install flags, and every value in the bounded execution
environment (`CI`, `HOME`, `PATH`, and `TMPDIR`). A hit still performs a frozen offline
materialization into the disposable clone. Corrupt/incomplete receipts or stores reject visibly
and retry clean; a final failure removes every partial `node_modules` tree and forces quality-scan
to bypass every target Knip/framework/provider config and attempt Knip directly in its all-plugins-
disabled, Harvey-inferred-entry source tier. Success preserves review-tier M5 findings and emits
M5-98; failure of that safe tier emits M5-00. A rejected installed tree is never consumed. The
receipt proves dependency materialization; it does not make arbitrary target code reproducible.
Install lifecycle scripts and executable configuration can read time, network, or file contents
outside the keyed tree even when every named environment value is unchanged.

Quality cacheability therefore comes from Harvey's installed Knip version, not a Harvey-maintained
framework filename list. Preparation imports Knip's live plugin catalog in a trusted child, selects
every plugin that loads configuration (`resolveConfig`), resolves that catalog's own config globs
with Knip's glob implementation across the package-manager and static Knip workspace roots, and
adds executable custom paths declared by `knip.json`, `knip.jsonc`, their dot-prefixed forms, or
`package.json#knip`. Package-manager workspace declarations are parsed from JSON/YAML and passed
unchanged to that same Knip glob implementation, including brace/extglob shapes; an unparseable or
non-enumerable declaration makes quality fresh. Knip's own executable control configs are included
too. A matching
`.js`/`.jsx`/`.mjs`/`.cjs`/`.ts`/`.tsx`/`.mts`/`.cts` input makes quality non-cacheable; so does any
catalog, workspace, static-config, or glob shape whose enumeration fails. The preparation receipt
and frozen offline install may still hit, but quality executes fresh and the scanner event records
the concrete paths or uncertainty. Static JSON/JSONC/YAML/TOML configuration remains cacheable
when it names no executable input: its tracked bytes are already bound by the pinned target tree.
This is intentionally fail-safe for new Knip plugins while retaining caching for targets proven
free of executable/dynamic configuration. npm, pnpm, and Yarn are all exercised through their real
clients from two checkout paths.

pnpm is forced to `enableGlobalVirtualStore=false`. pnpm 10/11 still writes a versioned `projects`
symlink to the current checkout, and a target can otherwise produce a versioned `links` installed
graph. Both trees are removed after every install; only content/index bytes remain. A real pnpm
cold-to-offline test with an actual package verifies the second checkout succeeds after that
sanitization, then asserts the store has no symlink and no `node_modules` path. This preserves the
content-addressed store/offline-materialization design rather than archiving an installed tree.

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

A pre-correction local Carbon candidate on 2026-08-12 used `--install`, snapshot external state, a
fresh shard cache, and the pinned 6,133-unit target. Cold was 417.75s wall / 397s phase-timed
(install 43.5s, quality 51.4s, detect-static 21.7s); restored was 49.21s wall / 32s phase-timed
(offline install 25.6s, quality 0.7s, detect-static 0.1s). Those are traceable local observations,
not final-design acceptance evidence: hosted run `31614708026` then showed that the relative cache
root was interpreted under each target cwd and M4 scanned cached package sources. The corrected
design canonicalizes that root before any child cwd change and has not yet produced a hosted
cold/warm pair.

The same pre-correction exercise recorded per-shard phase-timed sums of 32s, 84s, and 111s. Their
sum (227s) is not aggregate runner wall time, and their maximum (111s) is not the workflow critical
path; neither is claimed as such. Baseline conservation is outstanding because the cache-root
defect caused unrelated M4 drift. Two exact-base comparisons remain useful diagnostic
facts, not a conservation verdict: Rallly M5 expected 147 and measured 155 (+8), while Documenso M5
expected 1801 and measured 1800 (-1), identically at base `a157ff9`. Final cold/warm install totals,
runner critical path, aggregate runner wall time, all-shard cache size, and full baseline
conservation remain outstanding until the corrected hosted design runs.

The focused tests exercise both sides of every guard:

```sh
pnpm exec vitest run src/scan/mechanical-phase-cache.test.ts src/scan/mechanical-phase-identity.test.ts src/scan/mechanical-phase-cross-process.test.ts src/scan/semgrep.test.ts src/scan/mechanical.test.ts src/corpus-phase-cache-workflow.test.ts src/corpus-cache-transport.test.ts src/corpus-dependency-preparation.test.ts src/corpus-scanner-cache.test.ts src/corpus-scanner-identity.test.ts
HARVEY_HEAVY_CLI_TESTS=1 pnpm exec vitest run src/corpus-scanner-cross-process.test.ts
```

They prove cold/warm finding and scope equivalence, full-schema corruption rejection and
recomputation, discovery-backed helper closure, phase-granular invalidation, all-cacheable-phase
target-pin invalidation, live advisory and live-provider secret non-reuse, forced-cold mismatch and
all-miss failure, cache-miss execution, restored-registry validation/refusal, the required-context
aggregate, and the scheduled forced-cold path. The scanner cross-process guard creates two physical
Harvey checkout copies (only the tool installation is shared) and invokes the production corpus
scanner runner twice against matching tracked fixtures and a relative phase-cache root. Dependency
preparation and all three scanner families must miss then hit one external artifact directory while
preserving findings and examined scope; cache-only duplicate sources must remain invisible to M4.
The quality identity is separately falsified by changing its preparation key and each execution
environment value. A physical copy's real `src/quality-scan.ts` helper is mutated to prove closure
discovery moves only quality's implementation identity. The incomplete-preparation controls prove
all three directions across both failing corpus shapes: an incomplete receipt routes around the
partial provider, preserves source-only findings with M5-98 at both a package root and a nested
`nextjs/` scan root, and emits M5-00 if that safe tier itself fails; the same provider executes when
preparation is complete. The executable-config controls cover the live
Knip catalog's Vite default, a non-Vite provider in a declared workspace, a custom executable path
named only by static Knip configuration, an unenumerable configuration, and a static JSON/JSONC
direction that remains cacheable. The heavy Vite falsifier installs a local npm package named
`vite` and has `vite.config.js` choose its library entry from an external file under an unchanged
`HOME`, inside a real npm workspace declared by `packages/{app,lib}`: preparation reports miss then
hit/hit, all three quality runs are fresh, and changing only that external file moves M5-01 from
`packages/app/src/b.ts` to `packages/app/src/a.ts`.
