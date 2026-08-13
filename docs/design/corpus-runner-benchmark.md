# Corpus performance benchmark contract

The corpus workflow keeps its production defaults at `ubuntu-latest`, one serial target worker,
and three shards until an unchanged-head hosted cohort passes the committed evaluator. The PR and
scheduled runner selectors are independent repository variables (`CORPUS_PR_RUNNER_LABEL` and
`CORPUS_SCHEDULE_RUNNER_LABEL`). `CORPUS_BENCHMARK_RUNNER_LABEL` is only a benchmark candidate;
requesting it while it is unset fails the run. The repository API reported no repository-visible
runner and no selector variable on 2026-08-12, so no larger-runner result is claimed here.

## Evidence envelope

Every sample binds the workflow run and attempt, exact head, benchmark seed, and the immutable
workflow run that authored that seed bundle, plus repeat, actual
runner name class/group/labels/image (while retaining each hosted VM's raw unique name), CPU and cgroup-memory admission, Node/pnpm/tool versions, pinned
target commits, cache transport keys and provenance, raw job ids/timestamps, scorecard artifacts,
and per-target conservation. Critical path is the span from the first shard start to the last shard
finish. Summed runner time is the sum of shard intervals; it is never substituted for critical
path. Process-tree CPU/RSS is reported separately from phase wall time. Setup/network is the job
interval before the scoring step; dependency preparation retains its own phase total.

Cold samples require forced recomputation against the exact seed with no rejection or ordinary
miss. Warm samples require validated all-hit receipts. Every sample must retain passing baseline,
liveness, forced-cold, and recomputed conservation assertions. A mixed head, seed, target
population, runner identity, duplicate repeat/run, OOM, retry, stranded artifact, stale conservation
vector, or missing provenance rejects the cohort rather than weakening it. The decision artifact
retains every raw sample with a stable digest and per-cohort median/p95/total/max critical path,
aggregate runner time, CPU, RSS, billed minutes, dollar estimate, and cache counts, so its choices
can be recalculated without consulting an ephemeral workflow log.

## Predeclared decisions

The versioned thresholds live in `src/corpus-benchmark.ts` and are hashed before results exist.

- Concurrency needs at least 10% median critical-path improvement in both cold and warm profiles,
  cold p95 no more than 5% worse, summed runner time no more than 10% higher, peak RSS at or below
  75% of the runner limit, and zero OOM/retry. Among qualifying candidates within 5% of the fastest,
  the evaluator chooses the least complex design and then the lower concurrency.
- A larger PR runner needs at least 20% median and 15% p95 improvement, cost no more than 25%
  higher, and no matched cold repeat more than 10% worse. Adoption is forbidden when dollar cost
  is absent. The scheduled selector stays on the current runner unless a candidate is no slower
  and within 5% cost; timeout prevention remains an explicit operator decision.
- Four shards need at least 15% warm median improvement, cold p95 no more than 10% worse, summed
  runner time no more than 25% higher, and zero stranded artifacts. Three shards remain the explicit
  cold fallback.

Any measured metric within five percentage points of its own threshold, or a critical-path
coefficient of variation above 10%, extends the complete comparison pair from three to five runs.
For concurrency this means all five standard shapes in both profiles. A shard-stage extension means
those same ten three-shard cohorts plus the selected design at four shards in both profiles: twelve
cohorts × repeats four and five, exactly 24 additional runs. The evaluator emits those exact
pair-complete cohort ids; a named subset is never sufficient because repeat populations must match.
`split-carbon`
is absent from workflow and CLI choices because no separate job/runner lane exists. The evaluator
retains it only as an explicit non-admissible negative-control disposition.

## Shard profiles and transport

`src/scan/corpus-shards.ts` retains separate cold and warm profiles from run `31549148174`, attempts
1 and 2 respectively, at head `43d819b59aea38bcd777016f167037298c87c550`. Each profile carries
the exact target-population and source digest. Warm partitioning is allowed only for an exact target
population with verified-warm cache provenance; an uncertain cache, stale population, or explicit
cold request selects cold. Unknown warm targets fail loud. Production uses the fail-safe cold
profile while the hosted three-versus-four cohort is pending.

Transport key family v7 restores every trusted old shard and merges only validated
content-addressed inner artifacts. The merge requires the exact seed/ref/head and complete source
namespace population, rejects conflicting duplicates and mutable paths, then lets a target move
from a three-shard seed into a four-shard run without losing its finding or examined-scope bytes.
Only the immutable seed-bundle run saves an Actions cache. It uses the manifest-compatible
`corpus-phase-benchmark-v7` family, and every sample restores the exact run id and attempt with no
rolling fallback. Sample outputs are uploaded evidence artifacts; they never write into the seed
namespace or any second Actions-cache family.

## Hosted collection

Use one non-empty seed and one unchanged branch head. First author its seed bundle and retain that
workflow run id; pass it as `benchmark_seed_run_id` on every sample. Then dispatch
three cold and three warm runs for the complete predeclared three-shard matrix: `serial` at one,
`target-workers` at one, two, and three, and `intra-target-overlap` at two. After selecting a design,
run `pnpm corpus-benchmark --pilot --samples <pilot.json> --out <selection.json>`; its output is the
truthful mechanical selection receipt for the final three-versus-four stage. If its `next` block says
`extend-standard`, dispatch exactly the 20 standard repeat-4/5 runs and rerun the pilot before any
four-shard dispatch. Otherwise dispatch its exact six four-shard runs. Full evaluation requires
`--pilot-decision <selection.json>` and rejects a receipt whose standard-row or cohort digest, selected
design, seed, head, or thresholds no longer matches. It never silently reselects from later rows.

The base campaign is 38 workflow runs: one seed bundle, 30 standard pilot samples, six selected
four-shard samples, and the isolated failure drill. A near-threshold shard result first adds 20
standard repeats and forces a new pilot receipt. If the selected design is stable, the new receipt
requests only the four matching repeat-4/5 runs: +24, 62 total. If selection changes, it requests a
fresh five-repeat four-shard pair for the new design: +30, 68 total worst case. The evaluator never
promises those four-shard runs before the extended pilot is recomputed. The full evaluator still
rejects a missing or partial final cohort. The failure drill never opens or updates the real
drift-alert issue. Do not dispatch the unavailable larger-runner half.

Each hosted run uploads its merged scorecard, raw Actions jobs, transport/merge/runner receipts,
worker logs and resource traces, and the derived benchmark sample. Production defaults change only
in an evidence-only commit after the complete cohort evaluates successfully; otherwise the negative
result and current defaults remain.
