# Corpus performance benchmark contract

The corpus workflow keeps its production defaults at `ubuntu-latest`, one serial target worker,
and three shards until an unchanged-head hosted cohort passes the committed evaluator. The PR and
scheduled runner selectors are independent repository variables (`CORPUS_PR_RUNNER_LABEL` and
`CORPUS_SCHEDULE_RUNNER_LABEL`). `CORPUS_BENCHMARK_RUNNER_LABEL` is only a benchmark candidate;
requesting it while it is unset fails the run. The repository API reported no repository-visible
runner and no selector variable on 2026-08-12, so no larger-runner result is claimed here.

## Evidence envelope

Every sample binds the workflow run and attempt, exact head and benchmark seed, repeat, actual
runner name/group/labels/image, CPU and cgroup-memory admission, Node/pnpm/tool versions, pinned
target commits, cache transport keys and provenance, raw job ids/timestamps, scorecard artifacts,
and per-target conservation. Critical path is the span from the first shard start to the last shard
finish. Summed runner time is the sum of shard intervals; it is never substituted for critical
path. Process-tree CPU/RSS is reported separately from phase wall time. Setup/network is the job
interval before the scoring step; dependency preparation retains its own phase total.

Cold samples require forced recomputation against the exact seed with no rejection or ordinary
miss. Warm samples require validated all-hit receipts. Every sample must retain passing baseline,
liveness, forced-cold, and recomputed conservation assertions. A mixed head, seed, target
population, runner identity, duplicate repeat/run, OOM, retry, stranded artifact, stale conservation
vector, or missing provenance rejects the cohort rather than weakening it.

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
coefficient of variation above 10%, extends that cohort from three to five runs. The
`split-carbon` input is a pilot label, not evidence: until it produces an independently admitted
lane, the evaluator rejects it.

## Shard profiles and transport

`src/scan/corpus-shards.ts` retains separate cold and warm profiles from run `31549148174`, attempts
1 and 2 respectively, at head `43d819b59aea38bcd777016f167037298c87c550`. Each profile carries
the exact target-population and source digest. Warm partitioning is allowed only for an exact target
population with verified-warm cache provenance; an uncertain cache, stale population, or explicit
cold request selects cold. Unknown warm targets fail loud. Production uses the fail-safe cold
profile while the hosted three-versus-four cohort is pending.

Transport schema/key family v6 restores every trusted old shard and merges only validated
content-addressed inner artifacts. The merge requires the exact seed/ref/head and complete source
namespace population, rejects conflicting duplicates and mutable paths, then lets a target move
from a three-shard seed into a four-shard run without losing its finding or examined-scope bytes.

## Hosted collection

Use one non-empty seed and one unchanged branch head. First author its seed bundle. Then dispatch
three cold and three warm runs for each pilot design (`serial`, `target-workers` at two,
`intra-target-overlap` at two); `split-carbon` remains a negative control until it has a real lane.
After selecting a design, dispatch concurrency one, two, and three on three shards in both profiles,
plus the production concurrency on four shards in both profiles. Run the injected post-start failure
drill separately. Extend named cohorts to five only when the evaluator requests it. Do not dispatch
the unavailable larger-runner half.

Each hosted run uploads its merged scorecard, raw Actions jobs, transport/merge/runner receipts,
worker logs and resource traces, and the derived benchmark sample. Production defaults change only
in an evidence-only commit after the complete cohort evaluates successfully; otherwise the negative
result and current defaults remain.
