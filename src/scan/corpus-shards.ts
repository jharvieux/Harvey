// #1586: corpus-drift scores its targets serially in one job, and that job is a REQUIRED context
// since 2026-07-30, so its wall clock sits on the critical path to every merge. This splits the
// target list across parallel runners.
//
// Why sharding and not in-job concurrency, MEASURED 2026-07-30 rather than assumed: every scanner
// runs through `execFileSync` (blocking), and semgrep's own default `--jobs` is
// `logical cores x 0.85` — Harvey passes no `--jobs`, so ONE target scan already saturates the
// runner. Sampled locally on a 10-core box, a single semgrep pass held ~740-750% CPU. Running N
// target-scans concurrently on one runner therefore oversubscribes rather than filling idle time,
// and semgrep's help warns that raising jobs "induce[s] significant GC latency and slow scan
// times". The parallelism has to come from more machines.

// Per-target scan cost in SECONDS.
//
// PROVENANCE: maximum of each target's elapsed row in pinned-toolchain PR run 35964551348 and
// main run 35968096776 (2026-09-24). These are wall-clock target durations, not the sum of
// overlapping PHASE timers. Both runs used fresh mechanical execution and restored dependency
// preparation stores; a changed partition still needs hosted cold-store acceptance.
//
// These are a PARTITIONING HINT, not a claim about any future run — clone times, runner class and
// upstream tool versions all move them. No baseline is scored against them. A stale weight can
// exhaust a runner's deadline, so `--shard` prints each target's ACTUAL elapsed seconds and hosted
// acceptance must include setup, cache publication, scorecards, liveness and runner teardown.
export const TARGET_SCAN_SECONDS: Readonly<Record<string, number>> = {
  carbon: 2057,
  documenso: 898,
  "inbox-zero": 865,
  "tanstack-com": 390,
  ghostfolio: 356,
  rallly: 410,
  cravab: 235,
  "flori-web": 224,
  proposit: 149,
  boxyhq: 159,
  "saas-lite": 185,
  "mvp-boilerplate": 93,
  "multi-tenant-starter": 94,
  "launch-mvp": 105,
  "subscription-payments": 92,
  effective: 96,
  "supabase-security-labs": 71,
};

// An unmeasured target still receives a positive estimate and an owner. Its first hosted elapsed
// row must replace this fallback before the expanded population is considered budgeted.
export const DEFAULT_SCAN_SECONDS = 120;

// Hosted scoring uses four jobs on every full-population event. Local all-target runs retain
// the same canonical ownership: a target always reads and writes one of these four roots.
export const CORPUS_CACHE_SHARD_COUNT = 4;
export const CORPUS_CACHE_PARTITION_POLICY = "corpus-capacity-lpt-four-owner-v2";

// These are the existing whole-job limits, not a request to extend them. Keep setup, transport
// verification/publication, scorecard delivery and runner teardown out of the target capacity.
// The workflow contract checks the actual YAML limits; the scope receipt binds both inputs.
export const CORPUS_SHARD_JOB_BUDGET_SECONDS = [45 * 60, 35 * 60, 30 * 60, 30 * 60] as const;
export const CORPUS_SHARD_OVERHEAD_SECONDS = 5 * 60;

/** POSIX-style byte ordering for identities shared across runners and locales. */
export const compareUtf8Bytes = (a: string, b: string): number => Buffer.compare(Buffer.from(a), Buffer.from(b));

const weightFrom = (
  slug: string,
  weights: Readonly<Record<string, number>>,
): number => weights[slug] ?? DEFAULT_SCAN_SECONDS;

export const weightOf = (slug: string): number => weightFrom(slug, TARGET_SCAN_SECONDS);

/**
 * Longest-processing-time-first partition: sort by descending cost, then assign each target to
 * the least projected utilization of the available job time. The canonical four owners have
 * unequal deadlines; balancing raw seconds stranded capacity on the longer jobs while a 30m
 * owner timed out during publication. Other local shard counts retain equal-capacity LPT.
 * UTF-8 slug order and lower-namespace ties keep every producer/replay/cache owner deterministic.
 */
export function partitionTargets(
  slugs: readonly string[],
  shardCount: number,
  weights: Readonly<Record<string, number>> = TARGET_SCAN_SECONDS,
): string[][] {
  if (!Number.isInteger(shardCount) || shardCount < 1) {
    throw new Error(`shard count must be a positive integer, got ${shardCount}`);
  }
  const shards = Array.from({ length: shardCount }, (_, index) => ({
    slugs: [] as string[],
    load: 0,
    capacity: shardCount === CORPUS_CACHE_SHARD_COUNT
      ? CORPUS_SHARD_JOB_BUDGET_SECONDS[index]! - CORPUS_SHARD_OVERHEAD_SECONDS
      : 1,
  }));
  const selectedWeight = weights === TARGET_SCAN_SECONDS ? weightOf : (slug: string): number => weightFrom(slug, weights);

  const ordered = [...slugs].sort((a, b) => selectedWeight(b) - selectedWeight(a) || compareUtf8Bytes(a, b));
  for (const slug of ordered) {
    const weight = selectedWeight(slug);
    const lightest = shards.reduce((a, b) =>
      (b.load + weight) * a.capacity < (a.load + weight) * b.capacity ? b : a);
    lightest.slugs.push(slug);
    lightest.load += weight;
  }
  return shards.map((s) => s.slugs);
}

/**
 * The targets for one shard, addressed as 1-based `index/count` the way the CI matrix names it.
 *
 * A sharding bug that DROPS a target is the failure this repo cares about most: the dropped
 * target's baseline simply stops being checked, every shard exits 0, and the aggregate reads green
 * while coverage silently shrank. So the partition is verified exhaustive and disjoint on every
 * call rather than trusted — it is a few microseconds against a 20-minute job.
 */
export function shardTargets(slugs: readonly string[], shardIndex: number, shardCount: number): string[] {
  if (!Number.isInteger(shardIndex) || shardIndex < 1 || shardIndex > shardCount) {
    throw new Error(`shard index must be within 1..${shardCount}, got ${shardIndex}`);
  }
  const shards = partitionTargets(slugs, shardCount);
  assertPartitionCoversEveryTarget(slugs, shards);
  const mine = shards[shardIndex - 1];
  if (!mine) throw new Error(`shard ${shardIndex}/${shardCount} does not exist`);
  return mine;
}

/** The fixed, event-independent cache owner for one corpus target. */
export function corpusCacheNamespaceForTarget(slugs: readonly string[], slug: string): number {
  const shards = partitionTargets(slugs, CORPUS_CACHE_SHARD_COUNT);
  assertPartitionCoversEveryTarget(slugs, shards);
  const owner = shards.findIndex((members) => members.includes(slug));
  if (owner < 0) throw new Error(`corpus cache target ${slug} has no canonical owner`);
  return owner + 1;
}

/** Throws unless the shards are a true partition of `slugs` — every target exactly once. */
export function assertPartitionCoversEveryTarget(slugs: readonly string[], shards: readonly string[][]): void {
  const seen = new Map<string, number>();
  for (const shard of shards) for (const slug of shard) seen.set(slug, (seen.get(slug) ?? 0) + 1);

  const missing = slugs.filter((s) => !seen.has(s));
  const duplicated = [...seen].filter(([, n]) => n > 1).map(([s]) => s);
  const unknown = [...seen.keys()].filter((s) => !slugs.includes(s));

  if (missing.length || duplicated.length || unknown.length) {
    throw new Error(
      "corpus shard partition is not a partition — a target scored zero or twice is a silent coverage change: " +
        [
          missing.length ? `never scored: ${missing.join(", ")}` : "",
          duplicated.length ? `scored more than once: ${duplicated.join(", ")}` : "",
          unknown.length ? `not in the corpus: ${unknown.join(", ")}` : "",
        ]
          .filter(Boolean)
          .join("; "),
    );
  }
}
