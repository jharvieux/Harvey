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
// PROVENANCE: MEASURED from CI run 30584076405 (job `clone pinned commits + score baselines`,
// 2026-07-30, a full `--install` scoring pass over every target). Derived from the per-target
// `=== <slug> (<repo> @ <sha>) ===` banners corpus-drift.ts prints: each target's cost is the
// interval between its banner and the next one, and the last target's is the interval to the
// scorecard print. Total 1287s, which reconciles with that step's own 1289s runtime.
//
// These are a PARTITIONING HINT, not a claim about any future run — clone times, runner class and
// upstream tool versions all move them. Nothing is scored against them and no gate reads them; the
// only consequence of a stale weight is a less even split. `--shard` prints each target's ACTUAL
// elapsed seconds so a real run always re-measures what this table only estimates.
//
// n=1. carbon's dominance is what makes the partition robust to that: at 564s it is 4.7x the next
// largest target, so it lands alone in a shard under any plausible re-measurement.
export const TARGET_SCAN_SECONDS: Readonly<Record<string, number>> = {
  carbon: 564,
  documenso: 119,
  "inbox-zero": 95,
  proposit: 86,
  "saas-lite": 77,
  ghostfolio: 67,
  rallly: 56,
  boxyhq: 54,
  "tanstack-com": 46,
  "multi-tenant-starter": 37,
  "mvp-boilerplate": 35,
  "launch-mvp": 24,
  "subscription-payments": 17,
  "supabase-security-labs": 7,
};

// A target added to EXTERNAL_CORPUS after the table was measured has no entry. It gets a weight at
// the heavier end of the measured spread deliberately: under-weighting a new target concentrates it
// with others and skews one shard long, while over-weighting only isolates it. The cost of being
// wrong is asymmetric, so the default leans to the safe side rather than to the median.
export const DEFAULT_SCAN_SECONDS = 120;

export const weightOf = (slug: string): number => TARGET_SCAN_SECONDS[slug] ?? DEFAULT_SCAN_SECONDS;

/**
 * Longest-processing-time-first partition: sort by descending cost, then repeatedly assign the next
 * target to the shard that is currently lightest. Ties break on slug so the split is deterministic —
 * a given corpus and shard count always produce the same assignment, which is what lets a shard be
 * addressed by index from a CI matrix without any coordination between runners.
 *
 * LPT rather than round-robin because the corpus is heavily skewed: round-robin over a list whose
 * largest element is 44% of the total pairs that element with others and wastes the parallelism.
 */
export function partitionTargets(slugs: readonly string[], shardCount: number): string[][] {
  if (!Number.isInteger(shardCount) || shardCount < 1) {
    throw new Error(`shard count must be a positive integer, got ${shardCount}`);
  }
  const shards = Array.from({ length: shardCount }, () => ({ slugs: [] as string[], load: 0 }));

  const ordered = [...slugs].sort((a, b) => weightOf(b) - weightOf(a) || a.localeCompare(b));
  for (const slug of ordered) {
    const lightest = shards.reduce((a, b) => (b.load < a.load ? b : a));
    lightest.slugs.push(slug);
    lightest.load += weightOf(slug);
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
