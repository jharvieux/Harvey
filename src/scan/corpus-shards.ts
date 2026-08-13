import { createHash } from "node:crypto";

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

export type CorpusShardProfileName = "cold" | "warm";
export type CorpusShardProfileRequest = "auto" | CorpusShardProfileName;
export type CorpusShardCacheProvenance = "uncertain" | "verified-warm";

interface CorpusShardProfile {
  name: CorpusShardProfileName;
  runId: 31549148174;
  runAttempt: 1 | 2;
  headSha: "43d819b59aea38bcd777016f167037298c87c550";
  measuredAt: string;
  targetDigest: string;
  sourceDigest: string;
  seconds: Readonly<Record<string, number>>;
}

export interface CorpusShardProfileSelection {
  requested: CorpusShardProfileRequest;
  selected: CorpusShardProfileName;
  cacheProvenance: CorpusShardCacheProvenance;
  targetDigest: string;
  sourceDigest: string;
  runId: number;
  runAttempt: number;
  reason: string;
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function sha256(value: unknown): string {
  return createHash("sha256").update(stable(value)).digest("hex");
}

export function corpusShardTargetDigest(slugs: readonly string[]): string {
  return sha256([...slugs].sort());
}

function profile(input: Omit<CorpusShardProfile, "targetDigest" | "sourceDigest">): CorpusShardProfile {
  const targetDigest = corpusShardTargetDigest(Object.keys(input.seconds));
  const sourceDigest = sha256({ ...input, targetDigest });
  return { ...input, targetDigest, sourceDigest };
}

// #1875: both profiles are the same exact-head hosted run. Attempt 1 was the cold/miss path and
// attempt 2 restored it. The values are the per-target totals printed by corpus-drift itself, not
// estimates reconstructed from job duration. A warm choice is permitted only when its target
// digest still matches and cache provenance is verified; all uncertainty falls back to cold.
export const COLD_CORPUS_SHARD_PROFILE = profile({
  name: "cold",
  runId: 31549148174,
  runAttempt: 1,
  headSha: "43d819b59aea38bcd777016f167037298c87c550",
  measuredAt: "2026-08-12T00:21:05Z",
  seconds: {
    carbon: 671,
    proposit: 97,
    "inbox-zero": 94,
    "saas-lite": 93,
    documenso: 114,
    ghostfolio: 60,
    "launch-mvp": 56,
    "multi-tenant-starter": 54,
    rallly: 54,
    boxyhq: 51,
    cravab: 50,
    "tanstack-com": 48,
    "mvp-boilerplate": 47,
    "flori-web": 35,
    effective: 17,
    "subscription-payments": 15,
    "supabase-security-labs": 7,
  },
});

export const WARM_CORPUS_SHARD_PROFILE = profile({
  name: "warm",
  runId: 31549148174,
  runAttempt: 2,
  headSha: "43d819b59aea38bcd777016f167037298c87c550",
  measuredAt: "2026-08-12T00:29:18Z",
  seconds: {
    carbon: 290,
    documenso: 109,
    "inbox-zero": 91,
    proposit: 83,
    "saas-lite": 80,
    ghostfolio: 57,
    rallly: 51,
    boxyhq: 48,
    cravab: 46,
    "tanstack-com": 44,
    "multi-tenant-starter": 33,
    "launch-mvp": 32,
    "flori-web": 32,
    "mvp-boilerplate": 25,
    effective: 15,
    "subscription-payments": 14,
    "supabase-security-labs": 7,
  },
});

const CORPUS_SHARD_PROFILES: Readonly<Record<CorpusShardProfileName, CorpusShardProfile>> = {
  cold: COLD_CORPUS_SHARD_PROFILE,
  warm: WARM_CORPUS_SHARD_PROFILE,
};

// Compatibility export for consumers that intentionally mean the fail-safe profile.
export const TARGET_SCAN_SECONDS = COLD_CORPUS_SHARD_PROFILE.seconds;

// A target added to EXTERNAL_CORPUS after the table was measured has no entry. It gets a weight at
// the heavier end of the measured spread deliberately: under-weighting a new target concentrates it
// with others and skews one shard long, while over-weighting only isolates it. The cost of being
// wrong is asymmetric, so the default leans to the safe side rather than to the median.
export const DEFAULT_SCAN_SECONDS = 120;

export const weightOf = (slug: string, profileName: CorpusShardProfileName = "cold"): number => {
  const measured = profileName === "cold" ? TARGET_SCAN_SECONDS : CORPUS_SHARD_PROFILES.warm.seconds;
  return measured[slug] ?? DEFAULT_SCAN_SECONDS;
};

export function selectCorpusShardProfile(
  slugs: readonly string[],
  requested: CorpusShardProfileRequest,
  cacheProvenance: CorpusShardCacheProvenance,
): CorpusShardProfileSelection {
  const targetDigest = corpusShardTargetDigest(slugs);
  const warm = WARM_CORPUS_SHARD_PROFILE;
  const warmEligible = cacheProvenance === "verified-warm" && targetDigest === warm.targetDigest;
  const selected = requested === "cold" || !warmEligible ? COLD_CORPUS_SHARD_PROFILE : warm;
  const reason = requested === "cold"
    ? "cold requested explicitly"
    : cacheProvenance !== "verified-warm"
      ? "cache provenance is uncertain; selected the cold fallback"
      : targetDigest !== warm.targetDigest
        ? `warm profile population is stale (${warm.targetDigest} != ${targetDigest}); selected the cold fallback`
        : `${requested} request has exact verified-warm cache and target provenance`;
  return {
    requested,
    selected: selected.name,
    cacheProvenance,
    targetDigest,
    sourceDigest: selected.sourceDigest,
    runId: selected.runId,
    runAttempt: selected.runAttempt,
    reason,
  };
}

/**
 * Longest-processing-time-first partition: sort by descending cost, then repeatedly assign the next
 * target to the shard that is currently lightest. Ties break on slug so the split is deterministic —
 * a given corpus and shard count always produce the same assignment, which is what lets a shard be
 * addressed by index from a CI matrix without any coordination between runners.
 *
 * LPT rather than round-robin because the corpus is heavily skewed: round-robin over a list whose
 * largest element is 44% of the total pairs that element with others and wastes the parallelism.
 */
export function partitionTargets(slugs: readonly string[], shardCount: number, profileName: CorpusShardProfileName = "cold"): string[][] {
  if (!Number.isInteger(shardCount) || shardCount < 1) {
    throw new Error(`shard count must be a positive integer, got ${shardCount}`);
  }
  const shards = Array.from({ length: shardCount }, () => ({ slugs: [] as string[], load: 0 }));

  if (profileName === "warm") {
    const unknown = slugs.filter((slug) => CORPUS_SHARD_PROFILES.warm.seconds[slug] === undefined);
    if (unknown.length > 0) throw new Error(`warm corpus shard profile does not cover target(s): ${unknown.join(", ")}`);
  }
  const ordered = [...slugs].sort((a, b) => weightOf(b, profileName) - weightOf(a, profileName) || a.localeCompare(b));
  for (const slug of ordered) {
    const lightest = shards.reduce((a, b) => (b.load < a.load ? b : a));
    lightest.slugs.push(slug);
    lightest.load += weightOf(slug, profileName);
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
export function shardTargets(slugs: readonly string[], shardIndex: number, shardCount: number, profileName: CorpusShardProfileName = "cold"): string[] {
  if (!Number.isInteger(shardIndex) || shardIndex < 1 || shardIndex > shardCount) {
    throw new Error(`shard index must be within 1..${shardCount}, got ${shardIndex}`);
  }
  const shards = partitionTargets(slugs, shardCount, profileName);
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
