import { describe, expect, it } from "vitest";

import {
  assertPartitionCoversEveryTarget,
  COLD_CORPUS_SHARD_PROFILE,
  corpusShardTargetDigest,
  DEFAULT_SCAN_SECONDS,
  partitionTargets,
  selectCorpusShardProfile,
  shardTargets,
  TARGET_SCAN_SECONDS,
  WARM_CORPUS_SHARD_PROFILE,
  weightOf,
} from "./corpus-shards.js";
import { EXTERNAL_CORPUS } from "./external-corpus.js";

const SLUGS = EXTERNAL_CORPUS.map((t) => t.slug);
const load = (shard: string[]): number => shard.reduce((n, s) => n + weightOf(s), 0);

describe("corpus shard partition (#1586)", () => {
  // The failure this guards is silent: a target dropped from the partition stops being scored, its
  // shard still exits 0, and the aggregate reads green while coverage shrank. So the property is
  // asserted over the REAL corpus, not a fixture, and at every shard count CI might plausibly use.
  it.each([1, 2, 3, 4, 5])("scores every corpus target exactly once at %i shard(s)", (count) => {
    const shards = partitionTargets(SLUGS, count);
    expect(shards).toHaveLength(count);
    expect([...shards.flat()].sort()).toEqual([...SLUGS].sort());
  });

  it("addresses shards 1-based, matching how the CI matrix names them", () => {
    const shards = partitionTargets(SLUGS, 3);
    expect(shardTargets(SLUGS, 1, 3)).toEqual(shards[0]);
    expect(shardTargets(SLUGS, 3, 3)).toEqual(shards[2]);
    expect(() => shardTargets(SLUGS, 0, 3)).toThrow(/within 1\.\.3/);
    expect(() => shardTargets(SLUGS, 4, 3)).toThrow(/within 1\.\.3/);
  });

  it("is deterministic, so shards need no coordination between runners", () => {
    expect(partitionTargets(SLUGS, 3)).toEqual(partitionTargets([...SLUGS].reverse(), 3));
  });

  // The point of sharding is wall clock, so this asserts the OUTCOME rather than the mechanism: at
  // 3 shards the longest shard must be the single heaviest target, i.e. the split is already
  // optimal and bounded only by an indivisible target. If a future corpus change makes the split
  // worse than that floor, this fails and the shard count wants revisiting.
  it("at 3 shards the longest shard is bounded by the heaviest single target", () => {
    const heaviest = Math.max(...SLUGS.map((slug) => weightOf(slug)));
    const longest = Math.max(...partitionTargets(SLUGS, 3).map(load));
    expect(longest).toBe(heaviest);
  });

  it("beats the serial run it replaces", () => {
    const serial = load([...SLUGS]);
    const longest = Math.max(...partitionTargets(SLUGS, 3).map(load));
    expect(longest).toBeLessThan(serial / 2);
  });

  it("gives a target with no measured weight the heavier default rather than dropping it", () => {
    expect(weightOf("a-target-never-measured")).toBe(DEFAULT_SCAN_SECONDS);
    const withNew = [...SLUGS, "a-target-never-measured"];
    const shards = partitionTargets(withNew, 3);
    expect([...shards.flat()].sort()).toEqual([...withNew].sort());
  });

  it("rejects a nonsensical shard count instead of silently scoring nothing", () => {
    expect(() => partitionTargets(SLUGS, 0)).toThrow(/positive integer/);
    expect(() => partitionTargets(SLUGS, 1.5)).toThrow(/positive integer/);
  });
});

describe("provenance-bound cold/warm shard profiles (#1875)", () => {
  it("retains both exact-head measured populations and their source digests", () => {
    expect(COLD_CORPUS_SHARD_PROFILE).toMatchObject({ runId: 31549148174, runAttempt: 1, headSha: "43d819b59aea38bcd777016f167037298c87c550" });
    expect(WARM_CORPUS_SHARD_PROFILE).toMatchObject({ runId: 31549148174, runAttempt: 2, headSha: "43d819b59aea38bcd777016f167037298c87c550" });
    expect(Object.keys(COLD_CORPUS_SHARD_PROFILE.seconds).sort()).toEqual([...SLUGS].sort());
    expect(Object.keys(WARM_CORPUS_SHARD_PROFILE.seconds).sort()).toEqual([...SLUGS].sort());
    expect(COLD_CORPUS_SHARD_PROFILE.targetDigest).toBe(corpusShardTargetDigest(SLUGS));
    expect(WARM_CORPUS_SHARD_PROFILE.targetDigest).toBe(corpusShardTargetDigest(SLUGS));
    expect(COLD_CORPUS_SHARD_PROFILE.sourceDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(WARM_CORPUS_SHARD_PROFILE.sourceDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(COLD_CORPUS_SHARD_PROFILE.sourceDigest).not.toBe(WARM_CORPUS_SHARD_PROFILE.sourceDigest);
  });

  it("selects warm only for an exact population with verified cache provenance", () => {
    expect(selectCorpusShardProfile(SLUGS, "warm", "verified-warm").selected).toBe("warm");
    expect(selectCorpusShardProfile(SLUGS, "auto", "verified-warm").selected).toBe("warm");
    expect(selectCorpusShardProfile(SLUGS, "warm", "uncertain")).toMatchObject({ selected: "cold", reason: expect.stringMatching(/uncertain/) });
    expect(selectCorpusShardProfile([...SLUGS, "new-target"], "warm", "verified-warm")).toMatchObject({ selected: "cold", reason: expect.stringMatching(/stale/) });
    expect(selectCorpusShardProfile(SLUGS, "cold", "verified-warm")).toMatchObject({ selected: "cold", reason: "cold requested explicitly" });
  });

  it("keeps every target exact under both measured profiles and rejects an unknown warm weight", () => {
    for (const profile of ["cold", "warm"] as const) {
      for (const count of [3, 4]) expect([...partitionTargets(SLUGS, count, profile).flat()].sort()).toEqual([...SLUGS].sort());
    }
    expect(() => partitionTargets([...SLUGS, "unknown"], 3, "warm")).toThrow(/does not cover target/);
  });
});

describe("the partition guard can actually fail (#1586)", () => {
  // Negative controls. Without these the exhaustiveness check is untested code asserting a property
  // nothing ever violates, which is indistinguishable from no check at all.
  it("catches a target that would never be scored", () => {
    expect(() => assertPartitionCoversEveryTarget(["a", "b", "c"], [["a"], ["b"]])).toThrow(/never scored: c/);
  });

  it("catches a target scored twice", () => {
    expect(() => assertPartitionCoversEveryTarget(["a", "b"], [["a", "b"], ["b"]])).toThrow(/scored more than once: b/);
  });

  it("catches a slug that is not in the corpus at all", () => {
    expect(() => assertPartitionCoversEveryTarget(["a"], [["a"], ["typo"]])).toThrow(/not in the corpus: typo/);
  });

  it("passes a true partition", () => {
    expect(() => assertPartitionCoversEveryTarget(["a", "b", "c"], [["c"], ["a"], ["b"]])).not.toThrow();
  });
});

describe("the weight table tracks the corpus (#1586)", () => {
  // A weight is only a partitioning hint, so a missing one is not an error — but a weight for a
  // target that no longer exists is a stale row that will quietly mis-skew the split, and nothing
  // else would ever surface it.
  it("has no weight for a target that has left the corpus", () => {
    expect(Object.keys(TARGET_SCAN_SECONDS).filter((s) => !SLUGS.includes(s))).toEqual([]);
  });
});
