// The point of these tests is CONSERVATION: every heavy test file lands in exactly one shard, for
// any shard width CI might use. Sharding is the one change that can make a test file stop running
// while CI still goes green — the failure would be a regression merging clean, with no row in any
// tally to argue with. So the partition is asserted, not assumed.
import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { HEAVY_CLI_TESTS, shardHeavyTests } from "./heavy-cli-tests.js";

describe("heavy CLI test sharding", () => {
  it("every listed file exists — a rename that missed this list would silently stop running it", () => {
    for (const f of HEAVY_CLI_TESTS) expect(existsSync(f), `${f} is listed but not on disk`).toBe(true);
  });

  it("the list has no duplicates", () => {
    expect(new Set(HEAVY_CLI_TESTS).size).toBe(HEAVY_CLI_TESTS.length);
  });

  for (let n = 1; n <= HEAVY_CLI_TESTS.length; n++) {
    it(`partitions all ${HEAVY_CLI_TESTS.length} files across ${n} shard(s) — no file dropped, none run twice`, () => {
      const shards = shardHeavyTests(n);
      expect(shards).toHaveLength(n);
      const flat = shards.flat();
      expect(flat.length, "a file was dropped or duplicated").toBe(HEAVY_CLI_TESTS.length);
      expect([...flat].sort()).toEqual([...HEAVY_CLI_TESTS].sort());
      // An empty shard would make its CI job invoke vitest with no files, which exits non-zero.
      for (const s of shards) expect(s.length, "empty shard").toBeGreaterThan(0);
    });
  }

  it("is deterministic — shard N holds the same files every run, so a failure is reproducible", () => {
    expect(shardHeavyTests(3)).toEqual(shardHeavyTests(3));
  });

  it("gives run-audit a shard to ITSELF at the width CI uses", () => {
    // run-audit is both the longest single file and the most variable (58.3s and ~87s across two
    // CI runs), so it sets the wall-clock floor. Stacking anything behind it puts that variance on
    // the critical path — measured: the first sharded run landed at 141s against a 104s prediction
    // precisely because lighthouse sat behind it. Alone, its variance costs only itself.
    const shards = shardHeavyTests(3);
    const withRunAudit = shards.find((s) => s.includes("src/cli/run-audit.test.ts"));
    expect(withRunAudit, "run-audit.test.ts is not in any shard").toBeDefined();
    expect(withRunAudit, "run-audit must not share a shard — it is the wall-clock floor").toEqual([
      "src/cli/run-audit.test.ts",
    ]);
  });

  it("rejects a nonsensical shard count rather than silently returning nothing", () => {
    expect(() => shardHeavyTests(0)).toThrow(/positive integer/);
    expect(() => shardHeavyTests(-1)).toThrow(/positive integer/);
    expect(() => shardHeavyTests(1.5)).toThrow(/positive integer/);
  });
});
