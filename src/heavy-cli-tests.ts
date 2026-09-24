// The heavy child-process test files, and how a full run is split across CI runners.
//
// The list and weights live in heavy-test-workloads.json. Vitest, the local full-run sharder and
// CI's PR impact planner all consume that one registry. Writing file names into ci.yml would let a
// new heavy file be excluded locally and run in no hosted shard, passing CI by being invisible.
// That is the silent-omission shape Harvey ranks as worse than a wrong status, so selection and
// shard assignment are derived, never independently declared.
//
// Why sharding is sound despite `poolOptions.forks.maxForks: 1`: that constraint is about
// contention on ONE machine — the files starve vitest's worker→main birpc ack channel when they
// overlap (measured in vitest.config.ts's header, #1120/#1133). Separate GitHub runners are
// separate machines, so a shard still runs its own files one at a time while shards run
// concurrently. The constraint is preserved exactly, not relaxed.
import { readFileSync } from "node:fs";

interface HeavyWorkload {
  id: string;
  testFile: string;
  weightSeconds: number;
}

interface HeavyRegistry {
  version: number;
  workloads: HeavyWorkload[];
}

const registry = JSON.parse(readFileSync(new URL("./heavy-test-workloads.json", import.meta.url), "utf8")) as HeavyRegistry;
if (registry.version !== 1 || !Array.isArray(registry.workloads) || registry.workloads.length === 0) {
  throw new Error("src/heavy-test-workloads.json is not a version-1 heavy workload registry");
}

export const HEAVY_CLI_TESTS = registry.workloads.map((workload) => workload.testFile);

// Scheduling samples come from the exact hosted run recorded in the registry. They are n=1
// observations rounded up to seconds, not upper bounds. heavy-test-plan validates a receipt for
// every workload/gate and reports the evidence stale when the planned head or local tree differs.
// Correctness still depends on conservation, never the weights: every registered file runs once.
// shardHeavyTests uses the maximum observed weight for a missing registry key.
const WEIGHT_HINT_SECONDS: Record<string, number> = Object.fromEntries(
  registry.workloads.map((workload) => [workload.testFile, workload.weightSeconds]),
);

/**
 * Reserve run-audit by itself when at least three shards are available, then use
 * longest-processing-time bin packing for every other file. Deterministic — ties break on path —
 * so shard N holds the same files on every run and a failure is reproducible from the shard index.
 */
export function shardHeavyTests(shardCount: number): string[][] {
  if (!Number.isInteger(shardCount) || shardCount < 1) {
    throw new Error(`shardHeavyTests: shardCount must be a positive integer, got ${shardCount}`);
  }
  const heaviestKnown = Math.max(...Object.values(WEIGHT_HINT_SECONDS));
  const weightOf = (f: string) => WEIGHT_HINT_SECONDS[f] ?? heaviestKnown;

  const reserved = shardCount >= 3 ? "src/cli/run-audit.test.ts" : undefined;
  const ordered = HEAVY_CLI_TESTS.filter((file) => file !== reserved).sort(
    (a, b) => weightOf(b) - weightOf(a) || a.localeCompare(b),
  );
  const shards: string[][] = Array.from({ length: shardCount }, () => []);
  const load: number[] = new Array<number>(shardCount).fill(0);
  if (reserved) {
    shards[0]?.push(reserved);
    load[0] = Number.POSITIVE_INFINITY;
  }
  for (const file of ordered) {
    let lightest = 0;
    for (let i = 1; i < shardCount; i++) if ((load[i] ?? 0) < (load[lightest] ?? 0)) lightest = i;
    shards[lightest]?.push(file);
    load[lightest] = (load[lightest] ?? 0) + weightOf(file);
  }
  return shards;
}
