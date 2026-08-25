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

// Seconds, MEASURED from CI unless an inline row says otherwise. A BALANCE HINT ONLY — correctness never depends on these being
// current. They drift as tests are added, and a stale number costs a few seconds of imbalance,
// never a dropped file. A file absent from this table is deliberately treated as the heaviest known
// (see shardHeavyTests): an unweighted newcomer gets placed first and alone rather than silently
// padding an already-full shard.
//
// run-audit carries its HIGH observation, not its average, and that is deliberate. Two runs:
// 58.3s (run 30272315745) and ~87s (run 30276431912, the first sharded run — shard 1 spent 102s on
// run-audit + lighthouse). It is both the longest file and by far the most variable, and it sets
// the wall-clock floor no matter how many shards there are. Weighting it high makes LPT give it a
// shard to itself, so its variance stops pushing a second file's cost onto the critical path —
// which is exactly what made that first sharded run land at 141s against a 104s prediction.
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
