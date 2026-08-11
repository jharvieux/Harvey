// The heavy child-process test files, and how they are split across CI runners.
//
// The list lives here rather than in vitest.config.ts so that BOTH consumers read the same array:
// the vitest config (which excludes them from `pnpm verify` and includes them in the heavy run) and
// src/cli/heavy-shard.ts (which tells each CI shard what to run). The alternative — writing the
// file names into .github/workflows/ci.yml — would mean another heavy file could be added to the
// config and run in NO shard, passing CI by being invisible. That is the silent-omission shape
// CLAUDE.md ranks as worse than a wrong status, so the shard assignment is DERIVED, never declared.
//
// Why sharding is sound despite `poolOptions.forks.maxForks: 1`: that constraint is about
// contention on ONE machine — the files starve vitest's worker→main birpc ack channel when they
// overlap (measured in vitest.config.ts's header, #1120/#1133). Separate GitHub runners are
// separate machines, so a shard still runs its own files one at a time while shards run
// concurrently. The constraint is preserved exactly, not relaxed.
export const HEAVY_CLI_TESTS = [
  "src/cli/run-audit.test.ts",
  "src/fix/calibration-acceptance.test.ts",
  "src/cli/quick-scan.test.ts",
  "src/fix/detector-rerun.test.ts",
  "src/cli/mutation-scan.test.ts",
  "src/cli/quality-scan.test.ts",
  "src/cli/lighthouse-scan.test.ts",
  "src/cli/validate-calibration.test.ts",
  "src/cli/fix-execute.test.ts",
];

// Seconds, MEASURED from CI. A BALANCE HINT ONLY — correctness never depends on these being
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
const WEIGHT_HINT_SECONDS: Record<string, number> = {
  // 100s is a scheduling reservation above the 87s high observation so the long pole stays alone.
  "src/cli/run-audit.test.ts": 100.0,
  "src/fix/calibration-acceptance.test.ts": 37.7,
  "src/cli/quick-scan.test.ts": 28.4,
  "src/fix/detector-rerun.test.ts": 25.9,
  "src/cli/mutation-scan.test.ts": 21.1,
  "src/cli/quality-scan.test.ts": 18.9,
  "src/cli/lighthouse-scan.test.ts": 15.0,
  "src/cli/validate-calibration.test.ts": 40.0,
  "src/cli/fix-execute.test.ts": 23.3,
};

/**
 * Longest-processing-time bin packing: every file lands in exactly one shard, heaviest first onto
 * whichever shard is currently lightest. Deterministic — ties break on path — so shard N holds the
 * same files on every run and a failure is reproducible from the shard index alone.
 */
export function shardHeavyTests(shardCount: number): string[][] {
  if (!Number.isInteger(shardCount) || shardCount < 1) {
    throw new Error(`shardHeavyTests: shardCount must be a positive integer, got ${shardCount}`);
  }
  const heaviestKnown = Math.max(...Object.values(WEIGHT_HINT_SECONDS));
  const weightOf = (f: string) => WEIGHT_HINT_SECONDS[f] ?? heaviestKnown;

  const ordered = [...HEAVY_CLI_TESTS].sort(
    (a, b) => weightOf(b) - weightOf(a) || a.localeCompare(b),
  );
  const shards: string[][] = Array.from({ length: shardCount }, () => []);
  const load: number[] = new Array<number>(shardCount).fill(0);
  for (const file of ordered) {
    let lightest = 0;
    for (let i = 1; i < shardCount; i++) if ((load[i] ?? 0) < (load[lightest] ?? 0)) lightest = i;
    shards[lightest]?.push(file);
    load[lightest] = (load[lightest] ?? 0) + weightOf(file);
  }
  return shards;
}
