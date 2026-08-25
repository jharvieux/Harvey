// Prints the heavy CLI test files assigned to one CI shard, one per line.
//
//   pnpm exec tsx src/cli/heavy-shard.ts --shard 2 --of 3
//
// This is the local/full-run sharder. Hosted PR selection uses src/heavy-test-plan.mjs. Locally,
// the shard membership is derived from src/heavy-cli-tests.ts and an eighth heavy file cannot be
// excluded by Vitest yet absent from the hosted or local population: both paths now consume the
// same heavy-test-workloads.json registry (#1228).
//
// Exits non-zero on a bad index, and prints nothing but file paths on success — the workflow feeds
// stdout straight to vitest, so any stray output would be read as a filename.
import "./sync-stdio.js";
import { HEAVY_CLI_TESTS, shardHeavyTests } from "../heavy-cli-tests.js";
import { assertKnownFlags } from "./args.js";

const argv = process.argv.slice(2);
assertKnownFlags(["--shard", "--of"], argv);

const num = (flag: string): number => {
  const i = argv.indexOf(flag);
  const raw = i === -1 ? undefined : argv[i + 1];
  if (raw === undefined) {
    console.error("usage: pnpm exec tsx src/cli/heavy-shard.ts --shard <1-based> --of <count>");
    process.exit(2);
  }
  const v = Number(raw);
  if (!Number.isInteger(v) || v < 1) {
    console.error(`${flag} must be a positive integer, got ${raw}`);
    process.exit(2);
  }
  return v;
};

const of = num("--of");
const shard = num("--shard");
if (shard > of) {
  console.error(`--shard ${shard} is out of range for --of ${of}`);
  process.exit(2);
}
if (of > HEAVY_CLI_TESTS.length) {
  console.error(
    `--of ${of} exceeds the ${HEAVY_CLI_TESTS.length} heavy test files — a shard would get nothing to run, and an empty vitest invocation exits non-zero. Lower the matrix width in ci.yml.`,
  );
  process.exit(2);
}

// Non-null via the range checks above; kept explicit so a future width change fails loud here
// rather than printing an empty list that vitest would reject with a confusing "no test files".
const files = shardHeavyTests(of)[shard - 1];
if (!files || files.length === 0) {
  console.error(`shard ${shard} of ${of} resolved to no files — refusing to emit an empty list`);
  process.exit(2);
}
for (const file of files) console.log(file);
