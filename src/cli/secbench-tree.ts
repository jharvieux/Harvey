// pnpm secbench-tree --dir <secbench-checkout> --out <work-tree> [--concurrency 8]
//
// Builds the lockfile tree `validate-secbench.ts --lockfile-tree` needs: one
// `<out>/<class>/<slug>/package.json` per SecBench entry carrying that entry's pinned dependencies,
// then `npm install --package-lock-only` in each so osv-scanner has something to read. SecBench
// ships no lockfiles, so the SCA pathway builds its input out of process before scoring (#879).
//
// This existed only as a paragraph of prose in docs/design/secbench-recall-measurement.md, executed
// by hand on the three occasions the gate has ever been scored. #1288 puts the gate on a monthly
// cadence, and a cadence needs a command rather than a paragraph.
//
// THE DENOMINATOR TRAP, which is why this fails loud rather than reporting what it managed. An
// entry whose lockfile is absent is EXCLUDED from the recall denominator by scoreSecbench — that is
// correct for the handful of packages npm no longer resolves, and catastrophic for a registry
// outage: 300 failed installs would not lower the score, they would RAISE it, by deleting 300
// chances to miss. So a failure rate past --max-failure-pct aborts before anything is scored.

import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readNamesSafe } from "../fs-walk.js";
import { promisify } from "node:util";
import { arg, assertKnownFlags } from "./args.js";
import { SECBENCH_PIN, SECBENCH_REPO, loadSecbenchCorpus } from "../scan/secbench.js";

const FLAGS = ["--dir", "--target", "--out", "--concurrency", "--max-failure-pct", "--print-pin"] as const;
assertKnownFlags(FLAGS);

// `--print-pin` emits shell-eval-able assignments so a caller fetching the corpus takes the pin
// from the SAME constants the loader and every recorded measurement are scoped to. A workflow that
// hardcodes the SHA is a second copy of the pin that can drift from the first without anyone
// choosing to, and the score would then be attributed to the wrong tree.
if (process.argv.includes("--print-pin")) {
  console.log(`SECBENCH_REPO=${SECBENCH_REPO}`);
  console.log(`SECBENCH_PIN=${SECBENCH_PIN}`);
  process.exit(0);
}

const dir = arg("--dir") ?? arg("--target");
const out = arg("--out");
if (!dir || !out) {
  console.error(
    `Usage: secbench-tree --dir <secbench-checkout> --out <work-tree> [--concurrency 8] [--max-failure-pct 5]\n` +
      `  git clone https://github.com/${SECBENCH_REPO} && git -C SecBench.js checkout ${SECBENCH_PIN}`,
  );
  process.exit(2);
}
const workRoot: string = out;
const concurrency = Number(arg("--concurrency") ?? 8);
const maxFailurePct = Number(arg("--max-failure-pct") ?? 5);

const fs = { listDir: readNamesSafe, readText: (p: string) => readFileSync(p, "utf8"), exists: existsSync };
const entries = loadSecbenchCorpus(dir, fs);
if (entries.length === 0) {
  console.error(`No SecBench entries loaded from ${dir}. Is it a SecBench.js checkout?`);
  process.exit(2);
}

const run = promisify(execFile);
const failures: { key: string; why: string }[] = [];
let generated = 0;

async function build(entry: (typeof entries)[number]): Promise<void> {
  const entryDir = join(workRoot, entry.cls, entry.slug);
  mkdirSync(entryDir, { recursive: true });
  writeFileSync(
    join(entryDir, "package.json"),
    JSON.stringify({ name: `secbench-${entry.slug.replace(/[^a-z0-9-]/gi, "-").toLowerCase()}`, version: "0.0.0", private: true, dependencies: entry.deps }, null, 2),
  );
  try {
    await run("npm", ["install", "--package-lock-only", "--no-audit", "--no-fund"], { cwd: entryDir, timeout: 120_000 });
  } catch (err) {
    failures.push({ key: entry.key, why: String((err as { stderr?: string }).stderr ?? err).split("\n").filter((l) => l.includes("npm error") || l.includes("code E")).slice(0, 2).join(" ").slice(0, 160) });
    return;
  }
  if (existsSync(join(entryDir, "package-lock.json"))) generated += 1;
  else failures.push({ key: entry.key, why: "npm exited 0 but wrote no package-lock.json" });
}

const queue = [...entries];
await Promise.all(
  Array.from({ length: Math.max(1, concurrency) }, async () => {
    for (let next = queue.pop(); next; next = queue.pop()) await build(next);
  }),
);

console.log(`SecBench lockfile tree — ${SECBENCH_REPO} @ ${SECBENCH_PIN.slice(0, 10)} → ${workRoot}`);
console.log(`${generated}/${entries.length} lockfiles generated.`);
if (failures.length) {
  console.log(`\n${failures.length} entr${failures.length === 1 ? "y" : "ies"} produced no lockfile (named, never silently dropped):`);
  for (const f of failures.sort((a, b) => a.key.localeCompare(b.key))) console.log(`  ${f.key} — ${f.why}`);
}

const failurePct = (failures.length / entries.length) * 100;
if (failurePct > maxFailurePct) {
  console.error(
    `\n✗ ${failurePct.toFixed(1)}% of entries produced no lockfile, over the ${maxFailurePct}% ceiling.\n` +
      `  A missing lockfile REMOVES that entry from the recall denominator, so a registry outage does not\n` +
      `  lower the score — it raises it. Refusing to hand a hollowed-out tree to the scorer (#879).`,
  );
  process.exit(1);
}
console.log(`\n✓ tree usable: ${failurePct.toFixed(1)}% failures, under the ${maxFailurePct}% ceiling.`);
