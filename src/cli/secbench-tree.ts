// pnpm secbench-tree --dir <secbench-checkout> --out <work-tree> [--mode lockfile|source]
//                    [--concurrency 8] [--max-failure-pct 5]
//
// Builds the input tree `validate-secbench.ts` needs. Two modes, one layout
// (`<out>/<class>/<slug>/`), because the two pathways score different things:
//
//   --mode lockfile (default, #879) — writes each entry's pinned dependencies as a package.json and
//     runs `npm install --package-lock-only`, so osv-scanner has something to read. Feeds
//     `--lockfile-tree`, which scores the SCA pathway.
//   --mode source (#1275) — the same package.json, but a REAL `npm install`, so the vulnerable
//     package's own source lands at `<out>/<class>/<slug>/node_modules/<pkg>`. Feeds
//     `--library-source-tree`, which scores the library-internal parameter-sourced taint pathway
//     (#946). This existed only as prose — "a heavy, network-bound npm install per entry, run OUT
//     of this process" — so the 154/296 figure in the measurement doc had no command behind it and
//     the corpus's own denominator question could not be re-asked. #1275 is that question.
//
// This existed only as a paragraph of prose in docs/design/secbench-recall-measurement.md, executed
// by hand on the three occasions the gate has ever been scored. #1288 puts the gate on a monthly
// cadence, and a cadence needs a command rather than a paragraph.
//
// THE DENOMINATOR TRAP, which is why this fails loud rather than reporting what it managed. An
// entry whose lockfile is absent is EXCLUDED from the recall denominator by scoreSecbench — that is
// correct for the handful of packages npm no longer resolves, and catastrophic for a registry
// outage: 300 failed installs would not lower the score, they would RAISE it, by deleting 300
// chances to miss. So a failure rate past --max-failure-pct aborts before anything is scored. The
// trap is identical in source mode: a missing node_modules/<pkg> drops that entry out of
// scoreLibrarySource's `scanned` set the same way.

import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readNamesSafe } from "../fs-walk.js";
import { promisify } from "node:util";
import { arg, assertKnownFlags } from "./args.js";
import { SECBENCH_PIN, SECBENCH_REPO, loadSecbenchCorpus } from "../scan/secbench.js";

const FLAGS = ["--dir", "--target", "--out", "--mode", "--concurrency", "--max-failure-pct", "--print-pin"] as const;
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
    `Usage: secbench-tree --dir <secbench-checkout> --out <work-tree> [--mode lockfile|source] [--concurrency 8] [--max-failure-pct 5]\n` +
      `  git clone https://github.com/${SECBENCH_REPO} && git -C SecBench.js checkout ${SECBENCH_PIN}`,
  );
  process.exit(2);
}
const mode = arg("--mode") ?? "lockfile";
if (mode !== "lockfile" && mode !== "source") {
  console.error(`--mode ${mode}: expected "lockfile" (SCA input, --lockfile-tree) or "source" (library-taint input, --library-source-tree).`);
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
  // `--ignore-scripts` in source mode: this installs 600 arbitrary, deliberately-vulnerable npm
  // packages, and a postinstall script from one of them is code we did not choose to run. Nothing
  // is executed afterwards either — semgrep reads the source as text.
  const npmArgs = mode === "lockfile" ? ["install", "--package-lock-only", "--no-audit", "--no-fund"] : ["install", "--ignore-scripts", "--no-audit", "--no-fund"];
  try {
    await run("npm", npmArgs, { cwd: entryDir, timeout: mode === "lockfile" ? 120_000 : 300_000 });
  } catch (err) {
    failures.push({ key: entry.key, why: String((err as { stderr?: string }).stderr ?? err).split("\n").filter((l) => l.includes("npm error") || l.includes("code E")).slice(0, 2).join(" ").slice(0, 160) });
    return;
  }
  // In source mode the artefact that matters is the TARGET PACKAGE's own source at the path
  // validate-secbench scopes semgrep to. A successful install that landed everything except that
  // directory scores as "scanned, no hit" — a silent false miss — so it is a failure here instead.
  if (mode === "source") {
    if (!entry.pkg) {
      failures.push({ key: entry.key, why: "multi-dependency entry — no single target package for the scanner to scope to" });
      return;
    }
    if (existsSync(join(entryDir, "node_modules", ...entry.pkg.split("/")))) generated += 1;
    else failures.push({ key: entry.key, why: `npm exited 0 but node_modules/${entry.pkg} is absent` });
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

const artefact = mode === "lockfile" ? "lockfile" : "installed target-package source";
console.log(`SecBench ${mode} tree — ${SECBENCH_REPO} @ ${SECBENCH_PIN.slice(0, 10)} → ${workRoot}`);
console.log(`${generated}/${entries.length} ${artefact}s built.`);
if (failures.length) {
  console.log(`\n${failures.length} entr${failures.length === 1 ? "y" : "ies"} produced no ${artefact} (named, never silently dropped):`);
  for (const f of failures.sort((a, b) => a.key.localeCompare(b.key))) console.log(`  ${f.key} — ${f.why}`);
}

const failurePct = (failures.length / entries.length) * 100;
if (failurePct > maxFailurePct) {
  console.error(
    `\n✗ ${failurePct.toFixed(1)}% of entries produced no ${artefact}, over the ${maxFailurePct}% ceiling.\n` +
      `  A missing ${artefact} REMOVES that entry from the recall denominator, so a registry outage does not\n` +
      `  lower the score — it raises it. Refusing to hand a hollowed-out tree to the scorer (#879).`,
  );
  process.exit(1);
}
console.log(`\n✓ tree usable: ${failurePct.toFixed(1)}% failures, under the ${maxFailurePct}% ceiling.`);
