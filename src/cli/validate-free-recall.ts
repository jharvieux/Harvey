// FREE (mechanical, source-only) recall against the five independent answer keys (#1185).
// The sibling of validate-semantic.ts: same targets, same keys, the OTHER tier.
//
//   pnpm exec tsx src/cli/validate-free-recall.ts --clones-dir <dir> [--json] [--only <slug>]
//   pnpm exec tsx src/cli/validate-free-recall.ts --corpus     # print the answer keys only
//   pnpm exec tsx src/cli/validate-free-recall.ts --clone-into <dir>   # fetch the five targets
//
// <dir> holds ONE clone per target, named by slug. `--clone-into` produces exactly that layout;
// it is a separate flag because cloning five external repos is a network operation and this tool
// must be runnable against an existing checkout offline.
//
// THE MECHANICAL TIER, as run here: `quick-scan --findings-out` + `detect-static --out`, merged.
// That is the free tier as a client gets it. `pii-classify --schema` is NOT invoked separately —
// quick-scan already runs classifyMigrationSql over the same migrations (src/cli/quick-scan.ts's
// classifySchema) and feeds it to the scorecard and the cross-signal RLS findings, so a separate
// invocation would double-count the same input. It emits a data map, not Finding[], so it could not
// score against an answer key on its own.
//
// Exit 1 when a free-count finding lands on a recorded non-vulnerability, or when NOTHING could be
// scored. A LOW recall is the measurement, not a failure — see docs/design/free-tier-recall-measurement.md.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Finding } from "../findings.js";
import {
  FREE_RECALL_CORPUS,
  scoreFreeRecall,
  summarizeFreeRecall,
  unscoredFreeTarget,
  type FreeRecallResult,
  type FreeRecallTarget,
} from "../scan/free-recall-corpus.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const repoRoot = join(import.meta.dirname, "..", "..");

if (args.includes("--corpus")) {
  for (const t of FREE_RECALL_CORPUS) {
    const pos = t.entries.filter((e) => e.kind === "positive").length;
    console.log(`\n${t.slug} — ${t.repo}@${t.ref}${t.scope ? `/${t.scope}` : ""}  (${pos} positives, ${t.entries.length - pos} negatives)`);
    console.log(`  key: ${t.source}; mechanical tally recorded ${t.recordedMechanical}/${pos} on ${t.recordedMechanicalOn} — HAND-scored, a claim about the past`);
    for (const e of t.entries) console.log(`  ${e.kind === "positive" ? "POS" : "NEG"}  ${e.id.padEnd(7)} ${e.cls}`);
  }
  process.exit(0);
}

const cloneInto = flag("--clone-into");
if (cloneInto) {
  const dir = resolve(cloneInto);
  mkdirSync(dir, { recursive: true });
  // A failed clone is REPORTED and the loop continues, rather than aborting the fetch. These are
  // five third-party repos: one of them being renamed, made private or deleted is an ordinary
  // event, and it must cost that target's row (scoreOne then records it NOT SCORED with the reason)
  // rather than the whole measurement.
  let cloned = 0;
  for (const t of FREE_RECALL_CORPUS) {
    const dest = join(dir, t.slug);
    if (existsSync(dest)) {
      console.log(`${t.slug}: already present at ${dest} — left alone`);
      cloned++;
      continue;
    }
    try {
      execFileSync("git", ["clone", "--quiet", "--branch", t.ref, `https://github.com/${t.repo}.git`, dest], { stdio: "pipe" });
    } catch (e) {
      console.error(`${t.slug}: CLONE FAILED for ${t.repo}@${t.ref} — ${e instanceof Error ? e.message.split("\n").slice(-2).join(" ") : String(e)}`);
      continue;
    }
    cloned++;
    const head = execFileSync("git", ["-C", dest, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    console.log(`${t.slug}: ${t.repo}@${t.ref} = ${head}`);
  }
  if (cloned === 0) {
    console.error(`\nFAIL: not one of the ${FREE_RECALL_CORPUS.length} answer-keyed targets could be fetched. Scoring nothing must not exit 0.`);
    process.exit(1);
  }
  process.exit(0);
}

const clonesDir = flag("--clones-dir");
if (!clonesDir) {
  console.error("usage: validate-free-recall.ts --clones-dir <dir> [--json] [--only <slug>] | --corpus | --clone-into <dir>");
  process.exit(2);
}
const only = flag("--only");

// Runs the free mechanical tier over one clone and returns its raw Finding[]. Throws on a scan
// failure — a target whose scan crashed must not be scored as "caught nothing".
function runMechanicalTier(dir: string): Finding[] {
  const out = mkdtempSync(join(tmpdir(), "harvey-free-recall-"));
  try {
    const quick = join(out, "quick.json");
    execFileSync("pnpm", ["exec", "tsx", "src/cli/quick-scan.ts", "--dir", dir, "--findings-out", quick], { cwd: repoRoot, stdio: "pipe", maxBuffer: 64 * 1024 * 1024 });
    const staticOut = join(out, "static.json");
    execFileSync("pnpm", ["exec", "tsx", "src/cli/static-detect.ts", dir, "--out", staticOut], { cwd: repoRoot, stdio: "pipe", maxBuffer: 64 * 1024 * 1024 });
    const read = (p: string): Finding[] => (existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as Finding[]) : []);
    return [...read(quick), ...read(staticOut)];
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}

function scoreOne(target: FreeRecallTarget): FreeRecallResult {
  const clone = join(resolve(clonesDir!), target.slug);
  if (!existsSync(clone)) {
    return unscoredFreeTarget(
      target,
      `no clone at ${clone} — the mechanical tier was never run against this target. Fetch it with: ` +
        `git clone --branch ${target.ref} https://github.com/${target.repo}.git ${clone}`,
    );
  }
  const scanDir = target.scope ? join(clone, target.scope) : clone;
  if (!existsSync(scanDir)) {
    return unscoredFreeTarget(target, `${clone} exists but its answer-key scope "${target.scope}" is missing — the clone does not match the key (upstream may have restructured)`);
  }
  let findings: Finding[];
  try {
    findings = runMechanicalTier(scanDir);
  } catch (e) {
    return unscoredFreeTarget(target, `the mechanical scan of ${scanDir} FAILED: ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`);
  }
  // A scan that read nothing reports zero exactly like a scan that read everything and missed
  // everything. Refuse to score it (CLAUDE.md, the third OWASP-corpus rule).
  if (findings.length === 0) {
    return unscoredFreeTarget(target, `the mechanical scan of ${scanDir} produced ZERO findings of any kind — that is a scan that read nothing, not a recall of 0. Check the clone is git-tracked and non-empty.`);
  }
  return scoreFreeRecall(target, findings);
}

const targets = FREE_RECALL_CORPUS.filter((t) => !only || t.slug === only);
if (targets.length === 0) {
  console.error(`--only ${only}: no such target. Known: ${FREE_RECALL_CORPUS.map((t) => t.slug).join(", ")}`);
  process.exit(2);
}

const results = targets.map(scoreOne);
const matrix = summarizeFreeRecall(results);

if (args.includes("--json")) {
  console.log(JSON.stringify({ generatedAt: new Date().toISOString(), ...matrix }, null, 2));
} else {
  console.log("\nFREE (mechanical, source-only) RECALL — independent answer keys\n");
  for (const r of results) {
    console.log(`── ${r.slug} (${r.repo}) ──`);
    if (!r.scored) {
      console.log(`  NOT SCORED: ${r.reason}\n`);
      continue;
    }
    for (const row of r.rows) {
      const mark = row.kind === "positive" ? (row.tier === "high" ? "HIGH " : row.tier === "review" ? "rev  " : "MISS ") : row.tier === "high" ? "FP!  " : "ok   ";
      console.log(`  ${mark} ${row.id.padEnd(7)} ${row.cls}`);
      console.log(`         ${row.detail}${row.taxonomies.length ? ` [${row.taxonomies.slice(0, 3).join("; ")}]` : ""}`);
    }
    console.log(
      `  → ${r.caughtHigh}/${r.positivesTotal} at the FREE-COUNT (high) tier; ${r.caughtAnyTier}/${r.positivesTotal} surfaced at ANY tier. ` +
        `Negatives cleared ${r.negativesCleared}/${r.negativesTotal}. ${r.findingsScanned} raw findings scanned, ${r.sharedFindings} covering >1 entry.`,
    );
    console.log(`  → recorded ${r.recordedMechanical}/${r.positivesTotal} on ${r.recordedMechanicalOn} (${r.source}, HAND-scored — a different instrument, not a like-for-like delta)\n`);
  }
  console.log(
    `TOTAL over ${matrix.scoredTargets} scored target(s): ${matrix.caughtHigh}/${matrix.positivesTotal} free-count, ` +
      `${matrix.caughtAnyTier}/${matrix.positivesTotal} any-tier; negatives cleared ${matrix.negativesCleared}/${matrix.negativesTotal}.`,
  );
  if (matrix.unscoredTargets > 0) console.log(`${matrix.unscoredTargets} target(s) NOT SCORED — their positives are excluded from the denominator above, with the reason printed per target.`);
  console.log(
    "\nThis total is a blended number and hides the skew: the per-target column is the honest form " +
      "(free-tier-recall-measurement.md §2). A low recall here is the measurement, not a failure.",
  );
}

if (!matrix.ok) {
  const fps = results.flatMap((r) => r.negativesFalsePositiveHigh.map((id) => `${r.slug}/${id}`));
  console.error(
    `\nFAIL: ${matrix.scoredTargets === 0 ? "nothing could be scored — an unrun measurement must not exit 0" : `free-count false positive(s) on recorded non-vulnerabilities: ${fps.join(", ")}`}`,
  );
  process.exit(1);
}
