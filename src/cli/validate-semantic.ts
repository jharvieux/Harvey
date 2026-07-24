// M1 semantic-tier recall gate CLI (#870) — the sibling of validate-calibration.ts (mechanical)
// and validate-precision.ts (M7/M8 heuristics) for the paid LLM pass.
//
//   pnpm exec tsx src/cli/validate-semantic.ts --artifacts-dir <dir>   # score the recorded passes
//   pnpm exec tsx src/cli/validate-semantic.ts --artifacts-dir <dir> --json
//   pnpm exec tsx src/cli/validate-semantic.ts --corpus                # print the answer key only
//
// <dir> holds ONE subdirectory per corpus target, each containing the `M1.pass.json` that target's
// semantic pass left (`pnpm record-pass --module M1 --pass semantic --target <clone> --findings
// <triage.json> --out <dir>/<slug>`). See docs/design/semantic-recall-gate.md for the run loop.
//
// Exit 1 when a scored target catches fewer planted findings than its recorded baseline, when the
// pass reports a recorded non-vulnerability, or when NOTHING could be scored — an unrun gate must
// not exit 0. Targets whose pass is missing/stale/wrong are printed as NOT SCORED with the reason.

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  SEMANTIC_CORPUS,
  loadSemanticPass,
  scoreSemanticPass,
  summarizeSemantic,
  unscoredTarget,
  type SemanticTargetResult,
} from "../scan/semantic-corpus.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

if (args.includes("--corpus")) {
  for (const t of SEMANTIC_CORPUS) {
    const pos = t.entries.filter((e) => e.kind === "positive").length;
    console.log(`\n${t.slug} — ${t.repo}@${t.ref}${t.scope ? `/${t.scope}` : ""}  (${pos} positives, ${t.entries.length - pos} negatives)`);
    console.log(`  key: ${t.source}; semantic tally recorded ${t.recordedCaught}/${pos} on ${t.recordedOn} — a claim about the past, re-measured by a scored run`);
    for (const e of t.entries) console.log(`  ${e.kind === "positive" ? "POS" : "NEG"}  ${e.id.padEnd(7)} ${e.cls}`);
  }
  process.exit(0);
}

const artifactsDir = flag("--artifacts-dir");
if (!artifactsDir) {
  console.error("usage: pnpm exec tsx src/cli/validate-semantic.ts --artifacts-dir <dir> [--json]");
  console.error("       pnpm exec tsx src/cli/validate-semantic.ts --corpus");
  process.exit(2);
}

const root = resolve(artifactsDir);
const now = Date.now();

const results: SemanticTargetResult[] = SEMANTIC_CORPUS.map((target) => {
  const path = join(root, target.slug, "M1.pass.json");
  let raw: unknown;
  if (existsSync(path)) {
    try {
      raw = JSON.parse(readFileSync(path, "utf8"));
    } catch (err) {
      return unscoredTarget(target, `${path} is not valid JSON (${err instanceof Error ? err.message : String(err)})`);
    }
  }
  const load = loadSemanticPass(raw, target, path, now);
  if (!load.ok) return unscoredTarget(target, load.reason);
  return scoreSemanticPass(target, load.artifact.findings ?? [], load.artifact.generatedAt);
});

const matrix = summarizeSemantic(results);

if (args.includes("--json")) {
  console.log(JSON.stringify(matrix, null, 2));
  process.exit(matrix.ok ? 0 : 1);
}

const pct = (n: number): string => `${(n * 100).toFixed(1)}%`;

console.log(`M1 SEMANTIC recall gate (#870) — answer-keyed corpus, artifacts under ${root}\n`);

for (const t of matrix.targets) {
  console.log(`${t.slug} (${t.repo}) — key ${t.source}`);
  if (!t.scored) {
    console.log(`  NOT SCORED — ${t.reason}`);
    console.log(`  ${t.positivesTotal} planted finding(s) awaiting a semantic pass; recorded ${t.recordedCaught} caught on ${t.recordedOn} (unverified until a pass is scored here).\n`);
    continue;
  }
  for (const r of t.rows) console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.id.padEnd(7)} ${r.cls} — ${r.detail}`);
  console.log(
    `  recall ${t.positivesCaught}/${t.positivesTotal} (${pct(t.recall)}) vs ${t.recordedCaught} recorded ${t.recordedOn}` +
      `${t.negativesTotal ? `; negatives cleared ${t.negativesCleared}/${t.negativesTotal}` : ""}` +
      `; pass generated ${t.generatedAt}${t.regressed ? "  REGRESSION" : ""}`,
  );
  if (t.sharedFindings) {
    console.log(`  caveat: ${t.sharedFindings} finding(s) satisfied more than one answer-key entry — location+keyword matching is generous, so this target's recall is an upper bound on distinct-finding recall.`);
  }
  console.log("");
}

console.log(
  `Scored ${matrix.scoredTargets}/${matrix.targets.length} corpus targets: ` +
    `${matrix.positivesCaught}/${matrix.positivesTotal} planted findings caught (${matrix.positivesTotal ? pct(matrix.positivesCaught / matrix.positivesTotal) : "n/a"}), ` +
    `${matrix.negativesCleared}/${matrix.negativesTotal} recorded non-vulnerabilities cleared.`,
);
console.log("This is SEMANTIC-tier recall over the scored targets only — an unscored target contributes nothing to either side of the ratio, which is why every one is listed above.");
if (matrix.negativesTotal <= 1) {
  console.log(
    `Precision caveat, stated because it would otherwise read as unmeasured-therefore-fine: the SCORED targets carry ${matrix.negativesTotal} recorded non-vulnerability between them, so semantic PRECISION is essentially ungated by this run — it measures recall.`,
  );
}

if (!matrix.ok) {
  if (matrix.scoredTargets === 0) {
    console.log("\nGATE FAIL — NOTHING SCORED. No target had a fresh, well-formed semantic pass artifact, so this run measured nothing; a gate that measured nothing is not a gate that passed.");
  }
  const regressed = matrix.targets.filter((t) => t.regressed);
  if (regressed.length) {
    console.log(`\nGATE FAIL — semantic recall below the recorded baseline on: ${regressed.map((t) => `${t.slug} (${t.positivesCaught} < ${t.recordedCaught})`).join(", ")}`);
  }
  const fps = matrix.targets.flatMap((t) => t.rows.filter((r) => r.kind === "negative" && !r.pass).map((r) => `${t.slug}/${r.id}`));
  if (fps.length) console.log(`GATE FAIL — the semantic pass reported a recorded non-vulnerability: ${fps.join(", ")}`);
  process.exit(1);
}

console.log("\nGATE PASS — every scored target met its recorded semantic baseline and reported no recorded non-vulnerability.");
