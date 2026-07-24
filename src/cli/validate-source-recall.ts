// App-layer SOURCE-DETECTOR recall gate (#945). Runs the REAL mechanical scan (semgrep + the AST
// detectors — the same runMechanicalScan validate-calibration uses) against targets/calibration and
// scores it against the REQUEST→SINK source-detector answer key (src/scan/source-recall.ts), producing
// the free-tier source-detection recall number #868 needs.
//
//   pnpm exec tsx src/cli/validate-source-recall.ts            # scan targets/calibration, score source tier
//   pnpm exec tsx src/cli/validate-source-recall.ts --dir <p>  # score another labeled corpus
//   pnpm exec tsx src/cli/validate-source-recall.ts --json     # emit the raw matrix as JSON
//   pnpm exec tsx src/cli/validate-source-recall.ts --real     # #960: real-code tier (below)
//
// This number is REPORTED DISTINCTLY (never blended) from the SecBench/SCA number (0 there by
// construction) and the M1 MIXED-corpus number (validate-calibration, ~198/201). Exit 1 (gate FAIL)
// on: the answer key not resolving, any FREE-COUNT false positive on a source-tier negative, or any
// high-expected source positive no longer caught at high. Review-tier recall gaps are the MEASUREMENT
// (reported, non-fatal) — a low recall is a real number to publish, not a gate failure.
//
// --real (#960, the remainder of #945): the planted-fixture number above is honest about its own
// "Honest scope" limit — targets/calibration is code WE wrote to teach the detectors, not real code.
// --real clones each pin in src/scan/real-source-recall.ts (already-disclosed vulnerabilities in the
// six repos external-corpus.ts pins for the quality-drift baselines, cloned ON DEMAND — several ship
// no LICENSE, the same reason external-corpus.ts never vendors their source), scans each with the
// SAME runMechanicalScan, and scores it against that repo's own entries. Like the planted gate, a
// recall gap here is the measurement, never a failure — --real always exits 0; it reports, it does
// not gate. Needs network (git clone) in addition to the mechanical binaries.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { formatMetrics } from "../scan/detection-metrics.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import { scoreSourceRecall, sourceTierCorpus } from "../scan/source-recall.js";
import { REAL_SOURCE_RECALL_TARGETS, mergeRealSourceRecall, scoreRealSourceRecallTarget } from "../scan/real-source-recall.js";
import { recallPct } from "../scan/secbench.js";
import type { CoverageMatrix, MatrixRow } from "../scan/calibration.js";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

if (process.argv.includes("--real")) {
  const git = (cloneDir: string, ...a: string[]): void => void execFileSync("git", ["-C", cloneDir, ...a], { stdio: ["ignore", "ignore", "pipe"] });
  const matrices: CoverageMatrix[] = [];
  console.log(`\nREAL-CODE source-detector recall (#960) — ${REAL_SOURCE_RECALL_TARGETS.length} pinned target(s), cloned on demand\n`);
  for (const target of REAL_SOURCE_RECALL_TARGETS) {
    const cloneDir = mkdtempSync(join(tmpdir(), `harvey-real-source-recall-${target.slug}-`));
    try {
      execFileSync("git", ["init", "-q", cloneDir], { stdio: "inherit" });
      git(cloneDir, "remote", "add", "origin", `https://github.com/${target.repo}`);
      git(cloneDir, "fetch", "-q", "--depth", "1", "origin", target.commit);
      git(cloneDir, "checkout", "-q", "FETCH_HEAD");
      const findings = await runMechanicalScan({ dir: cloneDir });
      const matrix = scoreRealSourceRecallTarget(findings, target);
      matrices.push(matrix);
      console.log(`${target.slug} (${target.repo} @ ${target.commit.slice(0, 12)}, disclosure #${target.disclosureIssue}):`);
      for (const r of matrix.rows) console.log(`  ${r.pass ? "CAUGHT" : "GAP   "}  ${r.id.padEnd(32)} ${r.detail}`);
    } finally {
      if (existsSync(cloneDir)) rmSync(cloneDir, { recursive: true, force: true });
    }
  }
  const summary = mergeRealSourceRecall(matrices);
  console.log(
    `\nREAL-CODE RECALL — ${summary.positivesCaught}/${summary.positivesTotal} disclosed request→sink vulnerabilities caught at any tier ` +
      `(${recallPct(summary.positivesCaught, summary.positivesTotal)}).` +
      `\n  Detection metrics: ${formatMetrics(summary.metrics)}` +
      `\n  DISTINCT, NOT BLENDED: this is the REAL-CODE tier only — never combine with the planted-fixture` +
      `\n  38/39 above, or any other corpus number. A gap here is a real detector limitation, named per entry` +
      `\n  above, not a gate failure — this mode always reports (exit 0), it does not fail the build.`,
  );
  process.exit(0);
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const dir = arg("--dir") ?? join(repoRoot, "targets", "calibration");

const corpus = sourceTierCorpus(); // throws loud if the answer key drifted
const findings = await runMechanicalScan({ dir });
const matrix = scoreSourceRecall(findings);

if (process.argv.includes("--json")) {
  console.log(JSON.stringify(matrix, null, 2));
  process.exit(0);
}

const mark = (r: MatrixRow): string => (r.pass ? "PASS" : "FAIL");
const line = (r: MatrixRow): string =>
  `  ${mark(r)}  ${r.id.padEnd(26)} ${(r.caughtTier ?? "-").padEnd(7)} ${r.cls}`;

console.log(`\nApp-layer source-detector recall — ${dir}`);
console.log(`Answer key: ${corpus.length} request→sink fixtures (src/scan/source-recall.ts, #945)\n`);

console.log("POSITIVES (planted request→sink vulns — recall is how many are caught at any tier):");
for (const r of matrix.rows.filter((r) => r.kind === "positive")) console.log(line(r));
console.log("\nNEGATIVES (benign request→sink lookalikes — must NOT be flagged in the free count):");
for (const r of matrix.rows.filter((r) => r.kind === "negative")) console.log(line(r));

console.log(
  `\nSOURCE-DETECTOR RECALL (app-layer, request→sink) — the free-tier source number for #868:` +
    `\n  ${matrix.positivesCaught}/${matrix.positivesTotal} positives caught at any tier (${recallPct(matrix.positivesCaught, matrix.positivesTotal)}); ` +
    `${matrix.positivesCaughtHigh}/${matrix.positivesTotal} at HIGH (free-count) tier.` +
    `\n  Negatives cleared: ${matrix.negativesCleared}/${matrix.negativesTotal}.`,
);
console.log(`  Detection metrics (OWASP Benchmark model): ${formatMetrics(matrix.metrics)}`);
console.log(
  "  DISTINCT, NOT BLENDED: this is the request→sink SOURCE-detector recall only. It is NOT the\n" +
    "  SecBench/SCA number (0/600 there — a library-CVE corpus with no request source, #879) and NOT\n" +
    "  the M1 MIXED-corpus number (validate-calibration, whose answer key adds the SCA/secret/header/\n" +
    "  crypto/config/RLS-schema tiers). Corpus + in/out rationale: docs/design/source-detector-recall.md.",
);

const negFps = matrix.rows.filter((r) => r.kind === "negative" && r.highFlagged);
const highMisses = matrix.rows.filter((r) => r.kind === "positive" && r.expectedTier === "high" && !r.highFlagged);
const reviewMisses = matrix.rows.filter((r) => r.kind === "positive" && r.expectedTier !== "high" && !r.pass);

if (reviewMisses.length) {
  console.log(`\nRecall gaps (the measurement — reported, non-fatal): ${reviewMisses.map((r) => r.id).join(", ")}`);
}

const gatePass = negFps.length === 0 && highMisses.length === 0;
if (!gatePass) {
  if (negFps.length) console.log(`\nGATE FAIL — free-count false positives on source-tier negatives: ${negFps.map((r) => r.id).join(", ")}`);
  if (highMisses.length) console.log(`GATE FAIL — high-tier source positives no longer caught at high: ${highMisses.map((r) => r.id).join(", ")}`);
  process.exit(1);
}
console.log("\nGATE PASS — no free-count false positives; every high-tier source rule fired on its positive.");
