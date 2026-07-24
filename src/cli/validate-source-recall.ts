// App-layer SOURCE-DETECTOR recall gate (#945). Runs the REAL mechanical scan (semgrep + the AST
// detectors — the same runMechanicalScan validate-calibration uses) against targets/calibration and
// scores it against the REQUEST→SINK source-detector answer key (src/scan/source-recall.ts), producing
// the free-tier source-detection recall number #868 needs.
//
//   pnpm exec tsx src/cli/validate-source-recall.ts            # scan targets/calibration, score source tier
//   pnpm exec tsx src/cli/validate-source-recall.ts --dir <p>  # score another labeled corpus
//   pnpm exec tsx src/cli/validate-source-recall.ts --json     # emit the raw matrix as JSON
//
// This number is REPORTED DISTINCTLY (never blended) from the SecBench/SCA number (0 there by
// construction) and the M1 MIXED-corpus number (validate-calibration, ~198/201). Exit 1 (gate FAIL)
// on: the answer key not resolving, any FREE-COUNT false positive on a source-tier negative, or any
// high-expected source positive no longer caught at high. Review-tier recall gaps are the MEASUREMENT
// (reported, non-fatal) — a low recall is a real number to publish, not a gate failure.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { formatMetrics } from "../scan/detection-metrics.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import { scoreSourceRecall, sourceTierCorpus } from "../scan/source-recall.js";
import { recallPct } from "../scan/secbench.js";
import type { MatrixRow } from "../scan/calibration.js";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
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
