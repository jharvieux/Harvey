// Heuristic-detector precision gate CLI (#823; M1 tenant-scope added by #896) — the sibling of
// validate-calibration.ts for the heuristic detectors. Scores the labeled fixture corpus
// (src/scan/calibration/m1-tenant-scope.entries.ts + m7-code.entries.ts + m8-intent.entries.ts)
// against the LIVE detectors and reports per-module corpus precision/recall. Pure TS — needs none
// of the mechanical binaries, so it runs anywhere:
//
//   pnpm exec tsx src/cli/validate-precision.ts          # human-readable matrix
//   pnpm exec tsx src/cli/validate-precision.ts --json   # raw matrix as JSON
//
// Exit code: 1 if any planted positive is missed or any benign negative fires.

import "./sync-stdio.js";
import { formatMetrics } from "../scan/detection-metrics.js";
import { measureHeuristicPrecision, type HeuristicRow } from "../scan/heuristic-precision.js";

const matrix = measureHeuristicPrecision();

if (process.argv.includes("--json")) {
  console.log(JSON.stringify(matrix, null, 2));
  process.exit(matrix.ok ? 0 : 1);
}

const pct = (n: number): string => `${(n * 100).toFixed(1)}%`;
const line = (r: HeuristicRow): string => `  ${r.pass ? "PASS" : "FAIL"}  ${r.id.padEnd(26)} ${r.detail}`;

for (const m of matrix.modules) {
  const rows = matrix.rows.filter((r) => r.module === m.module);
  console.log(`\n${m.module} heuristic corpus — POSITIVES (planted classes, must fire):`);
  for (const r of rows.filter((r) => r.kind === "positive")) console.log(line(r));
  console.log(`${m.module} heuristic corpus — NEGATIVES (benign lookalikes, must stay silent):`);
  for (const r of rows.filter((r) => r.kind === "negative")) console.log(line(r));
  console.log(
    `${m.module}: recall ${m.positivesCaught}/${m.positivesTotal} (${pct(m.recall)}), ` +
      `negatives cleared ${m.negativesCleared}/${m.negativesTotal}, corpus precision ${pct(m.precision)}`,
  );
  // #881: the same counts in the OWASP Benchmark vocabulary, per module — never summed across
  // modules, because an M7+M8 blend would say nothing about either.
  console.log(`${m.module}: ${formatMetrics(m.metrics)}`);
}

console.log(
  "\nCorpus numbers, not field numbers: one planted instance per class, one lookalike per catalogued FP shape " +
    "(M7/M8: docs/m7-performance.md §2a) — 'precision' means no catalogued noise shape fires.",
);
console.log(
  "M1's negatives are the exception worth naming: they are distilled from three MIT libraries whose purpose IS correct " +
    "tenant scoping (docs/design/m1-tenant-scope-precision.md), so they test idioms we did not write and did not expect.",
);

if (!matrix.ok) {
  const failed = matrix.rows.filter((r) => !r.pass);
  console.log(`\nGATE FAIL — ${failed.length} row(s): ${failed.map((r) => r.id).join(", ")}`);
  process.exit(1);
}
console.log("\nGATE PASS — every planted class caught, every catalogued FP shape silent.");
