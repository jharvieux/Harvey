import "./sync-stdio.js";
import { writeFileSync } from "node:fs";
import { inspectCorpusAdvisoryFreshness } from "../corpus-advisory-freshness.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";

const args = process.argv.slice(2);
const outAt = args.indexOf("--out");
const out = outAt < 0 ? undefined : args[outAt + 1];
if (outAt >= 0 && (!out || out.startsWith("--"))) throw new Error("--out needs a file path");
const runHours = 6;
const warningHours = 72;
const receipt = inspectCorpusAdvisoryFreshness(EXTERNAL_CORPUS, {
  now: new Date(),
  runDurationMs: runHours * 60 * 60 * 1_000,
  warningLeadMs: warningHours * 60 * 60 * 1_000,
});
if (out) writeFileSync(out, `${JSON.stringify(receipt, null, 2)}\n`);
for (const row of receipt.rows) {
  const message = `${row.slug}: ${row.status}; ${row.reason}${row.capturedAt ? `; captured=${row.capturedAt}` : ""}${row.expiresAt ? `; expires=${row.expiresAt}` : ""}${row.sha256 ? `; sha256=${row.sha256}` : ""}`;
  if (row.status === "current") console.log(message);
  else if (row.status === "warning") console.warn(`::warning::${message}`);
  else console.error(`::error::${message}`);
}
console.log(`CORPUS ADVISORY FRESHNESS: ${receipt.rows.length}/${receipt.expectedCount} rows; required-through=${receipt.requiredThrough}; warning-through=${receipt.warningThrough}; ready=${receipt.readyForRun}`);
if (!receipt.readyForRun || (args.includes("--fail-warning") && receipt.warning)) process.exitCode = 1;
