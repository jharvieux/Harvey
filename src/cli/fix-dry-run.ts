// Dry-run the fix-implementation intake: screen the client-approved subset of a
// findings doc against an engagement manifest and print what *would* happen.
// Zero worktrees, zero pushes — the mandatory first run of every engagement (§3.1 rule 5).
//
//   pnpm exec tsx src/cli/fix-dry-run.ts <findings.json> <manifest.json>

import { readFileSync } from "node:fs";
import { validateFindings, type FindingsDocument } from "../findings.js";
import { intake, type EngagementManifest, type ScreenedFinding } from "../fix/pipeline.js";

const [findingsPath, manifestPath] = process.argv.slice(2);
if (!findingsPath || !manifestPath) {
  console.error("usage: pnpm exec tsx src/cli/fix-dry-run.ts <findings.json> <manifest.json>");
  process.exit(2);
}

const doc = JSON.parse(readFileSync(findingsPath, "utf8")) as FindingsDocument;
const { ok, errors } = validateFindings(doc);
if (!ok) {
  console.error(`✗ ${findingsPath} is not a valid findings document:`);
  for (const e of errors) console.error(`  ${e}`);
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as EngagementManifest;
const result = intake(doc, manifest);

const line = (e: ScreenedFinding) =>
  `  ${e.finding.id}  [${e.screen.tier}]  ${e.finding.severity}/${e.finding.category}  — ${e.finding.title}` +
  (e.screen.reason ? `\n      ↳ ${e.screen.reason}` : "");

console.log(`Fix dry-run — ${manifest.client} @ ${manifest.baselineCommit}`);
if (!result.baselineMatches) {
  console.log(`⚠ baseline mismatch: findings meta.commit=${doc.meta.commit} ≠ manifest.baselineCommit — re-baseline before running`);
}
console.log(`\nAUTO (${result.auto.length}) — enter the automated worktree path:`);
result.auto.forEach((e) => console.log(line(e)));
console.log(`\nMANUAL (${result.manual.length}) — plan drafted for operator, no subagent writes code:`);
result.manual.forEach((e) => console.log(line(e)));
console.log(`\nRECOMMEND-ONLY (${result.recommendOnly.length}) — recommendation in the report, no PR:`);
result.recommendOnly.forEach((e) => console.log(line(e)));

if (result.notApproved.length) {
  console.log(`\nNot client-approved (skipped): ${result.notApproved.join(", ")}`);
}
if (result.unknownApprovedIds.length) {
  console.log(`\n⚠ approved ids absent from findings doc: ${result.unknownApprovedIds.join(", ")}`);
}
console.log(`\nNo worktrees created, no branches pushed, no PRs opened (dry run).`);
