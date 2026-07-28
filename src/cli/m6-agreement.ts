// M6 two-reviewer agreement CLI (#813).
//
//   pnpm exec tsx src/cli/m6-agreement.ts <passA.verdict.json> <passB.verdict.json>
//       [--target <audited-dir> --artifacts-dir <dir>]
//
// Each input is the machine-readable verdict block a reviewer emits at the end of a
// `pnpm simplify-scan` packet pass (the packet's "Verdict format" section is the schema).
// Prints the agreement report: unanimous flags go to human triage, unanimous spares are
// spared, and splits go to a human adjudicator with both reviewers' arguments. Recorded
// baselines live in docs/design/m6-eval-runs/. Thin untested I/O wrapper per the repo
// convention — src/m6-agreement.ts holds the tested logic.
//
// --target/--artifacts-dir (#1364): writes M6.pass.json from the unanimous-flag verdicts (the #416
// durable-artifact convention) — the verdict-recording step #351 said M6's `ran` status needs,
// mirroring the manual `record-pass --pass verdict` path #283's first real-target verdict used
// (docs/design/m6-first-real-target-verdict.md). Splits are never included — they still need the
// human adjudicator this report already sends them to.

import { readFileSync } from "node:fs";
import { writePassArtifact } from "../audit-pass-artifact.js";
import { buildM6PassArtifact, compareReviewerPasses, parseReviewerPass, renderAgreementReport } from "../m6-agreement.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const [pathA, pathB] = args.filter((a) => !a.startsWith("--"));
if (!pathA || !pathB) {
  console.error("usage: pnpm exec tsx src/cli/m6-agreement.ts <passA.verdict.json> <passB.verdict.json> [--target <audited-dir> --artifacts-dir <dir>]");
  process.exit(2);
}

const target = flag("--target");
const artifactsDirPath = flag("--artifacts-dir");
if ((target && !artifactsDirPath) || (!target && artifactsDirPath)) {
  console.error("--target and --artifacts-dir must be given together — a pass artifact needs both the audited target and where to write it");
  process.exit(2);
}

const passA = parseReviewerPass(JSON.parse(readFileSync(pathA, "utf8")), pathA);
const passB = parseReviewerPass(JSON.parse(readFileSync(pathB, "utf8")), pathB);
const report = compareReviewerPasses(passA, passB);
console.log(renderAgreementReport(report));

if (target && artifactsDirPath) {
  const artifact = buildM6PassArtifact(passA, passB, report, target, new Date().toISOString());
  const path = writePassArtifact(artifactsDirPath, artifact);
  console.log(`\nM6 pass artifact → ${path} (run-audit --artifacts-dir ${artifactsDirPath} derives M6 ran from it; ${artifact.findings?.length ?? 0} unanimous-flag finding(s) recorded)`);
}
