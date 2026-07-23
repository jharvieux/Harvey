// M6 two-reviewer agreement CLI (#813).
//
//   pnpm exec tsx src/cli/m6-agreement.ts <passA.verdict.json> <passB.verdict.json>
//
// Each input is the machine-readable verdict block a reviewer emits at the end of a
// `pnpm simplify-scan` packet pass (the packet's "Verdict format" section is the schema).
// Prints the agreement report: unanimous flags go to human triage, unanimous spares are
// spared, and splits go to a human adjudicator with both reviewers' arguments. Recorded
// baselines live in docs/design/m6-eval-runs/. Thin untested I/O wrapper per the repo
// convention — src/m6-agreement.ts holds the tested logic.

import { readFileSync } from "node:fs";
import { compareReviewerPasses, parseReviewerPass, renderAgreementReport } from "../m6-agreement.js";

const [pathA, pathB] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
if (!pathA || !pathB) {
  console.error("usage: pnpm exec tsx src/cli/m6-agreement.ts <passA.verdict.json> <passB.verdict.json>");
  process.exit(2);
}

const passA = parseReviewerPass(JSON.parse(readFileSync(pathA, "utf8")), pathA);
const passB = parseReviewerPass(JSON.parse(readFileSync(pathB, "utf8")), pathB);
console.log(renderAgreementReport(compareReviewerPasses(passA, passB)));
