// The audit-level coverage gate (issue #229) — the check that an engagement covered all ten
// modules (M1–M10), not an ad-hoc subset.
//
//   pnpm audit-coverage --coverage <file.json>   # gate a recorded engagement
//   pnpm audit-coverage --template               # print a blank ledger to fill in
//
// Exit 1 (naming the modules) if any module is neither run nor explicitly recorded
// partial/requires-live-run WITH A REASON. This is the whole-audit counterpart to
// assertComplete's per-target gate in src/pentest/targets.ts.
//
// The coverage file is a JSON array of { module, status, reason?, detail? } — one entry per
// module, recorded from what actually executed. It is deliberately caller-supplied rather than
// inferred: the ten runners are separate CLIs across three tiers with their own prereqs (see
// CLAUDE.md's module table), and a gate that GUESSED a module ran would defeat its own purpose.
// Wiring the runners themselves behind one command is the remainder of #229.

import "./sync-stdio.js";
import { readFileSync } from "node:fs";
import { assertAuditComplete, AUDIT_MODULES, buildAuditCoverage, formatAuditCoverage, MODULES, type ModuleCoverage } from "../audit-coverage.js";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

if (process.argv.includes("--template")) {
  // Every row starts as an unfilled TODO, which the gate REJECTS (see isPlaceholder) — so an
  // untouched template can never pass as an audit. Each row must be answered deliberately.
  const template: ModuleCoverage[] = AUDIT_MODULES.map((module) => ({
    module,
    status: "requires-live-run",
    reason: `TODO: run ${module} (${MODULES[module].name}) — or state why it could not run`,
  }));
  console.log(JSON.stringify(template, null, 2));
  process.exit(0);
}

const coveragePath = arg("--coverage");
if (!coveragePath) {
  console.error("usage: pnpm audit-coverage --coverage <file.json> | --template");
  process.exit(2);
}

const recorded = JSON.parse(readFileSync(coveragePath, "utf8")) as ModuleCoverage[];
const report = buildAuditCoverage(recorded);

console.log(`\nAudit module coverage — ${coveragePath}\n`);
console.log(formatAuditCoverage(report));

try {
  assertAuditComplete(recorded);
} catch (err) {
  console.error(`\n${(err as Error).message}`);
  process.exit(1);
}
console.log("\nCOVERAGE PASS — all ten modules accounted for.");
