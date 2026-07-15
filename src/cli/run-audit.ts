// The full-audit runner (#229) — runs all ten modules against a target and DERIVES the coverage
// ledger from what actually executed.
//
//   pnpm exec tsx src/cli/run-audit.ts <target-dir> [--connected] [--dynamic] [--llm] [--out coverage.json]
//
// (No `pnpm run-audit` alias yet — adding one edits package.json, which is operator-owned.)
//
// The tier flags declare which environments the engagement HAS, not which modules to run: every
// module is always attempted, and a module whose environment is absent is recorded
// requires-live-run with that reason. There is no flag that skips a module — that is the point.
//
// Contrast with `pnpm audit-coverage --coverage <file>`, which gates a ledger a human wrote by
// hand: it enforces bookkeeping discipline, but cannot detect that you skipped M5. This command
// needs no such trust — every row is a probe's return value.
//
// Exit 1 on any coverage gap, never-run module, or crashed runner.

import { execFileSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { assertAuditComplete, AUDIT_MODULES, buildAuditCoverage, type EngagementEnv, formatAuditCoverage } from "../audit-coverage.js";
import { EXECUTION_LOG_PATH, readExecutionLog, recordExecutions } from "../audit-execution-log.js";
import { formatFailures, runAudit, type RunContext } from "../audit-runner.js";
import { AUDIT_RUNNERS } from "../audit-runners.js";

const args = process.argv.slice(2);
const targetArg = args.find((a) => !a.startsWith("--"));
const outIdx = args.indexOf("--out");
const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;

if (!targetArg) {
  console.error("usage: pnpm exec tsx src/cli/run-audit.ts <target-dir> [--connected] [--dynamic] [--llm] [--out coverage.json]");
  process.exit(2);
}

const targetDir = resolve(targetArg);
const env: EngagementEnv = {
  connected: args.includes("--connected"),
  dynamic: args.includes("--dynamic"),
  llm: args.includes("--llm"),
};

const ctx: RunContext = {
  targetDir,
  env,
  exec: (command, argv) => {
    try {
      const output = execFileSync(command, argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      return { ok: true, output };
    } catch (err) {
      // A tool that exits non-zero or is not installed is a real outcome the probe must judge, not
      // an orchestrator crash — hand it back and let the module's probe describe it.
      const e = err as { stdout?: string; stderr?: string; message?: string };
      return { ok: false, output: e.stderr || e.stdout || e.message || "" };
    }
  },
  exists: existsSync,
};

console.log(`\nFull audit — ${targetDir}`);
console.log(`Tiers in scope: source${env.connected ? " + connected" : ""}${env.dynamic ? " + dynamic" : ""}${env.llm ? " + llm" : ""}\n`);

const { recorded, failures } = runAudit(AUDIT_RUNNERS, ctx);
const report = buildAuditCoverage(recorded, env);

console.log(formatAuditCoverage(report));
if (outPath) {
  writeFileSync(outPath, JSON.stringify(recorded, null, 2));
  console.log(`\nDerived coverage ledger → ${outPath}`);
}

// #284: the never-run ledger is the complement of this log, so a module that genuinely ran here
// clears its never-run alarm by BANKING THE EVIDENCE — no one edits a Set by hand. Only a full
// `ran` counts: a partial produced real output but not the module's whole scope, and the claim the
// ledger makes is that the module has proven itself end to end at least once.
//
// Written with --record so a dry run can't quietly retire an alarm; the diff is reviewed like any
// other claim about what happened.
if (args.includes("--record")) {
  const ranModules = AUDIT_MODULES.filter((m) => recorded.find((r) => r.module === m)?.status === "ran");
  const updated = recordExecutions(AUDIT_MODULES, readExecutionLog(), ranModules, targetDir, new Date().toISOString().slice(0, 10), `pnpm exec tsx src/cli/run-audit.ts ${targetDir}`);
  writeFileSync(EXECUTION_LOG_PATH, `${JSON.stringify(updated, null, 2)}\n`);
  console.log(`\nExecution log updated → ${EXECUTION_LOG_PATH} (commit it: it is the evidence behind MODULES_NEVER_EXECUTED)`);
}

if (failures.length) {
  console.error(`\n${formatFailures(failures)}`);
  process.exit(1);
}

try {
  assertAuditComplete(recorded, env);
} catch (err) {
  console.error(`\n${(err as Error).message}`);
  process.exit(1);
}
console.log("\nCOVERAGE PASS — all ten modules accounted for, derived from actual execution.");
