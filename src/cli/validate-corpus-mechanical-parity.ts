import "./sync-stdio.js";
import { readFileSync, writeFileSync } from "node:fs";
import type { Finding } from "../findings.js";
import {
  buildCorpusMechanicalParityBaseline,
  compareCorpusMechanicalParity,
  formatCorpusMechanicalParityDifference,
  serializeCorpusMechanicalParityBaseline,
  type CorpusMechanicalParityBaseline,
} from "../corpus-mechanical-parity.js";

const flag = (name: string): string | undefined => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
};

const currentPath = flag("--current");
if (!currentPath) throw new Error("usage: validate-corpus-mechanical-parity --current <corpus-drift.json> [--baseline <baseline.json> | --baseline-out <baseline.json> --base-commit <sha> --base-run <id> --migration-head <sha> --migration-run <id>]");
const current = JSON.parse(readFileSync(currentPath, "utf8")) as { findings?: Record<string, Finding[]> };
if (!current.findings) throw new Error(`${currentPath}: corpus scorecard has no findings population`);
const baselineOut = flag("--baseline-out");
if (baselineOut) {
  const baseCommit = flag("--base-commit");
  const baseRun = Number(flag("--base-run"));
  const migrationHead = flag("--migration-head");
  const migrationRun = Number(flag("--migration-run"));
  if (!baseCommit || !migrationHead || !Number.isSafeInteger(baseRun) || !Number.isSafeInteger(migrationRun)) throw new Error("--baseline-out requires --base-commit, --base-run, --migration-head, and --migration-run");
  const generated = buildCorpusMechanicalParityBaseline({ baseCommit, baseRun, migrationHead, migrationRun }, current.findings);
  writeFileSync(baselineOut, serializeCorpusMechanicalParityBaseline(generated));
  console.log(`CORPUS MECHANICAL PARITY BASELINE WRITTEN — ${generated.targetCount} target(s), ${generated.mechanicalRowCount} digest-only mechanical row(s), aggregate sha256:${generated.aggregateDigest}`);
  process.exit(0);
}
const baselinePath = flag("--baseline") ?? new URL("../scan/__fixtures__/mechanical-registry-corpus-parity.json", import.meta.url).pathname;
const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as CorpusMechanicalParityBaseline;
const differences = compareCorpusMechanicalParity(baseline, current.findings);
for (const difference of differences) console.error(formatCorpusMechanicalParityDifference(difference));
if (differences.length > 0) {
  console.error(`CORPUS MECHANICAL PARITY FAIL — ${differences.length} added/removed/moved/modified row event(s)`);
  process.exit(1);
}
console.log(`CORPUS MECHANICAL PARITY PASS — ${Object.keys(baseline.targets).length} pinned target(s), every mechanical row read in order; base ${baseline.baseCommit} run ${baseline.baseRun}, migration ${baseline.migrationHead} run ${baseline.migrationRun}`);
