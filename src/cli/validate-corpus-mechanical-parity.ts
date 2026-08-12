import "./sync-stdio.js";
import { readFileSync, writeFileSync } from "node:fs";
import {
  buildCorpusMechanicalParityBaseline,
  compareCorpusMechanicalParity,
  formatCorpusMechanicalParityDifference,
  mechanicalFindingsFromCorpusArtifact,
  serializeCorpusMechanicalParityBaseline,
  type CorpusMechanicalParityBaseline,
} from "../corpus-mechanical-parity.js";

const flag = (name: string): string | undefined => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
};

const currentPath = flag("--current");
if (!currentPath) throw new Error("usage: validate-corpus-mechanical-parity --current <new-corpus-drift.json> [--baseline <baseline.json> | --base <old-corpus-drift.json> --baseline-out <baseline.json> --base-commit <sha> --base-run <id> --migration-head <sha> --migration-run <id>]");
const current = JSON.parse(readFileSync(currentPath, "utf8")) as { mechanicalPopulation?: unknown; mechanicalFindings?: unknown };
const currentFindings = mechanicalFindingsFromCorpusArtifact(current, currentPath);
const baselineOut = flag("--baseline-out");
if (baselineOut) {
  const basePath = flag("--base");
  const baseCommit = flag("--base-commit");
  const baseRun = Number(flag("--base-run"));
  const migrationHead = flag("--migration-head");
  const migrationRun = Number(flag("--migration-run"));
  if (!basePath || !baseCommit || !migrationHead || !Number.isSafeInteger(baseRun) || !Number.isSafeInteger(migrationRun)) throw new Error("--baseline-out requires --base, --base-commit, --base-run, --migration-head, and --migration-run");
  const base = JSON.parse(readFileSync(basePath, "utf8")) as { mechanicalPopulation?: unknown; mechanicalFindings?: unknown };
  const baseFindings = mechanicalFindingsFromCorpusArtifact(base, basePath);
  const generated = buildCorpusMechanicalParityBaseline({ baseCommit, baseRun, migrationHead, migrationRun }, baseFindings);
  const migrationDifferences = compareCorpusMechanicalParity(generated, currentFindings);
  for (const difference of migrationDifferences) console.error(formatCorpusMechanicalParityDifference(difference));
  if (migrationDifferences.length > 0) {
    console.error(`CORPUS MECHANICAL MIGRATION PARITY FAIL — ${migrationDifferences.length} added/removed/moved/modified row event(s); baseline not written`);
    process.exit(1);
  }
  writeFileSync(baselineOut, serializeCorpusMechanicalParityBaseline(generated));
  console.log(`CORPUS MECHANICAL MIGRATION PARITY PASS + BASELINE WRITTEN — ${generated.targetCount} target(s), ${generated.mechanicalRowCount} digest-only runMechanicalScanDetailed row(s), aggregate sha256:${generated.aggregateDigest}`);
  process.exit(0);
}
const baselinePath = flag("--baseline") ?? new URL("../scan/__fixtures__/mechanical-registry-corpus-parity.json", import.meta.url).pathname;
const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as CorpusMechanicalParityBaseline;
const differences = compareCorpusMechanicalParity(baseline, currentFindings);
for (const difference of differences) console.error(formatCorpusMechanicalParityDifference(difference));
if (differences.length > 0) {
  console.error(`CORPUS MECHANICAL PARITY FAIL — ${differences.length} added/removed/moved/modified row event(s)`);
  process.exit(1);
}
console.log(`CORPUS MECHANICAL PARITY PASS — ${Object.keys(baseline.targets).length} pinned target(s), every mechanical row read in order; base ${baseline.baseCommit} run ${baseline.baseRun}, migration ${baseline.migrationHead} run ${baseline.migrationRun}`);
