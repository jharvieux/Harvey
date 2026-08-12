import "./sync-stdio.js";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import {
  assertCorpusMechanicalExternalState,
  buildCorpusMechanicalParityBaseline,
  compareCorpusMechanicalParity,
  formatCorpusMechanicalParityDifference,
  mechanicalMigrationReplayArtifact,
  mechanicalFindingsFromCorpusArtifact,
  replayParityProvenance,
  serializeCorpusMechanicalParityBaseline,
  type CorpusMechanicalParityBaseline,
} from "../corpus-mechanical-parity.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";

const flag = (name: string): string | undefined => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
};

const currentPath = flag("--current");
if (!currentPath) throw new Error("usage: validate-corpus-mechanical-parity --current <corpus-drift-or-registry-replay.json> [--baseline <baseline.json> | --base <manual-replay.json> --baseline-out <baseline.json>]");
const currentBytes = readFileSync(currentPath);
const current = JSON.parse(currentBytes.toString("utf8")) as unknown;
const baselineOut = flag("--baseline-out");
if (baselineOut) {
  const basePath = flag("--base");
  if (!basePath) throw new Error("--baseline-out requires --base with a manual replay artifact");
  const expectedTargets = EXTERNAL_CORPUS.map((target) => target.slug);
  const baseBytes = readFileSync(basePath);
  const base = mechanicalMigrationReplayArtifact(JSON.parse(baseBytes.toString("utf8")), basePath, expectedTargets);
  const migration = mechanicalMigrationReplayArtifact(current, currentPath, expectedTargets);
  const sha256 = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");
  const provenance = replayParityProvenance(base, migration, { base: sha256(baseBytes), migration: sha256(currentBytes) });
  const generated = buildCorpusMechanicalParityBaseline(provenance, base.mechanicalFindings);
  const migrationDifferences = compareCorpusMechanicalParity(generated, migration.mechanicalFindings);
  for (const difference of migrationDifferences) console.error(formatCorpusMechanicalParityDifference(difference));
  if (migrationDifferences.length > 0) {
    console.error(`CORPUS MECHANICAL MIGRATION PARITY FAIL — ${migrationDifferences.length} added/removed/moved/modified row event(s); baseline not written`);
    process.exit(1);
  }
  writeFileSync(baselineOut, serializeCorpusMechanicalParityBaseline(generated));
  console.log(`CORPUS MECHANICAL MIGRATION PARITY PASS + BASELINE WRITTEN — ${generated.targetCount} target(s), ${generated.mechanicalRowCount} digest-only runMechanicalScanDetailed row(s), aggregate sha256:${generated.aggregateDigest}`);
  process.exit(0);
}
const currentFindings = mechanicalFindingsFromCorpusArtifact(current as { mechanicalPopulation?: unknown; mechanicalFindings?: unknown }, currentPath);
const baselinePath = flag("--baseline") ?? new URL("../scan/__fixtures__/mechanical-registry-corpus-parity.json", import.meta.url).pathname;
const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as CorpusMechanicalParityBaseline;
assertCorpusMechanicalExternalState(baseline, (current as { mechanicalExternalState?: unknown }).mechanicalExternalState, currentPath);
const differences = compareCorpusMechanicalParity(baseline, currentFindings);
for (const difference of differences) console.error(formatCorpusMechanicalParityDifference(difference));
if (differences.length > 0) {
  console.error(`CORPUS MECHANICAL PARITY FAIL — ${differences.length} added/removed/moved/modified row event(s)`);
  process.exit(1);
}
console.log(`CORPUS MECHANICAL PARITY PASS — ${Object.keys(baseline.targets).length} pinned target(s), every mechanical row read in order; manual ${baseline.base.engineCommit}${baseline.base.engineAmendmentPatchSha256 ? ` + patch sha256:${baseline.base.engineAmendmentPatchSha256}` : ""}, registry ${baseline.migration.engineCommit}${baseline.migration.engineAmendmentPatchSha256 ? ` + patch sha256:${baseline.migration.engineAmendmentPatchSha256}` : ""}`);
