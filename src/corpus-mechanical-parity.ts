import { createHash } from "node:crypto";
import type { Finding } from "./findings.js";

const SHA256 = /^[a-f0-9]{64}$/;
export const MECHANICAL_CORPUS_POPULATION = "runMechanicalScanDetailed.findings-v1" as const;

interface OrderedFindingRecord {
  ordinal: number;
  identityDigest: string;
  contentDigest: string;
  orderedDigest: string;
}

interface TargetParityBaseline {
  count: number;
  orderedDigest: string;
  rows: OrderedFindingRecord[];
}

export interface MechanicalReplayExternalState {
  advisorySha256: string;
  secretCandidateIdentity: string;
  semgrepRegistrySha256: string;
  networkFallbacksDisabled: true;
  bundleScanPinnedOff: true;
}

export interface MechanicalMigrationReplayArtifact {
  schema: 1;
  population: typeof MECHANICAL_CORPUS_POPULATION;
  engineCommit: string;
  orchestrator: "manual" | "registry";
  engineAmendmentPaths: string[];
  engineAmendmentPatchSha256?: string;
  harnessSha256: string;
  targetPinsSha256: string;
  advisoryManifestSha256: string;
  semgrepRegistrySha256: string;
  targetCount: number;
  targets: string[];
  externalState: Record<string, MechanicalReplayExternalState>;
  mechanicalFindings: Record<string, Finding[]>;
}

interface ReplayEngineProvenance {
  artifactSha256: string;
  engineCommit: string;
  orchestrator: "manual" | "registry";
  engineAmendmentPaths: string[];
  engineAmendmentPatchSha256?: string;
}

export interface CorpusMechanicalParityProvenance {
  replayContract: "pinned-advisories+frozen-semgrep+network-off+bundle-off";
  harnessSha256: string;
  targetPinsSha256: string;
  advisoryManifestSha256: string;
  semgrepRegistrySha256: string;
  base: ReplayEngineProvenance;
  migration: ReplayEngineProvenance;
  externalState: Record<string, MechanicalReplayExternalState>;
}

export interface CorpusMechanicalParityBaseline extends CorpusMechanicalParityProvenance {
  schema: 4;
  algorithm: "sha256";
  normalization: "finding-v3";
  population: typeof MECHANICAL_CORPUS_POPULATION;
  targetCount: number;
  mechanicalRowCount: number;
  aggregateDigest: string;
  targets: Record<string, TargetParityBaseline>;
}

function normalizeEphemeralRoots(value: string): string {
  return value.replace(/\/tmp\/harvey-[^/"\\]+/g, "<TARGET_ROOT>");
}

function digest(domain: string, ...parts: readonly string[]): string {
  const hash = createHash("sha256");
  hash.update(`${domain}\0`);
  for (const part of parts) hash.update(`${Buffer.byteLength(part, "utf8")}:${part}\0`);
  return hash.digest("hex");
}

function canonicalFinding(finding: Finding): string {
  return normalizeEphemeralRoots(JSON.stringify(finding));
}

function stableIdentity(finding: Finding): string {
  return normalizeEphemeralRoots(JSON.stringify([finding.id, finding.location]));
}

function orderedRowDigest(target: string, record: Pick<OrderedFindingRecord, "ordinal" | "identityDigest" | "contentDigest">): string {
  return digest("harvey/corpus-mechanical-parity/ordered-row/v3", target, String(record.ordinal), record.identityDigest, record.contentDigest);
}

function targetDigest(target: string, rows: readonly OrderedFindingRecord[]): string {
  return digest("harvey/corpus-mechanical-parity/target/v3", target, String(rows.length), ...rows.map((row) => row.orderedDigest));
}

function aggregateDigest(targets: Record<string, TargetParityBaseline>): string {
  const names = Object.keys(targets).sort();
  return digest("harvey/corpus-mechanical-parity/aggregate/v3", ...names.flatMap((target) => [target, String(targets[target]!.count), targets[target]!.orderedDigest]));
}

export function mechanicalFindingRecords(target: string, findings: readonly Finding[]): OrderedFindingRecord[] {
  const occurrences = new Map<string, number>();
  return findings.map((finding, ordinal) => {
    const identity = stableIdentity(finding);
    const occurrence = (occurrences.get(identity) ?? 0) + 1;
    occurrences.set(identity, occurrence);
    const identityDigest = digest("harvey/corpus-mechanical-parity/identity/v3", target, identity, String(occurrence));
    const contentDigest = digest("harvey/corpus-mechanical-parity/content/v3", target, canonicalFinding(finding));
    const record = { ordinal, identityDigest, contentDigest };
    return { ...record, orderedDigest: orderedRowDigest(target, record) };
  });
}

export function buildCorpusMechanicalParityBaseline(
  provenance: CorpusMechanicalParityProvenance,
  findings: Record<string, Finding[]>,
): CorpusMechanicalParityBaseline {
  const targets: Record<string, TargetParityBaseline> = {};
  for (const target of Object.keys(findings).sort()) {
    const rows = mechanicalFindingRecords(target, findings[target] ?? []);
    targets[target] = { count: rows.length, orderedDigest: targetDigest(target, rows), rows };
  }
  return {
    schema: 4,
    algorithm: "sha256",
    normalization: "finding-v3",
    population: MECHANICAL_CORPUS_POPULATION,
    ...provenance,
    targetCount: Object.keys(targets).length,
    mechanicalRowCount: Object.values(targets).reduce((sum, target) => sum + target.count, 0),
    aggregateDigest: aggregateDigest(targets),
    targets,
  };
}

export function mechanicalFindingsFromCorpusArtifact(
  artifact: { mechanicalPopulation?: unknown; mechanicalFindings?: unknown },
  source: string,
): Record<string, Finding[]> {
  if (artifact.mechanicalPopulation !== MECHANICAL_CORPUS_POPULATION) {
    throw new Error(`${source}: corpus scorecard does not identify ${MECHANICAL_CORPUS_POPULATION}`);
  }
  if (!artifact.mechanicalFindings || typeof artifact.mechanicalFindings !== "object" || Array.isArray(artifact.mechanicalFindings)) {
    throw new Error(`${source}: corpus scorecard has no runMechanicalScanDetailed findings population`);
  }
  const findings = artifact.mechanicalFindings as Record<string, Finding[]>;
  if (Object.keys(findings).length === 0) throw new Error(`${source}: runMechanicalScanDetailed findings population is empty`);
  for (const [target, rows] of Object.entries(findings)) {
    if (!Array.isArray(rows)) throw new Error(`${source}: ${target} runMechanicalScanDetailed population is not an array`);
    mechanicalFindingRecords(target, rows);
  }
  return findings;
}

function assertSha256(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new Error(`${label} is not a SHA-256 digest`);
}

function sortedUniqueStrings(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) throw new Error(`${label} is not a string array`);
  const sorted = [...value].sort();
  if (new Set(sorted).size !== sorted.length) throw new Error(`${label} contains duplicates`);
  return sorted;
}

export function mechanicalMigrationReplayArtifact(
  artifact: unknown,
  source: string,
  expectedTargets?: readonly string[],
): MechanicalMigrationReplayArtifact {
  if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)) throw new Error(`${source}: replay artifact is not an object`);
  const replay = artifact as Partial<MechanicalMigrationReplayArtifact>;
  if (replay.schema !== 1 || replay.population !== MECHANICAL_CORPUS_POPULATION) throw new Error(`${source}: replay artifact uses an unsupported schema or population`);
  if (!/^[a-f0-9]{40}$/.test(replay.engineCommit ?? "")) throw new Error(`${source}: replay engine commit is not a full Git commit`);
  if (replay.orchestrator !== "manual" && replay.orchestrator !== "registry") throw new Error(`${source}: replay orchestrator is not manual or registry`);
  const amendmentPaths = sortedUniqueStrings(replay.engineAmendmentPaths, `${source}: replay engine amendment paths`);
  if (amendmentPaths.length > 0) assertSha256(replay.engineAmendmentPatchSha256, `${source}: replay engine amendment patch`);
  if (amendmentPaths.length === 0 && replay.engineAmendmentPatchSha256 !== undefined) throw new Error(`${source}: replay records an amendment patch with no amended paths`);
  for (const [value, label] of [
    [replay.harnessSha256, "harness"],
    [replay.targetPinsSha256, "target pins"],
    [replay.advisoryManifestSha256, "advisory manifest"],
    [replay.semgrepRegistrySha256, "Semgrep registry"],
  ] as const) assertSha256(value, `${source}: replay ${label}`);
  const targets = sortedUniqueStrings(replay.targets, `${source}: replay targets`);
  if (replay.targetCount !== targets.length) throw new Error(`${source}: replay target count is ${replay.targetCount}, expected ${targets.length}`);
  if (expectedTargets) {
    const expected = [...expectedTargets].sort();
    if (JSON.stringify(targets) !== JSON.stringify(expected)) throw new Error(`${source}: replay target population differs: got [${targets.join(", ")}], expected [${expected.join(", ")}]`);
  }
  if (!replay.externalState || typeof replay.externalState !== "object" || Array.isArray(replay.externalState)) throw new Error(`${source}: replay external state is missing`);
  if (!replay.mechanicalFindings || typeof replay.mechanicalFindings !== "object" || Array.isArray(replay.mechanicalFindings)) throw new Error(`${source}: replay mechanical findings are missing`);
  for (const population of [Object.keys(replay.externalState), Object.keys(replay.mechanicalFindings)]) {
    if (JSON.stringify(population.sort()) !== JSON.stringify(targets)) throw new Error(`${source}: replay target, external-state, and findings populations differ`);
  }
  for (const target of targets) {
    const state = replay.externalState[target];
    if (!state || state.networkFallbacksDisabled !== true || state.bundleScanPinnedOff !== true) throw new Error(`${source}: ${target} did not disable every live/network fallback`);
    assertSha256(state.advisorySha256, `${source}: ${target} advisory`);
    assertSha256(state.secretCandidateIdentity, `${source}: ${target} secret candidate identity`);
    assertSha256(state.semgrepRegistrySha256, `${source}: ${target} Semgrep registry`);
    if (state.semgrepRegistrySha256 !== replay.semgrepRegistrySha256) throw new Error(`${source}: ${target} used a different Semgrep registry`);
    const rows = replay.mechanicalFindings[target];
    if (!Array.isArray(rows)) throw new Error(`${source}: ${target} runMechanicalScanDetailed population is not an array`);
    mechanicalFindingRecords(target, rows);
  }
  return replay as MechanicalMigrationReplayArtifact;
}

export function replayParityProvenance(
  base: MechanicalMigrationReplayArtifact,
  migration: MechanicalMigrationReplayArtifact,
  artifactDigests: { base: string; migration: string },
): CorpusMechanicalParityProvenance {
  assertSha256(artifactDigests.base, "base replay artifact");
  assertSha256(artifactDigests.migration, "migration replay artifact");
  if (base.orchestrator !== "manual") throw new Error(`base replay orchestrator is ${base.orchestrator}, expected manual`);
  if (migration.orchestrator !== "registry") throw new Error(`migration replay orchestrator is ${migration.orchestrator}, expected registry`);
  const common = (artifact: MechanicalMigrationReplayArtifact): string => JSON.stringify({
    population: artifact.population,
    harnessSha256: artifact.harnessSha256,
    targetPinsSha256: artifact.targetPinsSha256,
    advisoryManifestSha256: artifact.advisoryManifestSha256,
    semgrepRegistrySha256: artifact.semgrepRegistrySha256,
    targetCount: artifact.targetCount,
    targets: [...artifact.targets].sort(),
    externalState: Object.fromEntries([...artifact.targets].sort().map((target) => [target, artifact.externalState[target]])),
  });
  if (common(base) !== common(migration)) throw new Error("base and migration replays do not share one pinned input/external-state identity");
  const engine = (artifact: MechanicalMigrationReplayArtifact, artifactSha256: string): ReplayEngineProvenance => ({
    artifactSha256,
    engineCommit: artifact.engineCommit,
    orchestrator: artifact.orchestrator,
    engineAmendmentPaths: artifact.engineAmendmentPaths,
    ...(artifact.engineAmendmentPatchSha256 ? { engineAmendmentPatchSha256: artifact.engineAmendmentPatchSha256 } : {}),
  });
  return {
    replayContract: "pinned-advisories+frozen-semgrep+network-off+bundle-off",
    harnessSha256: base.harnessSha256,
    targetPinsSha256: base.targetPinsSha256,
    advisoryManifestSha256: base.advisoryManifestSha256,
    semgrepRegistrySha256: base.semgrepRegistrySha256,
    base: engine(base, artifactDigests.base),
    migration: engine(migration, artifactDigests.migration),
    externalState: Object.fromEntries([...base.targets].sort().map((target) => [target, base.externalState[target]!])),
  };
}

export function serializeCorpusMechanicalParityBaseline(baseline: CorpusMechanicalParityBaseline): string {
  return `${JSON.stringify(baseline, null, 2)}\n`;
}

export function assertCorpusMechanicalExternalState(
  baseline: CorpusMechanicalParityBaseline,
  value: unknown,
  source: string,
): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${source}: corpus scorecard has no mechanical external-state population`);
  const externalState = value as Record<string, { mode?: unknown; advisoryDigest?: unknown; networkFallbacksDisabled?: unknown; secretCandidateIdentity?: unknown }>;
  const baselineTargets = Object.keys(baseline.targets).sort();
  if (JSON.stringify(Object.keys(externalState).sort()) !== JSON.stringify(baselineTargets)) throw new Error(`${source}: mechanical external-state population differs from the parity baseline`);
  const modes = new Set(Object.values(externalState).map((state) => state.mode));
  if (modes.size !== 1) throw new Error(`${source}: mechanical targets used mixed external-state modes`);
  const mode = [...modes][0];
  // Scheduled live-verify runs intentionally exercise current providers and separately compare them
  // with these same committed snapshots. Plain live mode has neither deterministic input nor that
  // parity check and is never acceptable to the migration gate.
  if (mode === "live-verify") return;
  if (mode !== "snapshot") throw new Error(`${source}: mechanical parity ran without snapshot or live-verify external-state control`);
  for (const target of baselineTargets) {
    const actual = externalState[target];
    const expected = baseline.externalState[target];
    if (!actual || actual.networkFallbacksDisabled !== true) throw new Error(`${source}: ${target} mechanical scan permitted a live/network fallback`);
    if (!expected || actual.advisoryDigest !== expected.advisorySha256 || actual.secretCandidateIdentity !== expected.secretCandidateIdentity) throw new Error(`${source}: ${target} mechanical scan did not use the pinned replay provider identity`);
  }
}

function assertBaselineIntegrity(baseline: CorpusMechanicalParityBaseline): void {
  if (baseline.schema !== 4 || baseline.algorithm !== "sha256" || baseline.normalization !== "finding-v3"
    || baseline.population !== MECHANICAL_CORPUS_POPULATION) {
    throw new Error("corpus mechanical parity baseline uses an unsupported schema or digest contract");
  }
  const targetNames = Object.keys(baseline.targets).sort();
  if (baseline.replayContract !== "pinned-advisories+frozen-semgrep+network-off+bundle-off") throw new Error("corpus mechanical parity replay contract is invalid");
  for (const [value, label] of [
    [baseline.harnessSha256, "harness"],
    [baseline.targetPinsSha256, "target pins"],
    [baseline.advisoryManifestSha256, "advisory manifest"],
    [baseline.semgrepRegistrySha256, "Semgrep registry"],
    [baseline.base.artifactSha256, "base artifact"],
    [baseline.migration.artifactSha256, "migration artifact"],
  ] as const) assertSha256(value, `corpus mechanical parity ${label}`);
  if (baseline.base.orchestrator !== "manual" || baseline.migration.orchestrator !== "registry") throw new Error("corpus mechanical parity does not prove manual-to-registry migration timing");
  for (const [side, engine] of [["base", baseline.base], ["migration", baseline.migration]] as const) {
    if (!/^[a-f0-9]{40}$/.test(engine.engineCommit)) throw new Error(`corpus mechanical parity ${side} engine commit is invalid`);
    const paths = sortedUniqueStrings(engine.engineAmendmentPaths, `corpus mechanical parity ${side} amendment paths`);
    if (paths.length > 0) assertSha256(engine.engineAmendmentPatchSha256, `corpus mechanical parity ${side} amendment patch`);
    if (paths.length === 0 && engine.engineAmendmentPatchSha256 !== undefined) throw new Error(`corpus mechanical parity ${side} records an amendment patch with no paths`);
  }
  if (baseline.targetCount !== targetNames.length) throw new Error(`corpus mechanical parity target count is ${baseline.targetCount}, expected ${targetNames.length}`);
  if (JSON.stringify(Object.keys(baseline.externalState).sort()) !== JSON.stringify(targetNames)) throw new Error("corpus mechanical parity external-state population differs from its target population");
  for (const target of targetNames) {
    const state = baseline.externalState[target]!;
    if (state.networkFallbacksDisabled !== true || state.bundleScanPinnedOff !== true) throw new Error(`${target}: corpus mechanical parity permits a live/network fallback`);
    assertSha256(state.advisorySha256, `${target}: corpus mechanical parity advisory`);
    assertSha256(state.secretCandidateIdentity, `${target}: corpus mechanical parity secret candidate identity`);
    assertSha256(state.semgrepRegistrySha256, `${target}: corpus mechanical parity Semgrep registry`);
    if (state.semgrepRegistrySha256 !== baseline.semgrepRegistrySha256) throw new Error(`${target}: corpus mechanical parity Semgrep registry differs from provenance`);
  }
  let rowCount = 0;
  for (const target of targetNames) {
    const entry = baseline.targets[target]!;
    if (entry.count !== entry.rows.length) throw new Error(`${target}: corpus mechanical parity row count is ${entry.count}, expected ${entry.rows.length}`);
    for (const [ordinal, row] of entry.rows.entries()) {
      if (row.ordinal !== ordinal) throw new Error(`${target}: corpus mechanical parity ordinal ${row.ordinal} is stored at position ${ordinal}`);
      if (![row.identityDigest, row.contentDigest, row.orderedDigest].every((value) => SHA256.test(value))) throw new Error(`${target}:${ordinal}: corpus mechanical parity row contains a non-SHA-256 value`);
      if (row.orderedDigest !== orderedRowDigest(target, row)) throw new Error(`${target}:${ordinal}: corpus mechanical parity ordered digest is invalid`);
    }
    if (!SHA256.test(entry.orderedDigest) || entry.orderedDigest !== targetDigest(target, entry.rows)) throw new Error(`${target}: corpus mechanical parity target digest is invalid`);
    rowCount += entry.count;
  }
  if (baseline.mechanicalRowCount !== rowCount) throw new Error(`corpus mechanical parity row count is ${baseline.mechanicalRowCount}, expected ${rowCount}`);
  if (!SHA256.test(baseline.aggregateDigest) || baseline.aggregateDigest !== aggregateDigest(baseline.targets)) throw new Error("corpus mechanical parity aggregate digest is invalid");
}

interface OrderedParityDifference {
  target: string;
  kind: "added" | "removed" | "moved" | "modified";
  identityDigest: string;
  beforeOrdinal?: number;
  afterOrdinal?: number;
  beforeDigest?: string;
  afterDigest?: string;
}

export function compareCorpusMechanicalParity(baseline: CorpusMechanicalParityBaseline, findings: Record<string, Finding[]>): OrderedParityDifference[] {
  assertBaselineIntegrity(baseline);
  const differences: OrderedParityDifference[] = [];
  const targets = [...new Set([...Object.keys(baseline.targets), ...Object.keys(findings)])].sort();
  for (const target of targets) {
    const before = baseline.targets[target]?.rows ?? [];
    const after = mechanicalFindingRecords(target, findings[target] ?? []);
    const beforeById = new Map(before.map((record) => [record.identityDigest, record]));
    const afterById = new Map(after.map((record) => [record.identityDigest, record]));
    for (const [identityDigest, prior] of beforeById) {
      const current = afterById.get(identityDigest);
      if (!current) {
        differences.push({ target, kind: "removed", identityDigest, beforeOrdinal: prior.ordinal, beforeDigest: prior.orderedDigest });
        continue;
      }
      if (prior.contentDigest !== current.contentDigest) differences.push({ target, kind: "modified", identityDigest, beforeOrdinal: prior.ordinal, afterOrdinal: current.ordinal, beforeDigest: prior.contentDigest, afterDigest: current.contentDigest });
      if (prior.ordinal !== current.ordinal) differences.push({ target, kind: "moved", identityDigest, beforeOrdinal: prior.ordinal, afterOrdinal: current.ordinal, beforeDigest: prior.orderedDigest, afterDigest: current.orderedDigest });
    }
    for (const [identityDigest, current] of afterById) if (!beforeById.has(identityDigest)) {
      differences.push({ target, kind: "added", identityDigest, afterOrdinal: current.ordinal, afterDigest: current.orderedDigest });
    }
  }
  return differences;
}

export function formatCorpusMechanicalParityDifference(difference: OrderedParityDifference): string {
  return `${difference.target} ${difference.kind.toUpperCase()} identity=sha256:${difference.identityDigest} beforeOrdinal=${difference.beforeOrdinal ?? "-"} afterOrdinal=${difference.afterOrdinal ?? "-"} beforeDigest=${difference.beforeDigest ? `sha256:${difference.beforeDigest}` : "-"} afterDigest=${difference.afterDigest ? `sha256:${difference.afterDigest}` : "-"}`;
}
