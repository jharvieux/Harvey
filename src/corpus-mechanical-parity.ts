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

interface CorpusMechanicalParityProvenance {
  baseCommit: string;
  baseRun: number;
  migrationHead: string;
  migrationRun: number;
}

export interface CorpusMechanicalParityBaseline extends CorpusMechanicalParityProvenance {
  schema: 3;
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
    schema: 3,
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

export function serializeCorpusMechanicalParityBaseline(baseline: CorpusMechanicalParityBaseline): string {
  return `${JSON.stringify(baseline, null, 2)}\n`;
}

function assertBaselineIntegrity(baseline: CorpusMechanicalParityBaseline): void {
  if (baseline.schema !== 3 || baseline.algorithm !== "sha256" || baseline.normalization !== "finding-v3"
    || baseline.population !== MECHANICAL_CORPUS_POPULATION) {
    throw new Error("corpus mechanical parity baseline uses an unsupported schema or digest contract");
  }
  const targetNames = Object.keys(baseline.targets).sort();
  if (baseline.targetCount !== targetNames.length) throw new Error(`corpus mechanical parity target count is ${baseline.targetCount}, expected ${targetNames.length}`);
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
