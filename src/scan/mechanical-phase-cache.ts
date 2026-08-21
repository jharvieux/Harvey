import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { validateFindings, type Finding, type ReportMeta } from "../findings.js";
import { readEntriesSafe, readRecursiveSafe, statSafe } from "../fs-walk.js";
import type { SemgrepDiagnosticEvidence, SemgrepFamilyCacheOptions } from "./semgrep-family-cache.js";

export const MECHANICAL_PHASES = [
  "secrets-history",
  "dependency-advisory",
  "semgrep",
  "configuration",
  "structural-ast",
  "normalization",
] as const;

export type MechanicalPhase = (typeof MECHANICAL_PHASES)[number];
export type MechanicalCacheMode = "off" | "read-write" | "verify";
export type MechanicalCacheStatus = "hit" | "miss" | "recomputed" | "non-cacheable";

export interface MechanicalPhaseScope {
  unitsExamined: number;
  description: string;
}

export interface MechanicalExaminedUnitIdentity {
  producer: string;
  /** Names the selector's semantic namespace; target-path receives additional canonical checks. */
  kind: string;
  /** Raw, checkout-independent identity retained in selector order. */
  identity: string;
}

export interface MechanicalProducerNotAssessed {
  reason: string;
  provenance: string;
  falsifier: string;
  inventory: {
    broadUnits: number;
    selectedUnits: 0;
    pathSetDigest: string;
    scope: string;
  };
}

export interface MechanicalProducerRecord {
  detector: string;
  phase: MechanicalPhase;
  order: number;
  module: "M1" | "M5" | "M6" | "M8";
  unitsExamined: number;
  examinedUnitIdentities: MechanicalExaminedUnitIdentity[];
  examinedUnitDigest?: string;
  findings: number;
  durationMs: number;
  status: "ran" | "not-assessed" | "not-applicable" | "cached";
  notAssessed?: MechanicalProducerNotAssessed;
}

export interface MechanicalPhaseValue {
  findings: Finding[];
  scope: MechanicalPhaseScope;
  producers?: MechanicalProducerRecord[];
  evidence?: { semgrepDiagnostics: SemgrepDiagnosticEvidence };
}

export interface MechanicalPhaseRecord extends MechanicalPhaseValue {
  phase: MechanicalPhase;
  durationMs: number;
  cache: MechanicalCacheStatus;
  reason: string;
  key?: string;
}

export interface MechanicalPhaseCacheOptions {
  dir: string;
  mode: MechanicalCacheMode;
  targetRevision: string;
  targetTree: string;
  implementation: Partial<Record<MechanicalPhase, string>>;
  externalInputs: Partial<Record<MechanicalPhase, Record<string, string>>>;
  disabled?: Partial<Record<MechanicalPhase, string>>;
  materializedInputs?: Partial<Record<MechanicalPhase, readonly string[]>>;
  semgrepFamilies?: SemgrepFamilyCacheOptions;
  reproducible?: Partial<Record<MechanicalPhase, string>>;
  onEvent?: (message: string) => void;
}

interface MechanicalPhaseIdentityComponents {
  targetRevision: string;
  targetTree: string;
  implementation: string;
  externalInputs: Record<string, string>;
}

interface CacheArtifact {
  schema: 4;
  phase: MechanicalPhase;
  key: string;
  targetRevision: string;
  targetTree: string;
  identity: MechanicalPhaseIdentityComponents;
  payloadDigest: string;
  findings: Finding[];
  scope: MechanicalPhaseScope;
  producers?: MechanicalProducerRecord[];
  evidence?: MechanicalPhaseValue["evidence"];
}

const CACHEABILITY: Record<MechanicalPhase, { cacheable: boolean; reason: string }> = {
  "secrets-history": { cacheable: false, reason: "TruffleHog --only-verified consults live provider state whose result has no reproducible identity" },
  "dependency-advisory": { cacheable: false, reason: "OSV and npm registry/advisory responses have no immutable response identity on this path" },
  semgrep: { cacheable: true, reason: "resolved registry packs, local rules, implementation, target tree, and Semgrep version are keyed" },
  configuration: { cacheable: true, reason: "in-process configuration checks depend only on the keyed target tree and implementation" },
  "structural-ast": { cacheable: true, reason: "in-process structural/AST checks depend only on the keyed target tree, options, runtime, and implementation" },
  normalization: { cacheable: false, reason: "cheap composition step consumes this run's cacheable and live advisory outputs" },
};

export const CACHEABLE_MECHANICAL_PHASES = MECHANICAL_PHASES.filter(
  (phase): phase is MechanicalPhase => CACHEABILITY[phase].cacheable,
);

const CACHE_VALIDATION_META: ReportMeta = {
  client: "mechanical phase cache artifact",
  subtitle: "schema validation only",
  date: "1970-01-01",
  commit: "cache-artifact",
  auditor: "Harvey",
  confidential: true,
  overallHealth: 0,
  tenantIsolation: "not applicable",
  authModel: "not applicable",
  headline: "cache artifact validation",
  scope: "one cached mechanical phase",
  methodology: "canonical Finding schema",
  outOfScope: "document metadata",
};

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalTargetRelativePath(path: string): boolean {
  if (path.length === 0 || path.startsWith("/") || /^[A-Za-z]:/.test(path) || path.includes("\\")) return false;
  const segments = path.split("/");
  return segments.every((segment) => segment.length > 0 && segment !== "." && segment !== "..");
}

function examinedUnitProblems(detector: string, units: unknown): string[] {
  if (!Array.isArray(units)) return ["examined-unit identities are missing or malformed"];
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const [index, unit] of units.entries()) {
    if (!unit || typeof unit !== "object") {
      problems.push(`examined-unit identity ${index} is malformed`);
      continue;
    }
    const row = unit as Partial<MechanicalExaminedUnitIdentity>;
    if (row.producer !== detector) problems.push(`examined-unit identity ${index} belongs to the wrong producer`);
    if (typeof row.kind !== "string" || !/^[a-z][a-z0-9-]*$/.test(row.kind)) problems.push(`examined-unit identity ${index} has a noncanonical kind`);
    if (typeof row.identity !== "string" || row.identity.length === 0 || [...row.identity].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) {
      problems.push(`examined-unit identity ${index} is empty or contains control characters`);
      continue;
    }
    if (row.kind === "target-path" && !canonicalTargetRelativePath(row.identity)) problems.push(`examined-unit identity ${index} is not a canonical target-relative path`);
    if (row.kind !== "target-path" && (row.identity.includes("\\") || /(?:^|[=:])\/(?:Users|home|private|tmp|var\/folders)\//.test(row.identity))) {
      problems.push(`examined-unit identity ${index} contains a checkout-local path`);
    }
    const key = stable(row);
    if (seen.has(key)) problems.push(`examined-unit identity ${index} duplicates an earlier unit`);
    seen.add(key);
  }
  return problems;
}

export function targetPathExaminedUnits(producer: string, paths: readonly string[]): MechanicalExaminedUnitIdentity[] {
  return paths.map((identity) => ({ producer, kind: "target-path", identity }));
}

export function mechanicalExaminedUnitDigest(units: readonly MechanicalExaminedUnitIdentity[]): string {
  return digestParts([stable(units)]);
}

export function createMechanicalProducerRecord(
  input: Omit<MechanicalProducerRecord, "unitsExamined" | "examinedUnitDigest"> & { examinedUnitIdentities: MechanicalExaminedUnitIdentity[] },
): MechanicalProducerRecord {
  const record: MechanicalProducerRecord = {
    ...input,
    unitsExamined: input.examinedUnitIdentities.length,
    examinedUnitDigest: mechanicalExaminedUnitDigest(input.examinedUnitIdentities),
  };
  const problems = producerRecordProblems(record, record.phase);
  if (problems.length > 0) throw new Error(`${record.phase}:${record.detector}: ${problems.join("; ")}`);
  return record;
}

export function digestParts(parts: readonly (string | Buffer)[]): string {
  const hash = createHash("sha256");
  for (const part of parts) {
    const data = typeof part === "string" ? Buffer.from(part) : part;
    hash.update(String(data.length));
    hash.update("\0");
    hash.update(data);
  }
  return hash.digest("hex");
}

function producerRecordProblems(producer: unknown, expectedPhase: MechanicalPhase, requireDigest: boolean = false): string[] {
  if (!producer || typeof producer !== "object") return ["producer record is malformed"];
  const row = producer as Partial<MechanicalProducerRecord>;
  const problems: string[] = [];
  if (typeof row.detector !== "string" || !/^[a-z0-9][a-z0-9-]*$/.test(row.detector)) problems.push("producer id is missing or noncanonical");
  if (row.phase !== expectedPhase) problems.push("producer phase does not match its artifact");
  if (!Number.isInteger(row.order) || row.order! < 0) problems.push("producer order is malformed");
  if (row.module !== "M1" && row.module !== "M5" && row.module !== "M6" && row.module !== "M8") problems.push("producer module is malformed");
  if (!Number.isInteger(row.unitsExamined) || row.unitsExamined! < 0) problems.push("producer examined count is malformed");
  if (!Number.isInteger(row.findings) || row.findings! < 0) problems.push("producer finding count is malformed");
  if (typeof row.durationMs !== "number" || !Number.isFinite(row.durationMs) || row.durationMs < 0) problems.push("producer duration is malformed");
  if (row.status !== "ran" && row.status !== "not-assessed" && row.status !== "not-applicable" && row.status !== "cached") problems.push("producer status is malformed");
  const unitProblems = examinedUnitProblems(row.detector ?? "", row.examinedUnitIdentities);
  problems.push(...unitProblems);
  if (Array.isArray(row.examinedUnitIdentities) && row.unitsExamined !== row.examinedUnitIdentities.length) problems.push("producer examined count differs from its exact identity population");
  if (requireDigest && typeof row.examinedUnitDigest !== "string") problems.push("producer examined-unit digest is missing");
  if (Array.isArray(row.examinedUnitIdentities) && row.examinedUnitDigest !== undefined && row.examinedUnitDigest !== mechanicalExaminedUnitDigest(row.examinedUnitIdentities)) problems.push("producer examined-unit digest does not match its raw identity population");
  const receipt = row.notAssessed;
  if (row.status === "not-assessed") {
    if (row.unitsExamined !== 0) problems.push("not-assessed producer must examine zero selected units");
    if (!Number.isInteger(row.findings) || row.findings! <= 0) problems.push("not-assessed producer must emit a client-visible disclosure finding");
    if (!receipt || typeof receipt !== "object") {
      problems.push("not-assessed producer is missing its typed reason receipt");
    } else {
      if (typeof receipt.reason !== "string" || receipt.reason.trim().length < 20) problems.push("not-assessed reason is incomplete");
      if (typeof receipt.provenance !== "string" || receipt.provenance.trim().length < 20) problems.push("not-assessed provenance is incomplete");
      if (typeof receipt.falsifier !== "string" || receipt.falsifier.trim().length < 20) problems.push("not-assessed falsifier is incomplete");
      if (!receipt.inventory || typeof receipt.inventory !== "object") {
        problems.push("not-assessed inventory is missing");
      } else {
        if (!Number.isInteger(receipt.inventory.broadUnits) || receipt.inventory.broadUnits <= 0) problems.push("not-assessed broad inventory must be non-empty");
        if (receipt.inventory.selectedUnits !== 0) problems.push("not-assessed selected inventory must be exactly zero");
        if (!/^[a-f0-9]{64}$/.test(receipt.inventory.pathSetDigest ?? "")) problems.push("not-assessed path-set digest is malformed");
        if (typeof receipt.inventory.scope !== "string" || receipt.inventory.scope.trim().length < 20) problems.push("not-assessed scope is incomplete");
      }
    }
  } else if (receipt !== undefined) {
    problems.push("typed not-assessed receipt is attached to a producer with a different status");
  }
  return problems;
}

function phaseValueProblems(phase: MechanicalPhase, value: MechanicalPhaseValue, requireDigest: boolean = false): string[] {
  const problems: string[] = [];
  if (value.evidence !== undefined) {
    const diagnostic = value.evidence.semgrepDiagnostics;
    if (phase !== "semgrep") problems.push("Semgrep diagnostic evidence is attached to a non-Semgrep phase");
    if (diagnostic?.schema !== 1 || !Array.isArray(diagnostic.errors) || !Array.isArray(diagnostic.skipped) || !/^[a-f0-9]{64}$/.test(diagnostic.sha256 ?? "")) {
      problems.push("Semgrep diagnostic evidence is incomplete or malformed");
    } else if (diagnostic.sha256 !== createHash("sha256").update(stable({ errors: diagnostic.errors, skipped: diagnostic.skipped })).digest("hex")) {
      problems.push("Semgrep diagnostic evidence digest differs from its complete raw content");
    }
  }
  if (value.producers === undefined) return problems;
  problems.push(...value.producers.flatMap((producer) => producerRecordProblems(producer, phase, requireDigest).map((problem) => `${producer.detector}: ${problem}`)));
  for (let index = 1; index < value.producers.length; index++) {
    const prior = value.producers[index - 1]!;
    const current = value.producers[index]!;
    if (current.order <= prior.order) problems.push(`${current.detector}: producer order is duplicate or out of sequence after ${prior.detector}`);
  }
  if (new Set(value.producers.map((producer) => producer.detector)).size !== value.producers.length) problems.push("producer ids are duplicated");
  if (value.producers.reduce((sum, producer) => sum + producer.findings, 0) !== value.findings.length) problems.push("producer finding census does not equal the phase finding population");
  return problems;
}

function assertPhaseValue(phase: MechanicalPhase, value: MechanicalPhaseValue, requireDigest: boolean = false): void {
  const problems = phaseValueProblems(phase, value, requireDigest);
  if (problems.length > 0) throw new Error(`${phase}: producer execution receipts are malformed: ${problems.join("; ")}`);
}

function withProducerDigests(value: MechanicalPhaseValue): MechanicalPhaseValue {
  if (value.producers === undefined) return value;
  return {
    ...value,
    producers: value.producers.map((producer) => ({
      ...producer,
      examinedUnitDigest: mechanicalExaminedUnitDigest(producer.examinedUnitIdentities),
    })),
  };
}

export function digestTree(dir: string, include: (relativePath: string) => boolean = () => true): string {
  const files = readRecursiveSafe(dir).filter((p) => include(p) && !p.split("/").some((part) => part === ".git") && statSafe(join(dir, p))?.isFile());
  const parts: (string | Buffer)[] = [];
  for (const rel of files.sort()) {
    const path = join(dir, rel);
    try {
      parts.push(rel, readFileSync(path));
    } catch {
      // A directory or disappearing file is not an examined file; the stable path list still
      // captures every readable input. Corpus clones are immutable while this runs.
    }
  }
  return digestParts(parts);
}

export function digestFiles(paths: readonly string[], repoRoot: string): string {
  const parts: (string | Buffer)[] = [];
  for (const path of [...paths].sort()) {
    if (!existsSync(path)) throw new Error(`mechanical phase implementation input missing: ${path}`);
    const label = relative(repoRoot, path).replaceAll("\\", "/");
    if (label === "" || label === ".." || label.startsWith("../")) {
      throw new Error(`mechanical phase implementation input is outside its repository root: ${path}`);
    }
    parts.push(label, readFileSync(path));
  }
  return digestParts(parts);
}

export function binaryVersion(binary: string): string {
  try {
    return execFileSync(binary, ["--version"], { encoding: "utf8", timeout: 10_000 }).trim();
  } catch (error) {
    const e = error as { code?: string };
    return e.code === "ENOENT" ? "unavailable" : "version-command-failed";
  }
}

export function resolveGitTree(dir: string): string {
  try {
    return execFileSync("git", ["-C", dir, "rev-parse", "HEAD^{tree}"], { encoding: "utf8" }).trim();
  } catch (error) {
    throw new Error(`pinned corpus target has no resolvable git tree at ${dir}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function findingSchemaProblems(value: unknown): string[] {
  const result = validateFindings({ meta: CACHE_VALIDATION_META, findings: [value] });
  return result.errors.filter((error) => error.startsWith("findings[0]"));
}

function persistedPhaseValue(value: MechanicalPhaseValue): MechanicalPhaseValue {
  return {
    findings: value.findings,
    scope: value.scope,
    ...(value.evidence === undefined ? {} : { evidence: value.evidence }),
    ...(value.producers === undefined ? {} : {
      producers: value.producers.map((producer) => ({
        ...producer,
        examinedUnitDigest: mechanicalExaminedUnitDigest(producer.examinedUnitIdentities),
        durationMs: 0,
        status: producer.status === "cached" ? "ran" : producer.status,
      })),
    }),
  };
}

export function mechanicalPhasePayloadDigest(value: MechanicalPhaseValue): string {
  return digestParts([stable(persistedPhaseValue(value))]);
}

function parseArtifact(text: string, expected: Pick<CacheArtifact, "schema" | "phase" | "key" | "targetRevision" | "targetTree" | "identity">): CacheArtifact {
  const value = JSON.parse(text) as Partial<CacheArtifact>;
  if (value.schema !== 4 || value.phase !== expected.phase || value.key !== expected.key || value.targetRevision !== expected.targetRevision || value.targetTree !== expected.targetTree || stable(value.identity) !== stable(expected.identity)) {
    throw new Error("artifact identity/schema mismatch");
  }
  if (!Array.isArray(value.findings)) throw new Error("artifact findings are incomplete or malformed");
  const findingProblems = value.findings.flatMap((finding) => findingSchemaProblems(finding));
  if (findingProblems.length > 0) throw new Error(`artifact findings violate the normalized Finding schema: ${findingProblems.join("; ")}`);
  if (!value.scope || !Number.isInteger(value.scope.unitsExamined) || value.scope.unitsExamined <= 0 || typeof value.scope.description !== "string" || value.scope.description.length === 0) {
    throw new Error("artifact examined-scope metadata is incomplete or zero");
  }
  if (value.producers !== undefined && !Array.isArray(value.producers)) throw new Error("artifact producer execution receipts are malformed");
  const receiptProblems = phaseValueProblems(expected.phase, {
    findings: value.findings,
    scope: value.scope,
    ...(value.evidence === undefined ? {} : { evidence: value.evidence }),
    ...(value.producers === undefined ? {} : { producers: value.producers }),
  }, true);
  if (receiptProblems.length > 0) throw new Error(`artifact producer execution receipts are malformed: ${receiptProblems.join("; ")}`);
  const payloadDigest = mechanicalPhasePayloadDigest({
    findings: value.findings,
    scope: value.scope,
    ...(value.evidence === undefined ? {} : { evidence: value.evidence }),
    ...(value.producers === undefined ? {} : { producers: value.producers }),
  });
  if (value.payloadDigest !== payloadDigest) throw new Error("artifact payload checksum mismatch");
  return value as CacheArtifact;
}

function componentEntries(identity: MechanicalPhaseIdentityComponents): [string, string][] {
  return [
    ["targetRevision", identity.targetRevision],
    ["targetTree", identity.targetTree],
    ["implementation", identity.implementation],
    ...Object.entries(identity.externalInputs).sort(([a], [b]) => a.localeCompare(b)).map(([name, value]): [string, string] => [`externalInputs.${name}`, value]),
  ];
}

function closestPriorIdentity(dir: string, phase: MechanicalPhase, current: MechanicalPhaseIdentityComponents): string | undefined {
  const phaseDir = join(dir, phase);
  if (!existsSync(phaseDir)) return undefined;
  const currentEntries = new Map(componentEntries(current));
  let closest: { matches: number; changed: string[] } | undefined;
  for (const name of readEntriesSafe(phaseDir).entries.filter((candidate) => !candidate.isDirectory && candidate.name.endsWith(".json")).map((candidate) => candidate.name)) {
    try {
      const value = JSON.parse(readFileSync(join(phaseDir, name), "utf8")) as Partial<CacheArtifact>;
      if (value.schema !== 4 || value.phase !== phase || !value.identity) continue;
      const previous = new Map(componentEntries(value.identity));
      const names = [...new Set([...currentEntries.keys(), ...previous.keys()])].sort();
      const changed = names.filter((component) => currentEntries.get(component) !== previous.get(component));
      const matches = names.length - changed.length;
      if (changed.length > 0 && (!closest || matches > closest.matches)) closest = { matches, changed };
    } catch {
      continue;
    }
  }
  return closest?.changed.join(", ");
}

function equivalent(a: MechanicalPhaseValue, b: MechanicalPhaseValue): boolean {
  return stable(persistedPhaseValue(a)) === stable(persistedPhaseValue(b));
}

export async function executeMechanicalPhase(
  phase: MechanicalPhase,
  cache: MechanicalPhaseCacheOptions | undefined,
  execute: () => MechanicalPhaseValue | Promise<MechanicalPhaseValue>,
): Promise<MechanicalPhaseRecord> {
  const policy = CACHEABILITY[phase];
  const reproducible = cache?.reproducible?.[phase];
  const cacheable = policy.cacheable || reproducible !== undefined;
  const started = Date.now();
  const disabled = cache?.disabled?.[phase];
  if (!cache || cache.mode === "off" || !cacheable || disabled) {
    const value = withProducerDigests(await execute());
    assertPhaseValue(phase, value, true);
    const reason = disabled ?? (!cache || cache.mode === "off" ? "phase cache disabled" : policy.reason);
    cache?.onEvent?.(`CACHE BYPASS ${phase}: ${reason}`);
    return { phase, ...value, durationMs: Date.now() - started, cache: "non-cacheable", reason };
  }
  const implementation = cache.implementation[phase];
  if (!implementation) throw new Error(`${phase}: cacheable phase has no implementation identity`);
  const externalInputs = cache.externalInputs[phase];
  if (!externalInputs || Object.keys(externalInputs).length === 0) throw new Error(`${phase}: cacheable phase has no declared external-input identity`);
  const identity: MechanicalPhaseIdentityComponents = {
    targetRevision: digestParts([cache.targetRevision]),
    targetTree: digestParts([cache.targetTree]),
    implementation: digestParts([implementation]),
    externalInputs: Object.fromEntries(Object.entries(externalInputs).map(([name, value]) => [name, digestParts([value])])),
  };
  const key = digestParts([stable({ phase, identity })]);
  const path = join(cache.dir, phase, `${key}.json`);
  const expected = { schema: 4 as const, phase, key, targetRevision: cache.targetRevision, targetTree: cache.targetTree, identity };
  let hit: CacheArtifact | undefined;
  if (existsSync(path)) {
    try {
      hit = parseArtifact(readFileSync(path, "utf8"), expected);
    } catch (error) {
      cache.onEvent?.(`CACHE REJECT ${phase} ${key.slice(0, 12)}: ${error instanceof Error ? error.message : String(error)}; recomputing`);
      rmSync(path, { force: true });
    }
  }
  const movedIdentity = hit ? undefined : closestPriorIdentity(cache.dir, phase, identity);
  if (hit && cache.mode === "read-write") {
    cache.onEvent?.(`CACHE HIT ${phase} ${key.slice(0, 12)} (${hit.findings.length} finding(s), ${hit.scope.unitsExamined} unit(s))`);
    return { phase, findings: hit.findings, scope: hit.scope, ...(hit.evidence === undefined ? {} : { evidence: hit.evidence }), producers: hit.producers?.map((producer) => ({ ...producer, durationMs: 0, status: producer.status === "not-applicable" || producer.status === "not-assessed" ? producer.status : "cached" })), durationMs: Date.now() - started, cache: "hit", reason: reproducible ?? policy.reason, key };
  }
  const value = withProducerDigests(await execute());
  assertPhaseValue(phase, value, true);
  if (!Number.isInteger(value.scope.unitsExamined) || value.scope.unitsExamined <= 0) throw new Error(`${phase}: examined scope must be a positive integer`);
  const hitValue = hit ? { findings: hit.findings, scope: hit.scope, ...(hit.evidence === undefined ? {} : { evidence: hit.evidence }), ...(hit.producers === undefined ? {} : { producers: hit.producers }) } : undefined;
  if (hitValue && !equivalent(value, hitValue)) throw new Error(`${phase}: forced-cold result differs from cached findings, examined scope, or producer census for ${key}`);
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  const persisted = persistedPhaseValue(value);
  const payloadDigest = mechanicalPhasePayloadDigest(persisted);
  writeFileSync(temp, `${JSON.stringify({ ...expected, payloadDigest, ...persisted }, null, 2)}\n`);
  renameSync(temp, path);
  const reread = parseArtifact(readFileSync(path, "utf8"), expected);
  if (!equivalent(value, { findings: reread.findings, scope: reread.scope, ...(reread.evidence === undefined ? {} : { evidence: reread.evidence }), ...(reread.producers === undefined ? {} : { producers: reread.producers }) })) throw new Error(`${phase}: artifact changed during write/read equivalence check`);
  const status: MechanicalCacheStatus = hit ? "recomputed" : "miss";
  cache.onEvent?.(`CACHE ${hit ? "VERIFY" : "MISS"} ${phase} ${key.slice(0, 12)}: cold result ${hit ? "matches" : "stored and reread from"} artifact${movedIdentity ? `; identity changed: ${movedIdentity}` : ""}`);
  return { phase, ...value, durationMs: Date.now() - started, cache: status, reason: hit ? "forced-cold result matched cached artifact" : `no complete artifact for this content address; recomputed${movedIdentity ? `; identity changed: ${movedIdentity}` : ""}`, key };
}

export function assertMechanicalCacheVerification(
  phases: readonly MechanicalPhaseRecord[],
  cache: MechanicalPhaseCacheOptions | undefined,
): void {
  if (cache?.mode !== "verify") return;
  const expected = [...new Set([...CACHEABLE_MECHANICAL_PHASES, ...Object.keys(cache.reproducible ?? {}) as MechanicalPhase[]])];
  const unverified = expected.flatMap((phase) => {
    const record = phases.find((candidate) => candidate.phase === phase);
    return record?.cache === "recomputed" ? [] : [`${phase}=${record?.cache ?? "missing"}`];
  });
  if (unverified.length > 0) {
    throw new Error(`forced-cold cache verification incomplete: ${unverified.join(", ")}. A miss may seed a later run, but this run compared no restored artifact for every deterministic phase and cannot claim equivalence`);
  }
}
