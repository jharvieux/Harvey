import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { validateFindings, type Finding, type ReportMeta } from "../findings.js";
import { readEntriesSafe, readRecursiveSafe, statSafe } from "../fs-walk.js";

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

export interface MechanicalPhaseValue {
  findings: Finding[];
  scope: MechanicalPhaseScope;
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
  onEvent?: (message: string) => void;
}

interface MechanicalPhaseIdentityComponents {
  targetRevision: string;
  targetTree: string;
  implementation: string;
  externalInputs: Record<string, string>;
}

interface CacheArtifact {
  schema: 2;
  phase: MechanicalPhase;
  key: string;
  targetRevision: string;
  targetTree: string;
  identity: MechanicalPhaseIdentityComponents;
  payloadDigest: string;
  findings: Finding[];
  scope: MechanicalPhaseScope;
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

export function mechanicalPhasePayloadDigest(value: MechanicalPhaseValue): string {
  return digestParts([stable(value)]);
}

function parseArtifact(text: string, expected: Pick<CacheArtifact, "schema" | "phase" | "key" | "targetRevision" | "targetTree" | "identity">): CacheArtifact {
  const value = JSON.parse(text) as Partial<CacheArtifact>;
  if (value.schema !== 2 || value.phase !== expected.phase || value.key !== expected.key || value.targetRevision !== expected.targetRevision || value.targetTree !== expected.targetTree || stable(value.identity) !== stable(expected.identity)) {
    throw new Error("artifact identity/schema mismatch");
  }
  if (!Array.isArray(value.findings)) throw new Error("artifact findings are incomplete or malformed");
  const findingProblems = value.findings.flatMap((finding) => findingSchemaProblems(finding));
  if (findingProblems.length > 0) throw new Error(`artifact findings violate the normalized Finding schema: ${findingProblems.join("; ")}`);
  if (!value.scope || !Number.isInteger(value.scope.unitsExamined) || value.scope.unitsExamined <= 0 || typeof value.scope.description !== "string" || value.scope.description.length === 0) {
    throw new Error("artifact examined-scope metadata is incomplete or zero");
  }
  const payloadDigest = mechanicalPhasePayloadDigest({ findings: value.findings, scope: value.scope });
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
      if (value.schema !== 2 || value.phase !== phase || !value.identity) continue;
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
  return stable(a) === stable(b);
}

export async function executeMechanicalPhase(
  phase: MechanicalPhase,
  cache: MechanicalPhaseCacheOptions | undefined,
  execute: () => MechanicalPhaseValue | Promise<MechanicalPhaseValue>,
): Promise<MechanicalPhaseRecord> {
  const policy = CACHEABILITY[phase];
  const started = Date.now();
  const disabled = cache?.disabled?.[phase];
  if (!cache || cache.mode === "off" || !policy.cacheable || disabled) {
    const value = await execute();
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
  const expected = { schema: 2 as const, phase, key, targetRevision: cache.targetRevision, targetTree: cache.targetTree, identity };
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
    return { phase, findings: hit.findings, scope: hit.scope, durationMs: Date.now() - started, cache: "hit", reason: policy.reason, key };
  }
  const value = await execute();
  if (!Number.isInteger(value.scope.unitsExamined) || value.scope.unitsExamined <= 0) throw new Error(`${phase}: examined scope must be a positive integer`);
  if (hit && !equivalent(value, { findings: hit.findings, scope: hit.scope })) throw new Error(`${phase}: forced-cold result differs from cached findings or examined scope for ${key}`);
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  const payloadDigest = mechanicalPhasePayloadDigest(value);
  writeFileSync(temp, `${JSON.stringify({ ...expected, payloadDigest, ...value }, null, 2)}\n`);
  renameSync(temp, path);
  const reread = parseArtifact(readFileSync(path, "utf8"), expected);
  if (!equivalent(value, { findings: reread.findings, scope: reread.scope })) throw new Error(`${phase}: artifact changed during write/read equivalence check`);
  const status: MechanicalCacheStatus = hit ? "recomputed" : "miss";
  cache.onEvent?.(`CACHE ${hit ? "VERIFY" : "MISS"} ${phase} ${key.slice(0, 12)}: cold result ${hit ? "matches" : "stored and reread from"} artifact${movedIdentity ? `; identity changed: ${movedIdentity}` : ""}`);
  return { phase, ...value, durationMs: Date.now() - started, cache: status, reason: hit ? "forced-cold result matched cached artifact" : `no complete artifact for this content address; recomputed${movedIdentity ? `; identity changed: ${movedIdentity}` : ""}`, key };
}

export function assertMechanicalCacheVerification(
  phases: readonly MechanicalPhaseRecord[],
  mode: MechanicalCacheMode | undefined,
): void {
  if (mode !== "verify") return;
  const unverified = CACHEABLE_MECHANICAL_PHASES.flatMap((phase) => {
    const record = phases.find((candidate) => candidate.phase === phase);
    return record?.cache === "recomputed" ? [] : [`${phase}=${record?.cache ?? "missing"}`];
  });
  if (unverified.length > 0) {
    throw new Error(`forced-cold cache verification incomplete: ${unverified.join(", ")}. A miss may seed a later run, but this run compared no restored artifact for every deterministic phase and cannot claim equivalence`);
  }
}
