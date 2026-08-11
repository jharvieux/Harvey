import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Finding } from "../findings.js";
import { readRecursiveSafe, statSafe } from "../fs-walk.js";

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

interface CacheArtifact {
  schema: 1;
  phase: MechanicalPhase;
  key: string;
  targetRevision: string;
  targetTree: string;
  payloadDigest: string;
  findings: Finding[];
  scope: MechanicalPhaseScope;
}

const CACHEABILITY: Record<MechanicalPhase, { cacheable: boolean; reason: string }> = {
  "secrets-history": { cacheable: true, reason: "target tree/history, implementation/config, and scanner binary versions are reproducibly keyed" },
  "dependency-advisory": { cacheable: false, reason: "OSV and npm registry/advisory responses have no immutable response identity on this path" },
  semgrep: { cacheable: true, reason: "resolved registry packs, local rules, implementation, target tree, and Semgrep version are keyed" },
  configuration: { cacheable: true, reason: "in-process configuration checks depend only on the keyed target tree and implementation" },
  "structural-ast": { cacheable: true, reason: "in-process structural/AST checks depend only on the keyed target tree, options, runtime, and implementation" },
  normalization: { cacheable: false, reason: "cheap composition step consumes this run's cacheable and live advisory outputs" },
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

export function digestFiles(paths: readonly string[]): string {
  const parts: (string | Buffer)[] = [];
  for (const path of [...paths].sort()) {
    if (!existsSync(path)) throw new Error(`mechanical phase implementation input missing: ${path}`);
    parts.push(path, readFileSync(path));
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
  } catch {
    return digestTree(dir, (path) => !path.split("/").includes("node_modules"));
  }
}

function isFinding(value: unknown): value is Finding {
  if (!value || typeof value !== "object") return false;
  const row = value as Record<string, unknown>;
  return ["id", "title", "severity", "confidence", "taxonomy", "location", "evidence", "impact", "fix"].every((k) => typeof row[k] === "string")
    && ["value", "ease", "safety"].every((k) => typeof row[k] === "number");
}

function parseArtifact(text: string, expected: Pick<CacheArtifact, "schema" | "phase" | "key" | "targetRevision" | "targetTree">): CacheArtifact {
  const value = JSON.parse(text) as Partial<CacheArtifact>;
  if (value.schema !== 1 || value.phase !== expected.phase || value.key !== expected.key || value.targetRevision !== expected.targetRevision || value.targetTree !== expected.targetTree) {
    throw new Error("artifact identity/schema mismatch");
  }
  if (!Array.isArray(value.findings) || !value.findings.every(isFinding)) throw new Error("artifact findings are incomplete or malformed");
  if (!value.scope || !Number.isInteger(value.scope.unitsExamined) || value.scope.unitsExamined <= 0 || typeof value.scope.description !== "string" || value.scope.description.length === 0) {
    throw new Error("artifact examined-scope metadata is incomplete or zero");
  }
  const payloadDigest = digestParts([stable({ findings: value.findings, scope: value.scope })]);
  if (value.payloadDigest !== payloadDigest) throw new Error("artifact payload checksum mismatch");
  return value as CacheArtifact;
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
  const key = digestParts([stable({ phase, implementation, externalInputs, targetRevision: cache.targetRevision, targetTree: cache.targetTree })]);
  const path = join(cache.dir, phase, `${key}.json`);
  const expected = { schema: 1 as const, phase, key, targetRevision: cache.targetRevision, targetTree: cache.targetTree };
  let hit: CacheArtifact | undefined;
  if (existsSync(path)) {
    try {
      hit = parseArtifact(readFileSync(path, "utf8"), expected);
    } catch (error) {
      cache.onEvent?.(`CACHE REJECT ${phase} ${key.slice(0, 12)}: ${error instanceof Error ? error.message : String(error)}; recomputing`);
      rmSync(path, { force: true });
    }
  }
  if (hit && cache.mode === "read-write") {
    cache.onEvent?.(`CACHE HIT ${phase} ${key.slice(0, 12)} (${hit.findings.length} finding(s), ${hit.scope.unitsExamined} unit(s))`);
    return { phase, findings: hit.findings, scope: hit.scope, durationMs: Date.now() - started, cache: "hit", reason: policy.reason, key };
  }
  const value = await execute();
  if (!Number.isInteger(value.scope.unitsExamined) || value.scope.unitsExamined <= 0) throw new Error(`${phase}: examined scope must be a positive integer`);
  if (hit && !equivalent(value, { findings: hit.findings, scope: hit.scope })) throw new Error(`${phase}: forced-cold result differs from cached findings or examined scope for ${key}`);
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  const payloadDigest = digestParts([stable(value)]);
  writeFileSync(temp, `${JSON.stringify({ ...expected, payloadDigest, ...value }, null, 2)}\n`);
  renameSync(temp, path);
  const reread = parseArtifact(readFileSync(path, "utf8"), expected);
  if (!equivalent(value, { findings: reread.findings, scope: reread.scope })) throw new Error(`${phase}: artifact changed during write/read equivalence check`);
  const status: MechanicalCacheStatus = hit ? "recomputed" : "miss";
  cache.onEvent?.(`CACHE ${hit ? "VERIFY" : "MISS"} ${phase} ${key.slice(0, 12)}: cold result ${hit ? "matches" : "stored and reread from"} artifact`);
  return { phase, ...value, durationMs: Date.now() - started, cache: status, reason: hit ? "forced-cold result matched cached artifact" : "no complete artifact for this content address; recomputed", key };
}
