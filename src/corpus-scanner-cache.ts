import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { validateFindings, type Finding, type ReportMeta } from "./findings.js";
import { readEntriesSafe } from "./fs-walk.js";

export const CORPUS_CACHEABLE_SCANNERS = ["detect-static", "quality-scan", "mutation-detect-only"] as const;
export type CorpusCacheableScanner = (typeof CORPUS_CACHEABLE_SCANNERS)[number];
export type CorpusScannerCacheMode = "off" | "read-write" | "verify";
export type CorpusScannerCacheStatus = "hit" | "miss" | "recomputed" | "non-cacheable";

export interface CorpusScannerScope {
  unitsExamined: number;
  description: string;
}

interface CorpusScannerExecution {
  findings: Finding[];
  scope: CorpusScannerScope;
  completed: boolean;
  failure?: string;
}

export interface CorpusScannerCacheOptions {
  dir: string;
  mode: CorpusScannerCacheMode;
  scanner: CorpusCacheableScanner;
  targetRevision: string;
  targetTree: string;
  implementation: string;
  externalInputs: Record<string, string>;
  pathRoot?: string;
  onEvent?: (message: string) => void;
}

export interface CorpusScannerRecord {
  scanner: CorpusCacheableScanner;
  findings: Finding[];
  scope: CorpusScannerScope;
  cache: CorpusScannerCacheStatus;
  reason: string;
  key?: string;
}

interface ScannerIdentity {
  targetRevision: string;
  targetTree: string;
  implementation: string;
  externalInputs: Record<string, string>;
}

interface ScannerArtifact {
  schema: 2;
  scanner: CorpusCacheableScanner;
  key: string;
  identity: ScannerIdentity;
  payloadDigest: string;
  findings: Finding[];
  scope: CorpusScannerScope;
}

const TARGET_ROOT_TOKEN = "<CORPUS_TARGET_ROOT>";

function mapStrings<T>(value: T, map: (text: string) => string): T {
  if (typeof value === "string") return map(value) as T;
  if (Array.isArray(value)) return value.map((item) => mapStrings(item, map)) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, mapStrings(item, map)])) as T;
  }
  return value;
}

function canonicalizeTargetRoot<T>(value: T, pathRoot: string | undefined): T {
  if (!pathRoot) return value;
  const roots = [...new Set([pathRoot, realpathSync(pathRoot)])].sort((a, b) => b.length - a.length);
  return mapStrings(value, (text) => roots.reduce((current, root) => current.replaceAll(root, TARGET_ROOT_TOKEN), text));
}

function materializeTargetRoot<T>(value: T, pathRoot: string | undefined): T {
  if (!pathRoot) return value;
  return mapStrings(value, (text) => text.replaceAll(TARGET_ROOT_TOKEN, pathRoot));
}

const VALIDATION_META: ReportMeta = {
  client: "corpus scanner cache artifact",
  subtitle: "schema validation only",
  date: "1970-01-01",
  commit: "cache-artifact",
  auditor: "Harvey",
  confidential: true,
  overallHealth: 0,
  tenantIsolation: "not applicable",
  authModel: "not applicable",
  headline: "cache artifact validation",
  scope: "one corpus scanner result",
  methodology: "canonical Finding schema",
  outOfScope: "document metadata",
};

function stableCorpusValue(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableCorpusValue).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stableCorpusValue(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value: unknown): string {
  return createHash("sha256").update(stableCorpusValue(value)).digest("hex");
}

function validateArtifact(value: unknown, expected: Pick<ScannerArtifact, "scanner" | "key" | "identity">): ScannerArtifact {
  const artifact = value as Partial<ScannerArtifact>;
  if (artifact.schema !== 2 || artifact.scanner !== expected.scanner || artifact.key !== expected.key || stableCorpusValue(artifact.identity) !== stableCorpusValue(expected.identity)) {
    throw new Error("artifact identity/schema mismatch");
  }
  if (!Array.isArray(artifact.findings)) throw new Error("artifact findings are incomplete or malformed");
  const problems = artifact.findings.flatMap((finding) => validateFindings({ meta: VALIDATION_META, findings: [finding] }).errors.filter((error) => error.startsWith("findings[0]")));
  if (problems.length > 0) throw new Error(`artifact findings violate the normalized Finding schema: ${problems.join("; ")}`);
  if (!artifact.scope || !Number.isInteger(artifact.scope.unitsExamined) || artifact.scope.unitsExamined <= 0 || typeof artifact.scope.description !== "string" || artifact.scope.description.length === 0) {
    throw new Error("artifact examined-scope metadata is incomplete or zero");
  }
  if (artifact.payloadDigest !== digest({ findings: artifact.findings, scope: artifact.scope })) throw new Error("artifact payload checksum mismatch");
  return artifact as ScannerArtifact;
}

function closestChangedComponents(dir: string, scanner: CorpusCacheableScanner, identity: ScannerIdentity): string | undefined {
  const scannerDir = join(dir, "corpus-scanners", scanner);
  if (!existsSync(scannerDir)) return undefined;
  const current = new Map([
    ["targetRevision", identity.targetRevision],
    ["targetTree", identity.targetTree],
    ["implementation", identity.implementation],
    ...Object.entries(identity.externalInputs).map(([key, value]): [string, string] => [`externalInputs.${key}`, value]),
  ]);
  let closest: { matches: number; changed: string[] } | undefined;
  for (const entry of readEntriesSafe(scannerDir).entries.filter((entry) => !entry.isDirectory && entry.name.endsWith(".json"))) {
    try {
      const prior = (JSON.parse(readFileSync(join(scannerDir, entry.name), "utf8")) as Partial<ScannerArtifact>).identity;
      if (!prior) continue;
      const previous = new Map([
        ["targetRevision", prior.targetRevision],
        ["targetTree", prior.targetTree],
        ["implementation", prior.implementation],
        ...Object.entries(prior.externalInputs).map(([key, value]): [string, string] => [`externalInputs.${key}`, value]),
      ]);
      const names = [...new Set([...current.keys(), ...previous.keys()])].sort();
      const changed = names.filter((name) => current.get(name) !== previous.get(name));
      const matches = names.length - changed.length;
      if (changed.length > 0 && (!closest || matches > closest.matches)) closest = { matches, changed };
    } catch {
      continue;
    }
  }
  return closest?.changed.join(", ");
}

export async function executeCorpusScanner(
  options: CorpusScannerCacheOptions | undefined,
  execute: () => CorpusScannerExecution | Promise<CorpusScannerExecution>,
): Promise<CorpusScannerRecord> {
  if (!options || options.mode === "off") {
    const value = await execute();
    return { scanner: options?.scanner ?? "detect-static", findings: value.findings, scope: value.scope, cache: "non-cacheable", reason: value.failure ?? "corpus scanner cache disabled" };
  }
  if (Object.keys(options.externalInputs).length === 0) throw new Error(`${options.scanner}: no declared external-input identity`);
  const identity: ScannerIdentity = {
    targetRevision: digest(options.targetRevision),
    targetTree: digest(options.targetTree),
    implementation: digest(options.implementation),
    externalInputs: Object.fromEntries(Object.entries(options.externalInputs).sort(([a], [b]) => a.localeCompare(b)).map(([name, value]) => [name, digest(value)])),
  };
  const key = digest({ scanner: options.scanner, identity });
  const path = join(options.dir, "corpus-scanners", options.scanner, `${key}.json`);
  const expected = { scanner: options.scanner, key, identity };
  let hit: ScannerArtifact | undefined;
  if (existsSync(path)) {
    try {
      hit = validateArtifact(JSON.parse(readFileSync(path, "utf8")), expected);
    } catch (error) {
      options.onEvent?.(`CACHE REJECT ${options.scanner} ${key.slice(0, 12)}: ${error instanceof Error ? error.message : String(error)}; recomputing`);
      rmSync(path, { force: true });
    }
  }
  const moved = hit ? undefined : closestChangedComponents(options.dir, options.scanner, identity);
  if (hit && options.mode === "read-write") {
    options.onEvent?.(`CACHE HIT ${options.scanner} ${key.slice(0, 12)} (${hit.findings.length} finding(s), ${hit.scope.unitsExamined} unit(s))`);
    return { scanner: options.scanner, findings: materializeTargetRoot(hit.findings, options.pathRoot), scope: hit.scope, cache: "hit", reason: "complete content-addressed artifact", key };
  }
  const value = await execute();
  if (!value.completed) {
    const reason = value.failure ?? "scanner did not complete";
    options.onEvent?.(`CACHE BYPASS ${options.scanner}: ${reason}; incomplete output was not stored`);
    return { scanner: options.scanner, findings: value.findings, scope: value.scope, cache: "non-cacheable", reason, key };
  }
  if (!Number.isInteger(value.scope.unitsExamined) || value.scope.unitsExamined <= 0) throw new Error(`${options.scanner}: examined scope must be a positive integer`);
  const canonicalFindings = canonicalizeTargetRoot(value.findings, options.pathRoot);
  if (hit && stableCorpusValue({ findings: hit.findings, scope: hit.scope }) !== stableCorpusValue({ findings: canonicalFindings, scope: value.scope })) {
    throw new Error(`${options.scanner}: forced-cold result differs from cached findings or examined scope for ${key}`);
  }
  const artifact: ScannerArtifact = { schema: 2, ...expected, payloadDigest: digest({ findings: canonicalFindings, scope: value.scope }), findings: canonicalFindings, scope: value.scope };
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  writeFileSync(temp, `${JSON.stringify(artifact, null, 2)}\n`);
  renameSync(temp, path);
  validateArtifact(JSON.parse(readFileSync(path, "utf8")), expected);
  options.onEvent?.(`CACHE ${hit ? "VERIFY" : "MISS"} ${options.scanner} ${key.slice(0, 12)}: ${hit ? "cold result matches" : "stored and reread"}${moved ? `; identity changed: ${moved}` : ""}`);
  return { scanner: options.scanner, findings: value.findings, scope: value.scope, cache: hit ? "recomputed" : "miss", reason: hit ? "forced-cold result matched cached artifact" : `no complete artifact; recomputed${moved ? `; identity changed: ${moved}` : ""}`, key };
}

export function assertCorpusScannerCacheVerification(records: readonly CorpusScannerRecord[], mode: CorpusScannerCacheMode): void {
  if (mode !== "verify") return;
  const unverified = records.filter((record) => record.cache !== "recomputed").map((record) => `${record.scanner}=${record.cache}`);
  if (unverified.length > 0) throw new Error(`forced-cold corpus scanner verification incomplete: ${unverified.join(", ")}. A miss may seed a later run but cannot claim equivalence`);
}
