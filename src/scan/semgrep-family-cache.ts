import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { readRecursiveSafe } from "../fs-walk.js";
import type { SemgrepOutput } from "./semgrep.js";
import type { MechanicalCacheMode } from "./mechanical-phase-cache.js";

export interface SemgrepFamily {
  id: string;
  configPath: string;
}

export interface SemgrepFamilyCacheOptions {
  dir: string;
  mode: MechanicalCacheMode;
  targetRevision: string;
  targetTree: string;
  implementation: string;
  externalInputs: Record<string, string>;
  pathRoot?: string;
  onEvent?: (message: string) => void;
}

export interface SemgrepFamilyRecord {
  family: string;
  output: SemgrepOutput;
  cache: "hit" | "miss" | "recomputed";
  key: string;
  unitsExamined: number;
}

interface FamilyIdentity {
  targetRevision: string;
  targetTree: string;
  implementation: string;
  rules: string;
  externalInputs: Record<string, string>;
}

interface FamilyArtifact {
  schema: 3;
  family: string;
  key: string;
  identity: FamilyIdentity;
  payloadDigest: string;
  unitsExamined: number;
  output: SemgrepOutput;
}

const TARGET_ROOT_TOKEN = "<SEMGREP_TARGET_ROOT>";
const CACHE_ROOT_TOKEN = "<SEMGREP_CACHE_ROOT>";

function mapStrings<T>(value: T, map: (text: string) => string): T {
  if (typeof value === "string") return map(value) as T;
  if (Array.isArray(value)) return value.map((item) => mapStrings(item, map)) as T;
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, mapStrings(item, map)])) as T;
  return value;
}

function canonicalizeRoot<T>(value: T, pathRoot: string | undefined, token: string): T {
  if (!pathRoot) return value;
  const roots = [...new Set([pathRoot, realpathSync(pathRoot)])].sort((a, b) => b.length - a.length);
  return mapStrings(value, (text) => roots.reduce((current, root) => current.replaceAll(root, token), text));
}

function materializeRoot<T>(value: T, pathRoot: string | undefined, token: string): T {
  if (!pathRoot) return value;
  return mapStrings(value, (text) => text.replaceAll(token, pathRoot));
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function digest(value: unknown): string {
  return createHash("sha256").update(stable(value)).digest("hex");
}

function familyDirectory(id: string): string {
  return id.replaceAll(/[^a-zA-Z0-9.-]/g, "_");
}

function validateOutput(output: unknown): asserts output is SemgrepOutput {
  if (!output || typeof output !== "object") throw new Error("artifact output is missing");
  const value = output as SemgrepOutput;
  if (value.results !== undefined && !Array.isArray(value.results)) throw new Error("artifact results are malformed");
  if (value.errors !== undefined && !Array.isArray(value.errors)) throw new Error("artifact errors are malformed");
  if (!value.paths || !Array.isArray(value.paths.scanned) || !Array.isArray(value.paths.skipped)) throw new Error("artifact examined-path scope is incomplete");
  if (!value.time || !Array.isArray(value.time.rules)) throw new Error("artifact executed-rule scope is incomplete");
}

function parseArtifact(value: unknown, expected: Pick<FamilyArtifact, "family" | "key" | "identity">): FamilyArtifact {
  const artifact = value as Partial<FamilyArtifact>;
  if (artifact.schema !== 3 || artifact.family !== expected.family || artifact.key !== expected.key || stable(artifact.identity) !== stable(expected.identity)) {
    throw new Error("artifact identity/schema mismatch");
  }
  validateOutput(artifact.output);
  if (!Number.isInteger(artifact.unitsExamined) || artifact.unitsExamined! <= 0) throw new Error("artifact examined scope is zero or malformed");
  if (artifact.payloadDigest !== digest({ output: artifact.output, unitsExamined: artifact.unitsExamined })) throw new Error("artifact payload checksum mismatch");
  return artifact as FamilyArtifact;
}

export function assertSemgrepFamilyPlan(families: readonly SemgrepFamily[], expectedConfigs: readonly string[]): void {
  const ids = families.map((family) => family.id);
  const configs = families.map((family) => family.configPath);
  const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index);
  const duplicateConfigs = configs.filter((config, index) => configs.indexOf(config) !== index);
  const omitted = expectedConfigs.filter((config) => !configs.includes(config));
  const unregistered = configs.filter((config) => !expectedConfigs.includes(config));
  if (duplicateIds.length > 0 || duplicateConfigs.length > 0 || omitted.length > 0 || unregistered.length > 0) {
    throw new Error(`Semgrep family registry is not exhaustive/disjoint: duplicate ids [${duplicateIds.join(", ")}], duplicate configs [${duplicateConfigs.join(", ")}], omitted [${omitted.join(", ")}], unregistered [${unregistered.join(", ")}]`);
  }
}

export function rejectUnregisteredSemgrepFamilyArtifacts(options: SemgrepFamilyCacheOptions, registered: ReadonlySet<string>): void {
  const root = join(options.dir, "semgrep-families");
  if (!existsSync(root)) return;
  for (const relative of readRecursiveSafe(root).filter((path) => path.endsWith(".json"))) {
    const path = join(root, relative);
    try {
      const family = (JSON.parse(readFileSync(path, "utf8")) as Partial<FamilyArtifact>).family;
      if (typeof family !== "string" || !registered.has(family)) {
        options.onEvent?.(`CACHE REJECT semgrep family ${family ?? "(missing)"}: artifact is unregistered; removing before recompute`);
        rmSync(path, { force: true });
      }
    } catch (error) {
      options.onEvent?.(`CACHE REJECT semgrep family artifact ${relative}: ${error instanceof Error ? error.message : String(error)}; removing before recompute`);
      rmSync(path, { force: true });
    }
  }
}

export async function executeSemgrepFamily(
  family: SemgrepFamily,
  options: SemgrepFamilyCacheOptions,
  execute: () => SemgrepOutput | Promise<SemgrepOutput>,
): Promise<SemgrepFamilyRecord> {
  mkdirSync(options.dir, { recursive: true });
  const identity: FamilyIdentity = {
    targetRevision: digest(options.targetRevision),
    targetTree: digest(options.targetTree),
    implementation: digest(options.implementation),
    rules: digest(readFileSync(family.configPath)),
    externalInputs: Object.fromEntries(Object.entries(options.externalInputs).sort(([a], [b]) => a.localeCompare(b)).map(([name, value]) => [name, digest(value)])),
  };
  const key = digest({ family: family.id, identity });
  const path = join(options.dir, "semgrep-families", familyDirectory(family.id), `${key}.json`);
  const expected = { family: family.id, key, identity };
  let hit: FamilyArtifact | undefined;
  if (existsSync(path)) {
    try {
      hit = parseArtifact(JSON.parse(readFileSync(path, "utf8")), expected);
    } catch (error) {
      options.onEvent?.(`CACHE REJECT semgrep family ${family.id} ${key.slice(0, 12)}: ${error instanceof Error ? error.message : String(error)}; recomputing`);
      rmSync(path, { force: true });
    }
  }
  if (hit && options.mode === "read-write") {
    options.onEvent?.(`CACHE HIT semgrep family ${family.id} ${key.slice(0, 12)} (${hit.output.results?.length ?? 0} result(s), ${hit.unitsExamined} unit(s))`);
    const output = materializeRoot(materializeRoot(hit.output, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN);
    return { family: family.id, output, cache: "hit", key, unitsExamined: hit.unitsExamined };
  }
  const output = await execute();
  validateOutput(output);
  const canonicalOutput = canonicalizeSemgrepOutput(
    canonicalizeRoot(canonicalizeRoot(output, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN),
  );
  // A materialized registry pack can contain no rule applicable to this target. Semgrep then
  // reports zero scanned paths even though it did make one checkable applicability decision for
  // this exact config. Count that config decision as the unit instead of turning the exhaustive
  // partition into SEM-00 and silently abandoning every later family.
  const unitsExamined = Math.max(1, new Set(output.paths!.scanned).size);
  if (hit && stable(hit.output) !== stable(canonicalOutput)) throw new Error(`Semgrep family ${family.id}: forced-cold output differs from cached artifact ${key}`);
  const artifact: FamilyArtifact = { schema: 3, ...expected, payloadDigest: digest({ output: canonicalOutput, unitsExamined }), unitsExamined, output: canonicalOutput };
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  writeFileSync(temp, `${JSON.stringify(artifact, null, 2)}\n`);
  renameSync(temp, path);
  parseArtifact(JSON.parse(readFileSync(path, "utf8")), expected);
  options.onEvent?.(`CACHE ${hit ? "VERIFY" : "MISS"} semgrep family ${family.id} ${key.slice(0, 12)}: ${hit ? "cold output matches" : "stored and reread"}`);
  return { family: family.id, output: materializeRoot(materializeRoot(canonicalOutput, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN), cache: hit ? "recomputed" : "miss", key, unitsExamined };
}

export function assertSemgrepFamilyVerification(records: readonly SemgrepFamilyRecord[], families: readonly SemgrepFamily[], mode: MechanicalCacheMode): void {
  const recorded = records.map((record) => record.family);
  const missing = families.map((family) => family.id).filter((id) => !recorded.includes(id));
  const duplicates = recorded.filter((id, index) => recorded.indexOf(id) !== index);
  if (missing.length > 0 || duplicates.length > 0) throw new Error(`Semgrep family execution incomplete: missing [${missing.join(", ")}], duplicated [${duplicates.join(", ")}]`);
  if (mode === "verify") {
    const unverified = records.filter((record) => record.cache !== "recomputed").map((record) => `${record.family}=${record.cache}`);
    if (unverified.length > 0) throw new Error(`forced-cold Semgrep family verification incomplete: ${unverified.join(", ")}`);
  }
}

function uniqueSorted<T>(items: readonly T[]): T[] {
  return [...new Map(items.map((item) => [stable(item), item])).entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, item]) => item);
}

function stableRuleId(checkId: string): string {
  const registry = checkId.replace(/^.*?\.registry-packs\.[^.]+\./, "");
  if (registry !== checkId) return registry;
  const local = checkId.replace(/^.*?src\.scan\.rules\.semgrep\./, "");
  // A monolithic load of CUSTOM_RULES namespaces Harvey's local ids by the config directory.
  // Single-file family loads return the same ids bare. Rebuild the established monolithic
  // namespace for stable client taxonomy and corpus pairing.
  return local.startsWith("harvey-") ? `src.scan.rules.semgrep.${local}` : local;
}

export function mergeSemgrepFamilyOutputs(records: readonly SemgrepFamilyRecord[]): SemgrepOutput {
  const errors = uniqueSorted(records.flatMap((record) => record.output.errors ?? []));
  const errorsByPath = [...new Map(errors.map((error) => [error.path ?? stable(error), error])).values()];
  const skipped = uniqueSorted(records.flatMap((record) => record.output.paths?.skipped ?? []));
  const scanned = new Set(records.flatMap((record) => record.output.paths?.scanned ?? []));
  for (const error of errorsByPath) if (error.path) scanned.add(error.path);
  return canonicalizeSemgrepOutput({
    results: uniqueSorted(records.flatMap((record) => record.output.results ?? [])),
    errors: errorsByPath,
    paths: {
      scanned: [...scanned].sort(),
      skipped,
    },
    time: { rules: [...new Set(records.flatMap((record) => record.output.time?.rules ?? []))].sort() },
  });
}

export function canonicalizeSemgrepOutput(output: SemgrepOutput): SemgrepOutput {
  return {
    // Registry packs overlap. Separate invocations give the same logical rule a different
    // config-path namespace, while a monolithic invocation loads it once. Remove only Harvey's
    // generated materialization/local-directory prefix so the family merge deduplicates the same
    // logical match the same way as Semgrep's monolithic loader.
    results: uniqueSorted((output.results ?? []).map((result) => ({ ...result, check_id: stableRuleId(result.check_id) }))),
    errors: uniqueSorted(output.errors ?? []),
    paths: {
      scanned: [...new Set(output.paths?.scanned ?? [])].sort(),
      skipped: uniqueSorted(output.paths?.skipped ?? []),
    },
    time: { rules: [...new Set(output.time?.rules ?? [])].sort() },
  };
}
