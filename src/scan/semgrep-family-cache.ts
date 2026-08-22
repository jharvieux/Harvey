import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { readRecursiveSafe } from "../fs-walk.js";
import type { SemgrepOutput } from "./semgrep.js";
import { canonicalizeSemgrepTime, type SemgrepFixpointTimeout } from "./semgrep-time.js";
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
  execution?: SemgrepFamilyExecutionReceipt;
}

export interface SemgrepCommandSemanticReceipt {
  status: "succeeded";
  attempt: number;
  argv: string[];
  loadedRuleIds: string[];
  resultsSha256: string;
  scanned: string[];
  skipped: NonNullable<NonNullable<SemgrepOutput["paths"]>["skipped"]>;
  skippedRules: unknown[];
  errors: NonNullable<SemgrepOutput["errors"]>;
  fixpointTimeouts: SemgrepFixpointTimeout[];
  semanticSha256: string;
}

export interface SemgrepFamilyExecutionReceipt {
  ordinal: number;
  id: string;
  familyId: string;
  sourceKind: "registry-pack" | "local-config";
  sourceId: string;
  configSha256: string;
  ruleIds: string[];
  ownedRuleIds: string[];
  loadedRuleIds: string[];
  excludedRuleIds: string[];
  sourceConfigSha256: string;
  semanticObjectSha256?: string;
  argv: string[];
  verification: "single" | "paired-cold-exact";
  status: "succeeded";
  attempts: SemgrepCommandSemanticReceipt[];
}

export type SemgrepPlannedFamilyReceipt = Omit<SemgrepFamilyExecutionReceipt, "loadedRuleIds" | "status" | "attempts">;

export interface SemgrepPlannedExecutionReceipt {
  schema: 4;
  strategy: "globally-owned-partitioned-families";
  ownershipSha256: string;
  families: SemgrepPlannedFamilyReceipt[];
}

export interface SemgrepExecutionPlanReceipt {
  schema: 4;
  status: "succeeded";
  strategy: "globally-owned-partitioned-families";
  ownershipSha256: string;
  families: SemgrepFamilyExecutionReceipt[];
}

export function assertSuccessfulSemgrepExecutionReceipt(value: unknown): asserts value is SemgrepExecutionPlanReceipt {
  const receipt = value as Partial<SemgrepExecutionPlanReceipt>;
  if (!receipt || receipt.schema !== 4 || receipt.status !== "succeeded"
    || receipt.strategy !== "globally-owned-partitioned-families" || !/^[a-f0-9]{64}$/.test(receipt.ownershipSha256 ?? "")
    || !Array.isArray(receipt.families) || receipt.families.length === 0) {
    throw new Error("successful Semgrep semantic execution receipt is missing, failed, or malformed");
  }
  receipt.families.forEach((family, ordinal) => {
    if (family.ordinal !== ordinal) throw new Error("Semgrep semantic execution receipt family ordinal is malformed");
    assertSuccessfulSemgrepFamilyExecutionReceipt(family, family.id);
  });
  const owned = receipt.families.flatMap((family) => family.ownedRuleIds);
  const duplicates = owned.filter((id, index) => owned.indexOf(id) !== index);
  if (duplicates.length > 0) throw new Error(`Semgrep semantic execution receipt has duplicate global ownership: ${[...new Set(duplicates)].join(", ")}`);
  const ownership = receipt.families.map(({ ordinal, id, sourceKind, sourceId, sourceConfigSha256, configSha256, ownedRuleIds, excludedRuleIds, semanticObjectSha256, verification }) => ({ ordinal, id, sourceKind, sourceId, sourceConfigSha256, configSha256, ownedRuleIds, excludedRuleIds, semanticObjectSha256, verification }));
  if (receipt.ownershipSha256 !== digest(ownership)) throw new Error("Semgrep semantic execution receipt ownership digest is invalid");
}

export interface SemgrepDiagnosticEvidence {
  schema: 2;
  errors: NonNullable<SemgrepOutput["errors"]>;
  skipped: NonNullable<NonNullable<SemgrepOutput["paths"]>["skipped"]>;
  fixpointTimeouts: SemgrepFixpointTimeout[];
  sha256: string;
}

interface FamilyIdentity {
  targetRevision: string;
  targetTree: string;
  implementation: string;
  rules: string;
  externalInputs: Record<string, string>;
}

interface FamilyArtifact {
  schema: 4;
  family: string;
  key: string;
  identity: FamilyIdentity;
  payloadDigest: string;
  unitsExamined: number;
  output: SemgrepOutput;
  execution: SemgrepFamilyExecutionReceipt;
}

const TARGET_ROOT_TOKEN = "<SEMGREP_TARGET_ROOT>";
const CACHE_ROOT_TOKEN = "<SEMGREP_CACHE_ROOT>";
const SEMGREP_YAML_EXTENSIONS = new Set([".yml", ".yaml"]);

/** The execution-side loader: all local YAML configs Semgrep accepts, including nested configs. */
export function discoverLocalSemgrepFamilies(root: string): SemgrepFamily[] {
  return readRecursiveSafe(root)
    .filter((relative) => SEMGREP_YAML_EXTENSIONS.has(extname(relative).toLowerCase()))
    .sort()
    .map((relative) => ({
      id: `local-${relative.replaceAll(/[^a-zA-Z0-9.-]/g, "-").replace(/\.(?:yml|yaml)$/i, "")}`,
      configPath: join(root, relative),
    }));
}

/** Independent source-like yardstick: never derive expected configs from the execution loader. */
export function localSemgrepConfigYardstick(root: string): string[] {
  return readRecursiveSafe(root)
    .filter((relative) => /(?:^|\/)[^/]+\.(?:yml|yaml)$/i.test(relative))
    .sort()
    .map((relative) => join(root, relative));
}

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
  canonicalizeSemgrepTime(value.time);
}

export function assertSuccessfulSemgrepFamilyExecutionReceipt(value: unknown, family: string): asserts value is SemgrepFamilyExecutionReceipt {
  const receipt = value as Partial<SemgrepFamilyExecutionReceipt>;
  if (!receipt || receipt.status !== "succeeded" || receipt.familyId !== family || receipt.id !== family
    || !Number.isInteger(receipt.ordinal) || receipt.ordinal! < 0
    || (receipt.sourceKind !== "registry-pack" && receipt.sourceKind !== "local-config")
    || typeof receipt.sourceId !== "string" || receipt.sourceId.length === 0
    || !/^[a-f0-9]{64}$/.test(receipt.configSha256 ?? "") || !/^[a-f0-9]{64}$/.test(receipt.sourceConfigSha256 ?? "")
    || (receipt.semanticObjectSha256 !== undefined && !/^[a-f0-9]{64}$/.test(receipt.semanticObjectSha256))
    || !Array.isArray(receipt.argv) || receipt.argv.length === 0
    || (receipt.verification !== "single" && receipt.verification !== "paired-cold-exact")
    || !Array.isArray(receipt.ruleIds) || !Array.isArray(receipt.ownedRuleIds) || !Array.isArray(receipt.loadedRuleIds) || !Array.isArray(receipt.excludedRuleIds)
    || [...receipt.ruleIds, ...receipt.ownedRuleIds, ...receipt.loadedRuleIds, ...receipt.excludedRuleIds].some((id) => typeof id !== "string" || id.length === 0)
    || new Set(receipt.ownedRuleIds).size !== receipt.ownedRuleIds.length || new Set(receipt.loadedRuleIds).size !== receipt.loadedRuleIds.length
    || receipt.loadedRuleIds.some((id) => !receipt.ownedRuleIds!.includes(id))
    || !Array.isArray(receipt.attempts) || receipt.attempts.length !== (receipt.verification === "paired-cold-exact" ? 2 : 1)
    || receipt.attempts.some((attempt, ordinal) => attempt.status !== "succeeded" || attempt.attempt !== ordinal + 1
      || !Array.isArray(attempt.argv) || !Array.isArray(attempt.loadedRuleIds) || !Array.isArray(attempt.scanned)
      || !Array.isArray(attempt.skipped) || !Array.isArray(attempt.skippedRules) || !Array.isArray(attempt.errors)
      || !Array.isArray(attempt.fixpointTimeouts) || !/^[a-f0-9]{64}$/.test(attempt.resultsSha256 ?? "")
      || !/^[a-f0-9]{64}$/.test(attempt.semanticSha256 ?? "")
      || attempt.semanticSha256 !== digest({
        argv: attempt.argv,
        loadedRuleIds: attempt.loadedRuleIds,
        resultsSha256: attempt.resultsSha256,
        scanned: attempt.scanned,
        skipped: attempt.skipped,
        skippedRules: attempt.skippedRules,
        errors: attempt.errors,
        fixpointTimeouts: attempt.fixpointTimeouts,
      }))) {
    throw new Error("artifact successful semantic execution receipt is missing, failed, or malformed");
  }
  if (stable(receipt.ruleIds) !== stable(receipt.ownedRuleIds)
    || stable(receipt.loadedRuleIds) !== stable(receipt.attempts[0]!.loadedRuleIds)
    || stable(receipt.argv) !== stable(receipt.attempts[0]!.argv)
    || receipt.attempts.some((attempt) => stable(attempt.loadedRuleIds) !== stable(receipt.loadedRuleIds)
      || stable(attempt.argv) !== stable(receipt.argv))) {
    throw new Error("artifact semantic execution receipt population differs from its actual attempts");
  }
  if (receipt.verification === "paired-cold-exact") {
    const comparable = receipt.attempts.map((attempt) => Object.fromEntries(Object.entries(attempt).filter(([key]) => key !== "attempt")));
    if (stable(comparable[0]) !== stable(comparable[1])) throw new Error("artifact paired-cold semantic execution attempts differ");
  }
}

function assertExecutionMatchesOutput(execution: SemgrepFamilyExecutionReceipt, output: SemgrepOutput, canonicalStorage = true): void {
  const canonical = canonicalStorage ? canonicalizeSemgrepOutput(output) : output;
  const mappedLoaded = canonicalizeSemgrepTime(canonical.time).rules.map((checkId) => {
    const matches = execution.ownedRuleIds.filter((ruleId) => checkId === ruleId || checkId.endsWith(`.${ruleId}`));
    if (matches.length !== 1) throw new Error(`artifact executed rule ${checkId} has ${matches.length} owners in its bound receipt`);
    return matches[0]!;
  });
  const expected = {
    loadedRuleIds: [...new Set(mappedLoaded)].sort(),
    resultsSha256: digest([...(canonical.results ?? [])].map((result) => ({ ...result, check_id: stableRuleId(result.check_id) })).sort((left, right) => stable(left).localeCompare(stable(right)))),
    scanned: canonical.paths?.scanned ?? [],
    skipped: canonical.paths?.skipped ?? [],
    skippedRules: canonical.skipped_rules ?? [],
    errors: canonical.errors ?? [],
    fixpointTimeouts: canonicalStorage
      ? canonicalizeSemgrepTime(canonical.time).fixpoint_timeouts
      : (canonical.time?.fixpoint_timeouts ?? []) as SemgrepFixpointTimeout[],
  };
  for (const attempt of execution.attempts) {
    const actual = {
      loadedRuleIds: attempt.loadedRuleIds,
      resultsSha256: attempt.resultsSha256,
      scanned: attempt.scanned,
      skipped: attempt.skipped,
      skippedRules: attempt.skippedRules,
      errors: attempt.errors,
      fixpointTimeouts: attempt.fixpointTimeouts,
    };
    if (stable(actual) !== stable(expected)) {
      const fields = (Object.keys(expected) as Array<keyof typeof expected>).filter((field) => stable(actual[field]) !== stable(expected[field]));
      throw new Error(`artifact semantic execution receipt differs from its stored output: ${fields.join(", ")}`);
    }
  }
}

function rehashExecutionReceipt(receipt: SemgrepFamilyExecutionReceipt, output?: SemgrepOutput): SemgrepFamilyExecutionReceipt {
  const canonical = output ? canonicalizeSemgrepOutput(output) : undefined;
  return {
    ...receipt,
    attempts: receipt.attempts.map((attempt) => {
      const semantic = {
        argv: attempt.argv,
        loadedRuleIds: attempt.loadedRuleIds,
        resultsSha256: canonical ? digest(canonical.results ?? []) : attempt.resultsSha256,
        scanned: canonical?.paths?.scanned ?? attempt.scanned,
        skipped: canonical?.paths?.skipped ?? attempt.skipped,
        skippedRules: canonical?.skipped_rules ?? attempt.skippedRules,
        errors: canonical?.errors ?? attempt.errors,
        fixpointTimeouts: canonical ? canonicalizeSemgrepTime(canonical.time).fixpoint_timeouts : attempt.fixpointTimeouts,
      };
      return { ...attempt, ...semantic, semanticSha256: digest(semantic) };
    }),
  };
}

function parseArtifact(value: unknown, expected: Pick<FamilyArtifact, "family" | "key" | "identity"> & { configSha256: string }): FamilyArtifact {
  const artifact = value as Partial<FamilyArtifact>;
  if (artifact.schema !== 4 || artifact.family !== expected.family || artifact.key !== expected.key || stable(artifact.identity) !== stable(expected.identity)) {
    throw new Error("artifact identity/schema mismatch");
  }
  validateOutput(artifact.output);
  assertSuccessfulSemgrepFamilyExecutionReceipt(artifact.execution, expected.family);
  if (artifact.execution!.configSha256 !== expected.configSha256) throw new Error("artifact semantic execution config hash differs from its cache identity");
  assertExecutionMatchesOutput(artifact.execution!, artifact.output!);
  if (!Number.isInteger(artifact.unitsExamined) || artifact.unitsExamined! <= 0) throw new Error("artifact examined scope is zero or malformed");
  if (artifact.payloadDigest !== digest({ output: artifact.output, unitsExamined: artifact.unitsExamined, execution: artifact.execution })) throw new Error("artifact payload checksum mismatch");
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
  execute: () => { output: SemgrepOutput; execution: SemgrepFamilyExecutionReceipt } | Promise<{ output: SemgrepOutput; execution: SemgrepFamilyExecutionReceipt }>,
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
  const configSha256 = createHash("sha256").update(readFileSync(family.configPath)).digest("hex");
  const expected = { family: family.id, key, identity, configSha256 };
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
    return { family: family.id, output, cache: "hit", key, unitsExamined: hit.unitsExamined, execution: hit.execution };
  }
  const executed = await execute();
  const { output, execution } = executed;
  validateOutput(output);
  assertSuccessfulSemgrepFamilyExecutionReceipt(execution, family.id);
  const receiptOutput = canonicalizeSemgrepOutput(canonicalizeRoot(canonicalizeRoot(output, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN));
  const receiptExecution = canonicalizeRoot(canonicalizeRoot(execution, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN);
  try {
    assertExecutionMatchesOutput(receiptExecution, receiptOutput);
  } catch (canonicalError) {
    // Test doubles and older direct callers may already share one materialized root. Accept that
    // representation only before storage; every stored receipt below is rebound to portable bytes.
    try { assertExecutionMatchesOutput(execution, output, false); } catch { throw canonicalError; }
  }
  const canonicalOutput = canonicalizeSemgrepOutput(
    canonicalizeRoot(canonicalizeRoot(output, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN),
  );
  // A materialized registry pack can contain no rule applicable to this target. Semgrep then
  // reports zero scanned paths even though it did make one checkable applicability decision for
  // this exact config. Count that config decision as the unit instead of turning the exhaustive
  // partition into SEM-00 and silently abandoning every later family.
  const unitsExamined = Math.max(1, new Set(output.paths!.scanned).size);
  if (hit && stable(hit.output) !== stable(canonicalOutput)) throw new Error(`Semgrep family ${family.id}: forced-cold output differs from cached artifact ${key}`);
  const canonicalExecution = rehashExecutionReceipt(
    canonicalizeRoot(canonicalizeRoot(execution, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN),
    canonicalOutput,
  );
  assertSuccessfulSemgrepFamilyExecutionReceipt(canonicalExecution, family.id);
  if (canonicalExecution.configSha256 !== configSha256) throw new Error(`Semgrep family ${family.id}: execution config hash differs from the content-addressed config`);
  assertExecutionMatchesOutput(canonicalExecution, canonicalOutput);
  const artifact: FamilyArtifact = { schema: 4, family: family.id, key, identity, payloadDigest: digest({ output: canonicalOutput, unitsExamined, execution: canonicalExecution }), unitsExamined, output: canonicalOutput, execution: canonicalExecution };
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  writeFileSync(temp, `${JSON.stringify(artifact, null, 2)}\n`);
  renameSync(temp, path);
  parseArtifact(JSON.parse(readFileSync(path, "utf8")), expected);
  options.onEvent?.(`CACHE ${hit ? "VERIFY" : "MISS"} semgrep family ${family.id} ${key.slice(0, 12)}: ${hit ? "cold output matches" : "stored and reread"}`);
  return {
    family: family.id,
    output: materializeRoot(materializeRoot(canonicalOutput, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN),
    cache: hit ? "recomputed" : "miss",
    key,
    unitsExamined,
    execution: canonicalExecution,
  };
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

function uniqueAcrossFamilies<T>(records: readonly SemgrepFamilyRecord[], select: (record: SemgrepFamilyRecord) => readonly T[]): T[] {
  const seenInPriorFamilies = new Set<string>();
  const kept: T[] = [];
  for (const record of records) {
    const items = select(record);
    for (const item of items) if (!seenInPriorFamilies.has(stable(item))) kept.push(item);
    for (const item of items) seenInPriorFamilies.add(stable(item));
  }
  return kept;
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
  // A path is not an error identity. Semgrep can emit several structurally distinct diagnostics
  // for one file (including multiple PartialParsing records). Preserve the deterministic family
  // traversal order and remove only content-identical cross-family duplicates. The old path-keyed
  // Map silently discarded inbox-zero's second line-42 diagnostic while keeping the count-bearing
  // cache artifact internally valid.
  const errors = uniqueAcrossFamilies(records, (record) => record.output.errors ?? []);
  const skipped = uniqueAcrossFamilies(records, (record) => record.output.paths?.skipped ?? []);
  const scanned = new Set(records.flatMap((record) => record.output.paths?.scanned ?? []));
  for (const error of errors) if (error.path) scanned.add(error.path);
  const canonical = canonicalizeSemgrepOutput({
    results: uniqueAcrossFamilies(records, (record) => (record.output.results ?? []).map((result) => ({ ...result, check_id: stableRuleId(result.check_id) }))),
    skipped_rules: uniqueAcrossFamilies(records, (record) => record.output.skipped_rules ?? []),
    errors: [],
    paths: {
      scanned: [...scanned].sort(),
      skipped: [],
    },
    time: {
      rules: records.flatMap((record) => canonicalizeSemgrepTime(record.output.time).rules),
      fixpoint_timeouts: records.flatMap((record) => canonicalizeSemgrepTime(record.output.time).fixpoint_timeouts),
    },
  });
  return { ...canonical, errors, paths: { ...canonical.paths, skipped } };
}

/** Checkout-independent, content-bearing diagnostic evidence. Array order remains load-bearing. */
export function semgrepDiagnosticEvidence(output: SemgrepOutput, pathRoot: string): SemgrepDiagnosticEvidence {
  const errors = canonicalizeRoot(output.errors ?? [], pathRoot, TARGET_ROOT_TOKEN);
  const skipped = canonicalizeRoot(output.paths?.skipped ?? [], pathRoot, TARGET_ROOT_TOKEN);
  const fixpointTimeouts = canonicalizeRoot(canonicalizeSemgrepTime(output.time).fixpoint_timeouts, pathRoot, TARGET_ROOT_TOKEN);
  return { schema: 2, errors, skipped, fixpointTimeouts, sha256: digest({ errors, skipped, fixpointTimeouts }) };
}

export function canonicalizeSemgrepOutput(output: SemgrepOutput): SemgrepOutput {
  const sortedWithMultiplicity = <T>(items: readonly T[]): T[] => [...items].sort((a, b) => stable(a).localeCompare(stable(b)));
  return {
    // Registry packs overlap. Separate invocations give the same logical rule a different
    // config-path namespace, while a monolithic invocation loads it once. Remove only Harvey's
    // generated materialization/local-directory prefix so the family merge deduplicates the same
    // logical match the same way as Semgrep's monolithic loader.
    results: sortedWithMultiplicity((output.results ?? []).map((result) => ({ ...result, check_id: stableRuleId(result.check_id) }))),
    skipped_rules: sortedWithMultiplicity(output.skipped_rules ?? []),
    errors: sortedWithMultiplicity(output.errors ?? []),
    paths: {
      scanned: [...new Set(output.paths?.scanned ?? [])].sort(),
      skipped: sortedWithMultiplicity(output.paths?.skipped ?? []),
    },
    time: canonicalizeSemgrepTime(output.time),
  };
}
