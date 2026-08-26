import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { parse as parseYaml } from "yaml";
import { readRecursiveSafe } from "../fs-walk.js";
import type { SemgrepOutput } from "./semgrep.js";
import { canonicalizeSemgrepTime, SEMGREP_TIMEOUT_POLICY, SemgrepTimeoutTelemetryError, type SemgrepFixpointTimeout } from "./semgrep-time.js";
import type { MechanicalCacheMode } from "./mechanical-phase-cache.js";

export interface SemgrepFamily {
  id: string;
  configPath: string;
  cacheIdentity?: string;
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
  resultCount: number;
  resultsSha256: string;
  scanned: string[];
  skipped: NonNullable<NonNullable<SemgrepOutput["paths"]>["skipped"]>;
  skippedRules: unknown[];
  errors: NonNullable<SemgrepOutput["errors"]>;
  loadedTaintRuleIds: string[];
  taintCoverage: "not-assessed" | "no-timeout-observed";
  components?: SemgrepPartitionSemanticReceipt[];
  semanticSha256: string;
}

export interface SemgrepPartitionPlanReceipt {
  ordinal: number;
  id: string;
  component: "log-remainder" | "log-isolated-file" | "complement";
  target: "<SEMGREP_ROUTING_VIEW:remainder>" | "<SEMGREP_TARGET_ROOT>" | string;
  configSha256: string;
  ownedRuleIds: string[];
  ownedTaintRuleIds: string[];
  argv: string[];
  route?: SemgrepRoutingManifestEntry;
}

export interface SemgrepPartitionSemanticReceipt extends Omit<SemgrepCommandSemanticReceipt, "attempt" | "components" | "loadedTaintRuleIds" | "taintCoverage"> {
  ordinal: number;
  id: string;
  component: SemgrepPartitionPlanReceipt["component"];
  target: SemgrepPartitionPlanReceipt["target"];
  configSha256: string;
  ownedRuleIds: string[];
  ownedTaintRuleIds: string[];
  route?: SemgrepRoutingManifestEntry;
}

export interface SemgrepRoutingSelectorReceipt {
  extensions: ["js", "jsx", "ts", "tsx"];
  lowerExclusiveBytes: 81920;
  upperExclusiveBytes: 1000000;
  excludedDirectories: [".git", "node_modules"];
  order: "posix-relative-path";
}

export interface SemgrepRoutingManifestEntry {
  ordinal: number;
  path: string;
  type: "js" | "jsx" | "ts" | "tsx";
  bytes: number;
  contentSha256: string;
  component: string;
}

export interface SemgrepRoutingManifestReceipt {
  entries: SemgrepRoutingManifestEntry[];
  sha256: string;
}

export function comparePosixRelativePaths(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
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
  ownedTaintRuleIds: string[];
  loadedRuleIds: string[];
  loadedTaintRuleIds: string[];
  taintCoverage: "not-assessed" | "no-timeout-observed";
  excludedRuleIds: string[];
  sourceConfigSha256: string;
  semanticObjectSha256?: string;
  selector?: SemgrepRoutingSelectorReceipt;
  routingManifest?: SemgrepRoutingManifestReceipt;
  argv: string[];
  topology: "single-command-v1" | "rule-and-size-routed-file-isolation-v1";
  mergeAlgorithm: "single-command-v1" | "canonical-routed-semgrep-family-output-v1";
  partitions: SemgrepPartitionPlanReceipt[];
  verification: "single" | "paired-cold-exact" | "paired-topology-exact";
  status: "succeeded";
  attempts: SemgrepCommandSemanticReceipt[];
}

export type SemgrepPlannedFamilyReceipt = Omit<SemgrepFamilyExecutionReceipt, "loadedRuleIds" | "loadedTaintRuleIds" | "taintCoverage" | "status" | "attempts">;

export interface SemgrepPlannedExecutionReceipt {
  schema: 8;
  timeoutPolicy: typeof SEMGREP_TIMEOUT_POLICY;
  strategy: "globally-owned-partitioned-families";
  ownershipSha256: string;
  families: SemgrepPlannedFamilyReceipt[];
}

export interface SemgrepExecutionPlanReceipt {
  schema: 8;
  timeoutPolicy: typeof SEMGREP_TIMEOUT_POLICY;
  status: "succeeded";
  strategy: "globally-owned-partitioned-families";
  ownershipSha256: string;
  families: SemgrepFamilyExecutionReceipt[];
}

export function assertSuccessfulSemgrepExecutionReceipt(value: unknown): asserts value is SemgrepExecutionPlanReceipt {
  const receipt = value as Partial<SemgrepExecutionPlanReceipt>;
  if (!receipt || receipt.schema !== 8 || receipt.timeoutPolicy !== SEMGREP_TIMEOUT_POLICY || receipt.status !== "succeeded"
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
  const ownership = receipt.families.map(({ ordinal, id, sourceKind, sourceId, sourceConfigSha256, configSha256, ownedRuleIds, ownedTaintRuleIds, excludedRuleIds, semanticObjectSha256, selector, routingManifest, topology, mergeAlgorithm, partitions, verification }) => ({ ordinal, id, sourceKind, sourceId, sourceConfigSha256, configSha256, ownedRuleIds, ownedTaintRuleIds, excludedRuleIds, semanticObjectSha256, selector, routingManifest, topology, mergeAlgorithm, partitions, verification }));
  if (receipt.ownershipSha256 !== digest(ownership)) throw new Error("Semgrep semantic execution receipt ownership digest is invalid");
}

export interface SemgrepDiagnosticEvidence {
  schema: 4;
  errors: NonNullable<SemgrepOutput["errors"]>;
  skipped: NonNullable<NonNullable<SemgrepOutput["paths"]>["skipped"]>;
  sha256: string;
}

interface FamilyIdentity {
  targetRevision: string;
  targetTree: string;
  implementation: string;
  rules: string;
  plannedExecution: string;
  externalInputs: Record<string, string>;
  timeoutPolicy: typeof SEMGREP_TIMEOUT_POLICY;
}

interface FamilyArtifact {
  schema: 8;
  family: string;
  key: string;
  identity: FamilyIdentity;
  payloadDigest: string;
  unitsExamined: number;
  output: SemgrepOutput;
  execution: SemgrepFamilyExecutionReceipt;
}

export interface SemgrepFamilyExecutionFailure {
  schema: 8;
  status: "failed";
  reusable: false;
  family: string;
  reason: string;
  mismatchFields: string[];
  rawEvidence?: unknown;
  timeoutTelemetry?: SemgrepFamilyTimeoutTelemetry[];
  attempts: Array<{
    attempt: number;
    components: Array<{ plan: SemgrepPartitionPlanReceipt; output: SemgrepOutput; receipt: SemgrepPartitionSemanticReceipt }>;
    merged: { output: SemgrepOutput; receipt: SemgrepCommandSemanticReceipt };
  }>;
}

interface FamilyFailureArtifact {
  schema: 8;
  reusable: false;
  family: string;
  key: string;
  identity: FamilyIdentity;
  failure: SemgrepFamilyExecutionFailure;
  payloadDigest: string;
}

export interface SemgrepFamilyTimeoutTelemetry {
  attempt: number;
  components: Array<{ id: string; fixpointTimeouts: SemgrepFixpointTimeout[] }>;
}

interface FamilyTimeoutTelemetryArtifact {
  schema: 8;
  reusable: false;
  family: string;
  key: string;
  identity: FamilyIdentity;
  telemetry: SemgrepFamilyTimeoutTelemetry;
  payloadDigest: string;
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
  let real: string | undefined;
  try { real = realpathSync(pathRoot); } catch { real = undefined; }
  const roots = [...new Set([pathRoot, ...(real ? [real] : [])])].sort((a, b) => b.length - a.length);
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

function configuredTaintRuleIds(configPath: string): string[] {
  const parsed = parseYaml(readFileSync(configPath, "utf8")) as { rules?: unknown };
  if (!Array.isArray(parsed.rules)) throw new Error("Semgrep config rules population is malformed");
  return parsed.rules.filter((rule) => rule && typeof rule === "object" && (rule as { mode?: unknown }).mode === "taint")
    .map((rule) => (rule as { id?: unknown }).id)
    .filter((id): id is string => typeof id === "string" && id.length > 0)
    .sort();
}

function familyDirectory(id: string): string {
  return id.replaceAll(/[^a-zA-Z0-9.-]/g, "_");
}

function validateOutput(output: unknown, input: "raw" | "canonical" = "raw"): asserts output is SemgrepOutput {
  if (!output || typeof output !== "object") throw new Error("artifact output is missing");
  const value = output as SemgrepOutput;
  if (value.results !== undefined && !Array.isArray(value.results)) throw new Error("artifact results are malformed");
  if (value.errors !== undefined && !Array.isArray(value.errors)) throw new Error("artifact errors are malformed");
  if (!value.paths || !Array.isArray(value.paths.scanned) || !Array.isArray(value.paths.skipped)) throw new Error("artifact examined-path scope is incomplete");
  const time = canonicalizeSemgrepTime(value.time, undefined, input);
  if (input === "canonical" && time.fixpoint_timeouts.length > 0) throw new Error("canonical Semgrep output contains raw timeout telemetry");
}

function semanticReceiptPayload(receipt: Omit<SemgrepCommandSemanticReceipt, "status" | "attempt" | "semanticSha256">): unknown {
  return {
    argv: receipt.argv,
    loadedRuleIds: receipt.loadedRuleIds,
    resultCount: receipt.resultCount,
    resultsSha256: receipt.resultsSha256,
    scanned: receipt.scanned,
    skipped: receipt.skipped,
    skippedRules: receipt.skippedRules,
    errors: receipt.errors,
    ...(receipt.loadedTaintRuleIds === undefined ? {} : { loadedTaintRuleIds: receipt.loadedTaintRuleIds }),
    ...(receipt.taintCoverage === undefined ? {} : { taintCoverage: receipt.taintCoverage }),
    ...(receipt.components === undefined ? {} : { components: receipt.components }),
  };
}

function assertSemanticReceipt(receipt: Partial<SemgrepCommandSemanticReceipt>, expectedAttempt?: number, partition = false): void {
  if (receipt.status !== "succeeded" || (expectedAttempt !== undefined && receipt.attempt !== expectedAttempt)
    || !Array.isArray(receipt.argv) || !Array.isArray(receipt.loadedRuleIds) || !Array.isArray(receipt.scanned)
    || !Array.isArray(receipt.skipped) || !Array.isArray(receipt.skippedRules) || !Array.isArray(receipt.errors)
    || (!partition && (!Array.isArray(receipt.loadedTaintRuleIds) || (receipt.taintCoverage !== "not-assessed" && receipt.taintCoverage !== "no-timeout-observed")))
    || !Number.isInteger(receipt.resultCount) || receipt.resultCount! < 0 || !/^[a-f0-9]{64}$/.test(receipt.resultsSha256 ?? "")
    || !/^[a-f0-9]{64}$/.test(receipt.semanticSha256 ?? "")
    || receipt.semanticSha256 !== digest(semanticReceiptPayload(receipt as SemgrepCommandSemanticReceipt))) {
    throw new Error("artifact successful semantic execution receipt is missing, failed, or malformed");
  }
}

function assertSuccessfulSemgrepFamilyExecutionReceipt(value: unknown, family: string): asserts value is SemgrepFamilyExecutionReceipt {
  const receipt = value as Partial<SemgrepFamilyExecutionReceipt>;
  if (!receipt || receipt.status !== "succeeded" || receipt.familyId !== family || receipt.id !== family
    || !Number.isInteger(receipt.ordinal) || receipt.ordinal! < 0
    || (receipt.sourceKind !== "registry-pack" && receipt.sourceKind !== "local-config")
    || typeof receipt.sourceId !== "string" || receipt.sourceId.length === 0
    || !/^[a-f0-9]{64}$/.test(receipt.configSha256 ?? "") || !/^[a-f0-9]{64}$/.test(receipt.sourceConfigSha256 ?? "")
    || (receipt.semanticObjectSha256 !== undefined && !/^[a-f0-9]{64}$/.test(receipt.semanticObjectSha256))
    || !Array.isArray(receipt.argv) || receipt.argv.length === 0
    || (receipt.topology !== "single-command-v1" && receipt.topology !== "rule-and-size-routed-file-isolation-v1")
    || (receipt.mergeAlgorithm !== "single-command-v1" && receipt.mergeAlgorithm !== "canonical-routed-semgrep-family-output-v1")
    || !Array.isArray(receipt.partitions)
    || (receipt.verification !== "single" && receipt.verification !== "paired-cold-exact" && receipt.verification !== "paired-topology-exact")
    || !Array.isArray(receipt.ruleIds) || !Array.isArray(receipt.ownedRuleIds) || !Array.isArray(receipt.ownedTaintRuleIds)
    || !Array.isArray(receipt.loadedRuleIds) || !Array.isArray(receipt.loadedTaintRuleIds) || !Array.isArray(receipt.excludedRuleIds)
    || (receipt.taintCoverage !== "not-assessed" && receipt.taintCoverage !== "no-timeout-observed")
    || [...receipt.ruleIds, ...receipt.ownedRuleIds, ...receipt.ownedTaintRuleIds, ...receipt.loadedRuleIds, ...receipt.loadedTaintRuleIds, ...receipt.excludedRuleIds].some((id) => typeof id !== "string" || id.length === 0)
    || new Set(receipt.ownedRuleIds).size !== receipt.ownedRuleIds.length || new Set(receipt.loadedRuleIds).size !== receipt.loadedRuleIds.length
    || receipt.loadedRuleIds.some((id) => !receipt.ownedRuleIds!.includes(id))
    || receipt.ownedTaintRuleIds.some((id) => !receipt.ownedRuleIds!.includes(id))
    || receipt.loadedTaintRuleIds.some((id) => !receipt.loadedRuleIds!.includes(id) || !receipt.ownedTaintRuleIds!.includes(id))
    || !Array.isArray(receipt.attempts) || receipt.attempts.length !== (receipt.verification === "single" ? 1 : 2)) {
    throw new Error("artifact successful semantic execution receipt is missing, failed, or malformed");
  }
  receipt.attempts.forEach((attempt, ordinal) => assertSemanticReceipt(attempt, ordinal + 1));
  if (receipt.topology === "single-command-v1") {
    if (receipt.mergeAlgorithm !== "single-command-v1" || receipt.partitions.length !== 0
      || receipt.selector !== undefined || receipt.routingManifest !== undefined
      || receipt.verification === "paired-topology-exact" || receipt.attempts.some((attempt) => attempt.components !== undefined)) {
      throw new Error("artifact single-command topology is malformed");
    }
  } else {
    if (receipt.familyId !== "local-injection" || receipt.verification !== "paired-topology-exact"
      || receipt.mergeAlgorithm !== "canonical-routed-semgrep-family-output-v1"
      || !receipt.selector || !receipt.routingManifest || receipt.partitions.length !== receipt.routingManifest.entries.length + 2) {
      throw new Error("artifact routed topology is malformed");
    }
    const selector = receipt.selector;
    if (stable(selector) !== stable({ extensions: ["js", "jsx", "ts", "tsx"], lowerExclusiveBytes: 81920, upperExclusiveBytes: 1000000, excludedDirectories: [".git", "node_modules"], order: "posix-relative-path" })) {
      throw new Error("artifact routed selector is malformed");
    }
    const entries = receipt.routingManifest.entries;
    if (receipt.routingManifest.sha256 !== digest({ selector, entries })
      || entries.some((entry, ordinal) => entry.ordinal !== ordinal || entry.component !== `log-file-${String(ordinal + 1).padStart(3, "0")}`
        || !selector.extensions.includes(entry.type) || entry.bytes <= selector.lowerExclusiveBytes || entry.bytes >= selector.upperExclusiveBytes
        || !/^[a-f0-9]{64}$/.test(entry.contentSha256) || entry.path.startsWith("/") || entry.path.split("/").some((part) => selector.excludedDirectories.includes(part as ".git" | "node_modules")))
      || new Set(entries.map((entry) => entry.path)).size !== entries.length
      || stable(entries.map((entry) => entry.path)) !== stable(entries.map((entry) => entry.path).sort(comparePosixRelativePaths))) {
      throw new Error("artifact routed manifest identity/order is malformed");
    }
    const [remainder, ...rest] = receipt.partitions;
    const complement = rest.pop();
    const isolated = rest;
    if (remainder?.ordinal !== 0 || remainder.id !== "log-remainder" || remainder.component !== "log-remainder"
      || remainder.target !== "<SEMGREP_ROUTING_VIEW:remainder>" || stable(remainder.ownedRuleIds) !== stable(["harvey-log-injection"])
      || complement?.ordinal !== receipt.partitions.length - 1 || complement.id !== "complement" || complement.component !== "complement"
      || complement.target !== "<SEMGREP_TARGET_ROOT>" || complement.ownedRuleIds.length !== 29 || complement.ownedRuleIds.includes("harvey-log-injection")
      || isolated.some((component, index) => component.ordinal !== index + 1 || component.id !== entries[index]!.component
        || component.component !== "log-isolated-file" || component.target !== `<SEMGREP_TARGET_ROOT>/${entries[index]!.path}`
        || stable(component.route) !== stable(entries[index]) || stable(component.ownedRuleIds) !== stable(["harvey-log-injection"]))
      || [...receipt.partitions].some((partition) => !/^[a-f0-9]{64}$/.test(partition.configSha256) || !Array.isArray(partition.argv) || !Array.isArray(partition.ownedTaintRuleIds)
        || partition.ownedTaintRuleIds.some((id) => !partition.ownedRuleIds.includes(id))
        || partition.argv.includes("--exclude") || partition.argv.slice(0, 4).join(" ") !== "--x-ignore-semgrepignore-files --x-parmap -j 1")) {
      throw new Error("artifact routed ownership/topology is incomplete or malformed");
    }
    const routedRuleOwnership = [...remainder.ownedRuleIds, ...complement.ownedRuleIds];
    const routedTaintOwnership = [...remainder.ownedTaintRuleIds, ...complement.ownedTaintRuleIds];
    if (new Set(routedRuleOwnership).size !== routedRuleOwnership.length
      || stable([...routedRuleOwnership].sort()) !== stable([...receipt.ownedRuleIds].sort())
      || new Set(routedTaintOwnership).size !== routedTaintOwnership.length
      || stable([...routedTaintOwnership].sort()) !== stable([...receipt.ownedTaintRuleIds].sort())) {
      throw new Error("artifact partition ownership is incomplete or non-disjoint");
    }
    for (const attempt of receipt.attempts) {
      if (!Array.isArray(attempt.components) || attempt.components.length !== receipt.partitions.length) throw new Error("artifact routed component receipts are incomplete");
      for (const [ordinal, component] of attempt.components.entries()) {
        const plan = receipt.partitions[ordinal]!;
        assertSemanticReceipt({ ...component, attempt: attempt.attempt }, undefined, true);
        if (component.ordinal !== ordinal || component.id !== plan.id || component.component !== plan.component || component.target !== plan.target
          || component.configSha256 !== plan.configSha256 || stable(component.route) !== stable(plan.route)
        || stable(component.ownedRuleIds) !== stable(plan.ownedRuleIds) || stable(component.ownedTaintRuleIds) !== stable(plan.ownedTaintRuleIds)
        || stable(component.argv) !== stable(plan.argv)) {
          throw new Error("artifact routed component receipt differs from its bound topology");
        }
      }
      const componentLoaded = [...new Set(attempt.components.flatMap((component) => component.loadedRuleIds))].sort();
      if (stable(componentLoaded) !== stable(attempt.loadedRuleIds)) throw new Error("artifact merged loaded-rule population differs from its components");
    }
  }
  if (stable(receipt.ruleIds) !== stable(receipt.ownedRuleIds)
    || stable(receipt.loadedRuleIds) !== stable(receipt.attempts[0]!.loadedRuleIds)
    || stable(receipt.loadedTaintRuleIds) !== stable(receipt.attempts[0]!.loadedTaintRuleIds)
    || receipt.taintCoverage !== receipt.attempts[0]!.taintCoverage
    || stable(receipt.argv) !== stable(receipt.attempts[0]!.argv)
    || receipt.attempts.some((attempt) => stable(attempt.loadedRuleIds) !== stable(receipt.loadedRuleIds)
      || stable(attempt.loadedTaintRuleIds) !== stable(receipt.loadedTaintRuleIds)
      || attempt.taintCoverage !== receipt.taintCoverage
      || stable(attempt.argv) !== stable(receipt.argv))) {
    throw new Error("artifact semantic execution receipt population differs from its actual attempts");
  }
  if (receipt.verification !== "single") {
    const comparable = receipt.attempts.map((attempt) => Object.fromEntries(Object.entries(attempt).filter(([key]) => key !== "attempt")));
    if (stable(comparable[0]) !== stable(comparable[1])) throw new Error("artifact paired-cold semantic execution attempts differ");
  }
}

function assertExecutionMatchesOutput(execution: SemgrepFamilyExecutionReceipt, output: SemgrepOutput, canonicalStorage = true): void {
  const canonical = canonicalStorage ? canonicalizeSemgrepOutput(output, "canonical") : output;
  const mappedLoaded = canonicalizeSemgrepTime(canonical.time, execution.ownedRuleIds, canonicalStorage ? "canonical" : "raw").rules.map((checkId) => {
    const matches = execution.ownedRuleIds.filter((ruleId) => checkId === ruleId || checkId.endsWith(`.${ruleId}`));
    if (matches.length !== 1) throw new Error(`artifact executed rule ${checkId} has ${matches.length} owners in its bound receipt`);
    return matches[0]!;
  });
  const expected = {
    loadedRuleIds: [...new Set(mappedLoaded)].sort(),
    resultCount: canonical.results?.length ?? 0,
    resultsSha256: digest([...(canonical.results ?? [])].map((result) => ({ ...result, check_id: stableRuleId(result.check_id) })).sort((left, right) => stable(left).localeCompare(stable(right)))),
    scanned: canonical.paths?.scanned ?? [],
    skipped: canonical.paths?.skipped ?? [],
    skippedRules: canonical.skipped_rules ?? [],
    errors: canonical.errors ?? [],
    loadedTaintRuleIds: execution.loadedTaintRuleIds,
    taintCoverage: execution.taintCoverage,
  };
  for (const attempt of execution.attempts) {
    const actual = {
      loadedRuleIds: attempt.loadedRuleIds,
      resultCount: attempt.resultCount,
      resultsSha256: attempt.resultsSha256,
      scanned: attempt.scanned,
      skipped: attempt.skipped,
      skippedRules: attempt.skippedRules,
      errors: attempt.errors,
      loadedTaintRuleIds: attempt.loadedTaintRuleIds,
      taintCoverage: attempt.taintCoverage,
    };
    if (stable(actual) !== stable(expected)) {
      const fields = (Object.keys(expected) as Array<keyof typeof expected>).filter((field) => stable(actual[field]) !== stable(expected[field]));
      throw new Error(`artifact semantic execution receipt differs from its stored output: ${fields.join(", ")}`);
    }
  }
}

function rehashExecutionReceipt(receipt: SemgrepFamilyExecutionReceipt, output?: SemgrepOutput): SemgrepFamilyExecutionReceipt {
  const canonical = output ? canonicalizeSemgrepOutput(output, "canonical") : undefined;
  return {
    ...receipt,
    attempts: receipt.attempts.map((attempt) => {
      const semantic = {
        argv: attempt.argv,
        loadedRuleIds: attempt.loadedRuleIds,
        resultCount: canonical ? canonical.results?.length ?? 0 : attempt.resultCount,
        resultsSha256: canonical ? digest(canonical.results ?? []) : attempt.resultsSha256,
        scanned: canonical?.paths?.scanned ?? attempt.scanned,
        skipped: canonical?.paths?.skipped ?? attempt.skipped,
        skippedRules: canonical?.skipped_rules ?? attempt.skippedRules,
        errors: canonical?.errors ?? attempt.errors,
        loadedTaintRuleIds: attempt.loadedTaintRuleIds,
        taintCoverage: attempt.taintCoverage,
        ...(attempt.components === undefined ? {} : { components: attempt.components }),
      };
      return { ...attempt, ...semantic, semanticSha256: digest(semantic) };
    }),
  };
}

function plannedReceipt(execution: SemgrepFamilyExecutionReceipt): SemgrepPlannedFamilyReceipt {
  const planned: SemgrepPlannedFamilyReceipt & Partial<SemgrepFamilyExecutionReceipt> = { ...execution };
  delete planned.loadedRuleIds;
  delete planned.loadedTaintRuleIds;
  delete planned.taintCoverage;
  delete planned.status;
  delete planned.attempts;
  return planned;
}

function parseArtifact(value: unknown, expected: Pick<FamilyArtifact, "family" | "key" | "identity"> & { configSha256: string; ownedTaintRuleIds: string[]; planned?: SemgrepPlannedFamilyReceipt }): FamilyArtifact {
  const artifact = value as Partial<FamilyArtifact>;
  if (artifact.schema !== 8 || artifact.family !== expected.family || artifact.key !== expected.key || stable(artifact.identity) !== stable(expected.identity)) {
    throw new Error("artifact identity/schema mismatch");
  }
  validateOutput(artifact.output, "canonical");
  assertSuccessfulSemgrepFamilyExecutionReceipt(artifact.execution, expected.family);
  if (artifact.execution!.configSha256 !== expected.configSha256) throw new Error("artifact semantic execution config hash differs from its cache identity");
  if (stable(artifact.execution!.ownedTaintRuleIds) !== stable(expected.ownedTaintRuleIds)) throw new Error("artifact taint-mode ownership differs from its bound config bytes");
  if (expected.planned && stable(plannedReceipt(artifact.execution!)) !== stable(expected.planned)) throw new Error("artifact semantic execution differs from its fresh planned family receipt");
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

function writeTimeoutTelemetry(family: string, key: string, identity: FamilyIdentity, rows: readonly SemgrepFamilyTimeoutTelemetry[], options: SemgrepFamilyCacheOptions): void {
  for (const row of rows) {
    const telemetry = canonicalizeRoot(canonicalizeRoot(row, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN);
    const payloadDigest = digest(telemetry);
    const artifact: FamilyTimeoutTelemetryArtifact = { schema: 8, reusable: false, family, key, identity, telemetry, payloadDigest };
    const path = join(options.dir, "semgrep-family-timeout-telemetry", familyDirectory(family), key, `${payloadDigest}.json`);
    mkdirSync(dirname(path), { recursive: true });
    const temp = `${path}.${process.pid}.tmp`;
    writeFileSync(temp, `${JSON.stringify(artifact, null, 2)}\n`);
    renameSync(temp, path);
    options.onEvent?.(`SEMGREP TIMEOUT TELEMETRY ${family} attempt ${telemetry.attempt} ${payloadDigest.slice(0, 12)} reusable:false`);
  }
}

export async function executeSemgrepFamily(
  family: SemgrepFamily,
  options: SemgrepFamilyCacheOptions,
  execute: () => ({ output: SemgrepOutput; execution: SemgrepFamilyExecutionReceipt; telemetry?: SemgrepFamilyTimeoutTelemetry[]; outputMode?: "raw" | "canonical" } | { failure: SemgrepFamilyExecutionFailure }) | Promise<{ output: SemgrepOutput; execution: SemgrepFamilyExecutionReceipt; telemetry?: SemgrepFamilyTimeoutTelemetry[]; outputMode?: "raw" | "canonical" } | { failure: SemgrepFamilyExecutionFailure }>,
  planned?: SemgrepPlannedFamilyReceipt,
): Promise<SemgrepFamilyRecord> {
  mkdirSync(options.dir, { recursive: true });
  const identity: FamilyIdentity = {
    targetRevision: digest(options.targetRevision),
    targetTree: digest(options.targetTree),
    implementation: digest(options.implementation),
    rules: digest({ config: readFileSync(family.configPath, "utf8"), cacheIdentity: family.cacheIdentity ?? null }),
    plannedExecution: digest(planned ?? { direct: "unplanned-family-cache-v1" }),
    externalInputs: Object.fromEntries(Object.entries(options.externalInputs).sort(([a], [b]) => a.localeCompare(b)).map(([name, value]) => [name, digest(value)])),
    timeoutPolicy: SEMGREP_TIMEOUT_POLICY,
  };
  const key = digest({ family: family.id, identity });
  const path = join(options.dir, "semgrep-families", familyDirectory(family.id), `${key}.json`);
  const configSha256 = createHash("sha256").update(readFileSync(family.configPath)).digest("hex");
  const expected = { family: family.id, key, identity, configSha256, ownedTaintRuleIds: configuredTaintRuleIds(family.configPath), ...(planned ? { planned } : {}) };
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
  if ("failure" in executed) {
    const failure = canonicalizeRoot(canonicalizeRoot(executed.failure, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN);
    const payloadDigest = digest(failure);
    const artifact: FamilyFailureArtifact = { schema: 8, reusable: false, family: family.id, key, identity, failure, payloadDigest };
    const failurePath = join(options.dir, "semgrep-family-failures", familyDirectory(family.id), key, `${payloadDigest}.json`);
    mkdirSync(dirname(failurePath), { recursive: true });
    const temp = `${failurePath}.${process.pid}.tmp`;
    writeFileSync(temp, `${JSON.stringify(artifact, null, 2)}\n`);
    renameSync(temp, failurePath);
    options.onEvent?.(`SEMGREP FAMILY FAILURE EVIDENCE ${family.id} ${key.slice(0, 12)} ${payloadDigest.slice(0, 12)} reusable:false`);
    throw new Error(executed.failure.reason);
  }
  const { output, execution, telemetry = [], outputMode = "raw" } = executed;
  writeTimeoutTelemetry(family.id, key, identity, telemetry, options);
  validateOutput(output, outputMode);
  assertSuccessfulSemgrepFamilyExecutionReceipt(execution, family.id);
  if (outputMode === "raw") {
    const observed = canonicalizeSemgrepTime(output.time).fixpoint_timeouts.length > 0;
    if (observed !== (execution.taintCoverage === "not-assessed")) throw new Error("raw Semgrep timeout presence differs from its family assessment receipt");
  }
  const portableOutput = canonicalizeRoot(canonicalizeRoot(output, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN);
  const receiptOutput = canonicalizeSemgrepOutput(portableOutput, outputMode);
  const receiptExecution = canonicalizeRoot(canonicalizeRoot(execution, options.pathRoot, TARGET_ROOT_TOKEN), options.dir, CACHE_ROOT_TOKEN);
  try {
    assertExecutionMatchesOutput(receiptExecution, receiptOutput);
  } catch (canonicalError) {
    // Test doubles and older direct callers may already share one materialized root. Accept that
    // representation only before storage; every stored receipt below is rebound to portable bytes.
    if (outputMode === "canonical") throw canonicalError;
    try { assertExecutionMatchesOutput(execution, output, false); } catch { throw canonicalError; }
  }
  const canonicalOutput = canonicalizeSemgrepOutput(portableOutput, outputMode);
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
  const artifact: FamilyArtifact = { schema: 8, family: family.id, key, identity, payloadDigest: digest({ output: canonicalOutput, unitsExamined, execution: canonicalExecution }), unitsExamined, output: canonicalOutput, execution: canonicalExecution };
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
  const owned = checkId.replace(/^.*?\.semgrep-owned-configs\./, "");
  if (owned !== checkId) return owned.startsWith("harvey-") ? `src.scan.rules.semgrep.${owned}` : owned;
  const registry = checkId.replace(/^.*?\.registry-packs\.[^.]+\./, "");
  if (registry !== checkId) return registry;
  const local = checkId.replace(/^.*?src\.scan\.rules\.semgrep\./, "");
  // A monolithic load of CUSTOM_RULES namespaces Harvey's local ids by the config directory.
  // Single-file family loads return the same ids bare. Rebuild the established monolithic
  // namespace for stable client taxonomy and corpus pairing.
  return local.startsWith("harvey-") ? `src.scan.rules.semgrep.${local}` : local;
}

function stableOwnedRuleReferences<T>(value: T): T {
  return mapStrings(value, (text) => text.replace(
    /(?:[A-Za-z0-9_-]+\.)+semgrep-owned-configs\.(harvey-[A-Za-z0-9_.-]+)/g,
    (_match, ruleId: string) => `src.scan.rules.semgrep.${ruleId}`,
  ));
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
      rules: records.flatMap((record) => canonicalizeSemgrepTime(record.output.time, record.execution?.ownedRuleIds, "canonical").rules),
    },
  }, "canonical");
  return { ...canonical, errors, paths: { ...canonical.paths, skipped } };
}

/** Checkout-independent, content-bearing diagnostic evidence. Array order remains load-bearing. */
export function semgrepDiagnosticEvidence(output: SemgrepOutput, pathRoot: string): SemgrepDiagnosticEvidence {
  const errors = canonicalizeRoot(output.errors ?? [], pathRoot, TARGET_ROOT_TOKEN);
  const skipped = canonicalizeRoot(output.paths?.skipped ?? [], pathRoot, TARGET_ROOT_TOKEN);
  return { schema: 4, errors, skipped, sha256: digest({ errors, skipped }) };
}

export function canonicalizeSemgrepOutput(output: SemgrepOutput, input: "raw" | "canonical" = "raw", ownedRuleIds?: readonly string[]): SemgrepOutput {
  const sortedWithMultiplicity = <T>(items: readonly T[]): T[] => [...items].sort((a, b) => stable(a).localeCompare(stable(b)));
  const time = stableOwnedRuleReferences(canonicalizeSemgrepTime(output.time, ownedRuleIds, input));
  const { fixpoint_timeouts: rawTimeoutTelemetry, ...stableTime } = time;
  void rawTimeoutTelemetry;
  return {
    // Registry packs overlap. Separate invocations give the same logical rule a different
    // config-path namespace, while a monolithic invocation loads it once. Remove only Harvey's
    // generated materialization/local-directory prefix so the family merge deduplicates the same
    // logical match the same way as Semgrep's monolithic loader.
    results: sortedWithMultiplicity((output.results ?? []).map((result) => ({ ...result, check_id: stableRuleId(result.check_id) }))),
    skipped_rules: sortedWithMultiplicity(stableOwnedRuleReferences(output.skipped_rules ?? [])),
    errors: sortedWithMultiplicity(stableOwnedRuleReferences(output.errors ?? [])),
    paths: {
      scanned: [...new Set(output.paths?.scanned ?? [])].sort(),
      skipped: sortedWithMultiplicity(output.paths?.skipped ?? []),
    },
    time: {
      ...stableTime,
      rules: time.rules.map(stableRuleId).sort(),
      // Raw timeout rows are retained in non-reusable sidecars before this semantic boundary;
      // reusable output omits even an empty raw-telemetry field.
    },
  };
}

/** Remove Semgrep's config-path namespace only when it resolves to one bound owned rule. */
export function canonicalizeOwnedSemgrepOutput(output: SemgrepOutput, ownedRuleIds: readonly string[]): SemgrepOutput {
  const mappings = canonicalizeSemgrepTime(output.time, ownedRuleIds, "raw").rules.flatMap((checkId) => {
    const matches = ownedRuleIds.filter((ruleId) => checkId === ruleId || checkId.endsWith(`.${ruleId}`));
    return matches.length === 1 ? [{ checkId, stableId: stableRuleId(matches[0]!) }] : [];
  }).sort((left, right) => right.checkId.length - left.checkId.length);
  const normalized = mapStrings(output, (text) => mappings.reduce(
    (current, { checkId, stableId }) => current.replaceAll(checkId, stableId),
    text,
  ));
  return canonicalizeSemgrepOutput(normalized, "raw", ownedRuleIds);
}

/** Build the schema-8 semantic receipt from the same canonical value stored in family artifacts. */
export function buildSemgrepCommandSemanticReceipt(
  output: SemgrepOutput,
  pathRoot: string,
  argv: string[],
  attempt: number,
  loadedRuleIds?: string[],
  components?: SemgrepPartitionSemanticReceipt[],
  input: "raw" | "canonical" = "raw",
  ownedTaintRuleIds: readonly string[] = [],
  taintCoverageOverride?: "not-assessed" | "no-timeout-observed",
): SemgrepCommandSemanticReceipt {
  const rawTimeouts = canonicalizeSemgrepTime(output.time, loadedRuleIds, input).fixpoint_timeouts;
  const semanticOutput = input === "canonical"
    ? canonicalizeSemgrepOutput(output, "canonical")
    : loadedRuleIds
    ? canonicalizeOwnedSemgrepOutput(output, loadedRuleIds)
    : canonicalizeSemgrepOutput(output, "raw");
  const canonical = canonicalizeRoot({
    results: semanticOutput.results ?? [],
    scanned: semanticOutput.paths?.scanned ?? [],
    skipped: semanticOutput.paths?.skipped ?? [],
    skippedRules: semanticOutput.skipped_rules ?? [],
    errors: semanticOutput.errors ?? [],
  }, pathRoot, TARGET_ROOT_TOKEN);
  const resolvedLoadedRuleIds = loadedRuleIds ?? canonicalizeSemgrepTime(semanticOutput.time, undefined, "canonical").rules;
  const loadedTaintRuleIds = [...ownedTaintRuleIds].filter((id) => resolvedLoadedRuleIds.includes(id)).sort();
  const taintCoverage = taintCoverageOverride ?? (rawTimeouts.length > 0 ? "not-assessed" : "no-timeout-observed");
  if (taintCoverage === "not-assessed" && loadedTaintRuleIds.length === 0) {
    throw new SemgrepTimeoutTelemetryError("Semgrep reported fixpoint timeout telemetry without any bound loaded taint-mode rule", rawTimeouts);
  }
  const receipt = {
    argv,
    loadedRuleIds: resolvedLoadedRuleIds,
    resultCount: canonical.results.length,
    resultsSha256: digest(canonical.results),
    scanned: canonical.scanned,
    skipped: canonical.skipped,
    skippedRules: canonical.skippedRules,
    errors: canonical.errors,
    loadedTaintRuleIds,
    taintCoverage,
    ...(components === undefined ? {} : { components }),
  };
  return { status: "succeeded", attempt, ...receipt, semanticSha256: digest(receipt) };
}
