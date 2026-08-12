import { execFileSync } from "node:child_process";
import { cpSync, existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import type { Finding } from "./findings.js";
import { readRecursiveSafe, statSafe } from "./fs-walk.js";
import { cloneAtPinCached } from "./scan/corpus-clone.js";
import type { MechanicalContextMetrics } from "./scan/mechanical-context.js";
import type { MechanicalProducerRecord } from "./scan/mechanical-phase-cache.js";
import { binaryVersion, digestFiles, digestParts, digestTree, mechanicalExaminedUnitDigest, resolveGitTree } from "./scan/mechanical-phase-cache.js";
import { shardTargets } from "./scan/corpus-shards.js";
import { REGISTRY_PACKS, registryPackIdentity } from "./scan/semgrep.js";

export const CURRENT_MECHANICAL_POPULATION = "runMechanicalScanDetailed.current-readiness-v1" as const;
export const CURRENT_MECHANICAL_PREPARATION = "pinned-checkout/remove-vendored/copy-before-install/bundle-off-v1" as const;
const SHA256 = /^[a-f0-9]{64}$/;

export interface CurrentMechanicalTargetDefinition {
  slug: string;
  repo: string;
  commit: string;
  vendoredSubtrees?: readonly string[];
}

export interface SemgrepPackReceipt {
  schema: 1;
  aggregateSha256: string;
  files: Array<{ ordinal: number; name: string; bytes: number; sha256: string; bodyBase64: string }>;
}

export interface CurrentMechanicalTargetReceipt {
  slug: string;
  repo: string;
  pin: string;
  checkoutHead: string;
  checkoutTree: string;
  preparedTreeSha256: string;
  preparation: typeof CURRENT_MECHANICAL_PREPARATION;
  removedVendoredSubtrees: string[];
  captureBeforeInstall: true;
  installMutationAtCapture: false;
  skipBundleScan: true;
  bundleDigest: string;
  advisorySha256: string;
  advisoryVersion: string;
  secretCandidateIdentity: string;
  findings: Finding[];
  producers: MechanicalProducerRecord[];
  context: MechanicalContextMetrics;
}

export interface CurrentMechanicalExecutionArtifact {
  schema: 1;
  kind: "current-mechanical-execution";
  population: typeof CURRENT_MECHANICAL_POPULATION;
  side: "hosted-producer" | "independent-replay";
  executionId: string;
  headCommit: string;
  harnessSha256: string;
  commands: string[];
  options: {
    skipNetworkChecks: true;
    skipBundleScan: true;
    advisoryMode: "snapshot";
    phaseCache: "hosted-content-addressed" | "off";
    bundleDir: null;
    handrolledIndicators: false;
    authGuards: [];
  };
  targetPinsSha256: string;
  allTargets: CurrentMechanicalTargetDefinition[];
  semgrepRegistry: SemgrepPackReceipt;
  runtime: { node: string; platform: string; arch: string; semgrep: string; gitleaks: string; git: string };
  shard: { index: number; count: number };
  targets: Record<string, CurrentMechanicalTargetReceipt>;
}

export interface PreparedMechanicalTarget {
  checkoutDir: string;
  preparedDir: string;
  checkoutHead: string;
  checkoutTree: string;
  preparedTreeSha256: string;
  removedVendoredSubtrees: string[];
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => `${JSON.stringify(key)}:${stable(entry)}`).join(",")}}`;
  return JSON.stringify(value);
}

export function currentTargetPinsSha256(targets: readonly CurrentMechanicalTargetDefinition[]): string {
  return sha256(JSON.stringify(targets.map(({ slug, repo, commit, vendoredSubtrees }) => ({ slug, repo, commit, vendoredSubtrees: [...(vendoredSubtrees ?? [])] }))));
}

export function currentHarnessReceipt(repoRoot: string): { headCommit: string; harnessSha256: string } {
  const headCommit = execFileSync("git", ["-C", repoRoot, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const tracked = execFileSync("git", ["-C", repoRoot, "diff", "--name-only", "HEAD", "--", "src", "package.json", "pnpm-lock.yaml", ".github/workflows/corpus-drift.yml"], { encoding: "utf8" }).trim();
  const untracked = execFileSync("git", ["-C", repoRoot, "ls-files", "--others", "--exclude-standard", "--", "src", "package.json", "pnpm-lock.yaml", ".github/workflows/corpus-drift.yml"], { encoding: "utf8" }).trim();
  if (tracked || untracked) throw new Error(`current mechanical harness is dirty or untracked: ${[tracked, untracked].filter(Boolean).join(", ")}`);
  const files = [
    ...readRecursiveSafe(join(repoRoot, "src")).map((path) => join(repoRoot, "src", path)),
    join(repoRoot, "package.json"),
    join(repoRoot, "pnpm-lock.yaml"),
    join(repoRoot, ".github/workflows/corpus-drift.yml"),
  ].filter((path) => statSafe(path)?.isFile());
  return { headCommit, harnessSha256: digestFiles(files, repoRoot) };
}

export function semgrepPackReceipt(files: readonly string[], aggregateSha256: string): SemgrepPackReceipt {
  if (!SHA256.test(aggregateSha256)) throw new Error("Semgrep registry aggregate identity is not SHA-256");
  if (files.length !== 6) throw new Error(`Semgrep registry pack contains ${files.length} files, expected 6`);
  const rows = files.map((path, ordinal) => {
    const body = readFileSync(path);
    return { ordinal, name: path.split("/").pop()!, bytes: body.byteLength, sha256: sha256(body), bodyBase64: body.toString("base64") };
  });
  const actual = registryPackIdentity(rows.map((row, ordinal) => ({ pack: REGISTRY_PACKS[ordinal]!, body: Buffer.from(row.bodyBase64, "base64").toString("utf8") })));
  if (actual !== aggregateSha256) throw new Error(`Semgrep registry bytes hash to ${actual}, not ${aggregateSha256}`);
  return { schema: 1, aggregateSha256, files: rows };
}

export function prepareCurrentMechanicalTarget(options: {
  target: CurrentMechanicalTargetDefinition;
  checkoutDir: string;
  preparedDir: string;
  cloneCacheDir?: string;
  verifyRemote?: boolean;
}): PreparedMechanicalTarget {
  const { target, checkoutDir, preparedDir } = options;
  cloneAtPinCached(target.repo, target.commit, checkoutDir, options.cloneCacheDir, options.verifyRemote ?? true);
  const checkoutHead = execFileSync("git", ["-C", checkoutDir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  if (checkoutHead !== target.commit) throw new Error(`${target.slug}: checkout head ${checkoutHead} differs from pin ${target.commit}`);
  const checkoutTree = resolveGitTree(checkoutDir);
  const removedVendoredSubtrees = [...(target.vendoredSubtrees ?? [])];
  for (const subtree of removedVendoredSubtrees) {
    const path = join(checkoutDir, subtree);
    if (!existsSync(path)) throw new Error(`${target.slug}: vendored subtree ${subtree} is absent before preparation`);
    rmSync(path, { recursive: true, force: true });
  }
  cpSync(checkoutDir, preparedDir, { recursive: true, force: false, errorOnExist: true, verbatimSymlinks: true });
  for (const subtree of removedVendoredSubtrees) if (existsSync(join(preparedDir, subtree))) {
    throw new Error(`${target.slug}: vendored subtree ${subtree} survived the prepared copy`);
  }
  const preparedTreeSha256 = digestTree(preparedDir);
  return { checkoutDir, preparedDir, checkoutHead, checkoutTree, preparedTreeSha256, removedVendoredSubtrees };
}

export function assertPreparedTargetUnchanged(prepared: PreparedMechanicalTarget): void {
  const after = digestTree(prepared.preparedDir);
  if (after !== prepared.preparedTreeSha256) throw new Error(`prepared mechanical target mutated during execution: ${after} != ${prepared.preparedTreeSha256}`);
}

export function currentRuntimeReceipt(): CurrentMechanicalExecutionArtifact["runtime"] {
  return {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    semgrep: binaryVersion("semgrep"),
    gitleaks: binaryVersion("gitleaks"),
    git: binaryVersion("git"),
  };
}

export function newExecutionId(side: CurrentMechanicalExecutionArtifact["side"], shard: { index: number; count: number }): string {
  return `${side}:${shard.index}/${shard.count}:${randomUUID()}`;
}

function assertSha(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new Error(`${label} is not a SHA-256 digest`);
}

function validatePack(pack: SemgrepPackReceipt, source: string): void {
  if (pack.schema !== 1 || pack.files.length !== 6) throw new Error(`${source}: Semgrep receipt is incomplete`);
  assertSha(pack.aggregateSha256, `${source}: Semgrep aggregate`);
  pack.files.forEach((file, ordinal) => {
    const body = typeof file.bodyBase64 === "string" ? Buffer.from(file.bodyBase64, "base64") : Buffer.alloc(0);
    const expectedName = `${ordinal}-${REGISTRY_PACKS[ordinal]!.replaceAll("/", "-")}.yml`;
    if (file.ordinal !== ordinal || !Number.isInteger(file.bytes) || file.bytes <= 0 || file.name !== expectedName || body.byteLength !== file.bytes) throw new Error(`${source}: Semgrep file receipt name/order/population/bytes is invalid`);
    assertSha(file.sha256, `${source}: Semgrep file ${ordinal}`);
    if (sha256(body) !== file.sha256) throw new Error(`${source}: Semgrep file ${ordinal} bytes differ from their digest`);
  });
  const actual = registryPackIdentity(pack.files.map((file, ordinal) => ({ pack: REGISTRY_PACKS[ordinal]!, body: Buffer.from(file.bodyBase64, "base64").toString("utf8") })));
  if (actual !== pack.aggregateSha256) throw new Error(`${source}: Semgrep aggregate differs from its exact ordered bytes`);
}

function normalizedProducer(record: MechanicalProducerRecord): unknown {
  return Object.fromEntries(Object.entries(record).flatMap(([key, value]) => key === "durationMs"
    ? []
    : [[key, key === "status" && value === "cached" ? "ran" : value]]));
}

function validateArtifact(artifact: CurrentMechanicalExecutionArtifact, source: string): void {
  if (artifact.schema !== 1 || artifact.kind !== "current-mechanical-execution" || artifact.population !== CURRENT_MECHANICAL_POPULATION) throw new Error(`${source}: not a current mechanical execution artifact`);
  if (artifact.side !== "hosted-producer" && artifact.side !== "independent-replay") throw new Error(`${source}: execution side is invalid`);
  if (!artifact.executionId.startsWith(`${artifact.side}:`)) throw new Error(`${source}: execution id is missing or belongs to another side`);
  if (!Array.isArray(artifact.commands) || artifact.commands.length === 0 || artifact.commands.some((command) => typeof command !== "string" || command.length === 0)) throw new Error(`${source}: execution command receipt is missing`);
  if (!/^[a-f0-9]{40}$/.test(artifact.headCommit)) throw new Error(`${source}: head is not a full Git commit`);
  assertSha(artifact.harnessSha256, `${source}: harness`);
  assertSha(artifact.targetPinsSha256, `${source}: target pins`);
  validatePack(artifact.semgrepRegistry, source);
  if (artifact.options.skipNetworkChecks !== true || artifact.options.skipBundleScan !== true || artifact.options.advisoryMode !== "snapshot"
    || artifact.options.bundleDir !== null || artifact.options.handrolledIndicators !== false || artifact.options.authGuards.length !== 0) {
    throw new Error(`${source}: current execution did not retain the globally pinned scan options`);
  }
  if (artifact.side === "hosted-producer" && artifact.options.phaseCache !== "hosted-content-addressed") throw new Error(`${source}: hosted producer did not use its real phase-cache path`);
  if (artifact.side === "independent-replay" && artifact.options.phaseCache !== "off") throw new Error(`${source}: replay is not an independent cold process`);
  const targetNames = artifact.allTargets.map((target) => target.slug);
  if (new Set(targetNames).size !== targetNames.length || artifact.targetPinsSha256 !== currentTargetPinsSha256(artifact.allTargets)) throw new Error(`${source}: target pin population/identity is invalid`);
  const owned = Object.keys(artifact.targets).sort();
  if (owned.length === 0) throw new Error(`${source}: target population is empty`);
  const expectedOwned = shardTargets(targetNames, artifact.shard.index, artifact.shard.count).sort();
  if (stable(owned) !== stable(expectedOwned)) throw new Error(`${source}: target population differs from declared shard ${artifact.shard.index}/${artifact.shard.count}`);
  for (const slug of owned) {
    const target = artifact.targets[slug]!;
    const declared = artifact.allTargets.find((candidate) => candidate.slug === slug);
    if (!declared || target.slug !== slug || target.repo !== declared.repo || target.pin !== declared.commit || target.checkoutHead !== declared.commit) throw new Error(`${source}: ${slug} pin/revision receipt differs from the declared target`);
    if (target.preparation !== CURRENT_MECHANICAL_PREPARATION || target.captureBeforeInstall !== true || target.installMutationAtCapture !== false) throw new Error(`${source}: ${slug} was not captured before install mutation`);
    if (target.skipBundleScan !== true || target.bundleDigest !== digestParts(["bundle-pinned-off-v1"])) throw new Error(`${source}: ${slug} bundle input was not pinned off`);
    if (stable(target.removedVendoredSubtrees) !== stable([...(declared.vendoredSubtrees ?? [])])) throw new Error(`${source}: ${slug} vendored-subtree preparation differs from the manifest`);
    for (const [value, label] of [[target.preparedTreeSha256, "prepared tree"], [target.advisorySha256, "advisory"], [target.secretCandidateIdentity, "secret candidates"]] as const) assertSha(value, `${source}: ${slug} ${label}`);
    if (!Array.isArray(target.findings) || !Array.isArray(target.producers) || target.producers.length === 0) throw new Error(`${source}: ${slug} mechanical rows or producer census is missing`);
    const producerIds = target.producers.map((producer) => `${producer.phase}:${producer.order}:${producer.detector}`);
    if (new Set(producerIds).size !== producerIds.length) throw new Error(`${source}: ${slug} producer census contains a duplicate`);
    for (const producer of target.producers) {
      if (!Array.isArray(producer.examinedUnitIdentities)
        || producer.unitsExamined !== producer.examinedUnitIdentities.length
        || producer.examinedUnitDigest !== mechanicalExaminedUnitDigest(producer.examinedUnitIdentities)) {
        throw new Error(`${source}: ${slug}:${producer.detector} exact examined-unit population/digest is missing or inconsistent`);
      }
    }
  }
}

function invariant(artifact: CurrentMechanicalExecutionArtifact): unknown {
  return {
    schema: artifact.schema,
    kind: artifact.kind,
    population: artifact.population,
    side: artifact.side,
    headCommit: artifact.headCommit,
    harnessSha256: artifact.harnessSha256,
    options: artifact.options,
    targetPinsSha256: artifact.targetPinsSha256,
    allTargets: artifact.allTargets,
    semgrepRegistry: artifact.semgrepRegistry,
    runtime: artifact.runtime,
    shardCount: artifact.shard.count,
  };
}

export function mergeCurrentMechanicalShards(artifacts: CurrentMechanicalExecutionArtifact[], source: string): CurrentMechanicalExecutionArtifact {
  if (artifacts.length === 0) throw new Error(`${source}: no execution shards supplied`);
  artifacts.forEach((artifact, index) => validateArtifact(artifact, `${source}[${index}]`));
  const first = artifacts[0]!;
  for (const artifact of artifacts.slice(1)) if (stable(invariant(artifact)) !== stable(invariant(first))) throw new Error(`${source}: shards have mixed engine/input/runtime receipts`);
  const expectedCount = first.shard.count;
  if (artifacts.length !== expectedCount) throw new Error(`${source}: received ${artifacts.length} shard(s), expected ${expectedCount}`);
  const indexes = artifacts.map((artifact) => artifact.shard.index).sort((a, b) => a - b);
  if (stable(indexes) !== stable(Array.from({ length: expectedCount }, (_, index) => index + 1))) throw new Error(`${source}: shard index population is incomplete or duplicated`);
  const targets: CurrentMechanicalExecutionArtifact["targets"] = {};
  for (const artifact of artifacts) for (const [slug, receipt] of Object.entries(artifact.targets)) {
    if (targets[slug]) throw new Error(`${source}: target ${slug} appears in more than one shard`);
    targets[slug] = receipt;
  }
  const expectedTargets = first.allTargets.map((target) => target.slug).sort();
  if (stable(Object.keys(targets).sort()) !== stable(expectedTargets)) throw new Error(`${source}: merged target population differs from the declared pin population`);
  return {
    ...first,
    executionId: artifacts.map((artifact) => artifact.executionId).sort().join("+"),
    commands: [...artifacts].sort((a, b) => a.shard.index - b.shard.index).flatMap((artifact) => artifact.commands),
    shard: { index: 1, count: 1 },
    targets,
  };
}

export function compareCurrentMechanicalExecutions(producer: CurrentMechanicalExecutionArtifact, replay: CurrentMechanicalExecutionArtifact): void {
  validateArtifact(producer, "hosted producer");
  validateArtifact(replay, "independent replay");
  if (producer.side !== "hosted-producer" || replay.side !== "independent-replay") throw new Error("current equivalence requires one real hosted producer artifact and one independent replay artifact");
  if (producer.executionId === replay.executionId) throw new Error("scorecard self-comparison or one-side execution is not equivalence");
  const common = (artifact: CurrentMechanicalExecutionArtifact): unknown => ({
    population: artifact.population,
    headCommit: artifact.headCommit,
    harnessSha256: artifact.harnessSha256,
    targetPinsSha256: artifact.targetPinsSha256,
    allTargets: artifact.allTargets,
    semgrepRegistry: artifact.semgrepRegistry,
    runtime: artifact.runtime,
    shard: artifact.shard,
    targetPopulation: Object.keys(artifact.targets).sort(),
  });
  if (stable(common(producer)) !== stable(common(replay))) throw new Error("current producer and replay use different head/harness/pins/runtime/Semgrep bytes or target population");
  for (const slug of Object.keys(producer.targets).sort()) {
    const left = producer.targets[slug]!;
    const right = replay.targets[slug]!;
    const receipt = (target: CurrentMechanicalTargetReceipt): unknown => ({
      slug: target.slug,
      repo: target.repo,
      pin: target.pin,
      checkoutHead: target.checkoutHead,
      checkoutTree: target.checkoutTree,
      preparedTreeSha256: target.preparedTreeSha256,
      preparation: target.preparation,
      removedVendoredSubtrees: target.removedVendoredSubtrees,
      captureBeforeInstall: target.captureBeforeInstall,
      installMutationAtCapture: target.installMutationAtCapture,
      skipBundleScan: target.skipBundleScan,
      bundleDigest: target.bundleDigest,
      advisorySha256: target.advisorySha256,
      advisoryVersion: target.advisoryVersion,
      secretCandidateIdentity: target.secretCandidateIdentity,
    });
    if (stable(receipt(left)) !== stable(receipt(right))) throw new Error(`${slug}: producer/replay preparation or external-state receipt differs`);
    if (stable(left.findings) !== stable(right.findings)) throw new Error(`${slug}: ordered raw mechanical finding fields/order/population differ`);
    if (stable(left.producers.map(normalizedProducer)) !== stable(right.producers.map(normalizedProducer))) throw new Error(`${slug}: producer order, findings, status, or exact examined-unit population differs`);
  }
}
