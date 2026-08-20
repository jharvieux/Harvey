import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readlinkSync, rmSync, symlinkSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import type { Finding } from "./findings.js";
import { readEntriesSafe, readRecursiveSafe, statSafe } from "./fs-walk.js";
import { cloneAtPinCached } from "./scan/corpus-clone.js";
import type { MechanicalContextMetrics } from "./scan/mechanical-context.js";
import type { MechanicalPhaseCacheOptions, MechanicalProducerRecord } from "./scan/mechanical-phase-cache.js";
import { binaryVersion, digestFiles, digestParts, MECHANICAL_PHASES, mechanicalExaminedUnitDigest, resolveGitTree } from "./scan/mechanical-phase-cache.js";
import { buildMechanicalPhaseCache } from "./scan/mechanical-phase-identity.js";
import { shardTargets } from "./scan/corpus-shards.js";
import type { SemgrepDiagnosticEvidence } from "./scan/semgrep-family-cache.js";
import { REGISTRY_PACKS, registryPackIdentity, semgrepExecutionPlanReceipt, type SemgrepExecutionPlanReceipt } from "./scan/semgrep.js";

export const CURRENT_MECHANICAL_POPULATION = "runMechanicalScanDetailed.current-readiness-v1" as const;
export const CURRENT_MECHANICAL_PREPARATION = "pinned-tracked-tree/shared-pruned-scan-root/copy-before-install/bundle-off-v3" as const;
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

interface RestoredSemgrepPackArtifact {
  identity: string;
  files: string[];
  receipt: SemgrepPackReceipt;
}

export interface CurrentMechanicalTargetReceipt {
  slug: string;
  repo: string;
  pin: string;
  checkoutHead: string;
  checkoutTree: string;
  preparedTreeSha256: string;
  gitVersion: string;
  emptyGitlinks: EmptyGitlinkReceipt[];
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
  executionPlan: CurrentMechanicalExecutionPlanReceipt;
  cachePolicy: CurrentMechanicalCachePolicyReceipt;
  semgrepDiagnostics: SemgrepDiagnosticEvidence;
}

export interface EmptyGitlinkReceipt {
  path: string;
  object: string;
  representation: "empty-directory";
}

interface CurrentMechanicalExecutionPlanReceipt {
  schema: 1;
  phases: typeof MECHANICAL_PHASES;
  implementation: MechanicalPhaseCacheOptions["implementation"];
  externalInputs: MechanicalPhaseCacheOptions["externalInputs"];
  semgrep: SemgrepExecutionPlanReceipt;
}

interface CurrentMechanicalCachePolicyReceipt {
  schema: 1;
  mode: "hosted-content-addressed" | "independent-cold-off";
  namespaceSha256: string;
  emptyNamespaceVerified: boolean;
  producerArtifactsAllowed: boolean;
}

export interface CurrentMechanicalExecutionArtifact {
  schema: 3;
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
  runtime: { node: string; platform: string; arch: string; semgrep: string; gitleaks: string };
  shard: { index: number; count: number };
  targets: Record<string, CurrentMechanicalTargetReceipt>;
}

export interface PreparedMechanicalTarget {
  checkoutDir: string;
  preparedDir: string;
  scanDir: string;
  checkoutHead: string;
  checkoutTree: string;
  preparedTreeSha256: string;
  emptyGitlinks: EmptyGitlinkReceipt[];
  removedVendoredSubtrees: string[];
}

function currentMechanicalOptionIdentity(): string {
  return JSON.stringify({ bundleDir: null, skipBundleScan: true, skipNetworkChecks: true, handrolledIndicators: false, authGuards: [], externalStateMode: "snapshot" });
}

export function buildCurrentMechanicalPhasePlan(options: {
  side: CurrentMechanicalExecutionArtifact["side"];
  repoRoot: string;
  cacheDir: string;
  targetRevision: string;
  targetTree: string;
  advisoryDigest: string;
  advisoryVersion: string;
  secretCandidateIdentity: string;
  registry: { identity: string; files: string[] };
  producerMode?: "read-write" | "verify";
  onEvent?: (message: string) => void;
}): { phaseCache: MechanicalPhaseCacheOptions; executionPlan: CurrentMechanicalExecutionPlanReceipt; cachePolicy: CurrentMechanicalCachePolicyReceipt } {
  const cacheDir = resolve(options.cacheDir);
  if (options.side === "independent-replay") {
    if (existsSync(cacheDir) && readRecursiveSafe(cacheDir).length > 0) throw new Error("independent replay cache namespace is not empty; producer artifacts must never enter replay");
    mkdirSync(cacheDir, { recursive: true });
  }
  const mode = options.side === "independent-replay" ? "off" : (options.producerMode ?? "read-write");
  const phaseCache = buildMechanicalPhaseCache({
    repoRoot: options.repoRoot,
    cacheDir,
    mode,
    targetRevision: options.targetRevision,
    targetTree: options.targetTree,
    optionIdentity: currentMechanicalOptionIdentity(),
    deterministicExternalState: {
      advisoryDigest: options.advisoryDigest,
      advisoryVersion: options.advisoryVersion,
      secretCandidateIdentity: options.secretCandidateIdentity,
    },
    registryPackIdentity: options.registry,
    registrySnapshotMode: "reuse",
    onEvent: options.onEvent,
  });
  if (!phaseCache.semgrepFamilies || !phaseCache.materializedInputs?.semgrep) throw new Error("current readiness requires the exhaustive partitioned Semgrep plan");
  return {
    phaseCache,
    executionPlan: {
      schema: 1,
      phases: MECHANICAL_PHASES,
      implementation: phaseCache.implementation,
      externalInputs: phaseCache.externalInputs,
      semgrep: semgrepExecutionPlanReceipt(phaseCache.materializedInputs.semgrep),
    },
    cachePolicy: {
      schema: 1,
      mode: options.side === "independent-replay" ? "independent-cold-off" : "hosted-content-addressed",
      namespaceSha256: sha256(cacheDir),
      emptyNamespaceVerified: options.side === "independent-replay",
      producerArtifactsAllowed: options.side === "hosted-producer",
    },
  };
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => `${JSON.stringify(key)}:${stable(entry)}`).join(",")}}`;
  return JSON.stringify(value);
}

function canonicalTargetRelativePath(path: string): boolean {
  return path.length > 0 && !path.startsWith("/") && !path.includes("\\")
    && path.split("/").every((segment) => segment.length > 0 && segment !== "." && segment !== "..");
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

/**
 * Validate the complete upload-artifact/download-artifact payload, not merely the six files that
 * Semgrep happens to open. The receipt is an independent, byte-carrying description of the pack;
 * the manifest selects the canonical identity directory; and the exact inventory rejects nesting,
 * omitted hidden files, or a mixture left behind by another artifact restoration.
 */
export function validateRestoredSemgrepPackArtifact(dir: string): RestoredSemgrepPackArtifact {
  const currentPath = join(dir, "registry-packs", "current.json");
  const receiptPath = join(dir, "receipt.json");
  if (!existsSync(currentPath)) throw new Error(`restored Semgrep artifact is not canonical: registry-packs/current.json is missing under ${dir}`);
  if (!existsSync(receiptPath)) throw new Error(`restored Semgrep artifact is not canonical: receipt.json is missing under ${dir}`);

  let manifest: { schema?: unknown; identity?: unknown };
  let receipt: SemgrepPackReceipt;
  try {
    manifest = JSON.parse(readFileSync(currentPath, "utf8")) as { schema?: unknown; identity?: unknown };
  } catch (error) {
    throw new Error(`restored Semgrep artifact current.json is unreadable: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (manifest.schema !== 1 || typeof manifest.identity !== "string" || !SHA256.test(manifest.identity)) {
    throw new Error("restored Semgrep artifact current.json has an invalid schema or identity");
  }
  try {
    receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as SemgrepPackReceipt;
  } catch (error) {
    throw new Error(`restored Semgrep artifact receipt.json is unreadable: ${error instanceof Error ? error.message : String(error)}`);
  }
  validatePack(receipt, "restored Semgrep artifact receipt.json");

  const identity = manifest.identity;
  const files = REGISTRY_PACKS.map((pack, ordinal) => join(dir, "registry-packs", identity, `${ordinal}-${pack.replaceAll("/", "-")}.yml`));
  for (const file of files) if (!existsSync(file)) {
    throw new Error(`restored Semgrep artifact is incomplete: ${file.slice(dir.length + 1)} is missing`);
  }
  const actualReceipt = semgrepPackReceipt(files, identity);
  if (stable(actualReceipt) !== stable(receipt)) {
    throw new Error("restored Semgrep artifact bytes/current.json disagree with receipt.json");
  }

  const expectedInventory = [
    "receipt.json",
    "registry-packs",
    "registry-packs/current.json",
    `registry-packs/${identity}`,
    ...files.map((file) => file.slice(dir.length + 1)),
  ].sort();
  const actualInventory = readRecursiveSafe(dir).sort();
  if (stable(actualInventory) !== stable(expectedInventory)) {
    const unexpected = actualInventory.filter((path) => !expectedInventory.includes(path));
    const missing = expectedInventory.filter((path) => !actualInventory.includes(path));
    throw new Error(`restored Semgrep artifact inventory is mixed or nested; unexpected=[${unexpected.join(", ")}]; missing=[${missing.join(", ")}]`);
  }
  return { identity, files, receipt };
}

export function prepareCurrentMechanicalTarget(options: {
  target: CurrentMechanicalTargetDefinition;
  checkoutDir: string;
  preparedDir: string;
  cloneCacheDir?: string;
  verifyRemote?: boolean;
  onPreparationStage?: (stage: "checkout-cloned" | "checkout-validated", checkoutDir: string) => void;
}): PreparedMechanicalTarget {
  const { target, checkoutDir, preparedDir } = options;
  cloneAtPinCached(target.repo, target.commit, checkoutDir, options.cloneCacheDir, options.verifyRemote ?? true);
  options.onPreparationStage?.("checkout-cloned", checkoutDir);
  const checkoutHead = execFileSync("git", ["-C", checkoutDir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  if (checkoutHead !== target.commit) throw new Error(`${target.slug}: checkout head ${checkoutHead} differs from pin ${target.commit}`);
  const checkoutTree = resolveGitTree(checkoutDir);
  const expectedTree = execFileSync("git", ["-C", checkoutDir, "rev-parse", `${target.commit}^{tree}`], { encoding: "utf8" }).trim();
  if (checkoutTree !== expectedTree) throw new Error(`${target.slug}: checkout tree ${checkoutTree} differs from pinned tree ${expectedTree}`);
  const trackedMutation = execFileSync("git", ["-C", checkoutDir, "diff", "--name-only", target.commit, "--"], { encoding: "utf8" }).trim();
  if (trackedMutation) throw new Error(`${target.slug}: tracked checkout content differs from pin ${target.commit}: ${trackedMutation}`);
  const removedVendoredSubtrees = [...(target.vendoredSubtrees ?? [])];
  for (const subtree of removedVendoredSubtrees) {
    if (subtree.length === 0 || subtree.startsWith("/") || subtree.includes("\\") || subtree.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new Error(`${target.slug}: vendored subtree is not a canonical target-relative path: ${JSON.stringify(subtree)}`);
    }
    const path = join(checkoutDir, subtree);
    if (!existsSync(path)) throw new Error(`${target.slug}: vendored subtree ${subtree} is absent before preparation`);
  }
  options.onPreparationStage?.("checkout-validated", checkoutDir);
  const trackedGitlinks = materializePinnedTrackedTree(checkoutDir, preparedDir, removedVendoredSubtrees);
  for (const subtree of removedVendoredSubtrees) rmSync(join(preparedDir, subtree), { recursive: true, force: true });
  for (const subtree of removedVendoredSubtrees) if (existsSync(join(preparedDir, subtree))) {
    throw new Error(`${target.slug}: vendored subtree ${subtree} survived the prepared copy`);
  }
  const preparedTreeSha256 = digestScanPopulation(preparedDir);

  // corpus-drift's M4-M10 consumers need a mutable tree because dependency installation is part of
  // their real execution contract. Give them the same manifest-pruned population as the immutable
  // mechanical input before that mutation starts. This used to prune only `preparedDir`, leaving the
  // legacy scanners on the untouched checkout (effective's vendored repos/effect then expanded its
  // M5-M8 baselines by thousands of rows). Empty gitlinks are filesystem surface, not nested bytes:
  // keep them explicit unless their containing subtree is itself excluded by the target manifest.
  for (const subtree of removedVendoredSubtrees) rmSync(join(checkoutDir, subtree), { recursive: true, force: true });
  for (const gitlink of trackedGitlinks) if (!removedVendoredSubtrees.some((subtree) => gitlink.path === subtree || gitlink.path.startsWith(`${subtree}/`))) {
    mkdirSync(join(checkoutDir, gitlink.path), { recursive: true });
  }
  for (const subtree of removedVendoredSubtrees) if (existsSync(join(checkoutDir, subtree))) {
    throw new Error(`${target.slug}: vendored subtree ${subtree} survived the mutable scan-tree preparation`);
  }
  const scanTreeSha256 = digestScanPopulation(checkoutDir);
  if (scanTreeSha256 !== preparedTreeSha256) {
    throw new Error(`${target.slug}: mutable scan tree differs from the pinned prepared population before install: ${scanTreeSha256} != ${preparedTreeSha256}`);
  }
  return { checkoutDir, preparedDir, scanDir: checkoutDir, checkoutHead, checkoutTree, preparedTreeSha256, emptyGitlinks: trackedGitlinks, removedVendoredSubtrees };
}

function materializePinnedTrackedTree(checkoutDir: string, preparedDir: string, excludedSubtrees: readonly string[]): EmptyGitlinkReceipt[] {
  if (existsSync(preparedDir)) throw new Error(`prepared target destination already exists: ${preparedDir}`);
  const listed = execFileSync("git", ["-C", checkoutDir, "ls-files", "--stage", "-z"], { encoding: "buffer" });
  const entries = listed.toString("utf8").split("\0").filter(Boolean).map((row) => {
    const separator = row.indexOf("\t");
    if (separator < 0) throw new Error(`malformed tracked-file row: ${JSON.stringify(row)}`);
    const [mode, object, stage] = row.slice(0, separator).split(" ");
    const path = row.slice(separator + 1);
    if (!/^[a-f0-9]{40,64}$/.test(object ?? "") || stage !== "0" || path.length === 0 || path.startsWith("/") || path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new Error(`unsafe or incomplete tracked-file row: ${JSON.stringify(row)}`);
    }
    return { mode, object: object!, path };
  });
  const gitlinks: EmptyGitlinkReceipt[] = [];
  try {
    mkdirSync(preparedDir);
    for (const entry of entries) {
      if (excludedSubtrees.some((subtree) => entry.path === subtree || entry.path.startsWith(`${subtree}/`))) continue;
      // A gitlink without an initialized worktree is represented by Git as an empty directory. The
      // pinned inbox-zero revision carries exactly that shape (and no .gitmodules URL from which its
      // 160000 object could be fetched). Preserve the pinned checkout's real filesystem surface:
      // make the empty directory explicit, but never invent or fetch content the parent pin does not
      // contain. If a caller initializes a gitlink, refuse below rather than silently scanning an
      // unbound nested checkout whose bytes are outside the parent tree identity.
      if (entry.mode === "160000") {
        const source = join(checkoutDir, entry.path);
        const sourceStat = lstatSync(source, { throwIfNoEntry: false });
        if (sourceStat && (!sourceStat.isDirectory() || readRecursiveSafe(source).length > 0)) {
          throw new Error(`tracked gitlink ${entry.path} has materialized content that is not bound by the parent target tree`);
        }
        mkdirSync(join(preparedDir, entry.path), { recursive: true });
        gitlinks.push({ path: entry.path, object: entry.object, representation: "empty-directory" });
        continue;
      }
      if (entry.mode !== "100644" && entry.mode !== "100755" && entry.mode !== "120000") throw new Error(`tracked path ${entry.path} has unsupported Git mode ${entry.mode}`);
      const source = join(checkoutDir, entry.path);
      const destination = join(preparedDir, entry.path);
      const sourceStat = lstatSync(source, { throwIfNoEntry: false });
      if (!sourceStat) throw new Error(`tracked file ${entry.path} is missing from the validated checkout`);
      mkdirSync(dirname(destination), { recursive: true });
      if (entry.mode === "120000") {
        if (!sourceStat.isSymbolicLink()) throw new Error(`tracked symlink ${entry.path} is missing or has the wrong filesystem type`);
        symlinkSync(readlinkSync(source), destination);
      } else {
        if (!sourceStat.isFile()) throw new Error(`tracked file ${entry.path} is missing or has the wrong filesystem type`);
        copyFileSync(source, destination);
        chmodSync(destination, entry.mode === "100755" ? 0o755 : 0o644);
      }
    }
  } catch (error) {
    rmSync(preparedDir, { recursive: true, force: true });
    throw new Error(`pinned tracked-tree materialization failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  return gitlinks;
}

function digestScanPopulation(dir: string): string {
  const files: string[] = [];
  const walk = (current: string, prefix: string): void => {
    for (const entry of readEntriesSafe(current).entries) {
      if (entry.name === ".git") continue;
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory) walk(entry.path, relative);
      else if (statSafe(entry.path)?.isFile()) files.push(relative);
    }
  };
  walk(dir, "");
  const parts: Array<string | Buffer> = [];
  for (const relative of files.sort()) parts.push(relative, readFileSync(join(dir, relative)));
  return digestParts(parts);
}

export function assertPreparedTargetUnchanged(prepared: PreparedMechanicalTarget): void {
  const after = digestScanPopulation(prepared.preparedDir);
  if (after !== prepared.preparedTreeSha256) throw new Error(`prepared mechanical target mutated during execution: ${after} != ${prepared.preparedTreeSha256}`);
}

export function currentRuntimeReceipt(): CurrentMechanicalExecutionArtifact["runtime"] {
  return {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    semgrep: binaryVersion("semgrep"),
    gitleaks: binaryVersion("gitleaks"),
  };
}

export function currentGitVersionReceipt(): string {
  return binaryVersion("git");
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
  if (artifact.schema !== 3 || artifact.kind !== "current-mechanical-execution" || artifact.population !== CURRENT_MECHANICAL_POPULATION) throw new Error(`${source}: not a current mechanical execution artifact`);
  if (artifact.side !== "hosted-producer" && artifact.side !== "independent-replay") throw new Error(`${source}: execution side is invalid`);
  if (!artifact.executionId.startsWith(`${artifact.side}:`)) throw new Error(`${source}: execution id is missing or belongs to another side`);
  if (!Array.isArray(artifact.commands) || artifact.commands.length === 0 || artifact.commands.some((command) => typeof command !== "string" || command.length === 0)) throw new Error(`${source}: execution command receipt is missing`);
  if (!/^[a-f0-9]{40}$/.test(artifact.headCommit)) throw new Error(`${source}: head is not a full Git commit`);
  assertSha(artifact.harnessSha256, `${source}: harness`);
  assertSha(artifact.targetPinsSha256, `${source}: target pins`);
  if (!artifact.runtime || [artifact.runtime.node, artifact.runtime.platform, artifact.runtime.arch, artifact.runtime.semgrep, artifact.runtime.gitleaks].some((value) => typeof value !== "string" || value.length === 0)) {
    throw new Error(`${source}: runtime receipt is missing or malformed`);
  }
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
    if (typeof target.gitVersion !== "string" || target.gitVersion.length === 0) throw new Error(`${source}: ${slug} Git materialization provenance is missing`);
    if (target.preparation !== CURRENT_MECHANICAL_PREPARATION || target.captureBeforeInstall !== true || target.installMutationAtCapture !== false) throw new Error(`${source}: ${slug} was not captured before install mutation`);
    if (target.skipBundleScan !== true || target.bundleDigest !== digestParts(["bundle-pinned-off-v1"])) throw new Error(`${source}: ${slug} bundle input was not pinned off`);
    if (stable(target.removedVendoredSubtrees) !== stable([...(declared.vendoredSubtrees ?? [])])) throw new Error(`${source}: ${slug} vendored-subtree preparation differs from the manifest`);
    if (!Array.isArray(target.emptyGitlinks) || target.emptyGitlinks.some((entry) => !canonicalTargetRelativePath(entry.path) || !/^[a-f0-9]{40,64}$/.test(entry.object) || entry.representation !== "empty-directory")
      || new Set(target.emptyGitlinks.map((entry) => entry.path)).size !== target.emptyGitlinks.length) {
      throw new Error(`${source}: ${slug} empty-gitlink receipt is missing or malformed`);
    }
    if (target.executionPlan?.schema !== 1 || stable(target.executionPlan.phases) !== stable(MECHANICAL_PHASES)
      || target.executionPlan.semgrep?.strategy !== "partitioned-families" || target.executionPlan.semgrep.families.length === 0
      || new Set(target.executionPlan.semgrep.families.map((family) => family.id)).size !== target.executionPlan.semgrep.families.length
      || target.executionPlan.semgrep.families.some((family, ordinal) => family.ordinal !== ordinal
        || !SHA256.test(family.configSha256)
        || !Array.isArray(family.argv) || family.argv.length === 0
        || (family.verification !== "single" && family.verification !== "paired-cold-exact"))
      || target.executionPlan.semgrep.schema !== 3
      || Object.keys(target.executionPlan.implementation).length === 0 || Object.keys(target.executionPlan.externalInputs).length === 0) {
      throw new Error(`${source}: ${slug} semantic execution-plan receipt is missing or malformed`);
    }
    const policy = target.cachePolicy;
    if (policy?.schema !== 1 || !SHA256.test(policy.namespaceSha256)
      || (artifact.side === "hosted-producer" && (policy.mode !== "hosted-content-addressed" || policy.emptyNamespaceVerified || !policy.producerArtifactsAllowed))
      || (artifact.side === "independent-replay" && (policy.mode !== "independent-cold-off" || !policy.emptyNamespaceVerified || policy.producerArtifactsAllowed))) {
      throw new Error(`${source}: ${slug} cache policy/namespace does not preserve producer/replay isolation`);
    }
    const diagnostics = target.semgrepDiagnostics;
    if (diagnostics?.schema !== 1 || !Array.isArray(diagnostics.errors) || !Array.isArray(diagnostics.skipped)
      || diagnostics.sha256 !== sha256(stable({ errors: diagnostics.errors, skipped: diagnostics.skipped }))) {
      throw new Error(`${source}: ${slug} complete Semgrep diagnostic evidence is missing or corrupt`);
    }
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
    // Git provenance is deliberately retained on each target but not compared as an engine
    // identity. A different Git build is acceptable only after the same target's pin, checkout
    // tree, prepared bytes, execution plan, findings, producer census, and diagnostics all agree.
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
    if (stable(left.emptyGitlinks) !== stable(right.emptyGitlinks)) throw new Error(`${slug}: explicit empty-gitlink path/object/representation receipt differs`);
    if (stable(left.executionPlan) !== stable(right.executionPlan)) throw new Error(`${slug}: semantic execution-plan strategy/families/flags/config/identity differs`);
    if (left.cachePolicy.namespaceSha256 === right.cachePolicy.namespaceSha256) throw new Error(`${slug}: producer/replay cache namespaces overlap`);
    if (stable(left.semgrepDiagnostics) !== stable(right.semgrepDiagnostics)) throw new Error(`${slug}: complete ordered Semgrep errors/skipped evidence differs`);
    if (stable(left.findings) !== stable(right.findings)) throw new Error(`${slug}: ordered raw mechanical finding fields/order/population differ`);
    if (stable(left.producers.map(normalizedProducer)) !== stable(right.producers.map(normalizedProducer))) throw new Error(`${slug}: producer order, findings, status, or exact examined-unit population differs`);
  }
}
