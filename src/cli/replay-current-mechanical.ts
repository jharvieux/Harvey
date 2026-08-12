import "./sync-stdio.js";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  assertPreparedTargetUnchanged,
  CURRENT_MECHANICAL_POPULATION,
  CURRENT_MECHANICAL_PREPARATION,
  currentHarnessReceipt,
  currentRuntimeReceipt,
  currentTargetPinsSha256,
  newExecutionId,
  prepareCurrentMechanicalTarget,
  semgrepPackReceipt,
  type CurrentMechanicalExecutionArtifact,
  type CurrentMechanicalTargetDefinition,
} from "../corpus-mechanical-readiness.js";
import { loadCorpusAdvisorySnapshot } from "../corpus-advisory-snapshot.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { runMechanicalScanDetailed } from "../scan/mechanical.js";
import type { MechanicalPhaseCacheOptions } from "../scan/mechanical-phase-cache.js";
import { binaryVersion, digestFiles, digestParts } from "../scan/mechanical-phase-cache.js";
import { shardTargets } from "../scan/corpus-shards.js";
import { materializeRegistryPacks } from "../scan/semgrep.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const out = flag("--out");
const shardSpec = flag("--shard") ?? "1/1";
const registryDir = resolve(flag("--registry-dir") ?? ".harvey-current-replay-cache");
if (!out) throw new Error("usage: replay-current-mechanical --out <artifact.json> [--shard i/n] [--registry-dir dir]");
const [rawIndex, rawCount] = shardSpec.split("/");
const shard = { index: Number(rawIndex), count: Number(rawCount) };
const allTargets: CurrentMechanicalTargetDefinition[] = EXTERNAL_CORPUS.map(({ slug, repo, commit, vendoredSubtrees }) => ({ slug, repo, commit, vendoredSubtrees }));
const mine = new Set(shardTargets(allTargets.map((target) => target.slug), shard.index, shard.count));
const registry = materializeRegistryPacks(registryDir, "reuse");
if (!registry.identity || !registry.files || registry.failure) throw new Error(registry.failure ?? "shared Semgrep registry snapshot is unavailable");
const repoRoot = resolve(new URL("../..", import.meta.url).pathname);
const harness = currentHarnessReceipt(repoRoot);
const artifact: CurrentMechanicalExecutionArtifact = {
  schema: 1,
  kind: "current-mechanical-execution",
  population: CURRENT_MECHANICAL_POPULATION,
  side: "independent-replay",
  executionId: newExecutionId("independent-replay", shard),
  ...harness,
  commands: [process.argv.join(" ")],
  options: { skipNetworkChecks: true, skipBundleScan: true, advisoryMode: "snapshot", phaseCache: "off", bundleDir: null, handrolledIndicators: false, authGuards: [] },
  targetPinsSha256: currentTargetPinsSha256(allTargets),
  allTargets,
  semgrepRegistry: semgrepPackReceipt(registry.files, registry.identity),
  runtime: currentRuntimeReceipt(),
  shard,
  targets: {},
};

for (const target of allTargets.filter((candidate) => mine.has(candidate.slug))) {
  const root = mkdtempSync(join(tmpdir(), `harvey-current-replay-${target.slug}-`));
  const checkoutDir = join(root, "checkout");
  const preparedDir = join(root, "prepared");
  try {
    const prepared = prepareCurrentMechanicalTarget({ target, checkoutDir, preparedDir, cloneCacheDir: process.env.HARVEY_CORPUS_CACHE_DIR });
    const snapshot = loadCorpusAdvisorySnapshot(target.slug, target.commit);
    const targetTreeIdentity = `${prepared.checkoutTree}:${JSON.stringify(target.vendoredSubtrees ?? [])}:${prepared.preparedTreeSha256}`;
    const secretCandidateIdentity = digestParts([
      targetTreeIdentity,
      digestFiles([join(repoRoot, "src", "scan", "rules", "gitleaks-supabase.toml")], repoRoot),
      binaryVersion("gitleaks"),
    ]);
    const phaseCache: MechanicalPhaseCacheOptions = {
      dir: registryDir,
      mode: "off",
      targetRevision: target.commit,
      targetTree: targetTreeIdentity,
      implementation: {},
      externalInputs: {},
      materializedInputs: { semgrep: registry.files },
    };
    const result = await runMechanicalScanDetailed({
      dir: preparedDir,
      skipNetworkChecks: true,
      skipBundleScan: true,
      advisorySnapshot: snapshot,
      secretCandidateIdentity,
      phaseCache,
    });
    assertPreparedTargetUnchanged(prepared);
    artifact.targets[target.slug] = {
      slug: target.slug,
      repo: target.repo,
      pin: target.commit,
      checkoutHead: prepared.checkoutHead,
      checkoutTree: prepared.checkoutTree,
      preparedTreeSha256: prepared.preparedTreeSha256,
      preparation: CURRENT_MECHANICAL_PREPARATION,
      removedVendoredSubtrees: prepared.removedVendoredSubtrees,
      captureBeforeInstall: true,
      installMutationAtCapture: false,
      skipBundleScan: true,
      bundleDigest: digestParts(["bundle-pinned-off-v1"]),
      advisorySha256: snapshot.digest,
      advisoryVersion: snapshot.osvScannerVersion,
      secretCandidateIdentity,
      findings: result.findings,
      producers: result.detectors,
      context: result.context,
    };
    console.error(`${target.slug}: ${result.findings.length} ordered current-replay row(s), ${result.detectors.length} producer receipt(s)`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// Read-after-write is intentional: the artifact crossing the workflow boundary is the evidence,
// not merely the in-memory value the child happened to hold.
writeFileSync(out, `${JSON.stringify(artifact, null, 2)}\n`);
JSON.parse(readFileSync(out, "utf8"));
console.log(`CURRENT MECHANICAL INDEPENDENT REPLAY WRITTEN — ${Object.keys(artifact.targets).length} target(s), Semgrep sha256:${artifact.semgrepRegistry.aggregateSha256}`);
