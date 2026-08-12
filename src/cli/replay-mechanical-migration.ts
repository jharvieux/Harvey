import "./sync-stdio.js";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "../findings.js";
import { loadCorpusAdvisorySnapshot } from "../corpus-advisory-snapshot.js";
import { cloneAtPinCached } from "../scan/corpus-clone.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { runMechanicalScanDetailed } from "../scan/mechanical.js";
import type { MechanicalPhaseCacheOptions } from "../scan/mechanical-phase-cache.js";
import { binaryVersion, digestFiles, digestParts, resolveGitTree } from "../scan/mechanical-phase-cache.js";
import { shardTargets } from "../scan/corpus-shards.js";
import { materializeRegistryPacks } from "../scan/semgrep.js";

const MECHANICAL_CORPUS_POPULATION = "runMechanicalScanDetailed.findings-v1" as const;

interface ReplayArtifact {
  schema: 1;
  population: typeof MECHANICAL_CORPUS_POPULATION;
  engineCommit: string;
  orchestrator: "manual" | "registry";
  engineAmendmentPaths: string[];
  engineAmendmentPatchSha256?: string;
  harnessSha256: string;
  targetPinsSha256: string;
  advisoryManifestSha256: string;
  semgrepRegistrySha256: string;
  targetCount: number;
  targets: string[];
  externalState: Record<string, {
    advisorySha256: string;
    secretCandidateIdentity: string;
    semgrepRegistrySha256: string;
    networkFallbacksDisabled: true;
    bundleScanPinnedOff: true;
  }>;
  mechanicalFindings: Record<string, Finding[]>;
}

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const sha256 = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const harnessPath = fileURLToPath(import.meta.url);
const out = flag("--out");
const merge = flag("--merge");
if (merge) {
  if (!out) throw new Error("--merge requires --out");
  const paths = merge.split(",").filter(Boolean);
  if (paths.length < 2) throw new Error("--merge requires at least two comma-separated replay artifacts");
  const artifacts = paths.map((path) => JSON.parse(readFileSync(path, "utf8")) as ReplayArtifact);
  const first = artifacts[0]!;
  const invariant = (artifact: ReplayArtifact): string => JSON.stringify({
    schema: artifact.schema,
    population: artifact.population,
    engineCommit: artifact.engineCommit,
    orchestrator: artifact.orchestrator,
    engineAmendmentPaths: artifact.engineAmendmentPaths,
    engineAmendmentPatchSha256: artifact.engineAmendmentPatchSha256,
    harnessSha256: artifact.harnessSha256,
    targetPinsSha256: artifact.targetPinsSha256,
    advisoryManifestSha256: artifact.advisoryManifestSha256,
    semgrepRegistrySha256: artifact.semgrepRegistrySha256,
  });
  if (artifacts.some((artifact) => invariant(artifact) !== invariant(first))) throw new Error("replay shards do not share one engine/input/harness identity");
  const mechanicalFindings: Record<string, Finding[]> = {};
  const externalState: ReplayArtifact["externalState"] = {};
  for (const artifact of artifacts) for (const target of artifact.targets) {
    if (target in mechanicalFindings) throw new Error(`replay target ${target} appears in more than one shard`);
    mechanicalFindings[target] = artifact.mechanicalFindings[target]!;
    externalState[target] = artifact.externalState[target]!;
  }
  const targets = Object.keys(mechanicalFindings).sort();
  const expected = EXTERNAL_CORPUS.map((target) => target.slug).sort();
  if (JSON.stringify(targets) !== JSON.stringify(expected)) throw new Error(`merged replay target population differs: got [${targets.join(", ")}], expected [${expected.join(", ")}]`);
  writeFileSync(out, `${JSON.stringify({ ...first, targetCount: targets.length, targets, externalState, mechanicalFindings } satisfies ReplayArtifact, null, 2)}\n`);
  console.log(`MECHANICAL MIGRATION REPLAY MERGED — ${targets.length} target(s), ${Object.values(mechanicalFindings).reduce((sum, rows) => sum + rows.length, 0)} ordered row(s)`);
  process.exit(0);
}
const snapshotDir = resolve(flag("--snapshot-dir") ?? "src/scan/__fixtures__/corpus-advisories");
const registryDir = resolve(flag("--registry-dir") ?? ".harvey-mechanical-replay-registry");
const registryMode = flag("--registry-mode") ?? "reuse";
if (registryMode !== "refresh" && registryMode !== "reuse") throw new Error("--registry-mode must be refresh or reuse");
const registry = materializeRegistryPacks(registryDir, registryMode);
if (!registry.identity || !registry.files || registry.failure) throw new Error(registry.failure ?? "Semgrep registry snapshot did not materialize");
if (args.includes("--materialize-only")) {
  console.log(`MECHANICAL MIGRATION REPLAY REGISTRY SNAPSHOT sha256:${registry.identity}`);
  process.exit(0);
}
if (!out) throw new Error("usage: replay-mechanical-migration --out <artifact.json> [--shard i/n] [--snapshot-dir dir] [--registry-dir dir] [--registry-mode refresh|reuse]");

const head = execFileSync("git", ["-C", repoRoot, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const amendmentPaths = execFileSync("git", ["-C", repoRoot, "diff", "--name-only"], { encoding: "utf8" })
  .trim().split("\n").filter(Boolean).sort();
const allowedAmendments = (flag("--allow-amendment") ?? "").split(",").filter(Boolean).sort();
if (JSON.stringify(amendmentPaths) !== JSON.stringify(allowedAmendments)) {
  throw new Error(`replay engine has unaccounted working-tree amendments [${amendmentPaths.join(", ")}], allowed [${allowedAmendments.join(", ")}]`);
}
const amendmentPatch = amendmentPaths.length > 0
  ? execFileSync("git", ["-C", repoRoot, "diff", "--", ...amendmentPaths], { encoding: "utf8", maxBuffer: 1024 * 1024 * 16 })
  : undefined;
const mechanicalSource = readFileSync(join(repoRoot, "src/scan/mechanical.ts"), "utf8");
const orchestrator = mechanicalSource.includes("runRegisteredMechanicalDetectors") ? "registry" : "manual";
const targetPinsSha256 = sha256(JSON.stringify(EXTERNAL_CORPUS.map(({ slug, repo, commit, vendoredSubtrees }) => ({ slug, repo, commit, vendoredSubtrees }))));
const advisoryManifestPath = join(snapshotDir, "manifest.json");
if (!existsSync(advisoryManifestPath)) throw new Error(`advisory snapshot manifest is missing: ${advisoryManifestPath}`);
const advisoryManifestSha256 = sha256(readFileSync(advisoryManifestPath));
let selected = EXTERNAL_CORPUS;
const shard = flag("--shard");
if (shard) {
  const [rawIndex, rawCount] = shard.split("/");
  const index = Number(rawIndex);
  const count = Number(rawCount);
  const slugs = new Set(shardTargets(EXTERNAL_CORPUS.map((target) => target.slug), index, count));
  selected = EXTERNAL_CORPUS.filter((target) => slugs.has(target.slug));
}

const mechanicalFindings: Record<string, Finding[]> = {};
const externalState: ReplayArtifact["externalState"] = {};
for (const target of selected) {
  const dir = mkdtempSync(join(tmpdir(), `harvey-mechanical-replay-${target.slug}-`));
  try {
    cloneAtPinCached(target.repo, target.commit, dir, process.env.HARVEY_CORPUS_CACHE_DIR, true);
    const snapshot = loadCorpusAdvisorySnapshot(target.slug, target.commit, { dir: snapshotDir });
    const targetTreeIdentity = `${resolveGitTree(dir)}:${JSON.stringify(target.vendoredSubtrees ?? [])}`;
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
      dir,
      skipNetworkChecks: true,
      skipBundleScan: true,
      advisorySnapshot: snapshot,
      secretCandidateIdentity,
      phaseCache,
    });
    mechanicalFindings[target.slug] = result.findings;
    externalState[target.slug] = {
      advisorySha256: snapshot.digest,
      secretCandidateIdentity,
      semgrepRegistrySha256: registry.identity,
      networkFallbacksDisabled: true,
      bundleScanPinnedOff: true,
    };
    console.error(`${target.slug}: ${result.findings.length} ordered mechanical row(s)`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const targets = Object.keys(mechanicalFindings).sort();
const artifact: ReplayArtifact = {
  schema: 1,
  population: MECHANICAL_CORPUS_POPULATION,
  engineCommit: head,
  orchestrator,
  engineAmendmentPaths: amendmentPaths,
  ...(amendmentPatch ? { engineAmendmentPatchSha256: sha256(amendmentPatch) } : {}),
  harnessSha256: sha256(readFileSync(harnessPath)),
  targetPinsSha256,
  advisoryManifestSha256,
  semgrepRegistrySha256: registry.identity,
  targetCount: targets.length,
  targets,
  externalState,
  mechanicalFindings,
};
writeFileSync(out, `${JSON.stringify(artifact, null, 2)}\n`);
console.log(`MECHANICAL MIGRATION REPLAY ${orchestrator.toUpperCase()} — ${targets.length} target(s), ${Object.values(mechanicalFindings).reduce((sum, rows) => sum + rows.length, 0)} ordered row(s)`);
