import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";
import { compareCorpusAdvisoryState, type CorpusAdvisoryObservationArtifact } from "../corpus-advisory-snapshot.js";
import { semgrepPackReceipt } from "../corpus-mechanical-readiness.js";
import { partitionTargets } from "../scan/corpus-shards.js";
import { runOsvScanner } from "../scan/dependencies.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { REGISTRY_PACKS, registryPackIdentity } from "../scan/semgrep.js";

const root = process.cwd();
const tsxLoader = createRequire(import.meta.url).resolve("tsx");
const directories: string[] = [];
const workflow = parse(readFileSync(join(root, ".github/workflows/corpus-drift.yml"), "utf8")) as { jobs: { drift: { steps: { name?: string; run?: string }[] } } };
const command = workflow.jobs.drift.steps.find(({ name }) => name === "Merge and validate the complete live advisory population")!.run!;
afterEach(() => directories.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

function run(mutation: string) {
  const dir = mkdtempSync(join(tmpdir(), "corpus-observation-cli-"));
  directories.push(dir);
  const source = join(dir, "source");
  const snapshots = join(source, "src/scan/__fixtures__/corpus-advisories");
  const partsDir = join(dir, "advisory-parts");
  mkdirSync(snapshots, { recursive: true });
  mkdirSync(partsDir);
  const input = runOsvScanner(dir); // Empty input produces a real, offline not-applicable receipt.
  const snapshotBytes = gzipSync(JSON.stringify({ schema: 1, ...input }));
  const snapshotSha256 = createHash("sha256").update(snapshotBytes).digest("hex");
  const capturedAt = "2020-01-01T00:00:00Z";
  const expiresAt = "2999-01-01T00:00:00Z";
  const targets = EXTERNAL_CORPUS.map(({ slug, repo, commit }) => ({ slug, repo, pin: commit }));
  const manifest = { schema: 2, targets: Object.fromEntries(targets.map(({ slug, pin }) => {
    writeFileSync(join(snapshots, `${slug}.osv.json.gz`), snapshotBytes);
    return [slug, { file: `${slug}.osv.json.gz`, sha256: snapshotSha256, targetCommit: pin, capturedAt, expiresAt, osvScannerVersion: "fixture-2.3.8" }];
  })) };
  const manifestBytes = JSON.stringify(manifest);
  writeFileSync(join(snapshots, "manifest.json"), manifestBytes);
  const registry = join(source, ".harvey-current-semgrep");
  const bodies = REGISTRY_PACKS.map((pack, index) => ({ pack, body: `rules:\n  - id: fixture-${index}\n    message: ${pack}\n` }));
  const registrySha256 = registryPackIdentity(bodies);
  const packs = join(registry, "registry-packs", registrySha256);
  mkdirSync(packs, { recursive: true });
  const files = bodies.map(({ pack, body }, index) => {
    const path = join(packs, `${index}-${pack.replaceAll("/", "-")}.yml`);
    writeFileSync(path, body);
    return path;
  });
  writeFileSync(join(registry, "registry-packs/current.json"), JSON.stringify({ schema: 1, identity: registrySha256 }));
  writeFileSync(join(registry, "receipt.json"), JSON.stringify(semgrepPackReceipt(files, registrySha256)));
  const provenance = { headSha: "a".repeat(40), runId: "123", runAttempt: "1", registrySha256, snapshotManifestSha256: createHash("sha256").update(manifestBytes).digest("hex") };
  const comparison = compareCorpusAdvisoryState({ liveRaw: input.result, snapshotRaw: input.result, liveFindings: [], snapshotFindings: [], liveAssessment: input.assessment, snapshotAssessment: input.assessment });
  const parts: CorpusAdvisoryObservationArtifact[] = partitionTargets(targets.map(({ slug }) => slug), 4).map((slugs, index) => ({
    schema: 1, mode: "live-verify", provenance, shard: { index: index + 1, count: 4 },
    startedAt: capturedAt, completedAt: capturedAt, populationComplete: true, liveOsvScannerVersion: "fixture-2.3.8",
    expectedTargets: targets.filter(({ slug }) => slugs.includes(slug)),
    targets: Object.fromEntries(targets.filter(({ slug }) => slugs.includes(slug)).map((target) => [target.slug, {
      ...target, startedAt: capturedAt, observedAt: capturedAt, status: "equal",
      snapshot: { artifactSha256: snapshotSha256, capturedAt, expiresAt, osvScannerVersion: "fixture-2.3.8" },
      comparison: structuredClone(comparison),
    }])),
  }));
  if (mutation === "missing") parts.pop();
  if (mutation === "duplicate") parts[1] = structuredClone(parts[0]!);
  if (mutation === "wrong-run") parts[0]!.provenance = { ...provenance, runId: "another-run" };
  if (mutation === "interrupted") {
    parts[0]!.completedAt = null;
    parts[0]!.populationComplete = false;
    Object.values(parts[0]!.targets)[0]!.status = "started";
  }
  parts.forEach((part, index) => writeFileSync(join(partsDir, `corpus-advisory-observation-shard${index + 1}.json`), JSON.stringify(part)));
  const result = spawnSync("bash", ["-c", 'pnpm() { [ "$1" = exec ] && [ "$2" = tsx ] || return 99; shift 2; "$TEST_NODE" --import "$TEST_TSX" "$TEST_SOURCE/$1" "${@:2}"; }\n' + command], {
    cwd: source, encoding: "utf8",
    env: { ...process.env, TEST_NODE: process.execPath, TEST_TSX: tsxLoader, TEST_SOURCE: root, GITHUB_SHA: provenance.headSha, GITHUB_RUN_ID: provenance.runId, GITHUB_RUN_ATTEMPT: provenance.runAttempt },
  });
  const path = join(dir, "corpus-advisory-observation.json");
  return { result, parts, artifact: existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) as CorpusAdvisoryObservationArtifact : undefined };
}

describe("shipping live observation aggregation command (#2153)", () => {
  it("assembles the complete pinned population through the actual workflow command", () => {
    const { result, parts, artifact } = run("complete");
    expect(result.status, result.stderr).toBe(0);
    expect(artifact?.populationComplete).toBe(true);
    expect(artifact?.targets).toEqual(Object.assign({}, ...parts.map(({ targets }) => targets)));
    expect(artifact?.expectedTargets).toHaveLength(EXTERNAL_CORPUS.length);
  });
  it.each(["missing", "duplicate", "wrong-run"])("refuses %s inputs before publishing a canonical observation", (mutation) => {
    const { result, artifact } = run(mutation);
    expect(result.status, result.stderr).toBe(1);
    expect(artifact).toBeUndefined();
  });
  it("delivers interrupted observations with a nonzero outcome and incomplete population", () => {
    const { result, artifact } = run("interrupted");
    expect(result.status, result.stderr).toBe(1);
    expect(result.stderr).toContain("incomplete live advisory population");
    expect(artifact?.populationComplete).toBe(false);
    expect(artifact?.completedAt).toBeNull();
  });
});
