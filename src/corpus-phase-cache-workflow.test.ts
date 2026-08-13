import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { rejectCorpusCacheTransport } from "./corpus-cache-transport.js";
import { semgrepPackReceipt, validateRestoredSemgrepPackArtifact } from "./corpus-mechanical-readiness.js";
import { readRecursiveSafe, statSafe } from "./fs-walk.js";
import { REGISTRY_PACKS, registryPackIdentity } from "./scan/semgrep.js";

const root = process.cwd();
const path = join(root, ".github", "workflows", "corpus-drift.yml");
const workflow = readFileSync(path, "utf8");
const mechanical = readFileSync(join(root, "src", "scan", "mechanical.ts"), "utf8");
const corpusCli = readFileSync(join(root, "src", "cli", "corpus-drift.ts"), "utf8");
const replayCli = readFileSync(join(root, "src", "cli", "replay-current-mechanical.ts"), "utf8");
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const dir of temporaryDirectories.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function temporary(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(dir);
  return dir;
}

function seedSemgrepArtifact(dir: string, marker: string): string {
  const bodies = REGISTRY_PACKS.map((pack, ordinal) => ({ pack, body: `rules:\n  - id: ${marker}-${ordinal}\n    message: ${pack}\n` }));
  const identity = registryPackIdentity(bodies);
  const packDir = join(dir, "registry-packs", identity);
  mkdirSync(packDir, { recursive: true });
  const files = bodies.map(({ pack, body }, ordinal) => {
    const file = join(packDir, `${ordinal}-${pack.replaceAll("/", "-")}.yml`);
    writeFileSync(file, body);
    return file;
  });
  writeFileSync(join(dir, "registry-packs", "current.json"), `${JSON.stringify({ schema: 1, identity }, null, 2)}\n`);
  writeFileSync(join(dir, "receipt.json"), `${JSON.stringify(semgrepPackReceipt(files, identity), null, 2)}\n`);
  return identity;
}

/** Model upload-artifact's directory common-root stripping and download-by-name's direct restore. */
function artifactPayload(source: string, includeHiddenFiles: boolean): Map<string, Buffer> {
  return new Map(readRecursiveSafe(source)
    .filter((relative) => statSafe(join(source, relative))?.isFile())
    .filter((relative) => includeHiddenFiles || !relative.split("/").some((segment) => segment.startsWith(".")))
    .map((relative) => [relative, readFileSync(join(source, relative))]));
}

function downloadByName(payload: ReadonlyMap<string, Buffer>, destination: string): void {
  for (const [relative, body] of payload) {
    const file = join(destination, relative);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, body);
  }
}

function bytesDigest(files: readonly string[]): string {
  const hash = createHash("sha256");
  for (const file of files) hash.update(readFileSync(file));
  return hash.digest("hex");
}

describe("#1864 corpus phase-cache workflow contract", () => {
  it("keeps the required context reporting on every PR and failing on any shard result", () => {
    expect(workflow).toMatch(/^\s{2}pull_request:\s*$/m);
    expect(workflow).toContain("fail-fast: false");
    expect(workflow).toMatch(/drift:\n\s+name: clone\s+pinned\s+commits\s+\+\s+score\s+baselines\n\s+needs: \[prepare-current-inputs, shard, current-replay\]\n\s+if: always\(\)/);
    expect(workflow).toContain(`if [ "$result" != "success" ]`);
  });

  it("restores and saves the content-addressed directory without making a cache miss fatal or clean", () => {
    expect(workflow).toContain("uses: actions/cache/restore@v4");
    expect(workflow).toContain("uses: actions/cache/save@v4");
    expect(workflow.match(/path: \.harvey-corpus-phase-cache/g)).toHaveLength(5);
    expect(workflow).toContain("HARVEY_CORPUS_PHASE_CACHE_DIR: .harvey-corpus-phase-cache");
    expect(workflow).not.toMatch(/Restore content-addressed corpus phase results[\s\S]{0,300}continue-on-error/);
    expect(workflow).toContain("corpus-phase-run-v7-${{ runner.os }}-shard${{ matrix.shard }}-");
    expect(workflow).toContain("corpus-phase-main-v7-${{ runner.os }}-shard${{ matrix.shard }}-");
    expect(workflow).toContain("steps.phase-cache.outputs.cache-matched-key || steps.main-phase-cache.outputs.cache-matched-key");
    expect(workflow).toContain("Validate corpus phase-cache transport provenance");
    expect(workflow).toContain("Record corpus phase-cache transport provenance");
    expect(workflow).toContain("--matched-key '${{ steps.phase-cache.outputs.cache-matched-key || steps.main-phase-cache.outputs.cache-matched-key }}'");
    expect(workflow).toContain("--head-sha '${{ github.sha }}'");
    expect(workflow).toContain("--platform '${{ runner.os }}'");
    expect(workflow).toContain("--family '${{ inputs.benchmark_run_identity != '' && 'benchmark' || (github.event_name == 'push' && 'main' || 'run') }}'");
    expect(workflow).toContain("--namespace '${{ matrix.shard }}'");
    expect(workflow).toContain("CORPUS CACHE SIZE:");
  });

  it("seeds the default-branch cache after merge while preserving unconditional PR reporting", () => {
    expect(workflow).toMatch(/push:\n\s+branches: \[main\]/);
    expect(workflow).toContain("--default-ref 'refs/heads/${{ github.event.repository.default_branch }}'");
    expect(workflow).toContain("--event '${{ github.event_name }}'");
    expect(workflow).toContain("--ref '${{ github.ref }}'");
    expect(workflow).toContain("github.event_name == 'pull_request' || github.event_name == 'merge_group' || github.event_name == 'push'");
    expect(workflow.match(/github\.event_name == 'pull_request' \|\| github\.event_name == 'merge_group' \|\| github\.event_name == 'push'/g)).toHaveLength(5);
    expect(workflow).toContain("Save successful main-shard corpus phase results");
    expect(workflow).toContain("key: corpus-phase-main-v7-${{ runner.os }}-shard${{ matrix.shard }}-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.sha }}");
    expect(workflow).not.toContain("Save shard2 main-visible corpus phase results");
    expect(workflow).not.toContain("Save shard3 main-visible corpus phase results");
    expect(workflow).toContain("success() && steps.score.outcome == 'success'");
    expect(workflow).not.toMatch(/Save successful main-shard corpus phase results[\s\S]{0,250}if: always\(\)/);
    expect(workflow.match(/uses: actions\/cache\/save@v4/g)).toHaveLength(3);
  });

  it("materializes one exact Semgrep input and makes every producer and replay reuse it", () => {
    expect(workflow).toContain("name: Materialize the one current Semgrep registry input");
    expect(workflow).toContain("name: current-mechanical-semgrep-pack");
    expect(workflow.match(/name: Restore the run's exact shared Semgrep bytes/g)).toHaveLength(2);
    expect(workflow.match(/name: Validate the exact shared Semgrep artifact layout/g)).toHaveLength(2);
    expect(workflow.match(/path: \.harvey-current-semgrep/g)).toHaveLength(3);
    expect(workflow).toContain("include-hidden-files: true");
    expect(workflow).toContain("HARVEY_SEMGREP_REGISTRY_SNAPSHOT_DIR: .harvey-current-semgrep");
    expect(workflow).not.toContain("path: .harvey-current-replay-cache");
    expect(workflow).toContain("HARVEY_SEMGREP_REGISTRY_SNAPSHOT_MODE: reuse");
    expect(corpusCli).toContain("registryPackIdentity: sharedRegistry");
    expect(corpusCli).toContain("validateRestoredSemgrepPackArtifact(registrySnapshotDir!)");
    expect(corpusCli).toContain("resolve(registrySnapshotDir) === resolve(phaseCacheDir)");
    expect(replayCli).toContain("validateRestoredSemgrepPackArtifact(registryDir)");
  });

  it("reconstructs upload → download-by-name for both consumers with one identical canonical pack", () => {
    const source = join(temporary("semgrep-artifact-roundtrip-"), ".harvey-current-semgrep");
    const producer = join(temporary("semgrep-producer-"), ".harvey-current-semgrep");
    const replay = join(temporary("semgrep-replay-"), ".harvey-current-semgrep");
    const identity = seedSemgrepArtifact(source, "one-run");
    const payload = artifactPayload(source, true);

    expect(payload.has("registry-packs/current.json")).toBe(true);
    expect(payload.has("receipt.json")).toBe(true);
    expect([...payload.keys()].some((name) => name.startsWith(".harvey-current-semgrep/"))).toBe(false);
    downloadByName(payload, producer);
    downloadByName(payload, replay);

    const producerPack = validateRestoredSemgrepPackArtifact(producer);
    const replayPack = validateRestoredSemgrepPackArtifact(replay);
    expect(producerPack.identity).toBe(identity);
    expect(replayPack.identity).toBe(identity);
    expect(bytesDigest(producerPack.files)).toBe(bytesDigest(replayPack.files));
    expect(producerPack.receipt).toEqual(replayPack.receipt);
  });

  it("fails loud on nested, missing, mixed, or hidden upload payloads", () => {
    const source = join(temporary("semgrep-artifact-falsifiers-"), ".harvey-current-semgrep");
    seedSemgrepArtifact(source, "canonical");
    writeFileSync(join(source, ".partial-upload"), "must not disappear silently\n");
    const withHidden = artifactPayload(source, true);
    const withoutHidden = artifactPayload(source, false);
    expect(withHidden.has(".partial-upload")).toBe(true);
    expect(withoutHidden.has(".partial-upload")).toBe(false);

    const hidden = join(temporary("semgrep-hidden-"), ".harvey-current-semgrep");
    downloadByName(withHidden, hidden);
    expect(() => validateRestoredSemgrepPackArtifact(hidden)).toThrow(/inventory is mixed or nested/);

    const nested = join(temporary("semgrep-nested-"), ".harvey-current-semgrep");
    downloadByName(withoutHidden, join(nested, "current-mechanical-semgrep-pack"));
    expect(() => validateRestoredSemgrepPackArtifact(nested)).toThrow(/current\.json is missing/);

    const missing = join(temporary("semgrep-missing-"), ".harvey-current-semgrep");
    downloadByName(withoutHidden, missing);
    rmSync(join(missing, "registry-packs", "current.json"));
    expect(() => validateRestoredSemgrepPackArtifact(missing)).toThrow(/current\.json is missing/);

    const mixed = join(temporary("semgrep-mixed-"), ".harvey-current-semgrep");
    const other = join(temporary("semgrep-other-"), ".harvey-current-semgrep");
    downloadByName(withoutHidden, mixed);
    seedSemgrepArtifact(other, "different-run");
    copyFileSync(join(other, "receipt.json"), join(mixed, "receipt.json"));
    expect(() => validateRestoredSemgrepPackArtifact(mixed)).toThrow(/disagree with receipt\.json/);
  });

  it("keeps immutable registry bytes intact when a rejected mutable phase transport is cleared", () => {
    const job = temporary("semgrep-separated-transport-");
    const registry = join(job, ".harvey-current-semgrep");
    const phaseCache = join(job, ".harvey-corpus-phase-cache");
    seedSemgrepArtifact(registry, "immutable");
    mkdirSync(phaseCache);
    writeFileSync(join(phaseCache, "untrusted-phase.json"), "{}\n");

    rejectCorpusCacheTransport(phaseCache);

    expect(readRecursiveSafe(phaseCache)).toEqual([]);
    expect(() => validateRestoredSemgrepPackArtifact(registry)).not.toThrow();
  });

  it("keeps daily provider validation warm and exposes an explicit cold-equivalence drill", () => {
    expect(workflow).toContain("force_cold_cache:");
    expect(workflow).toContain('if [ "${{ inputs.force_cold_cache }}" = "true" ]');
    expect(workflow).not.toContain('if [ "${{ github.event_name }}" = "schedule" ] || [ "${{ github.event_name }}" = "workflow_dispatch" ]');
    expect(workflow).toContain("cold_flag=(--force-cold-cache)");
    expect(workflow.match(/"\$\{cold_flag\[@\]\}"/g)).toHaveLength(1);
    expect(mechanical).toContain("assertMechanicalCacheVerification(phases, opts.phaseCache)");
  });

  it("uses one discovered fail-open relevance receipt instead of copied workflow filters", () => {
    expect(workflow).toContain("pnpm corpus-relevance --base \"$base\" --head HEAD --out corpus-relevance.json");
    expect(workflow).toContain("name: corpus-relevance-receipt");
    expect(workflow).toContain("Reuse the one discovered corpus relevance verdict");
    expect(workflow).not.toContain('case "$f" in');
    const productionFiles = readRecursiveSafe(join(root, "src"))
      .filter((rel) => rel.endsWith(".ts") && !rel.endsWith(".test.ts") && statSafe(join(root, "src", rel))?.isFile());
    const importsTest = productionFiles.filter((rel) => /from\s+["'][^"']+\.test(?:\.js)?["']/.test(readFileSync(join(root, "src", rel), "utf8")));
    expect(importsTest, "a production module importing a test invalidates the workflow's test-only exclusion").toEqual([]);
  });

  it("keeps production selectors conservative and independently configurable", () => {
    expect(workflow).toContain("PR_RUNNER: ${{ vars.CORPUS_PR_RUNNER_LABEL }}");
    expect(workflow).toContain("SCHEDULE_RUNNER: ${{ vars.CORPUS_SCHEDULE_RUNNER_LABEL }}");
    expect(workflow).toContain("LARGER_RUNNER: ${{ vars.CORPUS_BENCHMARK_RUNNER_LABEL }}");
    expect(workflow).toContain("runner=ubuntu-latest");
    expect(workflow).toContain("configured-larger was requested but repository variable CORPUS_BENCHMARK_RUNNER_LABEL is empty; no runner claim is permitted");
    expect(workflow).toContain("default: serial");
    expect(workflow).toContain("default: '1'");
    expect(workflow).toContain("default: '3'");
    expect(workflow).toContain("--shard-profile auto --shard-cache-provenance uncertain");
    expect(workflow).toContain("--shard-profile warm --shard-cache-provenance verified-warm");
  });

  it("retains one sample envelope from the merged scorecard and raw Actions jobs", () => {
    expect(workflow).toContain("actions: read");
    expect(workflow).toContain("Read raw Actions jobs for the benchmark timing envelope");
    expect(workflow).toContain("Build the provenance-bound benchmark sample");
    expect(workflow).toContain("pnpm corpus-benchmark-sample");
    expect(workflow).toContain("benchmark-cache-merge-receipt-${{ matrix.shard }}.json");
    expect(workflow).toContain("benchmark-transport-${{ matrix.shard }}.json");
    expect(workflow).toContain("benchmark-runner-${{ matrix.shard }}.json");
    expect(workflow).toContain("shardProfiles: map(.shardProfile)");
    expect(workflow).toContain("corpus-benchmark-sample.json");
    expect(workflow).toContain("--run-attempt '${{ github.run_attempt }}'");
    expect(workflow).toContain("--benchmark-seed '${{ inputs.benchmark_seed }}'");
    expect(workflow).toContain("--requested-runner '${{ needs.prepare-current-inputs.outputs.runner }}'");
  });

  it("keeps split-carbon explicitly non-admissible until a separate runner lane exists", () => {
    expect(workflow).toContain("options: [serial, target-workers, intra-target-overlap]");
    expect(workflow).not.toContain("options: [serial, target-workers, intra-target-overlap, split-carbon]");
    expect(corpusCli).toContain("split-carbon has no independently admitted runner lane and is non-admissible");
    expect(corpusCli).toContain("process-isolated ${executionDesign}");
    const execution = readFileSync(join(root, "src", "corpus-execution.ts"), "utf8");
    expect(execution).toContain("split-carbon is non-admissible: this coordinator has no independent runner lane");
    const benchmark = readFileSync(join(root, "src", "corpus-benchmark.ts"), "utf8");
    expect(benchmark).toContain('if (sample.design === "serial" && sample.effectiveConcurrency !== 1)');
    expect(benchmark).toContain("non-admissible negative control: no independently admitted workflow job/runner lane exists");
  });
});
