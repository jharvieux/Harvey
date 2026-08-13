import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";
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
interface WorkflowStep { name?: string; if?: string; run?: string }
const parsedWorkflow = parse(workflow) as { jobs: { shard: { steps: WorkflowStep[] } } };
const shardSteps = parsedWorkflow.jobs.shard.steps;
const shardStep = (name: string): WorkflowStep => {
  const step = shardSteps.find((candidate) => candidate.name === name);
  if (!step) throw new Error(`workflow shard step is missing: ${name}`);
  return step;
};
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

  it("keeps benchmark advisory input immutable while schedule and ordinary dispatch stay live-verify", () => {
    const modeExpression = "${{ (github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.benchmark_run_identity == '')) && 'live-verify' || 'snapshot' }}";
    expect(workflow).toContain(`HARVEY_CORPUS_EXTERNAL_STATE_MODE: ${modeExpression}`);
    expect(workflow).toContain("HARVEY_CORPUS_BENCHMARK_RUN_IDENTITY: ${{ inputs.benchmark_run_identity }}");
    expect(workflow).not.toContain("(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && 'live-verify'");
    expect(corpusCli).toContain("benchmark seed/sample runs cannot consume mutable live advisory state");

    // The workflow expression's truth table is deliberate: schedule and an ordinary click are
    // freshness lanes; PR/push/queue and either benchmark shape are reproducible snapshot lanes.
    const intendedMode = (event: string, benchmarkIdentity: string): "snapshot" | "live-verify" =>
      event === "schedule" || (event === "workflow_dispatch" && benchmarkIdentity === "") ? "live-verify" : "snapshot";
    expect(intendedMode("schedule", "")).toBe("live-verify");
    expect(intendedMode("workflow_dispatch", "")).toBe("live-verify");
    expect(intendedMode("workflow_dispatch", "seed-bundle")).toBe("snapshot");
    expect(intendedMode("workflow_dispatch", "sample-repeat-1")).toBe("snapshot");
    expect(intendedMode("pull_request", "")).toBe("snapshot");
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
    expect(workflow).toContain("benchmark-prior-scorecard-policy-${{ matrix.shard }}.json");
    expect(workflow).toContain("benchmark-transport-${{ matrix.shard }}.json");
    expect(workflow).toContain("benchmark-runner-${{ matrix.shard }}.json");
    expect(workflow).toContain("shardProfiles: map(.shardProfile)");
    expect(workflow).toContain("corpus-benchmark-sample.json");
    expect(workflow).toContain("--run-attempt '${{ github.run_attempt }}'");
    expect(workflow).toContain("--benchmark-seed '${{ inputs.benchmark_seed }}'");
    expect(workflow).toContain("--benchmark-seed-run-id '${{ inputs.benchmark_seed_run_id }}'");
    expect(workflow).toContain("--requested-runner '${{ needs.prepare-current-inputs.outputs.runner }}'");
  });

  it("makes prior-scorecard acquisition and forwarding unreachable for every benchmark identity", () => {
    const fetch = shardStep("Fetch the latest prior scorecard for ordinary drift attribution (#1564)");
    const policy = shardStep("Record disabled benchmark prior-scorecard policy");
    const score = shardStep("Score the corpus against its baselines");
    expect(fetch.if).toBe("steps.filter.outputs.relevant == 'true' && inputs.benchmark_run_identity == ''");
    expect(policy.if).toBe("steps.filter.outputs.relevant == 'true' && inputs.benchmark_run_identity != ''");
    expect(policy.run).toContain('{schema:1,mode:"disabled-for-benchmark",reason:"prior-scorecard-is-diagnostic-only"}');
    expect(score.run).toContain("if [ -z '${{ inputs.benchmark_run_identity }}' ] && [ -f prior-drift/corpus-drift.json ]; then");
    expect(score.run).toContain("baseline_flag=(--baseline-findings prior-drift/corpus-drift.json)");

    const ghPriorSteps = shardSteps.filter((step) => /gh run (?:list|download)/.test(step.run ?? ""));
    expect(ghPriorSteps).toEqual([fetch]);
    expect(fetch.run).toContain("gh run list");
    expect(fetch.run).toContain("gh run download");
    expect(fetch.run).not.toContain("benchmark_seed_run_id");

    const route = (identity: string) => ({ fetch: identity === "", forward: identity === "", recordPolicy: identity !== "" });
    expect(route("")).toEqual({ fetch: true, forward: true, recordPolicy: false });
    for (const identity of ["seed-bundle", "sample-repeat-1", "all-settled-drill"]) {
      expect(route(identity), identity).toEqual({ fetch: false, forward: false, recordPolicy: true });
    }
    // Regression fixture: run 31743179519 was a benchmark seed routed through the old source-run
    // lookup; exercise that exact identity against the policy-only benchmark branch.
    const failedSeed = { runId: 31_743_179_519, identity: "seed-bundle" };
    expect({ runId: failedSeed.runId, ...route(failedSeed.identity) }).toEqual({ runId: 31_743_179_519, fetch: false, forward: false, recordPolicy: true });
  });

  it("restores only an immutable seed-bundle run and cannot contaminate it with sample outputs", () => {
    const phaseCache = shardStep("Restore content-addressed corpus phase results");
    expect(phaseCache.if).toBe("steps.filter.outputs.relevant == 'true' && inputs.benchmark_run_identity == ''");
    expect(workflow).toContain("benchmark_seed_run_id:");
    expect(workflow).toContain("benchmark_seed_run_id must name the immutable seed-bundle workflow run");
    expect(workflow).toContain("key: corpus-phase-benchmark-v7-${{ runner.os }}-seed${{ needs.prepare-current-inputs.outputs.benchmark-seed-digest }}-shard1-${{ inputs.benchmark_seed_run_id }}-${{ inputs.benchmark_seed_run_attempt }}-${{ github.sha }}");
    expect(workflow).toContain("key: corpus-phase-benchmark-v7-${{ runner.os }}-seed${{ needs.prepare-current-inputs.outputs.benchmark-seed-digest }}-shard${{ matrix.shard }}-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.sha }}");
    expect(workflow).not.toContain("Save sample output without polluting the immutable seed namespace");
    expect(workflow).not.toContain("corpus-phase-benchmark-sample-v7-");
    expect(workflow).not.toMatch(/Restore exact benchmark seed shard 1[\s\S]{0,450}restore-keys:/);
  });

  it("keeps the production alert on every ordinary freshness failure and isolates benchmark/drill failures", () => {
    const alertCondition = "failure() && !inputs.liveness_drill && inputs.benchmark_run_identity == '' && (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')";
    expect(workflow).toContain(alertCondition);
    expect(workflow).not.toContain("!inputs.liveness_drill && inputs.fail_after_start == ''");
    expect(workflow).toContain('benchmark_flags+=(--fail-after-start "${{ inputs.fail_after_start }}")');
    expect(workflow.match(/--fail-after-start/g)).toHaveLength(1);
    expect(workflow).toMatch(/if \[ -n "\$\{\{ inputs\.benchmark_run_identity \}\}" \]; then[\s\S]{0,900}if \[ -n "\$\{\{ inputs\.fail_after_start \}\}" \]; then[\s\S]{0,150}benchmark_flags\+=\(--fail-after-start/);
    expect(workflow).toContain("uses: ./.github/actions/alert-issue");

    const events = ["schedule", "workflow_dispatch", "pull_request", "merge_group", "push"] as const;
    const identities = ["", "benchmark-sample"] as const;
    const failTargets = ["", "proposit"] as const;
    const livenessDrills = [false, true] as const;
    const failures = [false, true] as const;
    const alertDrills = [false, true] as const;
    const rows: Array<{
      event: typeof events[number];
      identity: typeof identities[number];
      failTarget: typeof failTargets[number];
      livenessDrill: boolean;
      failure: boolean;
      alertDrill: boolean;
      forwarded: boolean;
      alertAction: boolean;
      productionAlert: boolean;
      drillAlert: boolean;
    }> = [];
    for (const event of events) for (const identity of identities) for (const failTarget of failTargets) for (const livenessDrill of livenessDrills) for (const failure of failures) for (const alertDrill of alertDrills) {
      const alertAction = failure && !livenessDrill && identity === "" && (event === "schedule" || event === "workflow_dispatch");
      rows.push({
        event,
        identity,
        failTarget,
        livenessDrill,
        failure,
        alertDrill,
        forwarded: identity !== "" && failTarget !== "",
        alertAction,
        productionAlert: alertAction && !alertDrill,
        drillAlert: alertAction && alertDrill,
      });
    }

    expect(rows).toHaveLength(160);
    expect(rows.filter((row) => row.forwarded)).toHaveLength(40);
    expect(rows.filter((row) => row.alertAction)).toHaveLength(8);
    expect(rows.filter((row) => row.productionAlert)).toHaveLength(4);
    expect(rows.filter((row) => row.drillAlert)).toHaveLength(4);
    expect(rows.find((row) => row.event === "workflow_dispatch" && row.identity === "" && row.failTarget === "proposit" && !row.livenessDrill && row.failure && !row.alertDrill)).toMatchObject({ forwarded: false, alertAction: true, productionAlert: true, drillAlert: false });
    expect(rows.find((row) => row.event === "workflow_dispatch" && row.identity === "benchmark-sample" && row.failTarget === "proposit" && !row.livenessDrill && row.failure && !row.alertDrill)).toMatchObject({ forwarded: true, alertAction: false, productionAlert: false, drillAlert: false });
    expect(rows.find((row) => row.event === "schedule" && row.identity === "" && row.failTarget === "" && !row.livenessDrill && !row.failure && !row.alertDrill)).toMatchObject({ alertAction: false, productionAlert: false, drillAlert: false });
    expect(rows.find((row) => row.event === "schedule" && row.identity === "" && row.failTarget === "" && row.livenessDrill && row.failure && !row.alertDrill)).toMatchObject({ alertAction: false, productionAlert: false, drillAlert: false });
    expect(rows.find((row) => row.event === "workflow_dispatch" && row.identity === "" && row.failTarget === "" && !row.livenessDrill && row.failure && row.alertDrill)).toMatchObject({ alertAction: true, productionAlert: false, drillAlert: true });

    // The old condition's only extra input was failTarget. These rows are the falsifier: an
    // ordinary failure value stays local to the dispatch, yet the old condition suppressed its alert.
    const legacyAlertAction = (row: (typeof rows)[number]): boolean => row.alertAction && row.failTarget === "";
    expect(rows.filter((row) => row.alertAction && !legacyAlertAction(row))).toHaveLength(4);
    expect(rows.filter((row) => row.productionAlert && !legacyAlertAction(row))).toEqual(expect.arrayContaining([
      expect.objectContaining({ event: "schedule", identity: "", failTarget: "proposit", failure: true, alertDrill: false, forwarded: false, productionAlert: true }),
      expect.objectContaining({ event: "workflow_dispatch", identity: "", failTarget: "proposit", failure: true, alertDrill: false, forwarded: false, productionAlert: true }),
    ]));
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
