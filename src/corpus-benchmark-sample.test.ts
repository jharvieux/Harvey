import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { buildCorpusBenchmarkSample, type CorpusBenchmarkApiJob, type CorpusBenchmarkScorecard } from "./corpus-benchmark-sample.js";
import type { CorpusBenchmarkArtifactEvidence, CorpusBenchmarkPriorScorecardPolicy, CorpusBenchmarkTransportEvidence } from "./corpus-benchmark.js";
import { corpusCacheTransportKey } from "./corpus-cache-transport.js";
import { corpusTargetConservationVector, type CorpusExecutionManifest } from "./corpus-execution.js";
import { EXTERNAL_CORPUS } from "./scan/external-corpus.js";
import { corpusShardTargetDigest, type CorpusShardProfileSelection } from "./scan/corpus-shards.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectories: string[] = [];
const commits = { alpha: "a".repeat(40), beta: "b".repeat(40) };
const hash = (value: string): string => createHash("sha256").update(value).digest("hex");
const DISABLED_PRIOR_SCORECARD_POLICY = {
  schema: 1,
  mode: "disabled-for-benchmark",
  reason: "prior-scorecard-is-diagnostic-only",
} as const satisfies CorpusBenchmarkPriorScorecardPolicy;

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function execution(index: number): CorpusExecutionManifest {
  return {
    schema: 1,
    design: "target-workers",
    profile: "cold",
    shard: { index, count: 3 },
    admission: { requested: 2, effective: 2, targetWorkers: 2, scannerLanes: 1, cpuLimit: 4, cpuSource: "cgroup", memoryLimitBytes: 16_000, memorySource: "cgroup", memoryPerWorkerBytes: 1_000, reasons: [] },
    startedAt: "2026-08-12T00:00:00Z",
    finishedAt: "2026-08-12T00:01:00Z",
    terminals: [{ ordinal: 0, slug: index === 1 ? "alpha" : "beta", state: "succeeded", startedAt: "2026-08-12T00:00:00Z", finishedAt: "2026-08-12T00:01:00Z", exitCode: 0, signal: null, outputDir: "/tmp/out", resultPath: "/tmp/result", stdoutPath: "/tmp/stdout", stderrPath: "/tmp/stderr", resourcePath: "/tmp/resource", peakRssBytes: 4_000, cpuSeconds: 5, oomDetected: false, retryDetected: false }],
    aggregate: { criticalPathMs: 60_000, summedWorkerMs: 60_000, peakRssBytes: 4_000, cpuSeconds: 5, oomCount: 0, retryCount: 0 },
  };
}

function profileSelection(targetCommits: Record<string, string> = commits): CorpusShardProfileSelection {
  return { requested: "cold", selected: "cold", cacheProvenance: "uncertain", targetDigest: corpusShardTargetDigest(Object.keys(targetCommits)), sourceDigest: "f".repeat(64), runId: 31549148174, runAttempt: 1, reason: "cold requested explicitly" };
}

function scorecard(targetCommits: Record<string, string> = commits): CorpusBenchmarkScorecard {
  const slugs = Object.keys(targetCommits);
  const rows = slugs.map((slug) => ({ slug, check: "M4 baseline", module: "M4", pass: true }));
  const findings = Object.fromEntries(slugs.map((slug) => [slug, [{ severity: "Low", confidence: "High" }]]));
  const detectors = Object.fromEntries(slugs.map((slug) => [slug, [{ detector: "fixture", unitsExamined: 2, examinedUnitIdentities: [`${slug}/route.ts`] }]]));
  const scannerRecords = Object.fromEntries(slugs.map((slug) => [slug, [{ scanner: "detect-static", cache: "recomputed", reason: "forced-cold result matched cached artifact", key: hash(`${slug}:scanner`), scope: { unitsExamined: 3, description: `${slug} source` } }]]));
  const card: CorpusBenchmarkScorecard = {
    rows,
    findings,
    detectors,
    mechanicalContexts: Object.fromEntries(slugs.map((slug) => [slug, {}])),
    mechanicalRuns: Object.fromEntries(slugs.map((slug) => [slug, {
      executionPlan: { families: ["auth", "tenant"] },
      semgrepDiagnostics: { errors: [], skipped: [], sha256: hash("empty diagnostics") },
      phases: [{
        phase: "semgrep",
        cache: "recomputed",
        reason: "forced-cold result matched cached artifact",
        durationMs: 100,
        scope: { unitsExamined: 2, description: `${slug} Semgrep files` },
        evidence: { semgrepDiagnostics: { errors: [], skipped: [], sha256: hash("empty diagnostics") } },
      }],
    }])),
    scannerRecords,
    dependencyPreparations: Object.fromEntries(slugs.map((slug) => [slug, [{
      status: "hit",
      complete: true,
      cacheable: true,
      key: hash(`${slug}:dependencies`),
      packageManager: "pnpm",
      packageManagerVersion: "10",
      lockfileDigest: hash(`${slug}:lockfile`),
      reason: "validated receipt and offline materialization",
      sourceTreeCacheable: true,
    }]])),
    phaseSeconds: Object.fromEntries(slugs.map((slug) => [slug, { install: 1, "detect-static": 2 }])),
    runtimeReceipts: Object.fromEntries(slugs.map((slug) => [slug, { node: "v24", pnpm: "10" }])),
    conservation: [],
    executions: [execution(1), execution(2), execution(3)],
    shardProfiles: [profileSelection(targetCommits), profileSelection(targetCommits), profileSelection(targetCommits)],
  };
  refreshConservation(card, targetCommits);
  return card;
}

function refreshConservation(card: CorpusBenchmarkScorecard, targetCommits: Record<string, string> = commits): void {
  card.conservation = Object.keys(targetCommits).map((slug) => corpusTargetConservationVector(card, slug));
}

function jobs(): CorpusBenchmarkApiJob[] {
  return [1, 2, 3].map((index) => ({
    id: index,
    name: `corpus shard ${index}`,
    status: "completed",
    conclusion: "success",
    started_at: `2026-08-12T00:00:0${index}Z`,
    completed_at: `2026-08-12T00:01:0${index}Z`,
    runner_name: `GitHub Actions ${index}`,
    runner_group_name: "GitHub Actions",
    labels: ["ubuntu-latest"],
    steps: [
      { name: "Score the corpus against its baselines", conclusion: "success", started_at: `2026-08-12T00:00:1${index}Z`, completed_at: `2026-08-12T00:00:5${index}Z` },
      { name: "Gate liveness — did this job actually score anything?", conclusion: "success", started_at: `2026-08-12T00:00:5${index}Z`, completed_at: `2026-08-12T00:00:5${index}Z` },
    ],
  }));
}

function build(
  card = scorecard(),
  apiJobs = jobs(),
  suppliedPolicies?: CorpusBenchmarkPriorScorecardPolicy[],
  policyArtifactHashes = [hash("prior-policy"), hash("prior-policy"), hash("prior-policy")],
  extraArtifacts: CorpusBenchmarkArtifactEvidence[] = [],
) {
  const headSha = "c".repeat(40);
  const benchmarkSeed = "seed";
  const seedDigest = hash(benchmarkSeed).slice(0, 16);
  const ref = "refs/heads/benchmark";
  const platform = "linux-x64";
  const transport = (role: "source" | "output", namespace: string, transportRunId: string): CorpusBenchmarkTransportEvidence => {
    const key = corpusCacheTransportKey({ family: "benchmark", platform, namespace, runId: transportRunId, runAttempt: "1", headSha, benchmarkSeed });
    return { role, key, family: "benchmark", event: "workflow_dispatch", ref, platform, namespace, runId: transportRunId, runAttempt: "1", headSha, benchmarkSeed, seedDigest, payloadBytes: 100 };
  };
  const sources = [transport("source", "1", "99")];
  const outputs = ["1", "2", "3"].map((namespace) => transport("output", namespace, "123"));
  const sourceFiles = [{ path: `${hash("cache")}.json`, sha256: hash("cache-body"), bytes: 10, sourceNamespaces: ["1"] }];
  const priorScorecardPolicy = structuredClone(DISABLED_PRIOR_SCORECARD_POLICY);
  const artifacts: CorpusBenchmarkArtifactEvidence[] = [
    { name: "actions/jobs.json", family: "actions/jobs", sha256: hash("jobs") },
    ...[1, 2, 3].map((index) => ({ name: `evidence/benchmark-prior-scorecard-policy-${index}.json`, family: "evidence/benchmark-prior-scorecard-policy", sha256: policyArtifactHashes[index - 1]! })),
    ...extraArtifacts,
    { name: "scorecard/corpus-drift.json", family: "scorecard/corpus-drift", sha256: hash("scorecard") },
  ].sort((left, right) => left.name.localeCompare(right.name));
  return buildCorpusBenchmarkSample({
    scorecard: card,
    jobs: apiJobs,
    runId: 123,
    runAttempt: 1,
    headSha,
    benchmarkSeed,
    benchmarkSeedRunId: 99,
    benchmarkSeedRunAttempt: 1,
    repeat: 1,
    runnerRole: "pr",
    requestedRunner: "ubuntu-latest",
    runnerImage: "ubuntu24@20260812/Linux/X64",
    profile: "cold",
    design: "target-workers",
    concurrency: 2,
    shardCount: 3,
    workflowUrl: "https://example.test/run/123",
    targetCommits: commits,
    transportKeys: [...sources, ...outputs].map((row) => row.key),
    provenanceDigests: ["d".repeat(64)],
    artifactDigests: artifacts.map((artifact) => artifact.sha256),
    artifacts,
    priorScorecardPolicies: suppliedPolicies ?? [structuredClone(priorScorecardPolicy), structuredClone(priorScorecardPolicy), structuredClone(priorScorecardPolicy)],
    cacheProvenance: {
      schema: 1,
      invariant: {
        benchmarkSeed,
        headSha,
        ref,
        platform,
        sourceNamespaces: ["1"],
        sourceContentDigest: hash(JSON.stringify(sourceFiles)),
        sourceTransports: sources.map((row) => ({ family: row.family, event: row.event, ref: row.ref, platform: row.platform, namespace: row.namespace, headSha: row.headSha, benchmarkSeed: row.benchmarkSeed, seedDigest: row.seedDigest, payloadBytes: row.payloadBytes })),
      },
      shape: { outputNamespaces: ["1", "2", "3"], artifactFamilies: [{ family: "actions/jobs", count: 1 }, { family: "evidence/benchmark-prior-scorecard-policy", count: 3 }, { family: "scorecard/corpus-drift", count: 1 }] },
      transports: { sources, outputs },
      sourceFiles,
      receiptDigests: [],
    },
  });
}

function runBenchmarkSampleCli(legacyFilename?: string) {
  const directory = mkdtempSync(join(tmpdir(), "harvey-benchmark-prior-policy-"));
  temporaryDirectories.push(directory);
  const evidenceDir = join(directory, "evidence");
  mkdirSync(evidenceDir);
  const headSha = "c".repeat(40);
  const benchmarkSeed = "seed";
  const targetCommits = Object.fromEntries(EXTERNAL_CORPUS.map((target) => [target.slug, target.commit]));
  const sourceFiles = [{ path: `${hash("cache")}.json`, sha256: hash("cache-body"), bytes: 10, sourceNamespaces: ["1", "2", "3"] }];
  const sourceTransports = ["1", "2", "3"].map((namespace) => ({
    namespace,
    key: corpusCacheTransportKey({ family: "benchmark", platform: "linux-x64", namespace, runId: "99", runAttempt: "1", headSha, benchmarkSeed }),
    family: "benchmark" as const,
    event: "workflow_dispatch",
    ref: "refs/heads/benchmark",
    platform: "linux-x64",
    runId: "99",
    runAttempt: "1",
    headSha,
    benchmarkSeed,
    payloadBytes: 10,
  }));
  const writeJson = (path: string, value: unknown): void => writeFileSync(path, `${JSON.stringify(value)}\n`);
  const aggregateSha256 = hash(JSON.stringify(sourceFiles));
  for (const shard of [1, 2, 3]) {
    writeJson(join(evidenceDir, `benchmark-cache-merge-receipt-${shard}.json`), {
      schema: 1,
      destination: `.harvey-corpus-phase-cache-${shard}`,
      benchmarkSeed,
      headSha,
      requiredNamespaces: ["1", "2", "3"],
      sources: sourceTransports,
      files: sourceFiles,
      aggregateSha256,
      duplicatePaths: 0,
      conflicts: 0,
    });
    writeJson(join(evidenceDir, `benchmark-prior-scorecard-policy-${shard}.json`), DISABLED_PRIOR_SCORECARD_POLICY);
    const key = corpusCacheTransportKey({ family: "benchmark", platform: "linux-x64", namespace: String(shard), runId: "123", runAttempt: "1", headSha, benchmarkSeed });
    writeJson(join(evidenceDir, `benchmark-transport-${shard}.json`), {
      schema: 4,
      key,
      family: "benchmark",
      event: "workflow_dispatch",
      ref: "refs/heads/benchmark",
      runId: "123",
      runAttempt: "1",
      headSha,
      writtenAt: "2026-08-13T00:00:00Z",
      payload: { bytes: 10, maxBytes: 1_000, symlinks: 0 },
      benchmarkSeed,
    });
    writeJson(join(evidenceDir, `benchmark-runner-${shard}.json`), {
      schema: 1,
      shard,
      imageOS: "ubuntu24",
      imageVersion: "20260813",
      runnerOS: "Linux",
      runnerArch: "X64",
    });
  }
  if (legacyFilename) writeJson(join(evidenceDir, legacyFilename), { schema: 1, sourceRunId: 99 });
  const scorecardPath = join(directory, "corpus-drift.json");
  const jobsPath = join(directory, "jobs.json");
  writeJson(scorecardPath, scorecard(targetCommits));
  writeJson(jobsPath, jobs());
  return spawnSync("node_modules/.bin/tsx", [
    "src/cli/corpus-benchmark-sample.ts",
    "--scorecard", scorecardPath,
    "--jobs", jobsPath,
    "--evidence-dir", evidenceDir,
    "--out", join(directory, "sample.json"),
    "--run-id", "123",
    "--run-attempt", "1",
    "--repeat", "1",
    "--concurrency", "2",
    "--shard-count", "3",
    "--head-sha", headSha,
    "--benchmark-seed", benchmarkSeed,
    "--benchmark-seed-run-id", "99",
    "--benchmark-seed-run-attempt", "1",
    "--runner-role", "pr",
    "--profile", "cold",
    "--design", "target-workers",
    "--requested-runner", "ubuntu-latest",
    "--workflow-url", "https://example.test/run/123",
  ], { cwd: REPO_ROOT, encoding: "utf8" });
}

describe("corpus benchmark sample evidence envelope", () => {
  it("rejects legacy prior-scorecard files in the CLI census before sample construction", () => {
    const currentPolicyOnly = runBenchmarkSampleCli();
    expect(currentPolicyOnly.status, currentPolicyOnly.stderr).toBe(0);

    for (const filename of ["benchmark-prior-scorecard-1.json", "benchmark-prior-scorecard-renamed-17.json"]) {
      const legacy = runBenchmarkSampleCli(filename);
      expect(legacy.status, filename).toBe(1);
      expect(legacy.stderr, filename).toContain(`legacy prior-scorecard evidence is forbidden before benchmark sample construction: ${filename}`);
      expect(legacy.stderr, filename).not.toContain("population has");
    }
  });

  it("retains separate critical/summed timing, actual runner, resources, tools, cache, and population evidence", () => {
    const sample = build();
    expect(sample).toMatchObject({ criticalPathMs: 62_000, aggregateRunnerMs: 180_000, aggregateCpuSeconds: 15, peakRssBytes: 4_000, setupNetworkMs: 30_000, dependencyMs: 2_000, targetProcessCpuMs: 15_000 });
    expect(sample.actualRunner.jobs).toEqual([
      { id: 1, name: "GitHub Actions 1" },
      { id: 2, name: "GitHub Actions 2" },
      { id: 3, name: "GitHub Actions 3" },
    ]);
    expect(sample.actualRunner.nameClass).toBe("GitHub Actions <hosted-id>");
    expect(sample.raw).toMatchObject({ jobIds: [1, 2, 3], targetCommits: commits, toolVersions: { node: "v24", pnpm: "10" } });
    expect(sample.raw.priorScorecardPolicy).toEqual(DISABLED_PRIOR_SCORECARD_POLICY);
    expect(sample.population.rowDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(sample.assertions).toEqual({ baselines: true, liveness: true, forcedCold: true, conservation: true });
  });

  it("requires the exact disabled prior-scorecard policy across every benchmark shard", () => {
    expect(() => build()).not.toThrow();
    const base = structuredClone(DISABLED_PRIOR_SCORECARD_POLICY);
    const live = { ...base, mode: "bound-live-scorecard" } as unknown as CorpusBenchmarkPriorScorecardPolicy;
    expect(() => build(scorecard(), jobs(), [base, structuredClone(base), live])).toThrow(/mixed prior-scorecard policies/);
    expect(() => build(scorecard(), jobs(), [live, structuredClone(live), structuredClone(live)])).toThrow(/exact disabled-for-benchmark policy/);
    expect(() => build(scorecard(), jobs(), [])).toThrow(/population has 0 rows/);
    const extra = { ...base, sourceRunId: 99 } as CorpusBenchmarkPriorScorecardPolicy;
    expect(() => build(scorecard(), jobs(), [extra, structuredClone(extra), structuredClone(extra)])).toThrow(/exact disabled-for-benchmark policy/);
    expect(() => build(scorecard(), jobs(), undefined, [hash("prior-policy"), hash("changed-policy"), hash("prior-policy")])).toThrow(/do not contain identical bytes/);

    for (const legacyArtifact of [
      { name: "evidence/benchmark-prior-scorecard-1.json", family: "evidence/benchmark-prior-scorecard", sha256: hash("legacy-numbered") },
      { name: "evidence/benchmark-prior-scorecard-renamed-17.json", family: "evidence/benchmark-prior-scorecard-renamed", sha256: hash("legacy-renamed") },
      { name: "evidence/renamed.json", family: "evidence/benchmark-prior-scorecard", sha256: hash("legacy-family") },
    ]) {
      expect(
        () => build(scorecard(), jobs(), undefined, [hash("prior-policy"), hash("prior-policy"), hash("prior-policy")], [legacyArtifact]),
        legacyArtifact.name,
      ).toThrow(/legacy prior-scorecard evidence is forbidden/);
    }
  });

  it("allows distinct machine names but fails loud on mixed runner shapes and stale conservation in both directions", () => {
    const mixed = jobs();
    mixed[2]!.labels = ["larger-linux"];
    expect(() => build(scorecard(), mixed)).toThrow(/mixed runner group\/label shapes/);

    const mixedResources = scorecard();
    mixedResources.executions[2]!.admission.cpuLimit = 8;
    expect(() => build(mixedResources)).toThrow(/mixed CPU or memory limits/);

    const stale = scorecard();
    stale.findings.alpha!.push({ severity: "High" });
    expect(() => build(stale)).toThrow(/stored full conservation envelope differs/);
    const overclaimed = scorecard();
    overclaimed.conservation[0]!.findings = 2;
    expect(() => build(overclaimed)).toThrow(/stored full conservation envelope differs/);
  });

  it("rejects stale dependency, scanner, runtime, Semgrep-plan/diagnostic, phase, scope, and cache evidence", () => {
    const mutations: Array<(card: CorpusBenchmarkScorecard) => void> = [
      (card) => { (card.dependencyPreparations.alpha![0] as { reason: string }).reason = "changed dependency reason"; },
      (card) => { (card.scannerRecords.alpha![0] as { reason: string }).reason = "changed scanner reason"; },
      (card) => { card.runtimeReceipts.alpha!.node = "v25"; },
      (card) => { (card.mechanicalRuns.alpha as { executionPlan: { families: string[] } }).executionPlan.families.push("changed"); },
      (card) => { (card.mechanicalRuns.alpha as { semgrepDiagnostics: { errors: unknown[] } }).semgrepDiagnostics.errors.push("changed"); },
      (card) => { ((card.mechanicalRuns.alpha as { phases: Array<{ evidence: { semgrepDiagnostics: { skipped: unknown[] } } }> }).phases[0]!.evidence.semgrepDiagnostics.skipped).push("changed"); },
      (card) => { (card.scannerRecords.alpha![0] as { scope: { unitsExamined: number } }).scope.unitsExamined = 99; },
      (card) => { (card.scannerRecords.alpha![0] as { cache: string }).cache = "hit"; },
    ];
    for (const mutate of mutations) {
      const card = scorecard();
      mutate(card);
      expect(() => build(card)).toThrow(/stored full conservation envelope differs/);
    }
  });

  it("normalizes only recognized hit/recompute wording and retains arbitrary dependency, scanner, and phase reasons", () => {
    const cold = build();
    const hit = scorecard();
    for (const slug of Object.keys(commits)) {
      Object.assign((hit.mechanicalRuns[slug] as { phases: Array<Record<string, unknown>> }).phases[0]!, {
        cache: "hit",
        reason: "resolved registry packs, local rules, implementation, target tree, and Semgrep version are keyed",
      });
      Object.assign(hit.scannerRecords[slug]![0]!, { cache: "hit", reason: "complete content-addressed artifact" });
      Object.assign(hit.dependencyPreparations[slug]![0] as Record<string, unknown>, { status: "miss", reason: "clean content-addressed preparation" });
    }
    refreshConservation(hit);
    const normalized = build(hit);
    expect(normalized.population).toMatchObject({
      evidenceDigest: cold.population.evidenceDigest,
      dependencyInputDigest: cold.population.dependencyInputDigest,
      cacheInputDigest: cold.population.cacheInputDigest,
      toolInputDigest: cold.population.toolInputDigest,
    });
    expect(normalized.population.conservationDigest).not.toBe(cold.population.conservationDigest);

    const mutations: Array<(card: CorpusBenchmarkScorecard) => void> = [
      (card) => { (card.dependencyPreparations.alpha![0] as { reason: string }).reason = "arbitrary dependency reason"; },
      (card) => { (card.scannerRecords.alpha![0] as { reason: string }).reason = "arbitrary scanner reason"; },
      (card) => { ((card.mechanicalRuns.alpha as { phases: Array<{ reason: string }> }).phases[0]!).reason = "arbitrary phase reason"; },
    ];
    for (const mutate of mutations) {
      const changed = scorecard();
      mutate(changed);
      refreshConservation(changed);
      expect(build(changed).population.evidenceDigest).not.toBe(cold.population.evidenceDigest);
    }
  });
});
