import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildCorpusBenchmarkSample, type CorpusBenchmarkApiJob, type CorpusBenchmarkScorecard } from "./corpus-benchmark-sample.js";
import type { CorpusBenchmarkArtifactEvidence, CorpusBenchmarkTransportEvidence } from "./corpus-benchmark.js";
import { corpusCacheTransportKey } from "./corpus-cache-transport.js";
import { corpusTargetConservationVector, type CorpusExecutionManifest } from "./corpus-execution.js";
import { corpusShardTargetDigest, type CorpusShardProfileSelection } from "./scan/corpus-shards.js";

const commits = { alpha: "a".repeat(40), beta: "b".repeat(40) };
const hash = (value: string): string => createHash("sha256").update(value).digest("hex");

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

function profileSelection(): CorpusShardProfileSelection {
  return { requested: "cold", selected: "cold", cacheProvenance: "uncertain", targetDigest: corpusShardTargetDigest(Object.keys(commits)), sourceDigest: "f".repeat(64), runId: 31549148174, runAttempt: 1, reason: "cold requested explicitly" };
}

function scorecard(): CorpusBenchmarkScorecard {
  const rows = Object.keys(commits).map((slug) => ({ slug, check: "M4 baseline", module: "M4", pass: true }));
  const findings = Object.fromEntries(Object.keys(commits).map((slug) => [slug, [{ severity: "Low", confidence: "High" }]]));
  const detectors = Object.fromEntries(Object.keys(commits).map((slug) => [slug, [{ detector: "fixture", unitsExamined: 2, examinedUnitIdentities: [`${slug}/route.ts`] }]]));
  const scannerRecords = Object.fromEntries(Object.keys(commits).map((slug) => [slug, [{ scanner: "detect-static", cache: "recomputed", reason: "forced-cold result matched cached artifact", key: hash(`${slug}:scanner`), scope: { unitsExamined: 3, description: `${slug} source` } }]]));
  const card: CorpusBenchmarkScorecard = {
    rows,
    findings,
    detectors,
    mechanicalContexts: { alpha: {}, beta: {} },
    mechanicalRuns: Object.fromEntries(Object.keys(commits).map((slug) => [slug, {
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
    dependencyPreparations: Object.fromEntries(Object.keys(commits).map((slug) => [slug, [{
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
    phaseSeconds: { alpha: { install: 1, "detect-static": 2 }, beta: { install: 1, "quality-scan": 2 } },
    runtimeReceipts: { alpha: { node: "v24", pnpm: "10" }, beta: { node: "v24", pnpm: "10" } },
    conservation: [],
    executions: [execution(1), execution(2), execution(3)],
    shardProfiles: [profileSelection(), profileSelection(), profileSelection()],
  };
  refreshConservation(card);
  return card;
}

function refreshConservation(card: CorpusBenchmarkScorecard): void {
  card.conservation = Object.keys(commits).map((slug) => corpusTargetConservationVector(card, slug));
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

function build(card = scorecard(), apiJobs = jobs()) {
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
  const artifacts: CorpusBenchmarkArtifactEvidence[] = [
    { name: "actions/jobs.json", family: "actions/jobs", sha256: hash("jobs") },
    { name: "scorecard/corpus-drift.json", family: "scorecard/corpus-drift", sha256: hash("scorecard") },
  ];
  return buildCorpusBenchmarkSample({
    scorecard: card,
    jobs: apiJobs,
    runId: 123,
    runAttempt: 1,
    headSha,
    benchmarkSeed,
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
      shape: { outputNamespaces: ["1", "2", "3"], artifactFamilies: [{ family: "actions/jobs", count: 1 }, { family: "scorecard/corpus-drift", count: 1 }] },
      transports: { sources, outputs },
      sourceFiles,
      receiptDigests: [],
    },
  });
}

describe("corpus benchmark sample evidence envelope", () => {
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
    expect(sample.population.rowDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(sample.assertions).toEqual({ baselines: true, liveness: true, forcedCold: true, conservation: true });
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
