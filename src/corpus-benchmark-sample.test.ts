import { describe, expect, it } from "vitest";
import { buildCorpusBenchmarkSample, type CorpusBenchmarkApiJob, type CorpusBenchmarkScorecard } from "./corpus-benchmark-sample.js";
import type { CorpusExecutionManifest } from "./corpus-execution.js";
import { corpusShardTargetDigest, type CorpusShardProfileSelection } from "./scan/corpus-shards.js";

const commits = { alpha: "a".repeat(40), beta: "b".repeat(40) };

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
  const detectors = Object.fromEntries(Object.keys(commits).map((slug) => [slug, [{ unitsExamined: 2 }]]));
  const scannerRecords = Object.fromEntries(Object.keys(commits).map((slug) => [slug, [{ cache: "recomputed", scope: { unitsExamined: 3 } }]]));
  return {
    rows,
    findings,
    detectors,
    mechanicalContexts: { alpha: {}, beta: {} },
    mechanicalRuns: { alpha: { phases: [{ cache: "recomputed" }] }, beta: { phases: [{ cache: "recomputed" }] } },
    scannerRecords,
    dependencyPreparations: { alpha: [], beta: [] },
    phaseSeconds: { alpha: { install: 1, "detect-static": 2 }, beta: { install: 1, "quality-scan": 2 } },
    runtimeReceipts: { alpha: { node: "v24", pnpm: "10" }, beta: { node: "v24", pnpm: "10" } },
    conservation: Object.keys(commits).map((slug) => ({ slug, modules: ["M4"], checks: 1, findings: 1, disclosures: 0, baselines: 1, examinedUnits: 5, digest: slug })),
    executions: [execution(1), execution(2), execution(3)],
    shardProfiles: [profileSelection(), profileSelection(), profileSelection()],
  };
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
  return buildCorpusBenchmarkSample({
    scorecard: card,
    jobs: apiJobs,
    runId: 123,
    runAttempt: 1,
    headSha: "c".repeat(40),
    benchmarkSeed: "seed",
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
    transportKeys: ["key"],
    provenanceDigests: ["d".repeat(64)],
    artifactDigests: ["e".repeat(64)],
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
    expect(() => build(stale)).toThrow(/stored conservation facts differ/);
    const overclaimed = scorecard();
    overclaimed.conservation[0]!.findings = 2;
    expect(() => build(overclaimed)).toThrow(/stored conservation facts differ/);
  });
});
