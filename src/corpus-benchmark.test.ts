import { describe, expect, it } from "vitest";
import {
  CORPUS_BENCHMARK_THRESHOLDS,
  corpusBenchmarkThresholdDigest,
  evaluateCorpusBenchmark,
  type CorpusBenchmarkSample,
} from "./corpus-benchmark.js";

const digest = (character: string): string => character.repeat(64);

function sample(overrides: Partial<CorpusBenchmarkSample> = {}): CorpusBenchmarkSample {
  const profile = overrides.profile ?? "warm";
  const shardCount = overrides.shardCount ?? 3;
  const runId = overrides.runId ?? 1;
  return {
    schema: 1,
    runId,
    runAttempt: 1,
    workflow: "corpus-drift.yml",
    headSha: "a".repeat(40),
    benchmarkSeed: "matched-seed",
    repeat: overrides.repeat ?? 1,
    runnerRole: overrides.runnerRole ?? "pr",
    requestedRunner: overrides.requestedRunner ?? "ubuntu-latest",
    actualRunner: { jobs: Array.from({ length: shardCount }, (_, index) => ({ id: index + 1, name: `GitHub Actions ${runId * 10 + index}` })), nameClass: "GitHub Actions <hosted-id>", group: "GitHub Actions", labels: ["ubuntu-latest"], image: "ubuntu24", cpuLimit: 4, memoryLimitBytes: 16_000 },
    profile,
    design: overrides.design ?? "serial",
    concurrency: overrides.concurrency ?? 1,
    effectiveConcurrency: overrides.effectiveConcurrency ?? overrides.concurrency ?? 1,
    shardCount,
    criticalPathMs: overrides.criticalPathMs ?? 1_000,
    aggregateRunnerMs: overrides.aggregateRunnerMs ?? 2_000,
    aggregateCpuSeconds: 10,
    peakRssBytes: overrides.peakRssBytes ?? 8_000,
    setupNetworkMs: 100,
    dependencyMs: 300,
    targetProcessCpuMs: 700,
    cache: { hits: profile === "warm" ? 10 : 0, misses: 0, recomputed: profile === "cold" ? 10 : 0, rejected: 0, transportKeys: ["key"], provenanceDigests: [digest("1")], strandedArtifacts: 0 },
    population: { targetDigest: digest("2"), targets: ["alpha", "beta"], rowDigest: digest("0"), findingDigest: digest("3"), disclosureDigest: digest("4"), baselineDigest: digest("5"), examinedDigest: digest("6"), evidenceDigest: digest("7") },
    assertions: { baselines: true, liveness: true, forcedCold: true, conservation: true },
    oomCount: 0,
    retryCount: 0,
    billedMinutes: overrides.billedMinutes ?? 2,
    estimatedCostUsd: overrides.estimatedCostUsd ?? 1,
    raw: { workflowUrl: `https://example.test/run/${runId}`, jobIds: Array.from({ length: shardCount }, (_, index) => index + 1), artifactDigests: [digest("8")], toolVersions: { node: "v24" }, targetCommits: { alpha: "b".repeat(40), beta: "c".repeat(40) } },
    ...overrides,
  };
}

let nextRunId = 100;

function triplet(overrides: Partial<CorpusBenchmarkSample>): CorpusBenchmarkSample[] {
  return [1, 2, 3].map((repeat) => sample({ ...overrides, repeat, runId: nextRunId++ }));
}

function qualifyingMatrix(): CorpusBenchmarkSample[] {
  return [
    ...triplet({ profile: "cold", design: "serial", concurrency: 1, shardCount: 3, criticalPathMs: 1_000, aggregateRunnerMs: 2_000 }),
    ...triplet({ profile: "warm", design: "serial", concurrency: 1, shardCount: 3, criticalPathMs: 1_000, aggregateRunnerMs: 2_000 }),
    ...triplet({ profile: "cold", design: "target-workers", concurrency: 1, shardCount: 3, criticalPathMs: 950, aggregateRunnerMs: 2_000 }),
    ...triplet({ profile: "warm", design: "target-workers", concurrency: 1, shardCount: 3, criticalPathMs: 950, aggregateRunnerMs: 2_000 }),
    ...triplet({ profile: "cold", design: "target-workers", concurrency: 2, shardCount: 3, criticalPathMs: 800, aggregateRunnerMs: 2_100 }),
    ...triplet({ profile: "warm", design: "target-workers", concurrency: 2, shardCount: 3, criticalPathMs: 800, aggregateRunnerMs: 2_100 }),
    ...triplet({ profile: "cold", design: "target-workers", concurrency: 3, shardCount: 3, criticalPathMs: 780, aggregateRunnerMs: 2_100 }),
    ...triplet({ profile: "warm", design: "target-workers", concurrency: 3, shardCount: 3, criticalPathMs: 780, aggregateRunnerMs: 2_100 }),
    ...triplet({ profile: "cold", design: "intra-target-overlap", concurrency: 2, shardCount: 3, criticalPathMs: 790, aggregateRunnerMs: 2_050 }),
    ...triplet({ profile: "warm", design: "intra-target-overlap", concurrency: 2, shardCount: 3, criticalPathMs: 790, aggregateRunnerMs: 2_050 }),
    ...triplet({ profile: "cold", design: "target-workers", concurrency: 2, shardCount: 4, criticalPathMs: 820, aggregateRunnerMs: 2_500 }),
    ...triplet({ profile: "warm", design: "target-workers", concurrency: 2, shardCount: 4, criticalPathMs: 650, aggregateRunnerMs: 2_500 }),
  ];
}

describe("#1873/#1868/#1875 corpus benchmark evaluator", () => {
  it("predeclares the operator thresholds behind a stable digest", () => {
    expect(CORPUS_BENCHMARK_THRESHOLDS).toMatchObject({
      concurrency: { medianCriticalImprovement: 0.10, coldP95MaxRegression: 0.05, aggregateMaxIncrease: 0.10, peakRssLimitFraction: 0.75 },
      largerPrRunner: { medianCriticalImprovement: 0.20, p95CriticalImprovement: 0.15, costMaxIncrease: 0.25, coldSampleMaxRegression: 0.10 },
      scheduledRunner: { costWithin: 0.05 },
      fourShards: { warmMedianImprovement: 0.15, coldP95MaxRegression: 0.10, aggregateMaxIncrease: 0.25 },
    });
    expect(corpusBenchmarkThresholdDigest()).toMatch(/^[0-9a-f]{64}$/);
  });

  it("selects the smallest qualifying bounded design, retains absent runner labels, and qualifies four shards", () => {
    const decision = evaluateCorpusBenchmark(qualifyingMatrix());
    expect(decision.concurrency.selected).toEqual({ design: "target-workers", concurrency: 2 });
    expect(decision.runners.pr).toMatchObject({ selected: "ubuntu-latest", adoptedLarger: false });
    expect(decision.runners.schedule).toMatchObject({ selected: "ubuntu-latest", adoptedLarger: false });
    expect(decision.shards).toMatchObject({ selected: 4, coldFallback: 3 });
    expect(decision.concurrency.rejected).toContainEqual({
      shape: "split-carbon",
      reasons: [expect.stringContaining("non-admissible negative control")],
    });
    expect(decision.evidence.cohorts).toHaveLength(12);
    expect(decision.evidence.sampleDigest).toMatch(/^[0-9a-f]{64}$/);
    const serialCold = decision.evidence.cohorts.find((row) => row.label.includes("/cold/serial-1/"));
    expect(serialCold).toMatchObject({
      repeats: [1, 2, 3],
      metrics: {
        criticalPathMs: { median: 1_000, p95: 1_000 },
        aggregateRunnerMs: { median: 2_000, p95: 2_000 },
        aggregateCpuSeconds: { median: 10 },
        peakRssBytes: { max: 8_000 },
        billedMinutes: { median: 2 },
        estimatedCostUsd: { median: 1 },
        cache: { recomputed: { total: 30 }, strandedArtifacts: { total: 0 } },
      },
    });
    expect(serialCold?.samples).toHaveLength(3);
    expect(serialCold?.samples.every((row) => row.digest.match(/^[0-9a-f]{64}$/) && row.sample.raw.workflowUrl)).toBe(true);
  });

  it("keeps concurrency and shard selection inside the standard PR runner cohort", () => {
    const matrix = qualifyingMatrix();
    const schedule = matrix.map((row, ordinal) => ({ ...row, runId: 20_000 + ordinal, runnerRole: "schedule" as const, criticalPathMs: 100 }));
    const larger = matrix.filter((row) => row.design === "target-workers" && row.concurrency === 2 && row.shardCount === 3).map((row, ordinal) => ({
      ...row,
      runId: 30_000 + ordinal,
      requestedRunner: "larger-linux",
      actualRunner: { ...row.actualRunner, labels: ["larger-linux"], cpuLimit: 8, memoryLimitBytes: 32_000 },
      criticalPathMs: 5_000,
      aggregateRunnerMs: 10_000,
    }));

    const decision = evaluateCorpusBenchmark([...matrix, ...schedule, ...larger]);
    expect(decision.concurrency.selected).toEqual({ design: "target-workers", concurrency: 2 });
    expect(decision.shards.selected).toBe(4);
  });

  it("adopts a larger PR runner only after all latency/cost/cold thresholds pass", () => {
    const larger = qualifyingMatrix().filter((row) => row.design === "target-workers" && row.shardCount === 3).map((row, ordinal) => sample({
      ...row,
      runId: 8_000 + ordinal,
      requestedRunner: "larger-linux",
      actualRunner: { ...row.actualRunner, labels: ["larger-linux"], cpuLimit: 8, memoryLimitBytes: 32_000 },
      criticalPathMs: 600,
      aggregateRunnerMs: 1_900,
      billedMinutes: 2,
      estimatedCostUsd: 1.20,
    }));
    expect(evaluateCorpusBenchmark([...qualifyingMatrix(), ...larger]).runners.pr).toMatchObject({ selected: "larger-linux", adoptedLarger: true });

    const tooExpensive = larger.map((row) => ({ ...row, estimatedCostUsd: 1.30 }));
    expect(evaluateCorpusBenchmark([...qualifyingMatrix(), ...tooExpensive]).runners.pr).toMatchObject({ selected: "ubuntu-latest", adoptedLarger: false });
  });

  it("retains three shards when warm gain, cold p95, aggregate cost, or artifact transport fails", () => {
    const slowWarm = qualifyingMatrix().map((row) => row.shardCount === 4 && row.profile === "warm" ? { ...row, criticalPathMs: 750 } : row);
    expect(evaluateCorpusBenchmark(slowWarm).shards.selected).toBe(3);

    const stranded = qualifyingMatrix();
    stranded.at(-1)!.cache.strandedArtifacts = 1;
    expect(() => evaluateCorpusBenchmark(stranded)).toThrow(/stranded/);
  });

  it("fails loud on OOM/retry, an incomplete predeclared matrix, and mixed head/population evidence", () => {
    const oom = qualifyingMatrix();
    oom[0]!.oomCount = 1;
    expect(() => evaluateCorpusBenchmark(oom)).toThrow(/OOM\/retry/);

    expect(() => evaluateCorpusBenchmark(qualifyingMatrix().filter((row) => !(row.design === "target-workers" && row.concurrency === 3 && row.profile === "cold")))).toThrow(/target-workers:3 cold: requires at least three distinct real repeats/);

    const mixed = qualifyingMatrix();
    mixed[0]!.headSha = "f".repeat(40);
    expect(() => evaluateCorpusBenchmark(mixed)).toThrow(/mixes head, seed/);
    const population = qualifyingMatrix();
    population[0]!.population.findingDigest = digest("9");
    expect(() => evaluateCorpusBenchmark(population)).toThrow(/target\/evidence/);

    const evidence = qualifyingMatrix();
    evidence[0]!.population.evidenceDigest = digest("e");
    expect(() => evaluateCorpusBenchmark(evidence)).toThrow(/target\/evidence/);

    const missingRaw = qualifyingMatrix();
    missingRaw[0]!.raw.artifactDigests = [];
    expect(() => evaluateCorpusBenchmark(missingRaw)).toThrow(/cache\/artifact provenance is incomplete/);
  });

  it("binds truthful runner/tool cohort identity while normalizing unique hosted VM suffixes", () => {
    const hosted = qualifyingMatrix().map((row) => ({
      ...row,
      actualRunner: {
        ...row.actualRunner,
        jobs: row.actualRunner.jobs.map((job, index) => ({ ...job, name: `GitHub Actions ${row.runId * 100 + index}` })),
      },
    }));
    expect(() => evaluateCorpusBenchmark(hosted)).not.toThrow();

    const mixedRunner = qualifyingMatrix();
    mixedRunner[0]!.actualRunner.image = "different-image";
    expect(() => evaluateCorpusBenchmark(mixedRunner)).toThrow(/cohort mixes actual runner/);

    const mixedTools = qualifyingMatrix();
    mixedTools[0]!.raw.toolVersions.node = "v25";
    expect(() => evaluateCorpusBenchmark(mixedTools)).toThrow(/tool\/runtime/);
  });

  it("refuses a concurrency candidate whose simultaneous peak exceeds 75% of runner memory", () => {
    const matrix = qualifyingMatrix();
    for (const row of matrix) {
      if (row.design === "target-workers" && row.concurrency === 2 && row.shardCount === 3) row.peakRssBytes = 12_001;
    }
    matrix.push(
      ...triplet({ profile: "cold", design: "target-workers", concurrency: 3, shardCount: 4, criticalPathMs: 800, aggregateRunnerMs: 2_500 }),
      ...triplet({ profile: "warm", design: "target-workers", concurrency: 3, shardCount: 4, criticalPathMs: 640, aggregateRunnerMs: 2_500 }),
    );
    const decision = evaluateCorpusBenchmark(matrix);
    expect(decision.concurrency.rejected).toContainEqual({
      shape: "target-workers:2",
      reasons: expect.arrayContaining([expect.stringContaining("peak RSS fraction")]),
    });
    expect(decision.concurrency.selected).not.toEqual({ design: "target-workers", concurrency: 2 });
  });
});
