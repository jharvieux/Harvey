import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CORPUS_BENCHMARK_THRESHOLDS,
  corpusBenchmarkProvenanceIntegrity,
  corpusBenchmarkThresholdDigest,
  evaluateCorpusBenchmark,
  type CorpusBenchmarkArtifactEvidence,
  type CorpusBenchmarkCacheProvenance,
  type CorpusBenchmarkSample,
  type CorpusBenchmarkTransportEvidence,
} from "./corpus-benchmark.js";
import { corpusCacheTransportKey } from "./corpus-cache-transport.js";

const digest = (character: string): string => character.repeat(64);
const stable = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  return JSON.stringify(value);
};
const hash = (value: unknown): string => createHash("sha256").update(stable(value)).digest("hex");
const directHash = (value: string): string => createHash("sha256").update(value).digest("hex");

function sample(overrides: Partial<CorpusBenchmarkSample> = {}): CorpusBenchmarkSample {
  const profile = overrides.profile ?? "warm";
  const shardCount = overrides.shardCount ?? 3;
  const runId = overrides.runId ?? 1;
  const runAttempt = overrides.runAttempt ?? 1;
  const headSha = "a".repeat(40);
  const benchmarkSeed = "matched-seed";
  const ref = "refs/heads/benchmark";
  const platform = "linux-x64";
  const targetCommits = { alpha: "b".repeat(40), beta: "c".repeat(40) };
  const targets = Object.keys(targetCommits).sort();
  const toolVersions = { node: "v24" };
  const conservationVectors = targets.map((slug) => ({ slug, modules: ["M4"], checks: 1, findings: 1, disclosures: 0, baselines: 1, examinedUnits: 5, digest: hash({ slug, profile, runId }) }));
  const invariantVectors = targets.map((slug) => ({
    slug,
    evidence: {
      rows: [{ slug, check: "M4 baseline", module: "M4", pass: true }],
      findings: [{ severity: "Low" }],
      detectors: [{ unitsExamined: 2 }],
      mechanicalContext: { files: 2 },
      mechanicalRun: {
        executionPlan: { families: ["auth"] },
        semgrepDiagnostics: { errors: [], skipped: [] },
        phases: [{ phase: "semgrep", cache: "verified", key: hash(`${slug}:semgrep`), scope: { unitsExamined: 2 }, evidence: { semgrepDiagnostics: { errors: [], skipped: [] } } }],
      },
      scannerRecords: [{ scanner: "detect-static", cache: "verified", reason: "complete content-addressed artifact", key: hash(`${slug}:scanner`), scope: { unitsExamined: 3 } }],
      dependencyPreparations: [{ status: "materialized", reason: "complete content-addressed dependency preparation", key: hash(`${slug}:deps`), complete: true }],
      phaseNames: ["install", "scan"],
      runtime: toolVersions,
    },
    dependencyInputs: [{ status: "materialized", reason: "complete content-addressed dependency preparation", key: hash(`${slug}:deps`), complete: true }],
    cacheInputs: { mechanicalPhases: [{ phase: "semgrep", key: hash(`${slug}:semgrep`), scope: { unitsExamined: 2 } }], scanners: [{ scanner: "detect-static", key: hash(`${slug}:scanner`), scope: { unitsExamined: 3 } }] },
    toolInputs: { runtime: toolVersions },
  }));
  const population: CorpusBenchmarkSample["population"] = {
    targetDigest: hash(Object.entries(targetCommits).sort(([left], [right]) => left.localeCompare(right))),
    targets,
    rowDigest: hash("rows"),
    findingDigest: hash("findings"),
    disclosureDigest: hash("disclosures"),
    baselineDigest: hash("baselines"),
    examinedDigest: hash(conservationVectors.map((row) => ({ slug: row.slug, examinedUnits: row.examinedUnits }))),
    evidenceDigest: hash(invariantVectors.map(({ slug, evidence }) => ({ slug, evidence }))),
    conservationDigest: hash(conservationVectors),
    dependencyInputDigest: hash(invariantVectors.map(({ slug, dependencyInputs }) => ({ slug, dependencyInputs }))),
    cacheInputDigest: hash(invariantVectors.map(({ slug, cacheInputs }) => ({ slug, cacheInputs }))),
    toolInputDigest: hash(invariantVectors.map(({ slug, toolInputs }) => ({ slug, toolInputs }))),
  };
  const seedDigest = directHash(benchmarkSeed).slice(0, 16);
  const transport = (role: "source" | "output", namespace: string, transportRunId: string): CorpusBenchmarkTransportEvidence => {
    const key = corpusCacheTransportKey({ family: "benchmark", platform, namespace, runId: transportRunId, runAttempt: String(runAttempt), headSha, benchmarkSeed });
    return { role, key, family: "benchmark", event: "workflow_dispatch", ref, platform, namespace, runId: transportRunId, runAttempt: String(runAttempt), headSha, benchmarkSeed, seedDigest, payloadBytes: 100 + Number(namespace) };
  };
  const sources = ["1", "2", "3"].map((namespace) => transport("source", namespace, String(50_000 + runId)));
  const outputs = Array.from({ length: shardCount }, (_, index) => transport("output", String(index + 1), String(runId)));
  const sourceFiles = [{ path: `corpus-scanners/detect-static/${hash("source")}.json`, sha256: hash("source body"), bytes: 123, sourceNamespaces: ["1", "2", "3"] }];
  const sourceContentDigest = directHash(JSON.stringify(sourceFiles));
  const artifacts: CorpusBenchmarkArtifactEvidence[] = [
    { name: "actions/jobs.json", family: "actions/jobs", sha256: hash({ runId, name: "jobs" }) },
    ...Array.from({ length: shardCount }, (_, index) => ({ name: `evidence/benchmark-cache-merge-receipt-${index + 1}.json`, family: "evidence/benchmark-cache-merge-receipt", sha256: hash({ runId, name: "merge", index }) })),
    ...Array.from({ length: shardCount }, (_, index) => ({ name: `evidence/benchmark-runner-${index + 1}.json`, family: "evidence/benchmark-runner", sha256: hash({ runId, name: "runner", index }) })),
    ...Array.from({ length: shardCount }, (_, index) => ({ name: `evidence/benchmark-transport-${index + 1}.json`, family: "evidence/benchmark-transport", sha256: hash({ runId, name: "transport", index }) })),
    { name: "scorecard/corpus-drift.json", family: "scorecard/corpus-drift", sha256: hash({ runId, name: "scorecard" }) },
  ].sort((left, right) => left.name.localeCompare(right.name));
  const mergeDigests = artifacts.filter((artifact) => artifact.family === "evidence/benchmark-cache-merge-receipt").map((artifact) => artifact.sha256);
  const transportDigests = artifacts.filter((artifact) => artifact.family === "evidence/benchmark-transport").map((artifact) => artifact.sha256);
  const artifactFamilies = [...artifacts.reduce((counts, artifact) => counts.set(artifact.family, (counts.get(artifact.family) ?? 0) + 1), new Map<string, number>())]
    .map(([family, count]) => ({ family, count })).sort((left, right) => left.family.localeCompare(right.family));
  const provenanceWithoutIntegrity: Omit<CorpusBenchmarkCacheProvenance, "integrityDigest"> = {
    schema: 1,
    invariant: {
      benchmarkSeed,
      headSha,
      ref,
      platform,
      targetDigest: population.targetDigest,
      evidenceDigest: population.evidenceDigest,
      dependencyInputDigest: population.dependencyInputDigest,
      cacheInputDigest: population.cacheInputDigest,
      toolInputDigest: population.toolInputDigest,
      sourceNamespaces: ["1", "2", "3"],
      sourceContentDigest,
      sourceTransports: sources.map((row) => ({ family: row.family, event: row.event, ref: row.ref, platform: row.platform, namespace: row.namespace, headSha: row.headSha, benchmarkSeed: row.benchmarkSeed, seedDigest: row.seedDigest, payloadBytes: row.payloadBytes })),
    },
    shape: { outputNamespaces: outputs.map((row) => row.namespace), artifactFamilies },
    transports: { sources, outputs },
    sourceFiles,
    receiptDigests: [...mergeDigests, ...transportDigests].sort(),
  };
  const transportKeys = [...sources, ...outputs].map((row) => row.key).sort();
  const provenanceDigests = [sourceContentDigest, ...transportDigests].sort();
  const provenance: CorpusBenchmarkCacheProvenance = {
    ...provenanceWithoutIntegrity,
    integrityDigest: corpusBenchmarkProvenanceIntegrity({ provenance: provenanceWithoutIntegrity, transportKeys, provenanceDigests, artifacts }),
  };
  return {
    schema: 1,
    runId,
    runAttempt,
    workflow: "corpus-drift.yml",
    headSha,
    benchmarkSeed,
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
    cache: { hits: profile === "warm" ? 10 : 0, misses: 0, recomputed: profile === "cold" ? 10 : 0, rejected: 0, transportKeys, provenanceDigests, strandedArtifacts: 0, provenance },
    population,
    assertions: { baselines: true, liveness: true, forcedCold: true, conservation: true },
    oomCount: 0,
    retryCount: 0,
    billedMinutes: overrides.billedMinutes ?? 2,
    estimatedCostUsd: overrides.estimatedCostUsd ?? 1,
    raw: { workflowUrl: `https://example.test/run/${runId}`, jobIds: Array.from({ length: shardCount }, (_, index) => index + 1), artifactDigests: [...new Set(artifacts.map((artifact) => artifact.sha256))].sort(), artifacts, conservationVectors, invariantVectors, toolVersions, targetCommits },
    ...overrides,
  };
}

let nextRunId = 100;

function triplet(overrides: Partial<CorpusBenchmarkSample>): CorpusBenchmarkSample[] {
  return [1, 2, 3].map((repeat) => sample({ ...overrides, repeat, runId: nextRunId++ }));
}

function resample(row: CorpusBenchmarkSample, overrides: Partial<CorpusBenchmarkSample> = {}): CorpusBenchmarkSample {
  return sample({
    repeat: row.repeat,
    runnerRole: row.runnerRole,
    requestedRunner: row.requestedRunner,
    profile: row.profile,
    design: row.design,
    concurrency: row.concurrency,
    effectiveConcurrency: row.effectiveConcurrency,
    shardCount: row.shardCount,
    criticalPathMs: row.criticalPathMs,
    aggregateRunnerMs: row.aggregateRunnerMs,
    peakRssBytes: row.peakRssBytes,
    billedMinutes: row.billedMinutes,
    estimatedCostUsd: row.estimatedCostUsd,
    ...overrides,
  });
}

function reseal(sampleRow: CorpusBenchmarkSample): void {
  const invariantVectors = sampleRow.raw.invariantVectors;
  sampleRow.population.targetDigest = hash(Object.entries(sampleRow.raw.targetCommits).sort(([left], [right]) => left.localeCompare(right)));
  sampleRow.population.targets = Object.keys(sampleRow.raw.targetCommits).sort();
  sampleRow.population.evidenceDigest = hash(invariantVectors.map(({ slug, evidence }) => ({ slug, evidence })));
  sampleRow.population.dependencyInputDigest = hash(invariantVectors.map(({ slug, dependencyInputs }) => ({ slug, dependencyInputs })));
  sampleRow.population.cacheInputDigest = hash(invariantVectors.map(({ slug, cacheInputs }) => ({ slug, cacheInputs })));
  sampleRow.population.toolInputDigest = hash(invariantVectors.map(({ slug, toolInputs }) => ({ slug, toolInputs })));
  sampleRow.population.conservationDigest = hash(sampleRow.raw.conservationVectors);
  sampleRow.population.examinedDigest = hash(sampleRow.raw.conservationVectors.map((row) => ({ slug: row.slug, examinedUnits: row.examinedUnits })));

  const provenance = sampleRow.cache.provenance;
  provenance.invariant.targetDigest = sampleRow.population.targetDigest;
  provenance.invariant.evidenceDigest = sampleRow.population.evidenceDigest;
  provenance.invariant.dependencyInputDigest = sampleRow.population.dependencyInputDigest;
  provenance.invariant.cacheInputDigest = sampleRow.population.cacheInputDigest;
  provenance.invariant.toolInputDigest = sampleRow.population.toolInputDigest;
  provenance.invariant.sourceNamespaces = provenance.transports.sources.map((transport) => transport.namespace).sort();
  provenance.invariant.sourceContentDigest = directHash(JSON.stringify(provenance.sourceFiles));
  provenance.invariant.sourceTransports = provenance.transports.sources.map((transport) => ({ family: transport.family, event: transport.event, ref: transport.ref, platform: transport.platform, namespace: transport.namespace, headSha: transport.headSha, benchmarkSeed: transport.benchmarkSeed, seedDigest: transport.seedDigest, payloadBytes: transport.payloadBytes }));
  provenance.shape.outputNamespaces = provenance.transports.outputs.map((transport) => transport.namespace).sort();
  sampleRow.raw.artifacts.sort((left, right) => left.name.localeCompare(right.name));
  provenance.shape.artifactFamilies = [...sampleRow.raw.artifacts.reduce((counts, artifact) => counts.set(artifact.family, (counts.get(artifact.family) ?? 0) + 1), new Map<string, number>())]
    .map(([family, count]) => ({ family, count })).sort((left, right) => left.family.localeCompare(right.family));
  sampleRow.raw.artifactDigests = [...new Set(sampleRow.raw.artifacts.map((artifact) => artifact.sha256))].sort();
  const mergeDigests = sampleRow.raw.artifacts.filter((artifact) => artifact.family === "evidence/benchmark-cache-merge-receipt").map((artifact) => artifact.sha256);
  const transportDigests = sampleRow.raw.artifacts.filter((artifact) => artifact.family === "evidence/benchmark-transport").map((artifact) => artifact.sha256);
  provenance.receiptDigests = [...mergeDigests, ...transportDigests].sort();
  sampleRow.cache.transportKeys = [...new Set([...provenance.transports.sources, ...provenance.transports.outputs].map((transport) => transport.key))].sort();
  sampleRow.cache.provenanceDigests = [...new Set([provenance.invariant.sourceContentDigest, ...transportDigests])].sort();
  const withoutIntegrity: Omit<CorpusBenchmarkCacheProvenance, "integrityDigest"> = {
    schema: provenance.schema,
    invariant: provenance.invariant,
    shape: provenance.shape,
    transports: provenance.transports,
    sourceFiles: provenance.sourceFiles,
    receiptDigests: provenance.receiptDigests,
  };
  provenance.integrityDigest = corpusBenchmarkProvenanceIntegrity({
    provenance: withoutIntegrity,
    transportKeys: sampleRow.cache.transportKeys,
    provenanceDigests: sampleRow.cache.provenanceDigests,
    artifacts: sampleRow.raw.artifacts,
  });
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
    const schedule = matrix.map((row, ordinal) => resample(row, { runId: 20_000 + ordinal, runnerRole: "schedule", criticalPathMs: 100 }));
    const larger = matrix.filter((row) => row.design === "target-workers" && row.concurrency === 2 && row.shardCount === 3).map((row, ordinal) => {
      const rerun = resample(row, { runId: 30_000 + ordinal, requestedRunner: "larger-linux", criticalPathMs: 5_000, aggregateRunnerMs: 10_000 });
      rerun.actualRunner = { ...rerun.actualRunner, labels: ["larger-linux"], cpuLimit: 8, memoryLimitBytes: 32_000 };
      return rerun;
    });

    const decision = evaluateCorpusBenchmark([...matrix, ...schedule, ...larger]);
    expect(decision.concurrency.selected).toEqual({ design: "target-workers", concurrency: 2 });
    expect(decision.shards.selected).toBe(4);
  });

  it("adopts a larger PR runner only after all latency/cost/cold thresholds pass", () => {
    const larger = qualifyingMatrix().filter((row) => row.design === "target-workers" && row.shardCount === 3).map((row, ordinal) => {
      const rerun = resample(row, { runId: 8_000 + ordinal, requestedRunner: "larger-linux", criticalPathMs: 600, aggregateRunnerMs: 1_900, billedMinutes: 2, estimatedCostUsd: 1.20 });
      rerun.actualRunner = { ...rerun.actualRunner, labels: ["larger-linux"], cpuLimit: 8, memoryLimitBytes: 32_000 };
      return rerun;
    });
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
    expect(() => evaluateCorpusBenchmark(mixed)).toThrow(/seed\/head|mixes head, seed/);
    const population = qualifyingMatrix();
    population[0]!.population.findingDigest = digest("9");
    expect(() => evaluateCorpusBenchmark(population)).toThrow(/target\/evidence/);

    const evidence = qualifyingMatrix();
    evidence[0]!.population.evidenceDigest = digest("e");
    expect(() => evaluateCorpusBenchmark(evidence)).toThrow(/target\/evidence|evidenceDigest/);

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
    expect(() => evaluateCorpusBenchmark(mixedTools)).toThrow(/tool\/runtime|evidenceDigest/);
  });

  it("rejects isolated mutations anywhere in the transport, artifact, conservation, dependency, cache, scanner, Semgrep, phase, or runtime envelope", () => {
    const mutations: Array<[string, (row: CorpusBenchmarkSample) => void]> = [
      ["transport key", (row) => { row.cache.provenance.transports.outputs[0]!.key = row.cache.provenance.transports.outputs[0]!.key.replace("shard1", "shard9"); }],
      ["provenance digest", (row) => { row.cache.provenanceDigests[0] = digest("f"); }],
      ["artifact digest", (row) => { row.raw.artifacts[0]!.sha256 = digest("f"); }],
      ["integrity digest", (row) => { row.cache.provenance.integrityDigest = digest("f"); }],
      ["conservation envelope", (row) => { row.raw.conservationVectors[0]!.digest = digest("f"); }],
      ["dependency reason", (row) => { ((row.raw.invariantVectors[0]!.dependencyInputs as Array<{ reason: string }>)[0]!).reason = "changed dependency reason"; }],
      ["cache identity", (row) => { ((row.raw.invariantVectors[0]!.cacheInputs as { mechanicalPhases: Array<{ key: string }> }).mechanicalPhases[0]!).key = digest("f"); }],
      ["tool identity", (row) => { ((row.raw.invariantVectors[0]!.toolInputs as { runtime: { node: string } }).runtime).node = "v25"; }],
      ["scanner reason", (row) => { ((((row.raw.invariantVectors[0]!.evidence as { scannerRecords: Array<{ reason: string }> }).scannerRecords)[0]!)).reason = "changed scanner reason"; }],
      ["Semgrep diagnostics", (row) => { ((row.raw.invariantVectors[0]!.evidence as { mechanicalRun: { semgrepDiagnostics: { errors: unknown[] } } }).mechanicalRun.semgrepDiagnostics.errors).push("changed"); }],
      ["phase evidence", (row) => { ((row.raw.invariantVectors[0]!.evidence as { mechanicalRun: { phases: Array<{ evidence: { semgrepDiagnostics: { skipped: unknown[] } } }> } }).mechanicalRun.phases[0]!.evidence.semgrepDiagnostics.skipped).push("changed"); }],
      ["runtime evidence", (row) => { ((row.raw.invariantVectors[0]!.evidence as { runtime: { node: string } }).runtime).node = "v25"; }],
    ];
    for (const [name, mutate] of mutations) {
      const matrix = qualifyingMatrix();
      mutate(matrix[0]!);
      expect(() => evaluateCorpusBenchmark(matrix), name).toThrow();
    }
  });

  it("rejects internally resealed mixed invariant evidence in either cohort direction while allowing run-specific bodies and transport run ids", () => {
    const invariantMutations: Array<[string, (row: CorpusBenchmarkSample) => void]> = [
      ["dependency reason", (row) => {
        const vector = row.raw.invariantVectors[0]!;
        ((vector.dependencyInputs as Array<{ reason: string }>)[0]!).reason = "complete content-addressed dependency preparation with a different invariant";
        ((((vector.evidence as { dependencyPreparations: Array<{ reason: string }> }).dependencyPreparations)[0]!)).reason = "complete content-addressed dependency preparation with a different invariant";
      }],
      ["scanner reason", (row) => { ((((row.raw.invariantVectors[0]!.evidence as { scannerRecords: Array<{ reason: string }> }).scannerRecords)[0]!)).reason = "different complete scanner evidence"; }],
      ["Semgrep diagnostics", (row) => { ((row.raw.invariantVectors[0]!.evidence as { mechanicalRun: { semgrepDiagnostics: { errors: unknown[] } } }).mechanicalRun.semgrepDiagnostics.errors).push("different diagnostic"); }],
      ["phase evidence", (row) => { ((row.raw.invariantVectors[0]!.evidence as { mechanicalRun: { phases: Array<{ evidence: { semgrepDiagnostics: { skipped: unknown[] } } }> } }).mechanicalRun.phases[0]!.evidence.semgrepDiagnostics.skipped).push("different phase evidence"); }],
      ["cache identity", (row) => {
        const changed = digest("f");
        ((row.raw.invariantVectors[0]!.cacheInputs as { mechanicalPhases: Array<{ key: string }> }).mechanicalPhases[0]!).key = changed;
        ((row.raw.invariantVectors[0]!.evidence as { mechanicalRun: { phases: Array<{ key: string }> } }).mechanicalRun.phases[0]!).key = changed;
      }],
      ["runtime/tool identity", (row) => {
        row.raw.toolVersions.node = "v25";
        (row.raw.invariantVectors[0]!.evidence as { runtime: { node: string } }).runtime.node = "v25";
        (row.raw.invariantVectors[0]!.toolInputs as { runtime: { node: string } }).runtime.node = "v25";
      }],
    ];
    for (const [name, mutate] of invariantMutations) {
      for (const index of [0, 2]) {
        const matrix = qualifyingMatrix();
        const changed = matrix[index]!;
        mutate(changed);
        changed.raw.conservationVectors[0]!.digest = hash({ resealed: changed.raw.invariantVectors[0] });
        reseal(changed);
        expect(() => evaluateCorpusBenchmark(matrix), `${name} at ${index}`).toThrow(/benchmark mixes|cohort mixes/);
      }
    }

    const transport = qualifyingMatrix();
    for (const source of transport[0]!.cache.provenance.transports.sources) source.event = "different-event";
    reseal(transport[0]!);
    expect(() => evaluateCorpusBenchmark(transport)).toThrow(/benchmark mixes|cohort mixes/);

    const sourceContent = qualifyingMatrix();
    sourceContent[0]!.cache.provenance.sourceFiles[0]!.sha256 = digest("f");
    reseal(sourceContent[0]!);
    expect(() => evaluateCorpusBenchmark(sourceContent)).toThrow(/benchmark mixes|cohort mixes/);

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
