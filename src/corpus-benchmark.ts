import { createHash } from "node:crypto";
import type { CorpusExecutionDesign } from "./corpus-execution.js";

export type CorpusCacheProfile = "cold" | "warm";
export type CorpusRunnerRole = "pr" | "schedule";

export interface CorpusBenchmarkSample {
  schema: 1;
  runId: number;
  runAttempt: number;
  workflow: "corpus-drift.yml";
  headSha: string;
  benchmarkSeed: string;
  repeat: number;
  runnerRole: CorpusRunnerRole;
  requestedRunner: string;
  actualRunner: {
    jobs: Array<{ id: number; name: string }>;
    group: string;
    labels: string[];
    image: string;
    cpuLimit: number;
    memoryLimitBytes: number;
  };
  profile: CorpusCacheProfile;
  design: CorpusExecutionDesign;
  concurrency: number;
  effectiveConcurrency: number;
  shardCount: number;
  criticalPathMs: number;
  aggregateRunnerMs: number;
  aggregateCpuSeconds: number;
  peakRssBytes: number;
  setupNetworkMs: number;
  dependencyMs: number;
  targetProcessCpuMs: number;
  cache: {
    hits: number;
    misses: number;
    recomputed: number;
    rejected: number;
    transportKeys: string[];
    provenanceDigests: string[];
    strandedArtifacts: number;
  };
  population: {
    targetDigest: string;
    targets: string[];
    rowDigest: string;
    findingDigest: string;
    disclosureDigest: string;
    baselineDigest: string;
    examinedDigest: string;
    evidenceDigest: string;
  };
  assertions: {
    baselines: boolean;
    liveness: boolean;
    forcedCold: boolean;
    conservation: boolean;
  };
  oomCount: number;
  retryCount: number;
  billedMinutes: number;
  estimatedCostUsd: number;
  raw: {
    workflowUrl: string;
    jobIds: number[];
    artifactDigests: string[];
    toolVersions: Record<string, string>;
    targetCommits: Record<string, string>;
  };
}

interface CorpusBenchmarkThresholds {
  schema: 1;
  version: string;
  concurrency: {
    medianCriticalImprovement: number;
    coldP95MaxRegression: number;
    aggregateMaxIncrease: number;
    peakRssLimitFraction: number;
    preferSmallerWithin: number;
  };
  largerPrRunner: {
    medianCriticalImprovement: number;
    p95CriticalImprovement: number;
    costMaxIncrease: number;
    coldSampleMaxRegression: number;
  };
  scheduledRunner: { costWithin: number; timeoutAvoidancePermitsAdoption: boolean };
  fourShards: {
    warmMedianImprovement: number;
    coldP95MaxRegression: number;
    aggregateMaxIncrease: number;
  };
}

export const CORPUS_BENCHMARK_THRESHOLDS: CorpusBenchmarkThresholds = {
  schema: 1,
  version: "corpus-performance-2026-08-12-v1",
  concurrency: {
    medianCriticalImprovement: 0.10,
    coldP95MaxRegression: 0.05,
    aggregateMaxIncrease: 0.10,
    peakRssLimitFraction: 0.75,
    preferSmallerWithin: 0.05,
  },
  largerPrRunner: {
    medianCriticalImprovement: 0.20,
    p95CriticalImprovement: 0.15,
    costMaxIncrease: 0.25,
    coldSampleMaxRegression: 0.10,
  },
  scheduledRunner: { costWithin: 0.05, timeoutAvoidancePermitsAdoption: true },
  fourShards: {
    warmMedianImprovement: 0.15,
    coldP95MaxRegression: 0.10,
    aggregateMaxIncrease: 0.25,
  },
};

interface CorpusBenchmarkDecision {
  schema: 1;
  thresholdVersion: string;
  thresholdDigest: string;
  provenance: { headSha: string; benchmarkSeed: string; targetDigest: string; sampleRunIds: number[] };
  concurrency: {
    selected: { design: CorpusExecutionDesign; concurrency: number };
    eligible: string[];
    rejected: Array<{ shape: string; reasons: string[] }>;
  };
  runners: {
    pr: { selected: string; adoptedLarger: boolean; reasons: string[] };
    schedule: { selected: string; adoptedLarger: boolean; reasons: string[] };
  };
  shards: {
    selected: 3 | 4;
    coldFallback: 3;
    reasons: string[];
  };
  extendToFive: string[];
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

export function corpusBenchmarkThresholdDigest(): string {
  return createHash("sha256").update(stable(CORPUS_BENCHMARK_THRESHOLDS)).digest("hex");
}

function median(values: readonly number[]): number {
  if (values.length === 0) throw new Error("median has no samples");
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1]! + sorted[middle]!) / 2 : sorted[middle]!;
}

function nearestRankP95(values: readonly number[]): number {
  if (values.length === 0) throw new Error("p95 has no samples");
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.ceil(0.95 * sorted.length) - 1]!;
}

function coefficientOfVariation(values: readonly number[]): number {
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  if (mean === 0) return 0;
  const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance) / mean;
}

function increase(candidate: number, baseline: number): number {
  return baseline === 0 ? (candidate === 0 ? 0 : Infinity) : candidate / baseline - 1;
}

function improvement(candidate: number, baseline: number): number {
  return -increase(candidate, baseline);
}

function cohort(samples: readonly CorpusBenchmarkSample[], predicate: (sample: CorpusBenchmarkSample) => boolean, label: string): CorpusBenchmarkSample[] {
  const rows = samples.filter(predicate);
  const repeats = new Set(rows.map((sample) => sample.repeat));
  const runs = new Set(rows.map((sample) => `${sample.runId}/${sample.runAttempt}`));
  if (rows.length < 3 || repeats.size < 3) throw new Error(`${label}: requires at least three distinct real repeats; got ${rows.length} sample(s), ${repeats.size} repeat(s)`);
  if (rows.length !== repeats.size) throw new Error(`${label}: repeats are duplicated; got ${rows.length} sample(s), ${repeats.size} repeat id(s)`);
  if (rows.length !== runs.size) throw new Error(`${label}: one hosted run was counted more than once`);
  return rows;
}

function assertSample(sample: CorpusBenchmarkSample): void {
  if (sample.schema !== 1 || sample.workflow !== "corpus-drift.yml") throw new Error(`run ${sample.runId}: unsupported benchmark sample`);
  if (!/^[0-9a-f]{40}$/.test(sample.headSha)) throw new Error(`run ${sample.runId}: headSha is invalid`);
  if (!Number.isInteger(sample.repeat) || sample.repeat < 1) throw new Error(`run ${sample.runId}: repeat is invalid`);
  if (!Number.isInteger(sample.concurrency) || sample.concurrency < 1 || sample.concurrency > 3) throw new Error(`run ${sample.runId}: concurrency is invalid`);
  if (![3, 4].includes(sample.shardCount)) throw new Error(`run ${sample.runId}: shard count is invalid`);
  if (sample.effectiveConcurrency < 1 || sample.effectiveConcurrency > sample.concurrency) throw new Error(`run ${sample.runId}: effective concurrency is invalid`);
  if (sample.design === "serial" && sample.effectiveConcurrency !== 1) throw new Error(`run ${sample.runId}: serial design claims concurrent execution`);
  if (sample.design === "split-carbon" && sample.effectiveConcurrency === 1) throw new Error(`run ${sample.runId}: split-carbon did not execute a separate lane and may not enter the benchmark`);
  if (sample.criticalPathMs <= 0 || sample.aggregateRunnerMs <= 0 || sample.billedMinutes <= 0) throw new Error(`run ${sample.runId}: timing/cost receipt is incomplete`);
  if (!Number.isFinite(sample.estimatedCostUsd) || sample.estimatedCostUsd < 0) throw new Error(`run ${sample.runId}: dollar-cost receipt is invalid`);
  if (sample.criticalPathMs > sample.aggregateRunnerMs) throw new Error(`run ${sample.runId}: critical path exceeds summed runner time`);
  if (sample.peakRssBytes <= 0 || sample.actualRunner.memoryLimitBytes <= 0 || sample.actualRunner.cpuLimit <= 0) throw new Error(`run ${sample.runId}: CPU/RSS receipt is incomplete`);
  if (sample.population.targets.length === 0 || new Set(sample.population.targets).size !== sample.population.targets.length) throw new Error(`run ${sample.runId}: target population is empty or duplicated`);
  for (const [name, digest] of Object.entries(sample.population).filter(([key]) => key.endsWith("Digest"))) {
    if (!/^[0-9a-f]{64}$/.test(String(digest))) throw new Error(`run ${sample.runId}: ${name} is not a SHA-256 digest`);
  }
  if (!Object.values(sample.assertions).every(Boolean)) throw new Error(`run ${sample.runId}: baseline/liveness/forced-cold/conservation assertion is missing`);
  if (sample.profile === "cold" && sample.cache.recomputed === 0) throw new Error(`run ${sample.runId}: cold sample has no forced-cold recomputation proof`);
  if (sample.profile === "warm" && (sample.cache.hits === 0 || sample.cache.misses !== 0 || sample.cache.recomputed !== 0 || sample.cache.rejected !== 0)) throw new Error(`run ${sample.runId}: warm sample is not an all-hit validated cache run`);
  if (sample.profile === "cold" && (sample.cache.misses !== 0 || sample.cache.rejected !== 0)) throw new Error(`run ${sample.runId}: cold sample is not an exact-seed forced recomputation run`);
  if (sample.oomCount !== 0 || sample.retryCount !== 0) throw new Error(`run ${sample.runId}: OOM/retry is a regression`);
  if (sample.cache.strandedArtifacts !== 0) throw new Error(`run ${sample.runId}: content-addressed artifacts were stranded`);
  if (sample.raw.jobIds.length !== sample.shardCount || new Set(sample.raw.jobIds).size !== sample.shardCount) throw new Error(`run ${sample.runId}: raw shard job population is incomplete or duplicated`);
  if (sample.cache.transportKeys.length === 0 || sample.cache.provenanceDigests.length === 0 || sample.raw.artifactDigests.length === 0) throw new Error(`run ${sample.runId}: cache/artifact provenance is incomplete`);
  if (![...sample.cache.provenanceDigests, ...sample.raw.artifactDigests].every((value) => /^[0-9a-f]{64}$/.test(value))) throw new Error(`run ${sample.runId}: cache/artifact digest is invalid`);
}

function assertMatchedPopulation(samples: readonly CorpusBenchmarkSample[]): { headSha: string; benchmarkSeed: string; targetDigest: string } {
  const heads = new Set(samples.map((sample) => sample.headSha));
  const seeds = new Set(samples.map((sample) => sample.benchmarkSeed));
  const targetDigests = new Set(samples.map((sample) => sample.population.targetDigest));
  for (const [label, values] of [["head", heads], ["benchmark seed", seeds], ["target population", targetDigests]] as const) {
    if (values.size !== 1) throw new Error(`benchmark mixes ${label} identities: ${[...values].join(", ")}`);
  }
  return { headSha: [...heads][0]!, benchmarkSeed: [...seeds][0]!, targetDigest: [...targetDigests][0]! };
}

function allAssertionsEqual(left: CorpusBenchmarkSample, right: CorpusBenchmarkSample): boolean {
  const comparable = (sample: CorpusBenchmarkSample): unknown => ({
    targetDigest: sample.population.targetDigest,
    targets: sample.population.targets,
    rowDigest: sample.population.rowDigest,
    findingDigest: sample.population.findingDigest,
    disclosureDigest: sample.population.disclosureDigest,
    baselineDigest: sample.population.baselineDigest,
    examinedDigest: sample.population.examinedDigest,
    assertions: sample.assertions,
  });
  return stable(comparable(left)) === stable(comparable(right));
}

function nearThreshold(value: number, threshold: number): boolean {
  return Math.abs(value - threshold) <= 0.05;
}

function highVariation(samples: readonly CorpusBenchmarkSample[]): boolean {
  return coefficientOfVariation(samples.map((sample) => sample.criticalPathMs)) > 0.10;
}

const DESIGN_COMPLEXITY: Record<CorpusExecutionDesign, number> = {
  serial: 0,
  "target-workers": 1,
  "intra-target-overlap": 2,
  "split-carbon": 3,
};

export function evaluateCorpusBenchmark(samples: readonly CorpusBenchmarkSample[]): CorpusBenchmarkDecision {
  samples.forEach(assertSample);
  const provenance = assertMatchedPopulation(samples);
  const isStandardPr = (sample: CorpusBenchmarkSample): boolean => sample.runnerRole === "pr" && sample.requestedRunner === "ubuntu-latest";
  const baseline = {
    cold: cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "cold" && sample.design === "serial" && sample.concurrency === 1 && sample.shardCount === 3, "cold serial baseline"),
    warm: cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "warm" && sample.design === "serial" && sample.concurrency === 1 && sample.shardCount === 3, "warm serial baseline"),
  };
  const candidateShapes = [...new Set(samples
    .filter((sample) => isStandardPr(sample) && sample.shardCount === 3)
    .map((sample) => `${sample.design}:${sample.concurrency}`))]
    .filter((candidate) => candidate !== "serial:1")
    .sort();
  const eligible: string[] = [];
  const rejected: Array<{ shape: string; reasons: string[] }> = [];
  const extendToFive: string[] = [];
  for (const candidate of candidateShapes) {
    const [design, rawConcurrency] = candidate.split(":") as [CorpusExecutionDesign, string];
    const concurrency = Number(rawConcurrency);
    const cold = cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "cold" && sample.design === design && sample.concurrency === concurrency && sample.shardCount === 3, `${candidate} cold`);
    const warm = cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "warm" && sample.design === design && sample.concurrency === concurrency && sample.shardCount === 3, `${candidate} warm`);
    const reasons: string[] = [];
    for (const profile of ["cold", "warm"] as const) {
      if (![...cold, ...warm].filter((sample) => sample.profile === profile).every((sample) => baseline[profile].every((base) => allAssertionsEqual(sample, base)))) reasons.push(`${profile} population/evidence differs`);
    }
    const warmGain = improvement(median(warm.map((sample) => sample.criticalPathMs)), median(baseline.warm.map((sample) => sample.criticalPathMs)));
    const coldGain = improvement(median(cold.map((sample) => sample.criticalPathMs)), median(baseline.cold.map((sample) => sample.criticalPathMs)));
    const coldP95Regression = increase(nearestRankP95(cold.map((sample) => sample.criticalPathMs)), nearestRankP95(baseline.cold.map((sample) => sample.criticalPathMs)));
    const aggregateIncrease = Math.max(
      increase(median(cold.map((sample) => sample.aggregateRunnerMs)), median(baseline.cold.map((sample) => sample.aggregateRunnerMs))),
      increase(median(warm.map((sample) => sample.aggregateRunnerMs)), median(baseline.warm.map((sample) => sample.aggregateRunnerMs))),
    );
    const rssFraction = Math.max(...[...cold, ...warm].map((sample) => sample.peakRssBytes / sample.actualRunner.memoryLimitBytes));
    if (warmGain < CORPUS_BENCHMARK_THRESHOLDS.concurrency.medianCriticalImprovement || coldGain < CORPUS_BENCHMARK_THRESHOLDS.concurrency.medianCriticalImprovement) reasons.push(`median critical improvement cold=${coldGain.toFixed(3)} warm=${warmGain.toFixed(3)}`);
    if (coldP95Regression > CORPUS_BENCHMARK_THRESHOLDS.concurrency.coldP95MaxRegression) reasons.push(`cold p95 regression ${coldP95Regression.toFixed(3)}`);
    if (aggregateIncrease > CORPUS_BENCHMARK_THRESHOLDS.concurrency.aggregateMaxIncrease) reasons.push(`aggregate runner increase ${aggregateIncrease.toFixed(3)}`);
    if (rssFraction > CORPUS_BENCHMARK_THRESHOLDS.concurrency.peakRssLimitFraction) reasons.push(`peak RSS fraction ${rssFraction.toFixed(3)}`);
    if (reasons.length === 0) eligible.push(candidate);
    else rejected.push({ shape: candidate, reasons });
    if ([[warmGain, CORPUS_BENCHMARK_THRESHOLDS.concurrency.medianCriticalImprovement],
      [coldGain, CORPUS_BENCHMARK_THRESHOLDS.concurrency.medianCriticalImprovement],
      [coldP95Regression, CORPUS_BENCHMARK_THRESHOLDS.concurrency.coldP95MaxRegression],
      [aggregateIncrease, CORPUS_BENCHMARK_THRESHOLDS.concurrency.aggregateMaxIncrease],
      [rssFraction, CORPUS_BENCHMARK_THRESHOLDS.concurrency.peakRssLimitFraction]]
      .some(([value, threshold]) => nearThreshold(value!, threshold!)) || highVariation([...cold, ...warm])) extendToFive.push(candidate);
  }
  const candidateMeasurements = eligible
    .map((candidate) => {
      const [design, rawConcurrency] = candidate.split(":") as [CorpusExecutionDesign, string];
      const rows = samples.filter((sample) => isStandardPr(sample) && sample.design === design && sample.concurrency === Number(rawConcurrency) && sample.shardCount === 3);
      return { candidate, design, concurrency: Number(rawConcurrency), median: median(rows.map((sample) => sample.criticalPathMs)) };
    });
  const fastestCandidate = candidateMeasurements.length > 0 ? Math.min(...candidateMeasurements.map((candidate) => candidate.median)) : undefined;
  const selectedCandidate = fastestCandidate === undefined ? undefined : candidateMeasurements
    .filter((candidate) => increase(candidate.median, fastestCandidate) <= CORPUS_BENCHMARK_THRESHOLDS.concurrency.preferSmallerWithin)
    .sort((left, right) => DESIGN_COMPLEXITY[left.design] - DESIGN_COMPLEXITY[right.design]
      || left.concurrency - right.concurrency
      || left.median - right.median)[0];
  const concurrencySelection = selectedCandidate ?? { candidate: "serial:1", design: "serial" as const, concurrency: 1, median: Infinity };

  const runnerDecision = (role: CorpusRunnerRole): CorpusBenchmarkDecision["runners"][CorpusRunnerRole] => {
    const current = samples.filter((sample) => sample.runnerRole === role && sample.requestedRunner === "ubuntu-latest" && sample.design === concurrencySelection.design && sample.concurrency === concurrencySelection.concurrency && sample.shardCount === 3);
    const alternatives = [...new Set(samples.filter((sample) => sample.runnerRole === role && sample.requestedRunner !== "ubuntu-latest").map((sample) => sample.requestedRunner))];
    if (alternatives.length === 0) return { selected: "ubuntu-latest", adoptedLarger: false, reasons: ["no repository-visible larger-runner sample exists"] };
    const qualifying: Array<{ runner: string; medianGain: number; costIncrease: number }> = [];
    const reasons: string[] = [];
    for (const runner of alternatives) {
      const rows = samples.filter((sample) => sample.runnerRole === role && sample.requestedRunner === runner && sample.design === concurrencySelection.design && sample.concurrency === concurrencySelection.concurrency && sample.shardCount === 3);
      for (const profile of ["cold", "warm"] as const) {
        cohort(current, (sample) => sample.profile === profile, `${role} current ${profile}`);
        cohort(rows, (sample) => sample.profile === profile, `${role} ${runner} ${profile}`);
      }
      if (!rows.every((row) => current.every((base) => allAssertionsEqual(row, base)))) { reasons.push(`${runner}: population/evidence differs`); continue; }
      if (![...current, ...rows].every((row) => row.estimatedCostUsd > 0)) { reasons.push(`${runner}: dollar cost estimate is missing; runner adoption is forbidden`); continue; }
      const medianGain = improvement(median(rows.map((sample) => sample.criticalPathMs)), median(current.map((sample) => sample.criticalPathMs)));
      const p95Gain = improvement(nearestRankP95(rows.map((sample) => sample.criticalPathMs)), nearestRankP95(current.map((sample) => sample.criticalPathMs)));
      const costIncrease = increase(median(rows.map((sample) => sample.estimatedCostUsd)), median(current.map((sample) => sample.estimatedCostUsd)));
      const currentCold = new Map(current.filter((sample) => sample.profile === "cold").map((sample) => [sample.repeat, sample.criticalPathMs]));
      const worstCold = Math.max(...rows.filter((sample) => sample.profile === "cold").map((sample) => increase(sample.criticalPathMs, currentCold.get(sample.repeat)!)));
      const prQualified = medianGain >= CORPUS_BENCHMARK_THRESHOLDS.largerPrRunner.medianCriticalImprovement
        && p95Gain >= CORPUS_BENCHMARK_THRESHOLDS.largerPrRunner.p95CriticalImprovement
        && costIncrease <= CORPUS_BENCHMARK_THRESHOLDS.largerPrRunner.costMaxIncrease
        && worstCold <= CORPUS_BENCHMARK_THRESHOLDS.largerPrRunner.coldSampleMaxRegression;
      const scheduleQualified = medianGain >= 0 && costIncrease <= CORPUS_BENCHMARK_THRESHOLDS.scheduledRunner.costWithin;
      if (role === "pr" ? prQualified : scheduleQualified) qualifying.push({ runner, medianGain, costIncrease });
      else reasons.push(`${runner}: thresholds not met (median=${medianGain.toFixed(3)}, p95=${p95Gain.toFixed(3)}, cost=${costIncrease.toFixed(3)}, worst-cold=${worstCold.toFixed(3)})`);
      const thresholds = role === "pr"
        ? [[medianGain, CORPUS_BENCHMARK_THRESHOLDS.largerPrRunner.medianCriticalImprovement], [p95Gain, CORPUS_BENCHMARK_THRESHOLDS.largerPrRunner.p95CriticalImprovement], [costIncrease, CORPUS_BENCHMARK_THRESHOLDS.largerPrRunner.costMaxIncrease], [worstCold, CORPUS_BENCHMARK_THRESHOLDS.largerPrRunner.coldSampleMaxRegression]]
        : [[medianGain, 0], [costIncrease, CORPUS_BENCHMARK_THRESHOLDS.scheduledRunner.costWithin]];
      if (thresholds.some(([value, threshold]) => nearThreshold(value!, threshold!)) || highVariation([...current, ...rows])) extendToFive.push(`${role}-runner:${runner}`);
    }
    const selected = qualifying.sort((left, right) => right.medianGain - left.medianGain || left.costIncrease - right.costIncrease)[0];
    return selected ? { selected: selected.runner, adoptedLarger: true, reasons: [`qualified median gain ${selected.medianGain.toFixed(3)} at cost increase ${selected.costIncrease.toFixed(3)}`] } : { selected: "ubuntu-latest", adoptedLarger: false, reasons };
  };

  const threeCold = cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "cold" && sample.design === concurrencySelection.design && sample.concurrency === concurrencySelection.concurrency && sample.shardCount === 3, "three-shard cold");
  const threeWarm = cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "warm" && sample.design === concurrencySelection.design && sample.concurrency === concurrencySelection.concurrency && sample.shardCount === 3, "three-shard warm");
  const fourCold = cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "cold" && sample.design === concurrencySelection.design && sample.concurrency === concurrencySelection.concurrency && sample.shardCount === 4, "four-shard cold");
  const fourWarm = cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "warm" && sample.design === concurrencySelection.design && sample.concurrency === concurrencySelection.concurrency && sample.shardCount === 4, "four-shard warm");
  const shardReasons: string[] = [];
  if (![...fourCold, ...fourWarm].every((sample) => [...threeCold, ...threeWarm].every((base) => allAssertionsEqual(sample, base)))) shardReasons.push("three/four shard population or evidence differs");
  const warmGain = improvement(median(fourWarm.map((sample) => sample.criticalPathMs)), median(threeWarm.map((sample) => sample.criticalPathMs)));
  const coldP95Regression = increase(nearestRankP95(fourCold.map((sample) => sample.criticalPathMs)), nearestRankP95(threeCold.map((sample) => sample.criticalPathMs)));
  const aggregateIncrease = Math.max(
    increase(median(fourWarm.map((sample) => sample.aggregateRunnerMs)), median(threeWarm.map((sample) => sample.aggregateRunnerMs))),
    increase(median(fourCold.map((sample) => sample.aggregateRunnerMs)), median(threeCold.map((sample) => sample.aggregateRunnerMs))),
  );
  if (warmGain < CORPUS_BENCHMARK_THRESHOLDS.fourShards.warmMedianImprovement) shardReasons.push(`warm median improvement ${warmGain.toFixed(3)}`);
  if (coldP95Regression > CORPUS_BENCHMARK_THRESHOLDS.fourShards.coldP95MaxRegression) shardReasons.push(`cold p95 regression ${coldP95Regression.toFixed(3)}`);
  if (aggregateIncrease > CORPUS_BENCHMARK_THRESHOLDS.fourShards.aggregateMaxIncrease) shardReasons.push(`aggregate runner increase ${aggregateIncrease.toFixed(3)}`);
  const fourQualified = shardReasons.length === 0;
  if ([[warmGain, CORPUS_BENCHMARK_THRESHOLDS.fourShards.warmMedianImprovement],
    [coldP95Regression, CORPUS_BENCHMARK_THRESHOLDS.fourShards.coldP95MaxRegression],
    [aggregateIncrease, CORPUS_BENCHMARK_THRESHOLDS.fourShards.aggregateMaxIncrease]]
    .some(([value, threshold]) => nearThreshold(value!, threshold!)) || highVariation([...fourCold, ...fourWarm])) extendToFive.push("four-shards");

  return {
    schema: 1,
    thresholdVersion: CORPUS_BENCHMARK_THRESHOLDS.version,
    thresholdDigest: corpusBenchmarkThresholdDigest(),
    provenance: { ...provenance, sampleRunIds: [...new Set(samples.map((sample) => sample.runId))].sort((a, b) => a - b) },
    concurrency: { selected: { design: concurrencySelection.design, concurrency: concurrencySelection.concurrency }, eligible, rejected },
    runners: { pr: runnerDecision("pr"), schedule: runnerDecision("schedule") },
    shards: { selected: fourQualified ? 4 : 3, coldFallback: 3, reasons: fourQualified ? [`qualified warm=${warmGain.toFixed(3)}, cold-p95=${coldP95Regression.toFixed(3)}, aggregate=${aggregateIncrease.toFixed(3)}`] : shardReasons },
    extendToFive: [...new Set(extendToFive)].sort(),
  };
}
