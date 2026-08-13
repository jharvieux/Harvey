import { createHash } from "node:crypto";
import { parseCorpusCacheTransportKey } from "./corpus-cache-transport.js";
import type { CorpusExecutionDesign } from "./corpus-execution.js";

export type CorpusCacheProfile = "cold" | "warm";
export type CorpusRunnerRole = "pr" | "schedule";

export interface CorpusBenchmarkArtifactEvidence {
  name: string;
  family: string;
  sha256: string;
}

export interface CorpusBenchmarkPriorScorecardEvidence {
  schema: 1;
  sourceRunId: number;
  sourceRunAttempt: number;
  sourceHeadSha: string;
  sourceEvent: "workflow_dispatch";
  sourceWorkflowPath: ".github/workflows/corpus-drift.yml";
  artifactId: number;
  artifactName: "corpus-drift-scorecard";
  artifactDigest: string;
  scorecardSha256: string;
  scorecardBytes: number;
}

export interface CorpusBenchmarkTransportEvidence {
  role: "source" | "output";
  key: string;
  family: "benchmark";
  event: string;
  ref: string;
  platform: string;
  namespace: string;
  runId: string;
  runAttempt: string;
  headSha: string;
  benchmarkSeed: string;
  seedDigest: string;
  payloadBytes: number;
}

export interface CorpusBenchmarkCacheProvenance {
  schema: 1;
  invariant: {
    benchmarkSeed: string;
    headSha: string;
    ref: string;
    platform: string;
    targetDigest: string;
    evidenceDigest: string;
    dependencyInputDigest: string;
    cacheInputDigest: string;
    toolInputDigest: string;
    sourceNamespaces: string[];
    sourceContentDigest: string;
    sourceTransports: Array<Omit<CorpusBenchmarkTransportEvidence, "role" | "key" | "runId" | "runAttempt">>;
  };
  shape: {
    outputNamespaces: string[];
    artifactFamilies: Array<{ family: string; count: number }>;
  };
  transports: {
    sources: CorpusBenchmarkTransportEvidence[];
    outputs: CorpusBenchmarkTransportEvidence[];
  };
  sourceFiles: Array<{ path: string; sha256: string; bytes: number; sourceNamespaces: string[] }>;
  receiptDigests: string[];
  integrityDigest: string;
}

export interface CorpusBenchmarkSample {
  schema: 1;
  runId: number;
  runAttempt: number;
  workflow: "corpus-drift.yml";
  headSha: string;
  benchmarkSeed: string;
  benchmarkSeedRunId: number;
  benchmarkSeedRunAttempt: number;
  repeat: number;
  runnerRole: CorpusRunnerRole;
  requestedRunner: string;
  actualRunner: {
    jobs: Array<{ id: number; name: string }>;
    nameClass: string;
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
    provenance: CorpusBenchmarkCacheProvenance;
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
    conservationDigest: string;
    dependencyInputDigest: string;
    cacheInputDigest: string;
    toolInputDigest: string;
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
    artifacts: CorpusBenchmarkArtifactEvidence[];
    conservationVectors: Array<Record<string, unknown>>;
    invariantVectors: Array<{
      slug: string;
      evidence: unknown;
      dependencyInputs: unknown;
      cacheInputs: unknown;
      toolInputs: unknown;
    }>;
    priorScorecard: CorpusBenchmarkPriorScorecardEvidence;
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

interface MetricSummary {
  median: number;
  p95: number;
  total: number;
  max: number;
}

interface CorpusBenchmarkCohortReport {
  id: string;
  label: string;
  identity: ReturnType<typeof cohortIdentity>;
  repeats: number[];
  sampleDigests: string[];
  metrics: {
    criticalPathMs: MetricSummary;
    aggregateRunnerMs: MetricSummary;
    aggregateCpuSeconds: MetricSummary;
    peakRssBytes: MetricSummary;
    billedMinutes: MetricSummary;
    estimatedCostUsd: MetricSummary;
    cache: Record<"hits" | "misses" | "recomputed" | "rejected" | "strandedArtifacts", MetricSummary>;
  };
  samples: Array<{ digest: string; sample: CorpusBenchmarkSample }>;
}

interface CorpusBenchmarkDecision {
  schema: 1;
  thresholdVersion: string;
  thresholdDigest: string;
  provenance: { headSha: string; benchmarkSeed: string; benchmarkSeedRunId: number; benchmarkSeedRunAttempt: number; priorScorecard: CorpusBenchmarkPriorScorecardEvidence; targetDigest: string; evidenceDigest: string; sampleRunIds: number[]; sampleDigest: string };
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
  evidence: { sampleDigest: string; cohorts: CorpusBenchmarkCohortReport[] };
  next: CorpusBenchmarkNextRuns;
}

export interface CorpusBenchmarkPilotDecision {
  schema: 1;
  stage: "pilot";
  thresholdVersion: string;
  thresholdDigest: string;
  provenance: { headSha: string; benchmarkSeed: string; benchmarkSeedRunId: number; benchmarkSeedRunAttempt: number; priorScorecard: CorpusBenchmarkPriorScorecardEvidence; targetDigest: string; evidenceDigest: string; sampleRunIds: number[]; sampleDigest: string };
  concurrency: CorpusBenchmarkDecision["concurrency"];
  extendToFive: string[];
  evidence: CorpusBenchmarkDecision["evidence"];
  next: CorpusBenchmarkNextRuns & { design: CorpusExecutionDesign; concurrency: number; requiredProfiles: ["cold", "warm"] };
}

interface CorpusBenchmarkNextRuns {
  stage: "extend-standard" | "four-shard" | "complete";
  requiredShardCounts: Array<3 | 4>;
  repeats: number[];
  requiredRuns: CorpusBenchmarkRequiredRun[];
  rerunPilotAfter: boolean;
}

interface CorpusBenchmarkRequiredRun {
  cohort: string;
  design: CorpusExecutionDesign;
  concurrency: number;
  shardCount: 3 | 4;
  profile: CorpusCacheProfile;
  repeat: number;
}

function corpusBenchmarkRequiredRuns(cohortIds: readonly string[], repeats: readonly number[]): CorpusBenchmarkRequiredRun[] {
  const parse = (cohort: string): Omit<CorpusBenchmarkRequiredRun, "cohort" | "repeat"> => {
    const standard = /^(serial|target-workers|intra-target-overlap):(\d+):(cold|warm)$/.exec(cohort);
    if (standard) return { design: standard[1] as CorpusExecutionDesign, concurrency: Number(standard[2]), shardCount: 3, profile: standard[3] as CorpusCacheProfile };
    const selected = /^selected:(serial|target-workers|intra-target-overlap):(\d+):shards-(4):(cold|warm)$/.exec(cohort);
    if (selected) return { design: selected[1] as CorpusExecutionDesign, concurrency: Number(selected[2]), shardCount: 4, profile: selected[4] as CorpusCacheProfile };
    throw new Error(`benchmark extension cohort id is not dispatchable: ${cohort}`);
  };
  return [...new Set(cohortIds)].sort().flatMap((cohort) => repeats.map((repeat) => ({ cohort, ...parse(cohort), repeat })));
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function digest(value: unknown): string {
  return createHash("sha256").update(stable(value)).digest("hex");
}

export function corpusBenchmarkProvenanceIntegrity(input: {
  provenance: Omit<CorpusBenchmarkCacheProvenance, "integrityDigest">;
  transportKeys: readonly string[];
  provenanceDigests: readonly string[];
  artifacts: readonly CorpusBenchmarkArtifactEvidence[];
}): string {
  return digest({
    provenance: input.provenance,
    transportKeys: [...input.transportKeys].sort(),
    provenanceDigests: [...input.provenanceDigests].sort(),
    artifacts: [...input.artifacts].sort((left, right) => left.name.localeCompare(right.name)),
  });
}

export function corpusRunnerNameClass(name: string, group: string): string {
  return group === "GitHub Actions" && /^GitHub Actions \d+$/.test(name)
    ? "GitHub Actions <hosted-id>"
    : name;
}

export function corpusBenchmarkThresholdDigest(): string {
  return digest(CORPUS_BENCHMARK_THRESHOLDS);
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

function invariantPopulation(sample: CorpusBenchmarkSample): Omit<CorpusBenchmarkSample["population"], "conservationDigest"> {
  return {
    targetDigest: sample.population.targetDigest,
    targets: sample.population.targets,
    rowDigest: sample.population.rowDigest,
    findingDigest: sample.population.findingDigest,
    disclosureDigest: sample.population.disclosureDigest,
    baselineDigest: sample.population.baselineDigest,
    examinedDigest: sample.population.examinedDigest,
    evidenceDigest: sample.population.evidenceDigest,
    dependencyInputDigest: sample.population.dependencyInputDigest,
    cacheInputDigest: sample.population.cacheInputDigest,
    toolInputDigest: sample.population.toolInputDigest,
  };
}

function invariantSourceTransport(transport: CorpusBenchmarkTransportEvidence): CorpusBenchmarkCacheProvenance["invariant"]["sourceTransports"][number] {
  return {
    family: transport.family,
    event: transport.event,
    ref: transport.ref,
    platform: transport.platform,
    namespace: transport.namespace,
    headSha: transport.headSha,
    benchmarkSeed: transport.benchmarkSeed,
    seedDigest: transport.seedDigest,
    payloadBytes: transport.payloadBytes,
  };
}

function outputTransportShape(transport: CorpusBenchmarkTransportEvidence): Omit<CorpusBenchmarkTransportEvidence, "key" | "runId" | "runAttempt" | "payloadBytes"> {
  return {
    role: transport.role,
    family: transport.family,
    event: transport.event,
    ref: transport.ref,
    platform: transport.platform,
    namespace: transport.namespace,
    headSha: transport.headSha,
    benchmarkSeed: transport.benchmarkSeed,
    seedDigest: transport.seedDigest,
  };
}

function outputTransportScope(sample: CorpusBenchmarkSample): unknown[] {
  return [...new Map(sample.cache.provenance.transports.outputs.map((transport) => {
    const shape = outputTransportShape(transport);
    const scope = {
      role: shape.role,
      family: shape.family,
      event: shape.event,
      ref: shape.ref,
      platform: shape.platform,
      headSha: shape.headSha,
      benchmarkSeed: shape.benchmarkSeed,
      seedDigest: shape.seedDigest,
    };
    return [stable(scope), scope] as const;
  })).values()].sort((left, right) => stable(left).localeCompare(stable(right)));
}

function cohortIdentity(sample: CorpusBenchmarkSample) {
  const actualRunner = {
    nameClass: sample.actualRunner.nameClass,
    group: sample.actualRunner.group,
    labels: sample.actualRunner.labels,
    image: sample.actualRunner.image,
    cpuLimit: sample.actualRunner.cpuLimit,
    memoryLimitBytes: sample.actualRunner.memoryLimitBytes,
  };
  return {
    headSha: sample.headSha,
    benchmarkSeed: sample.benchmarkSeed,
    runnerRole: sample.runnerRole,
    requestedRunner: sample.requestedRunner,
    actualRunner,
    profile: sample.profile,
    design: sample.design,
    concurrency: sample.concurrency,
    effectiveConcurrency: sample.effectiveConcurrency,
    shardCount: sample.shardCount,
    population: invariantPopulation(sample),
    cacheProvenance: {
      invariant: sample.cache.provenance.invariant,
      shape: sample.cache.provenance.shape,
      outputs: sample.cache.provenance.transports.outputs.map(outputTransportShape).sort((left, right) => stable(left).localeCompare(stable(right))),
    },
    priorScorecard: sample.raw.priorScorecard,
    toolVersions: sample.raw.toolVersions,
    targetCommits: sample.raw.targetCommits,
  };
}

function assertCohortRows(rows: readonly CorpusBenchmarkSample[], label: string): CorpusBenchmarkSample[] {
  const repeats = new Set(rows.map((sample) => sample.repeat));
  const runs = new Set(rows.map((sample) => `${sample.runId}/${sample.runAttempt}`));
  if (rows.length < 3 || repeats.size < 3) throw new Error(`${label}: requires at least three distinct real repeats; got ${rows.length} sample(s), ${repeats.size} repeat(s)`);
  if (rows.length !== repeats.size) throw new Error(`${label}: repeats are duplicated; got ${rows.length} sample(s), ${repeats.size} repeat id(s)`);
  if (rows.length !== runs.size) throw new Error(`${label}: one hosted run was counted more than once`);
  const identities = new Set(rows.map((sample) => stable(cohortIdentity(sample))));
  if (identities.size !== 1) throw new Error(`${label}: cohort mixes actual runner, prior-scorecard, tool/runtime, target/evidence, role, profile, design, concurrency, shard, or requested-runner identities`);
  return [...rows].sort((left, right) => left.repeat - right.repeat);
}

function cohort(samples: readonly CorpusBenchmarkSample[], predicate: (sample: CorpusBenchmarkSample) => boolean, label: string): CorpusBenchmarkSample[] {
  return assertCohortRows(samples.filter(predicate), label);
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function directDigest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalArtifactFamily(name: string): string {
  return name.replace(/(?:-\d+)?\.json$/, "");
}

function assertSampleEnvelope(sample: CorpusBenchmarkSample): void {
  const label = `run ${sample.runId}`;
  const populationTargets = [...sample.population.targets].sort();
  if (stable(sample.population.targets) !== stable(populationTargets)) throw new Error(`${label}: target population is not canonically ordered`);

  const targetCommitEntries = Object.entries(sample.raw.targetCommits).sort(([left], [right]) => left.localeCompare(right));
  if (stable(targetCommitEntries.map(([slug]) => slug)) !== stable(populationTargets)
    || targetCommitEntries.some(([, commit]) => !/^[0-9a-f]{40}$/.test(commit))) {
    throw new Error(`${label}: raw target commit rows are missing, foreign, or invalid`);
  }
  if (sample.population.targetDigest !== digest(targetCommitEntries)) throw new Error(`${label}: target digest differs from the complete pinned target population`);

  const conservationVectors = sample.raw.conservationVectors;
  const conservationTargets = conservationVectors.map((row) => String(row.slug)).sort();
  if (conservationVectors.length !== populationTargets.length
    || new Set(conservationTargets).size !== populationTargets.length
    || stable(conservationTargets) !== stable(populationTargets)) {
    throw new Error(`${label}: canonical conservation-vector target population is missing, duplicated, or foreign`);
  }
  for (const vector of conservationVectors) {
    for (const field of ["checks", "findings", "disclosures", "baselines", "examinedUnits"] as const) {
      if (!Number.isSafeInteger(vector[field]) || Number(vector[field]) < 0) throw new Error(`${label}: ${String(vector.slug)} conservation ${field} is invalid`);
    }
    if (!/^[0-9a-f]{64}$/.test(String(vector.digest))) throw new Error(`${label}: ${String(vector.slug)} canonical conservation envelope digest is invalid`);
  }
  if (sample.population.conservationDigest !== digest(conservationVectors)) throw new Error(`${label}: conservation digest differs from the complete canonical envelope population`);
  if (sample.population.examinedDigest !== digest(conservationVectors.map((row) => ({ slug: row.slug, examinedUnits: row.examinedUnits })))) {
    throw new Error(`${label}: examined-scope digest differs from the canonical conservation population`);
  }

  const invariantVectors = sample.raw.invariantVectors;
  const invariantTargets = invariantVectors.map((row) => String(row.slug)).sort();
  if (invariantVectors.length !== populationTargets.length
    || new Set(invariantTargets).size !== populationTargets.length
    || stable(invariantTargets) !== stable(populationTargets)) {
    throw new Error(`${label}: invariant evidence-vector target population is missing, duplicated, or foreign`);
  }
  const expectedInvariantDigests = {
    evidenceDigest: digest(invariantVectors.map(({ slug, evidence }) => ({ slug, evidence }))),
    dependencyInputDigest: digest(invariantVectors.map(({ slug, dependencyInputs }) => ({ slug, dependencyInputs }))),
    cacheInputDigest: digest(invariantVectors.map(({ slug, cacheInputs }) => ({ slug, cacheInputs }))),
    toolInputDigest: digest(invariantVectors.map(({ slug, toolInputs }) => ({ slug, toolInputs }))),
  };
  for (const [field, expected] of Object.entries(expectedInvariantDigests)) {
    if (sample.population[field as keyof typeof expectedInvariantDigests] !== expected) throw new Error(`${label}: ${field} differs from its complete raw invariant evidence population`);
  }
  for (const vector of invariantVectors) {
    const evidenceRuntime = (vector.evidence as { runtime?: unknown } | undefined)?.runtime;
    const toolRuntime = (vector.toolInputs as { runtime?: unknown } | undefined)?.runtime;
    if (stable(evidenceRuntime) !== stable(sample.raw.toolVersions) || stable(toolRuntime) !== stable(sample.raw.toolVersions)) {
      throw new Error(`${label}: ${vector.slug} raw runtime/tool identity differs from the benchmark tool receipt`);
    }
  }

  const artifacts = sample.raw.artifacts;
  if (artifacts.length === 0 || new Set(artifacts.map((artifact) => artifact.name)).size !== artifacts.length) throw new Error(`${label}: named artifact population is empty or duplicated`);
  if (stable(artifacts.map((artifact) => artifact.name)) !== stable(artifacts.map((artifact) => artifact.name).sort())) throw new Error(`${label}: named artifact population is not canonically ordered`);
  if (artifacts.some((artifact) => !artifact.name || artifact.family !== canonicalArtifactFamily(artifact.name) || !/^[0-9a-f]{64}$/.test(artifact.sha256))) {
    throw new Error(`${label}: named artifact identity or digest is invalid`);
  }
  if (!artifacts.some((artifact) => artifact.name === "scorecard/corpus-drift.json") || !artifacts.some((artifact) => artifact.name === "actions/jobs.json")) {
    throw new Error(`${label}: scorecard or Actions jobs artifact identity is missing`);
  }
  if (artifacts.filter((artifact) => artifact.family === "evidence/benchmark-prior-scorecard").length !== sample.shardCount) {
    throw new Error(`${label}: retained prior scorecard receipt artifact population is incomplete`);
  }
  const artifactDigests = sortedUnique(artifacts.map((artifact) => artifact.sha256));
  if (stable(sample.raw.artifactDigests) !== stable(artifactDigests)) throw new Error(`${label}: raw artifact digests differ from the named artifact population`);
  const artifactFamilyCounts = [...artifacts.reduce((counts, artifact) => counts.set(artifact.family, (counts.get(artifact.family) ?? 0) + 1), new Map<string, number>())]
    .map(([family, count]) => ({ family, count }))
    .sort((left, right) => left.family.localeCompare(right.family));

  const provenance = sample.cache.provenance;
  if (provenance.schema !== 1) throw new Error(`${label}: unsupported cache provenance schema`);
  const invariant = provenance.invariant;
  if (invariant.benchmarkSeed !== sample.benchmarkSeed || invariant.headSha !== sample.headSha || !invariant.ref || !invariant.platform) {
    throw new Error(`${label}: invariant cache seed/head/ref/platform identity differs from the sample`);
  }
  for (const field of ["targetDigest", "evidenceDigest", "dependencyInputDigest", "cacheInputDigest", "toolInputDigest"] as const) {
    if (invariant[field] !== sample.population[field]) throw new Error(`${label}: cache provenance ${field} differs from the verified population`);
  }
  if (stable(provenance.shape.artifactFamilies) !== stable(artifactFamilyCounts)) throw new Error(`${label}: artifact family census differs from the named artifact population`);

  const sources = provenance.transports.sources;
  const outputs = provenance.transports.outputs;
  if (sources.length === 0 || outputs.length !== sample.shardCount) throw new Error(`${label}: source/output transport population is incomplete`);
  if (sources.some((source) => source.runId !== String(sample.benchmarkSeedRunId))) throw new Error(`${label}: source transport belongs to sample run rather than immutable seed run ${sample.benchmarkSeedRunId}`);
  if (sources.some((source) => source.runAttempt !== String(sample.benchmarkSeedRunAttempt))) throw new Error(`${label}: source transport belongs to another seed-run attempt rather than immutable seed attempt ${sample.benchmarkSeedRunAttempt}`);
  const allTransports = [...sources, ...outputs];
  if (new Set(allTransports.map((transport) => transport.key)).size !== allTransports.length) throw new Error(`${label}: transport keys are duplicated across source/output roles`);
  const expectedSeedDigest = directDigest(sample.benchmarkSeed).slice(0, 16);
  for (const transport of allTransports) {
    const parsed = parseCorpusCacheTransportKey(transport.key);
    if (!parsed || parsed.family !== "benchmark" || parsed.seedDigest !== expectedSeedDigest
      || parsed.platform !== transport.platform || parsed.namespace !== transport.namespace
      || parsed.runId !== transport.runId || parsed.runAttempt !== transport.runAttempt || parsed.headSha !== transport.headSha
      || transport.family !== "benchmark" || transport.seedDigest !== parsed.seedDigest
      || transport.headSha !== sample.headSha || transport.benchmarkSeed !== sample.benchmarkSeed
      || transport.ref !== invariant.ref || transport.platform !== invariant.platform
      || !transport.event || !Number.isSafeInteger(transport.payloadBytes) || transport.payloadBytes < 0) {
      throw new Error(`${label}: ${transport.role} transport key/receipt identity is malformed or disagrees with the benchmark`);
    }
    if ((transport.role === "source") !== sources.includes(transport) || (transport.role === "output") !== outputs.includes(transport)) {
      throw new Error(`${label}: transport role disagrees with its structured source/output population`);
    }
    if (transport.role === "output" && (transport.runId !== String(sample.runId) || transport.runAttempt !== String(sample.runAttempt))) {
      throw new Error(`${label}: output transport belongs to another workflow run/attempt`);
    }
  }
  const sourceNamespaces = sources.map((transport) => transport.namespace).sort();
  const outputNamespaces = outputs.map((transport) => transport.namespace).sort();
  if (new Set(sources.map((transport) => transport.event)).size !== 1
    || new Set(sources.map((transport) => `${transport.runId}/${transport.runAttempt}`)).size !== 1
    || new Set(outputs.map((transport) => transport.event)).size !== 1) {
    throw new Error(`${label}: source/output transport population mixes event or source-run identities`);
  }
  if (stable(sourceNamespaces) !== stable(sortedUnique(invariant.sourceNamespaces)) || sourceNamespaces.length !== invariant.sourceNamespaces.length) {
    throw new Error(`${label}: source transport namespace population differs from invariant provenance`);
  }
  if (stable(outputNamespaces) !== stable(sortedUnique(provenance.shape.outputNamespaces)) || outputNamespaces.length !== provenance.shape.outputNamespaces.length) {
    throw new Error(`${label}: output transport namespace population differs from its benchmark shape`);
  }
  const normalizedSources = sources.map(invariantSourceTransport).sort((left, right) => stable(left).localeCompare(stable(right)));
  const storedSources = [...invariant.sourceTransports].sort((left, right) => stable(left).localeCompare(stable(right)));
  if (stable(normalizedSources) !== stable(storedSources)) throw new Error(`${label}: invariant source transport identity differs from its full structured receipts`);

  if (provenance.sourceFiles.length === 0 || new Set(provenance.sourceFiles.map((file) => file.path)).size !== provenance.sourceFiles.length) {
    throw new Error(`${label}: exact seed source-file population is empty or duplicated`);
  }
  for (const file of provenance.sourceFiles) {
    if (!file.path || !/^[0-9a-f]{64}$/.test(file.sha256) || !Number.isSafeInteger(file.bytes) || file.bytes < 0
      || file.sourceNamespaces.length === 0 || stable(file.sourceNamespaces) !== stable(sortedUnique(file.sourceNamespaces))
      || file.sourceNamespaces.some((namespace) => !invariant.sourceNamespaces.includes(namespace))) {
      throw new Error(`${label}: exact seed source-file provenance is malformed or foreign`);
    }
  }
  if (invariant.sourceContentDigest !== directDigest(JSON.stringify(provenance.sourceFiles))) throw new Error(`${label}: exact seed source-content digest differs from its file population`);

  const expectedTransportKeys = sortedUnique(allTransports.map((transport) => transport.key));
  if (stable(sample.cache.transportKeys) !== stable(expectedTransportKeys)) throw new Error(`${label}: raw transport keys differ from the structured source/output receipts`);
  const mergeArtifactDigests = artifacts.filter((artifact) => artifact.family === "evidence/benchmark-cache-merge-receipt").map((artifact) => artifact.sha256).sort();
  const transportArtifactDigests = artifacts.filter((artifact) => artifact.family === "evidence/benchmark-transport").map((artifact) => artifact.sha256).sort();
  if (mergeArtifactDigests.length !== sample.shardCount || transportArtifactDigests.length !== sample.shardCount) throw new Error(`${label}: cache merge/output transport receipt artifact population is incomplete`);
  if (stable(provenance.receiptDigests) !== stable([...mergeArtifactDigests, ...transportArtifactDigests].sort())) throw new Error(`${label}: receipt digests differ from the named transport artifacts`);
  if (stable(sample.cache.provenanceDigests) !== stable(sortedUnique([invariant.sourceContentDigest, ...transportArtifactDigests]))) {
    throw new Error(`${label}: cache provenance digests differ from the exact seed/output receipt identities`);
  }
  const { integrityDigest, ...withoutIntegrity } = provenance;
  const expectedIntegrity = corpusBenchmarkProvenanceIntegrity({
    provenance: withoutIntegrity,
    transportKeys: sample.cache.transportKeys,
    provenanceDigests: sample.cache.provenanceDigests,
    artifacts,
  });
  if (integrityDigest !== expectedIntegrity) throw new Error(`${label}: cache/transport/artifact provenance integrity digest differs from its complete envelope`);
}

function assertSample(sample: CorpusBenchmarkSample): void {
  if (sample.schema !== 1 || sample.workflow !== "corpus-drift.yml") throw new Error(`run ${sample.runId}: unsupported benchmark sample`);
  if (!/^[0-9a-f]{40}$/.test(sample.headSha)) throw new Error(`run ${sample.runId}: headSha is invalid`);
  if (!Number.isInteger(sample.repeat) || sample.repeat < 1) throw new Error(`run ${sample.runId}: repeat is invalid`);
  if (!Number.isInteger(sample.benchmarkSeedRunId) || sample.benchmarkSeedRunId < 1 || sample.benchmarkSeedRunId === sample.runId) throw new Error(`run ${sample.runId}: immutable benchmark seed-run identity is missing or aliases the sample run`);
  if (!Number.isInteger(sample.benchmarkSeedRunAttempt) || sample.benchmarkSeedRunAttempt < 1) throw new Error(`run ${sample.runId}: immutable benchmark seed-run attempt is missing`);
  if (!Number.isInteger(sample.concurrency) || sample.concurrency < 1 || sample.concurrency > 3) throw new Error(`run ${sample.runId}: concurrency is invalid`);
  if (![3, 4].includes(sample.shardCount)) throw new Error(`run ${sample.runId}: shard count is invalid`);
  if (sample.effectiveConcurrency < 1 || sample.effectiveConcurrency > sample.concurrency) throw new Error(`run ${sample.runId}: effective concurrency is invalid`);
  if (sample.design === "serial" && sample.effectiveConcurrency !== 1) throw new Error(`run ${sample.runId}: serial design claims concurrent execution`);
  if (sample.design === "target-workers" && sample.effectiveConcurrency !== sample.concurrency) throw new Error(`run ${sample.runId}: target-worker sample was resource-admitted below its requested concurrency`);
  if (sample.design === "intra-target-overlap" && sample.effectiveConcurrency !== 2) throw new Error(`run ${sample.runId}: intra-target-overlap sample did not admit both scanner lanes`);
  if (sample.criticalPathMs <= 0 || sample.aggregateRunnerMs <= 0 || sample.billedMinutes <= 0) throw new Error(`run ${sample.runId}: timing/cost receipt is incomplete`);
  if (!Number.isFinite(sample.estimatedCostUsd) || sample.estimatedCostUsd < 0) throw new Error(`run ${sample.runId}: dollar-cost receipt is invalid`);
  if (sample.criticalPathMs > sample.aggregateRunnerMs) throw new Error(`run ${sample.runId}: critical path exceeds summed runner time`);
  if (sample.peakRssBytes <= 0 || sample.actualRunner.memoryLimitBytes <= 0 || sample.actualRunner.cpuLimit <= 0) throw new Error(`run ${sample.runId}: CPU/RSS receipt is incomplete`);
  if (!sample.actualRunner.group || !sample.actualRunner.image || !sample.actualRunner.nameClass || sample.actualRunner.labels.length === 0) throw new Error(`run ${sample.runId}: actual runner identity is incomplete`);
  if (sample.actualRunner.jobs.length !== sample.shardCount
    || new Set(sample.actualRunner.jobs.map((job) => job.id)).size !== sample.shardCount
    || sample.actualRunner.jobs.some((job) => !Number.isInteger(job.id) || job.id <= 0 || !job.name)) {
    throw new Error(`run ${sample.runId}: actual runner job rows are incomplete or duplicated`);
  }
  const nameClasses = new Set(sample.actualRunner.jobs.map((job) => corpusRunnerNameClass(job.name, sample.actualRunner.group)));
  if (nameClasses.size !== 1 || !nameClasses.has(sample.actualRunner.nameClass)) throw new Error(`run ${sample.runId}: actual runner name class disagrees with raw hosted runner names`);
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
  if (stable([...sample.raw.jobIds].sort((a, b) => a - b)) !== stable(sample.actualRunner.jobs.map((job) => job.id).sort((a, b) => a - b))) throw new Error(`run ${sample.runId}: raw shard jobs disagree with actual runner jobs`);
  if (sample.cache.transportKeys.length === 0 || sample.cache.provenanceDigests.length === 0 || sample.raw.artifactDigests.length === 0) throw new Error(`run ${sample.runId}: cache/artifact provenance is incomplete`);
  if (![...sample.cache.provenanceDigests, ...sample.raw.artifactDigests].every((value) => /^[0-9a-f]{64}$/.test(value))) throw new Error(`run ${sample.runId}: cache/artifact digest is invalid`);
  if (!sample.raw.workflowUrl || Object.keys(sample.raw.toolVersions).length === 0 || Object.values(sample.raw.toolVersions).some((value) => !value)) throw new Error(`run ${sample.runId}: raw workflow/tool provenance is incomplete`);
  const prior = sample.raw.priorScorecard;
  if (!prior || prior.schema !== 1
    || prior.sourceRunId !== sample.benchmarkSeedRunId
    || prior.sourceRunAttempt !== sample.benchmarkSeedRunAttempt
    || prior.sourceHeadSha !== sample.headSha
    || prior.sourceEvent !== "workflow_dispatch"
    || prior.sourceWorkflowPath !== ".github/workflows/corpus-drift.yml"
    || !Number.isSafeInteger(prior.artifactId) || prior.artifactId < 1
    || prior.artifactName !== "corpus-drift-scorecard"
    || !/^sha256:[a-f0-9]{64}$/.test(prior.artifactDigest)
    || !/^[a-f0-9]{64}$/.test(prior.scorecardSha256)
    || !Number.isSafeInteger(prior.scorecardBytes) || prior.scorecardBytes < 1) {
    throw new Error(`run ${sample.runId}: prior scorecard identity/content is missing or differs from the immutable seed run`);
  }
  assertSampleEnvelope(sample);
  for (const value of [sample.aggregateCpuSeconds, sample.setupNetworkMs, sample.dependencyMs, sample.targetProcessCpuMs, sample.estimatedCostUsd]) {
    if (!Number.isFinite(value) || value < 0) throw new Error(`run ${sample.runId}: raw resource/cost metrics are incomplete`);
  }
  for (const name of ["hits", "misses", "recomputed", "rejected", "strandedArtifacts"] as const) {
    const value = sample.cache[name];
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`run ${sample.runId}: cache ${name} metric is invalid`);
  }
}

function comparableEvidence(sample: CorpusBenchmarkSample): unknown {
  return {
    headSha: sample.headSha,
    benchmarkSeed: sample.benchmarkSeed,
    benchmarkSeedRunId: sample.benchmarkSeedRunId,
    benchmarkSeedRunAttempt: sample.benchmarkSeedRunAttempt,
    population: invariantPopulation(sample),
    cacheProvenance: sample.cache.provenance.invariant,
    outputTransportScope: outputTransportScope(sample),
    priorScorecard: sample.raw.priorScorecard,
    toolVersions: sample.raw.toolVersions,
    targetCommits: sample.raw.targetCommits,
    assertions: sample.assertions,
  };
}

function assertMatchedPopulation(samples: readonly CorpusBenchmarkSample[]): { headSha: string; benchmarkSeed: string; benchmarkSeedRunId: number; benchmarkSeedRunAttempt: number; priorScorecard: CorpusBenchmarkPriorScorecardEvidence; targetDigest: string; evidenceDigest: string } {
  if (samples.length === 0) throw new Error("benchmark has no raw sample rows");
  const evidence = new Set(samples.map((sample) => stable(comparableEvidence(sample))));
  if (evidence.size !== 1) throw new Error("benchmark mixes head, seed, prior-scorecard, target/evidence, tool/runtime, target-commit, or assertion identities");
  const first = samples[0]!;
  return {
    headSha: first.headSha,
    benchmarkSeed: first.benchmarkSeed,
    benchmarkSeedRunId: first.benchmarkSeedRunId,
    benchmarkSeedRunAttempt: first.benchmarkSeedRunAttempt,
    priorScorecard: first.raw.priorScorecard,
    targetDigest: first.population.targetDigest,
    evidenceDigest: first.population.evidenceDigest,
  };
}

function allAssertionsEqual(left: CorpusBenchmarkSample, right: CorpusBenchmarkSample): boolean {
  return stable(comparableEvidence(left)) === stable(comparableEvidence(right));
}

function sameRunnerEnvironment(left: CorpusBenchmarkSample, right: CorpusBenchmarkSample): boolean {
  const comparable = (sample: CorpusBenchmarkSample): unknown => ({
    runnerRole: sample.runnerRole,
    requestedRunner: sample.requestedRunner,
    nameClass: sample.actualRunner.nameClass,
    group: sample.actualRunner.group,
    labels: sample.actualRunner.labels,
    image: sample.actualRunner.image,
    cpuLimit: sample.actualRunner.cpuLimit,
    memoryLimitBytes: sample.actualRunner.memoryLimitBytes,
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

const REQUIRED_STANDARD_SHAPES: ReadonlyArray<{ design: Exclude<CorpusExecutionDesign, "split-carbon">; concurrency: number }> = [
  { design: "serial", concurrency: 1 },
  { design: "target-workers", concurrency: 1 },
  { design: "target-workers", concurrency: 2 },
  { design: "target-workers", concurrency: 3 },
  { design: "intra-target-overlap", concurrency: 2 },
];

function metricSummary(values: readonly number[]): MetricSummary {
  return {
    median: median(values),
    p95: nearestRankP95(values),
    total: values.reduce((sum, value) => sum + value, 0),
    max: Math.max(...values),
  };
}

function describeCohort(identity: ReturnType<typeof cohortIdentity>): string {
  return `${identity.runnerRole}/${identity.requestedRunner}/${identity.actualRunner.nameClass}/${identity.profile}/${identity.design}-${identity.concurrency}/shards-${identity.shardCount}`;
}

function buildCohortReports(samples: readonly CorpusBenchmarkSample[]): CorpusBenchmarkCohortReport[] {
  const groups = new Map<string, CorpusBenchmarkSample[]>();
  for (const sample of samples) {
    const key = stable(cohortIdentity(sample));
    const rows = groups.get(key) ?? [];
    rows.push(sample);
    groups.set(key, rows);
  }
  return [...groups.entries()].map(([identityText, unsorted]) => {
    const identity = cohortIdentity(unsorted[0]!);
    const label = describeCohort(identity);
    const rows = assertCohortRows(unsorted, label);
    const sampleRows = rows.map((sample) => ({ digest: digest(sample), sample }));
    const cacheMetric = (field: "hits" | "misses" | "recomputed" | "rejected" | "strandedArtifacts"): MetricSummary => metricSummary(rows.map((sample) => sample.cache[field]));
    return {
      id: digest(identityText),
      label,
      identity,
      repeats: rows.map((sample) => sample.repeat),
      sampleDigests: sampleRows.map((row) => row.digest),
      metrics: {
        criticalPathMs: metricSummary(rows.map((sample) => sample.criticalPathMs)),
        aggregateRunnerMs: metricSummary(rows.map((sample) => sample.aggregateRunnerMs)),
        aggregateCpuSeconds: metricSummary(rows.map((sample) => sample.aggregateCpuSeconds)),
        peakRssBytes: metricSummary(rows.map((sample) => sample.peakRssBytes)),
        billedMinutes: metricSummary(rows.map((sample) => sample.billedMinutes)),
        estimatedCostUsd: metricSummary(rows.map((sample) => sample.estimatedCostUsd)),
        cache: {
          hits: cacheMetric("hits"),
          misses: cacheMetric("misses"),
          recomputed: cacheMetric("recomputed"),
          rejected: cacheMetric("rejected"),
          strandedArtifacts: cacheMetric("strandedArtifacts"),
        },
      },
      samples: sampleRows,
    };
  }).sort((left, right) => left.label.localeCompare(right.label));
}

function assertRepeatPair(left: readonly CorpusBenchmarkSample[], right: readonly CorpusBenchmarkSample[], label: string): void {
  if (stable(left.map((sample) => sample.repeat)) !== stable(right.map((sample) => sample.repeat))) {
    throw new Error(`${label}: compared cohorts do not carry the same repeat population`);
  }
}

type StandardCohorts = Map<string, { cold: CorpusBenchmarkSample[]; warm: CorpusBenchmarkSample[] }>;

function collectStandardCohorts(samples: readonly CorpusBenchmarkSample[], isStandardPr: (sample: CorpusBenchmarkSample) => boolean): StandardCohorts {
  const standard: StandardCohorts = new Map();
  for (const shape of REQUIRED_STANDARD_SHAPES) {
    const name = `${shape.design}:${shape.concurrency}`;
    standard.set(name, {
      cold: cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "cold" && sample.design === shape.design && sample.concurrency === shape.concurrency && sample.shardCount === 3, `${name} cold`),
      warm: cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "warm" && sample.design === shape.design && sample.concurrency === shape.concurrency && sample.shardCount === 3, `${name} warm`),
    });
  }
  return standard;
}

function evaluateConcurrency(standard: StandardCohorts): {
  selected: { design: CorpusExecutionDesign; concurrency: number };
  eligible: string[];
  rejected: Array<{ shape: string; reasons: string[] }>;
  extendToFive: string[];
} {
  const baseline = standard.get("serial:1")!;
  assertRepeatPair(baseline.cold, baseline.warm, "serial cold/warm");
  const repeatPopulation = baseline.cold.map((sample) => sample.repeat);
  if (stable(repeatPopulation) !== stable([1, 2, 3]) && stable(repeatPopulation) !== stable([1, 2, 3, 4, 5])) {
    throw new Error(`standard pilot repeat population must be exactly 1-3 or 1-5; got ${repeatPopulation.join(",")}`);
  }
  const candidateShapes = REQUIRED_STANDARD_SHAPES.slice(1).map((shape) => `${shape.design}:${shape.concurrency}`);
  const eligible: string[] = [];
  const rejected: Array<{ shape: string; reasons: string[] }> = [{
    shape: "split-carbon",
    reasons: ["non-admissible negative control: no independently admitted workflow job/runner lane exists"],
  }];
  let extendAllStandardPairs = false;
  for (const candidate of candidateShapes) {
    const { cold, warm } = standard.get(candidate)!;
    const reasons: string[] = [];
    for (const profile of ["cold", "warm"] as const) {
      const rows = profile === "cold" ? cold : warm;
      if (!rows.every((sample) => baseline[profile].every((base) => allAssertionsEqual(sample, base)))) reasons.push(`${profile} population/evidence differs`);
      if (!rows.every((sample) => baseline[profile].every((base) => sameRunnerEnvironment(sample, base)))) reasons.push(`${profile} actual runner environment differs`);
      assertRepeatPair(baseline[profile], rows, `${candidate} ${profile}`);
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
      .some(([value, threshold]) => nearThreshold(value!, threshold!)) || highVariation([...cold, ...warm])) extendAllStandardPairs = true;
  }
  const measurements = eligible.map((candidate) => {
    const [design, rawConcurrency] = candidate.split(":") as [CorpusExecutionDesign, string];
    const rows = Object.values(standard.get(candidate)!).flat();
    return { candidate, design, concurrency: Number(rawConcurrency), median: median(rows.map((sample) => sample.criticalPathMs)) };
  });
  const fastest = measurements.length > 0 ? Math.min(...measurements.map((candidate) => candidate.median)) : undefined;
  const selected = fastest === undefined ? undefined : measurements
    .filter((candidate) => increase(candidate.median, fastest) <= CORPUS_BENCHMARK_THRESHOLDS.concurrency.preferSmallerWithin)
    .sort((left, right) => DESIGN_COMPLEXITY[left.design] - DESIGN_COMPLEXITY[right.design]
      || left.concurrency - right.concurrency
      || left.median - right.median)[0];
  return {
    selected: selected ? { design: selected.design, concurrency: selected.concurrency } : { design: "serial", concurrency: 1 },
    eligible,
    rejected,
    extendToFive: extendAllStandardPairs && repeatPopulation.length === 3
      ? REQUIRED_STANDARD_SHAPES.flatMap((shape) => [`${shape.design}:${shape.concurrency}:cold`, `${shape.design}:${shape.concurrency}:warm`])
      : [],
  };
}

function isRequiredStandardShape(sample: CorpusBenchmarkSample): boolean {
  return REQUIRED_STANDARD_SHAPES.some((shape) => sample.design === shape.design && sample.concurrency === shape.concurrency);
}

function pilotDecisionCore(decision: CorpusBenchmarkPilotDecision): Omit<CorpusBenchmarkPilotDecision, "next"> {
  const core: Partial<CorpusBenchmarkPilotDecision> = { ...decision };
  delete core.next;
  return core as Omit<CorpusBenchmarkPilotDecision, "next">;
}

function existingSelectedFourRepeats(
  samples: readonly CorpusBenchmarkSample[],
  isStandardPr: (sample: CorpusBenchmarkSample) => boolean,
  selection: { design: CorpusExecutionDesign; concurrency: number },
  standard: StandardCohorts,
): number[] {
  const rows = (profile: CorpusCacheProfile): CorpusBenchmarkSample[] => samples.filter((sample) => isStandardPr(sample)
    && sample.shardCount === 4
    && sample.profile === profile
    && sample.design === selection.design
    && sample.concurrency === selection.concurrency);
  const rawCold = rows("cold");
  const rawWarm = rows("warm");
  if (rawCold.length === 0 && rawWarm.length === 0) return [];
  const cold = assertCohortRows(rawCold, "existing selected four-shard cold");
  const warm = assertCohortRows(rawWarm, "existing selected four-shard warm");
  assertRepeatPair(cold, warm, "existing selected four-shard cold/warm");
  const selectedStandard = standard.get(`${selection.design}:${selection.concurrency}`)!;
  for (const profile of ["cold", "warm"] as const) {
    const four = profile === "cold" ? cold : warm;
    if (!four.every((sample) => selectedStandard[profile].every((base) => allAssertionsEqual(sample, base)))) {
      throw new Error(`existing selected four-shard ${profile}: population/evidence differs`);
    }
    if (!four.every((sample) => selectedStandard[profile].every((base) => sameRunnerEnvironment(sample, base)))) {
      throw new Error(`existing selected four-shard ${profile}: actual runner environment differs`);
    }
  }
  const available = cold.map((sample) => sample.repeat);
  const required = selectedStandard.cold.map((sample) => sample.repeat);
  if (available.some((repeat) => !required.includes(repeat)) || stable(available) !== stable(required.slice(0, available.length))) {
    throw new Error(`existing selected four-shard repeat population is partial or non-prefix: ${available.join(",")}`);
  }
  return available;
}

export function evaluateCorpusBenchmarkPilot(samples: readonly CorpusBenchmarkSample[]): CorpusBenchmarkPilotDecision {
  samples.forEach(assertSample);
  if (new Set(samples.map((sample) => `${sample.runId}/${sample.runAttempt}`)).size !== samples.length) {
    throw new Error("benchmark raw sample rows reuse a workflow run/attempt across cohorts");
  }
  assertMatchedPopulation(samples);
  const isStandardPr = (sample: CorpusBenchmarkSample): boolean => sample.runnerRole === "pr" && sample.requestedRunner === "ubuntu-latest";
  const standardThree = samples.filter((sample) => isStandardPr(sample) && sample.shardCount === 3);
  if (standardThree.some((sample) => !isRequiredStandardShape(sample))) {
    throw new Error("pilot standard PR three-shard rows contain an undeclared design/concurrency shape");
  }
  const provenance = assertMatchedPopulation(standardThree);
  const standard = collectStandardCohorts(standardThree, isStandardPr);
  const concurrency = evaluateConcurrency(standard);
  const cohorts = buildCohortReports(standardThree);
  const sampleDigest = digest(cohorts.flatMap((report) => report.sampleDigests).sort());
  const standardRepeats = standard.get("serial:1")!.cold.map((sample) => sample.repeat);
  const needsStandardExtension = concurrency.extendToFive.length > 0;
  const selectedFourCohorts = ["cold", "warm"].map((profile) => `selected:${concurrency.selected.design}:${concurrency.selected.concurrency}:shards-4:${profile}`);
  const existingFourRepeats = needsStandardExtension ? [] : existingSelectedFourRepeats(samples, isStandardPr, concurrency.selected, standard);
  const missingFourRepeats = standardRepeats.filter((repeat) => !existingFourRepeats.includes(repeat));
  const requiredRuns = needsStandardExtension
    ? corpusBenchmarkRequiredRuns(concurrency.extendToFive, [4, 5])
    : corpusBenchmarkRequiredRuns(selectedFourCohorts, missingFourRepeats);
  return {
    schema: 1,
    stage: "pilot",
    thresholdVersion: CORPUS_BENCHMARK_THRESHOLDS.version,
    thresholdDigest: corpusBenchmarkThresholdDigest(),
    provenance: { ...provenance, sampleRunIds: [...new Set(standardThree.map((sample) => sample.runId))].sort((a, b) => a - b), sampleDigest },
    concurrency: { selected: concurrency.selected, eligible: concurrency.eligible, rejected: concurrency.rejected },
    extendToFive: concurrency.extendToFive,
    evidence: { sampleDigest, cohorts },
    next: {
      stage: needsStandardExtension ? "extend-standard" : requiredRuns.length > 0 ? "four-shard" : "complete",
      design: concurrency.selected.design,
      concurrency: concurrency.selected.concurrency,
      requiredShardCounts: needsStandardExtension ? [3] : requiredRuns.length > 0 ? [4] : [],
      requiredProfiles: ["cold", "warm"],
      repeats: needsStandardExtension ? [4, 5] : missingFourRepeats,
      requiredRuns,
      rerunPilotAfter: needsStandardExtension,
    },
  };
}

export function evaluateCorpusBenchmark(samples: readonly CorpusBenchmarkSample[], pilotDecision: CorpusBenchmarkPilotDecision): CorpusBenchmarkDecision {
  samples.forEach(assertSample);
  if (new Set(samples.map((sample) => `${sample.runId}/${sample.runAttempt}`)).size !== samples.length) {
    throw new Error("benchmark raw sample rows reuse a workflow run/attempt across cohorts");
  }
  const provenance = assertMatchedPopulation(samples);
  const isStandardPr = (sample: CorpusBenchmarkSample): boolean => sample.runnerRole === "pr" && sample.requestedRunner === "ubuntu-latest";
  const standardThree = samples.filter((sample) => isStandardPr(sample) && sample.shardCount === 3 && isRequiredStandardShape(sample));
  const expectedPilot = evaluateCorpusBenchmarkPilot(standardThree);
  if (!pilotDecision || stable(pilotDecisionCore(pilotDecision)) !== stable(pilotDecisionCore(expectedPilot))) {
    throw new Error("pilot decision receipt is missing, stale, or mismatched with the exact standard three-shard rows");
  }
  if (expectedPilot.next.rerunPilotAfter) {
    throw new Error("pilot decision requires the complete standard repeat-4/5 extension and a regenerated receipt before four-shard evaluation");
  }
  const standard = collectStandardCohorts(samples, isStandardPr);
  const concurrencySelection = pilotDecision.concurrency.selected;
  const eligible = pilotDecision.concurrency.eligible;
  const rejected = pilotDecision.concurrency.rejected;
  const extendToFive: string[] = [];

  const runnerDecision = (role: CorpusRunnerRole): CorpusBenchmarkDecision["runners"][CorpusRunnerRole] => {
    const alternatives = [...new Set(samples.filter((sample) => sample.runnerRole === role && sample.requestedRunner !== "ubuntu-latest").map((sample) => sample.requestedRunner))];
    if (alternatives.length === 0) return { selected: "ubuntu-latest", adoptedLarger: false, reasons: ["no repository-visible larger-runner sample exists"] };
    const rowsFor = (runner: string, profile: CorpusCacheProfile): CorpusBenchmarkSample[] => cohort(
      samples,
      (sample) => sample.runnerRole === role
        && sample.requestedRunner === runner
        && sample.profile === profile
        && sample.design === concurrencySelection.design
        && sample.concurrency === concurrencySelection.concurrency
        && sample.shardCount === 3,
      `${role} ${runner} ${profile}`,
    );
    const currentByProfile = { cold: rowsFor("ubuntu-latest", "cold"), warm: rowsFor("ubuntu-latest", "warm") };
    const current = [...currentByProfile.cold, ...currentByProfile.warm];
    const qualifying: Array<{ runner: string; medianGain: number; costIncrease: number }> = [];
    const reasons: string[] = [];
    for (const runner of alternatives) {
      const candidateByProfile = { cold: rowsFor(runner, "cold"), warm: rowsFor(runner, "warm") };
      const rows = [...candidateByProfile.cold, ...candidateByProfile.warm];
      for (const profile of ["cold", "warm"] as const) assertRepeatPair(currentByProfile[profile], candidateByProfile[profile], `${role} ${runner} ${profile}`);
      if (!rows.every((row) => current.every((base) => allAssertionsEqual(row, base)))) { reasons.push(`${runner}: population/evidence differs`); continue; }
      if (![...current, ...rows].every((row) => row.estimatedCostUsd > 0)) { reasons.push(`${runner}: dollar cost estimate is missing; runner adoption is forbidden`); continue; }
      const medianGain = improvement(median(rows.map((sample) => sample.criticalPathMs)), median(current.map((sample) => sample.criticalPathMs)));
      const p95Gain = improvement(nearestRankP95(rows.map((sample) => sample.criticalPathMs)), nearestRankP95(current.map((sample) => sample.criticalPathMs)));
      const costIncrease = increase(median(rows.map((sample) => sample.estimatedCostUsd)), median(current.map((sample) => sample.estimatedCostUsd)));
      const currentCold = new Map(currentByProfile.cold.map((sample) => [sample.repeat, sample.criticalPathMs]));
      const worstCold = Math.max(...candidateByProfile.cold.map((sample) => increase(sample.criticalPathMs, currentCold.get(sample.repeat)!)));
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

  const selectedStandard = standard.get(`${concurrencySelection.design}:${concurrencySelection.concurrency}`)!;
  const threeCold = selectedStandard.cold;
  const threeWarm = selectedStandard.warm;
  const fourCold = cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "cold" && sample.design === concurrencySelection.design && sample.concurrency === concurrencySelection.concurrency && sample.shardCount === 4, "four-shard cold");
  const fourWarm = cohort(samples, (sample) => isStandardPr(sample) && sample.profile === "warm" && sample.design === concurrencySelection.design && sample.concurrency === concurrencySelection.concurrency && sample.shardCount === 4, "four-shard warm");
  assertRepeatPair(threeCold, fourCold, "three/four shard cold");
  assertRepeatPair(threeWarm, fourWarm, "three/four shard warm");
  const shardReasons: string[] = [];
  if (![...fourCold, ...fourWarm].every((sample) => [...threeCold, ...threeWarm].every((base) => allAssertionsEqual(sample, base)))) shardReasons.push("three/four shard population or evidence differs");
  if (![...fourCold, ...fourWarm].every((sample) => [...threeCold, ...threeWarm].every((base) => sameRunnerEnvironment(sample, base)))) shardReasons.push("three/four shard actual runner environment differs");
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
  let requiresPilotRerun = false;
  if ([[warmGain, CORPUS_BENCHMARK_THRESHOLDS.fourShards.warmMedianImprovement],
    [coldP95Regression, CORPUS_BENCHMARK_THRESHOLDS.fourShards.coldP95MaxRegression],
    [aggregateIncrease, CORPUS_BENCHMARK_THRESHOLDS.fourShards.aggregateMaxIncrease]]
    .some(([value, threshold]) => nearThreshold(value!, threshold!)) || highVariation([...fourCold, ...fourWarm])) {
    requiresPilotRerun = threeCold.length === 3;
  }
  if (requiresPilotRerun) {
    extendToFive.push(
      ...REQUIRED_STANDARD_SHAPES.flatMap((shape) => [`${shape.design}:${shape.concurrency}:cold`, `${shape.design}:${shape.concurrency}:warm`]),
      `selected:${concurrencySelection.design}:${concurrencySelection.concurrency}:shards-4:cold`,
      `selected:${concurrencySelection.design}:${concurrencySelection.concurrency}:shards-4:warm`,
    );
  }

  const cohorts = buildCohortReports(samples);
  const sampleDigest = digest(cohorts.flatMap((report) => report.sampleDigests).sort());
  return {
    schema: 1,
    thresholdVersion: CORPUS_BENCHMARK_THRESHOLDS.version,
    thresholdDigest: corpusBenchmarkThresholdDigest(),
    provenance: { ...provenance, sampleRunIds: [...new Set(samples.map((sample) => sample.runId))].sort((a, b) => a - b), sampleDigest },
    concurrency: { selected: { design: concurrencySelection.design, concurrency: concurrencySelection.concurrency }, eligible, rejected },
    runners: { pr: runnerDecision("pr"), schedule: runnerDecision("schedule") },
    shards: { selected: fourQualified ? 4 : 3, coldFallback: 3, reasons: fourQualified ? [`qualified warm=${warmGain.toFixed(3)}, cold-p95=${coldP95Regression.toFixed(3)}, aggregate=${aggregateIncrease.toFixed(3)}`] : shardReasons },
    extendToFive: [...new Set(extendToFive)].sort(),
    evidence: { sampleDigest, cohorts },
    next: requiresPilotRerun ? {
      stage: "extend-standard",
      requiredShardCounts: [3],
      repeats: [4, 5],
      requiredRuns: corpusBenchmarkRequiredRuns(
        REQUIRED_STANDARD_SHAPES.flatMap((shape) => [`${shape.design}:${shape.concurrency}:cold`, `${shape.design}:${shape.concurrency}:warm`]),
        [4, 5],
      ),
      rerunPilotAfter: true,
    } : { stage: "complete", requiredShardCounts: [], repeats: [], requiredRuns: [], rerunPilotAfter: false },
  };
}
