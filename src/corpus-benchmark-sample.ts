import { createHash } from "node:crypto";
import {
  corpusBenchmarkProvenanceIntegrity,
  corpusRunnerNameClass,
  type CorpusBenchmarkArtifactEvidence,
  type CorpusBenchmarkCacheProvenance,
  type CorpusBenchmarkPriorScorecardEvidence,
  type CorpusBenchmarkSample,
  type CorpusCacheProfile,
  type CorpusRunnerRole,
} from "./corpus-benchmark.js";
import { corpusTargetConservationVector, type CorpusExecutionDesign, type CorpusExecutionManifest, type CorpusScorecard } from "./corpus-execution.js";
import type { CorpusShardProfileSelection } from "./scan/corpus-shards.js";

export interface CorpusBenchmarkApiStep {
  name: string;
  conclusion: string | null;
  started_at: string | null;
  completed_at: string | null;
}

export interface CorpusBenchmarkApiJob {
  id: number;
  name: string;
  status: string;
  conclusion: string | null;
  started_at: string | null;
  completed_at: string | null;
  runner_name: string | null;
  runner_group_name: string | null;
  labels: string[];
  steps: CorpusBenchmarkApiStep[];
}

export interface CorpusBenchmarkScorecard extends CorpusScorecard {
  rows: Array<{ slug: string; check: string; pass: boolean; module?: string; [key: string]: unknown }>;
  findings: Record<string, Array<{ confidence?: string; severity?: string; [key: string]: unknown }>>;
  detectors: Record<string, unknown[]>;
  mechanicalContexts: Record<string, unknown>;
  mechanicalRuns: Record<string, { phases?: Array<{ cache?: string }>; [key: string]: unknown }>;
  scannerRecords: Record<string, Array<{ cache?: string; [key: string]: unknown }>>;
  dependencyPreparations: Record<string, unknown[]>;
  phaseSeconds: Record<string, Record<string, number>>;
  runtimeReceipts: Record<string, Record<string, string>>;
  conservation: Array<Record<string, unknown>>;
  executions: Array<CorpusExecutionManifest | null>;
  shardProfiles: CorpusShardProfileSelection[];
}

interface CorpusBenchmarkSampleInput {
  scorecard: CorpusBenchmarkScorecard;
  jobs: CorpusBenchmarkApiJob[];
  runId: number;
  runAttempt: number;
  headSha: string;
  benchmarkSeed: string;
  benchmarkSeedRunId: number;
  benchmarkSeedRunAttempt: number;
  repeat: number;
  runnerRole: CorpusRunnerRole;
  requestedRunner: string;
  runnerImage: string;
  profile: CorpusCacheProfile;
  design: CorpusExecutionDesign;
  concurrency: number;
  shardCount: number;
  workflowUrl: string;
  targetCommits: Record<string, string>;
  transportKeys: string[];
  provenanceDigests: string[];
  artifactDigests: string[];
  artifacts: CorpusBenchmarkArtifactEvidence[];
  priorScorecards: CorpusBenchmarkPriorScorecardEvidence[];
  cacheProvenance: Omit<CorpusBenchmarkCacheProvenance, "invariant" | "integrityDigest"> & {
    invariant: Omit<CorpusBenchmarkCacheProvenance["invariant"], "targetDigest" | "evidenceDigest" | "dependencyInputDigest" | "cacheInputDigest" | "toolInputDigest">;
  };
  billedMs?: number;
  estimatedCostUsd?: number;
}

function assertPriorScorecardEvidence(input: CorpusBenchmarkSampleInput): CorpusBenchmarkPriorScorecardEvidence {
  if (input.priorScorecards.length !== input.shardCount) {
    throw new Error(`prior scorecard receipt population has ${input.priorScorecards.length} rows; expected ${input.shardCount}`);
  }
  if (new Set(input.priorScorecards.map(stable)).size !== 1) throw new Error("benchmark shards used mixed prior scorecard identities or content");
  const receipt = input.priorScorecards[0]!;
  if (receipt.schema !== 1
    || receipt.sourceRunId !== input.benchmarkSeedRunId
    || receipt.sourceRunAttempt !== input.benchmarkSeedRunAttempt
    || receipt.sourceHeadSha !== input.headSha
    || receipt.sourceEvent !== "workflow_dispatch"
    || receipt.sourceWorkflowPath !== ".github/workflows/corpus-drift.yml"
    || !Number.isSafeInteger(receipt.artifactId) || receipt.artifactId < 1
    || receipt.artifactName !== "corpus-drift-scorecard"
    || !/^sha256:[a-f0-9]{64}$/.test(receipt.artifactDigest)
    || !/^[a-f0-9]{64}$/.test(receipt.scorecardSha256)
    || !Number.isSafeInteger(receipt.scorecardBytes) || receipt.scorecardBytes < 1) {
    throw new Error("prior scorecard receipt is malformed or differs from the immutable benchmark seed run/attempt/head");
  }
  const retained = input.artifacts.filter((artifact) => artifact.family === "evidence/benchmark-prior-scorecard");
  if (retained.length !== input.shardCount) throw new Error(`retained prior scorecard receipt population has ${retained.length} artifacts; expected ${input.shardCount}`);
  return { ...receipt };
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function digest(value: unknown): string {
  return createHash("sha256").update(stable(value)).digest("hex");
}

function epoch(value: string | null): number | undefined {
  if (!value) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function elapsed(startedAt: string | null, completedAt: string | null): number | undefined {
  const start = epoch(startedAt);
  const finish = epoch(completedAt);
  return start === undefined || finish === undefined || finish < start ? undefined : finish - start;
}

function assertMapPopulation(scorecard: CorpusBenchmarkScorecard, targets: readonly string[]): void {
  const expected = stable([...targets].sort());
  for (const field of ["findings", "detectors", "mechanicalContexts", "mechanicalRuns", "scannerRecords", "dependencyPreparations", "phaseSeconds", "runtimeReceipts"] as const) {
    const actual = stable(Object.keys(scorecard[field]).sort());
    if (actual !== expected) throw new Error(`${field} target population differs: expected ${expected}, got ${actual}`);
  }
  const rowTargets = [...new Set(scorecard.rows.map((row) => row.slug))].sort();
  if (stable(rowTargets) !== expected) throw new Error(`row target population differs: expected ${expected}, got ${stable(rowTargets)}`);
  const conservationTargets = scorecard.conservation.map((row) => String(row.slug)).sort();
  if (new Set(conservationTargets).size !== targets.length || stable(conservationTargets) !== expected) throw new Error(`conservation target population differs: expected ${expected}, got ${stable(conservationTargets)}`);
}

function assertConservation(scorecard: CorpusBenchmarkScorecard, targets: readonly string[]): Array<Record<string, unknown>> {
  const stored = new Map(scorecard.conservation.map((row) => [String(row.slug), row]));
  if (stored.size !== targets.length) throw new Error(`conservation target population has ${stored.size} unique rows; expected ${targets.length}`);
  const recomputed: Array<Record<string, unknown>> = [];
  for (const slug of targets) {
    const row = stored.get(slug);
    if (!row) throw new Error(`${slug}: conservation row is missing`);
    const canonical = corpusTargetConservationVector(scorecard, slug);
    if (stable(row) !== stable(canonical)) throw new Error(`${slug}: stored full conservation envelope differs from raw mechanical/dependency/scanner/runtime/Semgrep/examined/cache evidence`);
    recomputed.push(canonical);
  }
  return recomputed;
}

function omitFields(value: unknown, fields: readonly string[]): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).filter(([key]) => !fields.includes(key)));
}

function invariantProducer(value: unknown): unknown {
  const producer = omitFields(value, ["durationMs"]) as Record<string, unknown>;
  if (producer && (producer.status === "ran" || producer.status === "cached")) producer.status = "executed";
  return producer;
}

function invariantDependencyPreparation(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const row = { ...(value as Record<string, unknown>) };
  const status = row.status;
  const reason = row.reason;
  if ((status === "hit" || status === "miss") && typeof reason === "string") {
    const prefix = status === "hit"
      ? "validated receipt and offline materialization"
      : "clean content-addressed preparation";
    if (reason === prefix) {
      row.reason = "complete content-addressed dependency preparation";
    } else if (reason.startsWith(`${prefix}; quality-scan remains non-cacheable because `)) {
      row.reason = `complete content-addressed dependency preparation; quality-scan remains non-cacheable because ${reason.slice(`${prefix}; quality-scan remains non-cacheable because `.length)}`;
    }
    row.status = "materialized";
  }
  return row;
}

function invariantScannerRecord(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const row = { ...(value as Record<string, unknown>) };
  if (row.cache === "hit" || row.cache === "recomputed") {
    const expectedReason = row.cache === "hit"
      ? "complete content-addressed artifact"
      : "forced-cold result matched cached artifact";
    if (row.reason === expectedReason) row.reason = "complete content-addressed artifact";
    row.cache = "verified";
  }
  return row;
}

const MECHANICAL_CACHE_HIT_REASONS = new Set([
  "resolved registry packs, local rules, implementation, target tree, and Semgrep version are keyed",
  "in-process configuration checks depend only on the keyed target tree and implementation",
  "in-process structural/AST checks depend only on the keyed target tree, options, runtime, and implementation",
  "deterministic corpus candidate lane: pinned target tree plus exact gitleaks rules/version; no provider verification",
  "immutable digested advisory snapshot plus offline lockfile/manifest checks; live registry fallbacks disabled",
]);

function invariantMechanicalRun(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const run = value as Record<string, unknown>;
  const phases = Array.isArray(run.phases) ? run.phases.map((phase) => {
    const phaseRow = phase as Record<string, unknown>;
    const recognizedCacheState = (phaseRow.cache === "hit" && typeof phaseRow.reason === "string" && MECHANICAL_CACHE_HIT_REASONS.has(phaseRow.reason))
      || (phaseRow.cache === "recomputed" && phaseRow.reason === "forced-cold result matched cached artifact");
    const normalized = omitFields(phase, ["durationMs"]) as Record<string, unknown>;
    if (recognizedCacheState) {
      normalized.cache = "verified";
      normalized.reason = "complete content-addressed artifact";
    }
    return { ...normalized, ...(Array.isArray(normalized.producers) ? { producers: normalized.producers.map(invariantProducer) } : {}) };
  }) : run.phases;
  const invariantRun = omitFields(run, ["durationMs"]) as Record<string, unknown>;
  return {
    ...invariantRun,
    ...(phases === undefined ? {} : { phases }),
    ...(Array.isArray(run.detectors) ? { detectors: run.detectors.map(invariantProducer) } : {}),
  };
}

function invariantTargetEvidence(scorecard: CorpusBenchmarkScorecard, slug: string): {
  slug: string;
  evidence: unknown;
  dependencyInputs: unknown;
  cacheInputs: unknown;
  toolInputs: unknown;
} {
  const dependencyInputs = (scorecard.dependencyPreparations[slug] ?? []).map(invariantDependencyPreparation);
  const scannerRecords = (scorecard.scannerRecords[slug] ?? []).map(invariantScannerRecord);
  const mechanicalRun = invariantMechanicalRun(scorecard.mechanicalRuns[slug]);
  const evidence = {
    rows: scorecard.rows.filter((row) => row.slug === slug),
    findings: scorecard.findings[slug] ?? [],
    detectors: (scorecard.detectors[slug] ?? []).map(invariantProducer),
    mechanicalContext: scorecard.mechanicalContexts[slug],
    mechanicalRun,
    scannerRecords,
    dependencyPreparations: dependencyInputs,
    phaseNames: Object.keys(scorecard.phaseSeconds[slug] ?? {}).sort(),
    runtime: scorecard.runtimeReceipts[slug],
    currentMechanical: scorecard.currentMechanicalExecution?.targets[slug],
  };
  const mechanicalPhases = ((mechanicalRun as { phases?: unknown[] } | undefined)?.phases ?? []).map((phase) => {
    const row = phase as { phase?: unknown; key?: unknown; scope?: unknown; producers?: unknown };
    return { phase: row.phase, key: row.key, scope: row.scope, producers: row.producers };
  });
  const cacheInputs = {
    mechanicalPhases,
    scanners: scannerRecords.map((record) => {
      const row = record as { scanner?: unknown; key?: unknown; scope?: unknown };
      return { scanner: row.scanner, key: row.key, scope: row.scope };
    }),
  };
  const toolInputs = {
    runtime: scorecard.runtimeReceipts[slug],
    currentMechanical: scorecard.currentMechanicalExecution?.targets[slug],
  };
  return { slug, evidence, dependencyInputs, cacheInputs, toolInputs };
}

export function buildCorpusBenchmarkSample(input: CorpusBenchmarkSampleInput): CorpusBenchmarkSample {
  const priorScorecard = assertPriorScorecardEvidence(input);
  const targets = Object.keys(input.targetCommits).sort();
  if (targets.length === 0 || new Set(targets).size !== targets.length) throw new Error("target commit population is empty or duplicated");
  for (const [slug, commit] of Object.entries(input.targetCommits)) if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error(`${slug}: target commit is not a 40-character SHA`);
  assertMapPopulation(input.scorecard, targets);
  const conservationVectors = assertConservation(input.scorecard, targets);
  const invariantVectors = targets.map((slug) => invariantTargetEvidence(input.scorecard, slug));
  const jobs = input.jobs.filter((job) => /^corpus shard \d+$/.test(job.name));
  if (jobs.length !== input.shardCount) throw new Error(`Actions job population has ${jobs.length} corpus shards; expected ${input.shardCount}`);
  if (jobs.some((job) => job.status !== "completed" || job.conclusion !== "success")) throw new Error("a corpus shard job did not complete successfully");
  const intervals = jobs.map((job) => {
    const duration = elapsed(job.started_at, job.completed_at);
    const start = epoch(job.started_at);
    const finish = epoch(job.completed_at);
    if (duration === undefined || start === undefined || finish === undefined) throw new Error(`${job.name}: complete Actions timing is missing`);
    return { job, duration, start, finish };
  });
  const actualRunnerRows = jobs.map((job) => ({ name: job.runner_name, group: job.runner_group_name, labels: [...job.labels].sort() }));
  if (actualRunnerRows.some((runner) => !runner.name || !runner.group || runner.labels.length === 0)) throw new Error("actual runner name/group/labels are incomplete");
  const runnerShapes = new Set(actualRunnerRows.map(({ group, labels }) => stable({ group, labels })));
  if (runnerShapes.size !== 1) throw new Error("benchmark shard jobs ran on mixed runner group/label shapes");
  const runnerNameClasses = new Set(actualRunnerRows.map((runner) => corpusRunnerNameClass(runner.name!, runner.group!)));
  if (runnerNameClasses.size !== 1) throw new Error("benchmark shard jobs ran on mixed runner name classes");
  const executions = input.scorecard.executions.filter((manifest): manifest is CorpusExecutionManifest => manifest !== null);
  if (executions.length !== input.shardCount) throw new Error(`scorecard has ${executions.length} execution manifests; expected ${input.shardCount}`);
  if (executions.some((manifest) => manifest.design !== input.design || manifest.profile !== input.profile || manifest.shard.count !== input.shardCount)) throw new Error("execution manifest design/profile/shard provenance differs from requested sample");
  const expectedTargetDigest = digest(targets);
  if (input.scorecard.shardProfiles.length !== input.shardCount
    || input.scorecard.shardProfiles.some((receipt) => receipt.selected !== input.profile)
    || input.scorecard.shardProfiles.some((receipt) => receipt.targetDigest !== expectedTargetDigest || !/^[0-9a-f]{64}$/.test(receipt.sourceDigest))
    || new Set(input.scorecard.shardProfiles.map((receipt) => stable(receipt))).size !== 1) {
    throw new Error("shard profile population/provenance differs from the requested cache profile");
  }
  const effectiveConcurrency = Math.max(...executions.map((manifest) => manifest.admission.effective));
  const cpuLimits = new Set(executions.map((manifest) => manifest.admission.cpuLimit));
  const memoryLimits = new Set(executions.map((manifest) => manifest.admission.memoryLimitBytes));
  if (cpuLimits.size !== 1 || memoryLimits.size !== 1) throw new Error("execution manifests carry mixed CPU or memory limits");
  const setupNetworkMs = intervals.reduce((sum, { job }) => {
    const score = job.steps.find((step) => step.name === "Score the corpus against its baselines");
    const jobStart = epoch(job.started_at)!;
    const scoreStart = epoch(score?.started_at ?? null);
    if (score?.conclusion !== "success" || scoreStart === undefined || scoreStart < jobStart) throw new Error(`${job.name}: scoring step timing/liveness is incomplete`);
    return sum + scoreStart - jobStart;
  }, 0);
  const phaseRows = Object.values(input.scorecard.phaseSeconds);
  const dependencyMs = phaseRows.reduce((sum, phases) => sum + (phases.install ?? 0) * 1_000, 0);
  const mechanicalPhases = Object.values(input.scorecard.mechanicalRuns).flatMap((run) => run.phases ?? []);
  const scannerRecords = Object.values(input.scorecard.scannerRecords).flat();
  const cacheStatuses = [...mechanicalPhases.map((phase) => phase.cache), ...scannerRecords.map((record) => record.cache)].filter((status): status is string => Boolean(status));
  const cacheCount = (status: string): number => cacheStatuses.filter((candidate) => candidate === status).length;
  const findings = Object.entries(input.scorecard.findings).sort(([left], [right]) => left.localeCompare(right));
  const disclosures = findings.map(([slug, rows]) => [slug, rows.filter((finding) => finding.confidence === "N/A" || finding.severity === "Info")] as const);
  const liveness = jobs.every((job) => job.steps.some((step) => step.name === "Gate liveness — did this job actually score anything?" && step.conclusion === "success"));
  const coldVerified = input.profile === "warm" || executions.every((manifest) => manifest.terminals.every((terminal) => terminal.state === "succeeded"))
    && cacheStatuses.includes("recomputed")
    && !cacheStatuses.includes("miss");
  const runtimeRows = Object.values(input.scorecard.runtimeReceipts);
  if (runtimeRows.length === 0 || new Set(runtimeRows.map(stable)).size !== 1) throw new Error("runtime/tool versions are missing or mixed across targets");
  const billedMs = input.billedMs ?? intervals.reduce((sum, interval) => sum + Math.ceil(interval.duration / 60_000) * 60_000, 0);
  const aggregateCpuSeconds = executions.reduce((sum, manifest) => sum + manifest.aggregate.cpuSeconds, 0);
  const targetDigest = digest(Object.entries(input.targetCommits).sort(([left], [right]) => left.localeCompare(right)));
  const evidenceDigest = digest(invariantVectors.map(({ slug, evidence }) => ({ slug, evidence })));
  const dependencyInputDigest = digest(invariantVectors.map(({ slug, dependencyInputs }) => ({ slug, dependencyInputs })));
  const cacheInputDigest = digest(invariantVectors.map(({ slug, cacheInputs }) => ({ slug, cacheInputs })));
  const toolInputDigest = digest(invariantVectors.map(({ slug, toolInputs }) => ({ slug, toolInputs })));
  const cacheProvenanceWithoutIntegrity: Omit<CorpusBenchmarkCacheProvenance, "integrityDigest"> = {
    ...input.cacheProvenance,
    invariant: {
      ...input.cacheProvenance.invariant,
      targetDigest,
      evidenceDigest,
      dependencyInputDigest,
      cacheInputDigest,
      toolInputDigest,
    },
  };
  const artifacts = [...input.artifacts].sort((left, right) => left.name.localeCompare(right.name));
  const transportKeys = [...new Set(input.transportKeys)].sort();
  const provenanceDigests = [...new Set(input.provenanceDigests)].sort();
  const cacheProvenance: CorpusBenchmarkCacheProvenance = {
    ...cacheProvenanceWithoutIntegrity,
    integrityDigest: corpusBenchmarkProvenanceIntegrity({
      provenance: cacheProvenanceWithoutIntegrity,
      transportKeys,
      provenanceDigests,
      artifacts,
    }),
  };
  return {
    schema: 1,
    runId: input.runId,
    runAttempt: input.runAttempt,
    workflow: "corpus-drift.yml",
    headSha: input.headSha,
    benchmarkSeed: input.benchmarkSeed,
    benchmarkSeedRunId: input.benchmarkSeedRunId,
    benchmarkSeedRunAttempt: input.benchmarkSeedRunAttempt,
    repeat: input.repeat,
    runnerRole: input.runnerRole,
    requestedRunner: input.requestedRunner,
    actualRunner: {
      jobs: actualRunnerRows.map((runner, index) => ({ id: jobs[index]!.id, name: runner.name! })),
      nameClass: [...runnerNameClasses][0]!,
      group: actualRunnerRows[0]!.group!,
      labels: actualRunnerRows[0]!.labels,
      image: input.runnerImage,
      cpuLimit: [...cpuLimits][0]!,
      memoryLimitBytes: [...memoryLimits][0]!,
    },
    profile: input.profile,
    design: input.design,
    concurrency: input.concurrency,
    effectiveConcurrency,
    shardCount: input.shardCount,
    criticalPathMs: Math.max(...intervals.map((interval) => interval.finish)) - Math.min(...intervals.map((interval) => interval.start)),
    aggregateRunnerMs: intervals.reduce((sum, interval) => sum + interval.duration, 0),
    aggregateCpuSeconds,
    peakRssBytes: Math.max(...executions.map((manifest) => manifest.aggregate.peakRssBytes)),
    setupNetworkMs,
    dependencyMs,
    targetProcessCpuMs: aggregateCpuSeconds * 1_000,
    cache: {
      hits: cacheCount("hit"),
      misses: cacheCount("miss"),
      recomputed: cacheCount("recomputed"),
      rejected: cacheCount("rejected"),
      transportKeys,
      provenanceDigests,
      strandedArtifacts: 0,
      provenance: cacheProvenance,
    },
    population: {
      targetDigest,
      targets,
      rowDigest: digest(input.scorecard.rows.map(({ slug, check, pass, module }) => ({ slug, check, pass, module })).sort((left, right) => stable(left).localeCompare(stable(right)))),
      findingDigest: digest(findings),
      disclosureDigest: digest(disclosures),
      baselineDigest: digest(input.scorecard.rows.filter((row) => row.check.includes("baseline"))),
      examinedDigest: digest(input.scorecard.conservation.map((row) => ({ slug: row.slug, examinedUnits: row.examinedUnits }))),
      evidenceDigest,
      conservationDigest: digest(conservationVectors),
      dependencyInputDigest,
      cacheInputDigest,
      toolInputDigest,
    },
    assertions: {
      baselines: input.scorecard.rows.length > 0 && input.scorecard.rows.every((row) => row.pass),
      liveness,
      forcedCold: coldVerified,
      conservation: input.scorecard.conservation.length === targets.length,
    },
    oomCount: executions.reduce((sum, manifest) => sum + manifest.aggregate.oomCount, 0),
    retryCount: executions.reduce((sum, manifest) => sum + manifest.aggregate.retryCount, 0),
    billedMinutes: billedMs / 60_000,
    estimatedCostUsd: input.estimatedCostUsd ?? 0,
    raw: {
      workflowUrl: input.workflowUrl,
      jobIds: jobs.map((job) => job.id).sort((a, b) => a - b),
      artifactDigests: [...new Set(input.artifactDigests)].sort(),
      artifacts,
      conservationVectors,
      invariantVectors,
      priorScorecard,
      toolVersions: runtimeRows[0]!,
      targetCommits: input.targetCommits,
    },
  };
}
