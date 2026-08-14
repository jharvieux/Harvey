import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import type { CorpusBenchmarkScorecard } from "./corpus-benchmark-sample.js";
import {
  aggregateCorpusWorkerResults,
  conservativePeakRssBytes,
  type CorpusExecutionManifest,
  type CorpusScorecard,
  type CorpusWorkerTerminal,
} from "./corpus-execution.js";
import {
  compareCurrentMechanicalExecutions,
  mergeCurrentMechanicalShards,
  type CurrentMechanicalExecutionArtifact,
} from "./corpus-mechanical-readiness.js";
import { readRecursiveSafe, statSafe } from "./fs-walk.js";
import {
  decideCorpusRelevance,
  discoverCorpusClosure,
  type CorpusChangedPath,
  type CorpusClosureReceipt,
} from "./scan/corpus-relevance.js";
import { EXTERNAL_CORPUS } from "./scan/external-corpus.js";
import { selectCorpusShardProfile, shardTargets, type CorpusShardProfileSelection } from "./scan/corpus-shards.js";

const SAMPLE_KIND = "corpus-checkin-performance-sample" as const;
const SHARD_COUNT = 3;
const REQUESTED_CONCURRENCY = 2;
const SHA1 = /^[a-f0-9]{40}$/;
const PRODUCER_JOB = /^corpus shard ([1-3])$/;
const REPLAY_JOB = /^current independent replay ([1-3])$/;
const SCORE_STEP = "Score the corpus against its baselines";
const LIVENESS_STEP = "Gate liveness — did this job actually score anything?";
const REPLAY_STEP = "Execute the independent exact-head replay";
const AGGREGATE_JOB = "clone pinned commits + score baselines";

let cachedClosure: { key: string; receipt: CorpusClosureReceipt } | null = null;

interface CorpusOomKillReceipt {
  source: "/sys/fs/cgroup/memory.events";
  before: number | null;
  after: number | null;
}

type CheckinExecutionManifest = CorpusExecutionManifest & { oomKills?: CorpusOomKillReceipt };

interface RawShardScorecard extends CorpusScorecard {
  rows: Array<{ slug: string; check: string; pass: boolean; module?: string; [key: string]: unknown }>;
  conservation: Array<Record<string, unknown>>;
  execution: CheckinExecutionManifest;
  shardProfile: CorpusShardProfileSelection;
  currentMechanicalExecution: CurrentMechanicalExecutionArtifact;
}

interface ActionsStep {
  name: string;
  status?: string;
  conclusion: string | null;
  number?: number;
  started_at: string | null;
  completed_at: string | null;
  [key: string]: unknown;
}

interface ActionsJob {
  id: number;
  run_id: number;
  run_attempt: number;
  head_sha: string;
  name: string;
  status: string;
  conclusion: string | null;
  started_at: string | null;
  completed_at: string | null;
  runner_name: string | null;
  runner_group_name: string | null;
  labels: string[];
  steps: ActionsStep[];
  [key: string]: unknown;
}

interface RelevanceDecision {
  schema: 1;
  base: CorpusClosureReceipt;
  head: CorpusClosureReceipt;
  changed: CorpusChangedPath[];
  relevant: boolean;
  verdict: "full-scan" | "declared-no-op";
  reasons: string[];
  matched: unknown[];
  disjoint: string[];
  uncertainties: unknown[];
}

interface RunnerReceipt {
  schema: 1;
  shard: number;
  requestedRunner: string;
  actual: {
    name: string;
    os: string;
    arch: string;
    environment: string;
    imageOS: string;
    imageVersion: string;
  };
}

interface CacheReceipt {
  schema: 1;
  shard: number;
  clone: { key: string; hit: boolean };
  phase: { runMatchedKey: string; mainMatchedKey: string; selectedMatchedKey: string };
}

interface SealOptions {
  scorecardPath: string;
  relevancePath: string;
  jobsPath: string;
  evidenceDir: string;
  producerPath: string;
  replayPath: string;
  repoRoot: string;
  runId: number;
  runAttempt: number;
  actionsHeadSha: string;
  executionHeadSha: string;
  event: string;
  ref: string;
  requestedRunner: string;
}

interface RawArtifact {
  role: string;
  path: string;
  bytes: number;
  sha256: string;
}

interface CacheVectorRow {
  slug: string;
  mechanical: Array<{ ordinal: number; phase: string; state: string; key: string | null }>;
  scanners: Array<{ ordinal: number; scanner: string; state: string; key: string | null }>;
  dependencies: Array<{ ordinal: number; packageManager: string; state: string; key: string | null }>;
}

interface NormalizedJob {
  id: number;
  kind: "producer" | "replay";
  shard: number;
  name: string;
  startedAt: string;
  completedAt: string;
  elapsedMs: number;
  roundedBillingMinutes: number;
  runnerName: string;
  runnerGroupName: string;
  labels: string[];
  measuredSteps: Array<{ name: string; startedAt: string; completedAt: string; elapsedMs: number }>;
}

interface CorpusCheckinSample {
  schema: 1;
  kind: typeof SAMPLE_KIND;
  validity: {
    correctnessValid: true;
    performanceComparable: boolean;
    performanceIncomparabilityReasons: string[];
  };
  provenance: {
    workflow: "corpus-drift.yml";
    event: "pull_request";
    ref: string;
    runId: number;
    runAttempt: number;
    actionsHeadSha: string;
    executionHeadSha: string;
    executedHeadClosureDigest: string;
    baseClosureDigest: string;
    closureChangedFromBase: boolean;
    headClosureUncertainties: number;
  };
  comparison: {
    key: string;
    identity: Record<string, unknown>;
  };
  population: {
    shardCount: 3;
    targetCount: 17;
    shardSizes: [1, 8, 8];
    orderedTargets: Array<{ slug: string; commit: string; shard: number; ordinal: number }>;
    targetDigest: string;
    rowsDigest: string;
    findingsDigest: string;
    conservationDigest: string;
    producerReplayDigest: string;
  };
  execution: {
    design: "target-workers";
    requestedConcurrency: 2;
    effectiveTargetWorkers: [1, 2, 2];
    scannerLanes: [1, 1, 1];
    actualWorkerOverlap: [false, true, true];
    terminalFailureCount: 0;
    retrySignalCount: 0;
    oomSignalCount: 0;
    cgroupOomDelta: number | null;
    cgroupOomMeasurementComplete: boolean;
    strandedArtifactCount: 0;
    aggregateCpuSeconds: number;
    peakRssBytes: number;
    shards: Array<Record<string, unknown>>;
  };
  assertions: {
    baselines: true;
    liveness: true;
    conservation: true;
    currentProducerReplayEquality: true;
    completeRawPopulation: true;
    noTerminalFailureRetryOrOomSignal: true;
    noStrandedArtifacts: true;
  };
  timing: {
    scope: "completed producer and replay job rows only; aggregate job remains in progress";
    producerCriticalPathMs: number;
    completedProducerJobMs: number;
    completedReplayJobMs: number;
    completedProducerReplayJobMs: number;
    completedProducerReplayWindowMs: number;
    aggregateFinalCompletedAt: null;
    workflowFinalCompletedAt: null;
    jobs: NormalizedJob[];
  };
  billing: {
    scope: "rounded completed producer and replay job rows only";
    completedProducerReplayRoundedMinutes: number;
    completeWorkflowBilling: false;
  };
  runner: {
    requested: string;
    consistentShape: boolean;
    receipts: RunnerReceipt[];
  };
  cache: {
    requestedProfileLabel: "warm";
    authority: "raw ordered phase/scanner/dependency states and exact retained transport keys";
    vector: CacheVectorRow[];
    vectorDigest: string;
    counts: Record<string, number>;
    receipts: CacheReceipt[];
    frozenSeedContentDigest: null;
    frozenSeedTransportDigest: null;
  };
  raw: {
    artifacts: RawArtifact[];
    artifactPopulationDigest: string;
    actionsJobs: ActionsJob[];
    terminalArtifacts: Array<{ shard: number; ordinal: number; slug: string; directory: string; files: string[] }>;
  };
  sealDigest: string;
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value: unknown): string {
  return createHash("sha256").update(stable(value)).digest("hex");
}

function bytesDigest(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function fail(message: string): never {
  throw new Error(`corpus check-in sample: ${message}`);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} is not an object`);
  return value as Record<string, unknown>;
}

function rejectSelfReseal(value: unknown, label: string): void {
  if (value && typeof value === "object" && !Array.isArray(value)
    && (value as Record<string, unknown>).kind === SAMPLE_KIND) {
    fail(`${label} is a prior check-in sample; self-reseal is forbidden`);
  }
}

function parseJson<T>(path: string, label: string): T {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`${label} is missing or invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  rejectSelfReseal(value, label);
  return value as T;
}

function epoch(value: unknown, label: string): number {
  if (typeof value !== "string") fail(`${label} timestamp is missing`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail(`${label} timestamp is invalid: ${value}`);
  return parsed;
}

function interval(startedAt: unknown, completedAt: unknown, label: string): { start: number; finish: number; elapsedMs: number } {
  const start = epoch(startedAt, `${label} start`);
  const finish = epoch(completedAt, `${label} completion`);
  if (finish < start) fail(`${label} completion precedes its start`);
  return { start, finish, elapsedMs: finish - start };
}

function portableRelative(path: string): boolean {
  return path.length > 0 && !path.startsWith("/") && !path.includes("\\")
    && path.split("/").every((segment) => segment.length > 0 && segment !== "." && segment !== "..");
}

function evidencePath(root: string, path: string): string {
  if (!portableRelative(path)) fail(`retained artifact identity is not portable: ${path}`);
  const absolute = join(root, ...path.split("/"));
  if (!statSafe(absolute)?.isFile()) fail(`retained artifact is missing: parts/${path}`);
  const realRoot = realpathSync(root);
  const real = realpathSync(absolute);
  const owned = relative(realRoot, real).replaceAll("\\", "/");
  if (!portableRelative(owned) || owned !== path) fail(`retained artifact escapes or aliases its relative identity: ${path}`);
  return real;
}

function artifact(role: string, logicalPath: string, physicalPath: string): RawArtifact {
  if (!portableRelative(logicalPath)) fail(`raw artifact logical path is not portable: ${logicalPath}`);
  const body = readFileSync(physicalPath);
  return { role, path: logicalPath, bytes: body.byteLength, sha256: bytesDigest(body) };
}

function closureDigest(receipt: CorpusClosureReceipt, label: string): string {
  if (receipt.schema !== 1 || !Array.isArray(receipt.roots) || !Array.isArray(receipt.inputs)
    || !Array.isArray(receipt.edges) || !Array.isArray(receipt.uncertainties) || !Array.isArray(receipt.inventory)) {
    fail(`${label} closure receipt is incomplete`);
  }
  const computed = digest({ roots: receipt.roots, inputs: receipt.inputs, edges: receipt.edges, uncertainties: receipt.uncertainties });
  if (receipt.digest !== computed) fail(`${label} closure digest differs from its retained roots/inputs/edges/uncertainties`);
  return computed;
}

function discoverExecutedHeadClosure(repoRoot: string, revision: string): CorpusClosureReceipt {
  // The check-in CLI seals and immediately verifies one immutable Actions checkout. Keep the
  // expensive implementation-graph discovery process-local and identity-bound so verification
  // still rebuilds every raw artifact claim without walking the same checkout twice.
  const key = `${realpathSync(repoRoot)}\0${revision}`;
  if (cachedClosure?.key === key) return structuredClone(cachedClosure.receipt);
  const receipt = discoverCorpusClosure(repoRoot, revision);
  cachedClosure = { key, receipt: structuredClone(receipt) };
  return receipt;
}

function exactPopulation(actual: readonly string[], expected: readonly string[], label: string): void {
  if (stable(actual) !== stable(expected)) fail(`${label} population/order differs: expected ${expected.join(",")}; got ${actual.join(",")}`);
}

function mapKeys(value: unknown, label: string): string[] {
  return Object.keys(record(value, label));
}

function assertScorecardPopulation(scorecard: RawShardScorecard | CorpusBenchmarkScorecard, targets: readonly string[], label: string): void {
  const sorted = [...targets].sort();
  for (const field of ["findings", "detectors", "mechanicalContexts", "mechanicalRuns", "scannerRecords", "dependencyPreparations", "phaseSeconds", "runtimeReceipts"] as const) {
    exactPopulation(mapKeys(scorecard[field], `${label}.${field}`).sort(), sorted, `${label}.${field}`);
  }
  exactPopulation([...new Set(scorecard.rows.map((row) => String(row.slug)))].sort(), sorted, `${label}.rows`);
}

function overlapCount(terminals: readonly CorpusWorkerTerminal[]): number {
  const events = terminals.flatMap((terminal) => [
    { at: epoch(terminal.startedAt, `${terminal.slug} terminal start`), delta: 1 },
    { at: epoch(terminal.finishedAt, `${terminal.slug} terminal finish`), delta: -1 },
  ]).sort((left, right) => left.at - right.at || left.delta - right.delta);
  let running = 0;
  let maximum = 0;
  for (const event of events) {
    running += event.delta;
    maximum = Math.max(maximum, running);
  }
  return maximum;
}

function normalizeCacheVector(scorecard: CorpusBenchmarkScorecard, orderedTargets: readonly string[]): CacheVectorRow[] {
  const state = (value: unknown, label: string): string => {
    if (typeof value !== "string" || value.length === 0) fail(`${label} cache state is missing`);
    return value;
  };
  const optionalKey = (value: unknown, label: string): string | null => {
    if (value === undefined) return null;
    if (typeof value !== "string" || value.length === 0) fail(`${label} cache key is malformed`);
    return value;
  };
  return orderedTargets.map((slug) => {
    const run = record(scorecard.mechanicalRuns[slug], `${slug}.mechanicalRun`);
    const phases = Array.isArray(run.phases) ? run.phases : fail(`${slug}.mechanicalRun.phases is missing`);
    const scanners = scorecard.scannerRecords[slug];
    const dependencies = scorecard.dependencyPreparations[slug];
    if (!Array.isArray(scanners) || !Array.isArray(dependencies)) fail(`${slug} scanner/dependency cache vector is missing`);
    return {
      slug,
      mechanical: phases.map((value, ordinal) => {
        const row = record(value, `${slug}.mechanical[${ordinal}]`);
        return {
          ordinal,
          phase: state(row.phase, `${slug}.mechanical[${ordinal}].phase`),
          state: state(row.cache, `${slug}.mechanical[${ordinal}]`),
          key: optionalKey(row.key, `${slug}.mechanical[${ordinal}]`),
        };
      }),
      scanners: scanners.map((value, ordinal) => {
        const row = record(value, `${slug}.scanner[${ordinal}]`);
        return {
          ordinal,
          scanner: state(row.scanner, `${slug}.scanner[${ordinal}].scanner`),
          state: state(row.cache, `${slug}.scanner[${ordinal}]`),
          key: optionalKey(row.key, `${slug}.scanner[${ordinal}]`),
        };
      }),
      dependencies: dependencies.map((value, ordinal) => {
        const row = record(value, `${slug}.dependency[${ordinal}]`);
        return {
          ordinal,
          packageManager: state(row.packageManager, `${slug}.dependency[${ordinal}].packageManager`),
          state: state(row.status, `${slug}.dependency[${ordinal}]`),
          key: optionalKey(row.key, `${slug}.dependency[${ordinal}]`),
        };
      }),
    };
  });
}

function cacheCounts(vector: readonly CacheVectorRow[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const row of vector) {
    for (const item of [...row.mechanical, ...row.scanners, ...row.dependencies]) {
      counts[item.state] = (counts[item.state] ?? 0) + 1;
    }
  }
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function normalizeJob(job: ActionsJob, kind: "producer" | "replay", shard: number, requiredSteps: readonly string[]): NormalizedJob {
  const timing = interval(job.started_at, job.completed_at, job.name);
  if (job.status !== "completed" || job.conclusion !== "success") fail(`${job.name} did not complete successfully`);
  if (!job.runner_name || !job.runner_group_name || !Array.isArray(job.labels) || job.labels.length === 0) fail(`${job.name} runner identity is incomplete`);
  const measuredSteps = requiredSteps.map((name) => {
    const matches = job.steps.filter((step) => step.name === name);
    if (matches.length !== 1) fail(`${job.name} has ${matches.length} ${name} steps; expected exactly one`);
    const step = matches[0]!;
    if (step.conclusion !== "success") fail(`${job.name} step ${name} did not complete successfully`);
    const measured = interval(step.started_at, step.completed_at, `${job.name} / ${name}`);
    if (measured.start < timing.start || measured.finish > timing.finish) fail(`${job.name} step ${name} lies outside the completed job interval`);
    return { name, startedAt: step.started_at!, completedAt: step.completed_at!, elapsedMs: measured.elapsedMs };
  });
  return {
    id: job.id,
    kind,
    shard,
    name: job.name,
    startedAt: job.started_at!,
    completedAt: job.completed_at!,
    elapsedMs: timing.elapsedMs,
    roundedBillingMinutes: Math.ceil(timing.elapsedMs / 60_000),
    runnerName: job.runner_name,
    runnerGroupName: job.runner_group_name,
    labels: [...job.labels],
    measuredSteps,
  };
}

function logicalTerminalFiles(shard: number, ordinal: number, slug: string): { directory: string; files: string[] } {
  const directory = `corpus-drift-shard${shard}.json.workers/${ordinal.toString().padStart(3, "0")}-${slug}`;
  return {
    directory,
    files: ["result.json", "stdout.log", "stderr.log", "resource-trace.json", "liveness.receipt"].map((name) => `${directory}/${name}`),
  };
}

function validateWorkerArtifacts(
  evidenceDir: string,
  shard: number,
  manifest: CheckinExecutionManifest,
  expectedTargets: readonly string[],
  rawArtifacts: RawArtifact[],
): { relocated: CorpusWorkerTerminal[]; retained: Array<{ shard: number; ordinal: number; slug: string; directory: string; files: string[] }> } {
  const retained: Array<{ shard: number; ordinal: number; slug: string; directory: string; files: string[] }> = [];
  const cgroup = manifest.oomKills;
  if (!cgroup || cgroup.source !== "/sys/fs/cgroup/memory.events"
    || (cgroup.before !== null && (!Number.isInteger(cgroup.before) || cgroup.before < 0))
    || (cgroup.after !== null && (!Number.isInteger(cgroup.after) || cgroup.after < 0))) {
    fail(`shard ${shard} raw cgroup OOM receipt is missing or malformed`);
  }
  const cgroupRaised = cgroup.before !== null && cgroup.after !== null && cgroup.after > cgroup.before;
  if (cgroup.before !== null && cgroup.after !== null && cgroup.after < cgroup.before) fail(`shard ${shard} cgroup OOM counter moved backwards`);
  const terminals = [...manifest.terminals].sort((left, right) => left.ordinal - right.ordinal);
  if (terminals.length !== expectedTargets.length) fail(`shard ${shard} terminal population has ${terminals.length}; expected ${expectedTargets.length}`);
  const relocated = terminals.map((terminal, ordinal): CorpusWorkerTerminal => {
    const slug = expectedTargets[ordinal]!;
    if (terminal.ordinal !== ordinal || terminal.slug !== slug) fail(`shard ${shard} terminal ${ordinal} identity/order differs; expected ${slug}`);
    if (terminal.state !== "succeeded" || terminal.exitCode !== 0 || terminal.signal !== null || terminal.failure !== undefined) fail(`shard ${shard}/${slug} has a failed or incomplete terminal`);
    const timing = interval(terminal.startedAt, terminal.finishedAt, `shard ${shard}/${slug} terminal`);
    if (timing.elapsedMs < 0) fail(`shard ${shard}/${slug} terminal interval is invalid`);
    const logical = logicalTerminalFiles(shard, ordinal, slug);
    const [resultPath, stdoutPath, stderrPath, resourcePath, livenessPath] = logical.files.map((path) => evidencePath(evidenceDir, path));
    for (const [index, path] of logical.files.entries()) {
      const names = ["worker-result", "worker-stdout", "worker-stderr", "worker-resource", "worker-liveness"];
      rawArtifacts.push(artifact(names[index]!, `parts/${path}`, evidencePath(evidenceDir, path)));
    }
    const trace = parseJson<unknown[]>(resourcePath!, `shard ${shard}/${slug} resource trace`);
    if (!Array.isArray(trace) || trace.length === 0) fail(`shard ${shard}/${slug} resource trace is empty`);
    let prior = -Infinity;
    let peakRssBytes = 0;
    let cpuSeconds = 0;
    for (const [index, pointValue] of trace.entries()) {
      const point = record(pointValue, `shard ${shard}/${slug} resource[${index}]`);
      const at = epoch(point.at, `shard ${shard}/${slug} resource[${index}]`);
      if (at < prior) fail(`shard ${shard}/${slug} resource trace is not ordered`);
      prior = at;
      const rss = Number(point.rssBytes);
      const cpu = Number(point.cpuSeconds);
      const processes = Number(point.processCount);
      if (![rss, cpu, processes].every(Number.isFinite) || rss < 0 || cpu < 0 || !Number.isInteger(processes) || processes < 0) fail(`shard ${shard}/${slug} resource point is malformed`);
      peakRssBytes = Math.max(peakRssBytes, rss);
      cpuSeconds = Math.max(cpuSeconds, cpu);
    }
    if (terminal.peakRssBytes !== peakRssBytes || terminal.cpuSeconds !== cpuSeconds) fail(`shard ${shard}/${slug} terminal resource summary differs from raw trace`);
    const logs = `${readFileSync(stdoutPath!, "utf8")}\n${readFileSync(stderrPath!, "utf8")}`;
    const oomDetected = terminal.signal === "SIGKILL" || /\b(?:out of memory|oom-kill)\b/i.test(logs) || cgroupRaised;
    const retryDetected = /\b(?:retrying|retry attempt)\b/i.test(logs);
    if (terminal.oomDetected !== oomDetected || terminal.retryDetected !== retryDetected) fail(`shard ${shard}/${slug} terminal OOM/retry claim differs from raw cgroup/log evidence`);
    if (oomDetected || retryDetected) fail(`shard ${shard}/${slug} recorded an OOM or retry regression`);
    const result = parseJson<CorpusScorecard & { conservation?: Record<string, unknown>[] }>(resultPath!, `shard ${shard}/${slug} worker result`);
    const receipt = readFileSync(livenessPath!, "utf8").trim().split(/\r?\n/).filter(Boolean);
    if (receipt.length !== 1) fail(`shard ${shard}/${slug} liveness receipt has ${receipt.length} rows; expected one`);
    const liveness = /^harvey-liveness gate=corpus-drift status=measured units=(\d+) scope=baseline checks over 1 pinned target\(s\)$/.exec(receipt[0]!);
    if (!liveness || Number(liveness[1]) !== result.rows.length || result.rows.length === 0) fail(`shard ${shard}/${slug} liveness receipt differs from its raw result row population`);
    retained.push({ shard, ordinal, slug, directory: `parts/${logical.directory}`, files: logical.files.map((path) => `parts/${path}`) });
    return {
      ...terminal,
      outputDir: resolve(evidenceDir, logical.directory),
      resultPath: resultPath!,
      stdoutPath: stdoutPath!,
      stderrPath: stderrPath!,
      resourcePath: resourcePath!,
    };
  });
  return { relocated, retained };
}

function validateManifestAggregate(manifest: CheckinExecutionManifest, shard: number): void {
  const started = epoch(manifest.startedAt, `shard ${shard} manifest start`);
  const finished = epoch(manifest.finishedAt, `shard ${shard} manifest finish`);
  if (finished < started) fail(`shard ${shard} manifest completion precedes start`);
  const durations = manifest.terminals.map((terminal) => interval(terminal.startedAt, terminal.finishedAt, `${terminal.slug} terminal`).elapsedMs);
  const expected = {
    criticalPathMs: finished - started,
    summedWorkerMs: durations.reduce((sum, value) => sum + value, 0),
    peakRssBytes: conservativePeakRssBytes(manifest.terminals),
    cpuSeconds: manifest.terminals.reduce((sum, terminal) => sum + terminal.cpuSeconds, 0),
    oomCount: manifest.terminals.filter((terminal) => terminal.oomDetected).length,
    retryCount: manifest.terminals.filter((terminal) => terminal.retryDetected).length,
  };
  if (stable(manifest.aggregate) !== stable(expected)) fail(`shard ${shard} manifest aggregate differs from terminal timing/resource/OOM/retry evidence`);
  if (expected.oomCount !== 0 || expected.retryCount !== 0) fail(`shard ${shard} aggregate records an OOM or retry`);
}

function assertActionPopulation(jobs: ActionsJob[], options: SealOptions): {
  normalized: NormalizedJob[];
  raw: ActionsJob[];
  aggregate: ActionsJob;
} {
  if (!Array.isArray(jobs) || jobs.length === 0) fail("Actions job population is empty");
  if (new Set(jobs.map((job) => job.id)).size !== jobs.length) fail("Actions job population contains a duplicate id");
  for (const job of jobs) {
    if (job.run_id !== options.runId || job.run_attempt !== options.runAttempt) fail(`${job.name} belongs to a foreign run or attempt`);
    if (job.head_sha !== options.actionsHeadSha) fail(`${job.name} belongs to a foreign Actions head`);
    if (!Array.isArray(job.steps)) fail(`${job.name} has no retained step rows`);
  }
  const producer = jobs.filter((job) => PRODUCER_JOB.test(job.name)).sort((left, right) => left.name.localeCompare(right.name));
  const replay = jobs.filter((job) => REPLAY_JOB.test(job.name)).sort((left, right) => left.name.localeCompare(right.name));
  if (producer.length !== SHARD_COUNT) fail(`Actions producer job population has ${producer.length}; expected 3`);
  if (replay.length !== SHARD_COUNT) fail(`Actions replay job population has ${replay.length}; expected 3`);
  const producerShards = producer.map((job) => Number(PRODUCER_JOB.exec(job.name)?.[1]));
  const replayShards = replay.map((job) => Number(REPLAY_JOB.exec(job.name)?.[1]));
  exactPopulation(producerShards.map(String), ["1", "2", "3"], "Actions producer shard");
  exactPopulation(replayShards.map(String), ["1", "2", "3"], "Actions replay shard");
  const normalized = [
    ...producer.map((job, index) => normalizeJob(job, "producer", index + 1, [SCORE_STEP, LIVENESS_STEP])),
    ...replay.map((job, index) => normalizeJob(job, "replay", index + 1, [REPLAY_STEP])),
  ];
  const aggregateRows = jobs.filter((job) => job.name === AGGREGATE_JOB);
  if (aggregateRows.length !== 1) fail(`aggregate Actions job population has ${aggregateRows.length}; expected exactly one in-progress row`);
  const aggregate = aggregateRows[0]!;
  if (aggregate.status !== "in_progress" || aggregate.conclusion !== null || aggregate.completed_at !== null || !aggregate.started_at) {
    fail("aggregate job must still be in progress with no final completion or conclusion when the sample is written");
  }
  return { normalized, raw: [...producer, ...replay, aggregate], aggregate };
}

function sum(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0);
}

function unsignedSampleDigest(sample: Omit<CorpusCheckinSample, "sealDigest">): string {
  return digest(sample);
}

export function sealCorpusCheckinSample(options: SealOptions): CorpusCheckinSample {
  if (!Number.isInteger(options.runId) || options.runId < 1 || !Number.isInteger(options.runAttempt) || options.runAttempt < 1) fail("run id and attempt must be positive integers");
  if (!SHA1.test(options.actionsHeadSha) || !SHA1.test(options.executionHeadSha)) fail("Actions and execution heads must be full lowercase Git SHAs");
  if (options.event !== "pull_request" || !/^refs\/pull\/[1-9]\d*\/merge$/.test(options.ref)) fail("check-in samples are ordinary pull_request merge-ref evidence only");
  if (!options.requestedRunner.trim()) fail("requested runner is empty");

  const evidenceDir = realpathSync(options.evidenceDir);
  const inventory = readRecursiveSafe(evidenceDir).filter((path) => statSafe(join(evidenceDir, path))?.isFile()).sort();
  if (inventory.some((path) => path.includes("corpus-checkin-performance-sample"))) fail("evidence directory contains a prior sample; self-reseal is forbidden");

  const rawArtifacts: RawArtifact[] = [
    artifact("merged-scorecard", "scorecard/corpus-drift.json", options.scorecardPath),
    artifact("relevance-receipt", "relevance/corpus-relevance.json", options.relevancePath),
    artifact("actions-jobs", "actions/corpus-checkin-jobs.json", options.jobsPath),
    artifact("hosted-producer", "current/current-hosted-producer.json", options.producerPath),
    artifact("independent-replay", "current/current-independent-replay.json", options.replayPath),
  ];

  const scorecard = parseJson<CorpusBenchmarkScorecard>(options.scorecardPath, "merged scorecard");
  const relevance = parseJson<RelevanceDecision>(options.relevancePath, "relevance receipt");
  const jobsValue = parseJson<ActionsJob[] | { jobs?: ActionsJob[] }>(options.jobsPath, "Actions jobs");
  const jobs = Array.isArray(jobsValue) ? jobsValue : jobsValue.jobs;
  if (!Array.isArray(jobs)) fail("Actions jobs input has no jobs array");
  const producer = parseJson<CurrentMechanicalExecutionArtifact>(options.producerPath, "hosted producer");
  const replay = parseJson<CurrentMechanicalExecutionArtifact>(options.replayPath, "independent replay");

  if (relevance.schema !== 1 || relevance.head.revision !== options.executionHeadSha || !relevance.relevant || relevance.verdict !== "full-scan") {
    fail("relevance receipt is foreign, incomplete, or does not declare the executed PR head a full scan");
  }
  closureDigest(relevance.base, "base");
  closureDigest(relevance.head, "head");
  const recomputedDecision = decideCorpusRelevance(relevance.base, relevance.head, relevance.changed);
  if (stable(recomputedDecision) !== stable(relevance)) fail("relevance decision differs from its retained base/head/changed populations");
  const freshHead = discoverExecutedHeadClosure(options.repoRoot, options.executionHeadSha);
  if (stable(freshHead) !== stable(relevance.head)) fail("retained executed .head closure differs from an independent exact-checkout discovery");

  const slugs = EXTERNAL_CORPUS.map((target) => target.slug);
  if (slugs.length !== 17 || new Set(slugs).size !== 17) fail(`declared corpus population is ${slugs.length}; expected exactly 17 unique targets`);
  const expectedProfile = selectCorpusShardProfile(slugs, "auto", "uncertain");
  const shardTargetsInExecutionOrder = Array.from({ length: SHARD_COUNT }, (_, offset) => {
    const selected = new Set(shardTargets(slugs, offset + 1, SHARD_COUNT, expectedProfile.selected));
    return slugs.filter((slug) => selected.has(slug));
  });
  const sizes = shardTargetsInExecutionOrder.map((targets) => targets.length);
  exactPopulation(sizes.map(String), ["1", "8", "8"], "ordinary PR shard-size");

  const expectedEvidencePaths = new Set<string>();
  const shardScorecards: RawShardScorecard[] = [];
  const terminalArtifacts: Array<{ shard: number; ordinal: number; slug: string; directory: string; files: string[] }> = [];
  const cgroupDeltas: Array<number | null> = [];
  for (let shard = 1; shard <= SHARD_COUNT; shard += 1) {
    const scorecardRelative = `corpus-drift-shard${shard}.json`;
    const manifestRelative = `${scorecardRelative}.workers/execution-manifest.json`;
    const runnerRelative = `corpus-checkin-runner-${shard}.json`;
    const cacheRelative = `corpus-checkin-cache-${shard}.json`;
    for (const path of [scorecardRelative, manifestRelative, runnerRelative, cacheRelative]) expectedEvidencePaths.add(path);
    const scorecardPath = evidencePath(evidenceDir, scorecardRelative);
    const manifestPath = evidencePath(evidenceDir, manifestRelative);
    rawArtifacts.push(
      artifact("shard-scorecard", `parts/${scorecardRelative}`, scorecardPath),
      artifact("execution-manifest", `parts/${manifestRelative}`, manifestPath),
      artifact("runner-receipt", `parts/${runnerRelative}`, evidencePath(evidenceDir, runnerRelative)),
      artifact("cache-receipt", `parts/${cacheRelative}`, evidencePath(evidenceDir, cacheRelative)),
    );
    const rawShard = parseJson<RawShardScorecard>(scorecardPath, `shard ${shard} scorecard`);
    const manifest = parseJson<CheckinExecutionManifest>(manifestPath, `shard ${shard} execution manifest`);
    if (stable(rawShard.execution) !== stable(manifest)) fail(`shard ${shard} scorecard execution differs from retained execution-manifest.json`);
    const expectedTargets = shardTargetsInExecutionOrder[shard - 1]!;
    if (manifest.schema !== 1 || manifest.design !== "target-workers" || manifest.profile !== "warm"
      || manifest.shard.index !== shard || manifest.shard.count !== SHARD_COUNT) fail(`shard ${shard} execution design/profile/identity is foreign`);
    const expectedEffective = shard === 1 ? 1 : 2;
    const admission = manifest.admission;
    if (admission.requested !== REQUESTED_CONCURRENCY || admission.effective !== expectedEffective
      || admission.targetWorkers !== expectedEffective || admission.scannerLanes !== 1
      || !Number.isFinite(admission.cpuLimit) || admission.cpuLimit <= 0
      || !Number.isFinite(admission.memoryLimitBytes) || admission.memoryLimitBytes <= 0) {
      fail(`shard ${shard} requested/effective target-worker/scanner admission differs from 2/${expectedEffective}/1`);
    }
    const expectedOverlap = shard !== 1;
    if ((overlapCount(manifest.terminals) >= 2) !== expectedOverlap) fail(`shard ${shard} did not physically prove its expected ${expectedOverlap ? "two-worker overlap" : "one-target serialization"}`);
    validateManifestAggregate(manifest, shard);
    const validated = validateWorkerArtifacts(evidenceDir, shard, manifest, expectedTargets, rawArtifacts);
    terminalArtifacts.push(...validated.retained);
    for (const row of validated.retained) for (const path of row.files) expectedEvidencePaths.add(path.replace(/^parts\//, ""));
    const rebuilt = aggregateCorpusWorkerResults(validated.relocated, expectedTargets);
    const expectedShard: RawShardScorecard = {
      rows: rebuilt.rows as RawShardScorecard["rows"],
      findings: rebuilt.findings,
      detectors: rebuilt.detectors,
      mechanicalContexts: rebuilt.mechanicalContexts,
      mechanicalRuns: rebuilt.mechanicalRuns,
      scannerRecords: rebuilt.scannerRecords,
      dependencyPreparations: rebuilt.dependencyPreparations,
      phaseSeconds: rebuilt.phaseSeconds,
      runtimeReceipts: rebuilt.runtimeReceipts,
      currentMechanicalExecution: rebuilt.currentMechanicalExecution!,
      conservation: rebuilt.conservation,
      execution: manifest,
      shardProfile: expectedProfile,
    };
    if (stable(rawShard) !== stable(expectedShard)) fail(`shard ${shard} scorecard differs from re-parsed worker result/log/resource/liveness evidence`);
    assertScorecardPopulation(rawShard, expectedTargets, `shard ${shard}`);
    shardScorecards.push(rawShard);
    const oom = manifest.oomKills!;
    cgroupDeltas.push(oom.before === null || oom.after === null ? null : oom.after - oom.before);
  }

  const relevantEvidence = inventory.filter((path) =>
    /^corpus-drift-shard\d+\.json$/.test(path)
    || /^corpus-drift-shard\d+\.json\.workers\//.test(path)
    || /^corpus-checkin-(?:runner|cache)-\d+\.json$/.test(path)
    || path.includes(SAMPLE_KIND));
  const stranded = relevantEvidence.filter((path) => !expectedEvidencePaths.has(path));
  const missingExpected = [...expectedEvidencePaths].filter((path) => !inventory.includes(path));
  if (missingExpected.length > 0) fail(`retained raw population omitted ${missingExpected.join(", ")}`);
  if (stranded.length > 0) fail(`retained raw population contains ${stranded.length} stranded/foreign artifact(s): ${stranded.join(", ")}`);

  const expectedMerged: CorpusBenchmarkScorecard = {
    rows: shardScorecards.flatMap((part) => part.rows),
    findings: Object.assign({}, ...shardScorecards.map((part) => part.findings)),
    detectors: Object.assign({}, ...shardScorecards.map((part) => part.detectors)),
    mechanicalContexts: Object.assign({}, ...shardScorecards.map((part) => part.mechanicalContexts)),
    mechanicalRuns: Object.assign({}, ...shardScorecards.map((part) => part.mechanicalRuns)),
    scannerRecords: Object.assign({}, ...shardScorecards.map((part) => part.scannerRecords)),
    dependencyPreparations: Object.assign({}, ...shardScorecards.map((part) => part.dependencyPreparations)),
    phaseSeconds: Object.assign({}, ...shardScorecards.map((part) => part.phaseSeconds)),
    runtimeReceipts: Object.assign({}, ...shardScorecards.map((part) => part.runtimeReceipts)),
    conservation: shardScorecards.flatMap((part) => part.conservation),
    shardProfiles: shardScorecards.map((part) => part.shardProfile),
    executions: shardScorecards.map((part) => part.execution),
  };
  if (stable(scorecard) !== stable(expectedMerged)) fail("merged scorecard differs from the exact ordered three-shard raw population");
  assertScorecardPopulation(scorecard, slugs, "merged scorecard");
  if (scorecard.rows.length === 0 || scorecard.rows.some((row) => row.pass !== true)) fail("baseline population is empty or contains a failed assertion");

  const mergedProducer = mergeCurrentMechanicalShards(shardScorecards.map((part) => part.currentMechanicalExecution), "retained hosted shard population");
  if (stable(mergedProducer) !== stable(producer)) fail("hosted producer artifact differs from the producer recomputed from raw shard scorecards");
  if (producer.headCommit !== options.executionHeadSha || replay.headCommit !== options.executionHeadSha) fail("producer or replay belongs to a foreign execution head");
  compareCurrentMechanicalExecutions(producer, replay);

  const actions = assertActionPopulation(jobs, options);
  const producerJobs = actions.normalized.filter((job) => job.kind === "producer");
  const replayJobs = actions.normalized.filter((job) => job.kind === "replay");
  const runners: RunnerReceipt[] = [];
  const cacheReceipts: CacheReceipt[] = [];
  for (let shard = 1; shard <= SHARD_COUNT; shard += 1) {
    const runner = parseJson<RunnerReceipt>(evidencePath(evidenceDir, `corpus-checkin-runner-${shard}.json`), `shard ${shard} runner receipt`);
    const cache = parseJson<CacheReceipt>(evidencePath(evidenceDir, `corpus-checkin-cache-${shard}.json`), `shard ${shard} cache receipt`);
    if (runner.schema !== 1 || runner.shard !== shard || runner.requestedRunner !== options.requestedRunner
      || Object.values(runner.actual).some((value) => typeof value !== "string")) fail(`shard ${shard} runner receipt is foreign or incomplete`);
    if (cache.schema !== 1 || cache.shard !== shard || typeof cache.clone?.key !== "string" || cache.clone.key.length === 0 || typeof cache.clone.hit !== "boolean"
      || typeof cache.phase?.runMatchedKey !== "string" || typeof cache.phase.mainMatchedKey !== "string" || typeof cache.phase.selectedMatchedKey !== "string") {
      fail(`shard ${shard} cache transport receipt is foreign or incomplete`);
    }
    const selected = cache.phase.runMatchedKey || cache.phase.mainMatchedKey;
    if (cache.phase.selectedMatchedKey !== selected) fail(`shard ${shard} selected phase transport key differs from raw run/main matched keys`);
    if (runner.actual.name !== producerJobs[shard - 1]!.runnerName) fail(`shard ${shard} runner receipt differs from its Actions job row`);
    runners.push(runner);
    cacheReceipts.push(cache);
  }
  const runnerShapes = runners.map((runner, index) => ({
    actual: { ...runner.actual, name: "<ephemeral-runner-name>" },
    group: producerJobs[index]!.runnerGroupName,
    labels: producerJobs[index]!.labels,
  }));
  const consistentRunnerShape = new Set(runnerShapes.map(stable)).size === 1;

  const cacheVector = normalizeCacheVector(scorecard, slugs);
  const counts = cacheCounts(cacheVector);
  const performanceReasons = ["frozen-cache-seed-content-and-transport-digests-are-not-retained-by-the-ordinary-PR-route"];
  if (relevance.head.uncertainties.length > 0) performanceReasons.push("executed-head-closure-has-discovery-uncertainty");
  if (relevance.base.digest !== relevance.head.digest) performanceReasons.push("executed-head-closure-changed-from-PR-base");
  if (cgroupDeltas.some((value) => value === null)) performanceReasons.push("raw-cgroup-OOM-counter-is-unavailable");
  if (!consistentRunnerShape) performanceReasons.push("producer-shards-used-mixed-runner-shapes");
  if (runners.some((runner) => Object.values(runner.actual).some((value) => value.trim().length === 0))) {
    performanceReasons.push("producer-runner-identity-is-incomplete");
  }
  if (cacheReceipts.some((receipt) => !receipt.phase.selectedMatchedKey)) performanceReasons.push("phase-cache-transport-has-no-exact-matched-key");
  if ((counts.miss ?? 0) > 0 || (counts.incomplete ?? 0) > 0 || (counts.recomputed ?? 0) > 0 || (counts.hit ?? 0) === 0) {
    performanceReasons.push("raw-cache-vector-is-not-a-complete-controlled-warm-hit-state");
  }

  const orderedTargets = shardTargetsInExecutionOrder.flatMap((targets, shardOffset) => targets.map((slug, ordinal) => ({
    slug,
    commit: EXTERNAL_CORPUS.find((target) => target.slug === slug)!.commit,
    shard: shardOffset + 1,
    ordinal,
  })));
  const comparisonIdentity: Record<string, unknown> = {
    schema: 1,
    actionsHeadSha: options.actionsHeadSha,
    executionHeadSha: options.executionHeadSha,
    executedHeadClosureDigest: relevance.head.digest,
    targetPins: EXTERNAL_CORPUS.map(({ slug, commit }) => ({ slug, commit })),
    shardProfile: expectedProfile,
    shardPopulation: orderedTargets,
    execution: { design: "target-workers", requested: 2, effective: [1, 2, 2], scannerLanes: [1, 1, 1] },
    requestedRunner: options.requestedRunner,
    runnerShapes,
    cacheVectorDigest: digest(cacheVector),
    cacheTransports: cacheReceipts,
    frozenCacheSeedContentDigest: null,
    frozenCacheSeedTransportDigest: null,
    currentMechanical: {
      population: producer.population,
      harnessSha256: producer.harnessSha256,
      targetPinsSha256: producer.targetPinsSha256,
      semgrepRegistrySha256: producer.semgrepRegistry.aggregateSha256,
      runtime: producer.runtime,
    },
  };

  const producerIntervals = producerJobs.map((job) => interval(job.startedAt, job.completedAt, job.name));
  const replayIntervals = replayJobs.map((job) => interval(job.startedAt, job.completedAt, job.name));
  const allIntervals = [...producerIntervals, ...replayIntervals];
  const completeCgroup = cgroupDeltas.every((value): value is number => value !== null);
  const cgroupOomDelta = completeCgroup ? sum(cgroupDeltas) : null;
  if (cgroupOomDelta !== null && cgroupOomDelta !== 0) fail(`raw cgroup evidence records ${cgroupOomDelta} OOM kill(s)`);

  const sortedArtifacts = rawArtifacts.sort((left, right) => left.path.localeCompare(right.path));
  if (new Set(sortedArtifacts.map((row) => row.path)).size !== sortedArtifacts.length) fail("raw artifact seal contains a duplicate logical path");
  const unsigned: Omit<CorpusCheckinSample, "sealDigest"> = {
    schema: 1,
    kind: SAMPLE_KIND,
    validity: {
      correctnessValid: true,
      performanceComparable: performanceReasons.length === 0,
      performanceIncomparabilityReasons: performanceReasons,
    },
    provenance: {
      workflow: "corpus-drift.yml",
      event: "pull_request",
      ref: options.ref,
      runId: options.runId,
      runAttempt: options.runAttempt,
      actionsHeadSha: options.actionsHeadSha,
      executionHeadSha: options.executionHeadSha,
      executedHeadClosureDigest: relevance.head.digest,
      baseClosureDigest: relevance.base.digest,
      closureChangedFromBase: relevance.base.digest !== relevance.head.digest,
      headClosureUncertainties: relevance.head.uncertainties.length,
    },
    comparison: { key: digest(comparisonIdentity), identity: comparisonIdentity },
    population: {
      shardCount: 3,
      targetCount: 17,
      shardSizes: [1, 8, 8],
      orderedTargets,
      targetDigest: digest(EXTERNAL_CORPUS.map(({ slug, commit }) => ({ slug, commit }))),
      rowsDigest: digest(scorecard.rows),
      findingsDigest: digest(scorecard.findings),
      conservationDigest: digest(scorecard.conservation),
      producerReplayDigest: digest({ producer, replay }),
    },
    execution: {
      design: "target-workers",
      requestedConcurrency: 2,
      effectiveTargetWorkers: [1, 2, 2],
      scannerLanes: [1, 1, 1],
      actualWorkerOverlap: [false, true, true],
      terminalFailureCount: 0,
      retrySignalCount: 0,
      oomSignalCount: 0,
      cgroupOomDelta,
      cgroupOomMeasurementComplete: completeCgroup,
      strandedArtifactCount: 0,
      aggregateCpuSeconds: sum(shardScorecards.map((part) => part.execution.aggregate.cpuSeconds)),
      peakRssBytes: Math.max(...shardScorecards.map((part) => part.execution.aggregate.peakRssBytes)),
      shards: shardScorecards.map((part) => ({
        shard: part.execution.shard,
        admission: part.execution.admission,
        startedAt: part.execution.startedAt,
        finishedAt: part.execution.finishedAt,
        aggregate: part.execution.aggregate,
        oomKills: part.execution.oomKills,
        terminals: part.execution.terminals.map((terminal) => ({
          ordinal: terminal.ordinal,
          slug: terminal.slug,
          state: terminal.state,
          startedAt: terminal.startedAt,
          finishedAt: terminal.finishedAt,
          exitCode: terminal.exitCode,
          signal: terminal.signal,
          peakRssBytes: terminal.peakRssBytes,
          cpuSeconds: terminal.cpuSeconds,
          oomDetected: terminal.oomDetected,
          retryDetected: terminal.retryDetected,
          artifactDirectory: terminalArtifacts.find((row) => row.shard === part.execution.shard.index && row.ordinal === terminal.ordinal)!.directory,
        })),
      })),
    },
    assertions: {
      baselines: true,
      liveness: true,
      conservation: true,
      currentProducerReplayEquality: true,
      completeRawPopulation: true,
      noTerminalFailureRetryOrOomSignal: true,
      noStrandedArtifacts: true,
    },
    timing: {
      scope: "completed producer and replay job rows only; aggregate job remains in progress",
      producerCriticalPathMs: Math.max(...producerIntervals.map((row) => row.finish)) - Math.min(...producerIntervals.map((row) => row.start)),
      completedProducerJobMs: sum(producerIntervals.map((row) => row.elapsedMs)),
      completedReplayJobMs: sum(replayIntervals.map((row) => row.elapsedMs)),
      completedProducerReplayJobMs: sum(allIntervals.map((row) => row.elapsedMs)),
      completedProducerReplayWindowMs: Math.max(...allIntervals.map((row) => row.finish)) - Math.min(...allIntervals.map((row) => row.start)),
      aggregateFinalCompletedAt: null,
      workflowFinalCompletedAt: null,
      jobs: actions.normalized,
    },
    billing: {
      scope: "rounded completed producer and replay job rows only",
      completedProducerReplayRoundedMinutes: sum(actions.normalized.map((job) => job.roundedBillingMinutes)),
      completeWorkflowBilling: false,
    },
    runner: { requested: options.requestedRunner, consistentShape: consistentRunnerShape, receipts: runners },
    cache: {
      requestedProfileLabel: "warm",
      authority: "raw ordered phase/scanner/dependency states and exact retained transport keys",
      vector: cacheVector,
      vectorDigest: digest(cacheVector),
      counts,
      receipts: cacheReceipts,
      frozenSeedContentDigest: null,
      frozenSeedTransportDigest: null,
    },
    raw: {
      artifacts: sortedArtifacts,
      artifactPopulationDigest: digest(sortedArtifacts),
      actionsJobs: actions.raw,
      terminalArtifacts,
    },
  };
  return { ...unsigned, sealDigest: unsignedSampleDigest(unsigned) };
}

export function verifyCorpusCheckinSample(sample: CorpusCheckinSample, options: SealOptions): CorpusCheckinSample {
  const rebuilt = sealCorpusCheckinSample(options);
  if (sample.sealDigest !== unsignedSampleDigest(Object.fromEntries(Object.entries(sample).filter(([key]) => key !== "sealDigest")) as Omit<CorpusCheckinSample, "sealDigest">)) {
    fail("sample seal digest differs from its own fields");
  }
  if (stable(sample) !== stable(rebuilt)) fail("sample differs from independently re-parsed retained raw evidence");
  return rebuilt;
}
