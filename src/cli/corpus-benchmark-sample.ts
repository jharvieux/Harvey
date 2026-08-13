import "./sync-stdio.js";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildCorpusBenchmarkSample, type CorpusBenchmarkApiJob, type CorpusBenchmarkScorecard } from "../corpus-benchmark-sample.js";
import type { CorpusCacheProfile, CorpusRunnerRole } from "../corpus-benchmark.js";
import type { CorpusExecutionDesign } from "../corpus-execution.js";
import { readRecursiveSafe } from "../fs-walk.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";

const args = process.argv.slice(2);
const optional = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
};
const required = (name: string): string => {
  const value = optional(name);
  if (!value) {
    console.error(`corpus-benchmark-sample: missing ${name}`);
    process.exit(2);
  }
  return value;
};
const integer = (name: string): number => {
  const value = Number(required(name));
  if (!Number.isInteger(value) || value < 1) {
    console.error(`corpus-benchmark-sample: ${name} must be a positive integer`);
    process.exit(2);
  }
  return value;
};

const parseChoice = <T extends string>(name: string, choices: readonly T[]): T => {
  const value = required(name);
  if (!choices.includes(value as T)) {
    console.error(`corpus-benchmark-sample: ${name} must be ${choices.join(" or ")}`);
    process.exit(2);
  }
  return value as T;
};

function sha256(body: Buffer): string {
  return createHash("sha256").update(body).digest("hex");
}

function parseJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

interface CacheMergeReceipt {
  schema: 1;
  benchmarkSeed: string;
  headSha: string;
  requiredNamespaces: string[];
  sources: Array<{ key: string }>;
  aggregateSha256: string;
}

interface TransportReceipt {
  schema: 4;
  family: "benchmark";
  key: string;
  headSha: string;
  benchmarkSeed: string;
}

interface RunnerReceipt {
  schema: 1;
  shard: number;
  imageOS: string;
  imageVersion: string;
  runnerOS: string;
  runnerArch: string;
}

try {
  const scorecardPath = required("--scorecard");
  const jobsPath = required("--jobs");
  const evidenceDir = required("--evidence-dir");
  const out = required("--out");
  const runId = integer("--run-id");
  const runAttempt = integer("--run-attempt");
  const repeat = integer("--repeat");
  const concurrency = integer("--concurrency");
  const shardCount = integer("--shard-count");
  const headSha = required("--head-sha");
  const benchmarkSeed = required("--benchmark-seed");
  const runnerRole = parseChoice<CorpusRunnerRole>("--runner-role", ["pr", "schedule"]);
  const profile = parseChoice<CorpusCacheProfile>("--profile", ["cold", "warm"]);
  const design = parseChoice<CorpusExecutionDesign>("--design", ["serial", "target-workers", "intra-target-overlap", "split-carbon"]);
  const expectedShards = Array.from({ length: shardCount }, (_, index) => index + 1);
  const allEvidenceFiles = readRecursiveSafe(evidenceDir).sort();
  const evidenceFiles = allEvidenceFiles.filter((path) => /^(?:benchmark-cache-merge-receipt|benchmark-transport|benchmark-runner)-\d+\.json$/.test(path));
  const byKind = (kind: string): string[] => evidenceFiles.filter((path) => path.startsWith(`${kind}-`));
  for (const kind of ["benchmark-cache-merge-receipt", "benchmark-transport", "benchmark-runner"]) {
    const files = byKind(kind);
    if (files.length !== shardCount) throw new Error(`${kind} population has ${files.length} files; expected ${shardCount}`);
    const indices = files.map((path) => Number(/-(\d+)\.json$/.exec(path)?.[1])).sort((a, b) => a - b);
    if (JSON.stringify(indices) !== JSON.stringify(expectedShards)) throw new Error(`${kind} shard population differs: ${indices.join(",")}`);
  }
  const merges = byKind("benchmark-cache-merge-receipt").map((path) => parseJson<CacheMergeReceipt>(join(evidenceDir, path)));
  const transports = byKind("benchmark-transport").map((path) => parseJson<TransportReceipt>(join(evidenceDir, path)));
  const runners = byKind("benchmark-runner").map((path) => parseJson<RunnerReceipt>(join(evidenceDir, path)));
  if (merges.some((receipt) => receipt.schema !== 1 || receipt.benchmarkSeed !== benchmarkSeed || receipt.headSha !== headSha || !/^[0-9a-f]{64}$/.test(receipt.aggregateSha256))) {
    throw new Error("cache-merge receipt seed/head/digest provenance differs from the benchmark");
  }
  if (transports.some((receipt) => receipt.schema !== 4 || receipt.family !== "benchmark" || receipt.benchmarkSeed !== benchmarkSeed || receipt.headSha !== headSha)) {
    throw new Error("saved benchmark transport seed/head provenance differs from the benchmark");
  }
  if (runners.some((receipt, index) => receipt.schema !== 1 || receipt.shard !== index + 1 || !receipt.imageOS || !receipt.imageVersion || !receipt.runnerOS || !receipt.runnerArch)) {
    throw new Error("runner image receipt population is incomplete or misordered");
  }
  const runnerImages = new Set(runners.map((receipt) => `${receipt.imageOS}@${receipt.imageVersion}/${receipt.runnerOS}/${receipt.runnerArch}`));
  if (runnerImages.size !== 1) throw new Error(`benchmark shards used mixed runner images: ${[...runnerImages].join(", ")}`);
  const jobsValue = parseJson<CorpusBenchmarkApiJob[] | { jobs?: CorpusBenchmarkApiJob[] }>(jobsPath);
  const jobs = Array.isArray(jobsValue) ? jobsValue : (jobsValue.jobs ?? []);
  const evidenceBodies = [scorecardPath, jobsPath, ...allEvidenceFiles.map((path) => join(evidenceDir, path))].map((path) => readFileSync(path));
  const sample = buildCorpusBenchmarkSample({
    scorecard: parseJson<CorpusBenchmarkScorecard>(scorecardPath),
    jobs,
    runId,
    runAttempt,
    headSha,
    benchmarkSeed,
    repeat,
    runnerRole,
    requestedRunner: required("--requested-runner"),
    runnerImage: [...runnerImages][0]!,
    profile,
    design,
    concurrency,
    shardCount,
    workflowUrl: required("--workflow-url"),
    targetCommits: Object.fromEntries(EXTERNAL_CORPUS.map((target) => [target.slug, target.commit])),
    transportKeys: [...transports.map((receipt) => receipt.key), ...merges.flatMap((receipt) => receipt.sources.map((source) => source.key))],
    provenanceDigests: [...merges.map((receipt) => receipt.aggregateSha256), ...transports.map((receipt) => sha256(Buffer.from(JSON.stringify(receipt))))],
    artifactDigests: evidenceBodies.map(sha256),
    ...(optional("--estimated-cost-usd") ? { estimatedCostUsd: Number(optional("--estimated-cost-usd")) } : {}),
  });
  writeFileSync(out, `${JSON.stringify(sample, null, 2)}\n`);
  console.error(`CORPUS BENCHMARK SAMPLE: run=${runId}/${runAttempt}; head=${headSha}; seed=${benchmarkSeed}; ${profile}/${design}/${concurrency}/${shardCount}; critical=${sample.criticalPathMs}ms; aggregate=${sample.aggregateRunnerMs}ms; jobs=${sample.raw.jobIds.join(",")}`);
} catch (error) {
  console.error(`CORPUS BENCHMARK SAMPLE REJECT: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
