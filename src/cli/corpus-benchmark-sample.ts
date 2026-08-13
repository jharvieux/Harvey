import "./sync-stdio.js";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildCorpusBenchmarkSample, type CorpusBenchmarkApiJob, type CorpusBenchmarkScorecard } from "../corpus-benchmark-sample.js";
import type { CorpusBenchmarkArtifactEvidence, CorpusBenchmarkTransportEvidence, CorpusCacheProfile, CorpusRunnerRole } from "../corpus-benchmark.js";
import { parseCorpusCacheTransportKey, type CorpusCacheMergeReceipt, type CorpusCacheTransportManifest } from "../corpus-cache-transport.js";
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
  const design = parseChoice<CorpusExecutionDesign>("--design", ["serial", "target-workers", "intra-target-overlap"]);
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
  const merges = byKind("benchmark-cache-merge-receipt").map((path) => parseJson<CorpusCacheMergeReceipt>(join(evidenceDir, path)));
  const transports = byKind("benchmark-transport").map((path) => parseJson<CorpusCacheTransportManifest>(join(evidenceDir, path)));
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
  const artifactPaths = [
    { name: "scorecard/corpus-drift.json", path: scorecardPath },
    { name: "actions/jobs.json", path: jobsPath },
    ...allEvidenceFiles.map((path) => ({ name: `evidence/${path}`, path: join(evidenceDir, path) })),
  ];
  const artifacts: CorpusBenchmarkArtifactEvidence[] = artifactPaths.map(({ name, path }) => ({
    name,
    family: name.replace(/(?:-\d+)?\.json$/, ""),
    sha256: sha256(readFileSync(path)),
  }));
  const artifactDigest = (name: string): string => {
    const artifact = artifacts.find((candidate) => candidate.name === `evidence/${name}`);
    if (!artifact) throw new Error(`named evidence artifact is missing: ${name}`);
    return artifact.sha256;
  };
  const transportEvidence = (role: "source" | "output", receipt: CorpusCacheTransportManifest | CorpusCacheMergeReceipt["sources"][number]): CorpusBenchmarkTransportEvidence => {
    const parsed = parseCorpusCacheTransportKey(receipt.key);
    if (!parsed || parsed.family !== "benchmark" || !parsed.seedDigest) throw new Error(`benchmark transport key is malformed: ${receipt.key}`);
    const enriched = receipt as CorpusCacheMergeReceipt["sources"][number];
    const manifest = receipt as CorpusCacheTransportManifest;
    return {
      role,
      key: receipt.key,
      family: "benchmark",
      event: enriched.event ?? manifest.event,
      ref: enriched.ref ?? manifest.ref,
      platform: enriched.platform ?? parsed.platform,
      namespace: enriched.namespace ?? parsed.namespace,
      runId: receipt.runId,
      runAttempt: receipt.runAttempt,
      headSha: receipt.headSha,
      benchmarkSeed: receipt.benchmarkSeed!,
      seedDigest: parsed.seedDigest,
      payloadBytes: enriched.payloadBytes ?? manifest.payload.bytes,
    };
  };
  const sourceTransports = [...new Map(merges.flatMap((receipt) => receipt.sources).map((receipt) => [receipt.key, transportEvidence("source", receipt)])).values()]
    .sort((left, right) => left.namespace.localeCompare(right.namespace));
  const outputTransports = transports.map((receipt) => transportEvidence("output", receipt)).sort((left, right) => left.namespace.localeCompare(right.namespace));
  const sourceFiles = merges[0]!.files;
  const semanticMerge = (receipt: CorpusCacheMergeReceipt): string => JSON.stringify({
    benchmarkSeed: receipt.benchmarkSeed,
    headSha: receipt.headSha,
    requiredNamespaces: receipt.requiredNamespaces,
    sources: receipt.sources,
    files: receipt.files,
    aggregateSha256: receipt.aggregateSha256,
  });
  if (new Set(merges.map(semanticMerge)).size !== 1) throw new Error("cache-merge receipts disagree on source transport/content identity");
  const sourceInvariant = sourceTransports.map((receipt) => ({
    family: receipt.family,
    event: receipt.event,
    ref: receipt.ref,
    platform: receipt.platform,
    namespace: receipt.namespace,
    headSha: receipt.headSha,
    benchmarkSeed: receipt.benchmarkSeed,
    seedDigest: receipt.seedDigest,
    payloadBytes: receipt.payloadBytes,
  }));
  const outputNamespaces = outputTransports.map((receipt) => receipt.namespace).sort();
  if (JSON.stringify(outputNamespaces) !== JSON.stringify(expectedShards.map(String))) throw new Error(`output transport namespace population differs: ${outputNamespaces.join(",")}`);
  const familyCounts = new Map<string, number>();
  for (const artifact of artifacts) familyCounts.set(artifact.family, (familyCounts.get(artifact.family) ?? 0) + 1);
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
    provenanceDigests: [...merges.map((receipt) => receipt.aggregateSha256), ...byKind("benchmark-transport").map(artifactDigest)],
    artifactDigests: artifacts.map((artifact) => artifact.sha256),
    artifacts,
    cacheProvenance: {
      schema: 1,
      invariant: {
        benchmarkSeed,
        headSha,
        ref: sourceInvariant[0]!.ref,
        platform: sourceInvariant[0]!.platform,
        sourceNamespaces: merges[0]!.requiredNamespaces,
        sourceContentDigest: merges[0]!.aggregateSha256,
        sourceTransports: sourceInvariant,
      },
      shape: {
        outputNamespaces,
        artifactFamilies: [...familyCounts].map(([family, count]) => ({ family, count })).sort((left, right) => left.family.localeCompare(right.family)),
      },
      transports: { sources: sourceTransports, outputs: outputTransports },
      sourceFiles,
      receiptDigests: [...byKind("benchmark-cache-merge-receipt").map(artifactDigest), ...byKind("benchmark-transport").map(artifactDigest)].sort(),
    },
    ...(optional("--estimated-cost-usd") ? { estimatedCostUsd: Number(optional("--estimated-cost-usd")) } : {}),
  });
  writeFileSync(out, `${JSON.stringify(sample, null, 2)}\n`);
  console.error(`CORPUS BENCHMARK SAMPLE: run=${runId}/${runAttempt}; head=${headSha}; seed=${benchmarkSeed}; ${profile}/${design}/${concurrency}/${shardCount}; critical=${sample.criticalPathMs}ms; aggregate=${sample.aggregateRunnerMs}ms; jobs=${sample.raw.jobIds.join(",")}`);
} catch (error) {
  console.error(`CORPUS BENCHMARK SAMPLE REJECT: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
