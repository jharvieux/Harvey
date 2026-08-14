import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { sealCorpusCheckinSample, verifyCorpusCheckinSample } from "./corpus-checkin-sample.js";
import {
  CURRENT_MECHANICAL_POPULATION,
  CURRENT_MECHANICAL_PREPARATION,
  currentTargetPinsSha256,
  mergeCurrentMechanicalShards,
  type CurrentMechanicalExecutionArtifact,
  type CurrentMechanicalTargetDefinition,
} from "./corpus-mechanical-readiness.js";
import {
  aggregateCorpusWorkerResults,
  conservativePeakRssBytes,
  corpusTargetConservationVector,
  type CorpusExecutionManifest,
  type CorpusScorecard,
  type CorpusWorkerTerminal,
} from "./corpus-execution.js";
import {
  decideCorpusRelevance,
  discoverCorpusClosure,
  type CorpusChangedPath,
  type CorpusClosureReceipt,
} from "./scan/corpus-relevance.js";
import { EXTERNAL_CORPUS } from "./scan/external-corpus.js";
import { MECHANICAL_PHASES, digestParts, mechanicalExaminedUnitDigest } from "./scan/mechanical-phase-cache.js";
import { REGISTRY_PACKS, registryPackIdentity } from "./scan/semgrep.js";
import { selectCorpusShardProfile, shardTargets } from "./scan/corpus-shards.js";

const repoRoot = process.cwd();
const executionHeadSha = execFileSync("git", ["-C", repoRoot, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const actionsHeadSha = "b".repeat(40);
const runId = 31_700;
const runAttempt = 2;
const currentClosure = discoverCorpusClosure(repoRoot, executionHeadSha);

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hash(value: unknown): string {
  return createHash("sha256").update(typeof value === "string" ? value : stable(value)).digest("hex");
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function rewriteJson<T>(path: string, mutate: (value: T) => void): void {
  const value = JSON.parse(readFileSync(path, "utf8")) as T;
  mutate(value);
  writeJson(path, value);
}

const targetDefinitions: CurrentMechanicalTargetDefinition[] = EXTERNAL_CORPUS.map(({ slug, repo, commit, vendoredSubtrees }) => ({
  slug,
  repo,
  commit,
  vendoredSubtrees,
}));

const registryFiles = REGISTRY_PACKS.map((pack, ordinal) => {
  const body = `rules:\n  - id: fixture-${ordinal}\n    message: ${pack}\n`;
  return {
    ordinal,
    name: `${ordinal}-${pack.replaceAll("/", "-")}.yml`,
    bytes: Buffer.byteLength(body),
    sha256: hash(body),
    bodyBase64: Buffer.from(body).toString("base64"),
  };
});

const semgrepRegistry = {
  schema: 1 as const,
  aggregateSha256: registryPackIdentity(registryFiles.map((file, ordinal) => ({ pack: REGISTRY_PACKS[ordinal]!, body: Buffer.from(file.bodyBase64, "base64").toString("utf8") }))),
  files: registryFiles,
};

function targetReceipt(slug: string, side: "hosted-producer" | "independent-replay"): Record<string, unknown> {
  const definition = targetDefinitions.find((target) => target.slug === slug)!;
  const units = [{ producer: "fixture", kind: "target-path", identity: "src/index.ts" }];
  const diagnostics = { errors: [], skipped: [] };
  return {
    slug,
    repo: definition.repo,
    pin: definition.commit,
    checkoutHead: definition.commit,
    checkoutTree: hash(`${slug}:checkout-tree`),
    preparedTreeSha256: hash(`${slug}:prepared-tree`),
    emptyGitlinks: [],
    preparation: CURRENT_MECHANICAL_PREPARATION,
    removedVendoredSubtrees: [...(definition.vendoredSubtrees ?? [])],
    captureBeforeInstall: true,
    installMutationAtCapture: false,
    skipBundleScan: true,
    bundleDigest: digestParts(["bundle-pinned-off-v1"]),
    advisorySha256: hash("advisory"),
    advisoryVersion: "fixture-v1",
    secretCandidateIdentity: hash(`${slug}:secrets`),
    findings: [],
    producers: [{
      detector: "fixture-detector",
      phase: "configuration",
      order: 0,
      module: "M1",
      unitsExamined: 1,
      examinedUnitIdentities: units,
      examinedUnitDigest: mechanicalExaminedUnitDigest(units),
      findings: 0,
      durationMs: side === "hosted-producer" ? 2 : 3,
      status: "ran",
    }],
    context: { fixture: true },
    executionPlan: {
      schema: 1,
      phases: [...MECHANICAL_PHASES],
      implementation: { configuration: hash("implementation") },
      externalInputs: { configuration: { fixture: hash("external") } },
      semgrep: {
        schema: 1,
        strategy: "partitioned-families",
        families: [{ ordinal: 0, id: "fixture-family", configSha256: hash("config") }],
        primaryArgv: ["--config", "<family-config>", "<target-root>"],
        fallbackArgv: ["-j", "1", "--config", "<family-config>", "<target-root>"],
      },
    },
    cachePolicy: {
      schema: 1,
      mode: side === "hosted-producer" ? "hosted-content-addressed" : "independent-cold-off",
      namespaceSha256: hash(`${side}:${slug}:namespace`),
      emptyNamespaceVerified: side === "independent-replay",
      producerArtifactsAllowed: side === "hosted-producer",
    },
    semgrepDiagnostics: { schema: 1, ...diagnostics, sha256: hash(diagnostics) },
  };
}

function currentArtifact(
  side: "hosted-producer" | "independent-replay",
  shard: { index: number; count: number },
  slugs: readonly string[],
  executionId: string,
  command: string,
): CurrentMechanicalExecutionArtifact {
  return {
    schema: 2,
    kind: "current-mechanical-execution",
    population: CURRENT_MECHANICAL_POPULATION,
    side,
    executionId: `${side}:${executionId}`,
    headCommit: executionHeadSha,
    harnessSha256: hash("harness"),
    commands: [command],
    options: {
      skipNetworkChecks: true,
      skipBundleScan: true,
      advisoryMode: "snapshot",
      phaseCache: side === "hosted-producer" ? "hosted-content-addressed" : "off",
      bundleDir: null,
      handrolledIndicators: false,
      authGuards: [],
    },
    targetPinsSha256: currentTargetPinsSha256(targetDefinitions),
    allTargets: targetDefinitions,
    semgrepRegistry,
    runtime: { node: "v24.0.0", platform: "linux", arch: "x64", semgrep: "1.164.0", gitleaks: "8.30.1", trufflehog: "3.91.0", trufflehogSha256: hash("trufflehog"), git: "2.50.0" },
    shard,
    targets: Object.fromEntries(slugs.map((slug) => [slug, targetReceipt(slug, side)])) as unknown as CurrentMechanicalExecutionArtifact["targets"],
  };
}

function targetScorecard(slug: string, current: CurrentMechanicalExecutionArtifact, cacheState: "hit" | "miss"): CorpusScorecard & { conservation: Record<string, unknown>[] } {
  const mechanicalPhases = MECHANICAL_PHASES.map((phase, ordinal) => ({
    phase,
    durationMs: ordinal + 1,
    cache: phase === "secrets-history" || phase === "normalization" ? "non-cacheable" : cacheState,
    reason: "fixture raw state",
    ...(phase === "secrets-history" || phase === "normalization" ? {} : { key: hash(`${slug}:${phase}`) }),
    findings: [],
    scope: { unitsExamined: 1, description: `${slug}:${phase}` },
    producers: [],
  }));
  const base: CorpusScorecard = {
    rows: [{ slug, check: "M1 baseline", module: "M1", detail: "fixture", pass: true }] as unknown as CorpusScorecard["rows"],
    findings: { [slug]: [] },
    detectors: { [slug]: [{ detector: "fixture", unitsExamined: 1, findings: 0 }] },
    mechanicalContexts: { [slug]: { files: 1 } },
    mechanicalRuns: { [slug]: { phases: mechanicalPhases } },
    scannerRecords: { [slug]: ["detect-static", "quality-scan", "mutation-detect-only"].map((scanner) => ({
      scanner,
      findings: [],
      scope: { unitsExamined: 1, description: `${slug}:${scanner}` },
      cache: cacheState,
      reason: "fixture raw state",
      key: hash(`${slug}:${scanner}`),
    })) },
    dependencyPreparations: { [slug]: [{
      status: cacheState,
      complete: true,
      cacheable: true,
      key: hash(`${slug}:deps`),
      packageManager: "pnpm",
      packageManagerVersion: "11.1.3",
      reason: "fixture raw state",
    }] },
    phaseSeconds: { [slug]: { install: 1, mechanical: 1 } },
    runtimeReceipts: { [slug]: { node: "v24.0.0", pnpm: "11.1.3" } },
    currentMechanicalExecution: current,
  };
  return { ...base, conservation: [corpusTargetConservationVector(base, slug)] };
}

interface FixtureOptions {
  cacheState?: "hit" | "miss";
  cgroupReadable?: boolean;
  baseClosureChanged?: boolean;
  unknownRunnerIdentity?: boolean;
}

interface Fixture {
  dir: string;
  evidenceDir: string;
  scorecardPath: string;
  relevancePath: string;
  jobsPath: string;
  producerPath: string;
  replayPath: string;
  options: Parameters<typeof sealCorpusCheckinSample>[0];
  shardScorecard: (shard: number) => string;
  manifest: (shard: number) => string;
  worker: (shard: number, ordinal: number, slug: string, file: string) => string;
}

function changedBaseClosure(head: CorpusClosureReceipt): CorpusClosureReceipt {
  const inputs = head.inputs.map((input, index) => index === 0 ? { ...input, digest: hash(`${input.digest}:base`) } : input);
  return { ...head, revision: "a".repeat(40), inputs, digest: hash({ roots: head.roots, inputs, edges: head.edges, uncertainties: head.uncertainties }) };
}

function actionsJob(name: string, shard: number, kind: "producer" | "replay"): Record<string, unknown> {
  const offset = kind === "producer" ? shard * 120_000 : shard * 120_000 + 30_000;
  const start = new Date(Date.parse("2026-08-13T00:00:00.000Z") + offset);
  const finish = new Date(start.getTime() + 90_000);
  const steps = kind === "producer"
    ? [
        { name: "Score the corpus against its baselines", conclusion: "success", started_at: new Date(start.getTime() + 10_000).toISOString(), completed_at: new Date(start.getTime() + 70_000).toISOString() },
        { name: "Gate liveness — did this job actually score anything?", conclusion: "success", started_at: new Date(start.getTime() + 75_000).toISOString(), completed_at: new Date(start.getTime() + 80_000).toISOString() },
      ]
    : [{ name: "Execute the independent exact-head replay", conclusion: "success", started_at: new Date(start.getTime() + 10_000).toISOString(), completed_at: new Date(start.getTime() + 75_000).toISOString() }];
  return {
    id: (kind === "producer" ? 100 : 200) + shard,
    run_id: runId,
    run_attempt: runAttempt,
    head_sha: actionsHeadSha,
    name,
    status: "completed",
    conclusion: "success",
    started_at: start.toISOString(),
    completed_at: finish.toISOString(),
    runner_name: `GitHub Actions ${shard}`,
    runner_group_name: "GitHub Actions",
    labels: ["ubuntu-latest"],
    steps,
  };
}

function fixture(options: FixtureOptions = {}): Fixture {
  const cacheState = options.cacheState ?? "hit";
  const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-checkin-"));
  const evidenceDir = join(dir, "parts");
  mkdirSync(evidenceDir, { recursive: true });
  const slugs = EXTERNAL_CORPUS.map((target) => target.slug);
  const profile = selectCorpusShardProfile(slugs, "auto", "uncertain");
  const shardTargetsOrdered = [1, 2, 3].map((shard) => {
    const selected = new Set(shardTargets(slugs, shard, 3, profile.selected));
    return slugs.filter((slug) => selected.has(slug));
  });
  const rawShards: Array<Record<string, unknown>> = [];
  const shardCurrents: CurrentMechanicalExecutionArtifact[] = [];
  for (const [shardOffset, owned] of shardTargetsOrdered.entries()) {
    const shard = shardOffset + 1;
    const effective = shard === 1 ? 1 : 2;
    const rawTerminals: CorpusWorkerTerminal[] = [];
    const relocated: CorpusWorkerTerminal[] = [];
    for (const [ordinal, slug] of owned.entries()) {
      const workerDir = join(evidenceDir, `corpus-drift-shard${shard}.json.workers`, `${ordinal.toString().padStart(3, "0")}-${slug}`);
      mkdirSync(join(workerDir, "tmp"), { recursive: true });
      const batch = Math.floor(ordinal / effective);
      const lane = ordinal % effective;
      const startedAt = new Date(Date.parse("2026-08-13T01:00:00.000Z") + shard * 100_000 + batch * 2_000 + lane * 50).toISOString();
      const finishedAt = new Date(Date.parse(startedAt) + 1_000).toISOString();
      const partialCurrent = currentArtifact("hosted-producer", { index: shard, count: 3 }, [slug], `${shard}:${ordinal}`, `worker ${slug}`);
      const result = targetScorecard(slug, partialCurrent, cacheState);
      writeJson(join(workerDir, "result.json"), result);
      writeFileSync(join(workerDir, "stdout.log"), "");
      writeFileSync(join(workerDir, "stderr.log"), "");
      writeJson(join(workerDir, "resource-trace.json"), [
        { at: startedAt, rssBytes: 1_000 + ordinal, cpuSeconds: 1 + ordinal / 10, processCount: 1 },
        { at: finishedAt, rssBytes: 1_000 + ordinal, cpuSeconds: 1 + ordinal / 10, processCount: 1 },
      ]);
      writeFileSync(join(workerDir, "liveness.receipt"), `harvey-liveness gate=corpus-drift status=measured units=${result.rows.length} scope=baseline checks over 1 pinned target(s)\n`);
      const terminal: CorpusWorkerTerminal = {
        ordinal,
        slug,
        state: "succeeded",
        pid: 10_000 + ordinal,
        startedAt,
        finishedAt,
        exitCode: 0,
        signal: null,
        outputDir: `/home/runner/work/Harvey/corpus-drift-shard${shard}.json.workers/${ordinal}-${slug}`,
        resultPath: `/home/runner/work/Harvey/${slug}/result.json`,
        stdoutPath: `/home/runner/work/Harvey/${slug}/stdout.log`,
        stderrPath: `/home/runner/work/Harvey/${slug}/stderr.log`,
        resourcePath: `/home/runner/work/Harvey/${slug}/resource-trace.json`,
        peakRssBytes: 1_000 + ordinal,
        cpuSeconds: 1 + ordinal / 10,
        oomDetected: false,
        retryDetected: false,
      };
      rawTerminals.push(terminal);
      relocated.push({
        ...terminal,
        outputDir: workerDir,
        resultPath: join(workerDir, "result.json"),
        stdoutPath: join(workerDir, "stdout.log"),
        stderrPath: join(workerDir, "stderr.log"),
        resourcePath: join(workerDir, "resource-trace.json"),
      });
    }
    const manifestStartedAt = new Date(Math.min(...rawTerminals.map((terminal) => Date.parse(terminal.startedAt))) - 100).toISOString();
    const manifestFinishedAt = new Date(Math.max(...rawTerminals.map((terminal) => Date.parse(terminal.finishedAt))) + 100).toISOString();
    const manifest: CorpusExecutionManifest & { oomKills: { source: "/sys/fs/cgroup/memory.events"; before: number | null; after: number | null } } = {
      schema: 1,
      design: "target-workers",
      profile: "warm",
      shard: { index: shard, count: 3 },
      admission: { requested: 2, effective, targetWorkers: effective, scannerLanes: 1, cpuLimit: 2, cpuSource: "/sys/fs/cgroup/cpu.max", memoryLimitBytes: 8_000_000_000, memorySource: "/sys/fs/cgroup/memory.max", memoryPerWorkerBytes: 1_500_000_000, reasons: ["fixture"] },
      startedAt: manifestStartedAt,
      finishedAt: manifestFinishedAt,
      oomKills: { source: "/sys/fs/cgroup/memory.events", before: options.cgroupReadable === false ? null : 7, after: options.cgroupReadable === false ? null : 7 },
      terminals: rawTerminals,
      aggregate: {
        criticalPathMs: Date.parse(manifestFinishedAt) - Date.parse(manifestStartedAt),
        summedWorkerMs: rawTerminals.reduce((total, terminal) => total + Date.parse(terminal.finishedAt) - Date.parse(terminal.startedAt), 0),
        peakRssBytes: conservativePeakRssBytes(rawTerminals),
        cpuSeconds: rawTerminals.reduce((total, terminal) => total + terminal.cpuSeconds, 0),
        oomCount: 0,
        retryCount: 0,
      },
    };
    const manifestPath = join(evidenceDir, `corpus-drift-shard${shard}.json.workers`, "execution-manifest.json");
    writeJson(manifestPath, manifest);
    const aggregated = aggregateCorpusWorkerResults(relocated, owned);
    const rawShard = {
      rows: aggregated.rows,
      findings: aggregated.findings,
      detectors: aggregated.detectors,
      mechanicalContexts: aggregated.mechanicalContexts,
      mechanicalRuns: aggregated.mechanicalRuns,
      scannerRecords: aggregated.scannerRecords,
      dependencyPreparations: aggregated.dependencyPreparations,
      phaseSeconds: aggregated.phaseSeconds,
      runtimeReceipts: aggregated.runtimeReceipts,
      currentMechanicalExecution: aggregated.currentMechanicalExecution,
      conservation: aggregated.conservation,
      execution: manifest,
      shardProfile: profile,
    };
    writeJson(join(evidenceDir, `corpus-drift-shard${shard}.json`), rawShard);
    writeJson(join(evidenceDir, `corpus-checkin-runner-${shard}.json`), {
      schema: 1,
      shard,
      requestedRunner: "ubuntu-latest",
      actual: {
        name: `GitHub Actions ${shard}`,
        os: "Linux",
        arch: "X64",
        environment: "github-hosted",
        imageOS: "ubuntu24",
        imageVersion: options.unknownRunnerIdentity ? "" : "20260801.1",
      },
    });
    writeJson(join(evidenceDir, `corpus-checkin-cache-${shard}.json`), {
      schema: 1,
      shard,
      clone: { key: `corpus-clone-cache-v2-${hash("pins")}`, hit: true },
      phase: { runMatchedKey: "", mainMatchedKey: `corpus-phase-main-v7-Linux-shard${shard}-seed`, selectedMatchedKey: `corpus-phase-main-v7-Linux-shard${shard}-seed` },
    });
    rawShards.push(rawShard);
    shardCurrents.push(aggregated.currentMechanicalExecution!);
  }
  const scorecard = {
    rows: rawShards.flatMap((part) => part.rows as unknown[]),
    findings: Object.assign({}, ...rawShards.map((part) => part.findings)),
    detectors: Object.assign({}, ...rawShards.map((part) => part.detectors)),
    mechanicalContexts: Object.assign({}, ...rawShards.map((part) => part.mechanicalContexts)),
    mechanicalRuns: Object.assign({}, ...rawShards.map((part) => part.mechanicalRuns)),
    scannerRecords: Object.assign({}, ...rawShards.map((part) => part.scannerRecords)),
    dependencyPreparations: Object.assign({}, ...rawShards.map((part) => part.dependencyPreparations)),
    phaseSeconds: Object.assign({}, ...rawShards.map((part) => part.phaseSeconds)),
    runtimeReceipts: Object.assign({}, ...rawShards.map((part) => part.runtimeReceipts)),
    conservation: rawShards.flatMap((part) => part.conservation as unknown[]),
    shardProfiles: rawShards.map((part) => part.shardProfile),
    executions: rawShards.map((part) => part.execution),
  };
  const scorecardPath = join(dir, "corpus-drift.json");
  writeJson(scorecardPath, scorecard);
  const producer = mergeCurrentMechanicalShards(shardCurrents, "fixture producer");
  const producerPath = join(dir, "current-hosted-producer.json");
  writeJson(producerPath, producer);
  const replay: CurrentMechanicalExecutionArtifact = {
    ...structuredClone(producer),
    side: "independent-replay",
    executionId: "independent-replay:fixture-merged",
    commands: ["pnpm replay:current-mechanical"],
    options: { ...producer.options, phaseCache: "off" },
    targets: Object.fromEntries(Object.keys(producer.targets).map((slug) => [slug, targetReceipt(slug, "independent-replay")])) as unknown as CurrentMechanicalExecutionArtifact["targets"],
  };
  const replayPath = join(dir, "current-independent-replay.json");
  writeJson(replayPath, replay);

  const freshHead = structuredClone(currentClosure);
  const base = options.baseClosureChanged ? changedBaseClosure(freshHead) : { ...freshHead, revision: "a".repeat(40) };
  const relevance = decideCorpusRelevance(base, freshHead, [{ status: "M", path: "src/corpus-execution.ts" }]);
  const relevancePath = join(dir, "corpus-relevance.json");
  writeJson(relevancePath, relevance);

  const jobs = [
    ...[1, 2, 3].map((shard) => actionsJob(`corpus shard ${shard}`, shard, "producer")),
    ...[1, 2, 3].map((shard) => actionsJob(`current independent replay ${shard}`, shard, "replay")),
    {
      id: 300,
      run_id: runId,
      run_attempt: runAttempt,
      head_sha: actionsHeadSha,
      name: "clone pinned commits + score baselines",
      status: "in_progress",
      conclusion: null,
      started_at: "2026-08-13T00:10:00.000Z",
      completed_at: null,
      runner_name: "GitHub Actions aggregate",
      runner_group_name: "GitHub Actions",
      labels: ["ubuntu-latest"],
      steps: [],
    },
  ];
  const jobsPath = join(dir, "corpus-checkin-jobs.json");
  writeJson(jobsPath, { jobs });

  const sealOptions = {
    scorecardPath,
    relevancePath,
    jobsPath,
    evidenceDir,
    producerPath,
    replayPath,
    repoRoot,
    runId,
    runAttempt,
    actionsHeadSha,
    executionHeadSha,
    event: "pull_request",
    ref: "refs/pull/1868/merge",
    requestedRunner: "ubuntu-latest",
  };
  return {
    dir,
    evidenceDir,
    scorecardPath,
    relevancePath,
    jobsPath,
    producerPath,
    replayPath,
    options: sealOptions,
    shardScorecard: (shard) => join(evidenceDir, `corpus-drift-shard${shard}.json`),
    manifest: (shard) => join(evidenceDir, `corpus-drift-shard${shard}.json.workers`, "execution-manifest.json"),
    worker: (shard, ordinal, slug, file) => join(evidenceDir, `corpus-drift-shard${shard}.json.workers`, `${ordinal.toString().padStart(3, "0")}-${slug}`, file),
  };
}

describe("ordinary-PR corpus check-in evidence sealer", () => {
  const scratch: string[] = [];
  const make = (options?: FixtureOptions): Fixture => {
    const value = fixture(options);
    scratch.push(value.dir);
    return value;
  };

  afterEach(async () => {
    scratch.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true }));
    await new Promise<void>((resolveYield) => setImmediate(resolveYield));
  });

  it("seals the exact 3-shard/17-target correctness population without overclaiming performance or workflow completion", () => {
    const input = make();
    const sample = sealCorpusCheckinSample(input.options);
    expect(sample).toMatchObject({
      validity: {
        correctnessValid: true,
        performanceComparable: false,
        performanceIncomparabilityReasons: expect.arrayContaining([
          "frozen-cache-seed-content-and-transport-digests-are-not-retained-by-the-ordinary-PR-route",
        ]),
      },
      population: { shardCount: 3, targetCount: 17, shardSizes: [1, 8, 8] },
      execution: {
        effectiveTargetWorkers: [1, 2, 2],
        scannerLanes: [1, 1, 1],
        actualWorkerOverlap: [false, true, true],
        terminalFailureCount: 0,
        retrySignalCount: 0,
        oomSignalCount: 0,
        cgroupOomDelta: 0,
        strandedArtifactCount: 0,
      },
      assertions: {
        baselines: true,
        liveness: true,
        conservation: true,
        currentProducerReplayEquality: true,
        completeRawPopulation: true,
      },
      timing: { aggregateFinalCompletedAt: null, workflowFinalCompletedAt: null },
      billing: { completeWorkflowBilling: false },
      cache: { frozenSeedContentDigest: null, frozenSeedTransportDigest: null },
    });
    expect(sample.population.orderedTargets.map((row) => row.slug)).toHaveLength(17);
    expect(new Set(sample.population.orderedTargets.map((row) => row.slug)).size).toBe(17);
    expect(sample.raw.artifacts).toHaveLength(102);
    expect(sample.raw.artifacts.every((row) => !row.path.startsWith("/") && /^[a-f0-9]{64}$/.test(row.sha256))).toBe(true);
    expect(sample.raw.actionsJobs.filter((job) => job.name.startsWith("corpus shard "))).toHaveLength(3);
    expect(sample.timing.scope).toContain("aggregate job remains in progress");
    expect(sample.comparison.key).toMatch(/^[a-f0-9]{64}$/);
    expect(verifyCorpusCheckinSample(sample, input.options)).toEqual(sample);
  });

  it("makes changed/unknown resource and cache authority correctness-valid but timing-inadmissible", () => {
    const changed = make({ cacheState: "miss", cgroupReadable: false, baseClosureChanged: true, unknownRunnerIdentity: true });
    const changedSample = sealCorpusCheckinSample(changed.options);
    expect(changedSample.validity).toMatchObject({
      correctnessValid: true,
      performanceComparable: false,
      performanceIncomparabilityReasons: expect.arrayContaining([
        "executed-head-closure-changed-from-PR-base",
        "raw-cgroup-OOM-counter-is-unavailable",
        "raw-cache-vector-is-not-a-complete-controlled-warm-hit-state",
        "producer-runner-identity-is-incomplete",
      ]),
    });
    expect(changedSample.execution).toMatchObject({ cgroupOomDelta: null, cgroupOomMeasurementComplete: false });
    const hit = make();
    const hitSample = sealCorpusCheckinSample(hit.options);
    expect(changedSample.cache.vectorDigest).not.toBe(hitSample.cache.vectorDigest);
    expect(changedSample.comparison.key).not.toBe(hitSample.comparison.key);
  });

  it("rejects a coherently resealed head closure that was not discovered from the executed checkout", () => {
    const input = make();
    const retained = JSON.parse(readFileSync(input.relevancePath, "utf8")) as {
      base: CorpusClosureReceipt;
      head: CorpusClosureReceipt;
      changed: CorpusChangedPath[];
    };
    const inputs = retained.head.inputs.map((row, index) => index === 0 ? { ...row, digest: hash(`${row.digest}:forged`) } : row);
    const head = {
      ...retained.head,
      inputs,
      digest: hash({ roots: retained.head.roots, inputs, edges: retained.head.edges, uncertainties: retained.head.uncertainties }),
    };
    writeJson(input.relevancePath, decideCorpusRelevance(retained.base, head, retained.changed));
    expect(() => sealCorpusCheckinSample(input.options)).toThrow(/retained executed \.head closure differs/);
  });

  it("rejects an omitted raw worker artifact", () => {
    const omitted = make();
    const manifest = JSON.parse(readFileSync(omitted.manifest(2), "utf8")) as CorpusExecutionManifest;
    const terminal = manifest.terminals[0]!;
    rmSync(omitted.worker(2, terminal.ordinal, terminal.slug, "stderr.log"));
    expect(() => sealCorpusCheckinSample(omitted.options)).toThrow(/worker-stderr|artifact is missing/);
  });

  it("rejects worker results swapped across target identities", () => {
    const swapped = make();
    const shard2 = JSON.parse(readFileSync(swapped.shardScorecard(2), "utf8")) as { execution: { terminals: CorpusWorkerTerminal[] } };
    const [left, right] = shard2.execution.terminals;
    const leftPath = swapped.worker(2, left!.ordinal, left!.slug, "result.json");
    const rightPath = swapped.worker(2, right!.ordinal, right!.slug, "result.json");
    const leftBody = readFileSync(leftPath);
    const rightBody = readFileSync(rightPath);
    writeFileSync(leftPath, rightBody);
    writeFileSync(rightPath, leftBody);
    expect(() => sealCorpusCheckinSample(swapped.options)).toThrow(/foreign findings population|row for another target/);
  });

  it("rejects a stranded or foreign shard artifact", () => {
    const foreign = make();
    writeJson(join(foreign.evidenceDir, "corpus-drift-shard4.json"), { foreign: true });
    expect(() => sealCorpusCheckinSample(foreign.options)).toThrow(/stranded\/foreign artifact/);
  });

  it("rejects a merged scorecard that overclaims the raw shard population", () => {
    const finalClaim = make();
    rewriteJson<{ rows: Array<{ pass: boolean }> }>(finalClaim.scorecardPath, (value) => { value.rows[0]!.pass = false; });
    expect(() => sealCorpusCheckinSample(finalClaim.options)).toThrow(/merged scorecard differs/);
  });

  it("rejects claimed concurrency without physical worker overlap", () => {
    const noOverlap = make();
    const manifest = JSON.parse(readFileSync(noOverlap.manifest(2), "utf8")) as CorpusExecutionManifest;
    const firstStart = Date.parse(manifest.terminals[0]!.startedAt);
    for (const [ordinal, terminal] of manifest.terminals.entries()) {
      terminal.startedAt = new Date(firstStart + ordinal * 2_000).toISOString();
      terminal.finishedAt = new Date(firstStart + ordinal * 2_000 + 1_000).toISOString();
    }
    manifest.startedAt = new Date(firstStart - 100).toISOString();
    manifest.finishedAt = new Date(Date.parse(manifest.terminals.at(-1)!.finishedAt) + 100).toISOString();
    manifest.aggregate = {
      criticalPathMs: Date.parse(manifest.finishedAt) - Date.parse(manifest.startedAt),
      summedWorkerMs: manifest.terminals.reduce((total, terminal) => total + Date.parse(terminal.finishedAt) - Date.parse(terminal.startedAt), 0),
      peakRssBytes: conservativePeakRssBytes(manifest.terminals),
      cpuSeconds: manifest.terminals.reduce((total, terminal) => total + terminal.cpuSeconds, 0),
      oomCount: 0,
      retryCount: 0,
    };
    writeJson(noOverlap.manifest(2), manifest);
    rewriteJson<{ execution: CorpusExecutionManifest }>(noOverlap.shardScorecard(2), (value) => { value.execution = manifest; });
    expect(() => sealCorpusCheckinSample(noOverlap.options)).toThrow(/physically prove.*two-worker overlap/);
  });

  it("rejects an OOM signal present in raw logs but absent from the terminal claim", () => {
    const oom = make();
    const oomShard = JSON.parse(readFileSync(oom.shardScorecard(2), "utf8")) as { execution: { terminals: CorpusWorkerTerminal[] } };
    const terminal = oomShard.execution.terminals[0]!;
    writeFileSync(oom.worker(2, terminal.ordinal, terminal.slug, "stderr.log"), "oom-kill observed\n");
    expect(() => sealCorpusCheckinSample(oom.options)).toThrow(/OOM\/retry claim differs/);
  });

  it("rejects a terminal resource summary that differs from its raw trace", () => {
    const resource = make();
    const resourceShard = JSON.parse(readFileSync(resource.shardScorecard(3), "utf8")) as { execution: { terminals: CorpusWorkerTerminal[] } };
    const resourceTerminal = resourceShard.execution.terminals[0]!;
    rewriteJson<Array<{ rssBytes: number }>>(resource.worker(3, resourceTerminal.ordinal, resourceTerminal.slug, "resource-trace.json"), (value) => { value[0]!.rssBytes += 999; });
    expect(() => sealCorpusCheckinSample(resource.options)).toThrow(/resource summary differs/);
  });

  it("rejects an incomplete producer job population", () => {
    const missingJob = make();
    rewriteJson<{ jobs: Array<{ name: string }> }>(missingJob.jobsPath, (value) => { value.jobs = value.jobs.filter((job) => job.name !== "corpus shard 3"); });
    expect(() => sealCorpusCheckinSample(missingJob.options)).toThrow(/producer job population has 2/);
  });

  it("rejects a producer job without a completion timestamp", () => {
    const incompleteJob = make();
    rewriteJson<{ jobs: Array<{ name: string; completed_at: string | null }> }>(incompleteJob.jobsPath, (value) => {
      value.jobs.find((job) => job.name === "corpus shard 2")!.completed_at = null;
    });
    expect(() => sealCorpusCheckinSample(incompleteJob.options)).toThrow(/completion timestamp is missing/);
  });

  it("rejects producer and replay inputs that are the same artifact", () => {
    const selfCompare = make();
    writeFileSync(selfCompare.replayPath, readFileSync(selfCompare.producerPath));
    expect(() => sealCorpusCheckinSample(selfCompare.options)).toThrow(/one real hosted producer artifact and one independent replay artifact/);
  });

  it("rejects a prior check-in sample used as raw input", () => {
    const selfReseal = make();
    const sample = sealCorpusCheckinSample(selfReseal.options);
    writeJson(selfReseal.jobsPath, sample);
    expect(() => sealCorpusCheckinSample(selfReseal.options)).toThrow(/self-reseal is forbidden/);
  });

  it("physically falsifies the raw-hash guard and restores byte-identical evidence", () => {
    const input = make();
    const original = sealCorpusCheckinSample(input.options);
    const shard = original.execution.shards[1] as { terminals: Array<{ ordinal: number; slug: string }> };
    const terminal = shard.terminals[0]!;
    const stdout = input.worker(2, terminal.ordinal, terminal.slug, "stdout.log");
    const before = readFileSync(stdout);
    writeFileSync(stdout, Buffer.concat([before, Buffer.from("benign raw mutation\n")]));
    expect(() => verifyCorpusCheckinSample(original, input.options)).toThrow(/differs from independently re-parsed retained raw evidence/);
    writeFileSync(stdout, before);
    expect(readFileSync(stdout)).toEqual(before);
    expect(verifyCorpusCheckinSample(original, input.options)).toEqual(original);

    const coherent = structuredClone(original);
    coherent.comparison.key = "c".repeat(64);
    const unsigned = Object.fromEntries(Object.entries(coherent).filter(([key]) => key !== "sealDigest"));
    coherent.sealDigest = hash(unsigned);
    expect(() => verifyCorpusCheckinSample(coherent, input.options)).toThrow(/differs from independently re-parsed retained raw evidence/);
  });

  it("keeps the CLI first-import exit guard and exposes the confirmed workflow contract", () => {
    const source = readFileSync(join(repoRoot, "src", "cli", "corpus-checkin-sample.ts"), "utf8");
    expect(source.startsWith('import "./sync-stdio.js";')).toBe(true);
    const help = execFileSync("pnpm", ["exec", "tsx", "src/cli/corpus-checkin-sample.ts", "--help"], { cwd: repoRoot, encoding: "utf8" });
    for (const flag of ["--scorecard", "--relevance", "--jobs", "--evidence-dir", "--producer", "--replay", "--out", "--run-id", "--run-attempt", "--actions-head-sha", "--execution-head-sha", "--event", "--ref", "--requested-runner"]) {
      expect(help).toContain(flag);
    }
  });

  it("makes duplicate, unknown, and raw-output-alias CLI inputs fail loud", () => {
    const run = (args: string[]) => spawnSync("pnpm", ["exec", "tsx", "src/cli/corpus-checkin-sample.ts", ...args], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    const unknown = run(["--unknown", "value"]);
    expect(unknown.status).toBe(1);
    expect(unknown.stderr).toContain("unknown argument --unknown");

    const duplicate = run(["--scorecard", "left.json", "--scorecard", "right.json"]);
    expect(duplicate.status).toBe(1);
    expect(duplicate.stderr).toContain("duplicate argument --scorecard");

    const aliased = join(tmpdir(), "corpus-checkin-alias.json");
    const alias = run([
      "--scorecard", aliased,
      "--relevance", join(tmpdir(), "corpus-checkin-relevance.json"),
      "--jobs", join(tmpdir(), "corpus-checkin-jobs.json"),
      "--evidence-dir", join(tmpdir(), "corpus-checkin-parts"),
      "--producer", join(tmpdir(), "corpus-checkin-producer.json"),
      "--replay", join(tmpdir(), "corpus-checkin-replay.json"),
      "--out", aliased,
      "--run-id", "1",
      "--run-attempt", "1",
      "--actions-head-sha", actionsHeadSha,
      "--execution-head-sha", executionHeadSha,
      "--event", "pull_request",
      "--ref", "refs/pull/1/merge",
      "--requested-runner", "ubuntu-latest",
    ]);
    expect(alias.status).toBe(1);
    expect(alias.stderr).toContain("--out must be distinct from every raw input");
  });
});
