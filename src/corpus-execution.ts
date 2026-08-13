import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { cpus, totalmem } from "node:os";
import { join, resolve } from "node:path";
import type { CurrentMechanicalExecutionArtifact } from "./corpus-mechanical-readiness.js";

export type CorpusExecutionDesign = "serial" | "target-workers" | "intra-target-overlap" | "split-carbon";

interface CorpusResourcePoint {
  at: string;
  rssBytes: number;
  cpuSeconds: number;
  processCount: number;
}

export interface CorpusAdmissionReceipt {
  requested: number;
  effective: number;
  targetWorkers: number;
  scannerLanes: number;
  cpuLimit: number;
  cpuSource: string;
  memoryLimitBytes: number;
  memorySource: string;
  memoryPerWorkerBytes: number;
  reasons: string[];
}

export interface CorpusWorkerTerminal {
  ordinal: number;
  slug: string;
  state: "succeeded" | "failed";
  pid?: number;
  startedAt: string;
  finishedAt: string;
  exitCode: number | null;
  signal: string | null;
  outputDir: string;
  resultPath: string;
  stdoutPath: string;
  stderrPath: string;
  resourcePath: string;
  peakRssBytes: number;
  cpuSeconds: number;
  oomDetected: boolean;
  retryDetected: boolean;
  failure?: string;
}

export interface CorpusExecutionManifest {
  schema: 1;
  design: CorpusExecutionDesign;
  profile: "cold" | "warm";
  shard: { index: number; count: number };
  admission: CorpusAdmissionReceipt;
  startedAt: string;
  finishedAt: string;
  terminals: CorpusWorkerTerminal[];
  aggregate: {
    criticalPathMs: number;
    summedWorkerMs: number;
    peakRssBytes: number;
    cpuSeconds: number;
    oomCount: number;
    retryCount: number;
  };
}

interface WorkerOptions {
  repoRoot: string;
  scriptPath: string;
  baseArgs: string[];
  slugs: string[];
  requestedConcurrency: number;
  design: CorpusExecutionDesign;
  profile: "cold" | "warm";
  shard: { index: number; count: number };
  artifactsDir: string;
  environment?: NodeJS.ProcessEnv;
  failAfterStart?: string;
  now?: () => Date;
}

interface ProcessRow {
  pid: number;
  ppid: number;
  rssBytes: number;
  cpuSeconds: number;
}

const DEFAULT_WORKER_MEMORY_BYTES = 1_500_000_000;

function readText(path: string): string | undefined {
  try {
    return readFileSync(path, "utf8").trim();
  } catch {
    return undefined;
  }
}

function positiveNumber(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function cpuLimit(environment: NodeJS.ProcessEnv): { value: number; source: string } {
  const planted = positiveNumber(environment.HARVEY_CORPUS_CPU_LIMIT);
  if (planted) return { value: planted, source: "HARVEY_CORPUS_CPU_LIMIT" };
  const cpuMax = readText("/sys/fs/cgroup/cpu.max");
  if (cpuMax) {
    const [quota, period] = cpuMax.split(/\s+/);
    if (quota && quota !== "max" && period) {
      const value = Number(quota) / Number(period);
      if (Number.isFinite(value) && value > 0) return { value, source: "/sys/fs/cgroup/cpu.max" };
    }
  }
  return { value: cpus().length, source: "os.cpus" };
}

function memoryLimit(environment: NodeJS.ProcessEnv): { value: number; source: string } {
  const planted = positiveNumber(environment.HARVEY_CORPUS_MEMORY_LIMIT_BYTES);
  if (planted) return { value: planted, source: "HARVEY_CORPUS_MEMORY_LIMIT_BYTES" };
  const raw = readText("/sys/fs/cgroup/memory.max");
  const cgroup = raw === "max" ? undefined : positiveNumber(raw);
  if (cgroup) return { value: cgroup, source: "/sys/fs/cgroup/memory.max" };
  return { value: totalmem(), source: "os.totalmem" };
}

export function admitCorpusConcurrency(
  requested: number,
  targetCount: number,
  environment: NodeJS.ProcessEnv = process.env,
): CorpusAdmissionReceipt {
  if (!Number.isInteger(requested) || requested < 1 || requested > 3) throw new Error(`target concurrency must be an integer in 1..3, got ${requested}`);
  const cpu = cpuLimit(environment);
  const memory = memoryLimit(environment);
  const memoryPerWorkerBytes = positiveNumber(environment.HARVEY_CORPUS_MEMORY_PER_WORKER_BYTES) ?? DEFAULT_WORKER_MEMORY_BYTES;
  const cpuBound = Math.max(1, Math.floor(cpu.value));
  const memoryBound = Math.max(1, Math.floor(memory.value / memoryPerWorkerBytes));
  const effective = Math.max(1, Math.min(requested, targetCount, cpuBound, memoryBound));
  const reasons = [
    `requested=${requested}`,
    `targets=${targetCount}`,
    `cpu allows ${cpuBound}`,
    `memory allows ${memoryBound} at ${memoryPerWorkerBytes} bytes/worker`,
  ];
  return {
    requested,
    effective,
    targetWorkers: effective,
    scannerLanes: 1,
    cpuLimit: cpu.value,
    cpuSource: cpu.source,
    memoryLimitBytes: memory.value,
    memorySource: memory.source,
    memoryPerWorkerBytes,
    reasons,
  };
}

export async function runBoundedCorpusTasks<T>(tasks: readonly (() => Promise<T>)[], concurrency: number): Promise<T[]> {
  if (!Number.isInteger(concurrency) || concurrency < 1) throw new Error(`bounded task concurrency must be a positive integer, got ${concurrency}`);
  const results = new Array<T>(tasks.length);
  const failures: Array<{ ordinal: number; error: unknown }> = [];
  let cursor = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const ordinal = cursor++;
      const task = tasks[ordinal];
      if (!task) return;
      try {
        results[ordinal] = await task();
      } catch (error) {
        failures.push({ ordinal, error });
      }
    }
  };
  const lanes = await Promise.allSettled(Array.from({ length: Math.min(concurrency, Math.max(1, tasks.length)) }, () => worker()));
  const laneFailures = lanes.flatMap((lane) => lane.status === "rejected" ? [lane.reason] : []);
  const taskFailures = failures.sort((left, right) => left.ordinal - right.ordinal);
  if (taskFailures.length > 0 || laneFailures.length > 0) {
    const ordinals = taskFailures.map(({ ordinal }) => ordinal).join(", ");
    throw new AggregateError(
      [...taskFailures.map(({ error }) => error), ...laneFailures],
      `bounded corpus tasks failed after all tasks settled${ordinals ? ` at ordinal(s) ${ordinals}` : ""}`,
    );
  }
  return results;
}

/**
 * Conservatively bounds shard RSS by treating each worker's measured peak as resident for its
 * whole execution interval. Peaks from workers that could not have coexisted are never summed.
 */
export function conservativePeakRssBytes(
  terminals: readonly Pick<CorpusWorkerTerminal, "startedAt" | "finishedAt" | "peakRssBytes">[],
): number {
  const events: Array<{ at: number; kind: "start" | "finish"; bytes: number }> = [];
  let peak = 0;
  for (const terminal of terminals) {
    const startedAt = Date.parse(terminal.startedAt);
    const finishedAt = Date.parse(terminal.finishedAt);
    if (!Number.isFinite(startedAt) || !Number.isFinite(finishedAt) || finishedAt < startedAt) {
      throw new Error(`target worker has an invalid resource interval: ${terminal.startedAt}..${terminal.finishedAt}`);
    }
    if (!Number.isFinite(terminal.peakRssBytes) || terminal.peakRssBytes < 0) {
      throw new Error(`target worker has an invalid peak RSS: ${terminal.peakRssBytes}`);
    }
    peak = Math.max(peak, terminal.peakRssBytes);
    if (startedAt === finishedAt || terminal.peakRssBytes === 0) continue;
    events.push(
      { at: startedAt, kind: "start", bytes: terminal.peakRssBytes },
      { at: finishedAt, kind: "finish", bytes: terminal.peakRssBytes },
    );
  }
  events.sort((left, right) => left.at - right.at
    || (left.kind === right.kind ? 0 : left.kind === "finish" ? -1 : 1));
  let resident = 0;
  for (const event of events) {
    resident += event.kind === "start" ? event.bytes : -event.bytes;
    peak = Math.max(peak, resident);
  }
  return peak;
}

function parseCpuTime(value: string): number {
  const [dayPart, clock] = value.includes("-") ? value.split("-") : ["0", value];
  const parts = clock!.split(":").map(Number);
  const seconds = parts.length === 3 ? parts[0]! * 3600 + parts[1]! * 60 + parts[2]! : parts[0]! * 60 + parts[1]!;
  return Number(dayPart) * 86400 + seconds;
}

function processRows(): ProcessRow[] {
  try {
    const output = execFileSync("ps", ["-axo", "pid=,ppid=,rss=,time="], { encoding: "utf8", timeout: 5_000 });
    return output.split("\n").flatMap((line): ProcessRow[] => {
      const match = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$/.exec(line);
      if (!match) return [];
      return [{ pid: Number(match[1]), ppid: Number(match[2]), rssBytes: Number(match[3]) * 1024, cpuSeconds: parseCpuTime(match[4]!) }];
    });
  } catch {
    return [];
  }
}

function processTreeSample(rootPid: number): Omit<CorpusResourcePoint, "at"> {
  const rows = processRows();
  const selected = new Set([rootPid]);
  for (;;) {
    const before = selected.size;
    for (const row of rows) if (selected.has(row.ppid)) selected.add(row.pid);
    if (selected.size === before) break;
  }
  const tree = rows.filter((row) => selected.has(row.pid));
  return {
    rssBytes: tree.reduce((sum, row) => sum + row.rssBytes, 0),
    cpuSeconds: tree.reduce((sum, row) => sum + row.cpuSeconds, 0),
    processCount: tree.length,
  };
}

function cgroupOomKills(): number {
  const events = readText("/sys/fs/cgroup/memory.events");
  const match = events?.match(/^oom_kill\s+(\d+)$/m);
  return match ? Number(match[1]) : 0;
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function digest(value: unknown): string {
  return createHash("sha256").update(stable(value)).digest("hex");
}

export interface CorpusScorecard {
  rows: Array<{ slug?: string; check?: string; module?: string; detail?: string }>;
  findings: Record<string, unknown[]>;
  detectors: Record<string, unknown[]>;
  mechanicalContexts: Record<string, unknown>;
  mechanicalRuns: Record<string, unknown>;
  scannerRecords: Record<string, unknown[]>;
  dependencyPreparations: Record<string, unknown[]>;
  phaseSeconds: Record<string, Record<string, number>>;
  runtimeReceipts: Record<string, unknown>;
  currentMechanicalExecution?: CurrentMechanicalExecutionArtifact;
  [key: string]: unknown;
}

export function corpusTargetConservationVector(scorecard: CorpusScorecard, slug: string): Record<string, unknown> {
  const rows = scorecard.rows.filter((row) => row.slug === slug);
  const findings = scorecard.findings[slug] ?? [];
  const detectors = scorecard.detectors[slug] ?? [];
  const scannerRecords = scorecard.scannerRecords[slug] ?? [];
  const envelope = {
    rows,
    findings,
    detectors,
    mechanicalContext: scorecard.mechanicalContexts[slug],
    mechanicalRun: scorecard.mechanicalRuns[slug],
    scannerRecords,
    dependencyPreparations: scorecard.dependencyPreparations[slug] ?? [],
    phaseSeconds: scorecard.phaseSeconds[slug],
    runtime: scorecard.runtimeReceipts[slug],
    currentMechanical: scorecard.currentMechanicalExecution?.targets[slug],
  };
  return {
    slug,
    modules: [...new Set(rows.map((row) => row.module ?? row.check?.split(" ")[0]).filter(Boolean))].sort(),
    checks: rows.length,
    findings: findings.length,
    disclosures: findings.filter((finding) => {
      const value = finding as { confidence?: string; severity?: string };
      return value.confidence === "N/A" || value.severity === "Info";
    }).length,
    baselines: rows.filter((row) => String(row.check).includes("baseline")).length,
    examinedUnits: scannerRecords.reduce<number>((sum, record) => sum + Number((record as { scope?: { unitsExamined?: number } }).scope?.unitsExamined ?? 0), 0)
      + detectors.reduce<number>((sum, record) => sum + Number((record as { unitsExamined?: number }).unitsExamined ?? 0), 0),
    digest: digest(envelope),
  };
}

function parseScorecard(path: string, slug: string): CorpusScorecard {
  const value = JSON.parse(readFileSync(path, "utf8")) as Partial<CorpusScorecard>;
  for (const field of ["rows", "findings", "detectors", "mechanicalContexts", "mechanicalRuns", "scannerRecords", "dependencyPreparations", "phaseSeconds", "runtimeReceipts"] as const) {
    if (value[field] === undefined) throw new Error(`${slug}: worker result is missing complete ${field} evidence`);
  }
  const scorecard = value as CorpusScorecard & { conservation?: Record<string, unknown>[] };
  if (Object.keys(scorecard.findings).length !== 1 || !scorecard.findings[slug]) throw new Error(`${slug}: worker result owns a missing or foreign findings population`);
  if (scorecard.rows.some((row) => row.slug !== slug)) throw new Error(`${slug}: worker result contains a row for another target`);
  // A worker may serialize a conservation receipt, but the coordinator never trusts it as the
  // source of truth. Recompute it from the raw target/module/check/finding/disclosure/baseline/
  // examined-unit evidence before the result can join the shard aggregate.
  assertCorpusConservation(scorecard, scorecard);
  return scorecard;
}

export function aggregateCorpusWorkerResults(terminals: readonly CorpusWorkerTerminal[], expectedSlugs: readonly string[]): CorpusScorecard & { execution: CorpusExecutionManifest | undefined; conservation: Record<string, unknown>[] } {
  const ordered = [...terminals].sort((a, b) => a.ordinal - b.ordinal);
  if (ordered.length !== expectedSlugs.length) throw new Error(`terminal task population ${ordered.length} differs from expected ${expectedSlugs.length}`);
  const outputDirectories = new Set<string>();
  const ownedFiles = new Set<string>();
  for (const [ordinal, slug] of expectedSlugs.entries()) {
    const terminal = ordered[ordinal];
    if (!terminal || terminal.ordinal !== ordinal || terminal.slug !== slug) throw new Error(`terminal task order/population differs at ordinal ${ordinal}: expected ${slug}`);
    if (terminal.state !== "succeeded") throw new Error(`${slug}: target worker failed after all tasks settled: ${terminal.failure ?? `exit ${terminal.exitCode}`}`);
    const outputDir = realpathSync(terminal.outputDir);
    if (outputDirectories.has(outputDir)) throw new Error(`${slug}: target worker shares output directory ${outputDir}`);
    outputDirectories.add(outputDir);
    for (const path of [terminal.resultPath, terminal.stdoutPath, terminal.stderrPath, terminal.resourcePath]) {
      readFileSync(path);
      const owned = realpathSync(path);
      if (owned !== join(outputDir, owned.slice(outputDir.length + 1)) || !owned.startsWith(`${outputDir}/`)) {
        throw new Error(`${slug}: target worker artifact escapes its immutable output directory: ${path}`);
      }
      if (ownedFiles.has(owned)) throw new Error(`${slug}: target worker shares artifact path ${owned}`);
      ownedFiles.add(owned);
    }
  }
  const results = ordered.map((terminal) => parseScorecard(terminal.resultPath, terminal.slug));
  const firstCurrent = results.find((result) => result.currentMechanicalExecution)?.currentMechanicalExecution;
  let currentMechanicalExecution: CurrentMechanicalExecutionArtifact | undefined;
  if (firstCurrent) {
    const targets: CurrentMechanicalExecutionArtifact["targets"] = {};
    for (const result of results) {
      const current = result.currentMechanicalExecution;
      if (!current || stable({ ...current, executionId: "", commands: [], targets: {} }) !== stable({ ...firstCurrent, executionId: "", commands: [], targets: {} })) {
        throw new Error("target workers carry mixed or incomplete current-mechanical provenance");
      }
      for (const [slug, target] of Object.entries(current.targets)) {
        if (targets[slug]) throw new Error(`${slug}: current-mechanical target appears twice`);
        targets[slug] = target;
      }
    }
    currentMechanicalExecution = {
      ...firstCurrent,
      executionId: results.map((result) => result.currentMechanicalExecution!.executionId).join("+"),
      commands: results.flatMap((result) => result.currentMechanicalExecution!.commands),
      targets,
    };
  }
  const mergeMap = <T>(key: keyof CorpusScorecard): Record<string, T> => Object.assign({}, ...results.map((result) => result[key]));
  const aggregate: CorpusScorecard = {
    rows: results.flatMap((result) => result.rows),
    findings: mergeMap<unknown[]>("findings"),
    detectors: mergeMap<unknown[]>("detectors"),
    mechanicalContexts: mergeMap("mechanicalContexts"),
    mechanicalRuns: mergeMap("mechanicalRuns"),
    scannerRecords: mergeMap<unknown[]>("scannerRecords"),
    dependencyPreparations: mergeMap<unknown[]>("dependencyPreparations"),
    phaseSeconds: mergeMap<Record<string, number>>("phaseSeconds"),
    runtimeReceipts: mergeMap("runtimeReceipts"),
    ...(currentMechanicalExecution ? { currentMechanicalExecution } : {}),
  };
  return { ...aggregate, execution: undefined, conservation: expectedSlugs.map((slug) => corpusTargetConservationVector(aggregate, slug)) };
}

export async function executeCorpusTargetWorkers(options: WorkerOptions): Promise<{ manifest: CorpusExecutionManifest; scorecard?: ReturnType<typeof aggregateCorpusWorkerResults> }> {
  if (options.design === "split-carbon") {
    throw new Error("split-carbon is non-admissible: this coordinator has no independent runner lane for that design");
  }
  const now = options.now ?? (() => new Date());
  const startedAt = now();
  const resourceAdmission = admitCorpusConcurrency(options.requestedConcurrency, options.slugs.length, options.environment);
  const admission: CorpusAdmissionReceipt = options.design === "target-workers"
    ? resourceAdmission
    : options.design === "intra-target-overlap"
      ? { ...resourceAdmission, targetWorkers: 1, scannerLanes: Math.min(2, resourceAdmission.effective), reasons: [...resourceAdmission.reasons, "intra-target-overlap holds target workers at 1 and admits at most 2 scanner lanes"] }
      : { ...resourceAdmission, effective: 1, targetWorkers: 1, scannerLanes: 1, reasons: [...resourceAdmission.reasons, `${options.design} holds this coordinator to one serial target worker`] };
  mkdirSync(options.artifactsDir, { recursive: true });
  const oomBefore = cgroupOomKills();
  let cursor = 0;

  const runOne = async (): Promise<CorpusWorkerTerminal[]> => {
    const owned: CorpusWorkerTerminal[] = [];
    for (;;) {
      const ordinal = cursor++;
      const slug = options.slugs[ordinal];
      if (!slug) return owned;
      const outputDir = resolve(options.artifactsDir, `${ordinal.toString().padStart(3, "0")}-${slug}`);
      mkdirSync(join(outputDir, "tmp"), { recursive: true });
      const resultPath = join(outputDir, "result.json");
      const stdoutPath = join(outputDir, "stdout.log");
      const stderrPath = join(outputDir, "stderr.log");
      const resourcePath = join(outputDir, "resource-trace.json");
      const taskStarted = now();
      const childArgs = [
        ...process.execArgv,
        options.scriptPath,
        ...options.baseArgs,
        "--target", slug,
        "--target-worker",
        "--json", resultPath,
        "--target-concurrency", String(options.requestedConcurrency),
        "--execution-design", options.design,
        "--cache-profile", options.profile,
      ];
      if (options.failAfterStart === slug) childArgs.push("--fail-after-start", slug);
      const child = spawn(process.execPath, childArgs, {
        cwd: options.repoRoot,
        env: {
          ...process.env,
          ...options.environment,
          TMPDIR: join(outputDir, "tmp"),
          HARVEY_LIVENESS_RECEIPT: join(outputDir, "liveness.receipt"),
        },
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
      child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
      const resources: CorpusResourcePoint[] = [];
      const sample = (): void => {
        if (!child.pid) return;
        resources.push({ at: now().toISOString(), ...processTreeSample(child.pid) });
      };
      sample();
      const timer = setInterval(sample, 1_000);
      const terminal = await new Promise<CorpusWorkerTerminal>((resolveTerminal) => {
        let spawnFailure: string | undefined;
        child.once("error", (error) => { spawnFailure = error.message; });
        child.once("close", (exitCode, signal) => {
          clearInterval(timer);
          sample();
          const out = Buffer.concat(stdout);
          const err = Buffer.concat(stderr);
          writeFileSync(stdoutPath, out);
          writeFileSync(stderrPath, err);
          writeFileSync(resourcePath, `${JSON.stringify(resources, null, 2)}\n`);
          const text = `${out.toString("utf8")}\n${err.toString("utf8")}`;
          const peakRssBytes = Math.max(0, ...resources.map((point) => point.rssBytes));
          const cpuSeconds = Math.max(0, ...resources.map((point) => point.cpuSeconds));
          const oomDetected = signal === "SIGKILL" || /\b(?:out of memory|oom-kill)\b/i.test(text);
          const retryDetected = /\b(?:retrying|retry attempt)\b/i.test(text);
          const state = exitCode === 0 && !signal && !spawnFailure && !oomDetected && !retryDetected ? "succeeded" : "failed";
          resolveTerminal({
            ordinal,
            slug,
            state,
            pid: child.pid,
            startedAt: taskStarted.toISOString(),
            finishedAt: now().toISOString(),
            exitCode,
            signal,
            outputDir,
            resultPath,
            stdoutPath,
            stderrPath,
            resourcePath,
            peakRssBytes,
            cpuSeconds,
            oomDetected,
            retryDetected,
            ...(state === "failed" ? { failure: spawnFailure ?? (oomDetected ? "OOM detected" : retryDetected ? "retry detected" : `exit ${exitCode}${signal ? ` signal ${signal}` : ""}`) } : {}),
          });
        });
      });
      owned.push(terminal);
    }
  };

  const settled = await Promise.allSettled(Array.from({ length: admission.targetWorkers }, () => runOne()));
  const terminals = settled.flatMap((result) => result.status === "fulfilled" ? result.value : []);
  for (const [index, result] of settled.entries()) {
    if (result.status === "rejected") {
      terminals.push({
        ordinal: options.slugs.length + index,
        slug: `<scheduler-${index}>`,
        state: "failed",
        startedAt: startedAt.toISOString(),
        finishedAt: now().toISOString(),
        exitCode: null,
        signal: null,
        outputDir: options.artifactsDir,
        resultPath: "",
        stdoutPath: "",
        stderrPath: "",
        resourcePath: "",
        peakRssBytes: 0,
        cpuSeconds: 0,
        oomDetected: false,
        retryDetected: false,
        failure: result.reason instanceof Error ? result.reason.message : String(result.reason),
      });
    }
  }
  terminals.sort((a, b) => a.ordinal - b.ordinal);
  const oomAfter = cgroupOomKills();
  if (oomAfter > oomBefore) for (const terminal of terminals) terminal.oomDetected = true;
  const finishedAt = now();
  const durations = terminals.map((terminal) => Date.parse(terminal.finishedAt) - Date.parse(terminal.startedAt));
  const manifest: CorpusExecutionManifest = {
    schema: 1,
    design: options.design,
    profile: options.profile,
    shard: options.shard,
    admission,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    terminals,
    aggregate: {
      criticalPathMs: finishedAt.getTime() - startedAt.getTime(),
      summedWorkerMs: durations.reduce((sum, duration) => sum + duration, 0),
      peakRssBytes: conservativePeakRssBytes(terminals),
      cpuSeconds: terminals.reduce((sum, terminal) => sum + terminal.cpuSeconds, 0),
      oomCount: terminals.filter((terminal) => terminal.oomDetected).length,
      retryCount: terminals.filter((terminal) => terminal.retryDetected).length,
    },
  };
  writeFileSync(join(options.artifactsDir, "execution-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  if (terminals.some((terminal) => terminal.state === "failed" || terminal.oomDetected || terminal.retryDetected)) return { manifest };
  return { manifest, scorecard: aggregateCorpusWorkerResults(terminals, options.slugs) };
}

export function assertCorpusConservation(left: CorpusScorecard & { conservation?: Record<string, unknown>[] }, right: CorpusScorecard & { conservation?: Record<string, unknown>[] }): void {
  const vectors = (scorecard: CorpusScorecard & { conservation?: Record<string, unknown>[] }): Record<string, unknown>[] => {
    const slugs = new Set<string>([
      ...scorecard.rows.map((row) => row.slug).filter((slug): slug is string => Boolean(slug)),
      ...Object.keys(scorecard.findings),
      ...Object.keys(scorecard.detectors),
      ...Object.keys(scorecard.mechanicalContexts),
      ...Object.keys(scorecard.mechanicalRuns),
      ...Object.keys(scorecard.scannerRecords),
      ...Object.keys(scorecard.dependencyPreparations),
      ...Object.keys(scorecard.phaseSeconds),
      ...Object.keys(scorecard.runtimeReceipts),
      ...Object.keys(scorecard.currentMechanicalExecution?.targets ?? {}),
    ]);
    const recomputed = [...slugs].sort().map((slug) => corpusTargetConservationVector(scorecard, slug));
    if (scorecard.conservation && stable(scorecard.conservation) !== stable(recomputed)) {
      throw new Error("stored corpus conservation differs from its raw target/module/check/finding/disclosure/baseline/examined-unit evidence");
    }
    return recomputed;
  };
  const leftVectors = vectors(left);
  const rightVectors = vectors(right);
  if (stable(leftVectors) !== stable(rightVectors)) throw new Error("serial/concurrent corpus conservation differs by target/module/check/finding/disclosure/baseline/examined-unit or evidence digest");
}
