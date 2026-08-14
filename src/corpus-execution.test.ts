import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  admitCorpusConcurrency,
  aggregateCorpusWorkerResults,
  assertCorpusConservation,
  conservativePeakRssBytes,
  executeCorpusTargetWorkers,
  runBoundedCorpusTasks,
} from "./corpus-execution.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporary(prefix: string): string {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

function fakeWorker(directory: string): string {
  const path = join(directory, "fake-corpus-worker.mjs");
  writeFileSync(path, `
import { writeFileSync } from "node:fs";
const args = process.argv.slice(2);
const flag = name => { const index = args.indexOf(name); return index < 0 ? undefined : args[index + 1]; };
const slug = flag("--target");
const out = flag("--json");
const shard = flag("--shard");
const delays = JSON.parse(process.env.FAKE_DELAYS ?? "{}");
await new Promise(resolve => setTimeout(resolve, Number(delays[slug] ?? 5)));
if (flag("--fail-after-start") === slug) { console.error("planted post-start failure " + slug); process.exit(7); }
if (process.env.FAKE_RETRY_SLUG === slug) console.error("retrying planted worker");
if (process.env.FAKE_OOM_SLUG === slug) console.error("out of memory planted worker");
const finding = { id: slug + "-finding", confidence: "High", severity: "High", title: slug };
writeFileSync(out, JSON.stringify({
  rows: [{ slug, check: "M1 baseline", module: "M1", pass: true, detail: slug + " baseline" }],
  findings: { [slug]: [finding] },
  detectors: { [slug]: [{ detector: "fake", unitsExamined: 2 }] },
  mechanicalContexts: { [slug]: { filesExamined: 1, evidence: slug + " context" } },
  mechanicalRuns: { [slug]: { findings: [finding], evidence: slug + " mechanical", executionPlan: { families: ["auth"] }, semgrepDiagnostics: { errors: [], skipped: [] } } },
  scannerRecords: { [slug]: [{ scanner: "detect-static", cache: "non-cacheable", reason: "fresh evidence", scope: { unitsExamined: 3 }, evidence: slug + " scanner" }] },
  dependencyPreparations: { [slug]: [{ digest: slug + " dependency" }] },
  phaseSeconds: { [slug]: { scan: 1 } },
  runtimeReceipts: { [slug]: { node: "v24", pnpm: "10" } },
  ...(process.env.FAKE_CURRENT === "1" ? { currentMechanicalExecution: {
    executionId: "worker:" + slug,
    commands: ["fake " + slug],
    shard: { index: Number(shard.split("/")[0]), count: Number(shard.split("/")[1]) },
    targets: { [slug]: { slug } }
  } } : {})
}) + "\\n");
console.log("worker stdout " + slug + " shard " + shard);
console.error("worker stderr " + slug);
`);
  return path;
}

function executionOptions(directory: string, slugs: string[], requestedConcurrency: number) {
  return {
    repoRoot: directory,
    scriptPath: fakeWorker(directory),
    baseArgs: [],
    slugs,
    requestedConcurrency,
    design: requestedConcurrency === 1 ? "serial" as const : "target-workers" as const,
    profile: "warm" as const,
    shard: { index: 1, count: 3 },
    artifactsDir: join(directory, "artifacts"),
    environment: {
      ...process.env,
      HARVEY_CORPUS_CPU_LIMIT: "8",
      HARVEY_CORPUS_MEMORY_LIMIT_BYTES: "12000000000",
      HARVEY_CORPUS_MEMORY_PER_WORKER_BYTES: "1000000000",
    },
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe("#1873 bounded corpus target execution", () => {
  it("sums only worker peaks whose execution intervals overlap", () => {
    const at = (seconds: number): string => new Date(Date.UTC(2026, 7, 12, 0, 0, seconds)).toISOString();
    expect(conservativePeakRssBytes([
      { startedAt: at(0), finishedAt: at(20), peakRssBytes: 400 },
      { startedAt: at(10), finishedAt: at(30), peakRssBytes: 600 },
    ])).toBe(1_000);
    expect(conservativePeakRssBytes([
      { startedAt: at(0), finishedAt: at(10), peakRssBytes: 400 },
      { startedAt: at(10), finishedAt: at(20), peakRssBytes: 600 },
    ])).toBe(600);
  });

  it("overlaps at most the admitted scanner lanes and preserves declaration order", async () => {
    const exercise = async (concurrency: number): Promise<{ results: string[]; peak: number }> => {
      let active = 0;
      let peak = 0;
      const tasks = [40, 5, 10].map((delay, ordinal) => async () => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, delay));
        active -= 1;
        return `task-${ordinal}`;
      });
      return { results: await runBoundedCorpusTasks(tasks, concurrency), peak };
    };
    expect(await exercise(1)).toEqual({ results: ["task-0", "task-1", "task-2"], peak: 1 });
    expect(await exercise(2)).toEqual({ results: ["task-0", "task-1", "task-2"], peak: 2 });
    await expect(runBoundedCorpusTasks([], 0)).rejects.toThrow(/positive integer/);
  });

  it("settles every sibling and keeps scheduling after a rejection before it fails", async () => {
    const completed: number[] = [];
    const tasks = [
      async () => { await new Promise((resolve) => setTimeout(resolve, 5)); completed.push(0); throw new Error("planted lane failure"); },
      async () => { await new Promise((resolve) => setTimeout(resolve, 25)); completed.push(1); return "one"; },
      async () => { completed.push(2); return "two"; },
      async () => { completed.push(3); return "three"; },
    ];

    await expect(runBoundedCorpusTasks(tasks, 2)).rejects.toThrow(/all tasks settled.*ordinal\(s\) 0/);
    expect(completed.sort()).toEqual([0, 1, 2, 3]);
  });

  it("reduces effective concurrency when either measured CPU or memory is lower", () => {
    const high = admitCorpusConcurrency(3, 5, {
      HARVEY_CORPUS_CPU_LIMIT: "8",
      HARVEY_CORPUS_MEMORY_LIMIT_BYTES: "12000000000",
      HARVEY_CORPUS_MEMORY_PER_WORKER_BYTES: "1000000000",
    });
    const lowCpu = admitCorpusConcurrency(3, 5, {
      HARVEY_CORPUS_CPU_LIMIT: "1.9",
      HARVEY_CORPUS_MEMORY_LIMIT_BYTES: "12000000000",
      HARVEY_CORPUS_MEMORY_PER_WORKER_BYTES: "1000000000",
    });
    const lowMemory = admitCorpusConcurrency(3, 5, {
      HARVEY_CORPUS_CPU_LIMIT: "8",
      HARVEY_CORPUS_MEMORY_LIMIT_BYTES: "1999999999",
      HARVEY_CORPUS_MEMORY_PER_WORKER_BYTES: "1000000000",
    });
    expect(high.effective).toBe(3);
    expect(lowCpu.effective).toBe(1);
    expect(lowMemory.effective).toBe(1);
    expect(lowCpu.cpuSource).toBe("HARVEY_CORPUS_CPU_LIMIT");
    expect(lowMemory.memorySource).toBe("HARVEY_CORPUS_MEMORY_LIMIT_BYTES");
  });

  it("aggregates reverse completion in ordinal target order with isolated complete artifacts", async () => {
    const directory = temporary("corpus-workers-order-");
    const execution = await executeCorpusTargetWorkers({
      ...executionOptions(directory, ["alpha", "beta", "gamma"], 3),
      environment: { ...process.env, HARVEY_CORPUS_CPU_LIMIT: "8", HARVEY_CORPUS_MEMORY_LIMIT_BYTES: "12000000000", HARVEY_CORPUS_MEMORY_PER_WORKER_BYTES: "1000000000", FAKE_DELAYS: JSON.stringify({ alpha: 120, beta: 70, gamma: 10 }) },
    });
    expect(execution.manifest.terminals.map((terminal) => terminal.slug)).toEqual(["alpha", "beta", "gamma"]);
    const oomKills = execution.manifest.oomKills;
    expect(oomKills?.source).toBe("/sys/fs/cgroup/memory.events");
    expect(oomKills?.before === null || typeof oomKills?.before === "number").toBe(true);
    expect(oomKills?.after === null || typeof oomKills?.after === "number").toBe(true);
    expect(execution.manifest.terminals.map((terminal) => terminal.outputDir)).toHaveLength(new Set(execution.manifest.terminals.map((terminal) => terminal.outputDir)).size);
    expect(execution.scorecard?.rows.map((row) => row.slug)).toEqual(["alpha", "beta", "gamma"]);
    for (const terminal of execution.manifest.terminals) {
      expect(readFileSync(terminal.stdoutPath, "utf8")).toContain(`worker stdout ${terminal.slug}`);
      expect(readFileSync(terminal.stderrPath, "utf8")).toContain(`worker stderr ${terminal.slug}`);
      expect(existsSync(terminal.resourcePath)).toBe(true);
    }
  });

  it("binds every child and merged current-mechanical evidence to the parent shard", async () => {
    const directory = temporary("corpus-workers-parent-shard-");
    const base = executionOptions(directory, ["alpha", "beta"], 2);
    const execution = await executeCorpusTargetWorkers({
      ...base,
      environment: { ...base.environment, FAKE_CURRENT: "1" },
    });
    expect(execution.scorecard?.currentMechanicalExecution?.shard).toEqual({ index: 1, count: 3 });
    expect(Object.keys(execution.scorecard?.currentMechanicalExecution?.targets ?? {})).toEqual(["alpha", "beta"]);
    for (const terminal of execution.manifest.terminals) {
      expect(readFileSync(terminal.stdoutPath, "utf8")).toContain(`worker stdout ${terminal.slug} shard 1/3`);
    }
  });

  it("collects every terminal task before reporting an injected post-start failure", async () => {
    const directory = temporary("corpus-workers-failure-");
    const execution = await executeCorpusTargetWorkers({
      ...executionOptions(directory, ["fails", "slow-a", "slow-b"], 3),
      failAfterStart: "fails",
      environment: { ...process.env, HARVEY_CORPUS_CPU_LIMIT: "8", HARVEY_CORPUS_MEMORY_LIMIT_BYTES: "12000000000", HARVEY_CORPUS_MEMORY_PER_WORKER_BYTES: "1000000000", FAKE_DELAYS: JSON.stringify({ fails: 5, "slow-a": 120, "slow-b": 150 }) },
    });
    expect(execution.scorecard).toBeUndefined();
    expect(execution.manifest.terminals).toHaveLength(3);
    expect(execution.manifest.terminals.map((terminal) => terminal.state)).toEqual(["failed", "succeeded", "succeeded"]);
    expect(Date.parse(execution.manifest.terminals[0]!.finishedAt)).toBeLessThan(Date.parse(execution.manifest.finishedAt));
    expect(readFileSync(join(directory, "artifacts", "execution-manifest.json"), "utf8")).toContain('"slug": "slow-b"');
  });

  it.each([
    ["retry", { FAKE_RETRY_SLUG: "alpha" }],
    ["OOM", { FAKE_OOM_SLUG: "alpha" }],
  ])("rejects a successful child that reports a %s", async (_label, planted) => {
    const directory = temporary("corpus-workers-resource-regression-");
    const execution = await executeCorpusTargetWorkers({
      ...executionOptions(directory, ["alpha"], 1),
      environment: { ...executionOptions(directory, ["alpha"], 1).environment, ...planted },
    });
    expect(execution.scorecard).toBeUndefined();
    expect(execution.manifest.terminals[0]).toMatchObject({ state: "failed" });
  });

  it("rejects shared paths, missing logs, and a reordered terminal population in both guard directions", async () => {
    const directory = temporary("corpus-workers-paths-");
    const execution = await executeCorpusTargetWorkers(executionOptions(directory, ["alpha", "beta"], 2));
    expect(execution.scorecard).toBeDefined();
    const terminals = execution.manifest.terminals;
    expect(() => aggregateCorpusWorkerResults(terminals, ["alpha", "beta"])).not.toThrow();

    const shared = clone(terminals);
    shared[1]!.stdoutPath = shared[0]!.stdoutPath;
    expect(() => aggregateCorpusWorkerResults(shared, ["alpha", "beta"])).toThrow(/escapes|shares artifact path/);

    const reordered = clone(terminals);
    [reordered[0]!.ordinal, reordered[1]!.ordinal] = [reordered[1]!.ordinal, reordered[0]!.ordinal];
    expect(() => aggregateCorpusWorkerResults(reordered, ["alpha", "beta"])).toThrow(/order\/population differs/);
    const relabeled = clone(terminals);
    [relabeled[0]!.slug, relabeled[1]!.slug] = [relabeled[1]!.slug, relabeled[0]!.slug];
    expect(() => aggregateCorpusWorkerResults(relabeled, ["alpha", "beta"])).toThrow(/order\/population differs/);

    const missing = clone(terminals);
    rmSync(missing[1]!.stderrPath);
    expect(() => aggregateCorpusWorkerResults(missing, ["alpha", "beta"])).toThrow();
  });

  it("fails conservation symmetrically for rows, findings, disclosures, baselines, examined units, and evidence", async () => {
    const directory = temporary("corpus-workers-conservation-");
    const execution = await executeCorpusTargetWorkers(executionOptions(directory, ["alpha"], 1));
    const baseline = execution.scorecard!;
    expect(() => assertCorpusConservation(baseline, clone(baseline))).not.toThrow();

    const mutations: Array<(value: typeof baseline) => void> = [
      (value) => { value.rows[0]!.detail = "changed row"; },
      (value) => { (value.findings.alpha![0] as { title: string }).title = "changed finding"; },
      (value) => { (value.findings.alpha![0] as { confidence: string }).confidence = "N/A"; },
      (value) => { value.rows[0]!.check = "M1 assertion"; },
      (value) => { (value.scannerRecords.alpha![0] as { scope: { unitsExamined: number } }).scope.unitsExamined = 99; },
      (value) => { (value.mechanicalRuns.alpha as { evidence: string }).evidence = "changed evidence"; },
      (value) => { value.scannerRecords.alpha!.pop(); },
      (value) => { value.dependencyPreparations.alpha!.pop(); },
      (value) => { delete (value.mechanicalRuns.alpha as { executionPlan?: unknown }).executionPlan; },
      (value) => { delete (value.mechanicalRuns.alpha as { semgrepDiagnostics?: unknown }).semgrepDiagnostics; },
      (value) => { value.detectors.alpha!.pop(); },
    ];
    for (const mutate of mutations) {
      const changed = clone(baseline);
      mutate(changed);
      expect(() => assertCorpusConservation(baseline, changed)).toThrow(/conservation differs/);
      expect(() => assertCorpusConservation(changed, baseline)).toThrow(/conservation differs/);
    }
  });
});
