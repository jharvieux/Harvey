import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import type { CorpusExecutionManifest } from "../corpus-execution.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const directory = mkdtempSync(join(tmpdir(), "harvey-corpus-cli-failure-"));
const artifacts = join(directory, "workers");
const benchmarkArtifacts = join(directory, "benchmark-workers");
const worker = join(directory, "fixture-worker.mjs");

afterAll(() => rmSync(directory, { recursive: true, force: true }));

writeFileSync(worker, `
import { writeFileSync } from "node:fs";
const args = process.argv.slice(2);
const flag = name => { const index = args.indexOf(name); return index < 0 ? undefined : args[index + 1]; };
const slug = flag("--target");
const out = flag("--json");
const failed = flag("--fail-after-start") === slug;
await new Promise(resolve => setTimeout(resolve, failed ? 5 : 25));
console.error((failed ? "FAILED " : "SUCCEEDED ") + slug + " " + "retained-log ".repeat(500));
if (failed) process.exit(7);
const finding = { id: slug + "-finding", confidence: "High", severity: "High", title: slug };
writeFileSync(out, JSON.stringify({
  rows: [{ slug, check: "M1 baseline", module: "M1", pass: true, detail: slug + " baseline" }],
  findings: { [slug]: [finding] },
  detectors: { [slug]: [{ detector: "fixture", unitsExamined: 2 }] },
  mechanicalContexts: { [slug]: { filesExamined: 1 } },
  mechanicalRuns: { [slug]: { findings: [finding], executionPlan: { families: ["fixture"] }, semgrepDiagnostics: { errors: [], skipped: [] } } },
  scannerRecords: { [slug]: [{ scanner: "detect-static", cache: "non-cacheable", reason: "fixture fresh", scope: { unitsExamined: 3 } }] },
  dependencyPreparations: { [slug]: [{ status: "non-cacheable", reason: "fixture dependency evidence" }] },
  phaseSeconds: { [slug]: { scan: 1 } },
  runtimeReceipts: { [slug]: { node: process.version, pnpm: "fixture" } }
}) + "\\n");
`);

function runPiped(failureSlug: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn("node_modules/.bin/tsx", [
      "src/cli/corpus-drift.ts",
      "--target-concurrency", "3",
      "--execution-design", "target-workers",
      "--worker-artifacts-dir", artifacts,
      "--fail-after-start", failureSlug,
    ], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        NODE_ENV: "test",
        HARVEY_CORPUS_TEST_MODE: "1",
        HARVEY_CORPUS_TEST_WORKER_SCRIPT: worker,
        HARVEY_CORPUS_CPU_LIMIT: "8",
        HARVEY_CORPUS_MEMORY_LIMIT_BYTES: "12000000000",
        HARVEY_CORPUS_MEMORY_PER_WORKER_BYTES: "1000000000",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.once("error", rejectRun);
    child.once("close", (code) => resolveRun({ code, stdout, stderr }));
  });
}

function runBenchmarkBoundary(mode: "live" | "live-verify" | "snapshot"): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn("node_modules/.bin/tsx", [
      "src/cli/corpus-drift.ts",
      "--target-concurrency", "3",
      "--execution-design", "target-workers",
      "--worker-artifacts-dir", benchmarkArtifacts,
    ], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        NODE_ENV: "test",
        HARVEY_CORPUS_TEST_MODE: "1",
        HARVEY_CORPUS_TEST_WORKER_SCRIPT: worker,
        HARVEY_CORPUS_CPU_LIMIT: "8",
        HARVEY_CORPUS_MEMORY_LIMIT_BYTES: "12000000000",
        HARVEY_CORPUS_MEMORY_PER_WORKER_BYTES: "1000000000",
        HARVEY_CORPUS_BENCHMARK_RUN_IDENTITY: "hosted-seed-or-sample",
        HARVEY_CORPUS_EXTERNAL_STATE_MODE: mode,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.once("error", rejectRun);
    child.once("close", (code) => resolveRun({ code, stdout, stderr }));
  });
}

describe("corpus-drift spawned all-settled failure control", () => {
  it("retains every terminal receipt/log and the final failure banner through piped stdio", async () => {
    const failureSlug = EXTERNAL_CORPUS[0]!.slug;
    const result = await runPiped(failureSlug);
    expect(result.code).toBe(1);
    const banner = `CORPUS TARGET AGGREGATION FAILED AFTER ALL ${EXTERNAL_CORPUS.length} TERMINAL TASKS WERE COLLECTED`;
    expect(result.stderr).toContain(banner);
    expect(result.stderr.trimEnd().endsWith(`manifest: ${join(artifacts, "execution-manifest.json")}`)).toBe(true);

    const manifestPath = join(artifacts, "execution-manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as CorpusExecutionManifest;
    expect(manifest.terminals).toHaveLength(EXTERNAL_CORPUS.length);
    expect(manifest.terminals.filter((terminal) => terminal.state === "failed")).toEqual([
      expect.objectContaining({ slug: failureSlug, exitCode: 7 }),
    ]);
    expect(manifest.terminals.at(-1)).toMatchObject({ state: "succeeded" });
    expect(Date.parse(manifest.terminals.find((terminal) => terminal.slug === failureSlug)!.finishedAt)).toBeLessThan(Date.parse(manifest.finishedAt));
    for (const terminal of manifest.terminals) {
      expect(existsSync(terminal.stdoutPath), `${terminal.slug} stdout`).toBe(true);
      expect(existsSync(terminal.stderrPath), `${terminal.slug} stderr`).toBe(true);
      expect(existsSync(terminal.resourcePath), `${terminal.slug} resource trace`).toBe(true);
      expect(readFileSync(terminal.stderrPath, "utf8"), `${terminal.slug} retained log`).toContain("retained-log");
    }
  });

  it("rejects mutable external state before a benchmark worker starts and accepts snapshot mode", async () => {
    for (const mode of ["live", "live-verify"] as const) {
      const rejected = await runBenchmarkBoundary(mode);
      expect(rejected.code).toBe(2);
      expect(rejected.stderr).toContain("benchmark seed/sample runs cannot consume mutable live advisory state");
      expect(existsSync(join(benchmarkArtifacts, "execution-manifest.json"))).toBe(false);
    }

    const accepted = await runBenchmarkBoundary("snapshot");
    expect(accepted.code).toBe(0);
    expect(accepted.stderr).toContain("CORPUS TARGET AGGREGATION PASS");
    const manifest = JSON.parse(readFileSync(join(benchmarkArtifacts, "execution-manifest.json"), "utf8")) as CorpusExecutionManifest;
    expect(manifest.terminals).toHaveLength(EXTERNAL_CORPUS.length);
    expect(manifest.terminals.every((terminal) => terminal.state === "succeeded")).toBe(true);
  });
});
