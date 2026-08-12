import "./sync-stdio.js";
import { spawn } from "node:child_process";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { arg, assertKnownFlags } from "./args.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import {
  aggregateM8TargetResults,
  buildM8CorpusPlan,
  m8PhasesFromOutput,
  parseM8TargetResult,
  type M8TargetResult,
} from "../scan/m8-corpus-artifacts.js";
import { M8_CORPUS_CONFIGS } from "../scan/m8-corpus.js";
import { readRecursiveSafe } from "../fs-walk.js";

assertKnownFlags(["--github-output", "--target", "--out", "--artifacts"]);

const mode = process.argv.slice(2).find((token) => !token.startsWith("--"));
const plan = buildM8CorpusPlan(EXTERNAL_CORPUS, M8_CORPUS_CONFIGS);

function required(flag: string): string {
  const value = arg(flag);
  if (!value) {
    console.error(`${mode ?? "corpus-m8"}: ${flag} is required`);
    process.exit(2);
  }
  return resolve(value);
}

if (mode === "plan") {
  const githubOutput = required("--github-output");
  appendFileSync(githubOutput, `matrix=${JSON.stringify({ target: plan.configured })}\n`);
  appendFileSync(githubOutput, `configured-count=${plan.configured.length}\n`);
  appendFileSync(githubOutput, `unconfigured-count=${plan.unconfigured.length}\n`);
  console.error(`M8 PLAN: ${plan.configured.length} mutation target(s), ${plan.unconfigured.length} target(s) with counted non-mutation reasons`);
  process.exit(0);
}

if (mode === "target") {
  const target = arg("--target");
  const out = required("--out");
  if (!target || !plan.configured.includes(target)) {
    console.error(`target: --target must name one configured M8 target (${plan.configured.join(", ")})`);
    process.exit(2);
  }
  mkdirSync(dirname(out), { recursive: true });
  const scorecardPath = join(dirname(out), `scorecard-${target}.json`);
  const started = performance.now();
  const run = spawn(
    "pnpm",
    ["corpus-drift", "--target", target, "--install", "--m8", "--json", scorecardPath],
    { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  let mutationCliStartedMs: number | undefined;
  for (const stream of [run.stdout, run.stderr]) {
    stream.setEncoding("utf8");
    stream.on("data", (chunk: string) => {
      output += chunk;
      process.stderr.write(chunk);
      if (mutationCliStartedMs === undefined && output.includes("src/cli/mutation-scan.ts")) {
        mutationCliStartedMs = performance.now() - started;
      }
    });
  }
  const { exitCode, signal, error: runError } = await new Promise<{ exitCode: number; signal: string | null; error?: string }>((done) => {
    let error: string | undefined;
    run.once("error", (err) => { error = err.message; });
    run.once("close", (code, closeSignal) => done({ exitCode: code ?? 1, signal: closeSignal, ...(error ? { error } : {}) }));
  });
  const durationMs = performance.now() - started;
  let scorecard: M8TargetResult["scorecard"] = null;
  let phases: M8TargetResult["phases"] = null;
  let parseError: string | undefined;
  try {
    scorecard = JSON.parse(readFileSync(scorecardPath, "utf8")) as NonNullable<M8TargetResult["scorecard"]>;
    if (mutationCliStartedMs === undefined) throw new Error("mutation CLI start marker was not emitted");
    phases = m8PhasesFromOutput(output, target, durationMs, mutationCliStartedMs);
  } catch (error) {
    parseError = `scorecard unavailable or corrupt: ${(error as Error).message}`;
  }
  const status = exitCode === 0 && !parseError ? "passed" : "failed";
  const result: M8TargetResult = {
    schemaVersion: 1,
    target,
    status,
    exitCode,
    durationMs,
    phases,
    scorecard,
    ...(parseError || runError || signal ? { error: [parseError, runError, signal ? `terminated by ${signal}` : undefined].filter(Boolean).join("; ") } : {}),
  };
  writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`);
  console.error(`M8 TARGET ${status.toUpperCase()}: ${target} in ${(durationMs / 1000).toFixed(1)}s — verdict deferred to aggregate`);
  process.exit(0);
}

if (mode === "aggregate") {
  const artifactsDir = required("--artifacts");
  const out = required("--out");
  const paths = readRecursiveSafe(artifactsDir)
    .filter((path) => basename(path) === "result.json")
    .map((path) => join(artifactsDir, path))
    .sort();
  const results = paths.map((path) => parseM8TargetResult(readFileSync(path, "utf8"), basename(resolve(path, ".."))));
  const report = aggregateM8TargetResults(plan, results);
  writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
  for (const target of report.targets) {
    const phases = target.phases
      ? Object.entries(target.phases).map(([phase, ms]) => `${phase} ${(ms / 1000).toFixed(1)}s`).join(", ")
      : "phase timings unavailable because the target failed before writing a scorecard";
    console.error(`  ${target.status === "passed" ? "✓" : "✗"} ${target.target}: ${phases}`);
  }
  for (const target of report.unconfiguredTargets) console.error(`  ↷ ${target.target}: COUNTED NOT MUTATION-SCORED — ${target.reason}`);
  console.error(`M8 CRITICAL PATH: ${report.criticalPath.target} ${(report.criticalPath.durationMs / 1000).toFixed(1)}s`);
  console.error(`M8 AGGREGATE RUNNER COST: ${(report.aggregateRunnerCostMs / 1000).toFixed(1)} runner-seconds`);
  console.error(`M8 AGGREGATE: ${report.passed}/${report.targets.length} configured target(s) passed; ${report.unconfiguredTargets.length} counted non-mutation reason(s)`);
  process.exit(report.ok ? 0 : 1);
}

console.error("usage: pnpm exec tsx src/cli/corpus-m8.ts <plan|target|aggregate> [options]");
process.exit(2);
