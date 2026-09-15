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
import { createBoundedLineRedactor, redactSecrets } from "../secret-redact.js";

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

function failureExcerpt(output: string): string {
  const safe = redactSecrets(output).trim();
  const lines = safe.split("\n");
  // Preparation reports combine manager identity and multiline child causes. Bound these
  // independently to retain the selected manager and first cause alongside the final error marker.
  const stages = [...new Set(lines.filter((line) => /tool-install|tool installation failed/i.test(line)).map((line) => line.slice(0, 600)))];
  const causes = [...new Set(lines.filter((line) => /\bERR_[A-Z0-9_]+|\berror\s*:/i.test(line)).map((line) => line.slice(0, 400)))];
  const retained = [...new Set([...stages.slice(0, 1), ...stages.slice(-1), ...causes.slice(0, 2), ...causes.slice(-2)])];
  const tail = safe.slice(-1000);
  return [...retained.filter((line) => !tail.includes(line)), tail].join("\n");
}

const MAX_FORWARDED_LINE_CHARS = 64 * 1024;
const MAX_CAPTURED_TAIL_CHARS = 32 * 1024;

interface DiagnosticCapture {
  tail: string;
  noteworthy: string[];
}

function captureDiagnostic(capture: DiagnosticCapture, redacted: string): void {
  capture.tail = `${capture.tail}${redacted}`.slice(-MAX_CAPTURED_TAIL_CHARS);
  if (!/tool-install|tool installation failed|\bERR_[A-Z0-9_]+|\berror\s*:/i.test(redacted)) return;
  const bounded = redacted.slice(0, 1000);
  if (!capture.noteworthy.includes(bounded)) capture.noteworthy = [...capture.noteworthy.slice(-7), bounded];
}

function capturedDiagnostic(capture: DiagnosticCapture): string {
  return `${capture.noteworthy.join("\n")}\n${capture.tail}`;
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
  let timingOutput = "";
  const streamCapture: Record<"stdout" | "stderr", DiagnosticCapture> = {
    stdout: { tail: "", noteworthy: [] },
    stderr: { tail: "", noteworthy: [] },
  };
  const markerTail = { stdout: "", stderr: "" };
  const mutationMarker = "src/cli/mutation-scan.ts";
  let mutationCliStartedMs: number | undefined;
  for (const [name, stream] of [["stdout", run.stdout], ["stderr", run.stderr]] as const) {
    // Complete lines are held until they can be scrubbed as one unit, so a credential split across
    // arbitrary pipe chunks never reaches CI output. Lines over the fixed cap are replaced with a
    // progress marker and discarded through their newline; final partial lines are scrubbed at EOF.
    const forwarder = createBoundedLineRedactor({
      maxLineChars: MAX_FORWARDED_LINE_CHARS,
      write: (redacted) => process.stderr.write(redacted),
      onRedacted: (redacted) => {
        captureDiagnostic(streamCapture[name], redacted);
        if (redacted.includes(`${target}:`) || redacted.includes("M8 PHASES:")) {
          timingOutput = `${timingOutput}${redacted}`.slice(-8 * 1024);
        }
      },
    });
    stream.setEncoding("utf8");
    stream.on("data", (chunk: string) => {
      const markerProbe = markerTail[name] + chunk;
      if (mutationCliStartedMs === undefined && markerProbe.includes(mutationMarker)) {
        mutationCliStartedMs = performance.now() - started;
      }
      markerTail[name] = markerProbe.slice(-(mutationMarker.length - 1));
      forwarder.write(chunk);
    });
    stream.once("end", () => forwarder.end());
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
    phases = m8PhasesFromOutput(timingOutput, target, durationMs, mutationCliStartedMs);
  } catch (error) {
    parseError = `scorecard unavailable or corrupt: ${(error as Error).message}`;
  }
  const status = exitCode === 0 && !parseError ? "passed" : "failed";
  // The child can fail before scorecard creation. Its captured diagnostic is the only durable
  // cause available to the uploaded target result; bound and scrub it before serialization.
  const childEvidence = status === "failed"
    ? (["stdout", "stderr"] as const).map((name) => capturedDiagnostic(streamCapture[name]).trim()
      ? `child ${name} (redacted excerpt): ${failureExcerpt(capturedDiagnostic(streamCapture[name]))}`
      : undefined).filter(Boolean).join("; ")
    : undefined;
  const result: M8TargetResult = {
    schemaVersion: 1,
    target,
    status,
    exitCode,
    durationMs,
    phases,
    scorecard,
    ...(status === "failed" ? { error: redactSecrets([parseError, runError, signal ? `terminated by ${signal}` : undefined, `child exited ${exitCode}`, childEvidence].filter(Boolean).join("; ")) } : {}),
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
  let results: M8TargetResult[];
  try {
    results = paths.map((path) => {
      const result = parseM8TargetResult(readFileSync(path, "utf8"), basename(resolve(path, "..")));
      return result.error === undefined ? result : { ...result, error: redactSecrets(result.error) };
    });
  } catch (error) {
    const detail = redactSecrets(error instanceof Error ? error.message : String(error));
    console.error(`M8 AGGREGATE INPUT INVALID: ${detail}`);
    process.exit(1);
  }
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
