// M8 mutation scan — runs StrykerJS against a target repo and shapes its JSON reporter
// output into the summary shape docs/m8-test-quality.md documents (mutation score overall +
// per module, ranked surviving-mutant list).
//
// StrykerJS is an EXTERNAL CLI TOOL, not an npm dependency of this repo — install it in (or
// alongside) the client repo: `npm install --no-save -D @stryker-mutator/core <test-runner-plugin>`
// (see https://stryker-mutator.io/docs/stryker-js/installation/). This wrapper shells out to the
// `stryker` binary; it throws if the binary isn't found on PATH.
//
// Prerequisite: the target repo needs a working Stryker config (`stryker.conf.json/.mjs/.cjs`)
// for its own test runner (Jest/Vitest/Mocha/etc — Stryker can't infer this). The config MUST
// set `coverageAnalysis: "perTest"` and enable the `json` reporter — this wrapper does not
// generate a config from scratch (test-runner choice is too client-specific for a generic
// wrapper) but will warn if a JSON config is missing `coverageAnalysis: "perTest"`.
//
//   pnpm mutation-scan <target-dir> [--config <path>] [--concurrency <n>] [--incremental]
//                       [--report <path>] [--hotspots <file>] [--out <file>]
//
// --report points at the mutation.json Stryker already wrote (skips re-running Stryker — use
// this to shape a report from a prior run). Without --report, this invokes `stryker run` and
// reads the json reporter's default output path, reports/mutation/mutation.json (relative to
// <target-dir>) — confirm this matches the installed Stryker version's default; older/newer
// versions may differ, in which case pass --report explicitly.
// --hotspots points at a text file, one repo-relative path per line (e.g. the M3 hotspot file
// list), used to flag surviving mutants that sit on a security/perf hotspot as top priority.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { summarizeMutationReport, toReportRows, type StrykerReport } from "../mutation-scan.js";

const args = process.argv.slice(2);

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

// Positional target-dir: the first bare token, expected before any flags (matches
// src/cli/quality-scan.ts's convention — usage is always `<target-dir> [--flags...]`).
const targetArg = args.find((a) => !a.startsWith("--"));

if (!targetArg) {
  console.error("usage: pnpm mutation-scan <target-dir> [--config <path>] [--concurrency <n>] [--incremental] [--report <path>] [--hotspots <file>] [--out <file>]");
  process.exit(2);
}

const targetDir = resolve(targetArg);
const configPath = arg("--config");
const concurrency = arg("--concurrency");
const incremental = process.argv.includes("--incremental");
const reportPath = arg("--report");
const hotspotsPath = arg("--hotspots");
const outPath = arg("--out");

function warnIfNotPerTest(cfgPath: string): void {
  if (!cfgPath.endsWith(".json")) return; // .mjs/.cjs configs aren't statically inspectable here
  try {
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as { coverageAnalysis?: string };
    if (cfg.coverageAnalysis !== "perTest") {
      console.error(`⚠ ${cfgPath}: coverageAnalysis is "${cfg.coverageAnalysis ?? "unset"}", expected "perTest" — this scan will be slower and less precise than intended.`);
    }
  } catch {
    console.error(`⚠ could not read ${cfgPath} to verify coverageAnalysis`);
  }
}

function runStryker(): string {
  const strykerArgs = ["run"];
  if (configPath) strykerArgs.push(configPath);
  if (concurrency) strykerArgs.push("--concurrency", concurrency);
  if (incremental) strykerArgs.push("--incremental");

  const cfgToCheck = configPath ?? ["stryker.conf.json", "stryker.config.json"].map((f) => join(targetDir, f)).find(existsSync);
  if (cfgToCheck) warnIfNotPerTest(cfgToCheck);

  try {
    // Stryker exits non-zero when the mutation score is under its configured break threshold —
    // that's not a wrapper failure, the report is still written; only a missing binary should throw.
    execFileSync("stryker", strykerArgs, { cwd: targetDir, stdio: ["ignore", "inherit", "inherit"] });
  } catch (err) {
    const e = err as { code?: string };
    if (e.code === "ENOENT") {
      throw new Error("stryker binary not found on PATH — install @stryker-mutator/core in the target repo (see this file's header comment)");
    }
    // Non-ENOENT: Stryker ran and (likely) failed its break threshold; fall through to read the report.
  }
  return reportPath ?? join(targetDir, "reports", "mutation", "mutation.json");
}

const resolvedReportPath = reportPath ? resolve(reportPath) : runStryker();

if (!existsSync(resolvedReportPath)) {
  console.error(`✗ mutation report not found at ${resolvedReportPath} — pass --report <path> if Stryker wrote it elsewhere`);
  process.exit(1);
}

const report = JSON.parse(readFileSync(resolvedReportPath, "utf8")) as StrykerReport;
const hotspotFiles = hotspotsPath
  ? readFileSync(hotspotsPath, "utf8").split("\n").map((l) => l.trim()).filter(Boolean)
  : [];

const summary = summarizeMutationReport(report, hotspotFiles);

console.error(`M8 mutation score: ${summary.overall.mutationScore}% (${summary.overall.killed + summary.overall.timeout}/${summary.overall.totalMutants - summary.overall.ignored - summary.overall.compileErrors} valid mutants killed)`);
console.error(`${summary.survivingMutants.length} surviving mutant(s), ${summary.survivingMutants.filter((m) => m.hotspot).length} on a flagged hotspot`);

const output = { summary, reportRows: toReportRows(summary) };
const json = JSON.stringify(output, null, 2);
if (outPath) {
  writeFileSync(outPath, json + "\n");
  console.error(`wrote summary to ${outPath}`);
} else {
  console.log(json);
}
