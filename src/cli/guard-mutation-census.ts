import "./sync-stdio.js";
// #1890: default runs a fresh census; --report requires its digest-bound capture receipt.
// Only --update-baseline writes the baseline, after printing population/identity/review deltas.

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, readFileSync, readlinkSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { stripVTControlCharacters } from "node:util";
import { arg, assertKnownFlags } from "./args.js";
import { formatGuardCensus, GUARD_SET, guardMutationCensus, guardSetIsFullyAccounted } from "../guard-mutation-census.js";
import {
  compareGuardMutationCensus, guardMutationDigest, normalizeGuardMutationCensus,
  parseGuardMutationBaseline, updateGuardMutationBaseline,
  type GuardMutationReceipt,
} from "../guard-mutation-baseline.js";
import type { StrykerReport } from "../mutation-scan.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const requireFromRoot = createRequire(join(REPO_ROOT, "package.json"));
const readJson = (path: string): unknown => JSON.parse(readFileSync(path, "utf8")) as unknown;
const digestFile = (path: string): string => guardMutationDigest(readFileSync(path));
const flags = ["--report", "--receipt", "--config", "--baseline", "--normalized-out", "--reviews", "--update-baseline"];
assertKnownFlags(flags);

function option(flag: string): string | undefined {
  const values = process.argv.slice(2).filter((value) => value === flag);
  if (values.length > 1) throw new Error(`duplicate flag: ${flag}`);
  const value = arg(flag);
  if (values.length && (!value || value.startsWith("--"))) throw new Error(`${flag} needs a value`);
  return value;
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx" });
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function pathIdentity(path: string): string {
  return resolvePathIdentity(resolve(path), new Set());
}

function resolvePathIdentity(path: string, seen: Set<string>): string {
  if (seen.has(path)) throw new Error(`cyclic output path alias: ${path}`);
  seen.add(path);
  let ancestor = path;
  const suffix: string[] = [];
  while (true) {
    try {
      const entry = lstatSync(ancestor);
      if (entry.isSymbolicLink()) return resolve(resolvePathIdentity(resolve(dirname(ancestor), readlinkSync(ancestor)), seen), ...suffix);
      return resolve(realpathSync(ancestor), ...suffix);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      suffix.unshift(relative(dirname(ancestor), ancestor));
      ancestor = dirname(ancestor);
    }
  }
}

function separateOutput(output: string, protectedPaths: string[]): void {
  const identity = pathIdentity(output);
  const outputStat = existsSync(identity) ? lstatSync(identity) : undefined;
  if (protectedPaths.some((path) => {
    const protectedIdentity = pathIdentity(path);
    if (protectedIdentity === identity) return true;
    if (!outputStat || !existsSync(protectedIdentity)) return false;
    const protectedStat = lstatSync(protectedIdentity);
    return outputStat.dev === protectedStat.dev && outputStat.ino === protectedStat.ino;
  })) throw new Error(`output would overwrite an input or baseline: ${output}`);
}

type ProbePaths = { file: string; config: string; log: string; json: string };

function preflightGeneratedOutputs(reportPath: string, omitted: string[], protectedPaths: string[]): ProbePaths[] {
  const outputs = [reportPath];
  const probes = omitted.map((file) => {
    const name = file.replaceAll("/", "-");
    const directory = dirname(reportPath);
    return { file, config: join(directory, `${name}.probe.config.json`), log: join(directory, `${name}.probe.log`), json: join(directory, `${name}.probe.json`) };
  });
  for (const probe of probes) for (const output of [probe.config, probe.log, probe.json]) {
    separateOutput(output, [...protectedPaths, ...outputs]);
    outputs.push(output);
  }
  return probes;
}

function toolchain(): GuardMutationReceipt["toolchain"] {
  const manifest = readJson(join(REPO_ROOT, "package.json")) as { packageManager: string };
  const packages = Object.fromEntries(["@stryker-mutator/core", "@stryker-mutator/vitest-runner", "vitest", "typescript"].map((name) => {
    const path = requireFromRoot.resolve(`${name}/package.json`);
    const pkg = readJson(path) as { version: string };
    return [name, { version: pkg.version, packageJsonSha256: digestFile(path) }];
  }));
  const packageManagerVersion = execFileSync("pnpm", ["--version"], { cwd: REPO_ROOT, encoding: "utf8" }).trim();
  if (`pnpm@${packageManagerVersion}` !== manifest.packageManager) throw new Error("installed package manager differs from package.json");
  return {
    node: process.version, packageManager: manifest.packageManager, packages,
    packageJsonSha256: digestFile(join(REPO_ROOT, "package.json")), lockfileSha256: digestFile(join(REPO_ROOT, "pnpm-lock.yaml")),
  };
}

function runFresh(configPath: string, receiptPath: string, protectedPaths: string[]): { reportPath: string; receipt: GuardMutationReceipt } {
  const config = readJson(configPath) as { mutate: string[]; jsonReporter: { fileName: string } };
  if (!Array.isArray(config.mutate) || !config.mutate.every((file) => typeof file === "string")) throw new Error("config.mutate must enumerate guard paths");
  const omitted = GUARD_SET.filter((file) => !config.mutate.includes(file));
  const accounting = guardSetIsFullyAccounted(config.mutate, omitted);
  if (accounting.missing.length || accounting.doubleBooked.length || accounting.unexpected.length) throw new Error(`guard config does not partition the declared guard set: ${JSON.stringify(accounting)}`);
  if (!config.jsonReporter?.fileName) throw new Error("guard config must name its JSON report");
  const reportPath = resolve(REPO_ROOT, config.jsonReporter.fileName);
  const protectedInputs = [...protectedPaths, configPath, ...GUARD_SET.map((file) => join(REPO_ROOT, file)), join(REPO_ROOT, "package.json"), join(REPO_ROOT, "pnpm-lock.yaml")];
  separateOutput(reportPath, [...protectedInputs, receiptPath]);
  separateOutput(receiptPath, [...protectedInputs, reportPath]);
  const probes = preflightGeneratedOutputs(reportPath, omitted, [...protectedInputs, receiptPath]);
  const startedAt = new Date().toISOString();
  const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT, encoding: "utf8" }).trim();
  const sourceSha256 = Object.fromEntries(GUARD_SET.map((file) => [file, digestFile(join(REPO_ROOT, file))]));
  const configSha256 = digestFile(configPath);
  const identity = toolchain();
  const sourceStatus = execFileSync("git", ["status", "--porcelain"], { cwd: REPO_ROOT, encoding: "utf8" });
  if (sourceStatus.trim()) throw new Error("a fresh in-place census requires a clean committed worktree; commit changes first");
  rmSync(reportPath, { force: true });
  console.log(`Running Stryker over ${configPath}`);
  execFileSync(join(REPO_ROOT, "node_modules", ".bin", "stryker"), ["run", configPath], { cwd: REPO_ROOT, stdio: "inherit" });
  if (!existsSync(reportPath)) throw new Error(`Stryker produced no report at ${reportPath}`);
  const exclusionChecks: GuardMutationReceipt["exclusionChecks"] = [];
  for (const { file, config: probeConfig, log: logPath, json: probeJson } of probes) {
    const name = file.replaceAll("/", "-");
    mkdirSync(dirname(probeConfig), { recursive: true });
    // A successful instrumented dry run falsifies an exclusion; it does not stand in for the
    // full mutant population. The next run must include that guard before the baseline shrinks.
    writeJson(probeConfig, { ...config, mutate: [file], dryRunOnly: true, reporters: ["json", "clear-text"], jsonReporter: { fileName: probeJson } });
    const args = ["run", probeConfig];
    const probe = spawnSync(join(REPO_ROOT, "node_modules", ".bin", "stryker"), args, { cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    const output = `${probe.stdout ?? ""}${probe.stderr ?? ""}${probe.error?.message ?? ""}`;
    writeFileSync(logPath, output);
    const plain = stripVTControlCharacters(output).replaceAll(REPO_ROOT, "<repo>");
    const attempted = Number(/Instrumented 1 source file\(s\) with (\d+) mutant\(s\)/.exec(plain)?.[1] ?? 0);
    const failedAt = plain.indexOf("One or more tests failed in the initial test run:");
    const detail = failedAt >= 0 ? plain.slice(failedAt).split(/\n(?=\d\d:\d\d:\d\d\b)/, 1)[0]!.trim() : `instrumented dry run exited ${probe.status ?? "without status"}; see ${name}.probe.log`;
    const outcome = attempted > 0 && probe.status === 0 ? "measurable" : attempted > 0 && probe.status === 1 && failedAt >= 0 ? "blocked" : "uncheckable";
    exclusionChecks.push({ file, outcome, attempted, exitCode: probe.status ?? 127, command: `node_modules/.bin/stryker run ${relative(REPO_ROOT, probeConfig)}`, outputSha256: guardMutationDigest(output), detail });
    console.log(`Exclusion probe ${file}: ${outcome}, ${attempted} attempted, exit ${probe.status ?? 127}; ${logPath}`);
  }
  for (const file of GUARD_SET) if (digestFile(join(REPO_ROOT, file)) !== sourceSha256[file]) throw new Error(`${file}: source changed during the census or Stryker did not restore it`);
  if (digestFile(configPath) !== configSha256 || JSON.stringify(toolchain()) !== JSON.stringify(identity)) throw new Error("configuration or toolchain changed during the census");
  const receipt: GuardMutationReceipt = {
    schemaVersion: 1, startedAt, finishedAt: new Date().toISOString(), sourceCommit, sourceSha256,
    reportSha256: digestFile(reportPath), configSha256, toolchain: identity, exclusionChecks,
  };
  writeJson(receiptPath, receipt);
  return { reportPath, receipt };
}

function main(): void {
  for (let i = 2; i < process.argv.length; i++) {
    const token = process.argv[i]!;
    if (!flags.includes(token)) throw new Error(`unexpected argument: ${token}`);
    if (token !== "--update-baseline") i++;
  }
  const update = process.argv.includes("--update-baseline");
  if (process.argv.filter((value) => value === "--update-baseline").length > 1) throw new Error("duplicate --update-baseline");
  const supplied = option("--report");
  const receiptOption = option("--receipt");
  const reviewsOption = option("--reviews");
  const normalizedOption = option("--normalized-out");
  const configPath = resolve(REPO_ROOT, option("--config") ?? "stryker.guards.config.json");
  const baselinePath = resolve(REPO_ROOT, option("--baseline") ?? "guard-mutation-baseline.json");
  const normalizedPath = normalizedOption ? resolve(normalizedOption) : supplied ? undefined : join(REPO_ROOT, "reports", "guard-mutation", "census.json");
  if (reviewsOption && !update) throw new Error("--reviews requires explicit --update-baseline");
  if (supplied && !receiptOption) throw new Error("--report requires --receipt; the current machine cannot supply a historical report's Node/package identity");
  if (!update && !existsSync(baselinePath)) throw new Error(`no baseline at ${baselinePath}; creating one requires --update-baseline and reviewed ownership records`);
  const previous = existsSync(baselinePath) ? parseGuardMutationBaseline(readJson(baselinePath), new Date().toISOString(), update) : undefined;
  const receiptPath = resolve(receiptOption ?? join(REPO_ROOT, "reports", "guard-mutation", "mutation.receipt.json"));
  if (normalizedPath) separateOutput(normalizedPath, [baselinePath, receiptPath, configPath, ...(supplied ? [resolve(supplied)] : []), ...(reviewsOption ? [resolve(reviewsOption)] : [])]);
  const captured = supplied ? { reportPath: resolve(supplied), receipt: readJson(receiptPath) } : runFresh(configPath, receiptPath, [baselinePath, ...(normalizedPath ? [normalizedPath] : []), ...(reviewsOption ? [resolve(reviewsOption)] : [])]);
  const reportBytes = readFileSync(captured.reportPath);
  const report = JSON.parse(reportBytes.toString("utf8")) as unknown;
  const census = normalizeGuardMutationCensus(report, captured.receipt, guardMutationDigest(reportBytes));
  if (normalizedPath) writeJson(normalizedPath, census);
  console.log(formatGuardCensus(guardMutationCensus(report as StrykerReport)));
  console.log("\nDECLARED GUARD POPULATIONS (attempted = generated mutant records; Timeout counts as killed):");
  for (const g of census.guards) console.log(`  ${g.file}: ${g.state}; ${JSON.stringify(g.population)}${g.exclusion ? `; fresh exclusion probe ${g.exclusion.outcome}, ${g.exclusion.attempted} generated, exit ${g.exclusion.exitCode}` : ""}`);
  console.log(`\nCapture: ${census.receipt.sourceCommit}; Node ${census.receipt.toolchain.node}; Stryker ${census.receipt.toolchain.packages["@stryker-mutator/core"]!.version}; raw ${census.receipt.reportSha256}`);
  if (update) {
    const result = updateGuardMutationBaseline(census, previous, reviewsOption ? readJson(resolve(reviewsOption)) : []);
    for (const issue of new Set(result.baseline.reviews.filter((r) => !previous?.reviews.some((old) => old.key === r.key && old.remediationIssue === r.remediationIssue)).flatMap((r) => r.remediationIssue ? [r.remediationIssue] : []))) {
      const checked = spawnSync("gh", ["issue", "view", issue, "--json", "url"], { cwd: REPO_ROOT, encoding: "utf8" });
      if (checked.status !== 0 || (JSON.parse(checked.stdout || "null") as { url?: string } | null)?.url !== issue) throw new Error(`remediation issue could not be verified: ${issue}`);
    }
    console.log(`\nSEMANTIC DELTA (${result.delta.length}):\n${result.delta.map((line) => `  ${line}`).join("\n") || "  (none)"}`);
    writeJson(baselinePath, result.baseline);
    console.log(`BASELINE UPDATED explicitly: ${baselinePath}`);
    return;
  }
  const comparison = compareGuardMutationCensus(census, previous!);
  for (const change of comparison.delta) console.log(`  ${change}`);
  for (const problem of comparison.problems) console.error(`  ${problem}`);
  console.log(`\nGUARD BASELINE ${comparison.ok ? "PASS" : "FAIL"}: ${comparison.problems.length} problem(s); ${previous!.reviews.length} reviewed retained row(s).`);
  if (!comparison.ok) process.exitCode = 1;
}

try {
  main();
} catch (error) {
  console.error(`GUARD BASELINE ERROR: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
