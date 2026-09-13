import "./sync-stdio.js";
// #1890: default runs a fresh census; --report requires its digest-bound capture receipt.
// Only --update-baseline writes the baseline, after printing population/identity/review deltas.

import { execFile } from "node:child_process";
import { closeSync, existsSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readlinkSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, parse, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { arg, assertKnownFlags } from "./args.js";
import { formatGuardCensus, GUARD_SET, guardMutationCensus } from "../guard-mutation-census.js";
import {
  compareGuardMutationCensus, guardMutationDigest, normalizeGuardMutationCensus,
  parseGuardMutationBaseline, updateGuardMutationBaseline,
} from "../guard-mutation-baseline.js";
import { DEFAULT_GUARD_SHARD_BOUNDS, guardShardBounds, readGuardMutationBundle } from "../guard-mutation-bundle.js";
import { runGuardMutationShards } from "../guard-mutation-shards.js";
import type { StrykerReport } from "../mutation-scan.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const readJson = (path: string): unknown => JSON.parse(readFileSync(path, "utf8")) as unknown;
const digestFile = (path: string): string => guardMutationDigest(readFileSync(path));
const flags = ["--report", "--receipt", "--config", "--baseline", "--normalized-out", "--reviews", "--update-baseline", "--bundle", "--bundle-dir", "--concurrency", "--shard-timeout-ms", "--aggregate-timeout-ms"];
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
  const descriptor = openSync(temporary, "wx");
  try {
    try { writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`); }
    finally { closeSync(descriptor); }
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function pathIdentity(path: string): string {
  const absolute = isAbsolute(path) ? path : `${process.cwd()}${sep}${path}`;
  let current = parse(absolute).root;
  const remaining = absolute.slice(current.length).split(sep);
  let links = 0;
  // Follow each filesystem component before interpreting a later parent traversal.
  // Lexically normalizing a symlink target first can select a different file.
  while (remaining.length) {
    const component = remaining.shift()!;
    if (!component || component === ".") continue;
    if (component === "..") { current = dirname(current); continue; }
    const candidate = join(current, component);
    try {
      if (lstatSync(candidate).isSymbolicLink()) {
        if (++links > 40) throw new Error(`cyclic or excessive output path alias: ${path}`);
        const target = readlinkSync(candidate);
        if (isAbsolute(target)) current = parse(target).root;
        remaining.unshift(...target.slice(isAbsolute(target) ? current.length : 0).split(sep));
        continue;
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    current = candidate;
  }
  return current;
}

function portablePathIdentity(identity: string): string {
  // Compatibility normalization and case expansion reject ambiguous destinations.
  // Lowercasing first includes capital sharp S in the subsequent SS expansion.
  return identity.normalize("NFKC").toLowerCase().toUpperCase().toLowerCase().normalize("NFKC");
}

// Atomic siblings are outputs too. Reserve them before a child starts, while retaining
// exclusive-create ownership in the writer for preexisting files and races.
const outputPaths = (path: string): string[] => [path, `${path}.${process.pid}.tmp`];

function separateOutput(output: string, protectedPaths: string[]): void {
  for (const destination of outputPaths(output)) separateDestination(destination, protectedPaths.flatMap(outputPaths));
}

function separateDestination(output: string, protectedPaths: string[]): void {
  const identity = pathIdentity(output);
  // Prospective destinations stay distinct across case-insensitive filesystems too.
  // Preserve the original identity for inode lookup on case-sensitive volumes.
  const portableIdentity = portablePathIdentity(identity);
  const outputStat = existsSync(identity) ? lstatSync(identity) : undefined;
  if (protectedPaths.some((path) => {
    const protectedIdentity = pathIdentity(path);
    if (portablePathIdentity(protectedIdentity) === portableIdentity) return true;
    if (!outputStat || !existsSync(protectedIdentity)) return false;
    const protectedStat = lstatSync(protectedIdentity);
    return outputStat.dev === protectedStat.dev && outputStat.ino === protectedStat.ino;
  })) throw new Error(`output would overwrite an input or baseline: ${output}`);
}

function outsideBundle(bundle: string, protectedPaths: string[]): void {
  const namespace = portablePathIdentity(pathIdentity(bundle));
  for (const path of protectedPaths.flatMap(outputPaths)) {
    const identity = portablePathIdentity(pathIdentity(path));
    if (identity === namespace || identity.startsWith(`${namespace}${sep}`)) throw new Error(`bundle output would overwrite an input or another output: ${path}`);
  }
}

async function runFresh(configPath: string, receiptPath: string, protectedPaths: string[]) {
  const config = readJson(configPath) as { jsonReporter?: { fileName?: string } };
  if (!config.jsonReporter?.fileName) throw new Error("guard config must name its JSON report");
  const reportPath = resolve(REPO_ROOT, config.jsonReporter.fileName);
  separateOutput(reportPath, [...protectedPaths, configPath, receiptPath]);
  separateOutput(receiptPath, [...protectedPaths, configPath]);
  const namedBundle = option("--bundle-dir");
  const paths = [...protectedPaths, configPath, reportPath, receiptPath];
  let bundleDir: string;
  if (namedBundle) {
    bundleDir = resolve(namedBundle);
    outsideBundle(bundleDir, paths);
    mkdirSync(dirname(bundleDir), { recursive: true });
    mkdirSync(bundleDir); // A bundle is write-once; existing captures are never reused or cleared.
  } else {
    const parent = join(REPO_ROOT, "reports", "guard-mutation");
    mkdirSync(parent, { recursive: true });
    bundleDir = mkdtempSync(join(parent, "bundle-"));
    outsideBundle(bundleDir, paths);
  }
  const number = (flag: string, fallback: number) => { const value = option(flag); return value === undefined ? fallback : Number(value); };
  const bounds = guardShardBounds({ ...DEFAULT_GUARD_SHARD_BOUNDS,
    concurrency: number("--concurrency", DEFAULT_GUARD_SHARD_BOUNDS.concurrency),
    shardTimeoutMs: number("--shard-timeout-ms", DEFAULT_GUARD_SHARD_BOUNDS.shardTimeoutMs),
    aggregateTimeoutMs: number("--aggregate-timeout-ms", DEFAULT_GUARD_SHARD_BOUNDS.aggregateTimeoutMs),
  });
  rmSync(reportPath, { force: true }); rmSync(receiptPath, { force: true });
  console.log(`GUARD BUNDLE ${bundleDir}`);
  const captured = await runGuardMutationShards({ root: REPO_ROOT, configPath, bundleDir, bounds, progress: (line) => console.log(line) });
  writeJson(reportPath, captured.report); writeJson(receiptPath, captured.receipt);
  return { reportPath, receipt: captured.receipt, bundleDir };
}

async function main(): Promise<void> {
  for (let i = 2; i < process.argv.length; i++) {
    const token = process.argv[i]!;
    if (!flags.includes(token)) throw new Error(`unexpected argument: ${token}`);
    if (token !== "--update-baseline") i++;
  }
  const update = process.argv.includes("--update-baseline");
  if (process.argv.filter((value) => value === "--update-baseline").length > 1) throw new Error("duplicate --update-baseline");
  const supplied = option("--report");
  const bundle = option("--bundle");
  if (bundle && (supplied || option("--receipt"))) throw new Error("--bundle cannot be combined with --report or --receipt");
  if ((bundle || supplied) && ["--bundle-dir", "--concurrency", "--shard-timeout-ms", "--aggregate-timeout-ms"].some((flag) => option(flag) !== undefined)) throw new Error("execution options require a fresh run");
  const receiptOption = option("--receipt");
  const reviewsOption = option("--reviews");
  const normalizedOption = option("--normalized-out");
  const configPath = resolve(REPO_ROOT, option("--config") ?? "stryker.guards.config.json");
  const baselinePath = resolve(REPO_ROOT, option("--baseline") ?? "guard-mutation-baseline.json");
  const normalizedPath = normalizedOption ? resolve(normalizedOption) : supplied || bundle ? undefined : join(REPO_ROOT, "reports", "guard-mutation", "census.json");
  if (reviewsOption && !update) throw new Error("--reviews requires explicit --update-baseline");
  if (supplied && !receiptOption) throw new Error("--report requires --receipt; the current machine cannot supply a historical report's Node/package identity");
  if (!update && !existsSync(baselinePath)) throw new Error(`no baseline at ${baselinePath}; creating one requires --update-baseline and reviewed ownership records`);
  const baselineBytes = existsSync(baselinePath) ? readFileSync(baselinePath) : undefined;
  const baselineSha256 = baselineBytes ? guardMutationDigest(baselineBytes) : undefined;
  const previous = baselineBytes ? parseGuardMutationBaseline(JSON.parse(baselineBytes.toString("utf8")) as unknown, new Date().toISOString(), update) : undefined;
  const assertBaselineUnchanged = () => {
    const current = existsSync(baselinePath) ? digestFile(baselinePath) : undefined;
    if (current !== baselineSha256) throw new Error("baseline changed during the census; retain this capture and compare again against the intended baseline");
  };
  const receiptPath = resolve(receiptOption ?? join(REPO_ROOT, "reports", "guard-mutation", "mutation.receipt.json"));
  const sourceInputs = [configPath, ...[...GUARD_SET, "package.json", "pnpm-lock.yaml", "vitest.config.ts"].map((file) => join(REPO_ROOT, file))];
  if (normalizedPath) separateOutput(normalizedPath, [...sourceInputs, baselinePath, receiptPath, ...(supplied ? [resolve(supplied)] : []), ...(reviewsOption ? [resolve(reviewsOption)] : [])]);
  const protectedPaths = [...sourceInputs, baselinePath, ...(normalizedPath ? [normalizedPath] : []), ...(reviewsOption ? [resolve(reviewsOption)] : [])];
  if (bundle) outsideBundle(resolve(bundle), [...protectedPaths, configPath, receiptPath]);
  const replay = bundle ? await readGuardMutationBundle(resolve(bundle)) : undefined;
  const captured = replay ? undefined : supplied ? { reportPath: resolve(supplied), receipt: readJson(receiptPath), bundleDir: undefined } : await runFresh(configPath, receiptPath, protectedPaths);
  const reportBytes = replay ? Buffer.from(replay.reportBytes) : readFileSync(captured!.reportPath);
  const report = JSON.parse(reportBytes.toString("utf8")) as unknown;
  const census = normalizeGuardMutationCensus(report, replay?.receipt ?? captured!.receipt, guardMutationDigest(reportBytes));
  if (normalizedPath) writeJson(normalizedPath, census);
  console.log(formatGuardCensus(guardMutationCensus(report as StrykerReport)));
  if (replay || captured?.bundleDir) console.log("Test counts in sharded captures are execution records: a test that ran in several shards is counted once per shard.");
  console.log("\nDECLARED GUARD POPULATIONS (attempted = generated mutant records; Timeout counts as killed):");
  for (const g of census.guards) console.log(`  ${g.file}: ${g.state}; ${JSON.stringify(g.population)}${g.exclusion ? `; fresh exclusion probe ${g.exclusion.outcome}, ${g.exclusion.attempted} generated, exit ${g.exclusion.exitCode}` : ""}`);
  console.log(`\nCapture: ${census.receipt.sourceCommit}; Node ${census.receipt.toolchain.node}; Stryker ${census.receipt.toolchain.packages["@stryker-mutator/core"]!.version}; raw ${census.receipt.reportSha256}`);
  if (update) {
    const result = updateGuardMutationBaseline(census, previous, reviewsOption ? readJson(resolve(reviewsOption)) : []);
    for (const issue of new Set(result.baseline.reviews.filter((r) => !previous?.reviews.some((old) => old.key === r.key && old.remediationIssue === r.remediationIssue)).flatMap((r) => r.remediationIssue ? [r.remediationIssue] : []))) {
      const checked = await new Promise<string>((done) => {
        execFile("gh", ["issue", "view", issue, "--json", "url"], { cwd: REPO_ROOT, encoding: "utf8", timeout: 15_000, killSignal: "SIGKILL", maxBuffer: 1024 * 1024 }, (error, stdout) => done(error ? "null" : stdout));
      });
      if ((JSON.parse(checked || "null") as { url?: string } | null)?.url !== issue) throw new Error(`remediation issue could not be verified: ${issue}`);
    }
    console.log(`\nSEMANTIC DELTA (${result.delta.length}):\n${result.delta.map((line) => `  ${line}`).join("\n") || "  (none)"}`);
    assertBaselineUnchanged();
    writeJson(baselinePath, result.baseline);
    console.log(`BASELINE UPDATED explicitly: ${baselinePath}`);
    return;
  }
  assertBaselineUnchanged();
  const comparison = compareGuardMutationCensus(census, previous!);
  if (captured?.bundleDir) writeJson(join(captured.bundleDir, "comparison.json"), {
    schemaVersion: 1, baselineSha256, bundleSha256: digestFile(join(captured.bundleDir, "bundle.json")),
    reportSha256: census.receipt.reportSha256, ...comparison,
  });
  for (const change of comparison.delta) console.log(`  ${change}`);
  for (const problem of comparison.problems) console.error(`  ${problem}`);
  console.log(`\nGUARD BASELINE ${comparison.ok ? "PASS" : "FAIL"}: ${comparison.problems.length} problem(s); ${previous!.reviews.length} reviewed retained row(s).`);
  if (!comparison.ok) process.exitCode = 1;
}

try {
  await main();
} catch (error) {
  console.error(`GUARD BASELINE ERROR: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
