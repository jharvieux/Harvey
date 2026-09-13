import assert from "node:assert/strict";
import { lstat, mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import { dirname, join, posix } from "node:path";
import { stripVTControlCharacters } from "node:util";
import { GUARD_SET } from "./guard-mutation-census.js";
import { guardMutationDigest, normalizeGuardMutationCensus, type GuardMutationReceipt, type NormalizedGuardCensus } from "./guard-mutation-baseline.js";
import type { GuardCommandResult } from "./guard-mutation-process.js";

export interface GuardShardBounds {
  concurrency: number;
  shardTimeoutMs: number;
  aggregateTimeoutMs: number;
  killGraceMs: number;
  maxParentBlockMs: number;
}
export const DEFAULT_GUARD_SHARD_BOUNDS: GuardShardBounds = {
  concurrency: 2, shardTimeoutMs: 30 * 60_000, aggregateTimeoutMs: 60 * 60_000,
  killGraceMs: 3_000, maxParentBlockMs: 15_000,
};
export interface GuardShard {
  id: string;
  guard: string;
  kind: "mutation" | "exclusion";
  workspace: string;
  configPath: string;
  configSha256: string;
}
export interface GuardShardManifest {
  schemaVersion: 1;
  createdAt: string;
  sourceCommit: string;
  sourceSha256: Record<string, string>;
  toolchain: GuardMutationReceipt["toolchain"];
  configSha256: string;
  launcherSha256: string;
  bounds: GuardShardBounds;
  shards: GuardShard[];
}
export interface GuardShardTerminal {
  schemaVersion: 1;
  id: string;
  guard: string;
  kind: GuardShard["kind"];
  startedAt: string;
  finishedAt: string;
  elapsedMs: number;
  state: "completed" | "failed" | "timed-out" | "aggregate-timeout" | "not-started" | "error";
  sourceCommit: string;
  sourceSha256: Record<string, string>;
  toolchain: GuardMutationReceipt["toolchain"];
  configSha256: string;
  commands: GuardCommandResult[];
  error: string | null;
  rawReport: { path: string; sha256: string } | null;
}
interface GuardBundleSeal {
  schemaVersion: 1;
  manifestSha256: string;
  finishedAt: string;
  artifacts: { path: string; sha256: string }[];
  conservation: { declared: number; terminal: number; completed: number; failed: number };
}

export const guardJsonBytes = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;
export async function writeGuardJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  const handle = await open(temporary, "wx");
  try {
    try { await handle.writeFile(guardJsonBytes(value)); }
    finally { await handle.close(); }
    await rename(temporary, path);
  }
  finally { await rm(temporary, { force: true }); }
}

function object(value: unknown, name: string): Record<string, unknown> {
  assert(value && typeof value === "object" && !Array.isArray(value), `${name} must be an object`);
  return value as Record<string, unknown>;
}
function timestamp(value: unknown, name: string): asserts value is string {
  assert(typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value)), `${name} must be an exact UTC timestamp`);
}
function finite(value: unknown, name: string, min = 0, max = Number.MAX_SAFE_INTEGER): asserts value is number {
  assert(typeof value === "number" && Number.isFinite(value) && value >= min && value <= max, `${name} is outside its finite bounds`);
}
function hash(value: unknown, name: string): asserts value is string { assert(typeof value === "string" && /^[a-f0-9]{64}$/.test(value), `${name} must be a SHA-256 digest`); }
function same(a: unknown, b: unknown, name: string): void { assert.deepEqual(a, b, name); }

export function guardShardBounds(value: unknown): GuardShardBounds {
  const x = object(value, "shard bounds");
  same(Object.keys(x).sort(), Object.keys(DEFAULT_GUARD_SHARD_BOUNDS).sort(), "unknown or missing shard bound");
  finite(x.concurrency, "concurrency", 1, 4); assert(Number.isSafeInteger(x.concurrency), "concurrency must be integral");
  finite(x.shardTimeoutMs, "shard timeout", 1, 4 * 60 * 60_000);
  finite(x.aggregateTimeoutMs, "aggregate timeout", 1, 12 * 60 * 60_000);
  assert(x.killGraceMs === DEFAULT_GUARD_SHARD_BOUNDS.killGraceMs, "process-group cleanup grace cannot be widened");
  assert(x.maxParentBlockMs === DEFAULT_GUARD_SHARD_BOUNDS.maxParentBlockMs, "parent blocking budget cannot be widened");
  return x as unknown as GuardShardBounds;
}

/** The manifest owns the live declared population, including a separate current falsifier for
 * each omitted guard. A configuration's omitted entries never become missing shard identities. */
export function buildGuardShardManifest(configValue: unknown, identity: Omit<GuardShardManifest, "schemaVersion" | "shards">): GuardShardManifest {
  const config = object(configValue, "guard config");
  const mutate = config.mutate;
  assert(Array.isArray(mutate) && mutate.every((file) => typeof file === "string" && (GUARD_SET as readonly string[]).includes(file)), "config.mutate must enumerate declared guard paths");
  assert(new Set(mutate).size === mutate.length, "duplicate guard in config.mutate");
  assert(mutate.length > 0, "guard configuration must score at least one guard");
  assert(typeof object(config.jsonReporter, "jsonReporter").fileName === "string", "guard config must name its JSON report");
  assert(config.testRunner === "vitest" && config.coverageAnalysis === "perTest" && config.inPlace === true, "guard shards require the configured in-place per-test Vitest runner");
  assert(config.dryRunOnly !== true && config.incremental !== true, "scored guard shards cannot reuse incremental or dry-run-only populations");
  const supported = ["$schema", "_comment", "inPlace", "packageManager", "testRunner", "reporters", "jsonReporter", "coverageAnalysis", "mutate", "vitest", "timeoutMS", "concurrency", "thresholds", "plugins", "dryRunOnly", "incremental"];
  assert(Object.keys(config).every((key) => supported.includes(key)), "guard config contains an unaudited execution/output option");
  assert(Array.isArray(config.reporters) && config.reporters.includes("json") && config.reporters.every((reporter) => ["json", "clear-text", "progress"].includes(String(reporter))), "guard shards require only local JSON/text reporters");
  same(config.vitest, { configFile: "vitest.config.ts" }, "guard shards require the committed Vitest configuration");
  same(config.plugins, ["@stryker-mutator/vitest-runner"], "guard shard plugins must match the captured toolchain");
  const bounds = guardShardBounds(identity.bounds);
  const shards = [...GUARD_SET].sort().map((guard, index): GuardShard => {
    const id = `guard-${String(index + 1).padStart(2, "0")}`;
    const shard: GuardShard = {
      id, guard, kind: mutate.includes(guard) ? "mutation" : "exclusion",
      workspace: `workspaces/${id}`, configPath: `shards/${id}/config.json`, configSha256: "",
    };
    shard.configSha256 = guardMutationDigest(guardJsonBytes(guardShardConfig(config, shard, bounds)));
    return shard;
  });
  return { schemaVersion: 1, ...identity, bounds, shards };
}

export function guardShardConfig(config: Record<string, unknown>, shard: GuardShard, bounds: GuardShardBounds): Record<string, unknown> {
  finite(config.concurrency, "Stryker concurrency", 1, 64);
  return {
    ...config, mutate: [shard.guard], inPlace: true, dryRunOnly: shard.kind === "exclusion", incremental: false,
    concurrency: Math.max(1, Math.floor(config.concurrency / bounds.concurrency)),
    jsonReporter: { fileName: `../../shards/${shard.id}/mutation.json` },
  };
}

/** No artifact reference may traverse a symlink or name an absolute/outside path. */
export async function readGuardArtifact(bundleDir: string, path: string): Promise<Buffer> {
  assert(path.length > 0 && !path.includes("\\") && !path.startsWith("/") && posix.normalize(path) === path && !path.split("/").includes(".."), `unsafe bundle artifact: ${path}`);
  const parts = path.split("/");
  for (let i = 1; i <= parts.length; i++) {
    const entry = await lstat(join(bundleDir, ...parts.slice(0, i)));
    assert(i === parts.length ? entry.isFile() : entry.isDirectory(), `unreadable/nonregular bundle artifact: ${path}`);
  }
  return readFile(join(bundleDir, path));
}

export function guardExclusionCheck(shard: GuardShard, result: GuardCommandResult, output: string): GuardMutationReceipt["exclusionChecks"][number] {
  const plain = stripVTControlCharacters(output);
  const attempted = Number(/Instrumented 1 source file\(s\) with (\d+) mutant\(s\)/.exec(plain)?.[1] ?? 0);
  const failedAt = plain.indexOf("One or more tests failed in the initial test run:");
  const detail = failedAt >= 0 ? plain.slice(failedAt).split(/\n(?=\d\d:\d\d:\d\d\b)/, 1)[0]!.trim() : `instrumented dry run exited ${result.exitCode ?? "without status"}; see shards/${shard.id}/stryker.stderr.log`;
  const healthy = result.state === "exited" && result.terminationAcknowledged && !result.error;
  const outcome = healthy && attempted > 0 && result.exitCode === 0 ? "measurable" : healthy && attempted > 0 && result.exitCode === 1 && failedAt >= 0 ? "blocked" : "uncheckable";
  return { file: shard.guard, outcome, attempted, exitCode: result.exitCode ?? 127, command: `node_modules/.bin/stryker run ../../${shard.configPath}`, outputSha256: guardMutationDigest(output), detail };
}

async function artifactPaths(bundleDir: string, directory: string): Promise<string[]> {
  const result: string[] = [];
  for (const entry of await readdir(join(bundleDir, directory), { withFileTypes: true })) {
    const path = `${directory}/${entry.name}`;
    if (entry.isDirectory()) result.push(...await artifactPaths(bundleDir, path));
    else { assert(entry.isFile(), `nonregular bundle artifact: ${path}`); result.push(path); }
  }
  return result;
}

export async function sealGuardMutationBundle(bundleDir: string, manifest: GuardShardManifest, terminals: GuardShardTerminal[]): Promise<void> {
  const paths = ["manifest.json", "base.config.json", "runtime.json", "stryker-launcher", ...await artifactPaths(bundleDir, "preflight"), ...await artifactPaths(bundleDir, "sources"), ...await artifactPaths(bundleDir, "shards")].sort();
  const artifacts = await Promise.all(paths.map(async (path) => ({ path, sha256: guardMutationDigest(await readGuardArtifact(bundleDir, path)) })));
  const completed = terminals.filter((terminal) => terminal.state === "completed").length;
  const seal: GuardBundleSeal = {
    schemaVersion: 1, manifestSha256: guardMutationDigest(await readGuardArtifact(bundleDir, "manifest.json")), finishedAt: new Date().toISOString(), artifacts,
    conservation: { declared: manifest.shards.length, terminal: terminals.length, completed, failed: terminals.length - completed },
  };
  await writeGuardJson(join(bundleDir, "bundle.json"), seal);
}

function commandResult(value: unknown, shard: GuardShard, maxBlock: number): GuardCommandResult {
  const x = object(value, `${shard.id} command`);
  assert(Array.isArray(x.command) && x.command.length > 0 && x.command.every((arg) => typeof arg === "string"), `${shard.id}: invalid command`);
  timestamp(x.startedAt, "command start"); timestamp(x.finishedAt, "command finish");
  assert(Date.parse(x.finishedAt) >= Date.parse(x.startedAt), `${shard.id}: inverted command time`);
  if (x.firstByteAt !== null) { timestamp(x.firstByteAt, "first child byte"); assert(x.firstByteAt >= x.startedAt && x.firstByteAt <= x.finishedAt, `${shard.id}: first byte outside command`); }
  finite(x.elapsedMs, "command elapsed"); finite(x.maxParentBlockMs, "parent blocking window");
  assert(x.maxParentBlockMs < maxBlock, `${shard.id}: parent exceeded blocking budget`);
  if (x.fromFirstByteMs !== null) finite(x.fromFirstByteMs, "first-byte runtime");
  assert(x.state === "exited" && x.terminationAcknowledged === true && x.error === null, `${shard.id}: command did not complete: ${String(x.state)} ${String(x.error)}`);
  assert(Number.isSafeInteger(x.exitCode) && Number(x.exitCode) >= 0 && x.signal === null, `${shard.id}: missing command exit status`);
  for (const channel of ["stdout", "stderr"]) {
    const output = object(x[channel], channel);
    assert(typeof output.path === "string" && output.path.startsWith(`shards/${shard.id}/`) && output.path.endsWith(`.${channel}.log`), `${shard.id}: output outside its shard`);
    hash(output.sha256, "output digest"); finite(output.bytes, "output bytes"); assert(typeof output.tail === "string", "missing output tail");
  }
  return x as unknown as GuardCommandResult;
}

/** Replay is also the fresh runner's acceptance boundary. Re-read every digest-bound raw file
 * from disk; a failed shard is never replaced with an empty file or removed from the census. */
export async function readGuardMutationBundle(bundleDir: string): Promise<{ manifest: GuardShardManifest; report: Record<string, unknown>; reportBytes: string; receipt: GuardMutationReceipt; census: NormalizedGuardCensus; terminals: GuardShardTerminal[] }> {
  const json = async (path: string): Promise<unknown> => JSON.parse((await readGuardArtifact(bundleDir, path)).toString("utf8")) as unknown;
  const seal = object(await json("bundle.json"), "bundle seal");
  assert(seal.schemaVersion === 1 && Array.isArray(seal.artifacts), "unsupported bundle seal"); timestamp(seal.finishedAt, "bundle finish");
  const artifacts = seal.artifacts.map((value) => { const row = object(value, "artifact"); assert(typeof row.path === "string", "artifact path missing"); hash(row.sha256, "artifact digest"); return { path: row.path, sha256: row.sha256 }; });
  assert(new Set(artifacts.map((row) => row.path)).size === artifacts.length, "duplicate bundle artifact");
  const currentPaths = ["manifest.json", "base.config.json", "runtime.json", "stryker-launcher", ...await artifactPaths(bundleDir, "preflight"), ...await artifactPaths(bundleDir, "sources"), ...await artifactPaths(bundleDir, "shards")].sort();
  same(artifacts.map((row) => row.path).sort(), currentPaths, "bundle artifact inventory changed");
  for (const artifact of artifacts) same(guardMutationDigest(await readGuardArtifact(bundleDir, artifact.path)), artifact.sha256, `corrupt bundle artifact: ${artifact.path}`);
  same(guardMutationDigest(await readGuardArtifact(bundleDir, "manifest.json")), seal.manifestSha256, "manifest digest mismatch");
  const m = object(await json("manifest.json"), "manifest");
  assert(m.schemaVersion === 1, "unsupported shard manifest"); timestamp(m.createdAt, "manifest creation");
  assert(typeof m.sourceCommit === "string" && /^[a-f0-9]{40}$/.test(m.sourceCommit), "manifest needs an immutable source commit");
  const sources = object(m.sourceSha256, "source identities");
  same(Object.keys(sources).sort(), [...GUARD_SET].sort(), "manifest must bind every live declared guard");
  for (const file of GUARD_SET) { hash(sources[file], file); same(guardMutationDigest(await readGuardArtifact(bundleDir, `sources/${file}`)), sources[file], `${file}: source bytes changed`); }
  const config = object(await json("base.config.json"), "base config");
  same(guardMutationDigest(await readGuardArtifact(bundleDir, "base.config.json")), m.configSha256, "base configuration digest mismatch");
  hash(m.launcherSha256, "Stryker launcher digest");
  same(guardMutationDigest(await readGuardArtifact(bundleDir, "stryker-launcher")), m.launcherSha256, "Stryker launcher identity mismatch");
  const expected = buildGuardShardManifest(config, {
    createdAt: m.createdAt, sourceCommit: m.sourceCommit, sourceSha256: sources as Record<string, string>,
    toolchain: m.toolchain as GuardMutationReceipt["toolchain"], configSha256: m.configSha256 as string, launcherSha256: m.launcherSha256, bounds: guardShardBounds(m.bounds),
  });
  same(m, expected, "manifest does not exactly partition the live guard set");
  const manifest = expected;
  same((await readdir(join(bundleDir, "shards"))).sort(), manifest.shards.map((shard) => shard.id).sort(), "missing or duplicate shard directory");
  const files: Record<string, unknown> = {};
  const testFiles: Record<string, { tests: unknown[] }> = {};
  const exclusionChecks: GuardMutationReceipt["exclusionChecks"] = [];
  const terminals: GuardShardTerminal[] = [];
  for (const shard of manifest.shards) {
    same(guardMutationDigest(await readGuardArtifact(bundleDir, shard.configPath)), shard.configSha256, `${shard.id}: effective configuration changed`);
    const t = object(await json(`shards/${shard.id}/terminal.json`), `${shard.id} terminal`);
    assert(t.schemaVersion === 1 && t.id === shard.id && t.guard === shard.guard && t.kind === shard.kind, `${shard.id}: duplicate or mismatched terminal identity`);
    timestamp(t.startedAt, "shard start"); timestamp(t.finishedAt, "shard finish"); finite(t.elapsedMs, "shard elapsed");
    assert(t.startedAt >= manifest.createdAt && t.finishedAt >= t.startedAt && t.finishedAt <= seal.finishedAt, `${shard.id}: terminal outside run time`);
    assert(t.elapsedMs <= manifest.bounds.shardTimeoutMs + manifest.bounds.killGraceMs + 2_000, `${shard.id}: shard deadline exceeded`);
    assert(t.state === "completed" && t.error === null, `${shard.id}: incomplete shard (${String(t.state)}): ${String(t.error)}`);
    same(t.sourceCommit, manifest.sourceCommit, `${shard.id}: source commit mismatch`);
    same(t.sourceSha256, manifest.sourceSha256, `${shard.id}: source identity mismatch`);
    same(t.toolchain, manifest.toolchain, `${shard.id}: toolchain mismatch`);
    same(t.configSha256, shard.configSha256, `${shard.id}: config receipt mismatch`);
    assert(Array.isArray(t.commands) && t.commands.length >= 4, `${shard.id}: missing execution receipts`);
    const commands = t.commands.map((value) => commandResult(value, shard, manifest.bounds.maxParentBlockMs));
    const stryker = commands.filter((command) => command.stdout.path === `shards/${shard.id}/stryker.stdout.log`);
    assert(stryker.length === 1, `${shard.id}: missing or duplicate Stryker execution`);
    for (const command of commands) {
      for (const output of [command.stdout, command.stderr]) {
        const bytes = await readGuardArtifact(bundleDir, output.path);
        same(guardMutationDigest(bytes), output.sha256, `${shard.id}: output digest mismatch`); same(bytes.length, output.bytes, `${shard.id}: output byte count mismatch`);
        same(bytes.subarray(-16 * 1024).toString("utf8"), output.tail, `${shard.id}: output tail mismatch`);
      }
      if (command !== stryker[0]) assert(command.exitCode === 0, `${shard.id}: failed setup/restoration command`);
    }
    const run = stryker[0]!;
    if (shard.kind === "exclusion") {
      assert(t.rawReport === null, `${shard.id}: dry-run mutants cannot be scored`);
      const output = (await readGuardArtifact(bundleDir, run.stdout.path)).toString("utf8") + (await readGuardArtifact(bundleDir, run.stderr.path)).toString("utf8");
      const probe = guardExclusionCheck(shard, run, output);
      assert(probe.outcome !== "uncheckable", `${shard.id}: exclusion falsifier is uncheckable`);
      exclusionChecks.push(probe);
    } else {
      assert(run.exitCode === 0, `${shard.id}: Stryker exited nonzero`);
      const raw = object(t.rawReport, `${shard.id} raw report`);
      assert(raw.path === `shards/${shard.id}/mutation.json`, `${shard.id}: raw report outside its shard`);
      const bytes = await readGuardArtifact(bundleDir, raw.path); same(guardMutationDigest(bytes), raw.sha256, `${shard.id}: raw report digest mismatch`);
      const report = object(JSON.parse(bytes.toString("utf8")) as unknown, `${shard.id} Stryker report`);
      assert(report.schemaVersion === "1.0", `${shard.id}: unsupported raw report`);
      const framework = object(report.framework, "Stryker framework");
      assert(framework.name === "StrykerJS" && framework.version === manifest.toolchain.packages["@stryker-mutator/core"]?.version, `${shard.id}: raw toolchain mismatch`);
      const effective = object(report.config, `${shard.id} raw config`);
      for (const [key, value] of Object.entries(guardShardConfig(config, shard, manifest.bounds))) {
        if (key === "vitest") same(object(effective[key], "raw Vitest config").configFile, object(value, "Vitest config").configFile, `${shard.id}: raw Vitest config differs`);
        else if (key !== "$schema" && key !== "_comment") same(effective[key], value, `${shard.id}: raw effective config differs for ${key}`);
      }
      const shardFiles = object(report.files, "Stryker files"); same(Object.keys(shardFiles), [shard.guard], `${shard.id}: missing or duplicate guard population`);
      assert(!Object.hasOwn(files, shard.guard), `${shard.id}: duplicate aggregated guard`);
      const file = object(shardFiles[shard.guard], shard.guard); assert(Array.isArray(file.mutants), `${shard.id}: missing raw mutants`);
      files[shard.guard] = { ...file, mutants: file.mutants.map((value) => {
        const mutant = object(value, "mutant");
        const prefix = (value: unknown) => { assert(Array.isArray(value), "test references must be an array"); return value.map((id) => `${shard.id}:${String(id)}`); };
        return { ...mutant, id: `${shard.id}:${String(mutant.id)}`, ...(mutant.killedBy ? { killedBy: prefix(mutant.killedBy) } : {}), ...(mutant.coveredBy ? { coveredBy: prefix(mutant.coveredBy) } : {}) };
      }) };
      for (const [path, value] of Object.entries(object(report.testFiles ?? {}, "test files"))) {
        const row = object(value, path); assert(Array.isArray(row.tests), `${path}: missing tests`);
        const tests = row.tests.map((value) => { const test = object(value, "test"); return { ...test, id: `${shard.id}:${String(test.id)}` }; });
        (testFiles[path] ??= { tests: [] }).tests.push(...tests);
      }
    }
    terminals.push(t as unknown as GuardShardTerminal);
  }
  same(seal.conservation, { declared: GUARD_SET.length, terminal: terminals.length, completed: terminals.length, failed: 0 }, "aggregate terminal conservation mismatch");
  assert(Date.parse(seal.finishedAt) - Date.parse(manifest.createdAt) <= manifest.bounds.aggregateTimeoutMs + manifest.bounds.killGraceMs + 5_000, "aggregate deadline exceeded");
  const report = { schemaVersion: "1.0", framework: { name: "StrykerJS", version: manifest.toolchain.packages["@stryker-mutator/core"]!.version }, projectRoot: ".", files, testFiles };
  const reportBytes = guardJsonBytes(report);
  const receipt: GuardMutationReceipt = {
    schemaVersion: 1, startedAt: manifest.createdAt, finishedAt: seal.finishedAt, sourceCommit: manifest.sourceCommit,
    reportSha256: guardMutationDigest(reportBytes), configSha256: manifest.configSha256, sourceSha256: manifest.sourceSha256,
    toolchain: manifest.toolchain, exclusionChecks,
  };
  const census = normalizeGuardMutationCensus(report, receipt, guardMutationDigest(reportBytes));
  assert(census.guards.every((guard) => guard.state !== "missing"), "aggregate lost a declared guard");
  return { manifest, report, reportBytes, receipt, census, terminals };
}
