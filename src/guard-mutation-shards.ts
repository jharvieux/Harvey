import assert from "node:assert/strict";
import { access, mkdir, readFile, readdir, realpath, stat, symlink, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { guardMutationDigest, type GuardMutationReceipt } from "./guard-mutation-baseline.js";
import { GUARD_SET } from "./guard-mutation-census.js";
import {
  buildGuardShardManifest, guardExclusionCheck, guardShardConfig, readGuardArtifact,
  readGuardMutationBundle, sealGuardMutationBundle, writeGuardJson,
  type GuardShard, type GuardShardBounds, type GuardShardManifest, type GuardShardTerminal,
} from "./guard-mutation-bundle.js";
import { runGuardCommand, type GuardCommandResult } from "./guard-mutation-process.js";

const digestFile = async (path: string): Promise<string> => guardMutationDigest(await readFile(path));
const sourceDigests = async (root: string): Promise<Record<string, string>> => Object.fromEntries(await Promise.all(GUARD_SET.map(async (file) => [file, await digestFile(join(root, file))])));

async function toolchain(root: string, version: string): Promise<GuardMutationReceipt["toolchain"]> {
  const manifest = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as { packageManager: string };
  assert(`pnpm@${version}` === manifest.packageManager, "installed package manager differs from package.json");
  const requireFromRoot = createRequire(join(root, "package.json"));
  const packages = Object.fromEntries(await Promise.all(["@stryker-mutator/core", "@stryker-mutator/vitest-runner", "vitest", "typescript"].map(async (name) => {
    const bytes = await readFile(requireFromRoot.resolve(`${name}/package.json`));
    return [name, { version: (JSON.parse(bytes.toString("utf8")) as { version: string }).version, packageJsonSha256: guardMutationDigest(bytes) }];
  })));
  return { node: process.version, packageManager: manifest.packageManager, packages, packageJsonSha256: await digestFile(join(root, "package.json")), lockfileSha256: await digestFile(join(root, "pnpm-lock.yaml")) };
}

/** Link installed packages, not the dependency directory. Vite/Vitest and Stryker therefore
 * create their cache and temporary files in this shard's filesystem instead of a sibling's. */
async function linkDependencies(from: string, to: string): Promise<void> {
  await mkdir(to, { recursive: true });
  for (const entry of await readdir(from, { withFileTypes: true })) {
    if (entry.name.startsWith(".") && entry.name !== ".bin") continue;
    const source = join(from, entry.name); const destination = join(to, entry.name);
    if (entry.name === ".bin" || entry.name.startsWith("@")) {
      await mkdir(destination, { recursive: true });
      for (const name of await readdir(source)) await symlink(await realpath(join(source, name)), join(destination, name));
    } else await symlink(await realpath(source), destination);
  }
}

function commandSucceeded(result: GuardCommandResult): boolean {
  return result.state === "exited" && result.exitCode === 0 && result.signal === null && result.terminationAcknowledged && !result.error;
}

async function executeShard(options: {
  root: string; bundleDir: string; manifest: GuardShardManifest; shard: GuardShard;
  config: Record<string, unknown>; version: string; signal: AbortSignal; progress: (line: string) => void;
}): Promise<GuardShardTerminal> {
  const { root, bundleDir, manifest, shard, config, version, signal, progress } = options;
  const started = performance.now();
  const terminal: GuardShardTerminal = {
    schemaVersion: 1, id: shard.id, guard: shard.guard, kind: shard.kind,
    startedAt: new Date().toISOString(), finishedAt: "", elapsedMs: 0, state: "error",
    sourceCommit: manifest.sourceCommit, sourceSha256: manifest.sourceSha256,
    toolchain: manifest.toolchain, configSha256: shard.configSha256, commands: [], error: null, rawReport: null,
  };
  const remaining = () => manifest.bounds.shardTimeoutMs - (performance.now() - started);
  const workspace = join(bundleDir, shard.workspace);
  const command = async (phase: string, args: string[], cwd = workspace): Promise<GuardCommandResult> => {
    if (signal.aborted) throw new Error("aggregate deadline reached");
    if (remaining() <= 0) throw new Error("shard deadline reached");
    const result = await runGuardCommand({
      command: args, cwd, bundleDir, outputPrefix: `shards/${shard.id}/${phase}`,
      timeoutMs: remaining(), killGraceMs: manifest.bounds.killGraceMs, signal,
      onFirstByte: () => progress(`${shard.id} ${phase}: first child byte`),
    });
    terminal.commands.push(result);
    if (result.maxParentBlockMs >= manifest.bounds.maxParentBlockMs) throw new Error(`${phase}: parent exceeded blocking budget`);
    if (result.state !== "exited" || !result.terminationAcknowledged || result.error) throw new Error(`${phase}: ${result.state}; ${result.error ?? result.signal ?? "no completion"}`);
    return result;
  };
  try {
    progress(`${shard.id} START ${shard.kind} ${shard.guard}`);
    const clone = await command("clone", ["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", "--shared", "--no-checkout", "--", root, workspace], root);
    assert(commandSucceeded(clone), "isolated source clone failed");
    const checkout = await command("checkout", ["git", "-c", "core.hooksPath=/dev/null", "checkout", "--quiet", "--detach", manifest.sourceCommit]);
    assert(commandSucceeded(checkout), "immutable source checkout failed");
    await linkDependencies(join(root, "node_modules"), join(workspace, "node_modules"));
    try { await access(join(root, "site", "node_modules")); await linkDependencies(join(root, "site", "node_modules"), join(workspace, "site", "node_modules")); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    assert.deepEqual(await sourceDigests(workspace), manifest.sourceSha256, "isolated checkout source differs from captured commit");
    assert.deepEqual(await toolchain(workspace, version), manifest.toolchain, "isolated toolchain differs from capture");
    assert.equal(await digestFile(join(workspace, "node_modules", ".bin", "stryker")), manifest.launcherSha256, "isolated Stryker launcher differs from capture");
    const configBytes = await readGuardArtifact(bundleDir, shard.configPath);
    assert.equal(guardMutationDigest(configBytes), shard.configSha256, "shard configuration changed before execution");
    assert.deepEqual(JSON.parse(configBytes.toString("utf8")) as unknown, guardShardConfig(config, shard, manifest.bounds), "unexpected effective shard configuration");
    const run = await command("stryker", [join(workspace, "node_modules", ".bin", "stryker"), "run", `../../${shard.configPath}`]);
    const status = await command("restore-status", ["git", "status", "--porcelain", "--untracked-files=no"]);
    assert(commandSucceeded(status) && status.stdout.bytes === 0, "Stryker changed tracked checkout files or did not restore instrumentation");
    terminal.sourceSha256 = await sourceDigests(workspace);
    terminal.toolchain = await toolchain(workspace, version);
    assert.deepEqual(terminal.sourceSha256, manifest.sourceSha256, "Stryker did not restore guard source bytes");
    assert.deepEqual(terminal.toolchain, manifest.toolchain, "toolchain changed during shard execution");
    assert.equal(await digestFile(join(workspace, "node_modules", ".bin", "stryker")), manifest.launcherSha256, "Stryker launcher changed during shard execution");
    assert.equal(await digestFile(join(bundleDir, shard.configPath)), shard.configSha256, "effective configuration changed during shard execution");
    if (shard.kind === "exclusion") {
      const output = (await readGuardArtifact(bundleDir, run.stdout.path)).toString("utf8") + (await readGuardArtifact(bundleDir, run.stderr.path)).toString("utf8");
      assert(guardExclusionCheck(shard, run, output).outcome !== "uncheckable", "exclusion dry run did not produce an actual instrumentation falsifier");
    } else {
      assert(commandSucceeded(run), `Stryker failed with exit ${run.exitCode}`);
      const path = `shards/${shard.id}/mutation.json`;
      terminal.rawReport = { path, sha256: guardMutationDigest(await readGuardArtifact(bundleDir, path)) };
    }
    terminal.state = "completed";
  } catch (error) {
    terminal.error = error instanceof Error ? error.message : String(error);
    terminal.state = signal.aborted ? (terminal.commands.length ? "aggregate-timeout" : "not-started") : remaining() <= 0 || terminal.commands.some((result) => result.state === "timed-out") ? "timed-out" : terminal.commands.some((result) => result.exitCode !== 0) ? "failed" : "error";
    // Failed/timeout reports, if Stryker emitted any, remain raw evidence only. They do not enter
    // normalization, but their bytes must not disappear from the failed bundle's inventory.
    try {
      const path = `shards/${shard.id}/mutation.json`;
      terminal.rawReport = { path, sha256: guardMutationDigest(await readGuardArtifact(bundleDir, path)) };
    } catch { /* A missing report remains an explicit null in the terminal receipt. */ }
  }
  terminal.finishedAt = new Date().toISOString(); terminal.elapsedMs = performance.now() - started;
  try { await writeGuardJson(join(bundleDir, "shards", shard.id, "terminal.json"), terminal); }
  catch (error) { terminal.state = "error"; terminal.error = `cannot retain terminal receipt: ${String(error)}`; }
  progress(`${shard.id} END ${terminal.state} ${(terminal.elapsedMs / 1_000).toFixed(1)}s ${terminal.error ?? ""}`.trim());
  return terminal;
}

/** bundleDir is newly created by the CLI after validating the whole output namespace. */
export async function runGuardMutationShards(options: {
  root: string; configPath: string; bundleDir: string; bounds: GuardShardBounds; progress?: (line: string) => void;
}): Promise<Awaited<ReturnType<typeof readGuardMutationBundle>>> {
  const root = await realpath(options.root); const bundleDir = resolve(options.bundleDir);
  const progress = options.progress ?? (() => {});
  const preflight = async (phase: string, command: string[]): Promise<string> => {
    const result = await runGuardCommand({ command, cwd: root, bundleDir, outputPrefix: `preflight/${phase}`, timeoutMs: 15_000, killGraceMs: options.bounds.killGraceMs });
    await writeGuardJson(join(bundleDir, "preflight", `${phase}.json`), result);
    assert(commandSucceeded(result), `${phase} preflight failed`);
    return (await readGuardArtifact(bundleDir, result.stdout.path)).toString("utf8").trim();
  };
  assert((await stat(join(root, "node_modules"))).isDirectory(), "installed dependencies are required");
  const status = await preflight("status", ["git", "status", "--porcelain"]);
  assert(!status, "a fresh census requires a clean committed worktree; commit changes first");
  const sourceCommit = await preflight("commit", ["git", "rev-parse", "HEAD"]);
  assert(/^[a-f0-9]{40}$/.test(sourceCommit), "capture requires an immutable Git head");
  const version = await preflight("pnpm", ["pnpm", "--version"]);
  const configBytes = await readFile(options.configPath);
  const config = JSON.parse(configBytes.toString("utf8")) as Record<string, unknown>;
  const manifest = buildGuardShardManifest(config, {
    createdAt: new Date().toISOString(), sourceCommit, sourceSha256: await sourceDigests(root),
    toolchain: await toolchain(root, version), configSha256: guardMutationDigest(configBytes), launcherSha256: await digestFile(join(root, "node_modules", ".bin", "stryker")), bounds: options.bounds,
  });
  await writeFile(join(bundleDir, "base.config.json"), configBytes, { flag: "wx" });
  await writeFile(join(bundleDir, "stryker-launcher"), await readFile(join(root, "node_modules", ".bin", "stryker")), { flag: "wx" });
  for (const file of GUARD_SET) { await mkdir(dirname(join(bundleDir, "sources", file)), { recursive: true }); await writeFile(join(bundleDir, "sources", file), await readFile(join(root, file)), { flag: "wx" }); }
  for (const shard of manifest.shards) await writeGuardJson(join(bundleDir, shard.configPath), guardShardConfig(config, shard, manifest.bounds));
  await writeGuardJson(join(bundleDir, "manifest.json"), manifest);
  progress(`MANIFEST ${join(bundleDir, "manifest.json")}: ${manifest.shards.length} guards, concurrency ${manifest.bounds.concurrency}; shard ${manifest.bounds.shardTimeoutMs}ms, aggregate ${manifest.bounds.aggregateTimeoutMs}ms`);
  const abort = new AbortController();
  const cancel = () => abort.abort();
  process.once("SIGTERM", cancel); process.once("SIGINT", cancel);
  const aggregate = setTimeout(() => abort.abort(), Math.max(1, manifest.bounds.aggregateTimeoutMs - (Date.now() - Date.parse(manifest.createdAt))));
  await mkdir(join(bundleDir, "workspaces"));
  let next = 0;
  const terminals: GuardShardTerminal[] = [];
  const workers = Array.from({ length: Math.min(manifest.bounds.concurrency, manifest.shards.length) }, async () => {
    while (next < manifest.shards.length) {
      const shard = manifest.shards[next++]!;
      terminals.push(await executeShard({ root, bundleDir, manifest, shard, config, version, signal: abort.signal, progress }));
    }
  });
  // A sibling's failed terminal never rejects this population. Even an unexpected filesystem
  // failure settles all active workers before the sealed inventory is read and rejected.
  const settled = await Promise.allSettled(workers);
  clearTimeout(aggregate);
  process.removeListener("SIGTERM", cancel); process.removeListener("SIGINT", cancel);
  const runtime = terminals.sort((a, b) => a.id.localeCompare(b.id)).map((terminal) => {
    const run = terminal.commands.find((command) => command.stdout.path.endsWith("/stryker.stdout.log"));
    return { id: terminal.id, guard: terminal.guard, state: terminal.state, startedAt: terminal.startedAt, finishedAt: terminal.finishedAt, elapsedMs: terminal.elapsedMs, firstByteAt: run?.firstByteAt ?? null, fromFirstByteMs: run?.fromFirstByteMs ?? null, maxParentBlockMs: Math.max(0, ...terminal.commands.map((command) => command.maxParentBlockMs)) };
  });
  await writeGuardJson(join(bundleDir, "runtime.json"), { schemaVersion: 1, runtime });
  await writeGuardJson(join(bundleDir, "aggregate.conservation.json"), {
    schemaVersion: 1, declared: manifest.shards.length, terminal: terminals.length,
    completed: terminals.filter((terminal) => terminal.state === "completed").length,
    failed: terminals.filter((terminal) => terminal.state !== "completed").length,
    normalized: false, attempted: null, accounted: null, runtime,
  });
  await sealGuardMutationBundle(bundleDir, manifest, terminals);
  assert(settled.every((worker) => worker.status === "fulfilled"), "one or more shard receipt writers failed; inspect the sealed incomplete bundle");
  const result = await readGuardMutationBundle(bundleDir);
  await writeGuardJson(join(bundleDir, "aggregate.json"), result.report);
  await writeGuardJson(join(bundleDir, "aggregate.receipt.json"), result.receipt);
  await writeGuardJson(join(bundleDir, "census.json"), result.census);
  await writeGuardJson(join(bundleDir, "aggregate.conservation.json"), {
    schemaVersion: 1, bundleSha256: await digestFile(join(bundleDir, "bundle.json")), reportSha256: result.receipt.reportSha256,
    guards: result.census.guards.map(({ file, state, population, exclusion }) => ({ file, state, population, ...(exclusion ? { exclusion } : {}) })),
    attempted: result.census.guards.reduce((sum, guard) => sum + guard.population.attempted, 0),
    accounted: result.census.guards.reduce((sum, guard) => sum + guard.population.killed + guard.population.survived + guard.population.noCoverage + guard.population.unscored, 0),
    runtime,
  });
  return result;
}
