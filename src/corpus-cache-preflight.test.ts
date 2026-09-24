import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { assertCorpusCachePreflight } from "./corpus-cache-preflight.js";
import { semgrepPackReceipt } from "./corpus-mechanical-readiness.js";
import { readRecursiveSafe } from "./fs-walk.js";
import { mechanicalPhasePayloadDigest } from "./scan/mechanical-phase-cache.js";
import { runOsvScanner } from "./scan/dependencies.js";
import { REGISTRY_PACKS, registryPackIdentity } from "./scan/semgrep.js";

const root = process.cwd();
const fixtures = join(root, "src", "__fixtures__", "corpus-cache-preflight");
const directories: string[] = [];
const activeInvocations = new Set<TrackedInvocation>();

interface ExternalInvocation {
  binary: string;
  args: string[];
  cwd: string;
  targetIsCwd?: boolean;
  targetEntries?: string[];
}
interface InvocationResult { status: number | null; stdout: string; stderr: string }
interface TrackedInvocation {
  child: ChildProcess;
  result: Promise<InvocationResult>;
  firstByte: Promise<boolean>;
  progress: () => string;
  finished: boolean;
  cleanup?: Promise<void>;
}

const wait = (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

const registryValidationConfigNames = REGISTRY_PACKS.map((pack, ordinal) => `${ordinal}-${pack.replaceAll("/", "-")}.yml`);

function isRegistryValidation(invocation: ExternalInvocation): boolean {
  const { args } = invocation;
  if (invocation.binary !== "semgrep" || args.length !== 19 || args[0] !== "scan") return false;
  for (let ordinal = 0; ordinal < registryValidationConfigNames.length; ordinal += 1) {
    if (args[1 + (ordinal * 2)] !== "--config" || basename(args[2 + (ordinal * 2)]!) !== registryValidationConfigNames[ordinal]) return false;
  }
  return JSON.stringify(args.slice(13, 18)) === JSON.stringify(["--json", "--strict", "--metrics", "off", "--disable-version-check"])
    && invocation.targetIsCwd === true
    && invocation.targetEntries?.length === 0;
}

function targetScans(invocations: ExternalInvocation[]): ExternalInvocation[] {
  // Receipt validation is an offline parse of six exact local configs against its own empty cwd.
  // Every command that does not carry that complete evidence remains a target/provider execution.
  return invocations.filter((invocation) => !isRegistryValidation(invocation));
}

function signalOwnedInvocation(invocation: TrackedInvocation, signal: NodeJS.Signals): boolean {
  const pid = invocation.child.pid;
  if (pid === undefined) return false;
  try {
    // `detached` below makes this pid the group leader. Never signal a bare PID on POSIX: the
    // corpus CLI can have scanner grandchildren that must leave before its fixture is removed.
    if (process.platform === "win32") return invocation.child.kill(signal);
    process.kill(-pid, signal);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw error;
  }
}

function ownedInvocationGroupExists(invocation: TrackedInvocation): boolean {
  const pid = invocation.child.pid;
  if (pid === undefined || process.platform === "win32") return false;
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw error;
  }
}

async function terminateAndReap(invocation: TrackedInvocation): Promise<void> {
  if (invocation.cleanup !== undefined) return invocation.cleanup;
  invocation.cleanup = (async () => {
    if (!invocation.finished) {
      signalOwnedInvocation(invocation, "SIGTERM");
      await Promise.race([invocation.result.then(() => undefined), wait(250)]);
      if (!invocation.finished) signalOwnedInvocation(invocation, "SIGKILL");
      await invocation.result;
    }
    // A successfully closed CLI should not have any process left in its own group either.
    // This remains scoped to its detached group and is a no-op after ordinary completion.
    if (ownedInvocationGroupExists(invocation)) {
      signalOwnedInvocation(invocation, "SIGKILL");
      const deadline = Date.now() + 500;
      while (ownedInvocationGroupExists(invocation)) {
        if (Date.now() >= deadline) throw new Error(`corpus cache preflight left owned process group ${invocation.child.pid} alive`);
        await wait(10);
      }
    }
  })();
  return invocation.cleanup;
}

async function reapActiveInvocations(): Promise<void> {
  await Promise.all([...activeInvocations].map(terminateAndReap));
}

function reportInterruptedInvocations(): void {
  for (const invocation of activeInvocations) {
    if (!invocation.finished) console.error(invocation.progress());
  }
}

async function waitForFile(path: string, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(path)) {
    if (Date.now() >= deadline) throw new Error(`timed out waiting for fixture record ${path}`);
    await wait(10);
  }
}
const temporary = (prefix: string): string => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  directories.push(dir);
  return dir;
};

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function artifacts(cache: string): Array<{ path: string; value: Record<string, unknown> }> {
  return readRecursiveSafe(cache).filter((path) => path.endsWith(".json")).map((path) => ({ path: join(cache, path), value: JSON.parse(readFileSync(join(cache, path), "utf8")) as Record<string, unknown> }));
}

function registryFixture(registry: string, message = "fixture"): string {
  const packs = REGISTRY_PACKS.map((pack, ordinal) => ({ pack, body: `rules:\n  - id: fixture-registry-${ordinal}\n    languages: [typescript]\n    message: ${message}\n    severity: WARNING\n    pattern: fixture_never_matches()\n` }));
  const identity = registryPackIdentity(packs);
  const packDir = join(registry, "registry-packs", identity);
  mkdirSync(packDir, { recursive: true });
  const files = packs.map(({ pack, body }, ordinal) => {
    const path = join(packDir, `${ordinal}-${pack.replaceAll("/", "-")}.yml`);
    writeFileSync(path, body);
    return path;
  });
  writeFileSync(join(registry, "registry-packs", "current.json"), JSON.stringify({ schema: 1, identity }));
  writeFileSync(join(registry, "receipt.json"), JSON.stringify(semgrepPackReceipt(files, identity)));
  return registry;
}

describe("forced-cold cache preflight through the shipping corpus CLI (#2049)", () => {
  let seedCache: string;
  let environment: NodeJS.ProcessEnv;
  let seedOutput: string;
  let targetRepository: string;

  async function invoke(cache: string, flags: string[] = [], extraEnvironment: NodeJS.ProcessEnv = {}, install = true) {
    const observation = temporary("harvey-preflight-observation-");
    const trace = join(observation, "children.jsonl");
    const cliRoot = extraEnvironment.HARVEY_PREFLIGHT_CLI_ROOT ?? root;
    const mode = extraEnvironment.HARVEY_CORPUS_EXTERNAL_STATE_MODE ?? environment.HARVEY_CORPUS_EXTERNAL_STATE_MODE;
    const args = ["--import", "tsx", "--import", join(fixtures, "hook.mjs"), join(cliRoot, "src", "cli", "corpus-drift.ts"), ...(install ? ["--install"] : []), "--json", join(observation, "scorecard.json"), ...(mode === "live-verify" ? ["--advisory-observation", join(observation, "advisories.json")] : []), ...flags];
    const child = spawn(process.execPath, args, {
      cwd: root,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...environment, HARVEY_CORPUS_PHASE_CACHE_DIR: cache, HARVEY_PREFLIGHT_TRACE: trace, ...extraEnvironment },
    });
    let settle!: (result: InvocationResult) => void;
    const result = new Promise<InvocationResult>((resolve) => { settle = resolve; });
    let observeFirstByte!: (observed: boolean) => void;
    const firstByte = new Promise<boolean>((resolve) => { observeFirstByte = resolve; });
    const startedAt = Date.now();
    let lastOutputAt = startedAt;
    const invocation: TrackedInvocation = {
      child, result, firstByte, finished: false,
      progress: () => `Interrupted corpus preflight CLI (pid ${child.pid}, ${(Date.now() - startedAt) / 1000}s elapsed, ${(Date.now() - lastOutputAt) / 1000}s since output)\nstdout tail:\n${stdout.slice(-2_000)}\nstderr tail:\n${stderr.slice(-6_000)}`,
    };
    // The outer CLI owns scanner children. A detached group lets test teardown terminate only this
    // invocation and await it before the shared disposable fixture directories are removed.
    let stdout = "";
    let stderr = "";
    let outputBytes = 0;
    let settled = false;
    let observedFirstByte = false;
    const finish = (status: number | null, cause = "") => {
      if (settled) return;
      settled = true;
      if (!observedFirstByte) observeFirstByte(false);
      invocation.finished = true;
      settle({ status, stdout, stderr: `${stderr}${cause}` });
    };
    const retain = (kind: "stdout" | "stderr") => (chunk: Buffer) => {
      lastOutputAt = Date.now();
      if (!observedFirstByte) {
        observedFirstByte = true;
        observeFirstByte(true);
      }
      outputBytes += chunk.length;
      if (outputBytes > 8 * 1024 * 1024) {
        signalOwnedInvocation(invocation, "SIGKILL");
        finish(null, "\npreflight CLI output exceeded 8 MiB\n");
        return;
      }
      if (kind === "stdout") stdout += chunk.toString("utf8");
      else stderr += chunk.toString("utf8");
    };
    child.stdout.on("data", retain("stdout"));
    child.stderr.on("data", retain("stderr"));
    child.once("error", (error) => finish(null, `\n${error.message}\n`));
    child.once("close", (code) => finish(code));
    activeInvocations.add(invocation);
    const completed = await result;
    await terminateAndReap(invocation);
    activeInvocations.delete(invocation);
    return {
      ...completed,
      output: `${completed.stdout}\n${completed.stderr}`,
      children: existsSync(trace) ? readFileSync(trace, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as ExternalInvocation) : [],
    };
  }

  const copyCache = (source = seedCache): string => {
    const cache = temporary("harvey-preflight-cache-copy-");
    cpSync(source, cache, { recursive: true });
    return cache;
  };

  beforeAll(async () => {
    const fixtureRoot = temporary("harvey-preflight-inputs-");
    const target = join(fixtureRoot, "target");
    targetRepository = target;
    mkdirSync(target);
    writeFileSync(join(target, "package.json"), `${JSON.stringify({ name: "cache-preflight-fixture", version: "1.0.0", private: true, license: "MIT", scripts: { test: "node --test" } })}\n`);
    writeFileSync(join(target, "package-lock.json"), `${JSON.stringify({ name: "cache-preflight-fixture", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "cache-preflight-fixture", version: "1.0.0", license: "MIT" } } })}\n`);
    writeFileSync(join(target, "index.ts"), 'console.log("cache preflight fixture");\n');
    writeFileSync(join(target, "index.test.ts"), 'import { test } from "node:test";\nimport { strictEqual } from "node:assert";\ntest("compares actual values", () => strictEqual(1 + 1, 2));\n');
    mkdirSync(join(target, "nested"));
    cpSync(join(target, "package.json"), join(target, "nested", "package.json"));
    cpSync(join(target, "package-lock.json"), join(target, "nested", "package-lock.json"));
    writeFileSync(join(target, "nested", "index.ts"), 'console.log("independent nested quality root");\n');
    for (const args of [["init", "-q"], ["add", "."], ["-c", "user.name=Cache fixture", "-c", "user.email=cache@example.invalid", "commit", "-qm", "Pin offline cache fixture"]]) execFileSync("git", ["-C", target, ...args]);
    const commit = execFileSync("git", ["-C", target, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    const targets = join(fixtureRoot, "targets.json");
    const advisories = join(fixtureRoot, "advisories");
    mkdirSync(advisories);
    // Preserve the real provider wrapper's input-gap assessment for this empty dependency
    // population in the snapshot fixture.
    const { result, assessment } = runOsvScanner(target);
    const bytes = gzipSync(JSON.stringify({ schema: 1, result, assessment }));
    writeFileSync(join(advisories, "fixture.osv.json.gz"), bytes);
    writeFileSync(join(advisories, "manifest.json"), JSON.stringify({ schema: 2, targets: Object.fromEntries(["fixture-first", "fixture-later"].map((slug) => [slug, {
      file: "fixture.osv.json.gz", sha256: createHash("sha256").update(bytes).digest("hex"), targetCommit: commit,
      capturedAt: "2026-01-01T00:00:00Z", expiresAt: "2099-01-01T00:00:00Z", osvScannerVersion: "fixture-osv-1",
    }])) }));
    // The detect-only consumer does not recognize strictEqual as a supported assertion;
    // its one assertion-free-suite finding is retained by both cache passes.
    writeFileSync(targets, JSON.stringify(["fixture-first", "fixture-later"].map((slug) => ({ slug, repo: "fixture/cache-target", commit, modules: { M4: { counted: 0, total: 0 }, M8: { counted: 1, total: 1 }, "M1-boundary": { counted: 0, total: 0 } }, ...(slug === "fixture-later" ? { scanRoots: { "M5-knip": "nested" } } : {}) }))));
    const registry = registryFixture(join(fixtureRoot, "registry"));
    const bin = join(fixtureRoot, "bin");
    mkdirSync(bin);
    // Reuse only V8's bytecode for unchanged module bytes. Every scanner still starts its real
    // CLI and recomputes findings. The launcher reaches tools inside quality's bounded PATH
    // without widening its production environment allowlist; the whole cache is suite-owned.
    const compileCache = join(fixtureRoot, "node-compile-cache");
    const nodeLauncher = join(bin, "node");
    const shellQuote = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;
    writeFileSync(nodeLauncher, `#!/bin/sh\nexport NODE_COMPILE_CACHE=${shellQuote(compileCache)}\nexec ${shellQuote(process.execPath)} "$@"\n`);
    chmodSync(nodeLauncher, 0o755);
    // Copy before chmod: a test must never mutate committed fixture permissions or a shared tool.
    const binary = join(bin, "binary.mjs");
    cpSync(join(fixtures, "binary.mjs"), binary);
    symlinkSync(join(root, "node_modules"), join(fixtureRoot, "node_modules"), "dir");
    chmodSync(binary, 0o755);
    for (const name of ["semgrep", "gitleaks", "trufflehog", "osv-scanner"]) symlinkSync(binary, join(bin, name));
    environment = {
      ...process.env,
      pnpm_config_verify_deps_before_run: "false",
      PATH: `${bin}:${process.env.PATH}`,
      NODE_COMPILE_CACHE: compileCache,
      HARVEY_PREFLIGHT_TARGETS: targets,
      HARVEY_PREFLIGHT_ADVISORIES: advisories,
      HARVEY_CORPUS_EXTERNAL_STATE_MODE: "live",
      HARVEY_CURRENT_MECHANICAL_READINESS: "0",
      HARVEY_SEMGREP_REGISTRY_SNAPSHOT_MODE: "reuse",
      HARVEY_SEMGREP_REGISTRY_SNAPSHOT_DIR: registry,
      HARVEY_CORPUS_CACHE_DIR: join(fixtureRoot, "clone-cache"),
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: `url.file://${target}.insteadOf`,
      GIT_CONFIG_VALUE_0: "https://github.com/fixture/cache-target",
    };
    seedCache = temporary("harvey-preflight-seed-");
    const seeded = await invoke(seedCache);
    seedOutput = seeded.output;
    expect(seeded.status, seeded.output).toBe(0);
    expect(targetScans(seeded.children).some((child) => child.binary === "semgrep")).toBe(true);
    expect(seeded.output).toContain("CACHE MISS semgrep family");
    expect(seeded.output).toContain("CACHE MISS quality-scan");
  });

  afterEach(async ({ task }) => {
    if (task.result?.state === "fail") reportInterruptedInvocations();
    await reapActiveInvocations();
  });

  afterAll(async () => {
    reportInterruptedInvocations();
    await reapActiveInvocations();
    directories.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true }));
  });

  it.each([
    ["fixture-first", 22],
    ["fixture-later", 23],
  ] as const)("compares every eligible family, phase and scanner for %s after a same-input local seed", async (slug, expectedCount) => {
    const before = artifacts(seedCache);
    const result = await invoke(copyCache(), ["--force-cold-cache", "--target", slug]);
    expect(result.status, result.output).toBe(0);
    const expected = before.flatMap(({ path, value }) => {
      const component = value.schema === 8 && value.family && value.output ? `semgrep family ${String(value.family)}`
        : value.schema === 5 && value.phase ? String(value.phase)
          : value.schema === 2 && value.scanner ? String(value.scanner) : undefined;
      const artifactSlug = path.startsWith(join(seedCache, "shard1")) ? "fixture-first" : "fixture-later";
      return component ? [`${artifactSlug}: CACHE VERIFY ${component} ${String(value.key).slice(0, 12)}`] : [];
    });
    expect(expected).toHaveLength(45);
    expect(new Set(expected).size).toBe(45);
    const selected = expected.filter((line) => line.startsWith(`${slug}: `));
    expect(selected).toHaveLength(expectedCount);
    const shard = slug === "fixture-first" ? "shard1" : "shard2";
    expect(new Set(before.filter(({ path, value }) => path.startsWith(join(seedCache, shard)) && value.schema === 2).map(({ value }) => value.scanner)))
      .toEqual(new Set(["detect-static", "quality-scan", "mutation-detect-only"]));
    const compared = [...result.output.matchAll(/^ {2}(fixture-(?:first|later): CACHE VERIFY .+? [a-f0-9]{12}):/gm)].map((match) => match[1]!);
    expect(compared.sort()).toEqual(selected.sort());
    expect(new Set(before.filter(({ value }) => value.schema === 2).map(({ value }) => value.scanner)))
      .toEqual(new Set(["detect-static", "quality-scan", "mutation-detect-only"]));
    expect(result.output).not.toContain("CACHE MISS semgrep family");
    expect(seedOutput).not.toContain("CACHE VERIFY");
    expect(result.output).toContain("Live provider phases and dependency installation are not cache-equivalence proof");
    expect(result.children.some((child) => child.binary === "trufflehog")).toBe(true);
  });

  it("rejects absent seeds before any family or provider scan", async () => {
    const result = await invoke(temporary("harvey-preflight-empty-"), ["--force-cold-cache"]);
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("fixture-first: forced-cold cache preflight rejected before scan execution");
    expect(result.output).toContain("semgrep-family:");
    expect(result.output).toContain("missing:");
    expect(result.output).toContain("without --force-cold-cache");
    expect(result.children.some(isRegistryValidation), JSON.stringify(result.children, null, 2)).toBe(true);
    expect(targetScans(result.children)).toEqual([]);
  });

  describe("snapshot phase consumers", () => {
    let snapshotSeed: string;
    const flags = ["--target", "fixture-first"];
    const snapshot = { HARVEY_CORPUS_EXTERNAL_STATE_MODE: "snapshot" };

    beforeAll(async () => {
      snapshotSeed = temporary("harvey-preflight-snapshot-cache-");
      const seeded = await invoke(snapshotSeed, flags, snapshot);
      expect(seeded.status, seeded.output).toBe(0);
    });

    it("compares the additional reproducible phase consumers in snapshot mode", async () => {
      const result = await invoke(copyCache(snapshotSeed), [...flags, "--force-cold-cache"], snapshot);
      expect(result.status, result.output).toBe(0);
      expect(result.output).toContain("CACHE VERIFY secrets-history");
      expect(result.output).toContain("CACHE VERIFY dependency-advisory");
      expect(result.children.some((child) => child.binary === "trufflehog")).toBe(false);
    });

    it("rejects a missing snapshot advisory seed before any scan", async () => {
      const cache = copyCache(snapshotSeed);
      rmSync(join(cache, "shard1", "dependency-advisory"), { recursive: true });
      const missing = await invoke(cache, [...flags, "--force-cold-cache"], snapshot);
      expect(missing.status, missing.output).not.toBe(0);
      expect(missing.output).toContain("mechanical-phase:dependency-advisory: missing:");
      expect(targetScans(missing.children)).toEqual([]);
    });
  });

  it("checks a later target before scanning any earlier target", async () => {
    const cache = copyCache();
    rmSync(join(cache, "shard2"), { recursive: true });
    const result = await invoke(cache, ["--force-cold-cache"]);
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("fixture-later: forced-cold cache preflight rejected");
    expect(targetScans(result.children)).toEqual([]);
  });

  it("rejects physically changed Harvey source through the production implementation builder", async () => {
    const changedRoot = temporary("harvey-preflight-changed-source-");
    for (const path of ["src", "tools", "report-template", "package.json", "pnpm-lock.yaml", "audit-execution-log.json"]) cpSync(join(root, path), join(changedRoot, path), { recursive: true });
    symlinkSync(join(root, "node_modules"), join(changedRoot, "node_modules"), "dir");
    const path = join(changedRoot, "src", "scan", "mechanical.ts");
    writeFileSync(path, `${readFileSync(path, "utf8")}\n// physically changed implementation input\n`);
    const result = await invoke(copyCache(), ["--force-cold-cache"], { HARVEY_PREFLIGHT_CLI_ROOT: changedRoot });
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("identity.implementation");
    expect(targetScans(result.children)).toEqual([]);
  });

  it("rejects a changed observed tool version before execution", async () => {
    const changedBin = temporary("harvey-preflight-changed-tool-");
    const binary = join(changedBin, "binary.mjs");
    const semgrep = join(changedBin, "semgrep");
    cpSync(join(fixtures, "binary.mjs"), binary);
    chmodSync(binary, 0o755);
    symlinkSync(binary, semgrep);
    symlinkSync(join(root, "node_modules"), join(changedBin, "node_modules"), "dir");
    const observedVersion = () => execFileSync(semgrep, ["--version"], { env: environment, encoding: "utf8" }).trim();
    expect(observedVersion()).toBe("semgrep fixture-1");
    // Warm this exact path, then change its bytes: V8 reuse must not preserve the prior tool
    // behavior, and the production version probe must still reject its now-incompatible seed.
    writeFileSync(binary, readFileSync(binary, "utf8").replace('?? "fixture-1"', '?? "fixture-2"'));
    expect(observedVersion()).toBe("semgrep fixture-2");
    const result = await invoke(copyCache(), ["--force-cold-cache"], { PATH: `${changedBin}:${environment.PATH}` });
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("identity.externalInputs.semgrep");
    expect(targetScans(result.children)).toEqual([]);
  });

  it("rejects changed materialized configuration and planned ownership identities", async () => {
    const registry = registryFixture(temporary("harvey-preflight-changed-config-"), "changed configuration input");
    const result = await invoke(copyCache(), ["--force-cold-cache"], { HARVEY_SEMGREP_REGISTRY_SNAPSHOT_DIR: registry });
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("identity.externalInputs.registryPacks");
    expect(result.output).toContain("identity.rules");
    expect(result.output).toContain("identity.plannedExecution");
    expect(targetScans(result.children)).toEqual([]);
  });

  it("rejects a changed later target pin/tree before scanning the earlier pin", async () => {
    writeFileSync(join(targetRepository, "new-source.ts"), 'console.log("changed target input");\n');
    execFileSync("git", ["-C", targetRepository, "add", "new-source.ts"]);
    execFileSync("git", ["-C", targetRepository, "-c", "user.name=Cache fixture", "-c", "user.email=cache@example.invalid", "commit", "-qm", "Move disposable target pin"]);
    const commit = execFileSync("git", ["-C", targetRepository, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    const targets = JSON.parse(readFileSync(environment.HARVEY_PREFLIGHT_TARGETS!, "utf8")) as Array<{ slug: string; commit: string }>;
    targets[1]!.commit = commit;
    const input = join(temporary("harvey-preflight-moved-pin-"), "targets.json");
    writeFileSync(input, JSON.stringify(targets));
    const result = await invoke(copyCache(), ["--force-cold-cache"], { HARVEY_PREFLIGHT_TARGETS: input });
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("fixture-later: forced-cold cache preflight rejected");
    expect(result.output).toContain("identity.targetRevision");
    expect(result.output).toContain("identity.targetTree");
    expect(targetScans(result.children)).toEqual([]);
  });

  it.each(["snapshot", "live-verify"])("rejects a changed %s mode with the exact mismatching option component", async (mode) => {
    const result = await invoke(copyCache(), ["--force-cold-cache"], { HARVEY_CORPUS_EXTERNAL_STATE_MODE: mode });
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("identity.externalInputs.options");
    expect(targetScans(result.children)).toEqual([]);
  });

  it("rejects a malformed exact-address family artifact before expensive execution", async () => {
    const cache = copyCache();
    const family = artifacts(cache).find(({ value }) => value.schema === 8 && value.family && value.output)!;
    writeFileSync(family.path, "{corrupt");
    const result = await invoke(cache, ["--force-cold-cache"]);
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain(`semgrep-family:${String(family.value.family)}: invalid:`);
    expect(targetScans(result.children)).toEqual([]);
    expect(readFileSync(family.path, "utf8")).toBe("{corrupt");
  });

  it("rejects a missing eligible quality seed after real preparation and before mechanical scanning", async () => {
    const cache = copyCache();
    for (const { path, value } of artifacts(cache)) if (value.schema === 2 && value.scanner === "quality-scan") rmSync(path);
    const result = await invoke(cache, ["--force-cold-cache"]);
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain('corpus-scanner:quality-scan {"root":".","install":true}: missing:');
    expect(targetScans(result.children)).toEqual([]);
    expect(result.output).not.toContain("SCANNER quality-scan —");
  });

  it("checks the scoped quality consumer at its own real preparation boundary", async () => {
    const cache = copyCache();
    const qualityKeys = [...seedOutput.matchAll(/fixture-later: CACHE MISS quality-scan ([a-f0-9]+)/g)].map((match) => match[1]!);
    expect(qualityKeys).toHaveLength(2);
    const scoped = artifacts(cache).find(({ value }) => value.schema === 2 && value.scanner === "quality-scan" && String(value.key).startsWith(qualityKeys[1]!))!;
    rmSync(scoped.path);
    const result = await invoke(cache, ["--force-cold-cache"]);
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain('corpus-scanner:quality-scan {"root":"nested","install":true}: incompatible:');
    expect(result.output).toContain("identity.externalInputs.targetConfig");
    expect(result.output).toContain("CACHE VERIFY quality-scan");
    expect(result.output).not.toContain(`CACHE MISS quality-scan ${qualityKeys[1]}`);
  });

  describe("source scanner population without dependency installation", () => {
    let sourceSeed: string;

    beforeAll(async () => {
      sourceSeed = temporary("harvey-preflight-without-install-");
      const seeded = await invoke(sourceSeed, [], {}, false);
      expect(seeded.status, seeded.output).toBe(0);
    });

    it("plans eligible source scanners across the population without installing dependencies", async () => {
      const verified = await invoke(copyCache(sourceSeed), ["--force-cold-cache"], {}, false);
      expect(verified.status, verified.output).toBe(0);
      expect(verified.output).toContain("CACHE PREFLIGHT EXCLUDED quality-scan");
      expect(verified.output).toContain("CACHE VERIFY detect-static");
      expect(verified.output).toContain("CACHE VERIFY mutation-detect-only");
    });

    it("rejects a missing later source scanner seed across the uninstalled population", async () => {
      const cache = copyCache(sourceSeed);
      rmSync(join(cache, "shard2", "corpus-scanners", "mutation-detect-only"), { recursive: true });
      const missing = await invoke(cache, ["--force-cold-cache"], {}, false);
      expect(missing.status, missing.output).not.toBe(0);
      expect(missing.output).toContain("fixture-later: forced-cold cache preflight rejected");
      expect(missing.output).toContain("corpus-scanner:mutation-detect-only");
      expect(targetScans(missing.children)).toEqual([]);
    });
  });

  it("keeps physically changed fresh family output red after a valid preflight", async () => {
    const result = await invoke(copyCache(), ["--force-cold-cache"], { HARVEY_PREFLIGHT_CHANGED_OUTPUT: "1" });
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("forced-cold output differs from cached artifact");
    expect(targetScans(result.children).some((child) => child.binary === "semgrep")).toBe(true);
  });

  it("reaps a cancelled CLI group before its disposable tool fixture can write again", async () => {
    const record = join(temporary("harvey-preflight-cancel-record-"), "lifecycle.json");
    const pending = invoke(temporary("harvey-preflight-cancel-cache-"), [], {
      HARVEY_PREFLIGHT_HANG: "semgrep",
      HARVEY_PREFLIGHT_CANCEL_RECORD: record,
    });
    const invocation = [...activeInvocations][0];
    expect(invocation).toBeDefined();
    expect(await invocation!.firstByte).toBe(true);
    await waitForFile(record);
    await terminateAndReap(invocation!);
    const result = await pending;
    expect(result.status, result.output).not.toBe(0);
    const first = readFileSync(record, "utf8");
    const { toolPid, descendantPid } = JSON.parse(first) as { toolPid: number; descendantPid: number };
    expect(() => process.kill(toolPid, 0)).toThrow();
    expect(() => process.kill(descendantPid, 0)).toThrow();
    await wait(75);
    expect(readFileSync(record, "utf8")).toBe(first);
  });

  it.each(["phase", "scanner"])("compares %s semantic output rather than accepting a validated artifact alone", async (kind) => {
    const cache = copyCache();
    const row = artifacts(cache).find(({ value }) => kind === "phase" ? value.schema === 5 && value.phase === "configuration" : value.schema === 2 && value.scanner === "detect-static")!;
    (row.value.scope as { description: string }).description += " physically changed seed scope";
    row.value.payloadDigest = kind === "phase"
      ? mechanicalPhasePayloadDigest(row.value as unknown as Parameters<typeof mechanicalPhasePayloadDigest>[0])
      : createHash("sha256").update(stable({ findings: row.value.findings, scope: row.value.scope })).digest("hex");
    writeFileSync(row.path, JSON.stringify(row.value));
    const result = await invoke(cache, ["--force-cold-cache"]);
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain(`${kind === "phase" ? "configuration" : "detect-static"}: forced-cold result differs`);
    expect(targetScans(result.children).some((child) => child.binary === "semgrep")).toBe(true);
  });
});

it("does not turn an empty preflight or a missing comparison into success", () => {
  expect(() => assertCorpusCachePreflight("empty", [])).toThrow("no eligible cache comparisons were planned");
  expect(() => assertCorpusCachePreflight("missing", [{ component: "semgrep-family:auth", status: "missing", reason: "no seed" }])).toThrow("semgrep-family:auth: missing: no seed");
});

it("does not let a target scan borrow the registry-validator exemption", () => {
  const validation: ExternalInvocation = {
    binary: "semgrep",
    args: [
      "scan",
      ...registryValidationConfigNames.flatMap((name) => ["--config", `/receipt/${name}`]),
      "--json", "--strict", "--metrics", "off", "--disable-version-check", "/empty-validator-target",
    ],
    cwd: "/empty-validator-target",
    targetIsCwd: true,
    targetEntries: [],
  };
  expect(targetScans([validation])).toEqual([]);
  for (const illicit of [
    { ...validation, targetIsCwd: false },
    { ...validation, targetEntries: ["target-source.ts"] },
    { ...validation, args: validation.args.with(2, "/receipt/target-rule.yml") },
    { ...validation, args: validation.args.filter((arg) => arg !== "--strict") },
  ]) {
    expect(targetScans([illicit]), JSON.stringify(illicit)).toEqual([illicit]);
  }
});
