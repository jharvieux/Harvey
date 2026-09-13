import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertCorpusCachePreflight } from "./corpus-cache-preflight.js";
import { semgrepPackReceipt } from "./corpus-mechanical-readiness.js";
import { readRecursiveSafe } from "./fs-walk.js";
import { mechanicalPhasePayloadDigest } from "./scan/mechanical-phase-cache.js";
import { runOsvScanner } from "./scan/dependencies.js";
import { REGISTRY_PACKS, registryPackIdentity } from "./scan/semgrep.js";

const runFile = promisify(execFile);
const root = process.cwd();
const fixtures = join(root, "src", "__fixtures__", "corpus-cache-preflight");
const directories: string[] = [];
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
    const result = await runFile(process.execPath, args, {
      cwd: root,
      env: { ...environment, HARVEY_CORPUS_PHASE_CACHE_DIR: cache, HARVEY_PREFLIGHT_TRACE: trace, ...extraEnvironment },
      maxBuffer: 8 * 1024 * 1024,
    }).then(({ stdout, stderr }) => ({ status: 0, stdout, stderr }), (error: { code: number; stdout: string; stderr: string }) => ({ status: error.code, stdout: error.stdout, stderr: error.stderr }));
    return {
      ...result,
      output: `${result.stdout}\n${result.stderr}`,
      children: existsSync(trace) ? readFileSync(trace, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as { binary: string; args: string[] }) : [],
    };
  }

  const copyCache = (): string => {
    const cache = temporary("harvey-preflight-cache-copy-");
    cpSync(seedCache, cache, { recursive: true });
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
    // This empty dependency population cannot invoke an external provider. Preserve the real
    // input-gap assessment rather than inventing a clean advisory receipt for snapshot tests.
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
    expect(seeded.children.some((child) => child.binary === "semgrep")).toBe(true);
    expect(seeded.output).toContain("CACHE MISS semgrep family");
    expect(seeded.output).toContain("CACHE MISS quality-scan");
  });

  afterAll(() => directories.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("compares every eligible family, phase and scanner after a same-input local seed", async () => {
    const before = artifacts(seedCache);
    const result = await invoke(copyCache(), ["--force-cold-cache"]);
    expect(result.status, result.output).toBe(0);
    for (const { value } of before) {
      if (value.schema === 8 && value.family && value.output) expect(result.output).toContain(`CACHE VERIFY semgrep family ${String(value.family)} ${String(value.key).slice(0, 12)}`);
      if (value.schema === 5 && value.phase) expect(result.output).toContain(`CACHE VERIFY ${String(value.phase)} ${String(value.key).slice(0, 12)}`);
      if (value.schema === 2 && value.scanner) expect(result.output).toContain(`CACHE VERIFY ${String(value.scanner)} ${String(value.key).slice(0, 12)}`);
    }
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
    expect(result.children).toEqual([]);
  });

  it("compares the additional reproducible phase consumers in snapshot mode", async () => {
    const cache = temporary("harvey-preflight-snapshot-cache-");
    const flags = ["--target", "fixture-first"];
    const snapshot = { HARVEY_CORPUS_EXTERNAL_STATE_MODE: "snapshot" };
    const seeded = await invoke(cache, flags, snapshot);
    expect(seeded.status, seeded.output).toBe(0);
    const result = await invoke(cache, [...flags, "--force-cold-cache"], snapshot);
    expect(result.status, result.output).toBe(0);
    expect(result.output).toContain("CACHE VERIFY secrets-history");
    expect(result.output).toContain("CACHE VERIFY dependency-advisory");
    expect(result.children.some((child) => child.binary === "trufflehog")).toBe(false);
    rmSync(join(cache, "shard1", "dependency-advisory"), { recursive: true });
    const missing = await invoke(cache, [...flags, "--force-cold-cache"], snapshot);
    expect(missing.status, missing.output).not.toBe(0);
    expect(missing.output).toContain("mechanical-phase:dependency-advisory: missing:");
    expect(missing.children).toEqual([]);
  });

  it("checks a later target before scanning any earlier target", async () => {
    const cache = copyCache();
    rmSync(join(cache, "shard2"), { recursive: true });
    const result = await invoke(cache, ["--force-cold-cache"]);
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("fixture-later: forced-cold cache preflight rejected");
    expect(result.children).toEqual([]);
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
    expect(result.children).toEqual([]);
  });

  it("rejects a changed observed tool version before execution", async () => {
    const result = await invoke(copyCache(), ["--force-cold-cache"], { HARVEY_PREFLIGHT_TOOL_VERSION: "fixture-2" });
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("identity.externalInputs.semgrep");
    expect(result.children).toEqual([]);
  });

  it("rejects changed materialized configuration and planned ownership identities", async () => {
    const registry = registryFixture(temporary("harvey-preflight-changed-config-"), "changed configuration input");
    const result = await invoke(copyCache(), ["--force-cold-cache"], { HARVEY_SEMGREP_REGISTRY_SNAPSHOT_DIR: registry });
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("identity.externalInputs.registryPacks");
    expect(result.output).toContain("identity.rules");
    expect(result.output).toContain("identity.plannedExecution");
    expect(result.children).toEqual([]);
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
    expect(result.children).toEqual([]);
  });

  it.each(["snapshot", "live-verify"])("rejects a changed %s mode with the exact mismatching option component", async (mode) => {
    const result = await invoke(copyCache(), ["--force-cold-cache"], { HARVEY_CORPUS_EXTERNAL_STATE_MODE: mode });
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("identity.externalInputs.options");
    expect(result.children).toEqual([]);
  });

  it("rejects a malformed exact-address family artifact before expensive execution", async () => {
    const cache = copyCache();
    const family = artifacts(cache).find(({ value }) => value.schema === 8 && value.family && value.output)!;
    writeFileSync(family.path, "{corrupt");
    const result = await invoke(cache, ["--force-cold-cache"]);
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain(`semgrep-family:${String(family.value.family)}: invalid:`);
    expect(result.children).toEqual([]);
    expect(readFileSync(family.path, "utf8")).toBe("{corrupt");
  });

  it("rejects a missing eligible quality seed after real preparation and before mechanical scanning", async () => {
    const cache = copyCache();
    for (const { path, value } of artifacts(cache)) if (value.schema === 2 && value.scanner === "quality-scan") rmSync(path);
    const result = await invoke(cache, ["--force-cold-cache"]);
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain('corpus-scanner:quality-scan {"root":".","install":true}: missing:');
    expect(result.children).toEqual([]);
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

  it("plans eligible source scanners across the population without installing dependencies", async () => {
    const cache = temporary("harvey-preflight-without-install-");
    const seeded = await invoke(cache, [], {}, false);
    expect(seeded.status, seeded.output).toBe(0);
    const verified = await invoke(cache, ["--force-cold-cache"], {}, false);
    expect(verified.status, verified.output).toBe(0);
    expect(verified.output).toContain("CACHE PREFLIGHT EXCLUDED quality-scan");
    expect(verified.output).toContain("CACHE VERIFY detect-static");
    expect(verified.output).toContain("CACHE VERIFY mutation-detect-only");
    rmSync(join(cache, "shard2", "corpus-scanners", "mutation-detect-only"), { recursive: true });
    const missing = await invoke(cache, ["--force-cold-cache"], {}, false);
    expect(missing.status, missing.output).not.toBe(0);
    expect(missing.output).toContain("fixture-later: forced-cold cache preflight rejected");
    expect(missing.output).toContain("corpus-scanner:mutation-detect-only");
    expect(missing.children).toEqual([]);
  });

  it("keeps physically changed fresh family output red after a valid preflight", async () => {
    const result = await invoke(copyCache(), ["--force-cold-cache"], { HARVEY_PREFLIGHT_CHANGED_OUTPUT: "1" });
    expect(result.status, result.output).not.toBe(0);
    expect(result.output).toContain("forced-cold output differs from cached artifact");
    expect(result.children.some((child) => child.binary === "semgrep")).toBe(true);
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
    expect(result.children.some((child) => child.binary === "semgrep")).toBe(true);
  });
});

it("does not turn an empty preflight or a missing comparison into success", () => {
  expect(() => assertCorpusCachePreflight("empty", [])).toThrow("no eligible cache comparisons were planned");
  expect(() => assertCorpusCachePreflight("missing", [{ component: "semgrep-family:auth", status: "missing", reason: "no seed" }])).toThrow("semgrep-family:auth: missing: no seed");
});
