import { execFile, execFileSync, spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { promisify } from "node:util";
import ts from "typescript";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildHtml } from "../report-template/render.mjs";
import { installCorpusDependencyExtras, prepareCorpusDependencies, releaseCorpusDependencies } from "./corpus-dependency-preparation.js";
import { observePackageManager } from "./corpus-package-manager.js";
import { runCorpusScanner } from "./corpus-scanner-runner.js";
import { digestObservedPaths } from "./corpus-scanner-scope.js";
import { readNamesSafe } from "./fs-walk.js";
import { SecretInArgvError } from "./secret-argv.js";
import * as packageManagers from "./package-manager.js";
import type { Finding } from "./findings.js";
import { mutationRunFromArtifact } from "./mutation-scan.js";
import { materializeM8Config, type M8CorpusConfig } from "./scan/m8-corpus.js";

const spawnState = vi.hoisted(() => ({ active: 0, maxActive: 0 }));

// Record the production boundary while executing the real quality CLI and its local scanners.
vi.mock("node:child_process", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:child_process")>();
  return {
    ...original,
    spawn: vi.fn((command: string, args: readonly string[], options: Parameters<typeof original.spawn>[2]) => {
      const child = original.spawn(command, args, options);
      spawnState.active += 1;
      spawnState.maxActive = Math.max(spawnState.maxActive, spawnState.active);
      child.once("close", () => { spawnState.active -= 1; });
      return child;
    }),
  };
});

const execFileAsync = promisify(execFile);

interface ProcessResult {
  statuses: Record<string, string>;
  findingCounts: Record<string, number>;
  scopeUnits: Record<string, number>;
  scopeDescriptions: Record<string, string>;
  scopeObservations: Record<string, { scanner: string }>;
  qualityLocation: string;
  qualityLocations: string[];
  preparation: string;
  preparationCacheable: boolean;
  events: string[];
}

type SyntheticScanner = "detect-static" | "quality-scan" | "mutation-detect-only";

function syntheticScope(scanner: SyntheticScanner): Record<string, unknown> {
  const pathsDigest = digestObservedPaths(["unit.ts"]);
  const common = { schema: 1, scanner, unitsExamined: 1, description: `synthetic ${scanner} scope after child close` };
  if (scanner === "detect-static") {
    return { ...common, observation: { scanner, loadedSources: { count: 1, pathsDigest }, ancillary: { productSources: 1, configSources: 0, testStorySources: 0 } } };
  }
  if (scanner === "quality-scan") {
    return {
      ...common,
      observation: {
        scanner,
        productSources: { count: 1, pathsDigest },
        jscpd: { status: "completed", comparedLines: 1 },
        knip: { discovered: [], completed: [], reduced: [], incomplete: [] },
        divergedClones: { securityPathSources: 0, wholeRepoEnabled: false, complementSources: 0 },
      },
    };
  }
  return {
    ...common,
    observation: {
      scanner,
      testSources: { count: 1, pathsDigest },
      suiteSignals: { packageManifest: true, strykerConfig: true, ancestorWorkspaceSuite: null, childWorkspaceSuites: [] },
    },
  };
}

function mockScannerChild(options: {
  scanner: SyntheticScanner;
  delayMs?: number;
  code?: number | null;
  signal?: NodeJS.Signals | null;
  malformedOutput?: boolean;
}): void {
  vi.mocked(spawn).mockImplementationOnce(((command: string, args: readonly string[]) => {
    const child = new EventEmitter() as ChildProcess;
    Object.defineProperty(child, "stdin", { value: null });
    Object.defineProperty(child, "killed", { value: false, writable: true });
    Object.defineProperty(child, "kill", { value: () => { Reflect.set(child, "killed", true); return true; } });
    spawnState.active += 1;
    spawnState.maxActive = Math.max(spawnState.maxActive, spawnState.active);
    child.once("close", () => { spawnState.active -= 1; });
    setTimeout(() => {
      const code = options.code === undefined ? 0 : options.code;
      const signal = options.signal ?? null;
      if (code === 0 && signal === null) {
        const outIndex = args.indexOf("--out");
        const scopeIndex = args.indexOf("--scope-out");
        if (outIndex < 0 || scopeIndex < 0) throw new Error(`${command}: synthetic child received no output paths`);
        writeFileSync(args[outIndex + 1]!, options.malformedOutput ? "{" : "[]\n");
        writeFileSync(args[scopeIndex + 1]!, `${JSON.stringify(syntheticScope(options.scanner))}\n`);
      }
      child.emit("close", code, signal);
    }, options.delayMs ?? 10);
    return child;
  }) as typeof spawn);
}

function mockStdinFailureChild(options: {
  primaryError: Error;
  cleanupError: Error;
  closeDelayMs?: number;
}): void {
  vi.mocked(spawn).mockImplementationOnce((() => {
    const child = new EventEmitter() as ChildProcess;
    const stdin = new EventEmitter() as NonNullable<ChildProcess["stdin"]>;
    Object.defineProperty(stdin, "end", {
      value: () => { queueMicrotask(() => stdin.emit("error", options.primaryError)); },
    });
    Object.defineProperty(child, "stdin", { value: stdin });
    Object.defineProperty(child, "killed", { value: false, writable: true });
    Object.defineProperty(child, "kill", {
      value: () => {
        Reflect.set(child, "killed", true);
        child.emit("error", options.cleanupError);
        setTimeout(() => child.emit("close", null, "SIGTERM"), options.closeDelayMs ?? 30);
        return true;
      },
    });
    spawnState.active += 1;
    spawnState.maxActive = Math.max(spawnState.maxActive, spawnState.active);
    child.once("close", () => { spawnState.active -= 1; });
    return child;
  }) as typeof spawn);
}

describe("corpus scanner execution across processes and checkout paths (#1871/#1872)", () => {
  const dirs: string[] = [];
  afterEach(() => {
    dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true }));
    vi.clearAllMocks();
    spawnState.active = 0;
    spawnState.maxActive = 0;
  });

  it("yields the worker before the first scanner event and reads delayed output only after child close (#1996)", async () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-async-close-"));
    dirs.push(targetDir);
    writeFileSync(join(targetDir, "package.json"), '{"name":"async-close-control","private":true}\n');
    const events: string[] = [];
    mockScannerChild({ scanner: "mutation-detect-only", delayMs: 40 });
    const timer = setTimeout(() => events.push("timer-serviced"), 0);
    const result = await runCorpusScanner({
      repoRoot: process.cwd(), targetDir, targetConfig: "async close control",
      script: "mutation-scan", scanner: "mutation-detect-only", scriptArgs: [targetDir, "--detect-only"],
      onEvent: (message) => events.push(message),
    });
    clearTimeout(timer);

    expect(events[0]).toBe("timer-serviced");
    expect(events[1]).toContain("SCANNER mutation-detect-only — fresh; 1 unit(s)");
    expect(result.findings).toEqual([]);
    expect(spawnState).toMatchObject({ active: 0, maxActive: 1 });
  });

  it("does not overlap scanner variants when each awaited call starts after the prior child closes (#1996)", async () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-sequential-"));
    dirs.push(targetDir);
    writeFileSync(join(targetDir, "package.json"), '{"name":"sequential-control","private":true}\n');
    for (const scanner of ["detect-static", "quality-scan", "mutation-detect-only"] as const) {
      mockScannerChild({ scanner, delayMs: 20 });
      const invocation = scanner === "detect-static"
        ? { script: "detect-static" as const, scanner, scriptArgs: [targetDir] }
        : scanner === "quality-scan"
          ? { script: "quality-scan" as const, scanner, scriptArgs: [targetDir] }
          : { script: "mutation-scan" as const, scanner, scriptArgs: [targetDir, "--detect-only"] };
      await runCorpusScanner({ repoRoot: process.cwd(), targetDir, targetConfig: `${scanner} sequential control`, ...invocation });
    }
    expect(spawnState).toMatchObject({ active: 0, maxActive: 1 });
  });

  it("waits for close after a stdin failure, preserves that primary error, and does not overlap the next scanner (#1996)", async () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-stdin-close-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-stdin-close-cache-"));
    dirs.push(targetDir, cacheDir);
    writeFileSync(join(targetDir, "package.json"), '{"name":"stdin-close-control","private":true}\n');
    const events: string[] = [];
    const primaryError = new Error("synthetic stdin write failed");
    const cleanupError = new Error("synthetic kill cleanup failed");
    mockStdinFailureChild({ primaryError, cleanupError, closeDelayMs: 40 });

    const failed = await runCorpusScanner({
      repoRoot: process.cwd(), targetDir, targetConfig: "stdin failure close control",
      script: "quality-scan", scanner: "quality-scan", scriptArgs: [targetDir],
      cache: {
        dir: cacheDir, mode: "read-write", targetRevision: "stdin-failure-pin", targetTree: "stdin-failure-tree",
        dependencyPreparation: {
          status: "incomplete", complete: false, cacheable: false, packageManager: "npm", packageManagerVersion: "fixture",
          reason: "synthetic dependency preparation failure",
        },
      },
      onEvent: (message) => events.push(message),
    });

    expect(failed.findings).toContainEqual(expect.objectContaining({ id: "M5-00", evidence: expect.stringContaining("synthetic dependency preparation failure") }));
    expect(events.join("\n")).toContain(primaryError.message);
    expect(events.join("\n")).not.toContain(cleanupError.message);
    expect(spawnState.active).toBe(0);

    mockScannerChild({ scanner: "mutation-detect-only", delayMs: 10 });
    await runCorpusScanner({
      repoRoot: process.cwd(), targetDir, targetConfig: "post-stdin-failure overlap control",
      script: "mutation-scan", scanner: "mutation-detect-only", scriptArgs: [targetDir, "--detect-only"],
    });
    expect(spawnState).toMatchObject({ active: 0, maxActive: 1 });
  });

  it.each([
    { name: "nonzero exit", code: 7, signal: null, malformedOutput: false, reason: "exited with code 7" },
    { name: "signal", code: null, signal: "SIGTERM" as const, malformedOutput: false, reason: "killed by signal SIGTERM" },
    { name: "malformed output", code: 0, signal: null, malformedOutput: true, reason: "incomplete output was not stored" },
  ])("keeps a $name incomplete and non-cacheable, then retries it as a miss (#1996)", async ({ code, signal, malformedOutput, reason }) => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-child-failure-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-child-failure-cache-"));
    dirs.push(targetDir, cacheDir);
    writeFileSync(join(targetDir, "package.json"), '{"name":"child-failure-control","private":true}\n');
    const events: string[] = [];
    const run = () => runCorpusScanner({
      repoRoot: process.cwd(), targetDir, targetConfig: "child failure control",
      script: "mutation-scan", scanner: "mutation-detect-only", scriptArgs: [targetDir, "--detect-only"],
      cache: { dir: cacheDir, mode: "read-write", targetRevision: "failure-pin", targetTree: "failure-tree" },
      onEvent: (message) => events.push(message),
    });

    mockScannerChild({ scanner: "mutation-detect-only", code, signal, malformedOutput });
    const failed = await run();
    expect(failed.findings).toEqual([]);
    expect(failed.cacheRecord).toMatchObject({ cache: "non-cacheable", scope: { unitsExamined: 0 } });
    expect(events.join("\n")).toContain(reason);

    mockScannerChild({ scanner: "mutation-detect-only" });
    const retry = await run();
    expect(retry.cacheRecord?.cache).toBe("miss");
  });

  it("caches proven zero-test mutation results for both no-package and package-without-suite targets", async () => {
    const fixture = mkdtempSync(join(tmpdir(), "harvey-corpus-zero-mutation-"));
    const cacheDir = join(fixture, "cache");
    dirs.push(fixture);
    for (const shape of ["no-package", "package-without-suite"] as const) {
      const targetDir = join(fixture, shape);
      mkdirSync(join(targetDir, "src"), { recursive: true });
      writeFileSync(join(targetDir, "src", "index.ts"), "export const live = true;\n");
      if (shape === "package-without-suite") {
        writeFileSync(join(targetDir, "package.json"), '{"name":"subscription-shaped","private":true,"scripts":{"build":"next build"}}\n');
      }
      const run = () => runCorpusScanner({
        repoRoot: process.cwd(),
        targetDir,
        targetConfig: shape,
        script: "mutation-scan",
        scanner: "mutation-detect-only",
        scriptArgs: [targetDir, "--detect-only"],
        cache: { dir: cacheDir, mode: "read-write", targetRevision: `${shape}-pin`, targetTree: `${shape}-tree` },
      });
      const cold = await run();
      const warm = await run();
      expect([cold.cacheRecord?.cache, warm.cacheRecord?.cache]).toEqual(["miss", "hit"]);
      expect(cold.findings).toContainEqual(expect.objectContaining({ id: "M8-00" }));
      expect(warm.findings).toEqual(cold.findings);
      expect(warm.cacheRecord?.scope).toEqual(cold.cacheRecord?.scope);
      expect(warm.cacheRecord?.scope.unitsExamined).toBe(0);
      expect(warm.cacheRecord?.scope.observation).toMatchObject({
        scanner: "mutation-detect-only",
        suiteSignals: { packageManifest: shape === "package-without-suite", strykerConfig: false, ancestorWorkspaceSuite: null, childWorkspaceSuites: [] },
        zeroTestDisposition: {
          status: shape === "no-package" ? "not-applicable" : "no-suite",
          reason: expect.any(String),
          provenance: expect.stringContaining("mutation-scan inspected"),
          falsifier: expect.stringContaining("invalidates"),
        },
      });
    }
  }, 30_000);

  it("materializes dependencies and caches all scanners across two physical Harvey/target checkouts", async () => {
    const fixture = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-process-"));
    dirs.push(fixture);
    const checkoutA = join(fixture, "checkout-a");
    const checkoutB = join(fixture, "checkout-b");
    const copyCheckout = (destination: string): void => {
      cpSync(process.cwd(), destination, {
        recursive: true,
        filter: (source) => {
          const rel = relative(process.cwd(), source).replaceAll("\\", "/");
          return rel === "" || ![".git", "node_modules", ".harvey-corpus-phase-cache"].some((excluded) => rel === excluded || rel.startsWith(`${excluded}/`));
        },
      });
      symlinkSync(join(process.cwd(), "node_modules"), join(destination, "node_modules"), "dir");
    };
    copyCheckout(checkoutA);
    copyCheckout(checkoutB);
    expect(lstatSync(checkoutA).isSymbolicLink()).toBe(false);
    expect(lstatSync(join(checkoutA, "src", "corpus-scanner-runner.ts")).isSymbolicLink()).toBe(false);

    const source = join(fixture, "target-source");
    const makeTarget = (): void => {
      const dir = source;
      mkdirSync(join(dir, "src", "workload"), { recursive: true });
      mkdirSync(join(dir, "provider"), { recursive: true });
      writeFileSync(join(dir, "package.json"), '{"name":"knip-provider-falsifier","private":true,"devDependencies":{"knip-config-provider":"file:provider"}}\n');
      writeFileSync(join(dir, "knip.json"), '{"entry":["src/index.ts","src/workload/*.ts"],"project":["src/**/*.ts"]}\n');
      writeFileSync(join(dir, "src", "index.ts"), 'import provider from "knip-config-provider"; export const selectedIndex = provider;\n');
      writeFileSync(join(dir, "src", "alternate.ts"), "export const selectedAlternate = true;\n");
      writeFileSync(join(dir, "provider", "package.json"), '{"name":"knip-config-provider","version":"1.0.0","main":"index.js"}\n');
      writeFileSync(join(dir, "provider", "index.js"), 'module.exports = require("./config.js");\n');
      writeFileSync(join(dir, "provider", "config.js"), 'module.exports = { selected: true };\n');
      // Keep one faithful large target but give every scanner a large surface it REALLY consumes.
      // Static opens both sets; quality's source passes open the product set; mutation detect-only
      // opens the test set. No shared target census is allowed to stand in for these three facts.
      for (let index = 0; index < 3_062; index += 1) {
        writeFileSync(
          join(dir, "src", "workload", `unit-${index.toString().padStart(4, "0")}.ts`),
          `export const workloadUnit${index} = ${index};\n`,
        );
      }
      for (let index = 0; index < 3_063; index += 1) {
        writeFileSync(
          join(dir, "src", "workload", `unit-${index.toString().padStart(4, "0")}.test.ts`),
          `test("workload ${index}", () => expect(${index}).toBe(${index}));\n`,
        );
      }
      // Tracked filler and broad JSON inputs must not inflate any scanner-owned receipt.
      writeFileSync(join(dir, "ignored.fixture"), "tracked but scanner-ineligible\n");
      writeFileSync(join(dir, "generic-data.json"), '{"not":"a static loader config or quality source"}\n');
      execFileSync("git", ["init", "-q", dir]);
      execFileSync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: dir, stdio: "ignore" });
      execFileSync("git", ["-C", dir, "add", "."]);
    };
    makeTarget();
    // The freshly-created git tree is checkout A; copy it once for the physically-distinct B.
    // Keeping an otherwise-unused third 6k-file tree bought no coverage and lengthened the same
    // blocking test window the heavy-suite split exists to control.
    const targetA = source;
    const targetB = join(fixture, "target-b");
    cpSync(source, targetB, { recursive: true, verbatimSymlinks: true });

    const cacheDir = join(process.cwd(), `.harvey-corpus-phase-cache-test-${process.pid}-${Date.now()}`);
    dirs.push(cacheDir);
    const cacheArgument = relative(process.cwd(), cacheDir);
    mkdirSync(join(cacheDir, "m4-cache-marker"), { recursive: true });
    const duplicatedCacheSource = "export function cacheOnlyDuplicate(value) {\n  const normalized = String(value).trim();\n  const lowered = normalized.toLowerCase();\n  return lowered.split(' ').filter(Boolean).join('-');\n}\n";
    writeFileSync(join(cacheDir, "m4-cache-marker", "cached-a.ts"), duplicatedCacheSource);
    writeFileSync(join(cacheDir, "m4-cache-marker", "cached-b.ts"), duplicatedCacheSource);
    const runner = join(fixture, "runner.mts");
    writeFileSync(runner, `
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const [repoRoot, targetDir, cacheDir] = process.argv.slice(2);
const module = await import(pathToFileURL(join(repoRoot, "src", "corpus-scanner-runner.ts")).href);
const preparationModule = await import(pathToFileURL(join(repoRoot, "src", "corpus-dependency-preparation.ts")).href);
const targetTree = execFileSync("git", ["-C", targetDir, "write-tree"], { encoding: "utf8" }).trim();
const events = [];
const preparation = preparationModule.prepareCorpusDependencies({ targetDir, cacheDir, targetRevision: "fixture-pinned-revision", targetTree, onEvent: (message) => events.push(message) });
const cache = { dir: cacheDir, mode: "read-write", targetRevision: "fixture-pinned-revision", targetTree, dependencyPreparation: preparation };
const common = { repoRoot, targetDir, targetConfig: "knip-provider-falsifier", onEvent: (message) => events.push(message) };
const detected = await module.runCorpusScanner({ ...common, script: "detect-static", scanner: "detect-static", scriptArgs: [targetDir], cache });
const quality = await module.runCorpusScanner({ ...common, script: "quality-scan", scanner: "quality-scan", scriptArgs: [targetDir], cache });
const mutation = await module.runCorpusScanner({ ...common, script: "mutation-scan", scanner: "mutation-detect-only", scriptArgs: [targetDir, "--detect-only"], cache });
const results = { "detect-static": detected, "quality-scan": quality, "mutation-detect-only": mutation };
const statuses = Object.fromEntries(Object.entries(results).map(([name, result]) => [name, result.cacheRecord?.cache ?? "fresh"]));
const findingCounts = Object.fromEntries(Object.entries(results).map(([name, result]) => [name, result.findings.length]));
const scopeUnits = Object.fromEntries(Object.entries(results).map(([name, result]) => [name, result.cacheRecord?.scope.unitsExamined ?? -1]));
const scopeDescriptions = Object.fromEntries(Object.entries(results).map(([name, result]) => [name, result.cacheRecord?.scope.description ?? "missing"]));
const scopeObservations = Object.fromEntries(Object.entries(results).map(([name, result]) => [name, result.cacheRecord?.scope.observation ?? { scanner: "missing" }]));
const qualityLocation = quality.findings.find((finding) => finding.id === "M5-01")?.location ?? "missing M5-01";
const qualityLocations = quality.findings.map((finding) => finding.location);
console.log("CORPUS_SCANNER_PROCESS=" + JSON.stringify({ statuses, findingCounts, scopeUnits, scopeDescriptions, scopeObservations, qualityLocation, qualityLocations, preparation: preparation.status, preparationCacheable: preparation.cacheable, events }));
`);
    const run = async (repoRoot: string, targetDir: string, environment: NodeJS.ProcessEnv = {}): Promise<ProcessResult> => {
      const { stdout } = await execFileAsync(join(process.cwd(), "node_modules", ".bin", "tsx"), [runner, repoRoot, targetDir, cacheArgument], {
        cwd: process.cwd(), encoding: "utf8", timeout: 55_000, maxBuffer: 1024 * 1024 * 8, env: { ...process.env, ...environment },
      });
      const marker = stdout.split("\n").find((line) => line.startsWith("CORPUS_SCANNER_PROCESS="));
      if (!marker) throw new Error(`child emitted no result: ${stdout}`);
      return JSON.parse(marker.slice("CORPUS_SCANNER_PROCESS=".length)) as ProcessResult;
    };

    const cold = await run(checkoutA, targetA);
    const warm = await run(checkoutB, targetB);
    expect(cold.preparation).toBe("miss");
    expect(warm.preparation).toBe("hit");
    expect([cold.preparationCacheable, warm.preparationCacheable]).toEqual([true, true]);
    expect(cold.statuses).toEqual({ "detect-static": "miss", "quality-scan": "miss", "mutation-detect-only": "miss" });
    expect(warm.statuses).toEqual({ "detect-static": "hit", "quality-scan": "hit", "mutation-detect-only": "hit" });
    expect(warm.findingCounts).toEqual(cold.findingCounts);
    expect(cold.scopeUnits).toEqual({ "detect-static": 6_131, "quality-scan": 3_066, "mutation-detect-only": 3_063 });
    expect(warm.scopeUnits).toEqual(cold.scopeUnits);
    expect(cold.scopeDescriptions).toEqual({
      "detect-static": "6131 source/config file(s) loaded and parsed by detect-static",
      "quality-scan": "3066 product source file(s) read by quality-scan's in-process source passes",
      "mutation-detect-only": "3063 test source file(s) opened by mutation detect-only suite detection",
    });
    expect(warm.scopeDescriptions).toEqual(cold.scopeDescriptions);
    expect(Object.fromEntries(Object.entries(cold.scopeObservations).map(([scanner, observation]) => [scanner, observation.scanner]))).toEqual({
      "detect-static": "detect-static",
      "quality-scan": "quality-scan",
      "mutation-detect-only": "mutation-detect-only",
    });
    expect(warm.scopeObservations).toEqual(cold.scopeObservations);
    expect(warm.qualityLocation).toBe(cold.qualityLocation);
    expect(warm.qualityLocations.some((location) => location.includes("m4-cache-marker"))).toBe(false);
    expect(lstatSync(cacheDir).isDirectory()).toBe(true);
    expect(() => lstatSync(join(targetA, cacheArgument))).toThrow();
    expect(warm.events).toContainEqual(expect.stringContaining("DEPENDENCY PREP HIT npm"));
    expect(warm.events).toContainEqual(expect.stringContaining("CACHE HIT quality-scan"));

    writeFileSync(join(checkoutB, "src", "quality-scan.ts"), `${readFileSync(join(checkoutB, "src", "quality-scan.ts"), "utf8")}\n// production closure mutation control\n`);
    const closureMoved = await run(checkoutB, targetB);
    expect(closureMoved.statuses).toEqual({ "detect-static": "hit", "quality-scan": "miss", "mutation-detect-only": "hit" });
    expect(closureMoved.findingCounts).toEqual(warm.findingCounts);

    writeFileSync(join(checkoutB, "src", "detectors", "app-router.ts"), `${readFileSync(join(checkoutB, "src", "detectors", "app-router.ts"), "utf8")}\n// static-only helper closure mutation control\n`);
    writeFileSync(join(checkoutB, "src", "mutation-scan.ts"), `${readFileSync(join(checkoutB, "src", "mutation-scan.ts"), "utf8")}\n// mutation helper closure mutation control\n`);
    const otherClosuresMoved = await run(checkoutB, targetB);
    expect(otherClosuresMoved.statuses).toEqual({ "detect-static": "miss", "quality-scan": "hit", "mutation-detect-only": "miss" });
    expect(otherClosuresMoved.findingCounts).toEqual(warm.findingCounts);

    const alternateHome = join(fixture, "home-b");
    mkdirSync(alternateHome);
    const homeMoved = await run(checkoutB, targetB, { HOME: alternateHome });
    expect(homeMoved.preparation).toBe("miss");
    expect(homeMoved.statuses).toEqual({ "detect-static": "hit", "quality-scan": "miss", "mutation-detect-only": "hit" });
    const homeStable = await run(checkoutB, targetB, { HOME: alternateHome });
    expect(homeStable.preparation).toBe("hit");
    expect(homeStable.statuses).toEqual({ "detect-static": "hit", "quality-scan": "hit", "mutation-detect-only": "hit" });

    writeFileSync(join(checkoutB, "src", "mutation-scan.ts"), `${readFileSync(join(checkoutB, "src", "mutation-scan.ts"), "utf8")}\nexport async function dynamicClosureFalsifier(name: string) { return import(name); }\n`);
    const dynamicClosure = await run(checkoutB, targetB, { HOME: alternateHome });
    expect(dynamicClosure.statuses).toEqual({ "detect-static": "hit", "quality-scan": "hit", "mutation-detect-only": "fresh" });
    expect(dynamicClosure.events).toContainEqual(expect.stringContaining("implementation closure is non-cacheable"));
  }, 60_000);

  it("keeps a Vite provider inside a brace-declared npm workspace fresh when its config reads unkeyed state", async () => {
    const fixture = mkdtempSync(join(tmpdir(), "harvey-vite-quality-cache-"));
    const targetDir = join(fixture, "target");
    const cacheDir = join(fixture, "cache");
    const stateHome = join(fixture, "home");
    dirs.push(fixture);
    const appDir = join(targetDir, "packages", "app");
    mkdirSync(join(appDir, "src"), { recursive: true });
    mkdirSync(join(targetDir, "packages", "lib"), { recursive: true });
    mkdirSync(join(targetDir, "provider"), { recursive: true });
    mkdirSync(stateHome);
    writeFileSync(join(targetDir, "package.json"), '{"name":"vite-cache-falsifier","private":true,"workspaces":["packages/{app,lib}"],"devDependencies":{"vite":"file:provider"}}\n');
    writeFileSync(join(appDir, "package.json"), '{"name":"vite-cache-app","private":true}\n');
    writeFileSync(join(targetDir, "packages", "lib", "package.json"), '{"name":"vite-cache-lib","private":true}\n');
    writeFileSync(join(targetDir, "provider", "package.json"), '{"name":"vite","version":"1.0.0","main":"index.js"}\n');
    writeFileSync(join(targetDir, "provider", "index.js"), "module.exports = {};\n");
    writeFileSync(join(appDir, "src", "a.ts"), "export const a = true;\n");
    writeFileSync(join(appDir, "src", "b.ts"), "export const b = true;\n");
    writeFileSync(join(appDir, "vite.config.js"), [
      'const { readFileSync } = require("node:fs");',
      'const { join } = require("node:path");',
      'const selected = readFileSync(join(process.env.HOME, "vite-entry.txt"), "utf8").trim();',
      'module.exports = { build: { lib: { entry: `src/${selected}.ts` } } };',
      "",
    ].join("\n"));
    writeFileSync(join(stateHome, "vite-entry.txt"), "a\n");
    execFileSync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: targetDir, stdio: "ignore" });

    const previousHome = process.env.HOME;
    process.env.HOME = stateHome;
    try {
      const run = async () => {
        const events: string[] = [];
        const preparation = prepareCorpusDependencies({
          targetDir,
          cacheDir,
          targetRevision: "vite-provider-pin",
          targetTree: "vite-provider-tree",
          onEvent: (message) => events.push(message),
        });
        const result = await runCorpusScanner({
          repoRoot: process.cwd(),
          targetDir,
          targetConfig: "real local Vite provider",
          script: "quality-scan",
          scanner: "quality-scan",
          scriptArgs: [targetDir],
          cache: {
            dir: cacheDir,
            mode: "read-write",
            targetRevision: "vite-provider-pin",
            targetTree: "vite-provider-tree",
            dependencyPreparation: preparation,
          },
          onEvent: (message) => events.push(message),
        });
        return {
          preparation,
          cache: result.cacheRecord?.cache ?? "fresh",
          unused: result.findings.find((finding) => finding.id === "M5-01")?.location,
          events,
        };
      };

      const cold = await run();
      const warm = await run();
      writeFileSync(join(stateHome, "vite-entry.txt"), "b\n");
      const changed = await run();

      expect([cold.unused, warm.unused, changed.unused]).toEqual(["packages/app/src/b.ts", "packages/app/src/b.ts", "packages/app/src/a.ts"]);
      expect([cold.cache, warm.cache, changed.cache]).toEqual(["fresh", "fresh", "fresh"]);
      expect(cold.preparation).toMatchObject({ status: "miss", complete: true, cacheable: false });
      expect(warm.preparation).toMatchObject({ status: "hit", complete: true, cacheable: false, key: cold.preparation.key });
      expect(changed.preparation).toMatchObject({ status: "hit", complete: true, cacheable: false, key: cold.preparation.key });
      expect(changed.events).toContainEqual(expect.stringContaining("packages/app/vite.config.js"));
      expect(changed.events).toContainEqual(expect.stringContaining("quality-scan executes fresh because validated receipt and offline materialization; quality-scan remains non-cacheable"));
    } finally {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
    }
  }, 30_000);

  it("never reuses quality output after a tarball dependency lifecycle rewrites Knip config from unchanged-HOME external state", async () => {
    const fixture = mkdtempSync(join(tmpdir(), "harvey-transitive-lifecycle-quality-"));
    const dependencyDir = join(fixture, "stateful-dependency");
    const targetDir = join(fixture, "target");
    const cacheDir = join(fixture, "cache");
    const stateHome = join(fixture, "home");
    dirs.push(fixture);
    mkdirSync(dependencyDir, { recursive: true });
    mkdirSync(join(targetDir, "src"), { recursive: true });
    mkdirSync(stateHome);
    writeFileSync(join(dependencyDir, "package.json"), JSON.stringify({
      name: "stateful-knip-config",
      version: "1.0.0",
      scripts: { postinstall: "node postinstall.cjs" },
      files: ["postinstall.cjs"],
    }));
    writeFileSync(join(dependencyDir, "postinstall.cjs"), [
      'const { readFileSync, writeFileSync } = require("node:fs");',
      'const { join } = require("node:path");',
      'const selected = readFileSync(join(process.env.HOME, "selected.txt"), "utf8").trim();',
      'writeFileSync(join(process.env.INIT_CWD, "knip.json"), JSON.stringify({ entry: [`src/${selected}.ts`], project: ["src/**/*.ts"] }));',
      "",
    ].join("\n"));
    const packed = JSON.parse(execFileSync("npm", ["pack", "--json", "--pack-destination", targetDir], {
      cwd: dependencyDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    })) as { filename: string }[];
    const tarball = packed[0]!.filename;
    writeFileSync(join(targetDir, "package.json"), JSON.stringify({
      name: "transitive-lifecycle-falsifier",
      private: true,
      dependencies: { "stateful-knip-config": `file:./${tarball}` },
    }));
    writeFileSync(join(targetDir, "src", "a.ts"), "export const a = true;\n");
    writeFileSync(join(targetDir, "src", "b.ts"), "export const b = true;\n");
    writeFileSync(join(stateHome, "selected.txt"), "a\n");
    execFileSync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: targetDir, stdio: "ignore" });

    const previousHome = process.env.HOME;
    process.env.HOME = stateHome;
    try {
      const run = async () => {
        const events: string[] = [];
        const preparation = prepareCorpusDependencies({
          targetDir,
          cacheDir,
          targetRevision: "transitive-lifecycle-pin",
          targetTree: "transitive-lifecycle-tree",
          onEvent: (message) => events.push(message),
        });
        const result = await runCorpusScanner({
          repoRoot: process.cwd(),
          targetDir,
          targetConfig: "local tarball dependency lifecycle",
          script: "quality-scan",
          scanner: "quality-scan",
          scriptArgs: [targetDir],
          cache: {
            dir: cacheDir,
            mode: "read-write",
            targetRevision: "transitive-lifecycle-pin",
            targetTree: "transitive-lifecycle-tree",
            dependencyPreparation: preparation,
          },
          onEvent: (message) => events.push(message),
        });
        return {
          preparation,
          cache: result.cacheRecord?.cache ?? "fresh",
          unused: result.findings.find((finding) => finding.taxonomy.startsWith("M5 —") && finding.title.startsWith("Unused file:") && finding.location.startsWith("src/"))?.location,
          events,
        };
      };

      const cold = await run();
      writeFileSync(join(stateHome, "selected.txt"), "b\n");
      const changed = await run();

      expect([cold.unused, changed.unused]).toEqual(["src/b.ts", "src/a.ts"]);
      expect([cold.cache, changed.cache]).toEqual(["fresh", "fresh"]);
      expect(cold.preparation).toMatchObject({ status: "miss", complete: true, cacheable: false });
      expect(changed.preparation).toMatchObject({ status: "hit", complete: true, cacheable: false, key: cold.preparation.key });
      expect(changed.preparation.reason).toContain("stateful-knip-config@1.0.0 (postinstall)");
      expect(changed.events.some((event) => event.includes("CACHE HIT quality-scan"))).toBe(false);
      expect(changed.preparation).toMatchObject({ sourceTreeCacheable: false, sourceTreeReason: expect.stringContaining("lifecycle") });
      const sourceCache = {
        dir: cacheDir,
        mode: "read-write" as const,
        targetRevision: "transitive-lifecycle-pin",
        targetTree: "transitive-lifecycle-tree",
        dependencyPreparation: changed.preparation,
      };
      const staticResult = await runCorpusScanner({
        repoRoot: process.cwd(), targetDir, targetConfig: "lifecycle static isolation", script: "detect-static", scanner: "detect-static", scriptArgs: [targetDir], cache: sourceCache,
      });
      const mutationResult = await runCorpusScanner({
        repoRoot: process.cwd(), targetDir, targetConfig: "lifecycle mutation isolation", script: "mutation-scan", scanner: "mutation-detect-only", scriptArgs: [targetDir, "--detect-only"], cache: sourceCache,
      });
      expect(staticResult.cacheRecord).toBeUndefined();
      expect(mutationResult.cacheRecord).toBeUndefined();
    } finally {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
    }
  }, 45_000);

  it("keeps multi-tenant-starter-shaped no-lock install failure output useful without counting degraded package guesses", async () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-multi-tenant-no-lock-quality-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-multi-tenant-no-lock-cache-"));
    dirs.push(targetDir, cacheDir);
    mkdirSync(join(targetDir, "app"), { recursive: true });
    mkdirSync(join(targetDir, "lib", "security"), { recursive: true });
    mkdirSync(join(targetDir, "lib", "supabase"), { recursive: true });
    writeFileSync(join(targetDir, "package.json"), JSON.stringify({
      name: "multi-tenant-no-lock-falsifier",
      private: true,
      scripts: { dev: "next dev", build: "next build", typecheck: "tsc --noEmit", "db:start": "supabase start" },
      dependencies: { next: "14.2.0", react: "18.3.0", "react-dom": "18.3.0" },
      devDependencies: { postcss: "8.4.0", supabase: "1.200.0", typescript: "5.6.0" },
    }));
    writeFileSync(join(targetDir, "tsconfig.json"), JSON.stringify({ compilerOptions: { module: "esnext", moduleResolution: "bundler" }, include: ["**/*.ts"] }));
    writeFileSync(join(targetDir, "lib", "security", "guards.ts"), [
      "export const liveGuard = () => true;",
      "export const requireTenantAccess = () => true;",
      "export const requireTenantAdmin = () => true;",
      "",
    ].join("\n"));
    writeFileSync(join(targetDir, "lib", "supabase", "server.ts"), [
      "export const liveClient = () => ({ kind: 'request' });",
      "export const createServiceRoleClient = () => ({ kind: 'service-role' });",
      "",
    ].join("\n"));
    writeFileSync(join(targetDir, "app", "page.ts"), [
      'import { liveGuard } from "../lib/security/guards";',
      'import { liveClient } from "../lib/supabase/server";',
      "export const page = () => [liveGuard(), liveClient()];",
      "",
    ].join("\n"));

    const dependencyPreparation = prepareCorpusDependencies({
      targetDir,
      cacheDir,
      targetRevision: "multi-tenant-pin",
      targetTree: "multi-tenant-tree",
      packageManagerVersion: "11.12.1",
      runInstall: () => { throw new Error("planted install failure"); },
    });
    expect(dependencyPreparation).toMatchObject({ status: "incomplete", complete: false, cacheable: false });
    expect(dependencyPreparation.reason).toContain("target has no package-manager lockfile; npm install failed");

    const result = await runCorpusScanner({
      repoRoot: process.cwd(),
      targetDir,
      targetConfig: "multi-tenant no-lock install-failure falsifier",
      script: "quality-scan",
      scanner: "quality-scan",
      scriptArgs: [targetDir],
      cache: {
        dir: cacheDir,
        mode: "read-write",
        targetRevision: "multi-tenant-pin",
        targetTree: "multi-tenant-tree",
        dependencyPreparation,
      },
    });
    const m5 = result.findings.filter((finding) => finding.taxonomy === "M5 — Slop / dead code");
    const counted = m5.filter((finding) => finding.severity !== "Info");
    expect(counted).toHaveLength(2);
    expect(counted.map((finding) => finding.location).sort()).toEqual(["lib/security/guards.ts", "lib/supabase/server.ts"]);
    expect(counted.every((finding) => finding.confidence === "Confirmed" && finding.precisionTier === "high")).toBe(true);

    const degradedPackageRows = m5.filter((finding) =>
      finding.title.includes("dependencies declared") || finding.title.includes("binary/binaries"),
    );
    expect(degradedPackageRows.length).toBeGreaterThan(0);
    expect(degradedPackageRows.every((finding) => finding.severity === "Info" && finding.confidence === "Review" && finding.precisionTier === "review")).toBe(true);
    expect(result.findings).toContainEqual(expect.objectContaining({ id: "M5-98", severity: "Info", confidence: "N/A" }));
    expect(result.findings.some((finding) => finding.id === "M5-00")).toBe(false);
  }, 45_000);

  it("preserves source-only M5 coverage and the stdin reason without executing a rejected provider, and fails loud if that safe tier fails", async () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-partial-quality-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-partial-cache-"));
    dirs.push(targetDir, cacheDir);
    mkdirSync(join(targetDir, "src"), { recursive: true });
    mkdirSync(join(targetDir, "node_modules", "partial-provider"), { recursive: true });
    writeFileSync(join(targetDir, "package.json"), '{"name":"partial-quality","private":true}\n');
    writeFileSync(join(targetDir, "src", "index.ts"), "export const live = true;\n");
    writeFileSync(join(targetDir, "src", "dead.ts"), "export const dead = true;\n");
    writeFileSync(join(targetDir, "knip.js"), 'module.exports = require("partial-provider");\n');
    writeFileSync(join(targetDir, "node_modules", "partial-provider", "package.json"), '{"name":"partial-provider","main":"index.js"}\n');
    writeFileSync(join(targetDir, "node_modules", "partial-provider", "index.js"), 'require("node:fs").writeFileSync(require("node:path").join(process.cwd(), "partial-provider-consumed"), "yes"); module.exports = { entry: ["src/index.ts"] };\n');
    const incompletePreparation = {
      status: "incomplete" as const,
      complete: false as const,
      cacheable: false as const,
      packageManager: "npm" as const,
      packageManagerVersion: "11.12.1",
      reason: "packageManager canary-quality-\u00e9\ud83d\udea6\"'\\\nclean and fallback installs failed after partial materialization\n",
    };
    const run = (scriptArgs: string[] = [targetDir]) => runCorpusScanner({
      repoRoot: process.cwd(),
      targetDir,
      targetConfig: "incomplete preparation control",
      script: "quality-scan",
      scanner: "quality-scan",
      scriptArgs,
      cache: {
        dir: cacheDir,
        mode: "read-write",
        targetRevision: "pin",
        targetTree: "tree",
        dependencyPreparation: incompletePreparation,
      },
    });
    const result = await run();
    const fullReason = `dependency preparation incomplete: ${incompletePreparation.reason}`;
    const qualityCalls = vi.mocked(spawn).mock.calls.filter(([, args]) => Array.isArray(args) && args[0] === join(process.cwd(), "src", "cli", "quality-scan.ts"));
    expect(qualityCalls).toHaveLength(1);
    const [, argv, invocation] = qualityCalls[0]!;
    expect(argv).toContain("--degraded-knip-reason-stdin");
    expect(argv).toContain("--degraded-knip-unresolved-dependency-surface");
    expect(argv).not.toContain("--degraded-knip-reason");
    expect((argv as string[]).some((arg) => arg.includes(incompletePreparation.reason))).toBe(false);
    expect(invocation).toMatchObject({ stdio: ["pipe", "ignore", "inherit"] });
    expect(Object.values(invocation?.env ?? {}).some((value) => value?.includes(incompletePreparation.reason))).toBe(false);
    expect(result.cacheRecord).toBeUndefined();
    expect(readNamesSafe(cacheDir)).toEqual([]);
    expect(result.findings).toContainEqual(expect.objectContaining({ taxonomy: expect.stringContaining("M5"), title: expect.stringMatching(/^Unused file:/), location: expect.stringMatching(/src\/dead\.ts$/), confidence: "Review" }));
    expect(result.findings).toContainEqual(expect.objectContaining({ id: "M5-98", evidence: `knip could not load the target's own config, so it re-ran with all plugins disabled and Harvey-inferred entry points: (repo root): ${fullReason}` }));
    expect(result.findings.some((finding) => finding.id === "M5-00")).toBe(false);
    expect(existsSync(join(targetDir, "partial-provider-consumed"))).toBe(false);

    const failedDegraded = await run([targetDir, "--timeout", "0.001"]);
    expect(failedDegraded.findings).toContainEqual(expect.objectContaining({ id: "M5-00" }));
    expect(failedDegraded.findings.some((finding) => finding.id === "M5-98")).toBe(false);
    expect(existsSync(join(targetDir, "partial-provider-consumed"))).toBe(false);

    const completeResult = await runCorpusScanner({
      repoRoot: process.cwd(),
      targetDir,
      targetConfig: "complete preparation control",
      script: "quality-scan",
      scanner: "quality-scan",
      scriptArgs: [targetDir],
      cache: {
        dir: cacheDir,
        mode: "read-write",
        targetRevision: "pin",
        targetTree: "tree",
        dependencyPreparation: {
          status: "hit",
          complete: true,
          cacheable: false,
          key: "complete-but-dynamic",
          packageManager: "npm",
          packageManagerVersion: "11.12.1",
          reason: "quality stays fresh for executable Knip configuration",
        },
      },
    });
    expect(completeResult.findings.some((finding) => finding.id === "M5-00")).toBe(false);
    expect(existsSync(join(targetDir, "partial-provider-consumed"))).toBe(true);
    const completeInvocation = vi.mocked(spawn).mock.calls.at(-1)!;
    expect(completeInvocation[1]).not.toContain("--degraded-knip-reason-stdin");
    expect(completeInvocation[2]?.stdio).toEqual(["ignore", "ignore", "inherit"]);
    expect(completeInvocation[2]?.env).toEqual(invocation?.env);
  }, 60_000);

  it.each([
    { name: "raw reason", reason: "canary-quality-argv-raw", argument: "canary-quality-argv-raw" },
    { name: "prefixed reason", reason: "brief", argument: "dependency preparation incomplete: brief" },
  ])("refuses the $name in quality argv before exec and preserves the typed refusal (#1778)", async ({ reason, argument }) => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-quality-refusal-"));
    dirs.push(targetDir);
    writeFileSync(join(targetDir, "package.json"), '{"name":"quality-refusal","private":true}\n');
    const events: string[] = [];
    const result = runCorpusScanner({
      repoRoot: process.cwd(), targetDir, targetConfig: "quality refusal control",
      script: "quality-scan", scanner: "quality-scan", scriptArgs: [targetDir, `--control=${argument}`],
      cache: {
        dir: join(targetDir, "cache"), mode: "read-write", targetRevision: "pin", targetTree: "tree",
        dependencyPreparation: { status: "incomplete", complete: false, cacheable: false, packageManager: "npm", packageManagerVersion: "fixture", reason },
      },
      onEvent: (message) => events.push(message),
    });
    await expect(result).rejects.toBeInstanceOf(SecretInArgvError);
    await expect(result).rejects.not.toThrow(argument);
    expect(spawn).not.toHaveBeenCalled();
    expect(events).toEqual([]);
  }, 30_000);

  it("preserves the nested nextjs M5 scope when a polyglot root has no package manifest", async () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-polyglot-quality-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-polyglot-cache-"));
    const nextDir = join(targetDir, "nextjs");
    dirs.push(targetDir, cacheDir);
    mkdirSync(join(nextDir, "src"), { recursive: true });
    mkdirSync(join(nextDir, "node_modules", "partial-provider"), { recursive: true });
    writeFileSync(join(nextDir, "package.json"), '{"name":"nested-nextjs","private":true}\n');
    writeFileSync(join(nextDir, "src", "index.ts"), "export const live = true;\n");
    writeFileSync(join(nextDir, "src", "dead.ts"), "export const dead = true;\n");
    writeFileSync(join(nextDir, "knip.js"), 'module.exports = require("partial-provider");\n');
    writeFileSync(join(nextDir, "node_modules", "partial-provider", "package.json"), '{"name":"partial-provider","main":"index.js"}\n');
    writeFileSync(join(nextDir, "node_modules", "partial-provider", "index.js"), 'require("node:fs").writeFileSync(require("node:path").join(process.cwd(), "partial-provider-consumed"), "yes"); module.exports = { entry: ["src/index.ts"] };\n');
    const dependencyPreparation = {
      status: "incomplete" as const,
      complete: false as const,
      cacheable: false as const,
      packageManager: "npm" as const,
      packageManagerVersion: "11.12.1",
      reason: "root or scoped package installation failed",
    };
    const run = (scanDir: string) => runCorpusScanner({
      repoRoot: process.cwd(),
      targetDir: scanDir,
      targetConfig: scanDir === targetDir ? "polyglot root" : "nextjs M5 scan root",
      script: "quality-scan",
      scanner: "quality-scan",
      scriptArgs: [scanDir],
      cache: {
        dir: cacheDir,
        mode: "read-write",
        targetRevision: "polyglot-pin",
        targetTree: "polyglot-tree",
        dependencyPreparation,
      },
    });

    const root = await run(targetDir);
    const scoped = await run(nextDir);
    // Knip itself requires a package manifest at its invocation root, so the whole polyglot tree
    // remains a disclosed M5-00. corpus-drift replaces that root M5 result with the explicit
    // nextjs/ module scope below; that is the hosted mvp-boilerplate seam this control protects.
    expect(root.findings).toContainEqual(expect.objectContaining({ id: "M5-00", evidence: expect.stringContaining(dependencyPreparation.reason) }));
    expect(root.findings.some((finding) => finding.id === "M5-98")).toBe(false);
    expect(scoped.findings).toContainEqual(expect.objectContaining({ taxonomy: expect.stringContaining("M5"), title: expect.stringMatching(/^Unused file:/), location: expect.stringMatching(/src\/dead\.ts$/), confidence: "Review" }));
    expect(scoped.findings).toContainEqual(expect.objectContaining({ id: "M5-98" }));
    expect(scoped.findings.some((finding) => finding.id === "M5-00")).toBe(false);
    expect(existsSync(join(nextDir, "partial-provider-consumed"))).toBe(false);
  }, 60_000);
});

// These controls execute the shipping corpus call sites as well as the real quality CLI. Extract
// only the two functions to avoid starting unrelated corpus scanners, clones or advisory queries.
function corpusInstallConsumer() {
  const source = readFileSync(join(process.cwd(), "src/cli/corpus-drift.ts"), "utf8");
  const ast = ts.createSourceFile("corpus-drift.ts", source, ts.ScriptTarget.Latest, true);
  const functions = ast.statements.filter((node) => ts.isFunctionDeclaration(node) && ["installTargetDeps", "runScanner", "disableGlobalVirtualStoreIfSet"].includes(node.name?.text ?? "")).map((node) => node.getText(ast)).join("\n");
  const bindings = { ...packageManagers, execFileSync, existsSync, join, readFileSync, writeFileSync, prepareCorpusDependencies, runCorpusScanner, repoRoot: process.cwd(), phaseCacheDir: undefined, phaseTarget: "2047-control", forceColdCache: false, GLOBAL_VIRTUAL_STORE_TRUE: /^(\s*enableGlobalVirtualStore:\s*)true\s*$/m };
  const code = ts.transpileModule(functions, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  return new Function(...Object.keys(bindings), `${code}\nreturn {installTargetDeps,runScanner};`)(...Object.values(bindings)) as {
    installTargetDeps: (dir: string, flags: string[], identity: { targetRevision: string; targetTree: string; sourceRoot: string }, cacheDir?: string) => ReturnType<typeof prepareCorpusDependencies>;
    runScanner: (options: { script: "quality-scan"; scanner: "quality-scan"; scriptArgs: string[]; targetDir: string; targetRevision: string; targetTree: string; targetConfig: string; records: unknown[]; cacheDir?: string; dependencyPreparation?: ReturnType<typeof prepareCorpusDependencies> }) => Promise<Finding[]>;
  };
}

function selectorFixture(root: string, manager: "npm" | "pnpm" | "yarn" = "npm"): string {
  const bin = join(root, "bin");
  mkdirSync(bin, { recursive: true });
  for (const [directory, version] of [["bounded", "8.8.8"], ["retained", "9.9.9"], ["full", "10.10.10"], ["alternate", "9.9.9"]]) {
    const dir = join(root, directory!);
    mkdirSync(dir);
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: manager, version }));
    writeFileSync(join(dir, "manager.cjs"), String.raw`
const fs = require("node:fs");
const path = require("node:path");
const mode = fs.existsSync("control-mode") ? fs.readFileSync("control-mode", "utf8") : "fail";
if (mode.startsWith("change") && fs.existsSync("selector-version")) {
  const entry = path.join(${JSON.stringify(root)}, fs.readFileSync("selector-version", "utf8"), "manager.cjs");
  if (entry !== process.argv[1]) { process.argv[1] = entry; require(entry); return; }
}
const version = ${JSON.stringify(version)};
fs.appendFileSync("manager-invocations.jsonl", JSON.stringify({version, args:process.argv.slice(2), corepack:process.env.COREPACK_HOME, unkeyed:process.env.HARVEY_UNKEYED_SELECTOR_2047}) + "\n");
if (process.argv.includes("--version")) {
  fs.writeFileSync("setup-attempted", "manager selection/provisioning is setup");
  if (mode === "probe-fail") { console.error("ERR_SETUP_2047: manager provisioning failed"); process.exit(41); }
  console.log(version); process.exit(0);
}
fs.mkdirSync("node_modules/partial-provider", {recursive:true});
fs.writeFileSync("node_modules/partial-provider/package.json", '{"name":"partial-provider","version":"1.0.0"}');
fs.writeFileSync("node_modules/partial-provider/index.js", 'require("node:fs").writeFileSync("provider-consumed", "yes"); module.exports = {};');
const frozen = process.argv.includes("ci") || process.argv.includes("--frozen-lockfile");
const offline = process.argv.includes("--offline");
if (mode === "fail-write" && process.argv.includes("add")) {
  fs.writeFileSync("package.json", '{"name":"mutated-by-failed-add"}');
  fs.writeFileSync("pnpm-lock.yaml", "mutated-by-failed-add\n");
}
if ((mode === "change" || mode === "change-same-version" || mode === "launcher-change") && frozen) fs.writeFileSync("selector-version", mode === "change-same-version" ? "alternate" : "full");
if (mode === "success" || (mode === "offline-fail" && !offline) || ((mode === "fallback" || mode === "launcher-change" || mode.startsWith("change")) && !frozen)) process.exit(0);
console.log("ERR_INSTALL_2047: rejected partial provider at " + process.cwd()); process.exit(42);
`);
  }
  writeFileSync(join(bin, manager), String.raw`#!${process.execPath}
const fs = require("node:fs"); const path = require("node:path");
const selected = fs.existsSync("selector-version") ? fs.readFileSync("selector-version", "utf8") : process.env.HARVEY_UNKEYED_SELECTOR_2047 ? "full" : process.env.COREPACK_HOME ? "retained" : "bounded";
const entry = path.join(${JSON.stringify(root)}, selected, "manager.cjs");
process.argv = [process.execPath, entry, ...process.argv.slice(2)]; require(entry);
`, { mode: 0o755 });
  return bin;
}

describe("dependency installation reaches the M5 client artifact (#2047)", () => {
  const dirs: string[] = [];
  afterEach(() => {
    vi.unstubAllEnvs();
    dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true }));
    vi.clearAllMocks();
  });
  function fixture(sourceRoot = ".", manager: "npm" | "pnpm" | "yarn" = "npm") {
    const root = mkdtempSync(join(tmpdir(), "harvey-install-delivery-")); dirs.push(root);
    const bin = selectorFixture(root, manager);
    const targetDir = join(root, "target", sourceRoot); mkdirSync(join(targetDir, "src"), { recursive: true });
    writeFileSync(join(targetDir, "package.json"), JSON.stringify({ name: "install-delivery", private: true, packageManager: `${manager}@9.9.9` }));
    writeFileSync(join(targetDir, manager === "npm" ? "package-lock.json" : manager === "pnpm" ? "pnpm-lock.yaml" : "yarn.lock"), manager === "npm" ? '{"lockfileVersion":3,"packages":{"":{}}}' : manager === "pnpm" ? "lockfileVersion: '9.0'\npackages: {}\n" : "# yarn lockfile v1\n");
    writeFileSync(join(targetDir, "src/index.ts"), "export const live = true;\n");
    writeFileSync(join(targetDir, "src/dead.ts"), "export const dead = true;\n");
    writeFileSync(join(targetDir, "knip.config.ts"), `import "./node_modules/partial-provider/index.js"; export default {entry:["src/index.ts"],project:["src/**/*.ts"]};\n`);
    vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
    vi.stubEnv("COREPACK_HOME", join(root, "manager-state"));
    return { root, targetDir, sourceRoot, cacheDir: join(root, "cache"), bin };
  }
  const meta = { client: "Install evidence", subtitle: "#2047", date: "2026-09-12", commit: "control", auditor: "Harvey", confidential: true, overallHealth: 5, tenantIsolation: "Not assessed", authModel: "Fixture", headline: "Preparation failure", scope: "quality control", methodology: "Quality scan", outOfScope: "Other modules" };

  it.each([{ cached: false, sourceRoot: "." }, { cached: false, sourceRoot: "nextjs" }, { cached: true, sourceRoot: "." }, { cached: true, sourceRoot: "nextjs" }])("delivers failed install reason without admitting partial providers: $sourceRoot cached=$cached", async ({ cached, sourceRoot }) => {
    const f = fixture(sourceRoot);
    const consumer = corpusInstallConsumer();
    const identity = { targetRevision: "pin", targetTree: "tree", sourceRoot };
    const cacheDir = cached ? f.cacheDir : undefined;
    const run = (preparation: ReturnType<typeof prepareCorpusDependencies>, extra: string[] = []) => consumer.runScanner({ script: "quality-scan", scanner: "quality-scan", scriptArgs: [f.targetDir, ...extra], targetDir: f.targetDir, ...identity, targetConfig: sourceRoot, records: [], cacheDir, dependencyPreparation: preparation });
    writeFileSync(join(f.targetDir, "control-mode"), "success");
    const complete = consumer.installTargetDeps(f.targetDir, [], identity, cacheDir);
    const control = await run(complete);
    expect(complete.complete).toBe(true);
    expect(control.some((finding) => ["M5-00", "M5-98"].includes(finding.id))).toBe(false);
    expect(existsSync(join(f.targetDir, "provider-consumed"))).toBe(true);
    rmSync(join(f.targetDir, "provider-consumed"));
    writeFileSync(join(f.targetDir, "control-mode"), "fail");
    const rejected = consumer.installTargetDeps(f.targetDir, [], identity, cacheDir);
    const findings = await run(rejected);
    const html = buildHtml({ meta, findings });
    expect(rejected).toMatchObject({ complete: false, status: "incomplete", packageManagerVersion: "9.9.9" });
    expect(rejected.installation?.stages.some((stage) => stage.exitCode === 42)).toBe(true);
    expect(existsSync(join(f.targetDir, "node_modules"))).toBe(false);
    expect(existsSync(join(f.targetDir, "provider-consumed"))).toBe(false);
    expect(findings).toContainEqual(expect.objectContaining({ id: "M5-98", evidence: expect.stringContaining("ERR_INSTALL_2047") }));
    expect(findings.some((finding) => finding.id === "M5-00")).toBe(false);
    expect(html).toContain("ERR_INSTALL_2047");
    expect(html).toContain("dependency preparation incomplete");
    expect(html).toContain("manager.cjs@9.9.9");
    const out = process.env.HARVEY_2047_EVIDENCE_DIR;
    if (out) {
      const name = `${cached ? "cached" : "uncached"}-${sourceRoot === "." ? "root" : "nested"}`;
      writeFileSync(join(out, `${name}-findings.json`), JSON.stringify(findings, null, 2));
      writeFileSync(join(out, `${name}-preparation.json`), JSON.stringify(rejected, null, 2));
      writeFileSync(join(out, `${name}.html`), html);
    }
    if (cached && sourceRoot === ".") {
      const failedKnip = await run(rejected, ["--timeout", "0.001"]);
      expect(failedKnip).toContainEqual(expect.objectContaining({ id: "M5-00", evidence: expect.stringContaining("ERR_INSTALL_2047") }));
      expect(buildHtml({ meta, findings: failedKnip })).toContain("ERR_INSTALL_2047");
      if (out) writeFileSync(join(out, "failed-reduced-knip.html"), buildHtml({ meta, findings: failedKnip }));
      const failedChild = await run(rejected, ["--timeout", "0"]);
      expect(failedChild).toContainEqual(expect.objectContaining({ id: "M5-00", evidence: expect.stringContaining("ERR_INSTALL_2047") }));
      expect(buildHtml({ meta, findings: failedChild })).toContain("ERR_INSTALL_2047");
      if (out) writeFileSync(join(out, "failed-quality-child.html"), buildHtml({ meta, findings: failedChild }));
    }
  });

  it.each(["npm", "pnpm", "yarn"] as const)("retains selector environment and canonical store on %s fallback; classifies provisioning separately", (manager) => {
    const f = fixture(".", manager);
    vi.stubEnv("HARVEY_UNKEYED_SELECTOR_2047", "select-a-different-manager-in-the-full-environment");
    writeFileSync(join(f.targetDir, "control-mode"), "fallback");
    const full = observePackageManager(manager, "version-probe", { bin: manager, args: ["--version"], cwd: f.targetDir, env: process.env });
    expect(full.selected?.version).toBe("10.10.10");
    const shards = [1, 2].map((shard) => prepareCorpusDependencies({ ...f, cacheDir: relative(process.cwd(), join(f.cacheDir, `shard${shard}`)), targetRevision: "pin", targetTree: "tree" }));
    const [first, second] = shards;
    expect(first).toMatchObject({ complete: true, cacheable: false, status: "non-cacheable", packageManagerVersion: "9.9.9" });
    expect(first!.installation?.stages.map((stage) => [stage.stage, stage.outcome, stage.selected?.version])).toEqual([["version-probe", "completed", "9.9.9"], ["frozen", "failed", "9.9.9"], ["legacy", "completed", "9.9.9"]]);
    for (const prepared of shards) {
      const installation = prepared.installation!;
      for (const stage of installation.stages.filter((stage) => stage.stage !== "version-probe")) {
        expect(stage.command).toContain(installation.dependencyStore);
        expect(stage.command.slice(0, 2)).toEqual([installation.stages[0]!.selected!.nodeExecutable, installation.stages[0]!.selected!.executable]);
      }
      expect(installation.dependencyStore).toMatch(new RegExp(`${f.cacheDir}/shard[12]/dependency-preparation/stores/`));
      expect(installation.managerProvisioning).toMatchObject({ kind: "installation-setup", isolation: "not-guaranteed", selectorEnvironment: { COREPACK_HOME: expect.stringMatching(/^sha256:/) } });
    }
    expect(first!.installation?.dependencyStore).not.toBe(second!.installation?.dependencyStore);
    expect(first!.installation?.managerProvisioning).toEqual(second!.installation?.managerProvisioning);
    const installs = readFileSync(join(f.targetDir, "manager-invocations.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line) as { args: string[]; corepack?: string; unkeyed?: string }).filter((row) => !row.args.includes("--version"));
    expect(installs).toHaveLength(4);
    expect(installs.every((row) => row.corepack === join(f.root, "manager-state") && row.unkeyed === undefined)).toBe(true);
    expect(existsSync(join(f.targetDir, "setup-attempted"))).toBe(true);
  });

  it.each(["change", "change-same-version"])("rejects a successful fallback when its selected executable changes: %s", (mode) => {
    const f = fixture();
    writeFileSync(join(f.targetDir, "control-mode"), mode);
    const result = prepareCorpusDependencies({ ...f, targetRevision: "pin", targetTree: "tree" });
    expect(result).toMatchObject({ complete: false, cacheable: false, status: "incomplete" });
    expect(result.installation?.stages.at(-1)).toMatchObject({ stage: "legacy", exitCode: 0, outcome: "failed", reason: expect.stringContaining("identity changed") });
    expect(existsSync(join(f.targetDir, "node_modules"))).toBe(false);
    expect(readNamesSafe(join(f.cacheDir, "dependency-preparation")).includes("receipts")).toBe(false);
  });

  it("binds the selected executable when the launcher's known-good choice moves after the frozen attempt", () => {
    const f = fixture();
    writeFileSync(join(f.targetDir, "package.json"), '{"name":"unpinned-selector-control","private":true}');
    writeFileSync(join(f.targetDir, "control-mode"), "launcher-change");
    const result = prepareCorpusDependencies({ ...f, targetRevision: "pin", targetTree: "tree" });
    const moved = observePackageManager("npm", "version-probe", { bin: "npm", args: ["--version"], cwd: f.targetDir, env: process.env });
    expect(moved.selected?.version).toBe("10.10.10");
    expect(result).toMatchObject({ complete: true, status: "non-cacheable", packageManagerVersion: "9.9.9" });
    expect(result.installation?.stages.map((stage) => stage.selected?.version)).toEqual(["9.9.9", "9.9.9", "9.9.9"]);
    expect(readFileSync(join(f.targetDir, "package.json"), "utf8")).toBe('{"name":"unpinned-selector-control","private":true}');
  });

  it("discloses a failed version-probe as installation setup without attempting installation", async () => {
    const f = fixture();
    writeFileSync(join(f.targetDir, "control-mode"), "probe-fail");
    const result = prepareCorpusDependencies({ ...f, targetRevision: "pin", targetTree: "tree" });
    expect(result).toMatchObject({ complete: false, status: "incomplete", reason: expect.stringContaining("ERR_SETUP_2047") });
    expect(result.installation?.stages).toHaveLength(1);
    expect(result.installation?.stages[0]).toMatchObject({ stage: "version-probe", outcome: "failed", exitCode: 41 });
    const scan = await runCorpusScanner({ repoRoot: process.cwd(), targetDir: f.targetDir, targetConfig: "setup failure", script: "quality-scan", scanner: "quality-scan", scriptArgs: [f.targetDir], dependencyPreparation: result });
    expect(buildHtml({ meta, findings: scan.findings })).toContain("ERR_SETUP_2047");
  });
});

function corpusMutationConsumer(onMutation: (appDir: string, out: string) => void) {
  const source = readFileSync(join(process.cwd(), "src/cli/corpus-drift.ts"), "utf8");
  const ast = ts.createSourceFile("corpus-drift.ts", source, ts.ScriptTarget.Latest, true);
  const declaration = ast.statements.find((node) => ts.isFunctionDeclaration(node) && node.name?.text === "runMutationScan")!;
  const bindings = {
    ...packageManagers, installCorpusDependencyExtras, materializeM8Config, mutationRunFromArtifact,
    join, mkdtempSync, tmpdir, readFileSync, repoRoot: process.cwd(),
    execFileSync: (bin: string, args: string[], options: Parameters<typeof execFileSync>[2]) => {
      if (args[0] !== "mutation-scan") return execFileSync(bin, args, options);
      onMutation(args[1]!, args[args.indexOf("--out") + 1]!);
      return Buffer.from("");
    },
  };
  const code = ts.transpileModule(declaration.getText(ast), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  return new Function(...Object.keys(bindings), `${code}\nreturn runMutationScan;`)(...Object.values(bindings)) as (
    slug: string, dir: string, config: M8CorpusConfig, preparation: ReturnType<typeof prepareCorpusDependencies> | undefined,
  ) => { mutationScore: number; killed: number; valid: number };
}

describe("M8 consumes the live dependency installation (#2047)", () => {
  const dirs: string[] = [];
  const preparations: ReturnType<typeof prepareCorpusDependencies>[] = [];
  afterEach(() => {
    preparations.splice(0).forEach((preparation) => releaseCorpusDependencies(preparation));
    dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true }));
    vi.unstubAllEnvs();
  });
  const identity = { targetRevision: "m8-local-pin", targetTree: "m8-local-tree" };
  const score = { summary: { overall: { mutationScore: 100, killed: 1, totalMutants: 1, ignored: 0, compileErrors: 0 } } };
  function prepare(options: Parameters<typeof prepareCorpusDependencies>[0]) {
    const result = prepareCorpusDependencies(options);
    preparations.push(result);
    return result;
  }
  function rootFixture() {
    const root = mkdtempSync(join(tmpdir(), "harvey-m8-install-"));
    dirs.push(root);
    return root;
  }
  function localPackage(root: string, directory: string, name: string, tool = false) {
    const source = join(root, directory, "package");
    mkdirSync(source, { recursive: true });
    writeFileSync(join(source, "package.json"), JSON.stringify({ name, version: "1.0.0", ...(tool ? { bin: { stryker: "tool.cjs" } } : {}) }));
    writeFileSync(join(source, tool ? "tool.cjs" : "index.js"), tool ? `#!${process.execPath}\nconsole.log(${JSON.stringify(JSON.stringify(score))});\n` : "module.exports = 'dependency-preserved';\n", { mode: 0o755 });
    const archive = join(root, `${directory}.tgz`);
    execFileSync("tar", ["-czf", archive, "-C", join(root, directory), "package"]);
    return `file:${archive}`;
  }

  it.each([{ cached: false, workspace: false }, { cached: false, workspace: true }, { cached: true, workspace: false }, { cached: true, workspace: true }])("keeps real pnpm's store through the shipping M8 install: cached=$cached workspace=$workspace", ({ cached, workspace }) => {
    vi.stubEnv("COREPACK_ENABLE_NETWORK", "0");
    vi.stubEnv("COREPACK_DEFAULT_TO_LATEST", "0");
    const root = rootFixture();
    const dependency = localPackage(root, "dependency", "m8-local-dependency");
    const tool = localPackage(root, "tool", "@stryker-mutator/core", true);
    const version = execFileSync("pnpm", ["--version"], { cwd: root, encoding: "utf8" }).trim();
    const target = join(root, "first");
    const appPath = workspace ? "apps/web" : undefined;
    const appDir = appPath ? join(target, appPath) : target;
    mkdirSync(appDir, { recursive: true });
    writeFileSync(join(target, "package.json"), JSON.stringify({ name: "m8-local-root", private: true, packageManager: `pnpm@${version}`, ...(!workspace ? { dependencies: { "m8-local-dependency": dependency } } : {}) }));
    if (workspace) {
      writeFileSync(join(appDir, "package.json"), JSON.stringify({ name: "m8-local-app", private: true, dependencies: { "m8-local-dependency": dependency } }));
      writeFileSync(join(target, "pnpm-workspace.yaml"), "packages: ['apps/*']\nenableGlobalVirtualStore: true\n");
    }
    writeFileSync(join(target, ".npmrc"), "registry=http://127.0.0.1:9\noffline=true\nupdate-notifier=false\n");
    execFileSync("pnpm", ["install", "--lockfile-only", "--offline", "--config.enableGlobalVirtualStore=false"], { cwd: target, stdio: "pipe" });
    const second = join(root, "second");
    cpSync(target, second, { recursive: true, filter: (path) => !path.includes("node_modules") });
    const cacheDir = cached ? join(root, "cache") : undefined;
    const config: M8CorpusConfig = { appPath, strykerPackages: [tool], installFlags: ["--legacy-peer-deps"], config: { mutate: ["unit.js"] } };
    let consumed = 0;
    const runMutation = corpusMutationConsumer((directory, out) => {
      consumed += 1;
      expect(JSON.parse(readFileSync(join(directory, "stryker.conf.json"), "utf8"))).toEqual(config.config);
      const output = execFileSync(join(directory, "node_modules/.bin/stryker"), [], { cwd: directory, encoding: "utf8" });
      writeFileSync(out, output);
      dirs.push(join(out, ".."));
    });
    for (const [index, directory] of [target, second].entries()) {
      const prepared = prepare({ targetDir: directory, cacheDir, ...identity });
      expect(prepared).toMatchObject({ complete: true, status: cached ? index === 0 ? "miss" : "hit" : "non-cacheable" });
      const store = prepared.installation!.dependencyStore;
      expect(existsSync(store)).toBe(true);
      const manifest = readFileSync(join(directory, "package.json"));
      const lock = readFileSync(join(directory, "pnpm-lock.yaml"));
      const memberManifest = appPath ? readFileSync(join(appDir, "package.json")) : undefined;
      const memberLock = appPath ? join(appDir, "pnpm-lock.yaml") : undefined;
      const memberLockBefore = memberLock && existsSync(memberLock) ? readFileSync(memberLock) : undefined;
      expect(runMutation("m8-local", directory, config, prepared)).toEqual({ mutationScore: 100, killed: 1, valid: 1 });
      const extra = prepared.installation!.stages.at(-1)!;
      expect(extra).toMatchObject({ stage: "tool-install", outcome: "completed", selected: { executable: prepared.installation!.stages[0]!.selected!.executable, nodeExecutable: prepared.installation!.stages[0]!.selected!.nodeExecutable, version } });
      expect(extra.command).toContain(store);
      expect(extra.command).not.toContain("--legacy-peer-deps");
      expect(readFileSync(join(directory, "package.json"))).toEqual(manifest);
      expect(readFileSync(join(directory, "pnpm-lock.yaml"))).toEqual(lock);
      if (memberManifest) expect(readFileSync(join(appDir, "package.json"))).toEqual(memberManifest);
      if (memberLock) {
        expect(existsSync(memberLock)).toBe(memberLockBefore !== undefined);
        if (memberLockBefore) expect(readFileSync(memberLock)).toEqual(memberLockBefore);
      }
      expect(prepared.cacheable).toBe(false);
      expect(prepared.sourceTreeCacheable).toBe(false);
      expect(readFileSync(join(appPath ? join(directory, appPath) : directory, "node_modules/m8-local-dependency/index.js"), "utf8")).toContain("dependency-preserved");
      expect(existsSync(store)).toBe(true);
      const versions = readNamesSafe(store).filter((name) => /^v\d+$/.test(name));
      for (const storeVersion of versions) {
        expect(existsSync(join(store, storeVersion, "projects"))).toBe(false);
        expect(existsSync(join(store, storeVersion, "links"))).toBe(false);
      }
      const keep = index === 1;
      releaseCorpusDependencies(prepared, keep);
      expect(existsSync(store)).toBe(cached || keep);
      if (keep && !cached) dirs.push(join(store, "../../../.."));
      const evidenceDir = process.env.HARVEY_2057_EVIDENCE_DIR;
      if (evidenceDir) {
        const sha256 = (bytes: Buffer | undefined) => bytes ? createHash("sha256").update(bytes).digest("hex") : null;
        const inputs = [
          { path: "package.json", before: manifest, after: readFileSync(join(directory, "package.json")) },
          { path: "pnpm-lock.yaml", before: lock, after: readFileSync(join(directory, "pnpm-lock.yaml")) },
          ...(appPath ? [
            { path: `${appPath}/package.json`, before: memberManifest, after: readFileSync(join(appDir, "package.json")) },
            { path: `${appPath}/pnpm-lock.yaml`, before: memberLockBefore, after: existsSync(memberLock!) ? readFileSync(memberLock!) : undefined },
          ] : []),
        ];
        writeFileSync(join(evidenceDir, `${workspace ? "nested" : "root"}-${cached ? "cached" : "uncached"}-${index}.json`), `${JSON.stringify({
          manager: extra.selected?.version, cached, workspace, keep, toolInstall: extra.outcome,
          inputs: inputs.map(({ path, before, after }) => ({ path, beforeSha256: sha256(before), afterSha256: sha256(after) })),
        }, null, 2)}\n`);
      }
      expect(() => installCorpusDependencyExtras(prepared, { appDir: directory, packages: [tool] })).toThrow(/active preparation/);
    }
    expect(consumed).toBe(2);
  });

  it.each(["npm", "pnpm", "yarn"] as const)("retains %s selector environment and identity through extra installation", (manager) => {
    const root = rootFixture();
    const bin = selectorFixture(root, manager);
    const target = join(root, "target"); mkdirSync(target);
    writeFileSync(join(target, "package.json"), JSON.stringify({ name: "m8-selector", private: true, packageManager: `${manager}@9.9.9` }));
    writeFileSync(join(target, "control-mode"), "success");
    const prepared = prepare({ targetDir: target, ...identity, environment: { ...process.env, PATH: `${bin}:${process.env.PATH}`, COREPACK_HOME: join(root, "retained-home") } });
    vi.stubEnv("PATH", "/missing-new-selector");
    vi.stubEnv("COREPACK_HOME", join(root, "changed-home"));
    vi.stubEnv("HARVEY_UNKEYED_SELECTOR_2047", "select-another-version");
    installCorpusDependencyExtras(prepared, { appDir: target, packages: ["local-tool"], installFlags: ["--legacy-peer-deps"] });
    const invocation = JSON.parse(readFileSync(join(target, "manager-invocations.jsonl"), "utf8").trim().split("\n").at(-1)!) as { version: string; args: string[]; corepack: string; unkeyed?: string };
    expect(invocation).toMatchObject({ version: "9.9.9", corepack: join(root, "retained-home") });
    expect(invocation.unkeyed).toBeUndefined();
    expect(invocation.args).toContain(prepared.installation!.dependencyStore);
    expect(invocation.args.includes("--legacy-peer-deps")).toBe(manager === "npm");
    expect(prepared.installation!.stages.at(-1)).toMatchObject({ stage: "tool-install", outcome: "completed" });
  });

  it.each(["incomplete", "tool-failure", "identity-change"])("stops the shipping M8 consumer on %s and preserves its cause", (mode) => {
    const root = rootFixture();
    const bin = selectorFixture(root);
    const target = join(root, "target"); mkdirSync(target);
    writeFileSync(join(target, "package.json"), '{"name":"m8-failed-install","private":true,"packageManager":"npm@9.9.9"}');
    writeFileSync(join(target, "control-mode"), mode === "incomplete" ? "fail" : "success");
    const prepared = prepare({ targetDir: target, ...identity, environment: { ...process.env, PATH: `${bin}:${process.env.PATH}`, COREPACK_HOME: join(root, "retained-home") } });
    writeFileSync(join(target, "control-mode"), mode === "identity-change" ? "change" : mode === "incomplete" ? "success" : "fail");
    if (mode === "identity-change") writeFileSync(join(target, "selector-version"), "full");
    const mutation = vi.fn((_appDir: string, out: string) => {
      writeFileSync(out, JSON.stringify(score));
      dirs.push(join(out, ".."));
    });
    const runMutation = corpusMutationConsumer(mutation);
    const cause = mode === "identity-change" ? /identity changed/ : /ERR_INSTALL_2047/;
    expect(() => runMutation("m8-failed", target, { strykerPackages: ["local-tool"], installFlags: [], config: {} }, prepared)).toThrow(cause);
    expect(mutation).not.toHaveBeenCalled();
    expect(existsSync(join(target, "node_modules"))).toBe(false);
    expect(prepared.complete).toBe(false);
    expect(prepared.reason).toMatch(cause);
    if (mode === "incomplete") expect(prepared.installation!.stages.some((stage) => stage.stage === "tool-install")).toBe(false);
    else expect(prepared.installation!.stages.at(-1)).toMatchObject({ stage: "tool-install", outcome: "failed" });
    const store = prepared.installation!.dependencyStore;
    releaseCorpusDependencies(prepared);
    expect(existsSync(store)).toBe(false);
  });

  it.each([{ workspace: false, keep: false }, { workspace: false, keep: true }, { workspace: true, keep: false }, { workspace: true, keep: true }])("restores root/member inputs after a failed tool add and respects keep=$keep workspace=$workspace", ({ workspace, keep }) => {
    const root = rootFixture();
    const bin = selectorFixture(root, "pnpm");
    const target = join(root, "target");
    const appDir = workspace ? join(target, "apps/web") : target;
    mkdirSync(appDir, { recursive: true });
    writeFileSync(join(target, "package.json"), '{"name":"original-root","private":true,"packageManager":"pnpm@9.9.9"}\n');
    writeFileSync(join(target, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\npackages: {}\n");
    if (workspace) writeFileSync(join(appDir, "package.json"), '{"name":"original-member","private":true}\n');
    writeFileSync(join(target, "control-mode"), "success");
    const prepared = prepare({ targetDir: target, ...identity, environment: { ...process.env, PATH: `${bin}:${process.env.PATH}`, COREPACK_HOME: join(root, "retained-home") } });
    expect(prepared.complete).toBe(true);
    const rootManifest = readFileSync(join(target, "package.json"));
    const rootLock = readFileSync(join(target, "pnpm-lock.yaml"));
    const memberManifest = workspace ? readFileSync(join(appDir, "package.json")) : undefined;
    writeFileSync(join(appDir, "control-mode"), "fail-write");
    const runMutation = corpusMutationConsumer(() => { throw new Error("unexpected mutation launch"); });
    expect(() => runMutation("m8-failed", target, { strykerPackages: ["local-tool"], installFlags: [], config: {}, ...(workspace ? { appPath: "apps/web" } : {}) }, prepared)).toThrow(/ERR_INSTALL_2047/);
    expect(prepared.installation!.stages.at(-1)).toMatchObject({ stage: "tool-install", outcome: "failed", exitCode: 42, selected: { version: "9.9.9" } });
    expect(readFileSync(join(target, "package.json"))).toEqual(rootManifest);
    expect(readFileSync(join(target, "pnpm-lock.yaml"))).toEqual(rootLock);
    if (memberManifest) expect(readFileSync(join(appDir, "package.json"))).toEqual(memberManifest);
    if (workspace) expect(existsSync(join(appDir, "pnpm-lock.yaml"))).toBe(false);
    expect(existsSync(join(appDir, "node_modules"))).toBe(false);
    const store = prepared.installation!.dependencyStore;
    releaseCorpusDependencies(prepared, keep);
    expect(existsSync(store)).toBe(keep);
  });

  it("requires a live preparation and retains an explicitly kept diagnostic store", () => {
    const root = rootFixture();
    const bin = selectorFixture(root);
    const target = join(root, "target"); mkdirSync(target);
    writeFileSync(join(target, "package.json"), '{"name":"m8-store-retention","private":true,"packageManager":"npm@9.9.9"}');
    writeFileSync(join(target, "control-mode"), "success");
    const prepared = prepare({ targetDir: target, ...identity, environment: { ...process.env, PATH: `${bin}:${process.env.PATH}`, COREPACK_HOME: join(root, "retained-home") } });
    const runMutation = corpusMutationConsumer(() => { throw new Error("unexpected mutation launch"); });
    const config: M8CorpusConfig = { strykerPackages: ["tool"], installFlags: [], config: {} };
    expect(() => runMutation("missing-prep", target, config, undefined)).toThrow(/requires dependency preparation/);
    expect(() => runMutation("serialized-prep", target, config, JSON.parse(JSON.stringify(prepared)))).toThrow(/active preparation/);
    const store = prepared.installation!.dependencyStore;
    releaseCorpusDependencies(prepared, true);
    expect(existsSync(store)).toBe(true);
    expect(() => runMutation("released-prep", target, config, prepared)).toThrow(/active preparation/);
    dirs.push(join(store, "../../../.."));
  });

  it.each([false, true])("releases root and nested stores at the shipping target failure boundary: keep=%s", (keep) => {
    const root = rootFixture();
    const bin = selectorFixture(root);
    const dependencies = ["target", "target/nextjs"].map((directory) => {
      const targetDir = join(root, directory); mkdirSync(targetDir, { recursive: true });
      writeFileSync(join(targetDir, "package.json"), '{"name":"m8-target-cleanup","private":true,"packageManager":"npm@9.9.9"}');
      writeFileSync(join(targetDir, "control-mode"), "success");
      return prepare({ targetDir, ...identity, environment: { ...process.env, PATH: `${bin}:${process.env.PATH}`, COREPACK_HOME: join(root, "retained-home") } });
    });
    const stores = dependencies.map((prepared) => prepared.installation!.dependencyStore);
    expect(stores[0]).not.toBe(stores[1]);
    const source = readFileSync(join(process.cwd(), "src/cli/corpus-drift.ts"), "utf8");
    const ast = ts.createSourceFile("corpus-drift.ts", source, ts.ScriptTarget.Latest, true);
    let targetCleanup: ts.Block | undefined;
    const visit = (node: ts.Node): void => {
      if (ts.isTryStatement(node) && node.finallyBlock?.getText(ast).includes("rmSync(targetRoot")) targetCleanup = node.finallyBlock;
      ts.forEachChild(node, visit);
    };
    visit(ast);
    expect(targetCleanup).toBeDefined();
    const bindings = {
      dependencyPreparations: dependencies, releaseCorpusDependencies, keep, rmSync,
      phaseSeconds: {}, target: { slug: "cleanup-fixture" }, startedAt: Date.now(), targetRoot: join(root, "target"),
      consume: () => {
        expect(stores.every((store) => existsSync(store))).toBe(true);
        throw new Error("fixture consumer failed before target cleanup");
      },
    };
    const code = ts.transpileModule(`try { consume(); } finally ${targetCleanup!.getText(ast)}`, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
    expect(() => new Function(...Object.keys(bindings), code)(...Object.values(bindings))).toThrow(/fixture consumer failed/);
    for (const store of stores) {
      expect(existsSync(store)).toBe(keep);
      if (keep) dirs.push(join(store, "../../../.."));
    }
  });
});
