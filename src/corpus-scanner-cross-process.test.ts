import { execFile, execFileSync } from "node:child_process";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { prepareCorpusDependencies } from "./corpus-dependency-preparation.js";
import { runCorpusScanner } from "./corpus-scanner-runner.js";

const execFileAsync = promisify(execFile);

interface ProcessResult {
  statuses: Record<string, string>;
  findingCounts: Record<string, number>;
  qualityLocation: string;
  qualityLocations: string[];
  preparation: string;
  preparationCacheable: boolean;
  events: string[];
}

describe("corpus scanner execution across processes and checkout paths (#1871/#1872)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

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
      mkdirSync(join(dir, "src"), { recursive: true });
      mkdirSync(join(dir, "provider"), { recursive: true });
      mkdirSync(join(dir, "assets"), { recursive: true });
      writeFileSync(join(dir, "package.json"), '{"name":"knip-provider-falsifier","private":true,"devDependencies":{"knip-config-provider":"file:provider"}}\n');
      writeFileSync(join(dir, "knip.json"), '{"entry":["src/index.ts"]}\n');
      writeFileSync(join(dir, "src", "index.ts"), 'import provider from "knip-config-provider"; export const selectedIndex = provider;\n');
      writeFileSync(join(dir, "src", "alternate.ts"), "export const selectedAlternate = true;\n");
      writeFileSync(join(dir, "provider", "package.json"), '{"name":"knip-config-provider","version":"1.0.0","main":"index.js"}\n');
      writeFileSync(join(dir, "provider", "index.js"), 'module.exports = require("./config.js");\n');
      writeFileSync(join(dir, "provider", "config.js"), 'module.exports = { selected: true };\n');
      // Carbon's production scope currently reports 6,133 tracked units. These distinct tracked
      // fixture units make the checkout/copy/cache path carry that same order of magnitude without
      // manufacturing thousands of duplicate TypeScript findings.
      for (let index = 0; index < 6_133; index += 1) writeFileSync(join(dir, "assets", `unit-${index}.fixture`), `${index}\n`);
      execFileSync("git", ["init", "-q", dir]);
      execFileSync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: dir, stdio: "ignore" });
      execFileSync("git", ["-C", dir, "add", "."]);
    };
    makeTarget();
    const targetA = join(fixture, "target-a");
    const targetB = join(fixture, "target-b");
    cpSync(source, targetA, { recursive: true, verbatimSymlinks: true });
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
const qualityLocation = quality.findings.find((finding) => finding.id === "M5-01")?.location ?? "missing M5-01";
const qualityLocations = quality.findings.map((finding) => finding.location);
console.log("CORPUS_SCANNER_PROCESS=" + JSON.stringify({ statuses, findingCounts, qualityLocation, qualityLocations, preparation: preparation.status, preparationCacheable: preparation.cacheable, events }));
`);
    const run = async (repoRoot: string, targetDir: string, environment: NodeJS.ProcessEnv = {}): Promise<ProcessResult> => {
      const { stdout } = await execFileAsync("pnpm", ["exec", "tsx", runner, repoRoot, targetDir, cacheArgument], {
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

    const alternateHome = join(fixture, "home-b");
    mkdirSync(alternateHome);
    const homeMoved = await run(checkoutB, targetB, { HOME: alternateHome });
    expect(homeMoved.preparation).toBe("miss");
    expect(homeMoved.statuses).toEqual({ "detect-static": "hit", "quality-scan": "miss", "mutation-detect-only": "hit" });
    const homeStable = await run(checkoutB, targetB, { HOME: alternateHome });
    expect(homeStable.preparation).toBe("hit");
    expect(homeStable.statuses).toEqual({ "detect-static": "hit", "quality-scan": "hit", "mutation-detect-only": "hit" });
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
    } finally {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
    }
  }, 45_000);

  it("preserves source-only M5 coverage without executing a rejected provider, and fails loud if that safe tier fails", async () => {
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
      reason: "clean and fallback installs failed after partial materialization",
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
    expect(result.cacheRecord).toBeUndefined();
    expect(result.findings).toContainEqual(expect.objectContaining({ taxonomy: expect.stringContaining("M5"), title: expect.stringMatching(/^Unused file:/), location: expect.stringMatching(/src\/dead\.ts$/), confidence: "Review" }));
    expect(result.findings).toContainEqual(expect.objectContaining({ id: "M5-98", evidence: expect.stringContaining("dependency preparation incomplete") }));
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
  }, 60_000);

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
    expect(root.findings).toContainEqual(expect.objectContaining({ id: "M5-00" }));
    expect(root.findings.some((finding) => finding.id === "M5-98")).toBe(false);
    expect(scoped.findings).toContainEqual(expect.objectContaining({ taxonomy: expect.stringContaining("M5"), title: expect.stringMatching(/^Unused file:/), location: expect.stringMatching(/src\/dead\.ts$/), confidence: "Review" }));
    expect(scoped.findings).toContainEqual(expect.objectContaining({ id: "M5-98" }));
    expect(scoped.findings.some((finding) => finding.id === "M5-00")).toBe(false);
    expect(existsSync(join(nextDir, "partial-provider-consumed"))).toBe(false);
  }, 60_000);
});
