import { execFile, execFileSync } from "node:child_process";
import { cpSync, lstatSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

interface ProcessResult {
  statuses: Record<string, string>;
  findingCounts: Record<string, number>;
  qualityLocation: string;
  preparation: string;
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
      writeFileSync(join(dir, "knip.js"), 'module.exports = require("knip-config-provider");\n');
      writeFileSync(join(dir, "src", "index.ts"), "export const selectedIndex = true;\n");
      writeFileSync(join(dir, "src", "alternate.ts"), "export const selectedAlternate = true;\n");
      writeFileSync(join(dir, "provider", "package.json"), '{"name":"knip-config-provider","version":"1.0.0","main":"index.js"}\n');
      writeFileSync(join(dir, "provider", "index.js"), 'module.exports = require("./config.js");\n');
      writeFileSync(join(dir, "provider", "config.js"), 'module.exports = { entry: ["src/index.ts"] };\n');
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

    const cacheDir = join(fixture, "cache");
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
console.log("CORPUS_SCANNER_PROCESS=" + JSON.stringify({ statuses, findingCounts, qualityLocation, preparation: preparation.status, events }));
`);
    const run = async (repoRoot: string, targetDir: string): Promise<ProcessResult> => {
      const { stdout } = await execFileAsync("pnpm", ["exec", "tsx", runner, repoRoot, targetDir, cacheDir], {
        cwd: process.cwd(), encoding: "utf8", timeout: 55_000, maxBuffer: 1024 * 1024 * 8,
      });
      const marker = stdout.split("\n").find((line) => line.startsWith("CORPUS_SCANNER_PROCESS="));
      if (!marker) throw new Error(`child emitted no result: ${stdout}`);
      return JSON.parse(marker.slice("CORPUS_SCANNER_PROCESS=".length)) as ProcessResult;
    };

    const cold = await run(checkoutA, targetA);
    const warm = await run(checkoutB, targetB);
    expect(cold.preparation).toBe("miss");
    expect(warm.preparation).toBe("hit");
    expect(cold.statuses).toEqual({ "detect-static": "miss", "quality-scan": "miss", "mutation-detect-only": "miss" });
    expect(warm.statuses).toEqual({ "detect-static": "hit", "quality-scan": "hit", "mutation-detect-only": "hit" });
    expect(warm.findingCounts).toEqual(cold.findingCounts);
    expect(warm.qualityLocation).toBe(cold.qualityLocation);
    expect(warm.events).toContainEqual(expect.stringContaining("DEPENDENCY PREP HIT npm"));
    expect(warm.events).toContainEqual(expect.stringContaining("CACHE HIT quality-scan"));
  }, 60_000);
});
