import { execFile, execFileSync } from "node:child_process";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

interface ProcessResult {
  statuses: Record<string, string>;
  findingCounts: Record<string, number>;
  qualityLocation: string;
  events: string[];
}

describe("corpus scanner execution across processes and checkout paths (#1871/#1872)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("caches source-only scanners while consecutive quality runs observe installed Knip config changes", async () => {
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

    const makeTarget = (name: string, entry: "index" | "alternate"): string => {
      const dir = join(fixture, name);
      mkdirSync(join(dir, "src"), { recursive: true });
      writeFileSync(join(dir, "package.json"), '{"name":"knip-provider-falsifier","private":true,"devDependencies":{"knip-config-provider":"1.0.0"}}\n');
      writeFileSync(join(dir, "knip.js"), 'module.exports = require("knip-config-provider");\n');
      writeFileSync(join(dir, "src", "index.ts"), "export const selectedIndex = true;\n");
      writeFileSync(join(dir, "src", "alternate.ts"), "export const selectedAlternate = true;\n");
      const provider = join(dir, "node_modules", "knip-config-provider");
      mkdirSync(provider, { recursive: true });
      writeFileSync(join(provider, "package.json"), '{"name":"knip-config-provider","version":"1.0.0","main":"index.js"}\n');
      writeFileSync(join(provider, "index.js"), 'module.exports = require("./config.js");\n');
      writeFileSync(join(provider, "config.js"), `module.exports = { entry: ["src/${entry}.ts"] };\n`);
      execFileSync("git", ["init", "-q", dir]);
      execFileSync("git", ["-C", dir, "add", "package.json", "knip.js", "src/index.ts", "src/alternate.ts"]);
      return dir;
    };
    const target = makeTarget("target", "index");
    const installedConfig = join(target, "node_modules", "knip-config-provider", "config.js");

    const cacheDir = join(fixture, "cache");
    const runner = join(fixture, "runner.mts");
    writeFileSync(runner, `
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const [repoRoot, targetDir, cacheDir] = process.argv.slice(2);
const module = await import(pathToFileURL(join(repoRoot, "src", "corpus-scanner-runner.ts")).href);
const targetTree = execFileSync("git", ["-C", targetDir, "write-tree"], { encoding: "utf8" }).trim();
const cache = { dir: cacheDir, mode: "read-write", targetRevision: "fixture-pinned-revision", targetTree };
const events = [];
const common = { repoRoot, targetDir, targetConfig: "knip-provider-falsifier", onEvent: (message) => events.push(message) };
const detected = await module.runCorpusScanner({ ...common, script: "detect-static", scanner: "detect-static", scriptArgs: [targetDir], cache });
const quality = await module.runCorpusScanner({ ...common, script: "quality-scan", scanner: "quality-scan", scriptArgs: [targetDir] });
const mutation = await module.runCorpusScanner({ ...common, script: "mutation-scan", scanner: "mutation-detect-only", scriptArgs: [targetDir, "--detect-only"], cache });
const results = { "detect-static": detected, "quality-scan": quality, "mutation-detect-only": mutation };
const statuses = Object.fromEntries(Object.entries(results).map(([name, result]) => [name, result.cacheRecord?.cache ?? "fresh"]));
const findingCounts = Object.fromEntries(Object.entries(results).map(([name, result]) => [name, result.findings.length]));
const qualityLocation = quality.findings.find((finding) => finding.id === "M5-01")?.location ?? "missing M5-01";
console.log("CORPUS_SCANNER_PROCESS=" + JSON.stringify({ statuses, findingCounts, qualityLocation, events }));
`);
    const run = async (repoRoot: string, targetDir: string): Promise<ProcessResult> => {
      const { stdout } = await execFileAsync("pnpm", ["exec", "tsx", runner, repoRoot, targetDir, cacheDir], {
        cwd: process.cwd(), encoding: "utf8", timeout: 55_000, maxBuffer: 1024 * 1024 * 8,
      });
      const marker = stdout.split("\n").find((line) => line.startsWith("CORPUS_SCANNER_PROCESS="));
      if (!marker) throw new Error(`child emitted no result: ${stdout}`);
      return JSON.parse(marker.slice("CORPUS_SCANNER_PROCESS=".length)) as ProcessResult;
    };

    const cold = await run(checkoutA, target);
    writeFileSync(installedConfig, 'module.exports = { entry: ["src/alternate.ts"] };\n');
    const warm = await run(checkoutB, target);
    expect(cold.statuses).toEqual({ "detect-static": "miss", "quality-scan": "fresh", "mutation-detect-only": "miss" });
    expect(warm.statuses).toEqual({ "detect-static": "hit", "quality-scan": "fresh", "mutation-detect-only": "hit" });
    expect(warm.findingCounts).toEqual(cold.findingCounts);
    expect(cold.qualityLocation).toBe("src/alternate.ts");
    expect(warm.qualityLocation).toBe("src/index.ts");
    expect(cold.events).toContainEqual(expect.stringContaining("quality-scan executes fresh"));
    expect(warm.events).toContainEqual(expect.stringContaining("quality-scan executes fresh"));
    expect(existsSync(join(cacheDir, "corpus-scanners", "quality-scan"))).toBe(false);
  });
});
