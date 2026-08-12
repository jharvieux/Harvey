import { execFile, execFileSync } from "node:child_process";
import { cpSync, lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

interface ProcessResult {
  statuses: Record<string, string>;
  findingCounts: Record<string, number>;
  units: number;
}

describe("corpus scanner cache across processes and checkout paths (#1871)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("runs the production scanners cold, warm, and scanner-specifically invalidated across physical checkouts", async () => {
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
      // Only the tool installation is shared. The checkout, production sources, and calibration
      // target are physical copies; the mutation control writes to checkout B alone.
      symlinkSync(join(process.cwd(), "node_modules"), join(destination, "node_modules"), "dir");
      execFileSync("git", ["init", "-q", destination]);
      execFileSync("git", ["-C", destination, "add", "-f", "targets/calibration"]);
    };
    copyCheckout(checkoutA);
    copyCheckout(checkoutB);
    expect(lstatSync(checkoutA).isSymbolicLink()).toBe(false);
    expect(lstatSync(join(checkoutA, "src", "cli", "static-detect.ts")).isSymbolicLink()).toBe(false);

    const cacheDir = join(fixture, "cache");
    const runner = join(fixture, "runner.mts");
    writeFileSync(runner, `
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const [repoRoot, cacheDir] = process.argv.slice(2);
const targetDir = join(repoRoot, "targets", "calibration");
const identity = await import(pathToFileURL(join(repoRoot, "src", "corpus-scanner-identity.ts")).href);
const cacheModule = await import(pathToFileURL(join(repoRoot, "src", "corpus-scanner-cache.ts")).href);
const scopeModule = await import(pathToFileURL(join(repoRoot, "src", "corpus-scanner-scope.ts")).href);
const commands = {
  "detect-static": [join(repoRoot, "src", "cli", "static-detect.ts"), targetDir],
  "quality-scan": [join(repoRoot, "src", "cli", "quality-scan.ts"), targetDir],
  "mutation-detect-only": [join(repoRoot, "src", "cli", "mutation-scan.ts"), targetDir, "--detect-only"],
};
const statuses = {};
const findingCounts = {};
const units = scopeModule.countCorpusScannerUnits(targetDir);
for (const scanner of cacheModule.CORPUS_SCANNERS) {
  const out = join(mkdtempSync(join(tmpdir(), "harvey-scanner-output-")), "findings.json");
  const cache = identity.buildCorpusScannerCache({
    repoRoot, cacheDir, mode: "read-write", scanner, targetDir,
    targetRevision: "calibration-pinned-revision",
    targetTree: execFileSync("git", ["-C", repoRoot, "write-tree"], { encoding: "utf8" }).trim(),
    targetConfig: JSON.stringify({ root: "targets/calibration", detectOnly: scanner === "mutation-detect-only" }),
  });
  const record = await cacheModule.executeCorpusScanner(cache, () => {
    execFileSync("pnpm", ["exec", "tsx", ...commands[scanner], "--out", out], { cwd: repoRoot, stdio: ["ignore", "ignore", "ignore"] });
    const parsed = JSON.parse(readFileSync(out, "utf8"));
    const findings = Array.isArray(parsed) ? parsed : [parsed.finding];
    return { findings, scope: { unitsExamined: units, description: scanner + " over the faithful calibration target" }, completed: true };
  });
  statuses[scanner] = record.cache;
  findingCounts[scanner] = record.findings.length;
}
console.log("CORPUS_SCANNER_PROCESS=" + JSON.stringify({ statuses, findingCounts, units }));
`);
    const run = async (repoRoot: string): Promise<ProcessResult> => {
      const { stdout } = await execFileAsync("pnpm", ["exec", "tsx", runner, repoRoot, cacheDir], {
        cwd: process.cwd(), encoding: "utf8", timeout: 55_000, maxBuffer: 1024 * 1024 * 8,
      });
      const marker = stdout.split("\n").find((line) => line.startsWith("CORPUS_SCANNER_PROCESS="));
      if (!marker) throw new Error(`child emitted no result: ${stdout}`);
      return JSON.parse(marker.slice("CORPUS_SCANNER_PROCESS=".length)) as ProcessResult;
    };

    const cold = await run(checkoutA);
    const warm = await run(checkoutB);
    expect(cold.statuses).toEqual({ "detect-static": "miss", "quality-scan": "miss", "mutation-detect-only": "miss" });
    expect(warm.statuses).toEqual({ "detect-static": "hit", "quality-scan": "hit", "mutation-detect-only": "hit" });
    expect(warm.findingCounts).toEqual(cold.findingCounts);
    expect(cold.units).toBeGreaterThan(600);
    expect(Object.values(cold.findingCounts).reduce((sum, count) => sum + count, 0)).toBeGreaterThan(100);

    writeFileSync(join(checkoutB, "src", "quality-scan.ts"), `${readFileSync(join(checkoutB, "src", "quality-scan.ts"), "utf8")}\n// scanner-specific identity control\n`);
    const invalidated = await run(checkoutB);
    expect(invalidated.statuses).toEqual({ "detect-static": "hit", "quality-scan": "miss", "mutation-detect-only": "hit" });
    expect(invalidated.findingCounts).toEqual(cold.findingCounts);
  });
});
