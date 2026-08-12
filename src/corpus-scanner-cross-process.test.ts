import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

describe("corpus scanner cache across processes and checkout paths (#1871)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("misses cold and hits all three independent artifacts from another checkout and process", async () => {
    const fixture = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-process-"));
    dirs.push(fixture);
    const checkoutA = join(fixture, "checkout-a");
    const checkoutB = join(fixture, "checkout-b");
    symlinkSync(process.cwd(), checkoutA, "dir");
    symlinkSync(process.cwd(), checkoutB, "dir");
    const cacheDir = join(fixture, "cache");
    const target = join(fixture, "large-target");
    mkdirSync(target);
    for (let index = 0; index < 500; index++) writeFileSync(join(target, `source-${index}.ts`), `export const value${index} = ${index};\n`);
    const runner = join(fixture, "runner.mts");
    const moduleUrl = pathToFileURL(join(process.cwd(), "src", "corpus-scanner-cache.ts")).href;
    writeFileSync(runner, `
import { readFileSync } from "node:fs";
import { executeCorpusScanner } from ${JSON.stringify(moduleUrl)};
const [repoRoot, cacheDir] = process.argv.slice(2);
const statuses = {};
for (const scanner of ["detect-static", "quality-scan", "mutation-detect-only"]) {
  const record = await executeCorpusScanner({
    dir: cacheDir, mode: "read-write", scanner,
    targetRevision: "fixed-revision", targetTree: "fixed-large-tree",
    implementation: readFileSync(repoRoot + "/package.json", "utf8") + scanner,
    externalInputs: { node: process.version, tools: "fixed", targetConfig: scanner, dependencyInstall: "fixed-lock" },
  }, () => ({
    findings: Array.from({ length: 500 }, (_, index) => ({
      id: scanner + "-" + index, title: scanner + "-" + index, severity: "Low", confidence: "Likely",
      category: "large-fixture", taxonomy: "M5 — large fixture", location: "source-" + index + ".ts:1",
      status: "Open", evidence: "fixture evidence", impact: "fixture impact", fix: "fixture fix", value: 1, ease: 1, safety: 1,
    })),
    scope: { unitsExamined: 500, description: "500-file faithful large fixture" }, completed: true,
  }));
  statuses[scanner] = record.cache;
}
console.log("CORPUS_SCANNER_PROCESS=" + JSON.stringify(statuses));
`);
    const run = async (repoRoot: string): Promise<Record<string, string>> => {
      const { stdout } = await execFileAsync("pnpm", ["exec", "tsx", runner, repoRoot, cacheDir], { cwd: process.cwd(), encoding: "utf8", timeout: 120_000, maxBuffer: 1024 * 1024 * 8 });
      const marker = stdout.split("\n").find((line) => line.startsWith("CORPUS_SCANNER_PROCESS="));
      if (!marker) throw new Error(`child emitted no result: ${stdout}`);
      return JSON.parse(marker.slice("CORPUS_SCANNER_PROCESS=".length)) as Record<string, string>;
    };
    expect(await run(checkoutA)).toEqual({ "detect-static": "miss", "quality-scan": "miss", "mutation-detect-only": "miss" });
    expect(await run(checkoutB)).toEqual({ "detect-static": "hit", "quality-scan": "hit", "mutation-detect-only": "hit" });
  });
});
