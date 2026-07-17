// #470: the corpus-drift job provisions no Stryker, so it calls this CLI with --detect-only —
// which must NEVER attempt a Stryker run. These child-process tests are the missing-stryker
// simulation: the fixture repos have a runner dep in package.json but no stryker binary anywhere,
// exactly the CI condition that used to crash `runStryker()` mid-corpus with "stryker binary not
// found on PATH". A pre-#470 (no --detect-only) invocation on the real-suite fixture is the
// negative control: it still fails, proving the flag (not luck) is what protects the drift job.
//
// The same fixtures exercise #252's suite-absent threshold end-to-end through the CLI: a harness
// with a single placeholder spec emits M8-00; a harness with one MEANINGFUL spec does not.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "mutation-scan.ts");

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function fixtureRepo(testFiles: Record<string, string>): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-m8-cli-"));
  dirs.push(repo);
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "fixture", scripts: { test: "vitest run" }, devDependencies: { vitest: "^3.0.0" } }));
  for (const [rel, text] of Object.entries(testFiles)) {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), text);
  }
  return repo;
}

function runCli(repo: string, extraArgs: string[]): { status: number; out: string } {
  const outPath = join(repo, "m8-out.json");
  try {
    execFileSync("node_modules/.bin/tsx", [CLI, repo, ...extraArgs, "--out", outPath], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      // A PATH with node but no stryker anywhere — the exact CI condition of issue #470.
      env: { ...process.env, PATH: `${dirname(process.execPath)}:/usr/bin:/bin` },
    });
    return { status: 0, out: readFileSync(outPath, "utf8") };
  } catch (err) {
    const e = err as { status?: number };
    return { status: e.status ?? 1, out: "" };
  }
}

const REAL_SPEC = `import { it, expect } from "vitest";\nimport { add } from "./add";\nit("adds", () => { expect(add(1, 2)).toBe(3); });\nit("throws on NaN", () => { expect(() => add(NaN, 1)).toThrow(); });\n`;

describe("mutation-scan --detect-only (#470/#252, child process, no stryker on PATH)", () => {
  it("exits 0 with an empty findings array when a meaningful suite is present — never invoking Stryker", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC });
    const { status, out } = runCli(repo, ["--detect-only"]);
    expect(status).toBe(0);
    expect(JSON.parse(out)).toEqual([]);
  });

  it("emits the M8-00 zero-coverage finding when the harness's only spec is a placeholder (#252)", () => {
    const repo = fixtureRepo({ "src/smoke.test.ts": `it("works", () => { expect(true).toBe(true); });\n` });
    const { status, out } = runCli(repo, ["--detect-only"]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { finding: Finding };
    expect(parsed.finding.id).toBe("M8-00");
    expect(parsed.finding.evidence).toContain("placeholder");
  });

  it("emits M8-00 when a harness is configured but zero test files exist (#252)", () => {
    const repo = fixtureRepo({});
    const { status, out } = runCli(repo, ["--detect-only"]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { finding: Finding };
    expect(parsed.finding.id).toBe("M8-00");
    expect(parsed.finding.evidence).toContain("ZERO test files");
  });

  it("negative control: WITHOUT --detect-only the same missing-stryker repo still fails — the flag is the protection", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC });
    expect(runCli(repo, []).status).not.toBe(0);
  });
});
