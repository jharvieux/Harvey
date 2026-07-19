// #470: the corpus-drift job provisions no Stryker, so it calls this CLI with --detect-only —
// which must NEVER attempt a Stryker run. These child-process tests are the missing-stryker
// simulation: the fixture repos have a runner dep in package.json but no stryker binary anywhere,
// exactly the CI condition that used to crash `runStryker()` mid-corpus with "stryker binary not
// found on PATH". A pre-#470 (no --detect-only) invocation on the real-suite fixture is the
// negative control: it still fails, proving the flag (not luck) is what protects the drift job.
//
// The same fixtures exercise #252's suite-absent threshold end-to-end through the CLI: a harness
// with a single placeholder spec emits M8-00; a harness with one MEANINGFUL spec does not.

import { execFileSync, spawn } from "node:child_process";
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

  // Negative control, updated for #513: WITHOUT --detect-only the same repo now proceeds to the
  // mutation rung — no config, so it reaches the scaffold path and (lacking --install and any
  // Stryker packages) degrades to the machine-readable partial verdict instead of the old ENOENT
  // crash. --detect-only remains the corpus-drift protection: it alone yields the bare [] shape
  // and never enters the mutation rung.
  it("negative control: WITHOUT --detect-only the same repo enters the mutation rung and degrades loudly, not to []", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC });
    const { status, out } = runCli(repo, []);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { moduleRecord?: { status: string; note: string } };
    expect(parsed.moduleRecord?.status).toBe("partial");
    expect(parsed.moduleRecord?.note).toMatch(/--install/);
  });
});

// #513: a suite-bearing target with no Stryker config gets the scaffold path, whose every degrade
// is a loud, machine-readable ladder statement — never a crash, never a silent skip.
describe("mutation-scan scaffold degradation ladder (#513, child process)", () => {
  it("no recognized test runner (ava-only harness): degrades naming the detection gap and the ladder", () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-m8-cli-"));
    dirs.push(repo);
    writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "fixture", scripts: { test: "ava" }, devDependencies: { ava: "^6.0.0" } }));
    // Two test files so #252's single-placeholder threshold can't trip — this fixture is about the
    // scaffold rung, not suite absence.
    writeFileSync(join(repo, "app.test.js"), `const test = require("ava");\ntest("adds", (t) => { t.is(1 + 2, 3); });\n`);
    writeFileSync(join(repo, "cli.test.js"), `const test = require("ava");\ntest("rejects", (t) => { t.throws(() => { throw new Error("x"); }); });\n`);
    const { status, out } = runCli(repo, []);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { moduleRecord?: { status: string; note: string } };
    expect(parsed.moduleRecord?.status).toBe("partial");
    expect(parsed.moduleRecord?.note).toMatch(/no recognized test runner/);
    expect(parsed.moduleRecord?.note).toMatch(/degradation ladder/);
    expect(parsed.moduleRecord?.note).toMatch(/--stub-check/);
  });

  it("recognized runner but no Stryker packages and no --install: degrades naming the exact unlock command", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC });
    const { status, out } = runCli(repo, []);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { moduleRecord?: { note: string } };
    expect(parsed.moduleRecord?.note).toMatch(/vitest suite but no Stryker install/);
    expect(parsed.moduleRecord?.note).toMatch(/@stryker-mutator\/core, @stryker-mutator\/vitest-runner/);
    expect(parsed.moduleRecord?.note).toMatch(/npm install --no-save/);
  });
});

// #504 end-to-end through the CLI: a replayed Stryker report that covers less than the target
// config's mutate globs must come out carrying the partial moduleRecord — the guard that a
// deliberately-scoped run can never be recorded as M8's measurement.
describe("mutation-scan --report scope verification (#504, child process)", () => {
  const killed = { id: "1", mutatorName: "ConditionalExpression", status: "Killed", location: { start: { line: 1, column: 1 }, end: { line: 1, column: 5 } } };

  function scopedFixture(reportFiles: string[]): { repo: string; reportPath: string } {
    const repo = fixtureRepo({
      "src/add.test.ts": REAL_SPEC,
      "src/add.ts": "export const add = (a: number, b: number) => a + b;\n",
      "src/mul.ts": "export const mul = (a: number, b: number) => a * b;\n",
    });
    writeFileSync(join(repo, "stryker.config.json"), JSON.stringify({ testRunner: "vitest", coverageAnalysis: "perTest", mutate: ["src/**/*.ts", "!**/*.test.ts"] }));
    const reportPath = join(repo, "scoped-mutation.json");
    writeFileSync(reportPath, JSON.stringify({ schemaVersion: "1", files: Object.fromEntries(reportFiles.map((f) => [f, { mutants: [killed] }])) }));
    return { repo, reportPath };
  }

  it("a report covering a subset of the configured mutate scope emits the partial moduleRecord alongside its summary", () => {
    const { repo, reportPath } = scopedFixture(["src/add.ts"]);
    const { status, out } = runCli(repo, ["--report", reportPath]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { summary: unknown; scope: { scoped: boolean; missing: string[] }; moduleRecord?: { status: string; note: string } };
    expect(parsed.summary).toBeTruthy();
    expect(parsed.scope.scoped).toBe(true);
    expect(parsed.scope.missing).toEqual(["src/mul.ts"]);
    expect(parsed.moduleRecord?.status).toBe("partial");
    expect(parsed.moduleRecord?.note).toMatch(/never ran \(#504\)/);
  });

  it("a report covering the full configured mutate scope carries no moduleRecord — a real full run still reads ran", () => {
    const { repo, reportPath } = scopedFixture(["src/add.ts", "src/mul.ts"]);
    const { status, out } = runCli(repo, ["--report", reportPath]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { scope: { scoped: boolean; verified: boolean }; moduleRecord?: unknown };
    expect(parsed.scope).toMatchObject({ scoped: false, verified: true });
    expect(parsed.moduleRecord).toBeUndefined();
  });
});

// #600: --stub-check used to write the stub directly into the target and restore it via
// try/finally on the same file — a finally that can't run once the process is killed. A real
// engagement's 2-minute stub-check timeout left a client's reporting.ts stubbed in the operator's
// checkout. The fix mutates a disposable copy instead, so the target is never opened for writing
// in the first place: "untouched" holds no matter when or how the process dies, which these
// tests prove for both the normal-completion path and a SIGTERM sent mid-mutation.
describe("mutation-scan --stub-check crash safety (#600)", () => {
  const SUBJECT = `export function add(a: number, b: number): number {\n  return a + b;\n}\n`;
  const COVERING_TEST = `import { it, expect } from "vitest";\nimport { add } from "./add";\nit("adds", () => { expect(add(1, 2)).toBe(3); });\n`;

  it("a normal (non-killed) run leaves the target checkout byte-identical, having actually run the stub against a copy", () => {
    const repo = fixtureRepo({ "src/add.ts": SUBJECT, "src/add.test.ts": COVERING_TEST });
    // "true" always exits 0 — the covering "suite" trivially "survives" the stub, proving the
    // stub-write-and-test cycle executed for real (not skipped) without depending on npm/vitest
    // actually being installed in the fixture.
    const { status, out } = runCli(repo, ["--stub-check", "--test-cmd", "true"]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { runs: unknown[]; findings: unknown[] };
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.findings).toHaveLength(1);
    expect(readFileSync(join(repo, "src/add.ts"), "utf8")).toBe(SUBJECT);
  });

  it("a run killed (SIGTERM) mid-mutation leaves the target checkout byte-identical", async () => {
    const repo = fixtureRepo({ "src/add.ts": SUBJECT, "src/add.test.ts": COVERING_TEST });
    const outPath = join(repo, "m8-out.json");
    // A test command that blocks for 5s — long enough to guarantee the SIGTERM below lands while
    // the CLI is mid-mutation (stub already written to its copy, execSync blocked waiting on
    // this child), simulating the timeout/kill that produced #600.
    const child = spawn("node_modules/.bin/tsx", [CLI, repo, "--stub-check", "--test-cmd", "node -e 'setTimeout(() => {}, 5000)'", "--out", outPath], {
      cwd: REPO_ROOT,
      stdio: "ignore",
      env: { ...process.env, PATH: `${dirname(process.execPath)}:/usr/bin:/bin` },
    });
    const exited = new Promise<void>((done) => child.on("exit", () => done()));
    await new Promise((r) => setTimeout(r, 1000));
    child.kill("SIGTERM");
    await exited;
    expect(readFileSync(join(repo, "src/add.ts"), "utf8")).toBe(SUBJECT);
  });
});
