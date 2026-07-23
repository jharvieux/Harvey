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
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "../findings.js";
import { TS7_TSCONFIG_BYPASS_FILENAME } from "../mutation-scan.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "mutation-scan.ts");

// #839: every test in this file drives the real CLI as a tsx (or, #600's kill test, a raw node)
// child process — 5s (vitest's default) is tight enough to flake under a loaded machine
// (full-suite `pnpm verify`) even though each test passes reliably in isolation. Raised once here
// rather than annotating each of this file's ~20 `it()` calls.
vi.setConfig({ testTimeout: 30_000 });

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

// #765: the stub-check runner used to build a SHELL string — `execSync(`${testCmd} ${tests.join(" ")}`)`
// — from covering-test paths walked out of the untrusted target. A filename may legally contain shell
// metacharacters, so a hostile repo shipping a test file named e.g. `evil;touch <marker>.test.ts`
// achieved arbitrary command execution on the auditor. The fix runs the suite via execFileSync with an
// argv array (no shell), each test path a literal argument. This fixture ships exactly that filename and
// proves the injected `touch` never fires while the real runner still receives the path verbatim.
describe("mutation-scan --stub-check no shell injection from target test-file paths (#765)", () => {
  const SUBJECT = `export function add(a: number, b: number): number {\n  return a + b;\n}\n`;

  it("a covering-test path containing shell metacharacters is passed as a literal argv element, never shell-executed", () => {
    const marker = join(mkdtempSync(join(tmpdir(), "harvey-inject-marker-")), "INJECTED");
    dirs.push(dirname(marker));
    const record = join(mkdtempSync(join(tmpdir(), "harvey-inject-record-")), "argv.txt");
    dirs.push(dirname(record));

    // Records each argv element it receives (proving literal-arg pass-through) and exits 0 so the
    // stub "survives" — i.e. the real runner definitely ran and its verdict was read.
    const recorder = join(mkdtempSync(join(tmpdir(), "harvey-inject-recorder-")), "record.mjs");
    dirs.push(dirname(recorder));
    writeFileSync(recorder, `import { appendFileSync } from "node:fs";\nfor (const a of process.argv.slice(2)) appendFileSync(process.env.RECORD, a + "\\n");\nprocess.exit(0);\n`);

    const repo = mkdtempSync(join(tmpdir(), "harvey-m8-inject-"));
    dirs.push(repo);
    writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "fixture", scripts: { test: "vitest run" }, devDependencies: { vitest: "^3.0.0" } }));
    mkdirSync(join(repo, "src"), { recursive: true });
    writeFileSync(join(repo, "src", "add.ts"), SUBJECT);
    // A covering test (imports ./add) whose FILENAME is a command injection. If the path ever reaches a
    // shell, `touch <marker>.test.ts` runs; as a literal argv element it is an (unopenable) file path.
    const evilName = `evil;touch $MARKER.test.ts`;
    writeFileSync(join(repo, "src", evilName), `import { it, expect } from "vitest";\nimport { add } from "./add";\nit("adds", () => { expect(add(1, 2)).toBe(3); });\n`);

    const outPath = join(repo, "m8-out.json");
    execFileSync("node_modules/.bin/tsx", [CLI, repo, "--stub-check", "--test-cmd", `node ${recorder}`, "--out", outPath], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, MARKER: marker, RECORD: record },
    });

    // The injected command must NOT have run.
    expect(existsSync(`${marker}.test.ts`)).toBe(false);
    // The real runner ran and read the survival verdict.
    const parsed = JSON.parse(readFileSync(outPath, "utf8")) as { runs: unknown[]; findings: unknown[] };
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.findings).toHaveLength(1);
    // The metacharacter-laden path arrived as ONE literal argument, not tokenized by a shell.
    const recorded = readFileSync(record, "utf8").split("\n").filter(Boolean);
    expect(recorded).toContain(`src/${evilName}`);
  });
});

// #623: a per-app invocation on a workspace monorepo whose test config lives at the ROOT (vitest
// workspace + a root test:* script, no per-app runner) used to report "no automated test suite" —
// a false zero-coverage verdict on an app the root suite covers. The CLI must instead emit the
// M8-04 measurement-gap finding. Exercised through --detect-only (no Stryker needed), the exact
// path corpus-drift and the orchestrator take.
describe("mutation-scan monorepo root-workspace suite (#623, child process)", () => {
  function monorepo(): { root: string; app: string } {
    const root = mkdtempSync(join(tmpdir(), "harvey-m8-monorepo-"));
    dirs.push(root);
    mkdirSync(join(root, ".git"), { recursive: true }); // repo-root boundary for the ancestor walk
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"], scripts: { "test:cross-tenant": "vitest run" }, devDependencies: { vitest: "^3.0.0" } }),
    );
    writeFileSync(join(root, "vitest.workspace.ts"), `export default ["apps/*"];\n`);
    const app = join(root, "apps", "main");
    mkdirSync(app, { recursive: true });
    // The app package declares NO test script and NO runner dependency of its own.
    writeFileSync(join(app, "package.json"), JSON.stringify({ name: "@app/main", dependencies: {} }));
    writeFileSync(join(app, "index.ts"), `export const main = () => 1;\n`);
    return { root, app };
  }

  function runCliOn(target: string, extraArgs: string[]): { status: number; out: string } {
    const outPath = join(target, "m8-out.json");
    try {
      execFileSync("node_modules/.bin/tsx", [CLI, target, ...extraArgs, "--out", outPath], {
        cwd: REPO_ROOT,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, PATH: `${dirname(process.execPath)}:/usr/bin:/bin` },
      });
      return { status: 0, out: readFileSync(outPath, "utf8") };
    } catch (err) {
      const e = err as { status?: number };
      return { status: e.status ?? 1, out: "" };
    }
  }

  it("emits the M8-04 measurement-gap finding for an app whose tests live at the monorepo root — NOT M8-00", () => {
    const { app } = monorepo();
    const { status, out } = runCliOn(app, ["--detect-only"]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { finding: Finding; moduleRecord: { status: string; note: string } };
    expect(parsed.finding.id).toBe("M8-04");
    expect(parsed.finding.evidence).toMatch(/workspace-root test suite/);
    expect(parsed.moduleRecord.status).toBe("partial");
    expect(parsed.moduleRecord.note).toMatch(/#623/);
  });

  it("negative control: a standalone app with no test suite and no workspace root still gets M8-00", () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-m8-standalone-"));
    dirs.push(repo);
    mkdirSync(join(repo, ".git"), { recursive: true });
    writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "solo", dependencies: {} }));
    writeFileSync(join(repo, "index.ts"), `export const x = () => 1;\n`);
    const { status, out } = runCliOn(repo, ["--detect-only"]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { finding: Finding };
    expect(parsed.finding.id).toBe("M8-00");
  });
});

// #655: closes the #623 measurement gap — WITHOUT --detect-only, the CLI must actually ATTEMPT a
// root-scoped Stryker run instead of jumping straight to the gap disclosure. Neither fixture below
// has a Stryker install anywhere (this suite runs with no stryker on PATH, like #470's), so both
// exercise a distinct degrade rung of that attempt — proving it is really invoked, not skipped —
// while a live Stryker run itself stays out of scope for a unit/CLI test (see #655's task note).
describe("mutation-scan monorepo root-scoped run attempt (#655, child process)", () => {
  function runCliOn(target: string, extraArgs: string[]): { status: number; out: string } {
    const outPath = join(target, "m8-out.json");
    try {
      execFileSync("node_modules/.bin/tsx", [CLI, target, ...extraArgs, "--out", outPath], {
        cwd: REPO_ROOT,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, PATH: `${dirname(process.execPath)}:/usr/bin:/bin` },
      });
      return { status: 0, out: readFileSync(outPath, "utf8") };
    } catch (err) {
      const e = err as { status?: number };
      return { status: e.status ?? 1, out: "" };
    }
  }

  it("degrades naming 'no recognized source directory' when the app has none of the scaffold's known dirs to scope to", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-m8-monorepo-nosrc-"));
    dirs.push(root);
    mkdirSync(join(root, ".git"), { recursive: true });
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"], scripts: { "test:cross-tenant": "vitest run" }, devDependencies: { vitest: "^3.0.0" } }),
    );
    writeFileSync(join(root, "vitest.workspace.ts"), `export default ["apps/*"];\n`);
    const app = join(root, "apps", "main");
    mkdirSync(app, { recursive: true });
    writeFileSync(join(app, "package.json"), JSON.stringify({ name: "@app/main", dependencies: {} }));
    writeFileSync(join(app, "index.ts"), `export const main = () => 1;\n`); // no src/lib/app/etc dir to scope to

    const { status, out } = runCliOn(app, []); // no --detect-only: the attempt must fire
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { finding: Finding; moduleRecord: { status: string; note: string } };
    expect(parsed.finding.id).toBe("M8-04");
    expect(parsed.moduleRecord.status).toBe("partial");
    expect(parsed.moduleRecord.note).toMatch(/Attempted a root-scoped run \(#655\)/);
    expect(parsed.moduleRecord.note).toMatch(/no recognized source directory/);
  });

  it("degrades naming the missing Stryker packages + --install when the app HAS a scopable source dir", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-m8-monorepo-withsrc-"));
    dirs.push(root);
    mkdirSync(join(root, ".git"), { recursive: true });
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"], scripts: { "test:cross-tenant": "vitest run" }, devDependencies: { vitest: "^3.0.0" } }),
    );
    writeFileSync(join(root, "vitest.workspace.ts"), `export default ["apps/*"];\n`);
    const app = join(root, "apps", "main");
    mkdirSync(join(app, "src"), { recursive: true });
    writeFileSync(join(app, "package.json"), JSON.stringify({ name: "@app/main", dependencies: {} }));
    writeFileSync(join(app, "src", "index.ts"), `export const main = () => 1;\n`);

    const { status, out } = runCliOn(app, []); // no --detect-only, no --install
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { finding: Finding; moduleRecord: { status: string; note: string } };
    expect(parsed.finding.id).toBe("M8-04");
    expect(parsed.moduleRecord.note).toMatch(/Attempted a root-scoped run \(#655\)/);
    expect(parsed.moduleRecord.note).toMatch(/no Stryker install there/);
    expect(parsed.moduleRecord.note).toMatch(/@stryker-mutator\/core/);
    expect(parsed.moduleRecord.note).toMatch(/--install/);
  });

  it("--detect-only takes precedence over #655 — never attempts the root-scoped run, unchanged #623 disclosure", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-m8-monorepo-detectonly-"));
    dirs.push(root);
    mkdirSync(join(root, ".git"), { recursive: true });
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"], scripts: { "test:cross-tenant": "vitest run" }, devDependencies: { vitest: "^3.0.0" } }),
    );
    writeFileSync(join(root, "vitest.workspace.ts"), `export default ["apps/*"];\n`);
    const app = join(root, "apps", "main");
    mkdirSync(join(app, "src"), { recursive: true });
    writeFileSync(join(app, "package.json"), JSON.stringify({ name: "@app/main", dependencies: {} }));
    writeFileSync(join(app, "src", "index.ts"), `export const main = () => 1;\n`);

    const { status, out } = runCliOn(app, ["--detect-only"]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { finding: Finding; moduleRecord: { status: string; note: string } };
    expect(parsed.finding.id).toBe("M8-04");
    expect(parsed.moduleRecord.note).not.toMatch(/Attempted a root-scoped run/);
  });
});

// #820: the json reporter's output path is read back from the Stryker config that actually ran
// (falling back to a glob search of cwd) instead of an unconditional hardcoded
// reports/mutation/mutation.json — these fake stryker binaries write their report wherever the
// test says, standing in for a target-declared jsonReporter path and for a Stryker major version
// that moved its own documented default.
describe("mutation-scan report-path auto-discovery (#820, child process)", () => {
  function writeFakeStrykerReporterBinary(repo: string, reportRelPath: string): void {
    const binDir = join(repo, "node_modules", ".bin");
    mkdirSync(binDir, { recursive: true });
    const script = `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const outPath = path.join(process.cwd(), ${JSON.stringify(reportRelPath)});
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify({ schemaVersion: "1", files: { "src/add.ts": { mutants: [{ id: "1", mutatorName: "ConditionalExpression", status: "Killed", location: { start: { line: 1, column: 1 }, end: { line: 1, column: 5 } } }] } } }));
process.exit(0);
`;
    writeFileSync(join(binDir, "stryker"), script);
    chmodSync(join(binDir, "stryker"), 0o755);
  }

  it("reads a custom jsonReporter.fileName off the target's own Stryker config, without --report", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC, "src/add.ts": "export const add = (a: number, b: number) => a + b;\n" });
    writeFileSync(join(repo, "stryker.config.json"), JSON.stringify({ testRunner: "vitest", coverageAnalysis: "perTest", jsonReporter: { fileName: "out/custom-mutation-report.json" } }));
    writeFakeStrykerReporterBinary(repo, "out/custom-mutation-report.json");
    const { status, out } = runCli(repo, []);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { summary?: { overall: { totalMutants: number } } };
    expect(parsed.summary?.overall.totalMutants).toBe(1);
  });

  it("falls back to a glob search when the report isn't at the configured/default path (a Stryker version writing elsewhere)", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC, "src/add.ts": "export const add = (a: number, b: number) => a + b;\n" });
    writeFileSync(join(repo, "stryker.config.json"), JSON.stringify({ testRunner: "vitest", coverageAnalysis: "perTest" })); // no jsonReporter — the wrapper's documented default applies
    writeFakeStrykerReporterBinary(repo, "dist/mutation.json"); // NOT reports/mutation/mutation.json
    const { status, out } = runCli(repo, []);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { summary?: { overall: { totalMutants: number } } };
    expect(parsed.summary?.overall.totalMutants).toBe(1);
  });
});

// #819: line coverage is auto-pulled from the target's own coverage-capable runner (vitest/jest)
// so the §3b coverage-vs-mutation-score gap no longer needs a hand-filled column. --report skips
// invoking Stryker itself (irrelevant to this feature) so these fixtures need no stryker binary.
describe("mutation-scan auto-pulled line coverage (#819, child process)", () => {
  function minimalReport(repo: string): string {
    const reportPath = join(repo, "mutation-report.json");
    writeFileSync(
      reportPath,
      JSON.stringify({ schemaVersion: "1", files: { "src/add.ts": { mutants: [{ id: "1", mutatorName: "ConditionalExpression", status: "Killed", location: { start: { line: 1, column: 1 }, end: { line: 1, column: 5 } } }] } } }),
    );
    return reportPath;
  }

  function writeFakeCoverageBinary(repo: string, runner: "vitest" | "jest", behavior: "succeed" | "produces-nothing"): void {
    const binDir = join(repo, "node_modules", ".bin");
    mkdirSync(binDir, { recursive: true });
    const script =
      behavior === "succeed"
        ? `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const dirArg = process.argv.find((a) => a.includes("Directory="));
const dir = dirArg.split("=")[1];
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, "coverage-summary.json"), JSON.stringify({ total: { lines: { total: 10, covered: 8, skipped: 0, pct: 80 } }, "src/add.ts": { lines: { total: 10, covered: 8, skipped: 0, pct: 80 } } }));
process.exit(0);
`
        : `#!/usr/bin/env node\nprocess.exit(1);\n`;
    writeFileSync(join(binDir, runner), script);
    chmodSync(join(binDir, runner), 0o755);
  }

  it("auto-pulls line coverage from a local vitest binary and merges it onto the same module row as mutation score", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC, "src/add.ts": "export const add = (a: number, b: number) => a + b;\n" });
    writeFakeCoverageBinary(repo, "vitest", "succeed");
    const reportPath = minimalReport(repo);
    const { status, out } = runCli(repo, ["--report", reportPath]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { lineCoverage: { status: string }; reportRows: { module: string; lineCoverage?: number }[] };
    expect(parsed.lineCoverage).toEqual({ status: "ran" });
    expect(parsed.reportRows.find((r) => r.module === "src")?.lineCoverage).toBe(80);
  });

  it("discloses partial with a reason when the coverage tool produces no summary — never a silent blank column", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC, "src/add.ts": "export const add = (a: number, b: number) => a + b;\n" });
    writeFakeCoverageBinary(repo, "vitest", "produces-nothing");
    const reportPath = minimalReport(repo);
    const { status, out } = runCli(repo, ["--report", reportPath]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { lineCoverage: { status: string; reason?: string } };
    expect(parsed.lineCoverage.status).toBe("partial");
    expect(parsed.lineCoverage.reason).toMatch(/coverage-summary\.json/);
  });

  it("discloses partial when no recognized test runner is detected to invoke a coverage tool for", () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-m8-cli-"));
    dirs.push(repo);
    writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "fixture", scripts: { test: "ava" }, devDependencies: { ava: "^6.0.0" } }));
    const reportPath = minimalReport(repo);
    const { status, out } = runCli(repo, ["--report", reportPath]);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { lineCoverage: { status: string; reason?: string } };
    expect(parsed.lineCoverage.status).toBe("partial");
    expect(parsed.lineCoverage.reason).toMatch(/no recognized test runner/);
  });
});

// #773: TypeScript 7's native/Go rewrite broke Stryker's own sandbox tsconfig preprocessor (it
// calls the classic compiler API, which TS7's restructured package no longer exports) — every
// Stryker run against a TS7 target crashed with no report written. These fixtures fake the
// `stryker` binary so the exact incompatibility can be reproduced and the fix's two mechanisms
// (proactive config patch, reactive crash-signature safety net) exercised end-to-end without a
// real Stryker/TypeScript-7 install.
describe("mutation-scan TS7 tsconfig-preprocessor bypass (#773, child process)", () => {
  const REAL_SPEC_TS7 = `import { it, expect } from "vitest";\nimport { add } from "./add";\nit("adds", () => { expect(add(1, 2)).toBe(3); });\n`;

  function writeFakeTypeScript7(repo: string): void {
    mkdirSync(join(repo, "node_modules", "typescript"), { recursive: true });
    writeFileSync(join(repo, "node_modules", "typescript", "package.json"), JSON.stringify({ name: "typescript", version: "7.0.2" }));
  }

  // "succeed-if-bypassed" only writes a report when the config it's handed carries the bypass
  // (proving the CLI actually applied it, not just that Stryker happened to succeed); "always-
  // crash-ts7" reproduces the upstream crash unconditionally, for the reactive-safety-net test.
  function writeFakeStrykerBinary(repo: string, behavior: "succeed-if-bypassed" | "always-crash-ts7"): void {
    const binDir = join(repo, "node_modules", ".bin");
    mkdirSync(binDir, { recursive: true });
    const binPath = join(binDir, "stryker");
    const crash = `process.stderr.write("TypeError: ts.parseConfigFileTextToJson is not a function\\n    at TSConfigPreprocessor.rewriteTSConfigFile\\n"); process.exit(1);`;
    const script =
      behavior === "always-crash-ts7"
        ? `#!/usr/bin/env node\n${crash}\n`
        : `#!/usr/bin/env node\nconst fs = require("node:fs");\nconst path = require("node:path");\nconst cfg = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));\nif (cfg.tsconfigFile === ${JSON.stringify(TS7_TSCONFIG_BYPASS_FILENAME)}) {\n  const outDir = path.join(process.cwd(), "reports", "mutation");\n  fs.mkdirSync(outDir, { recursive: true });\n  fs.writeFileSync(path.join(outDir, "mutation.json"), JSON.stringify({ schemaVersion: "1", files: { "src/add.ts": { mutants: [{ id: "1", mutatorName: "ConditionalExpression", status: "Killed", location: { start: { line: 1, column: 1 }, end: { line: 1, column: 5 } } }] } } }));\n  process.exit(0);\n} else {\n  ${crash}\n}\n`;
    writeFileSync(binPath, script);
    chmodSync(binPath, 0o755);
  }

  it("proactively patches the Stryker config for a detected TS7 target — the run completes instead of crashing", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC_TS7, "src/add.ts": "export const add = (a: number, b: number) => a + b;\n" });
    writeFakeTypeScript7(repo);
    writeFileSync(join(repo, "stryker.config.json"), JSON.stringify({ testRunner: "vitest", coverageAnalysis: "perTest" }));
    writeFakeStrykerBinary(repo, "succeed-if-bypassed");

    const { status, out } = runCli(repo, []);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { summary?: { overall: { totalMutants: number } }; moduleRecord?: unknown };
    // The fake binary only writes a report when it was HANDED the bypassed config — so a real
    // summary here proves the patch was applied, not merely that nothing crashed.
    expect(parsed.summary?.overall.totalMutants).toBe(1);
    expect(parsed.moduleRecord).toBeUndefined(); // a normal full run, not a degraded verdict
  });

  it("a TS7 target with a non-JSON Stryker config degrades immediately, naming the incompatibility, without ever invoking Stryker", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC_TS7 });
    writeFakeTypeScript7(repo);
    writeFileSync(join(repo, "stryker.config.mjs"), `export default { testRunner: "vitest" };\n`);
    // No stryker binary anywhere: if the CLI ever attempted an invocation this would ENOENT-crash
    // instead of degrading, proving the degrade fires BEFORE any invocation attempt.
    const { status, out } = runCli(repo, []);
    expect(status).toBe(0);
    const parsed = JSON.parse(out) as { moduleRecord?: { status: string; note: string } };
    expect(parsed.moduleRecord?.status).toBe("partial");
    expect(parsed.moduleRecord?.note).toMatch(/TypeScript is v7\.0\.2/);
    expect(parsed.moduleRecord?.note).toMatch(/#773/);
    expect(parsed.moduleRecord?.note).toMatch(/not JSON/);
  });

  it("reactive safety net: an undetected TS7 install still degrades precisely when Stryker crashes with the known signature — never a bare hard failure", () => {
    const repo = fixtureRepo({ "src/add.test.ts": REAL_SPEC_TS7 });
    // Deliberately NO node_modules/typescript here, simulating the proactive check missing an
    // unusually-hoisted install — Stryker itself still hits the incompatibility and crashes.
    writeFileSync(join(repo, "stryker.config.json"), JSON.stringify({ testRunner: "vitest", coverageAnalysis: "perTest" }));
    writeFakeStrykerBinary(repo, "always-crash-ts7");

    const { status, out } = runCli(repo, []);
    expect(status).toBe(0); // not the pre-#773 hard exit-1 "mutation report not found" crash
    const parsed = JSON.parse(out) as { moduleRecord?: { status: string; note: string } };
    expect(parsed.moduleRecord?.status).toBe("partial");
    expect(parsed.moduleRecord?.note).toMatch(/#773/);
    expect(parsed.moduleRecord?.note).toMatch(/parseConfigFileTextToJson is not a function/);
  });
});
