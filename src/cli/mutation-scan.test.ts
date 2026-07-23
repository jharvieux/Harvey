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
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
