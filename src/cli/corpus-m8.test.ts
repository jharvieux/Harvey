import { execFileSync, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { M8_CORPUS_CONFIGS } from "../scan/m8-corpus.js";
import { buildM8CorpusPlan, type M8TargetResult } from "../scan/m8-corpus-artifacts.js";
import { createBoundedLineRedactor, redactSecrets } from "../secret-redact.js";
import { describePreparationStages } from "../corpus-package-manager.js";

const plan = buildM8CorpusPlan(EXTERNAL_CORPUS, M8_CORPUS_CONFIGS);
const cli = join(import.meta.dirname, "corpus-m8.ts");
const tsxLoader = createRequire(import.meta.url).resolve("tsx");

function writePassingPeerArtifacts(artifacts: string, except: string): void {
  for (const other of plan.configured.filter((slug) => slug !== except)) {
    const directory = join(artifacts, other);
    mkdirSync(directory);
    writeFileSync(join(directory, "result.json"), `${JSON.stringify({
      schemaVersion: 1, target: other, status: "passed", exitCode: 0, durationMs: 1,
      phases: { clone: 0, "dependency preparation": 0, "test baseline": 0, mutation: 0, scoring: 1 },
      scorecard: { rows: [{ slug: other, check: "M8 mutation baseline", pass: true }], findings: {} },
    })}\n`);
  }
}

describe("M8 target failure evidence (#2057)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it.each(["separate streams", "multiline preparation detail"])("retains bounded, redacted %s through target and aggregate artifacts", (shape) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-m8-wrapper-"));
    dirs.push(root);
    const bin = join(root, "bin");
    mkdirSync(bin);
    const detail = describePreparationStages([{
      stage: "tool-install", outcome: "failed", exitCode: 42, command: ["pnpm", "add"],
      selected: {
        executable: "/tools/pnpm", executableSha256: "a".repeat(64), version: "11.1.3",
        launcher: "pnpm", launcherRealpath: "/tools/node", launcherSha256: "b".repeat(64),
        nodeExecutable: process.execPath, nodeVersion: process.version,
      },
      reason: "ERR_PNPM_STDOUT_2057 Authorization: Bearer abcdefgh12345678 https://alice:passwordvalue@example.invalid/pkg?token=queryvalue\nERR_PNPM_STDERR_2057 ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n" + "peer dependency detail\n".repeat(220),
    }]);
    const output = shape === "multiline preparation detail" ? [
      `writeSync(2, ${JSON.stringify(`DEPENDENCY PREP TOOL ${detail}\nError: tool installation failed: ${detail}\n`)});`,
    ] : [
      `writeSync(1, "tool-install failed, exit 42: /tools/pnpm@11.1.3; ERR_PNPM_STDOUT_2057 Authorization: Bearer abcdefgh12345678 https://alice:passwordvalue@example.invalid/pkg?token=queryvalue\\n");`,
      `writeSync(2, "ERR_PNPM_STDERR_2057 ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\\n");`,
    ];
    writeFileSync(join(bin, "pnpm"), [
      `#!${process.execPath}`,
      `const { writeSync } = require("node:fs");`,
      `writeSync(1, "noise\\n".repeat(20000));`,
      ...output,
      `writeSync(1, "traceback filler\\n".repeat(1000));`,
      `writeSync(2, "traceback filler\\n".repeat(1000));`,
      `process.exit(42);`,
    ].join("\n"), { mode: 0o755 });
    const artifacts = join(root, "artifacts");
    const target = "proposit";
    const targetDir = join(artifacts, target);
    mkdirSync(targetDir, { recursive: true });
    const resultPath = join(targetDir, "result.json");
    execFileSync(process.execPath, ["--import", tsxLoader, cli, "target", "--target", target, "--out", resultPath], {
      cwd: root,
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` },
      stdio: "pipe",
      maxBuffer: 1024 * 1024,
    });
    const raw = readFileSync(resultPath, "utf8");
    const result = JSON.parse(raw) as M8TargetResult;
    expect(result).toMatchObject({ target, status: "failed", exitCode: 42, scorecard: null });
    expect(result.error).toContain("scorecard unavailable or corrupt");
    expect(result.error).toContain("ERR_PNPM_STDOUT_2057");
    expect(result.error).toContain("ERR_PNPM_STDERR_2057");
    expect(result.error).toContain("/tools/pnpm@11.1.3");
    expect(result.error!.length).toBeLessThan(9000);
    expect(raw).not.toContain("abcdefgh12345678");
    expect(raw).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
    expect(raw).not.toContain("passwordvalue");
    expect(raw).not.toContain("queryvalue");
    expect(raw).toContain("[REDACTED]");

    writePassingPeerArtifacts(artifacts, target);
    const reportPath = join(root, "aggregate.json");
    expect(() => execFileSync(process.execPath, ["--import", tsxLoader, cli, "aggregate", "--artifacts", artifacts, "--out", reportPath], { cwd: root, stdio: "pipe" })).toThrow();
    expect(existsSync(reportPath)).toBe(true);
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as { ok: boolean; failed: number; targets: M8TargetResult[] };
    expect(report).toMatchObject({ ok: false, failed: 1 });
    expect(report.targets.find((entry) => entry.target === target)?.error).toBe(result.error);
  });
});

describe("M8 terminal and aggregate redaction (#2060)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it.each(["success", "failure"] as const)("redacts split stdout/stderr credentials on %s and bounds long/final lines", (outcome) => {
    const root = mkdtempSync(join(tmpdir(), `harvey-m8-terminal-${outcome}-`));
    dirs.push(root);
    const bin = join(root, "bin");
    mkdirSync(bin);
    const target = "proposit";
    const stdoutSecret = "stdoutcredential2060";
    const stderrSecret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
    const longLineSecret = "longlinecredential2060";
    const finalSecret = "finalpartialcredential2060";
    const crossLineSecret = "reviewercredential2060";
    const blankFinalSecret = "blankfinalcredential2060";
    const wrappedBearerSecret = "wrappedbearercredential2060";
    const contextSecret = "contextcredential2060";
    writeFileSync(join(bin, "pnpm"), [
      `#!${process.execPath}`,
      `const { writeFileSync, writeSync } = require("node:fs");`,
      `const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));`,
      `(async () => {`,
      `  writeSync(1, "selected manager pnpm@11.1.3; live progress 1/3\\n");`,
      `  writeSync(1, "Authorization: Bea"); await wait(10); writeSync(1, "rer ${stdoutSecret}\\n");`,
      `  writeSync(1, "password:\\n"); await wait(10); writeSync(1, "${crossLineSecret}\\n");`,
      `  writeSync(1, "Authorization: Bearer\\n"); await wait(10); writeSync(1, "${wrappedBearerSecret}\\n");`,
      `  writeSync(2, "password:\\n"); await wait(10); writeSync(2, "${contextSecret} (loaded)\\n");`,
      `  writeSync(2, "stderr diagnostic ghp_ABCDEFGHIJ"); await wait(10); writeSync(2, "KLMNOPQRSTUVWXYZ012345\\n");`,
      `  writeSync(1, "password: ${longLineSecret} " + "x".repeat(70 * 1024) + "\\n");`,
      `  writeSync(1, "${target}: 1s — clone 0.1s\\n");`,
      `  writeSync(2, "launch src/cli/mutation-"); await wait(10); writeSync(2, "scan.ts now\\n");`,
      `  writeSync(2, "M8 PHASES: test baseline 0.1s, mutation 0.2s, line coverage 0.1s\\n");`,
      `  writeSync(2, "tool-install ${outcome === "success" ? "complete" : "failed"}, selected manager pnpm@11.1.3\\n");`,
      `  writeSync(2, "secret: finalpartial"); await wait(10); writeSync(2, "credential2060");`,
      `  writeSync(1, "secret:\\n\\n"); await wait(10); writeSync(1, "${blankFinalSecret}");`,
      ...(outcome === "success" ? [
        `  const scorecard = process.argv[process.argv.length - 1];`,
        `  writeFileSync(scorecard, JSON.stringify({ rows: [{ slug: "${target}", check: "M8 mutation baseline", pass: true }], findings: {} }));`,
      ] : []),
      `  process.exit(${outcome === "success" ? 0 : 42});`,
      `})().catch((error) => { console.error(error); process.exit(99); });`,
    ].join("\n"), { mode: 0o755 });

    const artifacts = join(root, "artifacts");
    const targetDir = join(artifacts, target);
    mkdirSync(targetDir, { recursive: true });
    const resultPath = join(targetDir, "result.json");
    const targetRun = spawnSync(process.execPath, ["--import", tsxLoader, cli, "target", "--target", target, "--out", resultPath], {
      cwd: root,
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` },
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });

    expect(targetRun.status).toBe(0);
    expect(targetRun.stderr).toContain("selected manager pnpm@11.1.3");
    expect(targetRun.stderr).toContain("live progress 1/3");
    expect(targetRun.stderr).toContain("diagnostic line exceeded 65536 characters; content suppressed");
    expect(targetRun.stderr).toContain("M8 PHASES: test baseline 0.1s, mutation 0.2s");
    expect(targetRun.stderr).toContain(`M8 TARGET ${outcome === "success" ? "PASSED" : "FAILED"}`);
    for (const secret of [stdoutSecret, stderrSecret, longLineSecret, finalSecret, crossLineSecret, blankFinalSecret, wrappedBearerSecret, contextSecret]) {
      expect(targetRun.stderr).not.toContain(secret);
    }
    expect(targetRun.stderr).toContain("password:\n[REDACTED]\n");
    expect(targetRun.stderr).toContain("Authorization: Bearer\n[REDACTED]\n");
    expect(targetRun.stderr).toContain("password:\n[REDACTED] (loaded)\n");
    expect(targetRun.stderr).toContain("secret:\n\n[REDACTED]");
    expect(targetRun.stderr.match(/\[REDACTED\]/g)?.length).toBeGreaterThanOrEqual(5);

    const targetArtifact = readFileSync(resultPath, "utf8");
    const result = JSON.parse(targetArtifact) as M8TargetResult;
    expect(result.status).toBe(outcome === "success" ? "passed" : "failed");
    for (const secret of [stdoutSecret, stderrSecret, longLineSecret, finalSecret, crossLineSecret, blankFinalSecret, wrappedBearerSecret, contextSecret]) {
      expect(targetArtifact).not.toContain(secret);
    }
    if (outcome === "success") {
      expect(result.phases).not.toBeNull();
    } else {
      expect(result.error).toContain("tool-install failed, selected manager pnpm@11.1.3");
      expect(result.error).toContain("child exited 42");
    }

    // Treat aggregate input as independently untrusted: an old/foreign target artifact can still
    // contain a credential-shaped diagnostic, and the assembled upload must scrub it again.
    const aggregateSecret = "aggregatecredential2060";
    writeFileSync(resultPath, `${JSON.stringify({ ...result, error: `${result.error ?? "legacy diagnostic"}; Authorization: Bearer ${aggregateSecret}` }, null, 2)}\n`);
    writePassingPeerArtifacts(artifacts, target);
    const reportPath = join(root, "aggregate.json");
    const aggregateRun = spawnSync(process.execPath, ["--import", tsxLoader, cli, "aggregate", "--artifacts", artifacts, "--out", reportPath], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });
    expect(aggregateRun.status).toBe(outcome === "success" ? 0 : 1);
    expect(aggregateRun.stderr).toContain("M8 AGGREGATE RUNNER COST:");
    expect(aggregateRun.stderr).not.toContain(aggregateSecret);
    const aggregateArtifact = readFileSync(reportPath, "utf8");
    expect(aggregateArtifact).not.toContain(aggregateSecret);
    expect(aggregateArtifact).toContain("Authorization: Bearer [REDACTED]");
  });

  it.each(["passed", "failed"] as const)("redacts an independently supplied %s target artifact during aggregation", (status) => {
    const root = mkdtempSync(join(tmpdir(), `harvey-m8-aggregate-${status}-`));
    dirs.push(root);
    const artifacts = join(root, "artifacts");
    const target = "proposit";
    const targetDir = join(artifacts, target);
    mkdirSync(targetDir, { recursive: true });
    const aggregateSecret = "independentaggregatecredential2060";
    const targetResult: M8TargetResult = {
      schemaVersion: 1,
      target,
      status,
      exitCode: status === "passed" ? 0 : 42,
      durationMs: 400,
      phases: status === "passed" ? { clone: 100, "dependency preparation": 50, "test baseline": 50, mutation: 100, scoring: 100 } : null,
      scorecard: status === "passed" ? { rows: [{ slug: target, check: "M8 mutation baseline", pass: true }], findings: {} } : null,
      error: `legacy child stderr: Authorization: Bearer ${aggregateSecret}`,
    };
    writeFileSync(join(targetDir, "result.json"), `${JSON.stringify(targetResult)}\n`);
    writePassingPeerArtifacts(artifacts, target);

    const reportPath = join(root, "aggregate.json");
    const aggregateRun = spawnSync(process.execPath, ["--import", tsxLoader, cli, "aggregate", "--artifacts", artifacts, "--out", reportPath], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });

    expect(aggregateRun.status).toBe(status === "passed" ? 0 : 1);
    expect(aggregateRun.stderr).toContain("M8 AGGREGATE RUNNER COST:");
    expect(aggregateRun.stderr).not.toContain(aggregateSecret);
    const aggregateArtifact = readFileSync(reportPath, "utf8");
    expect(aggregateArtifact).not.toContain(aggregateSecret);
    expect(aggregateArtifact).toContain("Authorization: Bearer [REDACTED]");
  });

  it.each(["plan", "target", "aggregate"])("sanitizes %s filesystem failures at the terminal boundary", (mode) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-m8-io-boundary-"));
    dirs.push(root);
    const secret = "ghp_1234567890ABCDEF";
    const blocker = join(root, secret);
    writeFileSync(blocker, "not a directory");
    const out = join(blocker, "result.json");
    const artifacts = join(root, "artifacts");
    mkdirSync(artifacts);
    if (mode === "aggregate") writePassingPeerArtifacts(artifacts, "");
    const args = mode === "plan" ? ["--github-output", out]
      : mode === "target" ? ["--target", "proposit", "--out", out]
        : ["--artifacts", artifacts, "--out", out];
    const result = spawnSync(process.execPath, ["--import", tsxLoader, cli, mode, ...args], { cwd: root, encoding: "utf8" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("M8 CORPUS FAILED:");
    expect(result.stderr).toContain("[REDACTED]");
    expect(result.stderr).not.toContain(secret);
    expect(result.stderr).not.toContain("at Object.");
  });

  it("sanitizes rejected flags without changing exit status or accepted flag context", () => {
    const secret = "ghp_1234567890ABCDEF";
    const result = spawnSync(process.execPath, ["--import", tsxLoader, cli, "plan", `--${secret}`], { encoding: "utf8" });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Unrecognized flag: --[REDACTED]");
    expect(result.stderr).toContain("--github-output");
    expect(result.stderr).not.toContain(secret);
  });

  it.each(["schemaVersion", "target"])("redacts credential-shaped %s values from aggregate validation failures", (field) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-m8-invalid-aggregate-"));
    dirs.push(root);
    const artifacts = join(root, "artifacts");
    const target = "proposit";
    const targetDir = join(artifacts, target);
    mkdirSync(targetDir, { recursive: true });
    const schemaSecret = "ghp_1234567890ABCDEF";
    writeFileSync(join(targetDir, "result.json"), `${JSON.stringify(field === "schemaVersion" ? { schemaVersion: schemaSecret } : { schemaVersion: 1, target: schemaSecret, status: "failed", exitCode: 42, durationMs: 1, phases: null, scorecard: null })}\n`);

    const reportPath = join(root, "aggregate.json");
    const aggregateRun = spawnSync(process.execPath, ["--import", tsxLoader, cli, "aggregate", "--artifacts", artifacts, "--out", reportPath], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });

    expect(aggregateRun.status).toBe(1);
    expect(aggregateRun.stderr).toContain(field === "schemaVersion" ? "M8 AGGREGATE INPUT INVALID: proposit" : "M8 CORPUS FAILED:");
    expect(aggregateRun.stderr).toContain(field === "schemaVersion" ? "schemaVersion" : "configured M8 target set");
    expect(aggregateRun.stderr).toContain("[REDACTED]");
    expect(aggregateRun.stderr).not.toContain(schemaSecret);
    expect(existsSync(reportPath)).toBe(false);
  });
});


describe("M8 bounded credential grammar", () => {
  it.each(["Bearer", "token", "api_key", "api-key", "apikey", "password", "secret"])("preserves whole-text policy for split %s diagnostics", (label) => {
    for (const separator of ["\n", ":\r\n", " = \"\n\n", ":\n : '\n"]) {
      for (const suffix of ["\n", " (loaded)\n", "", "; next stage\nsecret:\nsecondcredential2060\n"]) {
        const input = `stage ready\n${label}${separator}reviewercredential2060${suffix}`;
        const expected = redactSecrets(input);
        expect(expected).not.toContain("reviewercredential2060");
        for (let split = 0; split <= input.length; split += 1) {
          let actual = "";
          const stream = createBoundedLineRedactor({ write: (value) => { actual += value; } });
          stream.write(input.slice(0, split));
          stream.write(input.slice(split));
          stream.end();
          expect(actual).toBe(expected);
        }
      }
    }
  });

  it("bounds continued separators and retains final-token redaction", () => {
    let actual = "";
    const stream = createBoundedLineRedactor({ maxLineChars: 32, write: (value) => { actual += value; } });
    stream.write("password:\n");
    for (let i = 0; i < 1000; i += 1) stream.write(" ' : \"\n");
    stream.write("reviewercredential2060 (loaded)");
    stream.end();
    expect(actual).not.toContain("reviewercredential2060");
    expect(actual).toContain("[REDACTED] (loaded)");
    expect(actual).toContain("suppressed");
    expect(actual.length).toBeLessThan(300);
  });
});
