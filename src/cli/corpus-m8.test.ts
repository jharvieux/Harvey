import { execFileSync, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { M8_CORPUS_CONFIGS } from "../scan/m8-corpus.js";
import { buildM8CorpusPlan, type M8TargetResult } from "../scan/m8-corpus-artifacts.js";
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
    writeFileSync(join(bin, "pnpm"), [
      `#!${process.execPath}`,
      `const { writeFileSync, writeSync } = require("node:fs");`,
      `const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));`,
      `(async () => {`,
      `  writeSync(1, "selected manager pnpm@11.1.3; live progress 1/3\\n");`,
      `  writeSync(1, "Authorization: Bea"); await wait(10); writeSync(1, "rer ${stdoutSecret}\\n");`,
      `  writeSync(2, "stderr diagnostic ghp_ABCDEFGHIJ"); await wait(10); writeSync(2, "KLMNOPQRSTUVWXYZ012345\\n");`,
      `  writeSync(1, "password: ${longLineSecret} " + "x".repeat(70 * 1024) + "\\n");`,
      `  writeSync(1, "${target}: 1s — clone 0.1s\\n");`,
      `  writeSync(2, "launch src/cli/mutation-"); await wait(10); writeSync(2, "scan.ts now\\n");`,
      `  writeSync(2, "M8 PHASES: test baseline 0.1s, mutation 0.2s, line coverage 0.1s\\n");`,
      `  writeSync(2, "tool-install ${outcome === "success" ? "complete" : "failed"}, selected manager pnpm@11.1.3\\n");`,
      `  writeSync(2, "secret: finalpartial"); await wait(10); writeSync(2, "credential2060");`,
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
    for (const secret of [stdoutSecret, stderrSecret, longLineSecret, finalSecret]) expect(targetRun.stderr).not.toContain(secret);
    expect(targetRun.stderr.match(/\[REDACTED\]/g)?.length).toBeGreaterThanOrEqual(3);

    const targetArtifact = readFileSync(resultPath, "utf8");
    const result = JSON.parse(targetArtifact) as M8TargetResult;
    expect(result.status).toBe(outcome === "success" ? "passed" : "failed");
    for (const secret of [stdoutSecret, stderrSecret, longLineSecret, finalSecret]) expect(targetArtifact).not.toContain(secret);
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
});
