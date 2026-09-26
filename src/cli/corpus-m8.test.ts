import { spawn } from "node:child_process";
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

const MAX_BUFFER_BYTES = 1024 * 1024;
type CliRun = { status: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string; error?: NodeJS.ErrnoException };

function runCommand(command: string, args: string[], cwd: string, env: NodeJS.ProcessEnv): Promise<CliRun> {
  return new Promise((resolveRun) => {
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let overflow = false;
    let finished = false;
    let launchError: NodeJS.ErrnoException | undefined;
    const finish = (status: number | null, signal: NodeJS.Signals | null, error?: NodeJS.ErrnoException) => {
      if (finished) return;
      finished = true;
      resolveRun({ status, signal, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8"), error });
    };
    const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    const collect = (output: Buffer[], chunk: Buffer) => {
      if (overflow) return;
      const remaining = MAX_BUFFER_BYTES - bytes;
      if (chunk.length <= remaining) {
        output.push(chunk);
        bytes += chunk.length;
        return;
      }
      if (remaining > 0) output.push(chunk.subarray(0, remaining));
      bytes = MAX_BUFFER_BYTES;
      overflow = true;
      child.kill("SIGTERM");
    };
    child.stdout.on("data", (chunk: Buffer) => collect(stdout, chunk));
    child.stderr.on("data", (chunk: Buffer) => collect(stderr, chunk));
    child.once("error", (error: NodeJS.ErrnoException) => {
      launchError = error;
      if (child.pid === undefined) finish(null, null, error);
    });
    child.once("close", (status, signal) => {
      if (!overflow) return finish(status, signal, launchError);
      const error = Object.assign(new Error(`stdout and stderr exceeded ${MAX_BUFFER_BYTES} bytes`), { code: "ENOBUFS" }) as NodeJS.ErrnoException;
      finish(null, "SIGTERM", error);
    });
  });
}

function runCli(args: string[], cwd: string, env: NodeJS.ProcessEnv = process.env): Promise<CliRun> {
  return runCommand(process.execPath, ["--import", tsxLoader, cli, ...args], cwd, env);
}

async function runCliResponsive(args: string[], cwd: string, env: NodeJS.ProcessEnv = process.env): Promise<CliRun> {
  let finished = false;
  let heartbeats = 0;
  const heartbeat = setInterval(() => { if (!finished) heartbeats += 1; }, 5);
  try {
    const result = await runCli(args, cwd, env);
    finished = true;
    // This interval runs during the actual CLI child. A synchronous helper blocks it until close.
    expect(heartbeats, "M8 corpus CLI child work must service the Vitest worker event loop").toBeGreaterThan(0);
    return result;
  } finally {
    finished = true;
    clearInterval(heartbeat);
  }
}

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
  it("caps combined local-child stdout and stderr at the former 1 MiB synchronous limit", async () => {
    const result = await runCommand(process.execPath, ["--eval", 'process.stdout.write("o".repeat(600000)); process.stderr.write("e".repeat(600000)); setTimeout(() => process.exit(0), 1000);'], process.cwd(), process.env);
    expect(result).toMatchObject({ status: null, signal: "SIGTERM", error: { code: "ENOBUFS" } });
    expect(Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr)).toBeLessThanOrEqual(MAX_BUFFER_BYTES);
    expect(result.stdout).not.toHaveLength(0);
    expect(result.stderr).not.toHaveLength(0);
  });

  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it.each(["separate streams", "multiline preparation detail"])("retains bounded, redacted %s through target and aggregate artifacts", async (shape) => {
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
    expect((await runCliResponsive(["target", "--target", target, "--out", resultPath], root, { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` })).status).toBe(0);
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
    expect((await runCliResponsive(["aggregate", "--artifacts", artifacts, "--out", reportPath], root)).status).toBe(1);
    expect(existsSync(reportPath)).toBe(true);
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as { ok: boolean; failed: number; targets: M8TargetResult[] };
    expect(report).toMatchObject({ ok: false, failed: 1 });
    expect(report.targets.find((entry) => entry.target === target)?.error).toBe(result.error);
  });
});

describe("M8 terminal and aggregate redaction (#2060)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it.each(["success", "failure"] as const)("redacts split stdout/stderr credentials on %s and bounds long/final lines", async (outcome) => {
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
    const targetRun = await runCliResponsive(["target", "--target", target, "--out", resultPath], root, { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` });

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
    const aggregateRun = await runCliResponsive(["aggregate", "--artifacts", artifacts, "--out", reportPath], root);
    expect(aggregateRun.status).toBe(outcome === "success" ? 0 : 1);
    expect(aggregateRun.stderr).toContain("M8 AGGREGATE RUNNER COST:");
    expect(aggregateRun.stderr).not.toContain(aggregateSecret);
    const aggregateArtifact = readFileSync(reportPath, "utf8");
    expect(aggregateArtifact).not.toContain(aggregateSecret);
    expect(aggregateArtifact).toContain("Authorization: Bearer [REDACTED]");
  });

  it.each(["passed", "failed"] as const)("redacts an independently supplied %s target artifact during aggregation", async (status) => {
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
    const aggregateRun = await runCliResponsive(["aggregate", "--artifacts", artifacts, "--out", reportPath], root);

    expect(aggregateRun.status).toBe(status === "passed" ? 0 : 1);
    expect(aggregateRun.stderr).toContain("M8 AGGREGATE RUNNER COST:");
    expect(aggregateRun.stderr).not.toContain(aggregateSecret);
    const aggregateArtifact = readFileSync(reportPath, "utf8");
    expect(aggregateArtifact).not.toContain(aggregateSecret);
    expect(aggregateArtifact).toContain("Authorization: Bearer [REDACTED]");
  });

  it.each(["plan", "target", "aggregate"])("sanitizes %s filesystem failures at the terminal boundary", async (mode) => {
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
    const result = await runCliResponsive([mode, ...args], root);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("M8 CORPUS FAILED:");
    expect(result.stderr).toContain("[REDACTED]");
    expect(result.stderr).not.toContain(secret);
    expect(result.stderr).not.toContain("at Object.");
  });

  it("sanitizes rejected flags without changing exit status or accepted flag context", async () => {
    const secret = "ghp_1234567890ABCDEF";
    const result = await runCliResponsive(["plan", `--${secret}`], process.cwd());
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Unrecognized flag: --[REDACTED]");
    expect(result.stderr).toContain("--github-output");
    expect(result.stderr).not.toContain(secret);
  });

  it.each(["schemaVersion", "target"])("redacts credential-shaped %s values from aggregate validation failures", async (field) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-m8-invalid-aggregate-"));
    dirs.push(root);
    const artifacts = join(root, "artifacts");
    const target = "proposit";
    const targetDir = join(artifacts, target);
    mkdirSync(targetDir, { recursive: true });
    const schemaSecret = "ghp_1234567890ABCDEF";
    writeFileSync(join(targetDir, "result.json"), `${JSON.stringify(field === "schemaVersion" ? { schemaVersion: schemaSecret } : { schemaVersion: 1, target: schemaSecret, status: "failed", exitCode: 42, durationMs: 1, phases: null, scorecard: null })}\n`);

    const reportPath = join(root, "aggregate.json");
    const aggregateRun = await runCliResponsive(["aggregate", "--artifacts", artifacts, "--out", reportPath], root);

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
