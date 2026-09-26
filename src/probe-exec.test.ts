import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { probeExec } from "./probe-exec.js";
import {
  assertCommandExecutionReceipt,
  commandReceiptSucceeded,
  createCommandExecutionReceipt,
  verifyCommandExecutionReceiptArtifacts,
} from "./producer-execution-receipt.js";

describe("probeExec command execution receipts", () => {
  const root = mkdtempSync(join(tmpdir(), "harvey-command-receipt-"));
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  const receiptOptions = (over: Record<string, unknown> = {}) => ({
    receipt: {
      invocationId: "invocation-1",
      target: { identity: "fixture-target", value: { revision: "abc123" } },
      toolchain: [{ name: "node", version: process.version }],
      configuration: { identity: "fixture-config", value: { mode: "test" } },
      ...over,
    },
  });

  it("advances a heartbeat within the real child's delayed process window", async () => {
    const beats: bigint[] = [];
    let heartbeat: NodeJS.Immediate;
    const tick = () => {
      beats.push(process.hrtime.bigint());
      heartbeat = setImmediate(tick);
    };
    heartbeat = setImmediate(tick);
    try {
      const result = await probeExec(process.execPath, ["-e", `
        process.stdout.write(process.hrtime.bigint().toString() + "\\n");
        setTimeout(() => {
          process.stdout.write(process.hrtime.bigint().toString() + "\\n");
        }, 180);
      `], receiptOptions({ invocationId: "heartbeat" }));
      const [started, finished] = result.output.trim().split("\n").map(BigInt);
      expect(result.ok).toBe(true);
      expect(started).toBeDefined();
      expect(finished).toBeDefined();
      // Count only ticks between the child timestamps so host work outside the child window
      // stays excluded from the liveness assertion.
      expect(beats.some((beat) => beat > started! && beat < finished!)).toBe(true);
    } finally {
      clearImmediate(heartbeat);
    }
  });

  it("settles distinct complete streams before binding a delayed artifact", async () => {
    const report = join(root, "delayed-report.json");
    const result = await probeExec(process.execPath, ["-e", `
      const fs = require('node:fs');
      const bytes = Buffer.from('α🙂');
      process.stdout.write(bytes.subarray(0, 3));
      process.stderr.write('scope-start\\n');
      setTimeout(() => {
        fs.writeFileSync(${JSON.stringify(report)}, '{"findings":[]}\\n');
        process.stdout.write(bytes.subarray(3));
        process.stderr.write('scope-finished\\n');
      }, 40);
    `], { ...receiptOptions({ invocationId: "delayed-streams", artifacts: [{ role: "report", path: report }] }), cwd: root });
    expect(result).toMatchObject({ ok: true, output: "α🙂", stderr: "scope-start\nscope-finished\n" });
    expect(result.receipt?.stdout).toMatchObject({ bytes: Buffer.byteLength("α🙂"), completeness: "complete", sha256: createHash("sha256").update("α🙂").digest("hex") });
    expect(result.receipt?.stderr).toMatchObject({ completeness: "complete", sha256: createHash("sha256").update("scope-start\nscope-finished\n").digest("hex") });
    expect(result.receipt?.command.cwd).toBe(root);
    expect(result.receipt?.artifacts).toEqual([expect.objectContaining({ path: report, bytes: 16 })]);
    expect(() => verifyCommandExecutionReceiptArtifacts(result.receipt!)).not.toThrow();
  });

  it("waits for inherited pipe tails after the direct child exits", async () => {
    const tail = "setTimeout(() => { process.stdout.write('late-out'); process.stderr.write('late-err'); }, 60)";
    const result = await probeExec(process.execPath, ["-e", `
      require('node:child_process').spawn(process.execPath, ['-e', ${JSON.stringify(tail)}], { stdio: ['ignore', 1, 2] }).unref();
      process.stdout.write('early-out;');
      process.exit(0);
    `], receiptOptions({ invocationId: "inherited-pipe-tail" }));
    expect(result).toMatchObject({ ok: true, output: "early-out;late-out", stderr: "late-err" });
    expect(result.receipt?.stdout.completeness).toBe("complete");
    expect(result.receipt?.stderr.completeness).toBe("complete");
  });

  it("bounds owned pipes after a zero-exit child leaves an inherited descriptor open", async () => {
    const started = join(root, "pipe-holder-started");
    const released = join(root, "pipe-holder-release");
    const stopped = join(root, "pipe-holder-stopped");
    const holder = `
      const fs = require('node:fs');
      fs.writeFileSync(${JSON.stringify(started)}, process.pid.toString());
      process.stdout.write('holding-pipe');
      const stop = () => { fs.writeFileSync(${JSON.stringify(stopped)}, 'stopped'); process.exit(0); };
      setInterval(() => { if (fs.existsSync(${JSON.stringify(released)})) stop(); }, 10);
      setTimeout(stop, 5000);
    `;
    try {
      const result = await probeExec(process.execPath, ["-e", `
        require('node:child_process').spawn(process.execPath, ['-e', ${JSON.stringify(holder)}], { stdio: ['ignore', 1, 2] }).unref();
        process.exit(0);
      `], { timeoutMs: 600 });
      expect(existsSync(started)).toBe(true);
      expect(existsSync(stopped), "the owned pipe must close without waiting for the external holder").toBe(false);
      expect(result.ok).toBe(false);
      expect(result.receipt?.outcome).toEqual({ state: "timed-out", exitCode: null, observedExitCode: 0, signal: null, errorCode: "ETIMEDOUT" });
      expect(result.receipt?.stdout.completeness).toBe("unknown");
      expect(result.receipt?.stderr.completeness).toBe("unknown");
    } finally {
      writeFileSync(released, "release");
      const deadline = performance.now() + 5000;
      while (!existsSync(stopped) && performance.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
      if (!existsSync(stopped) && existsSync(started)) {
        try { process.kill(Number(readFileSync(started, "utf8")), "SIGKILL"); } catch { /* The fixture may already have exited. */ }
      }
      expect(existsSync(stopped), "the fixture descriptor holder must settle during cleanup").toBe(true);
    }
  });

  it("preserves the real signal, stdout and stderr of a signaled child", async () => {
    const result = await probeExec(process.execPath, ["-e", "process.stdout.write('out'); process.stderr.write('err'); process.kill(process.pid, 'SIGTERM')"]);
    expect(result).toMatchObject({ ok: false, output: "err", stderr: "err" });
    expect(result.receipt?.outcome).toEqual({ state: "signaled", exitCode: null, signal: "SIGTERM" });
    expect(result.receipt?.stdout.bytes).toBe(3);
    expect(result.receipt?.stderr.bytes).toBe(3);
  });

  it("keeps a deadline failure after a handler flushes output and exits zero", async () => {
    const report = join(root, "timeout-handler-report.json");
    const result = await probeExec(process.execPath, ["-e", `
      process.on('SIGTERM', () => {
        require('node:fs').writeFileSync(${JSON.stringify(report)}, '{}');
        process.stdout.write('handled');
        process.stderr.write('final-scope');
        process.exit(0);
      });
      process.stdout.write('ready;');
      setInterval(() => {}, 1000);
      setTimeout(() => process.exit(99), 5000);
    `], { ...receiptOptions({ invocationId: "timeout-zero", artifacts: [{ role: "report", path: report }] }), timeoutMs: 600 });
    expect(result.ok).toBe(false);
    expect(result.receipt?.outcome).toEqual({ state: "timed-out", exitCode: null, observedExitCode: 0, signal: null, errorCode: "ETIMEDOUT" });
    expect(result.receipt?.timeoutPolicy).toEqual({ timeoutMs: 600, killSignal: "SIGTERM" });
    expect(result.receipt?.stdout).toMatchObject({ bytes: 13, completeness: "complete" });
    expect(result.stderr).toBe("final-scope");
    expect(result.receipt?.artifactFailures).toEqual([]);
    expect(result.receipt?.artifacts[0]?.path).toBe(report);
    expect(commandReceiptSucceeded(result.receipt!)).toBe(false);
  });

  it("settles the owned child after escalating an ignored termination signal", async () => {
    const pidPath = join(root, "ignored-term.pid");
    const result = await probeExec(process.execPath, ["-e", `
      require('node:fs').writeFileSync(${JSON.stringify(pidPath)}, process.pid.toString());
      process.on('SIGTERM', () => process.stderr.write('ignored SIGTERM'));
      process.stdout.write(process.pid.toString());
      setInterval(() => {}, 1000);
      setTimeout(() => process.exit(99), 5000);
    `], { timeoutMs: 600 });
    expect(result.ok).toBe(false);
    expect(result.receipt?.outcome).toEqual({ state: "timed-out", exitCode: null, signal: "SIGKILL", errorCode: "ETIMEDOUT" });
    expect(result.stderr).toBe("ignored SIGTERM");
    const pid = Number(readFileSync(pidPath, "utf8"));
    expect(() => process.kill(pid, 0)).toThrow();
    expect(result.receipt?.stdout.bytes).toBeGreaterThan(0);
    expect(result.receipt?.stdout.completeness).toBe("complete");
  });

  it.each(["stdout", "stderr"] as const)("bounds %s bytes when an overflowing child ignores SIGTERM", async (stream) => {
    const result = await probeExec(process.execPath, ["-e", `
      process.on('SIGTERM', () => {});
      process.${stream}.write('x'.repeat(2 * 1024 * 1024));
      setInterval(() => {}, 1000);
      setTimeout(() => process.exit(99), 5000);
    `]);
    expect(result.ok).toBe(false);
    expect(result.receipt?.outcome).toEqual({ state: "output-limit-exceeded", exitCode: null, signal: "SIGKILL", errorCode: "ENOBUFS" });
    expect(result.receipt?.[stream]).toMatchObject({ bytes: 1024 * 1024, completeness: "truncated" });
    expect(result.receipt!.stdout.bytes + result.receipt!.stderr.bytes).toBe(1024 * 1024);
  });

  it("applies one shared output budget while accepting output exactly at the boundary", async () => {
    const boundary = await probeExec(process.execPath, ["-e", "process.stdout.write('x'.repeat(1024 * 1024))"]);
    expect(boundary.ok).toBe(true);
    expect(boundary.receipt?.stdout).toMatchObject({ bytes: 1024 * 1024, completeness: "complete" });
    const overflow = await probeExec(process.execPath, ["-e", "process.stdout.write('x'.repeat(600000)); process.stderr.write('y'.repeat(600000))"]);
    expect(overflow.ok).toBe(false);
    expect(overflow.receipt?.outcome.state).toBe("output-limit-exceeded");
    expect(overflow.receipt!.stdout.bytes + overflow.receipt!.stderr.bytes).toBe(1024 * 1024);
    expect(overflow.receipt?.stdout.bytes).toBeGreaterThan(0);
    expect(overflow.receipt?.stderr.bytes).toBeGreaterThan(0);
  });

  it("binds the receipt to invocation inputs frozen before the child yields", async () => {
    const report = join(root, "original-invocation-report.json");
    const replacement = join(root, "replacement-invocation-report.json");
    writeFileSync(replacement, "replacement");
    const secret = "original-receipt-secret";
    const argv = ["-e", `setTimeout(() => {
      require('node:fs').writeFileSync(${JSON.stringify(report)}, 'original');
      process.stdout.write(process.env.HARVEY_PROBE_EXEC_FIXTURE);
    }, 80)`, "--", secret];
    const originalArgs = [...argv];
    const options = {
      cwd: root, timeoutMs: 1000, env: { HARVEY_PROBE_EXEC_FIXTURE: "original" },
      receipt: {
        invocationId: "frozen-input", attempt: 1,
        target: { identity: "target", value: { revision: "original" } },
        configuration: { identity: "config", value: { flags: ["original"] } },
        artifacts: [{ role: "report" as const, path: report }],
        toolchain: [{ name: "node", version: process.version }],
        secretValues: [secret], measurements: { completedTests: 1 },
      },
    };
    const pending = probeExec(process.execPath, argv, options);
    argv.push("forged-argument");
    options.cwd = join(root, "forged-cwd");
    options.timeoutMs = 1;
    options.env.HARVEY_PROBE_EXEC_FIXTURE = "replacement";
    options.receipt.invocationId = "forged-invocation";
    options.receipt.attempt = 9;
    options.receipt.target.identity = "forged-target";
    options.receipt.target.value.revision = "replacement";
    options.receipt.configuration.value.flags.push("replacement");
    options.receipt.artifacts[0]!.path = replacement;
    options.receipt.toolchain[0]!.version = "forged-version";
    options.receipt.secretValues.length = 0;
    options.receipt.measurements.completedTests = 99;
    const result = await pending;
    expect(result).toMatchObject({ ok: true, output: "original" });
    expect(result.receipt).toMatchObject({ invocationId: "frozen-input", attempt: 1, command: { cwd: root }, timeoutPolicy: { timeoutMs: 1000 }, measurements: { completedTests: 1 } });
    expect(result.receipt?.command.argv).toEqual([...originalArgs.slice(0, -1), "<redacted>"]);
    expect(result.receipt?.target).toEqual({ identity: "target", sha256: createHash("sha256").update(JSON.stringify({ revision: "original" })).digest("hex") });
    expect(result.receipt?.configuration).toEqual({ identity: "config", sha256: createHash("sha256").update(JSON.stringify({ flags: ["original"] })).digest("hex") });
    expect(result.receipt?.toolchain).toEqual([{ name: "node", version: process.version }]);
    expect(result.receipt?.artifacts).toEqual([expect.objectContaining({ path: report, bytes: 8 })]);
    expect(JSON.stringify(result.receipt)).not.toContain(secret);
    expect(options.receipt.invocationId).toBe("forged-invocation"); // The snapshot never mutates its caller.
  });

  it("binds the effective default cwd before a caller changes the process directory", async () => {
    const originalCwd = process.cwd();
    const pending = probeExec(process.execPath, ["-e", "setTimeout(() => process.stdout.write(process.cwd()), 50)"]);
    try {
      process.chdir(root);
      const result = await pending;
      expect(result).toMatchObject({ ok: true, output: realpathSync(originalCwd) });
      expect(result.receipt?.command.cwd).toBe(originalCwd);
      expect(result.receipt?.target.sha256).toBe(createHash("sha256").update(JSON.stringify(originalCwd)).digest("hex"));
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("binds a relative cwd artifact to the launch directory despite a later process chdir", async () => {
    const originalCwd = process.cwd();
    const launch = join(root, "relative-launch");
    const later = join(root, "relative-later");
    mkdirSync(join(launch, "run"), { recursive: true });
    mkdirSync(join(later, "run"), { recursive: true });
    const actual = '{"actual":1}';
    const decoy = '{"decoy":"later"}';
    writeFileSync(join(later, "run", "report.json"), decoy);
    try {
      process.chdir(launch);
      const launchedCwd = join(process.cwd(), "run");
      const options = { cwd: "run", receipt: { artifacts: [{ role: "report" as const, path: "report.json" }] } };
      const pending = probeExec(process.execPath, ["-e", `
        setTimeout(() => {
          require('node:fs').writeFileSync('report.json', ${JSON.stringify(actual)});
          process.stdout.write(process.cwd());
        }, 80);
      `], options);
      process.chdir(later);
      const result = await pending;
      expect(result).toMatchObject({ ok: true, output: launchedCwd });
      expect(readFileSync(join(launch, "run", "report.json"), "utf8")).toBe(actual);
      expect(result.receipt?.artifacts).toEqual([expect.objectContaining({
        path: join(launchedCwd, "report.json"), bytes: Buffer.byteLength(actual),
        sha256: createHash("sha256").update(actual).digest("hex"),
      })]);
      expect(result.receipt?.command.cwd).toBe(launchedCwd);
      expect(result.receipt?.target.sha256).toBe(createHash("sha256").update(JSON.stringify(launchedCwd)).digest("hex"));
      expect(options.cwd).toBe("run");
      expect(readFileSync(join(later, "run", "report.json"), "utf8")).toBe(decoy);
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("keeps a nonexistent relative cwd as a disclosed spawn failure", async () => {
    const relativeCwd = "missing-probe-cwd-do-not-create";
    const result = await probeExec(process.execPath, ["-e", "process.stdout.write('must-not-run')"], { cwd: relativeCwd });
    expect(result.ok).toBe(false);
    expect(result.receipt?.outcome).toEqual({ state: "spawn-failed", exitCode: null, signal: null, errorCode: "ENOENT" });
    expect(result.receipt?.command.cwd).toBe(join(process.cwd(), relativeCwd));
    expect(result.receipt?.stdout.bytes).toBe(0);
  });

  it("rejects non-cloneable receipt metadata without silently replacing its identity", async () => {
    const marker = join(root, "non-cloneable-metadata-started");
    const pending = probeExec(process.execPath, ["-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'started')`], {
      receipt: { target: { identity: "invalid-target", value: { callback: () => "not receipt data" } } },
    });
    await expect(pending).rejects.toMatchObject({ name: "DataCloneError" });
    expect(existsSync(marker)).toBe(false);
  });

  it("overlays per-child environment and cwd without changing the parent", async () => {
    const original = process.env.HARVEY_PROBE_EXEC_FIXTURE;
    const result = await probeExec(process.execPath, ["-e", "process.stdout.write(JSON.stringify({ cwd: process.cwd(), overlay: process.env.HARVEY_PROBE_EXEC_FIXTURE, inherited: !!process.env.PATH }))"], { cwd: root, env: { HARVEY_PROBE_EXEC_FIXTURE: "child-only" } });
    expect(JSON.parse(result.output)).toEqual({ cwd: realpathSync(root), overlay: "child-only", inherited: true });
    expect(process.env.HARVEY_PROBE_EXEC_FIXTURE).toBe(original);
  });

  it("records an unreadable declared artifact without rewriting a successful native exit", async () => {
    const result = await probeExec(process.execPath, ["-e", "process.exit(0)"], receiptOptions({ invocationId: "unreadable-artifact", artifacts: [{ role: "report", path: root }] }));
    expect(result.ok).toBe(false);
    expect(result.receipt?.outcome).toEqual({ state: "exited", exitCode: 0, signal: null });
    expect(result.receipt?.artifactFailures).toEqual([{ role: "report", path: root, reason: "unreadable", errorCode: "EISDIR" }]);
    expect(result.output).toContain("declared report artifact unreadable");
    expect(() => verifyCommandExecutionReceiptArtifacts(result.receipt!)).toThrow(/artifact is unreadable/);
  });

  it("rejects invalid pre-spawn options at the awaited seam without starting a child", async () => {
    const marker = join(root, "invalid-timeout-started");
    await expect(probeExec(process.execPath, ["-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'started')`], { timeoutMs: -1 })).rejects.toThrow(/timeout/);
    expect(existsSync(marker)).toBe(false);
    await expect(probeExec("invalid\0command", [])).rejects.toThrow(/null bytes/);
  });

  it("does not turn a very large configured timeout into an immediate deadline", async () => {
    const result = await probeExec(process.execPath, ["-e", "setTimeout(() => process.stdout.write('done'), 30)"], { timeoutMs: 2_147_483_648 });
    expect(result).toMatchObject({ ok: true, output: "done" });
    expect(result.receipt?.timeoutPolicy.timeoutMs).toBe(2_147_483_648);
  });

  it("records real success and non-zero exit without inferring either from output shape", async () => {
    const zeroTests = await probeExec(process.execPath, ["-e", "process.stdout.write('0 tests completed')"], receiptOptions());
    expect(zeroTests.ok).toBe(true);
    expect(zeroTests.receipt?.outcome).toMatchObject({ state: "exited", exitCode: 0, signal: null });
    expect(zeroTests.receipt?.stdout.bytes).toBeGreaterThan(0);
    expect(commandReceiptSucceeded(zeroTests.receipt!)).toBe(true);

    const failed = await probeExec(process.execPath, ["-e", "process.stdout.write('looks clean'); process.exit(7)"], receiptOptions({ invocationId: "invocation-2" }));
    expect(failed.ok).toBe(false);
    expect(failed.receipt?.outcome).toMatchObject({ state: "exited", exitCode: 7, signal: null });
    expect(commandReceiptSucceeded(failed.receipt!)).toBe(false);
  });

  it("distinguishes policy denial, spawn failure, timeout and cancellation", async () => {
    const denied = await probeExec(process.execPath, ["-e", "process.exit(0)"], receiptOptions({ invocationId: "denied", policyAllowed: false, policyReason: "scope denied" }));
    expect(denied.receipt?.outcome.state).toBe("policy-denied");

    const missing = await probeExec(join(root, "does-not-exist"), [], receiptOptions({ invocationId: "missing" }));
    expect(missing.receipt?.outcome.state).toBe("spawn-failed");

    const timedOut = await probeExec(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { ...receiptOptions({ invocationId: "timeout" }), timeoutMs: 20 });
    expect(timedOut.receipt?.outcome.state).toBe("timed-out");

    const controller = new AbortController();
    controller.abort();
    const marker = join(root, "cancelled-child-started");
    const cancelled = await probeExec(process.execPath, ["-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed')`], { ...receiptOptions({ invocationId: "cancelled" }), signal: controller.signal });
    expect(existsSync(marker)).toBe(false);
    expect(cancelled.ok).toBe(false);
    expect(cancelled.receipt?.outcome.state).toBe("cancelled");
    expect(cancelled.receipt?.cancellationPolicy).toBe("pre-start-only");
  });

  it("records a real output-limit interruption as truncated execution, not a spawn failure", async () => {
    const secret = "overflow-secret";
    const interrupted = await probeExec(
      process.execPath,
      ["-e", "process.stdout.write('x'.repeat(2 * 1024 * 1024))", secret],
      receiptOptions({ invocationId: "output-limit", secretValues: [secret] }),
    );

    expect(interrupted.ok).toBe(false);
    expect(interrupted.receipt?.outcome).toMatchObject({
      state: "output-limit-exceeded",
      exitCode: null,
      errorCode: "ENOBUFS",
    });
    expect(interrupted.receipt?.outcome.signal).toBeTruthy();
    expect(interrupted.receipt?.stdout).toMatchObject({
      completeness: "truncated",
      sha256Scope: "captured-bytes",
    });
    expect(interrupted.receipt?.stdout.bytes).toBeGreaterThan(0);
    expect(interrupted.receipt?.stderr).toMatchObject({
      completeness: "unknown",
      sha256Scope: "captured-bytes",
    });
    expect(commandReceiptSucceeded(interrupted.receipt!)).toBe(false);
    expect(JSON.stringify(interrupted.receipt)).not.toContain(secret);
  });

  it("retains a native exit observed after an output-limit interrupt without inventing success", async () => {
    const script = "process.stdout.on('error', () => {}); process.on('SIGTERM', () => process.exit(7)); process.stdout.write('x'.repeat(2 * 1024 * 1024)); setInterval(() => {}, 1000)";
    const raw = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    expect(raw.error).toMatchObject({ code: "ENOBUFS" });
    expect(raw.status).not.toBeNull();

    const interrupted = await probeExec(process.execPath, ["-e", script], receiptOptions({ invocationId: "output-limit-handler" }));
    expect(interrupted.receipt?.outcome).toMatchObject({
      state: "output-limit-exceeded",
      exitCode: null,
      observedExitCode: raw.status,
      signal: raw.signal,
      errorCode: "ENOBUFS",
    });
    expect(interrupted.ok).toBe(false);
    expect(commandReceiptSucceeded(interrupted.receipt!)).toBe(false);
  });

  it("rejects contradictory command outcomes while accepting a coherent timeout", () => {
    const receipt = (
      outcome: Parameters<typeof createCommandExecutionReceipt>[0]["outcome"],
      outputCompleteness?: Parameters<typeof createCommandExecutionReceipt>[0]["outputCompleteness"],
    ) => () => createCommandExecutionReceipt({
      invocationId: "outcome-control",
      command: { executable: process.execPath, argv: [], cwd: root },
      target: { identity: "fixture-target", value: { revision: "abc123" } },
      toolchain: [{ name: "node", version: process.version }],
      configuration: { identity: "fixture-config", value: { mode: "test" } },
      startedAt: "2026-09-25T00:00:00.000Z",
      finishedAt: "2026-09-25T00:00:01.000Z",
      outcome,
      ...(outputCompleteness ? { outputCompleteness } : {}),
    });

    expect(receipt({ state: "timed-out", exitCode: 0, signal: null, errorCode: "ETIMEDOUT" })).toThrow(/timed-out.*exit code/i);
    expect(receipt({ state: "spawn-failed", exitCode: null, signal: "SIGTERM", errorCode: "ENOENT" })).toThrow(/spawn-failed.*signal/i);
    expect(receipt({ state: "exited", exitCode: 0, signal: null, errorCode: "EIO" })).toThrow(/exited.*error/i);
    expect(receipt({ state: "exited", exitCode: 0, observedExitCode: 7, signal: null })).toThrow(/observed interrupted exit code/i);
    expect(receipt(
      { state: "output-limit-exceeded", exitCode: null, observedExitCode: 7, signal: "SIGTERM", errorCode: "ENOBUFS" },
      { stdout: "truncated", stderr: "unknown" },
    )).toThrow(/observed exit code.*signal/i);
    expect(receipt({ state: "timed-out", exitCode: null, observedExitCode: 7, signal: "SIGTERM", errorCode: "ETIMEDOUT" })).toThrow(/observed exit code.*signal/i);

    const timeout = receipt({ state: "timed-out", exitCode: null, signal: "SIGTERM", errorCode: "ETIMEDOUT" })();
    expect(timeout.outcome.state).toBe("timed-out");
    expect(commandReceiptSucceeded(timeout)).toBe(false);
    const handledTimeout = receipt({ state: "timed-out", exitCode: null, observedExitCode: 7, signal: null, errorCode: "ETIMEDOUT" })();
    expect(commandReceiptSucceeded(handledTimeout)).toBe(false);
    const handledOutputLimit = receipt(
      { state: "output-limit-exceeded", exitCode: null, observedExitCode: 7, signal: null, errorCode: "ENOBUFS" },
      { stdout: "truncated", stderr: "unknown" },
    )();
    expect(commandReceiptSucceeded(handledOutputLimit)).toBe(false);
  });

  it("preserves pre-start-only cancellation despite an abort during the real child", async () => {
    const controller = new AbortController();
    const abort = new Promise<void>((resolve) => setTimeout(() => { controller.abort(); resolve(); }, 1));
    let completed = false;
    const pending = probeExec(process.execPath, ["-e", "setTimeout(() => process.exit(7), 100)"], { signal: controller.signal })
      .then((result) => { completed = true; return result; });
    await abort;
    expect(completed).toBe(false);
    const result = await pending;
    expect(controller.signal.aborted).toBe(true);
    expect(result.receipt?.outcome).toEqual({ state: "exited", exitCode: 7, signal: null });
    expect(result.receipt?.cancellationPolicy).toBe("pre-start-only");
  });

  it.each([0, 7])("retains exit %i and the missing output identity without accepting an incomplete command", async (exitCode) => {
    const report = join(root, `absent-${exitCode}.json`);
    const result = await probeExec(process.execPath, ["-e", `process.exit(${exitCode})`], receiptOptions({ artifacts: [{ role: "report", path: report }] }));
    expect(result.ok).toBe(false);
    expect(result.receipt?.outcome).toEqual({ state: "exited", exitCode, signal: null });
    expect(result.receipt?.artifactFailures).toEqual([{ role: "report", path: report, reason: "missing", errorCode: "ENOENT" }]);
    expect(result.output).toContain("declared report artifact missing");
    expect(commandReceiptSucceeded(result.receipt!)).toBe(false);
    expect(() => verifyCommandExecutionReceiptArtifacts(result.receipt!)).toThrow(/artifact is missing/);
  });

  it("sanitizes assignment URL credentials before retaining argv and hashing effective configuration", async () => {
    const run = async (password: string, token: string) => await probeExec(process.execPath, ["-e", "process.exit(0)", "--", `--db-url=postgres://demo:${password}@example.test/db`, `--endpoint=https://example.test?token=${token}`]);
    const first = await run("sentinel-password", "sentinel-token");
    const second = await run("different-password", "different-token");
    expect(first.ok).toBe(true);
    expect(JSON.stringify(first.receipt)).not.toContain("sentinel-");
    expect(first.receipt?.configuration.sha256).toBe(second.receipt?.configuration.sha256);
  });

  it("redacts credentials and invalidates acceptance when a bound artifact is regenerated", async () => {
    const report = join(root, "report.json");
    writeFileSync(report, "{\"run\":1}\n");
    const result = await probeExec(process.execPath, ["-e", "process.exit(0)", "--token", "secret-value", "https://user:pass@example.test/path?api_key=also-secret"], receiptOptions({
      invocationId: "artifact-run",
      secretValues: ["secret-value", "also-secret"],
      artifacts: [{ role: "report", path: report }],
    }));
    expect(result.receipt).toBeDefined();
    assertCommandExecutionReceipt(result.receipt);
    expect(JSON.stringify(result.receipt)).not.toContain("secret-value");
    expect(JSON.stringify(result.receipt)).not.toContain("also-secret");
    expect(JSON.stringify(result.receipt)).not.toContain("user:pass");
    verifyCommandExecutionReceiptArtifacts(result.receipt!);

    writeFileSync(report, "{\"run\":2}\n");
    expect(() => verifyCommandExecutionReceiptArtifacts(result.receipt!)).toThrow(/changed after invocation/);

    const firstSecret = await probeExec(process.execPath, ["-e", "process.exit(0)"], receiptOptions({
      invocationId: "secret-a", secretValues: ["first-low-entropy-secret"],
      configuration: { identity: "auth-config", value: { apiToken: "first-low-entropy-secret", mode: "test" } },
    }));
    const secondSecret = await probeExec(process.execPath, ["-e", "process.exit(0)"], receiptOptions({
      invocationId: "secret-b", secretValues: ["second-low-entropy-secret"],
      configuration: { identity: "auth-config", value: { apiToken: "second-low-entropy-secret", mode: "test" } },
    }));
    expect(firstSecret.receipt?.configuration.sha256).toBe(secondSecret.receipt?.configuration.sha256);
  });
});
