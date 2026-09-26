import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
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
      // Child timestamps bound the actual process window; ticks before launch or after exit
      // cannot make a synchronous implementation appear to yield.
      expect(beats.some((beat) => beat > started! && beat < finished!)).toBe(true);
    } finally {
      clearImmediate(heartbeat);
    }
  });

  it("records real success and non-zero exit without inferring either from output shape", () => {
    const zeroTests = probeExec(process.execPath, ["-e", "process.stdout.write('0 tests completed')"], receiptOptions());
    expect(zeroTests.ok).toBe(true);
    expect(zeroTests.receipt?.outcome).toMatchObject({ state: "exited", exitCode: 0, signal: null });
    expect(zeroTests.receipt?.stdout.bytes).toBeGreaterThan(0);
    expect(commandReceiptSucceeded(zeroTests.receipt!)).toBe(true);

    const failed = probeExec(process.execPath, ["-e", "process.stdout.write('looks clean'); process.exit(7)"], receiptOptions({ invocationId: "invocation-2" }));
    expect(failed.ok).toBe(false);
    expect(failed.receipt?.outcome).toMatchObject({ state: "exited", exitCode: 7, signal: null });
    expect(commandReceiptSucceeded(failed.receipt!)).toBe(false);
  });

  it("distinguishes policy denial, spawn failure, timeout and cancellation", () => {
    const denied = probeExec(process.execPath, ["-e", "process.exit(0)"], receiptOptions({ invocationId: "denied", policyAllowed: false, policyReason: "scope denied" }));
    expect(denied.receipt?.outcome.state).toBe("policy-denied");

    const missing = probeExec(join(root, "does-not-exist"), [], receiptOptions({ invocationId: "missing" }));
    expect(missing.receipt?.outcome.state).toBe("spawn-failed");

    const timedOut = probeExec(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { ...receiptOptions({ invocationId: "timeout" }), timeoutMs: 20 });
    expect(timedOut.receipt?.outcome.state).toBe("timed-out");

    const controller = new AbortController();
    controller.abort();
    const marker = join(root, "cancelled-child-started");
    const cancelled = probeExec(process.execPath, ["-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed')`], { ...receiptOptions({ invocationId: "cancelled" }), signal: controller.signal });
    expect(existsSync(marker)).toBe(false);
    expect(cancelled.ok).toBe(false);
    expect(cancelled.receipt?.outcome.state).toBe("cancelled");
    expect(cancelled.receipt?.cancellationPolicy).toBe("pre-start-only");
  });

  it("records a real output-limit interruption as truncated execution, not a spawn failure", () => {
    const secret = "overflow-secret";
    const interrupted = probeExec(
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

  it("retains a native exit observed after an output-limit interrupt without inventing success", () => {
    const script = "process.stdout.on('error', () => {}); process.on('SIGTERM', () => process.exit(7)); process.stdout.write('x'.repeat(2 * 1024 * 1024)); setInterval(() => {}, 1000)";
    const raw = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    expect(raw.error).toMatchObject({ code: "ENOBUFS" });
    expect(raw.status).not.toBeNull();

    const interrupted = probeExec(process.execPath, ["-e", script], receiptOptions({ invocationId: "output-limit-handler" }));
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

  it("discloses synchronous cancellation limits and preserves the real completed exit", async () => {
    const controller = new AbortController();
    const abort = new Promise<void>((resolve) => setTimeout(() => { controller.abort(); resolve(); }, 1));
    const result = probeExec(process.execPath, ["-e", "setTimeout(() => process.exit(7), 25)"], { signal: controller.signal });
    await abort;
    expect(controller.signal.aborted).toBe(true);
    expect(result.receipt?.outcome).toEqual({ state: "exited", exitCode: 7, signal: null });
    expect(result.receipt?.cancellationPolicy).toBe("pre-start-only");
  });

  it.each([0, 7])("retains exit %i and the missing output identity without accepting an incomplete command", (exitCode) => {
    const report = join(root, `absent-${exitCode}.json`);
    const result = probeExec(process.execPath, ["-e", `process.exit(${exitCode})`], receiptOptions({ artifacts: [{ role: "report", path: report }] }));
    expect(result.ok).toBe(false);
    expect(result.receipt?.outcome).toEqual({ state: "exited", exitCode, signal: null });
    expect(result.receipt?.artifactFailures).toEqual([{ role: "report", path: report, reason: "missing", errorCode: "ENOENT" }]);
    expect(result.output).toContain("declared report artifact missing");
    expect(commandReceiptSucceeded(result.receipt!)).toBe(false);
    expect(() => verifyCommandExecutionReceiptArtifacts(result.receipt!)).toThrow(/artifact is missing/);
  });

  it("sanitizes assignment URL credentials before retaining argv and hashing effective configuration", () => {
    const run = (password: string, token: string) => probeExec(process.execPath, ["-e", "process.exit(0)", "--", `--db-url=postgres://demo:${password}@example.test/db`, `--endpoint=https://example.test?token=${token}`]);
    const first = run("sentinel-password", "sentinel-token");
    const second = run("different-password", "different-token");
    expect(first.ok).toBe(true);
    expect(JSON.stringify(first.receipt)).not.toContain("sentinel-");
    expect(first.receipt?.configuration.sha256).toBe(second.receipt?.configuration.sha256);
  });

  it("redacts credentials and invalidates acceptance when a bound artifact is regenerated", () => {
    const report = join(root, "report.json");
    writeFileSync(report, "{\"run\":1}\n");
    const result = probeExec(process.execPath, ["-e", "process.exit(0)", "--token", "secret-value", "https://user:pass@example.test/path?api_key=also-secret"], receiptOptions({
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

    const firstSecret = probeExec(process.execPath, ["-e", "process.exit(0)"], receiptOptions({
      invocationId: "secret-a", secretValues: ["first-low-entropy-secret"],
      configuration: { identity: "auth-config", value: { apiToken: "first-low-entropy-secret", mode: "test" } },
    }));
    const secondSecret = probeExec(process.execPath, ["-e", "process.exit(0)"], receiptOptions({
      invocationId: "secret-b", secretValues: ["second-low-entropy-secret"],
      configuration: { identity: "auth-config", value: { apiToken: "second-low-entropy-secret", mode: "test" } },
    }));
    expect(firstSecret.receipt?.configuration.sha256).toBe(secondSecret.receipt?.configuration.sha256);
  });
});
