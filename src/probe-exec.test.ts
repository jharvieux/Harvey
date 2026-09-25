import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { probeExec } from "./probe-exec.js";
import {
  assertCommandExecutionReceipt,
  commandReceiptSucceeded,
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
