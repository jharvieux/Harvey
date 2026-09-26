// The ONE real implementation of RunContext.exec — how a probe shells out to its module's CLI.
//
// #1109: it lived twice, copy-pasted into src/cli/run-audit.ts and src/cli/validate-conservation.ts,
// and the copies drifted the moment one of them learned to keep stderr: the orchestrator handed M4
// and M5 their scope counts while the conservation gate — running the same probes over the same
// fixture — did not, so the gate failed on a difference between two spellings of "run the tool".
// A probe's view of the outside world has to be identical in both, so there is one of these.
//
// Await both child streams: quality-scan prints the jscpd/knip scope counts M4 and M5 need on
// stderr, and the event loop must remain available while a module CLI runs. Keep stderr separate
// from `output`: M4/M5 parse stdout as bare Finding[] JSON, so merging the streams would break it.

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import type { RunContext } from "./audit-runner.js";
import {
  commandReceiptSucceeded,
  createCommandExecutionReceipt,
  type CommandExecutionReceipt,
  type CommandTerminalState,
} from "./producer-execution-receipt.js";

type ProbeExecOptions = NonNullable<Parameters<RunContext["exec"]>[2]>;

// Match spawnSync's default combined output budget without retaining an unbounded stream.
const MAX_OUTPUT_BYTES = 1024 * 1024;
const KILL_GRACE_MS = 500;
const STREAM_CLOSE_GRACE_MS = 500;

type OutputCompleteness = { stdout: "complete" | "truncated" | "unknown"; stderr: "complete" | "truncated" | "unknown" };

interface ChildResult {
  stdout: Buffer;
  stderr: Buffer;
  status: number | null;
  signal: NodeJS.Signals | null;
  error?: NodeJS.ErrnoException;
  completeness: OutputCompleteness;
}

function terminalState(result: ChildResult): CommandTerminalState {
  if (result.error?.code === "ETIMEDOUT") return "timed-out";
  if (result.error?.code === "ENOBUFS") return "output-limit-exceeded";
  if (result.error) return "spawn-failed";
  if (typeof result.status === "number") return "exited";
  if (result.signal) return "signaled";
  return "unknown-exit";
}

function executeChild(command: string, argv: string[], options: ProbeExecOptions): Promise<ChildResult> {
  if (options.timeoutMs !== undefined && (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 1)) {
    return Promise.reject(new RangeError("command timeoutMs must be a positive integer"));
  }
  return new Promise((resolve, reject) => {
    const began = performance.now();
    const child = spawn(command, argv, {
      stdio: ["ignore", "pipe", "pipe"],
      cwd: options.cwd,
      // Overlay per-project credentials without changing the parent or another invocation.
      ...(options.env ? { env: { ...process.env, ...options.env } } : {}),
    });
    const chunks: Record<"stdout" | "stderr", Buffer[]> = { stdout: [], stderr: [] };
    const completeness: OutputCompleteness = { stdout: "complete", stderr: "complete" };
    let capturedBytes = 0;
    let outputLimited = false;
    let timedOut = false;
    let error: NodeJS.ErrnoException | undefined;
    let streamError: Error | undefined;
    let deadline: NodeJS.Timeout | undefined;
    let escalation: NodeJS.Timeout | undefined;
    let streamDeadline: NodeJS.Timeout | undefined;

    const terminate = () => {
      if (escalation) return;
      child.kill("SIGTERM");
      // A handler may ignore SIGTERM or exit zero. Keep the interruption as the outcome and
      // wait for actual process termination; never finalize from the deadline callback alone.
      escalation = setTimeout(() => {
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
        streamDeadline = setTimeout(() => {
          // Descendants can inherit these descriptors after the owned child exits. Closing our
          // read ends bounds cleanup without claiming that an incomplete stream was complete.
          for (const name of ["stdout", "stderr"] as const) {
            if (!child[name].readableEnded) {
              if (completeness[name] === "complete") completeness[name] = "unknown";
              child[name].destroy();
            }
          }
        }, STREAM_CLOSE_GRACE_MS);
      }, KILL_GRACE_MS);
    };

    for (const name of ["stdout", "stderr"] as const) {
      child[name].on("error", (cause: Error) => {
        streamError = new Error(`command ${name} stream failed: ${cause.message}`, { cause });
        completeness[name] = "unknown";
        terminate();
      });
      child[name].on("data", (chunk: Buffer) => {
        const available = Math.max(0, MAX_OUTPUT_BYTES - capturedBytes);
        const retained = chunk.subarray(0, available);
        if (retained.length) {
          chunks[name].push(retained);
          capturedBytes += retained.length;
        }
        if (retained.length < chunk.length) {
          outputLimited = true;
          completeness[name] = "truncated";
          terminate();
        }
      });
    }
    child.on("error", (cause: NodeJS.ErrnoException) => { error = cause; });
    child.once("close", (status, signal) => {
      clearTimeout(deadline);
      clearTimeout(escalation);
      clearTimeout(streamDeadline);
      if (outputLimited) {
        for (const name of ["stdout", "stderr"] as const) {
          if (completeness[name] === "complete") completeness[name] = "unknown";
        }
      }
      if (streamError) { reject(streamError); return; }
      resolve({
        stdout: Buffer.concat(chunks.stdout),
        stderr: Buffer.concat(chunks.stderr),
        status,
        signal,
        completeness,
        ...(timedOut
          ? { error: Object.assign(new Error(`command timed out after ${options.timeoutMs}ms`), { code: "ETIMEDOUT" }) }
          : outputLimited
            ? { error: Object.assign(new Error("command exceeded the output buffer limit"), { code: "ENOBUFS" }) }
            : error ? { error } : {}),
      });
    });
    const timeoutMs = options.timeoutMs;
    if (timeoutMs !== undefined) {
      const checkDeadline = () => {
        const remaining = timeoutMs - (performance.now() - began);
        if (remaining > 0) deadline = setTimeout(checkDeadline, Math.min(remaining, 2_147_483_647));
        else { timedOut = true; terminate(); }
      };
      checkDeadline();
    }
  });
}

function finalizeReceipt(
  command: string,
  argv: string[],
  opts: ProbeExecOptions,
  startedAt: string,
  finishedAt: string,
  stdout: string | Buffer,
  stderr: string | Buffer,
  state: CommandTerminalState,
  observedStatus: number | null,
  signal: string | null,
  errorCode?: string,
  outputCompleteness?: {
    stdout: "complete" | "truncated" | "unknown";
    stderr: "complete" | "truncated" | "unknown";
  },
): CommandExecutionReceipt {
  const cwd = opts.cwd ?? process.cwd();
  return createCommandExecutionReceipt({
    invocationId: opts.receipt?.invocationId ?? randomUUID(),
    attempt: opts.receipt?.attempt,
    command: { executable: command, argv, cwd },
    target: opts.receipt?.target ?? { identity: "working-directory", value: cwd },
    toolchain: opts.receipt?.toolchain ?? [{ name: command, version: process.version }],
    configuration: opts.receipt?.configuration ?? { identity: "sanitized-argv", value: argv },
    startedAt,
    finishedAt,
    outcome: {
      state,
      exitCode: state === "exited" ? observedStatus : null,
      ...(["timed-out", "output-limit-exceeded"].includes(state) && typeof observedStatus === "number" ? { observedExitCode: observedStatus } : {}),
      signal,
      ...(errorCode ? { errorCode } : {}),
    },
    timeoutPolicy: { timeoutMs: opts.timeoutMs ?? null, killSignal: "SIGTERM" },
    cancellationPolicy: "pre-start-only",
    stdout,
    stderr,
    ...(outputCompleteness ? { outputCompleteness } : {}),
    artifacts: opts.receipt?.artifacts,
    measurements: opts.receipt?.measurements,
    secretValues: opts.receipt?.secretValues,
  });
}

export const probeExec: RunContext["exec"] = async (command, argv, opts) => {
  // Receipt inputs must describe the launched invocation even if its caller changes shared
  // arrays, metadata, or the process cwd while this function yields. Keep only the live signal
  // and clock callback outside the value snapshot; neither belongs in persisted metadata.
  const args = [...argv];
  const { signal, receipt: metadata, ...execution } = opts ?? {};
  const { now: receiptNow, ...receiptValues } = metadata ?? {};
  const options: ProbeExecOptions = {
    ...structuredClone(execution),
    cwd: resolve(execution.cwd ?? process.cwd()),
    ...(signal ? { signal } : {}),
    ...(metadata ? { receipt: { ...structuredClone(receiptValues), ...(receiptNow ? { now: receiptNow } : {}) } } : {}),
  };
  const now = receiptNow ?? (() => new Date().toISOString());
  const startedAt = now();
  if (options.receipt?.policyAllowed === false) {
    const receipt = finalizeReceipt(
      command, args, options, startedAt, now(), "", options.receipt.policyReason ?? "command denied by policy",
      "policy-denied", null, null, "POLICY_DENIED",
    );
    return { ok: false, output: options.receipt.policyReason ?? "command denied by policy", stderr: options.receipt.policyReason ?? "command denied by policy", receipt };
  }
  // Cancellation remains pre-start-only. Yielding does not authorize late aborts to kill a child
  // or relabel the actual exit; callers retain the same cancellation contract.
  if (options.signal?.aborted) {
    const receipt = finalizeReceipt(command, args, options, startedAt, now(), "", "command cancelled before start", "cancelled", null, null, "ABORT_ERR");
    return { ok: false, output: "command cancelled before start", stderr: "command cancelled before start", receipt };
  }
  const r = await executeChild(command, args, options);
  const stdout = r.stdout.toString("utf8");
  const stderr = r.stderr.toString("utf8");
  const state = terminalState(r);
  const receipt = finalizeReceipt(
    command,
    args,
    options,
    startedAt,
    now(),
    r.stdout,
    r.stderr,
    state,
    r.status,
    r.signal,
    r.error?.code,
    r.completeness,
  );
  // A tool that exits non-zero or is not installed is a real outcome the probe must judge, not an
  // orchestrator crash — hand it back and let the module's probe describe it.
  if (!commandReceiptSucceeded(receipt)) {
    const artifactError = receipt.artifactFailures.map((artifact) => `declared ${artifact.role} artifact ${artifact.reason}: ${artifact.path}`).join("; ");
    return { ok: false, output: [stderr || stdout || r.error?.message || "", artifactError].filter(Boolean).join("\n"), stderr, receipt };
  }
  return { ok: true, output: stdout, stderr, receipt };
};
