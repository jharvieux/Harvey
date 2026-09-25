// The ONE real implementation of RunContext.exec — how a probe shells out to its module's CLI.
//
// #1109: it lived twice, copy-pasted into src/cli/run-audit.ts and src/cli/validate-conservation.ts,
// and the copies drifted the moment one of them learned to keep stderr: the orchestrator handed M4
// and M5 their scope counts while the conservation gate — running the same probes over the same
// fixture — did not, so the gate failed on a difference between two spellings of "run the tool".
// A probe's view of the outside world has to be identical in both, so there is one of these.
//
// spawnSync, not execFileSync, because execFileSync RETURNS stdout only: a successful tool's stderr
// was discarded, and that is where quality-scan prints the jscpd/knip scope counts M4 and M5 need to
// say what they examined. stderr is kept SEPARATE from `output` — M4/M5's non-capturing path parses
// stdout as a bare Finding[] JSON, so merging the streams would break it.

import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import type { RunContext } from "./audit-runner.js";
import {
  commandReceiptSucceeded,
  createCommandExecutionReceipt,
  type CommandExecutionReceipt,
  type CommandTerminalState,
} from "./producer-execution-receipt.js";

type ProbeExecOptions = NonNullable<Parameters<RunContext["exec"]>[2]>;

function terminalState(result: ReturnType<typeof spawnSync>): CommandTerminalState {
  const code = (result.error as NodeJS.ErrnoException | undefined)?.code;
  if (code === "ETIMEDOUT") return "timed-out";
  if (result.error) return "spawn-failed";
  if (typeof result.status === "number") return "exited";
  if (result.signal) return "signaled";
  return "unknown-exit";
}

function finalizeReceipt(
  command: string,
  argv: string[],
  opts: ProbeExecOptions,
  startedAt: string,
  finishedAt: string,
  stdout: string,
  stderr: string,
  state: CommandTerminalState,
  status: number | null,
  signal: string | null,
  errorCode?: string,
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
    outcome: { state, exitCode: status, signal, ...(errorCode ? { errorCode } : {}) },
    timeoutPolicy: { timeoutMs: opts.timeoutMs ?? null, killSignal: "SIGTERM" },
    cancellationPolicy: "pre-start-only",
    stdout,
    stderr,
    artifacts: opts.receipt?.artifacts,
    measurements: opts.receipt?.measurements,
    secretValues: opts.receipt?.secretValues,
  });
}

export const probeExec: RunContext["exec"] = (command, argv, opts) => {
  const options = opts ?? {};
  const now = options.receipt?.now ?? (() => new Date().toISOString());
  const startedAt = now();
  if (options.receipt?.policyAllowed === false) {
    const receipt = finalizeReceipt(
      command, argv, options, startedAt, now(), "", options.receipt.policyReason ?? "command denied by policy",
      "policy-denied", null, null, "POLICY_DENIED",
    );
    return { ok: false, output: options.receipt.policyReason ?? "command denied by policy", stderr: options.receipt.policyReason ?? "command denied by policy", receipt };
  }
  // spawnSync blocks JavaScript callbacks and does not support AbortSignal. Honor cancellation
  // before starting, and never relabel a completed child based on a later signal observation.
  if (options.signal?.aborted) {
    const receipt = finalizeReceipt(command, argv, options, startedAt, now(), "", "command cancelled before start", "cancelled", null, null, "ABORT_ERR");
    return { ok: false, output: "command cancelled before start", stderr: "command cancelled before start", receipt };
  }
  const r = spawnSync(command, argv, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    cwd: options.cwd,
    timeout: options.timeoutMs,
    // #520: overlay a per-child env (e.g. a per-project SUPABASE_DB_URL for M10's live tier) onto
    // the inherited environment; absent ⇒ inherit unchanged.
    ...(opts?.env ? { env: { ...process.env, ...opts.env } } : {}),
  });
  const stdout = r.stdout ?? "";
  const stderr = r.stderr ?? "";
  const state = terminalState(r);
  const receipt = finalizeReceipt(
    command,
    argv,
    options,
    startedAt,
    now(),
    stdout,
    stderr,
    state,
    state === "exited" ? r.status : null,
    r.signal,
    (r.error as NodeJS.ErrnoException | undefined)?.code,
  );
  // A tool that exits non-zero or is not installed is a real outcome the probe must judge, not an
  // orchestrator crash — hand it back and let the module's probe describe it.
  if (!commandReceiptSucceeded(receipt)) {
    const artifactError = receipt.artifactFailures.map((artifact) => `declared ${artifact.role} artifact ${artifact.reason}: ${artifact.path}`).join("; ");
    return { ok: false, output: [stderr || stdout || r.error?.message || "", artifactError].filter(Boolean).join("\n"), stderr, receipt };
  }
  return { ok: true, output: stdout, stderr, receipt };
};
