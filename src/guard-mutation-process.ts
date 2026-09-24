import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";

export interface GuardCommandResult {
  command: string[];
  startedAt: string;
  firstByteAt: string | null;
  finishedAt: string;
  elapsedMs: number;
  fromFirstByteMs: number | null;
  maxParentBlockMs: number;
  exitCode: number | null;
  signal: string | null;
  state: "exited" | "timed-out" | "aborted" | "spawn-error";
  terminationAcknowledged: boolean;
  error: string | null;
  stdout: GuardOutput;
  stderr: GuardOutput;
}

interface GuardOutput { path: string; sha256: string; bytes: number; tail: string }

const TAIL_BYTES = 16 * 1024;
const HEARTBEAT_MS = 50;

/** All potentially long work runs outside the caller's event loop. Deadlines cover silent
 * children and terminate abandoned Vitest workers through their process groups. */
export async function runGuardCommand(options: {
  command: string[];
  cwd: string;
  bundleDir: string;
  outputPrefix: string;
  timeoutMs: number;
  killGraceMs: number;
  signal?: AbortSignal;
  onFirstByte?: () => void;
  /** Undefined ignores stdin, null keeps it open, and a string sends those exact bytes then EOF. */
  stdin?: string | null;
}): Promise<GuardCommandResult> {
  const { command, cwd, bundleDir, outputPrefix, timeoutMs, killGraceMs, signal } = options;
  if (!command[0] || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || !Number.isFinite(killGraceMs) || killGraceMs <= 0) throw new Error("guard command requires a command and finite positive time bounds");
  if (process.platform === "win32") throw new Error("guard mutation process-group isolation requires Linux or macOS");
  await mkdir(dirname(join(bundleDir, outputPrefix)), { recursive: true });
  const outputs = ["stdout", "stderr"].map((name) => {
    const path = `${outputPrefix}.${name}.log`;
    const stream = createWriteStream(join(bundleDir, path), { flags: "wx" });
    const hash = createHash("sha256");
    return { path, stream, hash, bytes: 0, tail: Buffer.alloc(0) };
  });
  const startedAt = new Date().toISOString();
  const started = performance.now();
  let firstByteAt: string | null = null;
  let firstByte: number | null = null;
  let lastTick = started;
  let maxParentBlockMs = 0;
  let state: GuardCommandResult["state"] = "exited";
  let error: string | null = null;
  let acknowledged = true;
  const sample = () => {
    const now = performance.now();
    if (firstByte !== null) maxParentBlockMs = Math.max(maxParentBlockMs, now - lastTick - HEARTBEAT_MS);
    lastTick = now;
  };
  const heartbeat = setInterval(sample, HEARTBEAT_MS);
  const child = spawn(command[0], command.slice(1), {
    cwd, detached: true, stdio: [options.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    // Dependencies are already installed and linked into private cache directories. Never let
    // pnpm's opportunistic verifier rewrite the shared installed package store.
    env: { ...process.env, pnpm_config_verify_deps_before_run: "false" },
  });
  let forceTimer: NodeJS.Timeout | undefined;
  let acknowledgmentTimer: NodeJS.Timeout | undefined;
  const killGroup = (kind: NodeJS.Signals) => {
    if (!child.pid) return;
    try { process.kill(-child.pid, kind); } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code !== "ESRCH") error ??= `process-group ${kind}: ${String(cause)}`;
    }
  };
  let resolveClose!: (result: { code: number | null; signal: string | null }) => void;
  const closed = new Promise<{ code: number | null; signal: string | null }>((done) => { resolveClose = done; });
  const terminate = (reason: "timed-out" | "aborted") => {
    if (state !== "exited") return;
    state = reason;
    killGroup("SIGTERM");
    forceTimer = setTimeout(() => killGroup("SIGKILL"), killGraceMs);
    acknowledgmentTimer = setTimeout(() => {
      acknowledged = false;
      error ??= "process group did not acknowledge termination before the cleanup deadline";
      child.stdout!.destroy(); child.stderr!.destroy(); child.unref();
      resolveClose({ code: null, signal: null });
    }, killGraceMs + 1_000);
  };
  const deadline = setTimeout(() => terminate("timed-out"), timeoutMs);
  const abort = () => terminate("aborted");
  signal?.addEventListener("abort", abort, { once: true });
  child.stdin?.on("error", (cause: NodeJS.ErrnoException) => {
    // A command may reject its arguments before consuming stdin; retain its native exit result.
    if (cause.code !== "EPIPE") { error ??= `stdin: ${cause.message}`; terminate("aborted"); }
  });
  if (options.stdin !== null) child.stdin?.end(options.stdin);
  for (const [index, stream] of [child.stdout!, child.stderr!].entries()) {
    const output = outputs[index]!;
    stream.on("data", (chunk: Buffer) => {
      if (firstByte === null) {
        firstByte = performance.now(); firstByteAt = new Date().toISOString(); lastTick = firstByte;
        options.onFirstByte?.();
      }
      output.hash.update(chunk); output.bytes += chunk.length;
      output.tail = Buffer.concat([output.tail, chunk]).subarray(-TAIL_BYTES);
      if (!output.stream.write(chunk)) {
        stream.pause(); output.stream.once("drain", () => stream.resume());
      }
    });
    output.stream.on("error", (cause) => { error ??= `cannot retain ${output.path}: ${cause.message}`; terminate("aborted"); stream.resume(); });
  }
  child.once("error", (cause) => { state = "spawn-error"; error ??= cause.message; });
  child.once("close", (code, endingSignal) => resolveClose({ code, signal: endingSignal }));
  if (signal?.aborted) abort();
  const terminal = await closed;
  // Even a normally exiting group leader must not leave background descendants behind.
  killGroup("SIGKILL");
  clearTimeout(deadline); clearTimeout(forceTimer); clearTimeout(acknowledgmentTimer);
  signal?.removeEventListener("abort", abort);
  await Promise.all(outputs.map(({ stream }) => new Promise<void>((done) => {
    if (stream.destroyed) { done(); return; }
    stream.once("error", () => done()); stream.end(done);
  })));
  // Let the timer observe a block ending in the final output/close callback.
  await new Promise<void>((done) => setTimeout(done, HEARTBEAT_MS));
  sample(); clearInterval(heartbeat);
  const finished = performance.now();
  return {
    command, startedAt, firstByteAt, finishedAt: new Date().toISOString(),
    elapsedMs: finished - started, fromFirstByteMs: firstByte === null ? null : finished - firstByte,
    maxParentBlockMs: Math.max(0, maxParentBlockMs), exitCode: terminal.code, signal: terminal.signal,
    state, terminationAcknowledged: acknowledged, error,
    stdout: { path: outputs[0]!.path, sha256: outputs[0]!.hash.digest("hex"), bytes: outputs[0]!.bytes, tail: outputs[0]!.tail.toString("utf8") },
    stderr: { path: outputs[1]!.path, sha256: outputs[1]!.hash.digest("hex"), bytes: outputs[1]!.bytes, tail: outputs[1]!.tail.toString("utf8") },
  };
}
