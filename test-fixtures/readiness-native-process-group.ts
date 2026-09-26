// Physical comparison fixture: native groups do not prove descendant ownership.
// Shipping readiness uses the contained runner; this preserves the original failure direction.
import { spawn, type ChildProcess } from "node:child_process";
import { debuglog } from "node:util";
import type { ReadinessSpawnRequest } from "../src/audit-readiness-authority.js";
import { BoundedOutputCapture, configureBoundedProcess, validateBoundedProcessRequest,
  type BoundedProcessOptions, type BoundedProcessResult } from "../src/bounded-process.js";
type Configuration = ReturnType<typeof configureBoundedProcess>;
type ProcessEnd = NonNullable<BoundedProcessResult["exit"]>;
const MAX_OVERLAP_BYTES = 64 * 1024;

const SYSTEM_CODES = new Set(["EACCES", "EAGAIN", "EBADF", "E2BIG", "EFAULT", "EINTR", "EINVAL", "EIO", "EISDIR", "ELOOP", "EMFILE", "ENAMETOOLONG", "ENFILE", "ENOENT", "ENOEXEC", "ENOMEM", "ENOSYS", "ENOTDIR", "EPERM", "EPIPE", "ESRCH", "ETXTBSY"]);

function errorCode(error: unknown): string {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return typeof code === "string" && SYSTEM_CODES.has(code) ? code : "UNKNOWN";
}

function integer(value: number, max: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && value <= max;
}

function groupState(pid: number): "absent" | "present" | "unknown" {
  try { process.kill(-pid, 0); return "present"; }
  catch (error) { return errorCode(error) === "ESRCH" ? "absent" : "unknown"; }
}

async function execute(request: ReadinessSpawnRequest, options: Configuration, queuedAt: string, queued: number): Promise<BoundedProcessResult> {
  const started = performance.now();
  const startedAt = new Date().toISOString();
  // Full values remain transient; B3 also handles partial values longer than the overlap cap.
  const overlap = Math.min(MAX_OVERLAP_BYTES, Math.max(1_024, ...Object.values(request.env).map((value) => Buffer.byteLength(value))));
  const stdout = new BoundedOutputCapture(options.output.headBytes, options.output.tailBytes, overlap);
  const stderr = new BoundedOutputCapture(options.output.headBytes, options.output.tailBytes, overlap);
  const errors: BoundedProcessResult["errors"] = [];
  const termination: BoundedProcessResult["termination"] = { reason: null, attempts: [], tree: "not-started", stdioForcedClosed: false };
  let state: BoundedProcessResult["state"] = "exited";
  let child: ChildProcess | undefined;
  let pid: number | null = null;
  let spawnedAt: string | null = null;
  let firstByteAt: string | null = null;
  let firstByte: number | null = null;
  let exit: ProcessEnd | null = null;
  let close: ProcessEnd | null = null;
  let deadline: NodeJS.Timeout | undefined;
  let forceTimer: NodeJS.Timeout | undefined;
  let closeTimer: NodeJS.Timeout | undefined;
  let groupTimer: NodeJS.Timeout | undefined;
  let finished = false;
  let done!: () => void;
  const settled = new Promise<void>((resolve) => { done = resolve; });
  const abort = () => terminate("abort", "aborted");

  const finish = () => {
    if (finished) return;
    finished = true;
    clearTimeout(deadline); clearTimeout(forceTimer); clearTimeout(closeTimer); clearInterval(groupTimer);
    options.signal?.removeEventListener("abort", abort);
    done();
  };

  const killGroup = (signal: "SIGTERM" | "SIGKILL") => {
    if (pid === null) return;
    try {
      process.kill(-pid, signal);
      termination.attempts.push({ at: new Date().toISOString(), signal, status: "sent", code: null });
    } catch (error) {
      const code = errorCode(error);
      termination.attempts.push({ at: new Date().toISOString(), signal, status: code === "ESRCH" ? "absent" : "failed", code });
      if (code !== "ESRCH") errors.push({ phase: "termination", code });
    }
  };

  const checkCompletion = () => {
    if (finished) return;
    if (pid === null) {
      if (close) finish();
      return;
    }
    const observed = groupState(pid);
    termination.tree = observed === "absent" ? "absent" : "unconfirmed";
    if (close && observed === "absent") finish();
    else if (close && termination.reason === null) terminate("descendants", "descendant-cleanup");
  };

  function terminate(reason: NonNullable<BoundedProcessResult["termination"]["reason"]>, failure: BoundedProcessResult["state"]): void {
    if (finished || termination.reason !== null) return;
    termination.reason = reason;
    if (state === "exited") state = failure;
    killGroup("SIGTERM");
    // Close alone is insufficient: descendants that closed their fds may still be alive.
    forceTimer = setTimeout(() => { killGroup("SIGKILL"); checkCompletion(); }, options.killGraceMs);
    groupTimer = setInterval(checkCompletion, 20);
    closeTimer = setTimeout(() => {
      checkCompletion();
      if (finished) return;
      errors.push({ phase: "termination", code: "TERMINATION_UNCONFIRMED" });
      termination.stdioForcedClosed = !close;
      if (!close || termination.tree !== "absent") state = "termination-unconfirmed";
      child?.stdout?.destroy(); child?.stderr?.destroy(); child?.unref();
      finish();
    }, options.killGraceMs + options.closeGraceMs);
    checkCompletion();
  }

  if (options.signal?.aborted) {
    state = "aborted";
    termination.reason = "abort";
    finish();
  } else if (process.platform !== "linux" && process.platform !== "darwin") {
    state = "unsupported-platform";
    errors.push({ phase: "spawn", code: "PROCESS_GROUPS_UNSUPPORTED" });
    finish();
  } else if (debuglog("child_process").enabled || debuglog("stream").enabled) {
    // Builtin diagnostics print envPairs or raw stream chunks before any hook can redact them.
    state = "spawn-error";
    errors.push({ phase: "spawn", code: "UNSAFE_PARENT_DIAGNOSTICS" });
    finish();
  } else {
    try {
      const env = Object.assign(Object.create(null) as NodeJS.ProcessEnv, { NODE_V8_COVERAGE: undefined }, request.env);
      // An own undefined coverage key suppresses Node's otherwise unconditional parent propagation.
      child = spawn(request.bin, [...request.args], { cwd: request.cwd, env, shell: false, detached: true, stdio: ["ignore", "pipe", "pipe"] });
      pid = child.pid ?? null;
      child.once("spawn", () => { if (!finished) spawnedAt = new Date().toISOString(); });
      child.on("error", (error) => {
        if (finished) return;
        errors.push({ phase: "spawn", code: errorCode(error) });
        state = "spawn-error";
        if (pid !== null) terminate("process-error", "spawn-error");
      });
      child.once("exit", (code, signal) => { if (!finished) exit = { at: new Date().toISOString(), code, signal }; });
      child.once("close", (code, signal) => {
        if (finished) return;
        close = { at: new Date().toISOString(), code, signal };
        checkCompletion();
      });
      for (const [stream, capture, name] of [[child.stdout!, stdout, "stdout"], [child.stderr!, stderr, "stderr"]] as const) {
        stream.on("data", (chunk: Buffer) => {
          if (finished) return;
          capture.write(chunk);
          if (firstByte === null) {
            firstByte = performance.now(); firstByteAt = new Date().toISOString();
            try { options.onFirstByte?.(); }
            catch { errors.push({ phase: "observer", code: "OBSERVER_FAILED" }); terminate("observer-error", "observer-error"); }
          }
        });
        stream.once("end", () => { if (!finished) capture.ended = true; });
        stream.on("error", (error) => {
          if (finished) return;
          capture.failed = true;
          errors.push({ phase: name, code: errorCode(error) });
          terminate("io-error", "io-error");
        });
      }
      deadline = setTimeout(() => terminate("timeout", "timed-out"), options.timeoutMs);
      options.signal?.addEventListener("abort", abort, { once: true });
      if (options.signal?.aborted) abort();
    } catch (error) {
      state = "spawn-error";
      errors.push({ phase: "spawn", code: errorCode(error) });
      finish();
    }
  }

  await settled;
  const redactionError = () => {
    if (!errors.some((error) => error.phase === "redaction")) errors.push({ phase: "redaction", code: "REDACTION_FAILED" });
    if (state === "exited") state = "redaction-error";
  };
  const output = {
    stdout: stdout.finish("stdout", options.redact, redactionError, spawnedAt !== null, termination.stdioForcedClosed),
    stderr: stderr.finish("stderr", options.redact, redactionError, spawnedAt !== null, termination.stdioForcedClosed),
  };
  const ended = performance.now();
  return {
    containment: { kind: "native-process-group", descendantOwnership: "unproven", groupObservation: termination.tree },
    state, succeeded: state === "exited" && spawnedAt !== null && exit !== null && close !== null
      && (exit as ProcessEnd).code === 0 && (exit as ProcessEnd).signal === null && (close as ProcessEnd).code === 0 && (close as ProcessEnd).signal === null
      && errors.length === 0 && termination.tree === "absent" && Object.values(output).every((stream) => stream.complete && !stream.truncated && !stream.redactionTruncated),
    pid, queuedAt, startedAt, spawnedAt, firstByteAt, endedAt: new Date().toISOString(),
    queueDurationMs: Math.max(0, started - queued), durationMs: Math.max(0, ended - started), fromFirstByteMs: firstByte === null ? null : Math.max(0, ended - firstByte),
    exit, close, errors, termination, ...output,
  };
}

/** Trusted native helpers only. Escaped descendants are outside this original-group observation. */
export function createBoundedProcessRunner(options: { concurrency?: number } = {}): { run(request: ReadinessSpawnRequest, options: BoundedProcessOptions): Promise<BoundedProcessResult> } {
  const concurrency = options.concurrency ?? 1;
  if (!integer(concurrency, 16)) throw new Error("Bounded process concurrency must be an integer between one and sixteen.");
  let active = 0;
  const pending: { start: () => void }[] = [];
  const drain = () => { while (active < concurrency && pending.length) pending.shift()!.start(); };
  return {
    async run(request, processOptions) {
      validateBoundedProcessRequest(request);
      const configuration = configureBoundedProcess(processOptions);
      const queuedAt = new Date().toISOString();
      const queued = performance.now();
      return new Promise<BoundedProcessResult>((resolve, reject) => {
        const cancelQueued = () => {
          const index = pending.indexOf(job);
          if (index === -1) return;
          pending.splice(index, 1);
          configuration.signal?.removeEventListener("abort", cancelQueued);
          void execute(request, configuration, queuedAt, queued).then(resolve, reject);
        };
        const job = { start: () => {
          configuration.signal?.removeEventListener("abort", cancelQueued);
          active++;
          void execute(request, configuration, queuedAt, queued).then(resolve, reject).finally(() => { active--; drain(); });
        } };
        pending.push(job);
        configuration.signal?.addEventListener("abort", cancelQueued, { once: true });
        if (configuration.signal?.aborted) cancelQueued();
        drain();
      });
    },
  };
}
