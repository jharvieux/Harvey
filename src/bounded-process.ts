import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import { debuglog } from "node:util";
import type { ReadinessSpawnRequest } from "./audit-readiness-authority.js";

export type BoundedProcessRedactor = (text: string, context: {
  stream: "stdout" | "stderr" | "error";
  boundary: "head" | "tail" | "whole";
  /** Transient context outside the retained excerpt; never part of the result. */
  before: string;
  after: string;
}) => string;

export interface BoundedProcessOptions {
  timeoutMs: number;
  killGraceMs?: number;
  closeGraceMs?: number;
  output?: { headBytes: number; tailBytes: number };
  /** Must also redact partial values at a head/tail cutoff. Called before evidence leaves this module. */
  redact: BoundedProcessRedactor;
  signal?: AbortSignal;
  onFirstByte?: () => void;
}

interface ProcessEnd {
  at: string;
  code: number | null;
  signal: NodeJS.Signals | null;
}

/** Native process groups describe the original group only, never descendant ownership. */
export type ReadinessProcessContainment =
  | { kind: "native-process-group"; descendantOwnership: "unproven"; groupObservation: "not-started" | "absent" | "unconfirmed" }
  | { kind: "unavailable"; reasonCode: string }
  | {
    kind: "docker-pid-namespace";
    imageId: string;
    containerId: string | null;
    leaseName: string | null;
    runtimeVersion: string;
    apiVersion: string;
    namespace: "not-started" | "terminated" | "unconfirmed";
    targetWork: "not-started" | "begun" | "unknown";
    terminalObservation: { at: string; running: false; pid: 0 } | null;
    metadata: "verified" | "unavailable";
    cleanup: "not-required" | "removed" | "retained";
    /** The fixed restrictions below were compared with this exact container before start. */
    isolationVerified: boolean;
    isolation: {
      privatePidNamespace: true; network: "none"; noNewPrivileges: true; capDrop: "ALL";
      observerCapabilities: ["SETUID", "SETGID"]; targetUid: number; targetGid: number;
      mountScope: "disposable-root-only"; rootfs: "private-writable-overlay";
    };
    targetIdentity: { uid: number; gid: number; capEff: "0000000000000000"; noNewPrivileges: true } | null;
    observerNodeVersion: string | null;
  };

export interface BoundedProcessOutput {
  /** Byte count and SHA-256 cover every raw byte drained, including omitted bytes. */
  bytes: number;
  sha256: string;
  head: string;
  tail: string;
  /** Source byte spans retained before redaction, without overlap. */
  headBytes: number;
  tailBytes: number;
  omittedBytes: number;
  truncated: boolean;
  /** Redaction can expand text; the returned excerpts still obey their byte limits. */
  redactionTruncated: boolean;
  /** False when any part of the stream could not be drained to its natural end. */
  complete: boolean;
}

export interface BoundedProcessResult {
  state: "exited" | "timed-out" | "aborted" | "spawn-error" | "io-error" | "observer-error" | "redaction-error" | "descendant-cleanup" | "termination-unconfirmed" | "unsupported-platform" | "containment-unavailable";
  containment: ReadinessProcessContainment;
  succeeded: boolean;
  pid: number | null;
  queuedAt: string;
  startedAt: string;
  spawnedAt: string | null;
  firstByteAt: string | null;
  endedAt: string;
  queueDurationMs: number;
  durationMs: number;
  fromFirstByteMs: number | null;
  exit: ProcessEnd | null;
  close: ProcessEnd | null;
  /** OS codes only: child messages, argv, paths, and environment values are never diagnostics. */
  errors: { phase: "spawn" | "stdout" | "stderr" | "observer" | "redaction" | "termination"; code: string }[];
  termination: {
    reason: "timeout" | "abort" | "process-error" | "io-error" | "observer-error" | "descendants" | null;
    attempts: { at: string; signal: "SIGTERM" | "SIGKILL"; status: "sent" | "absent" | "failed"; code: string | null }[];
    /** Native helper: original group only. Owned descendant absence requires containment evidence. */
    tree: "not-started" | "absent" | "unconfirmed";
    stdioForcedClosed: boolean;
  };
  stdout: BoundedProcessOutput;
  stderr: BoundedProcessOutput;
}

interface Configuration extends BoundedProcessOptions {
  killGraceMs: number;
  closeGraceMs: number;
  output: { headBytes: number; tailBytes: number };
}

const DEFAULT_EXCERPT_BYTES = 4 * 1024;
const MAX_EXCERPT_BYTES = 1024 * 1024;
const MAX_OVERLAP_BYTES = 64 * 1024;
const SYSTEM_CODES = new Set(["EACCES", "EAGAIN", "EBADF", "E2BIG", "EFAULT", "EINTR", "EINVAL", "EIO", "EISDIR", "ELOOP", "EMFILE", "ENAMETOOLONG", "ENFILE", "ENOENT", "ENOEXEC", "ENOMEM", "ENOSYS", "ENOTDIR", "EPERM", "EPIPE", "ESRCH", "ETXTBSY"]);

function errorCode(error: unknown): string {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return typeof code === "string" && SYSTEM_CODES.has(code) ? code : "UNKNOWN";
}

function integer(value: number, max: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && value <= max;
}

export function configureBoundedProcess(options: BoundedProcessOptions): Configuration {
  const killGraceMs = options.killGraceMs ?? 250;
  const closeGraceMs = options.closeGraceMs ?? 1_000;
  const output = options.output ?? { headBytes: DEFAULT_EXCERPT_BYTES, tailBytes: DEFAULT_EXCERPT_BYTES };
  if (!integer(options.timeoutMs, 2_147_483_647) || !integer(killGraceMs, 60_000) || !integer(closeGraceMs, 60_000)) {
    throw new Error("Bounded process requires a positive finite timeout and bounded termination grace periods.");
  }
  if (!integer(output.headBytes, MAX_EXCERPT_BYTES) || !integer(output.tailBytes, MAX_EXCERPT_BYTES)) {
    throw new Error("Bounded process requires positive excerpt limits of at most one MiB each.");
  }
  if (typeof options.redact !== "function" || (options.onFirstByte !== undefined && typeof options.onFirstByte !== "function")) {
    throw new Error("Bounded process requires an explicit output redactor and a valid observer.");
  }
  return { ...options, killGraceMs, closeGraceMs, output: { ...output } };
}

export function validateBoundedProcessRequest(request: ReadinessSpawnRequest): void {
  if (request.shell !== false || typeof request.bin !== "string" || request.bin === "" || request.bin.includes("\0")
    || !Array.isArray(request.args) || request.args.some((arg) => typeof arg !== "string" || arg.includes("\0"))
    || typeof request.cwd !== "string" || !isAbsolute(request.cwd) || request.cwd.includes("\0")
    || !request.env || typeof request.env !== "object" || Object.entries(request.env).some(([key, value]) => key.includes("=") || key.includes("\0") || typeof value !== "string" || value.includes("\0"))) {
    throw new Error("Bounded process requires the tokenized command, absolute cwd, shell:false, and explicit environment from readiness admission.");
  }
}

/** Align a byte cutoff without introducing a replacement character inside valid UTF-8. */
function headEnd(bytes: Buffer, end: number): number {
  while (end > 0 && end < bytes.length && (bytes[end]! & 0xc0) === 0x80) end--;
  return end;
}

function tailStart(bytes: Buffer, start: number): number {
  while (start < bytes.length && (bytes[start]! & 0xc0) === 0x80) start++;
  return start;
}

function boundedText(text: string, limit: number, boundary: "head" | "tail"): { text: string; truncated: boolean } {
  const bytes = Buffer.from(text);
  if (bytes.length <= limit) return { text, truncated: false };
  return { text: (boundary === "head" ? bytes.subarray(0, headEnd(bytes, limit)) : bytes.subarray(tailStart(bytes, bytes.length - limit))).toString("utf8"), truncated: true };
}

export class BoundedOutputCapture {
  readonly hash = createHash("sha256");
  bytes = 0;
  prefix: Buffer = Buffer.alloc(0);
  suffix: Buffer = Buffer.alloc(0);
  ended = false;
  failed = false;

  constructor(readonly headLimit: number, readonly tailLimit: number, readonly overlap: number) {}

  write(chunk: Buffer): void {
    this.hash.update(chunk);
    this.bytes += chunk.length;
    const prefixRoom = this.headLimit + this.overlap - this.prefix.length;
    if (prefixRoom > 0) this.prefix = Buffer.concat([this.prefix, chunk.subarray(0, prefixRoom)]);
    const suffixLimit = this.tailLimit + this.overlap;
    this.suffix = chunk.length >= suffixLimit
      ? Buffer.from(chunk.subarray(-suffixLimit))
      : Buffer.concat([this.suffix.subarray(Math.max(0, this.suffix.length + chunk.length - suffixLimit)), chunk]);
  }

  finish(stream: "stdout" | "stderr", redact: BoundedProcessRedactor, onRedactionError: () => void, spawned: boolean, forced: boolean): BoundedProcessOutput {
    const end = headEnd(this.prefix, Math.min(this.headLimit, this.bytes));
    const suffixOffset = this.bytes - this.suffix.length;
    const start = tailStart(this.suffix, Math.max(end, this.bytes - this.tailLimit) - suffixOffset);
    const head = this.prefix.subarray(0, end);
    const tail = this.suffix.subarray(start);
    const headBytes = head.length;
    const tailBytes = tail.length;
    const omittedBytes = this.bytes - headBytes - tailBytes;
    const sanitize = (raw: Buffer, boundary: "head" | "tail", before: string, after: string) => {
      if (raw.length === 0) return { text: "", truncated: false };
      try {
        const text = redact(raw.toString("utf8"), { stream, boundary: raw.length === this.bytes ? "whole" : boundary, before, after });
        if (typeof text !== "string") throw new Error("invalid redactor output");
        return boundedText(text, boundary === "head" ? this.headLimit : this.tailLimit, boundary);
      } catch {
        onRedactionError();
        return { text: "", truncated: false };
      }
    };
    const cleanHead = sanitize(head, "head", "", this.prefix.subarray(end, headEnd(this.prefix, this.prefix.length)).toString("utf8"));
    const cleanTail = sanitize(tail, "tail", this.suffix.subarray(tailStart(this.suffix, 0), start).toString("utf8"), "");
    // Drop all raw excerpt references before returning the serializable result.
    this.prefix = Buffer.alloc(0);
    this.suffix = Buffer.alloc(0);
    return {
      bytes: this.bytes, sha256: this.hash.digest("hex"), head: cleanHead.text, tail: cleanTail.text,
      headBytes, tailBytes, omittedBytes, truncated: omittedBytes > 0,
      redactionTruncated: cleanHead.truncated || cleanTail.truncated,
      complete: spawned && this.ended && !this.failed && !forced,
    };
  }
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
  } else if (debuglog("child_process").enabled) {
    // Node's builtin child_process debug logger prints envPairs before any hook can redact them.
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
