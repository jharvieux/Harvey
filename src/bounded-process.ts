import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
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
