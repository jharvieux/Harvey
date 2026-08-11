// Verification contract: a fix is "verified" only if the client's own checks
// pass AND the detector that found the problem no longer fires — both actually
// executed, output captured. See docs/design/fix-implementation.md §2.
//
// The harness runs commands itself; a subagent *claiming* green is worth nothing.

import { spawn } from "node:child_process";

export interface CommandRun {
  command: string;
  cwd: string;
  exitCode: number;
  durationMs: number;
  outputTail: string; // last ~50 lines, secrets-scrubbed
  skipped?: "needs-ci" | "pre-existing-failure-on-baseline";
}

export interface DetectorRun {
  detectorId: string;
  fired: boolean;
  output: string;
  // §2.3 honesty: set when the detector for this finding could NOT be re-run (no resolver for its
  // taxonomy, the external engine wasn't available, …). An unrun detector is NOT a clean detector —
  // computeGreen treats a notRun `detectorAfter` as not-green, so a caller filling in `fired: false`
  // for something that never executed cannot manufacture a false green (the repo's signature defect).
  notRun?: string;
}

export interface VerificationEvidence {
  findingId: string;
  worktreeCommit: string; // HEAD after the fix
  baselineCommit: string; // pinned engagement commit
  detectorBefore: DetectorRun; // from the original scan (fired: true)
  detectorAfter: DetectorRun; // must be fired: false
  clientChecks: CommandRun[]; // every discovered command, run or explicitly skipped
  newTestAdded?: string; // path of regression test, if the plan called for one
  green: boolean;
  attempts: number;
}

// Redact anything that looks like a credential before output goes into evidence
// or a PR body. Conservative on purpose: over-redacting a log line is harmless.
const SECRET_PATTERNS: readonly RegExp[] = [
  /gh[pousr]_[A-Za-z0-9]{16,}/g,
  /github_pat_[A-Za-z0-9_]{20,}/g,
  /sk-[A-Za-z0-9]{16,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // JWTs
  /(bearer|token|api[_-]?key|password|secret)(["'\s:=]+)([A-Za-z0-9._\-/+]{8,})/gi,
];

export function scrubSecrets(text: string): string {
  let out = text;
  for (const re of SECRET_PATTERNS) {
    out = out.replace(re, (m, p1, p2) => (p2 !== undefined ? `${p1}${p2}[REDACTED]` : "[REDACTED]"));
  }
  return out;
}

function tail(text: string, lines: number): string {
  const all = text.split("\n");
  return all.slice(Math.max(0, all.length - lines)).join("\n");
}

// Discover the client's verify commands (§2.1 step 1). package.json scripts in
// preference order: verify > check/ci > the union of typecheck/tsc, lint, test.
// CI-only steps (from workflow parsing) are passed in already-resolved.
export function discoverVerifyCommands(
  scripts: Record<string, string> | undefined,
  runner = "pnpm",
  extraCiSteps: string[] = [],
): string[] {
  const has = (name: string) => scripts !== undefined && typeof scripts[name] === "string";
  const run = (name: string) => `${runner} run ${name}`;

  let commands: string[];
  if (has("verify")) commands = [run("verify")];
  else if (has("check")) commands = [run("check")];
  else if (has("ci")) commands = [run("ci")];
  else {
    commands = [];
    if (has("typecheck")) commands.push(run("typecheck"));
    else if (has("tsc")) commands.push(run("tsc"));
    if (has("lint")) commands.push(run("lint"));
    if (has("test")) commands.push(run("test"));
  }
  for (const step of extraCiSteps) if (!commands.includes(step)) commands.push(step);
  return commands;
}

// A client suite that never terminates would hang the whole ingest, so every run is bounded. A
// killed command reports a non-zero exit and says WHY in its own output tail — never a silent 0.
const DEFAULT_COMMAND_TIMEOUT_MS = 15 * 60 * 1000;
const MAX_CAPTURED_BYTES = 32 * 1024 * 1024;

// How many client commands were ever spawned AT ONCE, measured at the spawn boundary rather than at
// the §4 semaphore. The two are different facts and read identically in an artifact: a worker can
// occupy the maxClientChecks gate while doing git work, so `peakClientChecks` can reach the cap with
// a spawnSync runner that never overlaps a single client suite (MEASURED 2026-07-31 — the six-
// component CLI test still reported peakClientChecks 2 with runCommand reverted to spawnSync). This
// counter is what goes red in that case.
let liveClientCommands = 0;
let peakClientCommands = 0;
export const observedClientCommandConcurrency = (): number => peakClientCommands;

// #1464: spawn, not spawnSync. This is the client's own suite — minutes of wall clock — and it is
// the scarce resource the §4 maxClientChecks semaphore bounds. A spawnSync here blocks the event
// loop for its whole duration, so two workers holding that semaphore could never actually overlap
// and the cap was enforced over a workload that was serial anyway.
export function runCommand(command: string, cwd: string, timeoutMs = DEFAULT_COMMAND_TIMEOUT_MS): Promise<CommandRun> {
  const start = Date.now();
  liveClientCommands++;
  peakClientCommands = Math.max(peakClientCommands, liveClientCommands);
  return new Promise<CommandRun>((resolve) => {
    // Keep the suite in the caller's foreground process group so Ctrl-C reaches it naturally.
    // The timeout does not wait for `close`: a self-detaching descendant can leave the wrapper's
    // group while retaining its stdout/stderr fds, and `close` then waits until that descendant
    // exits. The timer below stops waiting, closes Harvey's pipe readers, and settles the evidence
    // row itself, settling the evidence at the timer boundary (#1797).
    const child = spawn(command, { cwd, shell: true });
    let captured = "";
    let timedOut = false;
    let settled = false;
    // setEncoding, never `chunk.toString("utf8")` per chunk (#1759): that decodes THAT CHUNK in
    // isolation, so a multi-byte character straddling a chunk boundary decodes to U+FFFD on both
    // sides — real risk here, since a client's own CI output is exactly the kind of text this
    // captures. setEncoding installs a StringDecoder per stream that holds an incomplete trailing
    // sequence back until the next chunk completes it.
    const capture = (chunk: string) => {
      if (captured.length < MAX_CAPTURED_BYTES) captured += chunk;
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", capture);
    child.stderr.on("data", capture);
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGKILL");
      } catch {
        // The timeout result stays truthful: Harvey stops waiting even when the OS refuses the kill.
      }
      child.stdout.destroy();
      child.stderr.destroy();
      child.unref();
      finish(1);
    }, timeoutMs);
    const finish = (exitCode: number) => {
      if (settled) return;
      settled = true;
      liveClientCommands--;
      clearTimeout(timer);
      const combined = timedOut
        ? `${captured}\n[harvey] stopped waiting after ${timeoutMs}ms — command exceeded the client-check timeout`
        : captured;
      resolve({ command, cwd, exitCode, durationMs: Date.now() - start, outputTail: scrubSecrets(tail(combined, 50)) });
    };
    child.on("error", (err) => {
      capture(err.message);
      finish(1);
    });
    child.on("close", (code, signal) => finish(code ?? (signal !== null ? 1 : 0)));
  });
}

// The DETECTOR half of the §2 contract on its own: the finding's detector re-ran, and it is clean.
// Split out of computeGreen because a caller that scores only this half must SAY so rather than
// passing an empty clientChecks array and collecting a green it did not earn (see computeGreen).
export function detectorHalfClean(detectorAfter: DetectorRun): boolean {
  if (detectorAfter.notRun !== undefined) return false; // fail loud: an unrun detector is not clean
  return !detectorAfter.fired;
}

// A fix is green iff the detector no longer fires AND no client check newly
// fails. Skipped checks (needs-ci, pre-existing baseline failures) don't count
// against green — but they're always visible in the evidence (§2.2).
//
// #1272: an EMPTY clientChecks is not green. `[].every(...)` is vacuously true, so for as long as
// the only production assembler hardcoded `clientChecks: []` the client half of this decision did
// not merely go unrun — it silently PASSED, and a fix that broke the client's own suite could be
// reported verified. The contract says both halves must have actually executed; nothing discovered
// and nothing run is a reason to withhold green, not to grant it.
export function computeGreen(ev: Pick<VerificationEvidence, "detectorAfter" | "clientChecks">): boolean {
  if (!detectorHalfClean(ev.detectorAfter)) return false;
  if (ev.clientChecks.length === 0) return false;
  return ev.clientChecks.every((c) => c.skipped !== undefined || c.exitCode === 0);
}
