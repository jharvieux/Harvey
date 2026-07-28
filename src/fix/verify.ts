// Verification contract: a fix is "verified" only if the client's own checks
// pass AND the detector that found the problem no longer fires — both actually
// executed, output captured. See docs/design/fix-implementation.md §2.
//
// The harness runs commands itself; a subagent *claiming* green is worth nothing.

import { spawnSync } from "node:child_process";

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

export function runCommand(command: string, cwd: string, timeoutMs = DEFAULT_COMMAND_TIMEOUT_MS): CommandRun {
  const start = Date.now();
  const res = spawnSync(command, { cwd, shell: true, encoding: "utf8", maxBuffer: 32 * 1024 * 1024, timeout: timeoutMs });
  const durationMs = Date.now() - start;
  const timedOut = res.error !== undefined && (res.error as NodeJS.ErrnoException).code === "ETIMEDOUT";
  const combined = `${res.stdout ?? ""}${res.stderr ?? ""}${timedOut ? `\n[harvey] killed after ${timeoutMs}ms — command exceeded the client-check timeout` : ""}`;
  const exitCode = res.status ?? (res.error ? 1 : 0);
  return { command, cwd, exitCode, durationMs, outputTail: scrubSecrets(tail(combined, 50)) };
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
