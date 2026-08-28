// #1695 — attribute the RPC-ack starvation instead of inferring it.
//
// The flake: a heavy test file drives a child process through synchronous execFileSync, which
// blocks its vitest worker's event loop. A blocked worker never services the birpc ack for the
// `onTaskUpdate` it already sent, so once a single blocking window outlasts vitest's hardcoded 60s
// (`DEFAULT_TIMEOUT = 6e4`) the run reports `[vitest-worker]: Timeout calling "onTaskUpdate"` as an
// Unhandled Error and exits 1 with ZERO failing tests.
//
// MEASURED 2026-07-31 (#1695): 3 of 12 local runs, 1 of 111 CI shard jobs. That 12-run sample could
// not say WHICH file starved — vitest attributes the error to no file, and no reported TEST reached
// 60s (max 35.6s), so the starving window is not one test and guessing which it was is exactly the
// move this repo keeps catching itself making.
//
// What this measures: the longest UNINTERRUPTED gap in the worker's own event loop, and what was
// running when it happened. A 100ms unref'd heartbeat stays unscheduled while the loop is blocked, so the
// gap observed on the tick AFTER a block is that block's duration. That is the same quantity
// vitest's ack window is racing, measured from inside the worker that would lose the race — and it
// covers module load, hooks and teardown, which per-test durations do not.
//
// It reports on EVERY run rather than behind a flag, because the thing it exists to attribute
// happens ~1 in 100 CI jobs: a probe nobody remembered to enable is indistinguishable from one that
// has been switched off (#1287).

import { afterAll, afterEach, beforeEach } from "vitest";

const HEARTBEAT_MS = 100;

// vitest 3.2.6's worker→main ack window. Reported as a fraction of it so a number in the log is
// legible without knowing the constant, and so a block that is merely CLOSE still says so — the
// standing constraint (#1120) is "no single blocking window may approach 60s", not "under 60s".
const ACK_WINDOW_MS = 60_000;
export const MAX_ENFORCED_BLOCK_MS = ACK_WINDOW_MS * 0.25;

const ENFORCED_FILE_SUFFIXES = [
  "src/cli/validate-reasons.test.ts",
  "src/cli/validate-acceptance.test.ts",
  "src/cli/validate-test-only-exports.test.ts",
  "src/cli/brief-freshness.test.ts",
  "src/cli/fix-verify-cli.test.ts",
  "src/fix/detector-rerun.test.ts",
];

// Below this a gap is scheduling noise on a loaded machine, and printing it would bury the signal.
// Overridable so the probe's own guard can exercise the real path in under a second rather than
// blocking a worker for ten.
const REPORT_FLOOR_MS = Number(process.env.HARVEY_EVENTLOOP_FLOOR_MS ?? 10_000);

const IDLE = "(no test running — module load, a hook, or between files)";

let last = performance.now();
let worstMs = 0;
let worstDuring = IDLE;
let current = IDLE;
let currentFile = "";
const worstByFile = new Map<string, { ms: number; during: string }>();
// MEASURED 2026-08-01, three heavy runs: the worst window was 26.7s / 28.6s / 42.2s and in all
// three it spanned a WHOLE FILE of back-to-back synchronous tests, not one test. The heartbeat
// stays unscheduled while the loop is blocked, so a file whose tests never await runs as ONE window; that
// is why #1695's 12-run sample found no test over 35.6s and still saw the 60s ack blow. Counting
// the tests a window spans is what turns "which test" into the right question, "which FILE".
let testsThisWindow = 0;

// REASON: src/vitest-event-loop-probe.ts's exports have no production caller and are listed by the test-only-exports gate, because its ONLY caller is `setupFiles` in vitest.config.ts — a test-runner entry, which knip.production.json deliberately does not treat as production.
// KIND: empirical
// PROVENANCE: MEASURED 2026-08-28 — `pnpm test-only-exports --list` reports `file   src/vitest-event-loop-probe.ts — every export unreachable: MAX_ENFORCED_BLOCK_MS, worstBlock, describeBlock, enforcedBlockLimit, assertBlockBelow`, i.e. it flags the FILE as unreachable rather than the symbols as unused, and the path is in test-only-exports.baseline.json's `files` array. describeBlock, enforcedBlockLimit and assertBlockBelow have in-file test-runner callers; the exports let the guard prove, from inside the worker, that setupFiles still loads this module — the one fact no output check can establish when the module is absent. The falsifier below carried NO `--list` until 2026-08-01, and the gate enumerates its rows only under that flag: the blocker held, the grep matched nothing, and reasons-drift read exit 0 as "blocker gone" (run 30694879524). Re-exercised both directions after the fix: exit 1 as committed, exit 0 with the probe imported by a production module so the row leaves the gate's list. The `case` on the banner is the other half of the repair — a crashed gate now exits 127 (unverifiable) instead of printing nothing and reading as "gone" — and the match is on the `--list` row's own `— every export unreachable` suffix, because the GATE-FAIL "STALE baseline rows" block prints the bare path and would otherwise report the blocker as holding at the exact moment it lifted.
// FALSIFIER: test -f knip.production.json || exit 127; test -f src/vitest-event-loop-probe.ts || exit 127; o=$(pnpm test-only-exports --list 2>&1); case "$o" in *"test-only-exports gate (#1307)"*) ;; *) exit 127;; esac; case "$o" in *"src/vitest-event-loop-probe.ts — every export unreachable"*) exit 1;; *) exit 0;; esac
// TOUCHES: src/vitest-event-loop-probe.ts vitest.config.ts knip.production.json

/** The worst block this worker has seen so far, and what was running. Read by the probe's guard. */
export function worstBlock(): { ms: number; during: string } {
  return { ms: worstMs, during: worstDuring };
}

const heartbeat = setInterval(() => {
  const now = performance.now();
  const gap = now - last - HEARTBEAT_MS;
  last = now;
  const spanned = testsThisWindow;
  testsThisWindow = 0;
  if (gap > worstMs) {
    worstMs = gap;
    worstDuring = current;
  }
  if (currentFile !== "") {
    const fileWorst = worstByFile.get(currentFile);
    if (fileWorst === undefined || gap > fileWorst.ms) worstByFile.set(currentFile, { ms: gap, during: current });
  }
  // Printed the moment it is observed, not only at exit: a worker that dies after starving its RPC
  // channel never reaches the exit handler, and that is precisely the run whose attribution matters.
  if (gap >= REPORT_FLOOR_MS) {
    process.stderr.write(`harvey-eventloop BLOCKED ${describeBlock(gap, current, spanned)}\n`);
  }
}, HEARTBEAT_MS);
heartbeat.unref();

export function describeBlock(ms: number, during: string, spannedTests = 0): string {
  const span = spannedTests > 1 ? ` spanning ${spannedTests} tests that never yielded the loop` : "";
  return `${Math.round(ms)}ms (${Math.round((ms / ACK_WINDOW_MS) * 100)}% of vitest's ${ACK_WINDOW_MS}ms RPC-ack window)${span} during: ${during}`;
}

export function enforcedBlockLimit(file: string): number | undefined {
  const normalized = file.replaceAll("\\", "/");
  return ENFORCED_FILE_SUFFIXES.some((suffix) => normalized.endsWith(suffix)) ? MAX_ENFORCED_BLOCK_MS : undefined;
}

export function assertBlockBelow(ms: number, during: string, file: string, limitMs = MAX_ENFORCED_BLOCK_MS): void {
  if (ms >= limitMs) {
    throw new Error(`${file} exceeded its ${limitMs}ms event-loop budget: ${describeBlock(ms, during)}`);
  }
}

beforeEach((ctx) => {
  currentFile = ctx.task.file?.name ?? currentFile;
  current = `${currentFile} > ${ctx.task.name}`;
  testsThisWindow++;
});
// Keep the FILE in the attribution. Before this the between-tests state named nothing, and the
// worst window in every measured run landed in exactly that state — so the probe reproduced #1695's
// own "vitest attributes the error to no file" instead of answering it.
afterEach(() => {
  current = `${currentFile || "?"} > (between tests — a hook, a teardown, or a synchronous run that never yielded)`;
});

// Freeze #1813's measured population below 25% of Vitest's 60s worker-RPC acknowledgement
// window. The short await lets the heartbeat observe a block ending in the last test without
// inserting a yield between tests, which would hide the file-spanning synchronous failure mode.
afterAll(async () => {
  const file = currentFile;
  const limit = enforcedBlockLimit(file);
  if (limit === undefined) return;
  await new Promise((resolveWait) => setTimeout(resolveWait, HEARTBEAT_MS + 50));
  const block = worstByFile.get(file) ?? { ms: 0, during: `${file} > (no observed block)` };
  process.stderr.write(`harvey-eventloop ENFORCED max ${describeBlock(block.ms, block.during)} limit: <${limit}ms file: ${file}\n`);
  assertBlockBelow(block.ms, block.during, file, limit);
});

// No process-exit summary on purpose. The ENFORCED checkpoint above runs in Vitest's observable
// afterAll lifecycle. TRIED 2026-08-01: a `process.on("exit")` writer in a vitest
// worker produced no line in a real child run (`spawnSync` over this file, stdout+stderr both
// captured) while the live line above appeared every time — vitest tears the worker's streams down
// first. A branch nothing can observe is worse than no branch, and it would have added nothing
// anyway: every block past the floor has already printed itself, which is also the only form that
// survives the worker dying mid-run.
