// #1758 — a CLI's LAST line before `process.exit()` is the one most likely to be thrown away.
//
// Node writes to a FILE synchronously and to a PIPE asynchronously. `process.exit()` terminates
// without draining the async queue, so when stdout is a pipe — which is every CI step, every
// `| tee`, every `spawn(..., stdio: "pipe")` — whatever is still buffered is discarded. The verdict
// line of a gate and the refusal banner of an export sit immediately before their `process.exit(1)`,
// which is the worst position in the program to occupy.
//
// That is not a cosmetic loss: this repo's whole posture is that a run which could not do its job
// must SAY so, and an exit 1 whose reason was discarded is indistinguishable from a crash.
//
// MEASURED 2026-07-31, spawned with `stdio: ["ignore", "pipe", "pipe"]` exactly as the test harness
// and CI do — 20000 filler lines, then one marker line, then `process.exit(1)`:
//   without this module   marker lost in 5/5 runs
//   with this module      marker lost in 0/5 runs
// `src/cli/sync-stdio.test.ts` holds both directions, so deleting the body below turns it red.
//
// Import it for effect, FIRST, before anything can write:  import "./sync-stdio.js";
//
// `_handle` is internal, hence the feature test rather than a bare call: when a stream is already
// closed, or is something without a libuv handle, there is nothing to switch and nothing to fix.
// Node itself uses setBlocking for TTY and file descriptors — this extends the same treatment to
// pipes, at the cost of backpressure we would rather pay than lose the verdict.
for (const stream of [process.stdout, process.stderr]) {
  const handle = (stream as unknown as { _handle?: { setBlocking?: (blocking: boolean) => void } })._handle;
  handle?.setBlocking?.(true);
}
