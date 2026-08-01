// #1695 — the probe's own failing direction.
//
// A setup file that is not registered, or a heartbeat that is not running, produces exactly what a
// healthy run produces: nothing. So this blocks the loop for real, in the worker the probe is
// supposed to be watching, and requires it to have SEEN the block and named this test. If
// `setupFiles` loses the entry, the import below is the only thing that loads the module, its
// `beforeEach` never registers, and the attribution assertion goes red rather than silent.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { describeBlock, worstBlock } from "./vitest-event-loop-probe.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function blockLoopFor(ms: number): void {
  const until = performance.now() + ms;
  while (performance.now() < until) {
    /* deliberately synchronous: this is the shape execFileSync imposes on a worker */
  }
}

// One heartbeat period has to elapse AFTER the block for the interval to fire and observe the gap.
const settle = () => new Promise((r) => setTimeout(r, 400));

describe("the event-loop probe attributes a blocking window (#1695)", () => {
  it("sees a real synchronous block in this worker and names the test that caused it", async () => {
    const before = worstBlock().ms;
    blockLoopFor(700);
    await settle();

    const after = worstBlock();
    expect(after.ms, `the probe saw no block larger than ${before}ms after this test blocked its worker for 700ms — either setupFiles no longer registers src/vitest-event-loop-probe.ts, or its heartbeat is not running`).toBeGreaterThan(500);
    expect(after.during).toContain("vitest-event-loop-probe.test.ts");
    expect(after.during).toContain("names the test that caused it");
  });

  it("states the block as a fraction of the 60s ack window, which is the number #1120's constraint is about", () => {
    expect(describeBlock(30_000, "x")).toContain("50% of vitest's 60000ms RPC-ack window");
    expect(describeBlock(61_000, "src/cli/run-audit.test.ts > y")).toContain("102%");
    expect(describeBlock(61_000, "src/cli/run-audit.test.ts > y")).toContain("during: src/cli/run-audit.test.ts > y");
  });

  it("says how many tests a window spanned — the fact that turns 'which test' into 'which file'", () => {
    // MEASURED 2026-08-01: the worst window in all three heavy runs spanned a whole file of
    // synchronous tests, none of which individually came near 60s. A report that named only a test
    // would send the reader after the wrong thing.
    expect(describeBlock(42_246, "src/fix/detector-rerun.test.ts > (between tests)", 20)).toContain("spanning 20 tests that never yielded the loop");
    // One test is not a span, and saying "spanning 1 tests" would be noise on the common case.
    expect(describeBlock(8_000, "f > t", 1)).not.toContain("spanning");
    expect(describeBlock(8_000, "f > t")).not.toContain("spanning");
  });

  it("is REGISTERED, not merely importable — a setup file nobody loads reports the same nothing as a clean run", () => {
    expect(readFileSync(join(REPO_ROOT, "vitest.config.ts"), "utf8")).toContain('setupFiles: ["./src/vitest-event-loop-probe.ts"]');
  });

  it("prints its attribution to a stream a dying worker has already flushed", () => {
    // stderr, not console.log: the run this exists for ends with the worker's channel starved, and
    // #1768 measured that a queued pipe write can be discarded on exit. `process.stderr.write` is
    // the same call src/cli/sync-stdio.ts makes synchronous for exactly that reason.
    const source = readFileSync(join(REPO_ROOT, "src", "vitest-event-loop-probe.ts"), "utf8");
    expect(source).toContain("process.stderr.write(`harvey-eventloop BLOCKED");
    expect(source).not.toContain("console.log");
  });

  it("REPORTS: a real vitest run over a blocking test emits the attribution where a human reads it", () => {
    // The in-process assertions above read the counter; nothing there proves a human ever SEES the
    // line. This drives a real child run of the blocking test with a floor it will clear, and reads
    // the same combined stream a CI log is.
    const child = spawnSync(
      "node_modules/.bin/vitest",
      ["run", "src/vitest-event-loop-probe.test.ts", "-t", "names the test that caused it"],
      { cwd: REPO_ROOT, encoding: "utf8", env: { ...process.env, HARVEY_EVENTLOOP_FLOOR_MS: "500" }, timeout: 120_000 },
    );
    const out = `${child.stdout ?? ""}${child.stderr ?? ""}`;
    expect(out, "a real run of a test that blocks its worker for 700ms printed no harvey-eventloop line").toContain("harvey-eventloop BLOCKED");
    expect(out).toContain("vitest-event-loop-probe.test.ts > sees a real synchronous block");
    // The floor is a floor: the same run must NOT narrate every scheduling hiccup, or the signal
    // this exists to surface arrives buried.
    expect(out.split("harvey-eventloop BLOCKED").length - 1).toBeLessThan(5);
  });
});
