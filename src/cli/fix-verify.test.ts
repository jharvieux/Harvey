// #1357 — the fix-verification gate's paid-rescan gate. #1013's operator decision: the base
// engagement includes ONE re-audit/rescan at no extra charge; additional rescans are a paid add-on
// (50% of the original audit price), both within 30 days of the original audit. #1013's own sweep
// comment named this as unbuilt — "the gate carries no tier flag today" — and the issue closed on
// the commercial terms alone without the code ever landing (#1357).
//
// writebackGate is a free function (no CLI parsing, no I/O), tested directly here rather than by
// spawning src/cli/fix-verify.ts as a child process — mirrors how #824's paid-tier gate for
// file-findings.ts is tested at the library level (src/trackers/findings-to-tickets.test.ts), not
// through that CLI's own wrapper (which, like this one, has no dedicated test file).

import { describe, expect, it } from "vitest";
import { writebackGate } from "./fix-verify.js";

describe("writebackGate — #1357 paid-rescan add-on", () => {
  it("allows write-back on the FIRST verification pass (no --prior) even without --paid — the included rescan", () => {
    const gate = writebackGate(false, false, 3);
    expect(gate.allowed).toBe(true);
    expect(gate.message).toBeUndefined();
  });

  it("withholds write-back on an ADDITIONAL rescan (--prior supplied) without --paid, and discloses why", () => {
    const gate = writebackGate(true, false, 2);
    expect(gate.allowed).toBe(false);
    expect(gate.message).toContain("ADDITIONAL rescan");
    expect(gate.message).toContain("paid add-on");
    expect(gate.message).toContain("2 ticket write-back action(s)");
  });

  it("allows write-back on an additional rescan once --paid is supplied", () => {
    const gate = writebackGate(true, true, 2);
    expect(gate.allowed).toBe(true);
    expect(gate.message).toBeUndefined();
  });

  it("never withholds when there is nothing actionable — an additional rescan that resolved nothing is not a billing event", () => {
    const gate = writebackGate(true, false, 0);
    expect(gate.allowed).toBe(true);
    expect(gate.message).toBeUndefined();
  });
});
