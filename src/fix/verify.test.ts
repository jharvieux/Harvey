import { describe, expect, it } from "vitest";
import { computeGreen, detectorHalfClean, discoverVerifyCommands, runCommand, scrubSecrets, type CommandRun, type DetectorRun } from "./verify.js";

const node = process.execPath;

describe("discoverVerifyCommands", () => {
  it("prefers a single verify script over everything else", () => {
    expect(discoverVerifyCommands({ verify: "x", typecheck: "y", test: "z" })).toEqual(["pnpm run verify"]);
  });

  it("falls back to the typecheck/lint/test union when there is no verify/check/ci", () => {
    expect(discoverVerifyCommands({ typecheck: "x", lint: "y", test: "z" })).toEqual([
      "pnpm run typecheck",
      "pnpm run lint",
      "pnpm run test",
    ]);
  });

  it("appends CI-only steps that the scripts don't already cover", () => {
    expect(discoverVerifyCommands({ verify: "x" }, "pnpm", ["pnpm knip", "pnpm run verify"])).toEqual([
      "pnpm run verify",
      "pnpm knip",
    ]);
  });

  it("returns nothing when there are no scripts at all", () => {
    expect(discoverVerifyCommands(undefined)).toEqual([]);
  });
});

describe("runCommand", () => {
  it("captures a real exit code and output — it never trusts a claim of green", async () => {
    const ok = await runCommand(`${node} -e "console.log('built ok')"`, process.cwd());
    expect(ok.exitCode).toBe(0);
    expect(ok.outputTail).toContain("built ok");
    // `>= 0` has no failing direction: every unsigned elapsed time satisfies it, and so does a hardcoded 0.
    // Spawning a node process is never free, so `> 0` is the form that goes red if `durationMs`
    // ever stops being a measurement (#1674).
    expect(ok.durationMs).toBeGreaterThan(0);

    const bad = await runCommand(`${node} -e "process.exit(3)"`, process.cwd());
    expect(bad.exitCode).toBe(3);
  });
});

describe("scrubSecrets", () => {
  it("redacts tokens, keys, and bearer values but leaves ordinary text", () => {
    expect(scrubSecrets("using ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")).toContain("[REDACTED]");
    expect(scrubSecrets("Authorization: Bearer abcdefgh12345678")).toContain("[REDACTED]");
    expect(scrubSecrets("all tests passed in 4.2s")).toBe("all tests passed in 4.2s");
  });
});

describe("computeGreen", () => {
  const check = (o: Partial<CommandRun>): CommandRun => ({
    command: "pnpm run test",
    cwd: ".",
    exitCode: 0,
    durationMs: 10,
    outputTail: "",
    ...o,
  });

  it("is green only when the detector is clean and no client check newly fails", () => {
    expect(
      computeGreen({ detectorAfter: { detectorId: "d", fired: false, output: "" }, clientChecks: [check({})] }),
    ).toBe(true);
  });

  it("is not green if the detector still fires, even with all checks passing", () => {
    expect(
      computeGreen({ detectorAfter: { detectorId: "d", fired: true, output: "" }, clientChecks: [check({})] }),
    ).toBe(false);
  });

  it("is not green if a non-skipped client check fails", () => {
    expect(
      computeGreen({ detectorAfter: { detectorId: "d", fired: false, output: "" }, clientChecks: [check({ exitCode: 1 })] }),
    ).toBe(false);
  });

  it("is not green when the detector did not run — an unrun detector is not a clean one", () => {
    expect(
      computeGreen({
        detectorAfter: { detectorId: "d", fired: false, output: "", notRun: "no resolver for taxonomy" },
        clientChecks: [check({})],
      }),
    ).toBe(false);
  });

  it("does not count skipped checks (needs-ci / pre-existing) against green", () => {
    expect(
      computeGreen({
        detectorAfter: { detectorId: "d", fired: false, output: "" },
        clientChecks: [check({ exitCode: 1, skipped: "pre-existing-failure-on-baseline" }), check({ skipped: "needs-ci" })],
      }),
    ).toBe(true);
  });

  // #1272, the vacuous-truth defect. `[].every(...)` is true, so for as long as the only production
  // assembler hardcoded `clientChecks: []` the client half of this decision silently PASSED — a fix
  // that broke the client's own suite could be reported verified. Pinned here because the failure mode
  // is invisible by construction: nothing about an empty array looks like a missing measurement.
  it("is NOT green on an empty clientChecks — nothing ran, so nothing passed", () => {
    expect(computeGreen({ detectorAfter: { detectorId: "d", fired: false, output: "" }, clientChecks: [] })).toBe(false);
  });

  it("the empty case is the ONLY thing separating it from the detector half — which is a named function", () => {
    // Guards the split: a caller that legitimately scores only the detector half (runFixAcceptance
    // over a single-file corpus) must say so by calling detectorHalfClean, not by passing [].
    const clean: DetectorRun = { detectorId: "d", fired: false, output: "" };
    expect(detectorHalfClean(clean)).toBe(true);
    expect(computeGreen({ detectorAfter: clean, clientChecks: [] })).toBe(false);
    expect(detectorHalfClean({ ...clean, notRun: "no resolver" })).toBe(false);
    expect(detectorHalfClean({ ...clean, fired: true })).toBe(false);
  });
});

describe("runCommand — the timeout bound", () => {
  // Both cases assert ELAPSED time, not just the exit code and the banner. Without that they pass on
  // a runner that never actually bounds anything: `timedOut` is set by the timer regardless of
  // whether the kill landed, so the banner and the non-zero exit still show up — five seconds late.
  // That is exactly how the broken bound shipped.
  it("kills a command that overruns and reports the kill in its own output, never a silent 0", async () => {
    const start = Date.now();
    const slow = await runCommand(`${node} -e "setTimeout(() => {}, 5000)"`, process.cwd(), 300);
    expect(Date.now() - start).toBeLessThan(2000);
    expect(slow.exitCode).not.toBe(0);
    expect(slow.outputTail).toContain("exceeded the client-check timeout");
  }, 20_000);

  // The simple case above is the one that stayed green while the bound was broken on macOS: a shell
  // handed a single command execs itself away, so killing the wrapper pid happens to kill the work.
  // A COMPOUND line leaves the shell resident and the grandchild unreached — and compound is what
  // arrives in practice, since extractCiRunSteps emits a multi-line `run: |` block as one command
  // and client scripts chain with `&&`. Reverting `detached` + the group kill in runCommand turns
  // this red at ~5s.
  it("bounds a COMPOUND command too — the kill reaches the grandchild, not just the shell wrapper", async () => {
    const start = Date.now();
    const slow = await runCommand(`${node} -e "setTimeout(() => {}, 5000)" ; true`, process.cwd(), 300);
    expect(Date.now() - start).toBeLessThan(2000);
    expect(slow.exitCode).not.toBe(0);
    expect(slow.outputTail).toContain("exceeded the client-check timeout");
  }, 20_000);

  it("bounds an && chain, the shape a client verify script actually uses", async () => {
    const start = Date.now();
    const slow = await runCommand(`true && ${node} -e "setTimeout(() => {}, 5000)"`, process.cwd(), 300);
    expect(Date.now() - start).toBeLessThan(2000);
    expect(slow.exitCode).not.toBe(0);
  }, 20_000);
});
