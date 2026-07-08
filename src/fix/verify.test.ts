import { describe, expect, it } from "vitest";
import { computeGreen, discoverVerifyCommands, runCommand, scrubSecrets, type CommandRun } from "./verify.js";

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
  it("captures a real exit code and output — it never trusts a claim of green", () => {
    const ok = runCommand(`${node} -e "console.log('built ok')"`, process.cwd());
    expect(ok.exitCode).toBe(0);
    expect(ok.outputTail).toContain("built ok");
    expect(ok.durationMs).toBeGreaterThanOrEqual(0);

    const bad = runCommand(`${node} -e "process.exit(3)"`, process.cwd());
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

  it("does not count skipped checks (needs-ci / pre-existing) against green", () => {
    expect(
      computeGreen({
        detectorAfter: { detectorId: "d", fired: false, output: "" },
        clientChecks: [check({ exitCode: 1, skipped: "pre-existing-failure-on-baseline" }), check({ skipped: "needs-ci" })],
      }),
    ).toBe(true);
  });
});
