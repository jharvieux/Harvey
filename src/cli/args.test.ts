// Guards the fix for the silent-wrong-tree defect found 2026-07-26 (see src/cli/args.ts header).
//
// The bug: `quick-scan --target <dir>` — the spelling dry-run.ts uses — was not recognized, so
// `arg("--dir") ?? process.cwd()` fell through to the cwd and the tool produced a confident report
// about the wrong tree. Exit 0, no warning, 188 findings from outside the stated target.
//
// These tests fail if either half of the fix regresses: the loud rejection of an unknown flag, and
// the `--target` alias that makes the natural guess work instead of silently retargeting.

import { describe, expect, it, vi } from "vitest";
import { arg, assertKnownFlags, targetDir } from "./args.js";

const FLAGS = ["--dir", "--target", "--out", "--json"] as const;

function captureExit(run: () => void): { code: number | undefined; stderr: string } {
  let code: number | undefined;
  const exit = vi.spyOn(process, "exit").mockImplementation(((c?: number) => {
    code = c;
    throw new Error("__exit__");
  }) as never);
  const err = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    run();
  } catch (e) {
    if (!(e instanceof Error) || e.message !== "__exit__") throw e;
  }
  // Read the captured calls BEFORE restoring — mockRestore() clears them.
  const stderr = err.mock.calls.map((c) => String(c[0])).join("\n");
  exit.mockRestore();
  err.mockRestore();
  return { code, stderr };
}

describe("assertKnownFlags", () => {
  it("accepts a recognized flag and its value", () => {
    const { code } = captureExit(() => assertKnownFlags(FLAGS, ["--dir", "targets/calibration"]));
    expect(code).toBeUndefined();
  });

  it("exits 2 naming an unrecognized flag rather than ignoring it", () => {
    const { code, stderr } = captureExit(() => assertKnownFlags(FLAGS, ["--bogus", "x"]));
    expect(code).toBe(2);
    expect(stderr).toContain("--bogus");
  });

  it("does not mistake a flag VALUE for a flag", () => {
    // A value that itself looks like a flag is consumed positionally, not re-checked.
    const { code } = captureExit(() => assertKnownFlags(FLAGS, ["--out", "--weird-looking-value"]));
    expect(code).toBeUndefined();
  });

  it("still rejects an unknown flag that follows a valid flag/value pair", () => {
    const { code, stderr } = captureExit(() =>
      assertKnownFlags(FLAGS, ["--dir", "targets/calibration", "--nope"]),
    );
    expect(code).toBe(2);
    expect(stderr).toContain("--nope");
  });

  it("treats a valueless flag as consuming nothing", () => {
    const { code, stderr } = captureExit(() => assertKnownFlags(FLAGS, ["--json", "--nope"]));
    expect(code).toBe(2);
    expect(stderr).toContain("--nope");
  });
});

describe("targetDir", () => {
  it("reads --dir", () => {
    expect(targetDir(["node", "cli", "--dir", "a/b"])).toBe("a/b");
  });

  it("accepts --target as an alias, the spelling that caused the original defect", () => {
    expect(targetDir(["node", "cli", "--target", "a/b"])).toBe("a/b");
  });

  it("falls back to cwd only when NEITHER is given", () => {
    expect(targetDir(["node", "cli"])).toBe(process.cwd());
  });

  it("exits rather than silently picking a winner when the two disagree", () => {
    const { code } = captureExit(() => targetDir(["node", "cli", "--dir", "a", "--target", "b"]));
    expect(code).toBe(2);
  });

  it("accepts both when they agree", () => {
    expect(targetDir(["node", "cli", "--dir", "a", "--target", "a"])).toBe("a");
  });
});

describe("arg", () => {
  it("returns undefined for an absent flag", () => {
    expect(arg("--missing", ["node", "cli"])).toBeUndefined();
  });
});
