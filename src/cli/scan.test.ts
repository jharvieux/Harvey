// #1298 — gotrueProbeArg is the CLI-layer half of wiring opts.gotrueProbe: before this, nothing
// in the repo could set it (grep gotrueProbe was four hits: the type, the guard, the call, one
// mocked unit test — no CLI flag, no env var, no orchestrator plumbing). These tests lock the
// flag-pairing contract so a future edit does not silently reopen that gap.

import { describe, expect, it, vi } from "vitest";
import { gotrueProbeArg } from "./scan.js";

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
  const stderr = err.mock.calls.map((c) => String(c[0])).join("\n");
  exit.mockRestore();
  err.mockRestore();
  return { code, stderr };
}

describe("gotrueProbeArg", () => {
  it("returns undefined when neither flag is passed", () => {
    let result: unknown;
    const { code } = captureExit(() => {
      result = gotrueProbeArg([]);
    });
    expect(code).toBeUndefined();
    expect(result).toBeUndefined();
  });

  it("returns the probe target when both flags are passed", () => {
    let result: unknown;
    const { code } = captureExit(() => {
      result = gotrueProbeArg(["--gotrue-url", "https://self-hosted.example.com/auth/v1", "--gotrue-anon-key", "anon-key-value"]);
    });
    expect(code).toBeUndefined();
    expect(result).toEqual({ authUrl: "https://self-hosted.example.com/auth/v1", anonKey: "anon-key-value" });
  });

  it("exits 2 when --gotrue-url is passed without --gotrue-anon-key", () => {
    const { code, stderr } = captureExit(() => gotrueProbeArg(["--gotrue-url", "https://self-hosted.example.com/auth/v1"]));
    expect(code).toBe(2);
    expect(stderr).toContain("--gotrue-url and --gotrue-anon-key must be passed together");
  });

  it("exits 2 when --gotrue-anon-key is passed without --gotrue-url", () => {
    const { code, stderr } = captureExit(() => gotrueProbeArg(["--gotrue-anon-key", "anon-key-value"]));
    expect(code).toBe(2);
    expect(stderr).toContain("--gotrue-url and --gotrue-anon-key must be passed together");
  });
});
