// #1664 negative controls: runSemgrep used to treat ANY non-empty stdout as success, so a
// semgrep-core crash (`semgrep-core exited with -10!`) returned `failure: undefined` and a
// zero/partial-finding scan read as CLEAN. Each mock below replays a crash shape MEASURED on
// 2026-07-31 against semgrep 1.164.0 (see execSemgrep's comment in semgrep.ts), not an invented
// one. Separate file from semgrep.test.ts because that file's module mock hard-codes ENOENT.

import { describe, expect, it } from "vitest";
import { vi } from "vitest";

// Each test assigns the semgrep behaviour it needs; non-semgrep binaries pass through untouched.
let semgrepBehavior: () => string = () => {
  throw new Error("test forgot to set semgrepBehavior");
};

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFileSync: vi.fn((bin: string, args: string[], opts?: unknown) => {
      if (bin === "semgrep") return semgrepBehavior();
      return actual.execFileSync(bin as never, args as never, opts as never) as never;
    }),
  };
});

const { runSemgrep, runSemgrepOnFile } = await import("./semgrep.js");

// The real exit-7 envelope shape (`semgrep --config /dev/null`, captured 2026-07-31): valid JSON,
// zero results, errors[] at level "error" — exactly what the old swallow accepted as a clean scan.
const EXIT7_ENVELOPE = JSON.stringify({
  version: "1.164.0",
  results: [],
  errors: [
    { code: 2, level: "error", type: "SemgrepError", message: "config location `/dev/null` is not a file or folder!" },
    { code: 7, level: "error", type: "SemgrepError", message: "invalid configuration file found (1 configs were invalid)" },
  ],
  paths: { scanned: [], skipped: [] },
});

function execError(over: { status?: number | null; signal?: string | null; stdout?: string }): Error {
  const err = new Error("Command failed: semgrep") as Error & { status: number | null; signal: string | null; stdout: string | undefined };
  err.status = over.status ?? null;
  err.signal = over.signal ?? null;
  err.stdout = over.stdout;
  return err;
}

describe("runSemgrep refuses an incomplete run (#1664)", () => {
  it("a non-zero exit with a valid-but-empty envelope is a failure naming the exit code, never a clean scan", () => {
    semgrepBehavior = () => {
      throw execError({ status: 7, stdout: EXIT7_ENVELOPE });
    };
    const { result, failure } = runSemgrep("/some/target");
    expect(failure).toBeDefined();
    expect(failure).toContain("exited with code 7");
    expect(failure).toContain("invalid configuration file found");
    expect(result).toEqual({});
  });

  it("a signal-killed run is a failure naming the signal, even with partial JSON on stdout", () => {
    semgrepBehavior = () => {
      throw execError({ signal: "SIGBUS", stdout: JSON.stringify({ version: "1.164.0", results: [], errors: [], paths: { scanned: [] } }) });
    };
    const { failure } = runSemgrep("/some/target");
    expect(failure).toBeDefined();
    expect(failure).toContain("killed by signal SIGBUS");
  });

  it("the measured `<ERROR: missing output>` stdout degrades to a failure, not an uncaught SyntaxError", () => {
    semgrepBehavior = () => {
      throw execError({ status: 2, stdout: "<ERROR: missing output>" });
    };
    const { failure } = runSemgrep("/some/target");
    expect(failure).toBeDefined();
    expect(failure).toContain("exited with code 2");
  });

  it("a completed run (exit 0) still parses and reports no failure", () => {
    semgrepBehavior = () => JSON.stringify({ version: "1.164.0", results: [], errors: [], paths: { scanned: ["/some/target/a.ts"] } });
    const { result, failure } = runSemgrep("/some/target");
    expect(failure).toBeUndefined();
    expect(result.paths?.scanned).toEqual(["/some/target/a.ts"]);
  });

  it("the single-file re-run refuses an incomplete run the same way — its partial output must not feed the paths.scanned check", () => {
    semgrepBehavior = () => {
      throw execError({ status: 2, stdout: EXIT7_ENVELOPE });
    };
    const { failure } = runSemgrepOnFile("/some/target/a.ts", "/some/target");
    expect(failure).toBeDefined();
    expect(failure).toContain("exited with code 2");
  });
});
