// #1752 negative controls: runOsvScanner used to treat ANY non-empty stdout as a complete report,
// discarding the exit code and signal — the #1664 swallow shape. Each mock below replays a failure
// shape MEASURED on 2026-07-31 against osv-scanner 2.3.8 (see runOsvScanner's comment in
// dependencies.ts), not an invented one. Same harness shape as semgrep-crash.test.ts.

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";

let osvBehavior: () => string = () => {
  throw new Error("test forgot to set osvBehavior");
};

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFileSync: vi.fn((bin: string, args: string[], opts?: unknown) => {
      if (bin === "osv-scanner") return osvBehavior();
      return actual.execFileSync(bin as never, args as never, opts as never) as never;
    }),
  };
});

const { runOsvScanner } = await import("./dependencies.js");

// runOsvScanner only invokes the binary when a lockfile exists — the mock never reads it.
const dir = mkdtempSync(join(tmpdir(), "harvey-osv-crash-"));
writeFileSync(join(dir, "package-lock.json"), "{}");
afterAll(() => rmSync(dir, { recursive: true, force: true }));

// The real report shape (osv-scanner 2.3.8 over targets/calibration emits 230,602 bytes of this).
const COMPLETE_REPORT = JSON.stringify({
  results: [{ source: { path: "package-lock.json" }, packages: [{ package: { name: "lodash", version: "4.17.11" }, vulnerabilities: [{ id: "GHSA-x", summary: "s" }] }] }],
});

function execError(over: { status?: number | null; signal?: string | null; stdout?: string; code?: string }): Error {
  const err = new Error("Command failed: osv-scanner") as Error & { status: number | null; signal: string | null; stdout: string | undefined; code: string | undefined };
  err.status = over.status ?? null;
  err.signal = over.signal ?? null;
  err.stdout = over.stdout;
  err.code = over.code;
  return err;
}

describe("runOsvScanner refuses an incomplete run (#1752)", () => {
  it("exit 1 with the complete report is the benign vulns-found case — parsed, no failure", () => {
    osvBehavior = () => {
      throw execError({ status: 1, stdout: COMPLETE_REPORT });
    };
    const { result, failure } = runOsvScanner(dir);
    expect(failure).toBeUndefined();
    expect(result.results?.[0]?.packages?.[0]?.vulnerabilities?.[0]?.id).toBe("GHSA-x");
  });

  it("a signal-killed run is a failure naming the signal, even with a truncated report on stdout (MEASURED: SIGKILL mid-flush left 196,563 of 230,602 bytes)", () => {
    osvBehavior = () => {
      throw execError({ signal: "SIGKILL", stdout: COMPLETE_REPORT.slice(0, 120) });
    };
    const { result, failure } = runOsvScanner(dir);
    expect(failure).toContain("killed by signal SIGKILL");
    expect(result).toEqual({});
  });

  it("a maxBuffer kill (ENOBUFS + SIGTERM, truncated stdout) is a failure naming the cap, never an uncaught SyntaxError", () => {
    osvBehavior = () => {
      throw execError({ signal: "SIGTERM", code: "ENOBUFS", stdout: COMPLETE_REPORT.slice(0, 120) });
    };
    const { failure } = runOsvScanner(dir);
    expect(failure).toContain("64 MiB stdout cap");
  });

  it("exit 127 with empty stdout (corrupt lockfile / dead network / mid-scan connection loss — all MEASURED) names the exit code", () => {
    osvBehavior = () => {
      throw execError({ status: 127, stdout: "" });
    };
    const { failure } = runOsvScanner(dir);
    expect(failure).toContain("exited with code 127");
  });

  it("a missing binary still reads as not-found, not as an incomplete run", () => {
    osvBehavior = () => {
      throw execError({ code: "ENOENT" });
    };
    const { failure } = runOsvScanner(dir);
    expect(failure).toContain("not found on PATH");
  });

  it("exit 0 with non-JSON stdout degrades to a failure instead of an uncaught SyntaxError", () => {
    osvBehavior = () => "<ERROR: not a report>";
    const { result, failure } = runOsvScanner(dir);
    expect(failure).toContain("something other than its JSON report");
    expect(result).toEqual({});
  });

  it("exit 1 with EMPTY stdout is a failure, not a silently clean scan", () => {
    osvBehavior = () => {
      throw execError({ status: 1, stdout: "" });
    };
    const { failure } = runOsvScanner(dir);
    expect(failure).toContain("printed no report");
  });
});
