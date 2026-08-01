// #556: a bad LIGHTHOUSE_CHROME_PATH makes chrome-launcher spawn a nonexistent binary, which Node
// reports as an unhandled 'error' event on the underlying child_process — that event bypasses every
// promise .catch() in between (including main()'s try/catch) and used to crash the whole CLI with an
// uncaught ENOENT exit, instead of degrading through the fail-loud M7L-00 disclosure like every other
// unmeasurable case. This proves the fix on a REAL child-process run of the CLI (the closest an
// offline test gets to the actual failure, mirroring the pentest --mode=coverage child-process test),
// not just a unit test of the wrapper in isolation.

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "lighthouse-scan.ts");

// #839: every test in this file spawns a real tsx child process — 5s (vitest's default) is
// tight enough to flake under a loaded machine (full-suite `pnpm verify`) even though each test
// passes reliably in isolation. Raised once here rather than annotating every `it()`.
vi.setConfig({ testTimeout: 30_000 });

// #1134: awaited spawn, not execFileSync. execFileSync blocks the vitest worker's event loop for the
// call's duration, and a blocked worker cannot service the birpc ack for a task update it already
// sent — vitest hardcodes a 60s window for that ack (see vitest.config.ts's HEAVY_CLI_TESTS comment,
// and #1120/#1133 which found run-audit.test.ts's beforeAll actually over that line). Measured calls
// in this file are ~1s each on this hardware, well under the ceiling either way, but the standing
// constraint is "no single blocking window may approach 60s" for every heavy CLI test.
function run(args: string[], env: Record<string, string>): Promise<{ stdout: string }> {
  return new Promise((res, rej) => {
    const child = spawn("node_modules/.bin/tsx", args, { cwd: REPO_ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    // setEncoding, never `stdout += <Buffer>` (#1759): string-concatenating a Buffer decodes THAT
    // CHUNK in isolation, so a multi-byte character straddling a chunk boundary decodes to U+FFFD.
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (d: string) => (stdout += d));
    child.on("error", rej);
    child.on("close", (code) => (code === 0 ? res({ stdout }) : rej(new Error(`lighthouse-scan ${args.join(" ")} exited ${code}`))));
  });
}

describe("lighthouse-scan: a bad LIGHTHOUSE_CHROME_PATH degrades to M7L-00 (#556)", () => {
  let workDir: string;
  beforeEach(() => (workDir = mkdtempSync(join(tmpdir(), "harvey-lh-"))));
  afterEach(() => rmSync(workDir, { recursive: true, force: true }));

  it("exits 0 and records the fail-loud disclosure instead of an uncaught ENOENT exit", async () => {
    const outPath = join(workDir, "findings.json");
    // --url skips build/serve entirely, so launchChrome() is reached (and fails) before anything
    // network-dependent runs — the bad chromePath is the only thing under test here.
    const env = {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      LIGHTHOUSE_CHROME_PATH: join(workDir, "not-a-real-chrome-binary"),
    };
    // rejects if the child exits non-zero — the pre-fix behavior for this env
    await run([CLI, "--url", "http://localhost:1", "--out", outPath], env);

    const findings = JSON.parse(readFileSync(outPath, "utf8"));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe("M7L-00");
    expect(findings[0].taxonomy).toBe("M7 — Core Web Vitals not measured");
    expect(findings[0].evidence).toMatch(/ENOENT|not-a-real-chrome-binary/);
  });
});

// #841: launchChrome() falling through on a soft NO_FCP result (not just a hard launch failure) is
// covered as a hermetic unit test of the extracted retry contract — see
// src/lighthouse-chrome-candidates.test.ts. A real nested Chrome launch has proven unreliable to
// even exercise inside a sandboxed child process here (the same class of issue #838 found with
// jscpd: it hangs making zero requests, rather than failing fast, when launched several process
// generations under this environment's sandbox) — real-browser behavior stays untested in THIS
// file per its existing convention (only #556's ENOENT case is a child-process test).

// #818: proves the resolved browser-candidate ORDER without ever launching a browser (no
// system/network dependency in the test itself) via the LIGHTHOUSE_PRINT_CHROME_ORDER dry-run
// seam — the fastest way to pin the fallback chain the header comment documents.
describe("lighthouse-scan: browser-candidate resolution order (#818)", () => {
  async function printOrder(env: Record<string, string>): Promise<string> {
    const { stdout } = await run([CLI], { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", LIGHTHOUSE_PRINT_CHROME_ORDER: "1", ...env });
    return stdout.trim();
  }

  it("tries the bundled Playwright chromium before system Chrome by default", async () => {
    expect(await printOrder({})).toBe("bundled-playwright,system,provisioned");
  });

  it("an explicit LIGHTHOUSE_CHROME_PATH override short-circuits every other candidate", async () => {
    expect(await printOrder({ LIGHTHOUSE_CHROME_PATH: "/some/chrome" })).toBe("override");
  });

  it("LIGHTHOUSE_SKIP_BUNDLED_CHROMIUM skips straight to system Chrome", async () => {
    expect(await printOrder({ LIGHTHOUSE_SKIP_BUNDLED_CHROMIUM: "1" })).toBe("system,provisioned");
  });

  it("both skip flags leave only network-dependent provisioning as a candidate", async () => {
    expect(await printOrder({ LIGHTHOUSE_SKIP_BUNDLED_CHROMIUM: "1", LIGHTHOUSE_SKIP_SYSTEM_CHROME: "1" })).toBe("provisioned");
  });
});
