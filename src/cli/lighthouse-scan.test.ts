// #556: a bad LIGHTHOUSE_CHROME_PATH makes chrome-launcher spawn a nonexistent binary, which Node
// reports as an unhandled 'error' event on the underlying child_process — that event bypasses every
// promise .catch() in between (including main()'s try/catch) and used to crash the whole CLI with an
// uncaught ENOENT exit, instead of degrading through the fail-loud M7L-00 disclosure like every other
// unmeasurable case. This proves the fix on a REAL child-process run of the CLI (the closest an
// offline test gets to the actual failure, mirroring the pentest --mode=coverage child-process test),
// not just a unit test of the wrapper in isolation.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "lighthouse-scan.ts");

describe("lighthouse-scan: a bad LIGHTHOUSE_CHROME_PATH degrades to M7L-00 (#556)", () => {
  let workDir: string;
  beforeEach(() => (workDir = mkdtempSync(join(tmpdir(), "harvey-lh-"))));
  afterEach(() => rmSync(workDir, { recursive: true, force: true }));

  it("exits 0 and records the fail-loud disclosure instead of an uncaught ENOENT exit", { timeout: 30_000 }, () => {
    const outPath = join(workDir, "findings.json");
    // --url skips build/serve entirely, so launchChrome() is reached (and fails) before anything
    // network-dependent runs — the bad chromePath is the only thing under test here.
    const env = {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      LIGHTHOUSE_CHROME_PATH: join(workDir, "not-a-real-chrome-binary"),
    };
    execFileSync("node_modules/.bin/tsx", [CLI, "--url", "http://localhost:1", "--out", outPath], {
      cwd: REPO_ROOT,
      env,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }); // throws if the child exits non-zero — the pre-fix behavior for this env

    const findings = JSON.parse(readFileSync(outPath, "utf8"));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe("M7L-00");
    expect(findings[0].taxonomy).toBe("M7 — Core Web Vitals not measured");
    expect(findings[0].evidence).toMatch(/ENOENT|not-a-real-chrome-binary/);
  });
});

// #818: proves the resolved browser-candidate ORDER without ever launching a browser (no
// system/network dependency in the test itself) via the LIGHTHOUSE_PRINT_CHROME_ORDER dry-run
// seam — the fastest way to pin the fallback chain the header comment documents.
describe("lighthouse-scan: browser-candidate resolution order (#818)", () => {
  function printOrder(env: Record<string, string>): string {
    return execFileSync("node_modules/.bin/tsx", [CLI], {
      cwd: REPO_ROOT,
      env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", LIGHTHOUSE_PRINT_CHROME_ORDER: "1", ...env },
      encoding: "utf8",
    }).trim();
  }

  it("tries the bundled Playwright chromium before system Chrome by default", () => {
    expect(printOrder({})).toBe("bundled-playwright,system,provisioned");
  });

  it("an explicit LIGHTHOUSE_CHROME_PATH override short-circuits every other candidate", () => {
    expect(printOrder({ LIGHTHOUSE_CHROME_PATH: "/some/chrome" })).toBe("override");
  });

  it("LIGHTHOUSE_SKIP_BUNDLED_CHROMIUM skips straight to system Chrome", () => {
    expect(printOrder({ LIGHTHOUSE_SKIP_BUNDLED_CHROMIUM: "1" })).toBe("system,provisioned");
  });

  it("both skip flags leave only network-dependent provisioning as a candidate", () => {
    expect(printOrder({ LIGHTHOUSE_SKIP_BUNDLED_CHROMIUM: "1", LIGHTHOUSE_SKIP_SYSTEM_CHROME: "1" })).toBe("provisioned");
  });
});
