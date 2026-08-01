// #1715 — the light suite has ONE timeout, in vitest.config.ts, with its measurement beside it.
//
// The failure this exists to stop is not a slow test; it is the drift back to per-file literals.
// Four files picked one up incident-by-incident (#1646) while src/fs-walk.test.ts sat in the same
// class with nothing, and each literal carried its own private justification, so nobody could see
// that the DEFAULT was the thing that had never been measured against this suite.
//
// Discovery-backed, not a one-time sweep: the population is recomputed from the tree every run, so
// a new literal fails here instead of quietly becoming the fifth. Same posture as sync-stdio.ts's
// exiting-CLI ratchet and the #1330 conditional-scan registry.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { HEAVY_CLI_TESTS } from "./heavy-cli-tests.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// vitest's per-test / per-hook timeout is the trailing numeric argument of `it`/`test`/`describe`/
// `beforeAll`, i.e. a `}` closing the callback followed by `, <number>)`. Deliberately NOT
// `timeout:` — that spelling belongs to execFileSync/spawnSync options in half these files, and a
// pattern that conflated the two would fail on child-process budgets this rule has no opinion about.
const TRAILING_TIMEOUT = /\n[ \t]*\}\s*,\s*([\d_]+)\s*\)\s*;/g;

function timeoutLiteralsIn(source: string): string[] {
  return [...source.matchAll(TRAILING_TIMEOUT)].map((m) => m[1] ?? "");
}

/**
 * Light-suite files that still carry their own literal, each with the reason the uniform budget
 * does not serve it. This list may only SHRINK: a file that is here and no longer has a literal
 * fails as a stale claim, exactly like TWIN_BACKLOG and the test-only-exports baseline.
 *
 * Heavy files (src/heavy-cli-tests.ts) are not eligible at all — they are excluded from the light
 * suite, their blocking windows ARE the subject of #1120, and their per-test literals are load-
 * bearing rather than incidental.
 */
const AD_HOC_TIMEOUT_BACKLOG: Record<string, string> = {
  "src/cli/fix-execute.test.ts":
    "60-120s per test: each one builds a corpus and spawns the CLIENT's own suites concurrently, so its wall time tracks a spawned toolchain, not this repo's. Measured 20.5s for the whole file on an idle machine.",
  "src/cli/sync-stdio.test.ts":
    "60s: spawns real children and asserts on reader backpressure, so its clock is the child's, and #1768 records that a timing-anchored assertion here is exactly what went flaky.",
  "src/cli/validate-conservation.test.ts":
    "240s: the HARVEY_CONSERVATION_E2E opt-in (#1105) runs the whole ten-module orchestrator in a child. It is skipped in the light suite and runs in conservation.yml.",
  "src/cli/validate-reasons.test.ts":
    "120s on a beforeAll that builds a git fixture and rebuilds the claim baseline through the real CLI. This file already has the highest non-test time in the suite (10512ms measured under contention).",
  "src/cli/validate-secbench.test.ts":
    "120s: runs real semgrep over the SecBench corpus in a child process.",
  "src/fix/verify.test.ts":
    "20s, TIGHTER than the uniform budget on purpose: these assertions prove a client command that hangs is killed at 300ms, so a generous ceiling would let a broken kill path look like a slow machine.",
};

function lightSuiteTestFiles(): string[] {
  const heavy = new Set<string>(HEAVY_CLI_TESTS);
  return execFileSync("git", ["ls-files", "*.test.ts"], { cwd: REPO_ROOT, encoding: "utf8" })
    .trim()
    .split("\n")
    .filter((f) => f.length > 0 && !heavy.has(f));
}

describe("the light suite has one measured timeout, not a literal per incident (#1715)", () => {
  it("no light-suite file carries an unlisted per-test or per-hook timeout literal", () => {
    const files = lightSuiteTestFiles();
    // A discovery that returns nothing would make every assertion below pass vacuously — the shape
    // #1388/#1509 exist to prevent. The population is part of the measurement.
    expect(files.length, "git ls-files found no light-suite test files — the discovery is broken, not the tree").toBeGreaterThan(100);

    const unlisted = files.filter((f) => timeoutLiteralsIn(readFileSync(join(REPO_ROOT, f), "utf8")).length > 0 && !(f in AD_HOC_TIMEOUT_BACKLOG));
    expect(
      unlisted,
      "these light-suite files declare their own test/hook timeout. #1715 settled this once: vitest.config.ts carries one measured 30s budget for the whole light suite. Delete the literal, or add the file to AD_HOC_TIMEOUT_BACKLOG with the reason the uniform budget does not serve it.",
    ).toEqual([]);
  });

  it("no backlog row has outlived its literal", () => {
    const stale = Object.keys(AD_HOC_TIMEOUT_BACKLOG).filter((f) => timeoutLiteralsIn(readFileSync(join(REPO_ROOT, f), "utf8")).length === 0);
    expect(stale, "these files no longer carry a timeout literal, so their backlog rows are claims that are no longer true. Delete the rows — a backlog that never shrinks is a list, not a ratchet.").toEqual([]);
  });

  it("vitest.config.ts sets ONE budget, and testTimeout and hookTimeout agree", () => {
    const config = readFileSync(join(REPO_ROOT, "vitest.config.ts"), "utf8");
    const declared = /const TIMEOUT_MS = ([\d_]+);/.exec(config)?.[1];
    expect(declared, "vitest.config.ts no longer declares a single TIMEOUT_MS — #1715's whole point is that the number lives in exactly one place, with its measurement beside it").toBeDefined();
    expect(config).toContain("testTimeout: TIMEOUT_MS");
    expect(config).toContain("hookTimeout: TIMEOUT_MS");
    // Inside #1120's standing ceiling: no single blocking window may approach vitest's hardcoded
    // 60s worker->main RPC ack, and a timeout is the ceiling on exactly such a window.
    expect(Number((declared ?? "0").replaceAll("_", ""))).toBeLessThan(60_000);
  });

  it("NEGATIVE CONTROL: the detector reads a real literal, and is not satisfied by its absence", () => {
    // The same function the assertions above run, against sources whose answer is known — so a
    // matcher that stopped matching (or one that matched everything) fails here rather than turning
    // the ratchet above into a green no-op.
    expect(timeoutLiteralsIn("it('x', async () => {\n  await go();\n}, 30_000);\n")).toEqual(["30_000"]);
    expect(timeoutLiteralsIn("it('x', () => {\n  expect(1).toBe(1);\n});\n")).toEqual([]);
    // A child-process budget is not a test timeout and must not be counted as one.
    expect(timeoutLiteralsIn("execFileSync('sh', ['-c', c], { timeout: 60_000 });\n")).toEqual([]);
  });
});
