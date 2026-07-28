// #1064 (4)+(5), the WIRING proof: the real CLI, driving the real ten-module orchestrator against
// targets/calibration and the real assembler. src/audit-conservation.test.ts proves the gate's
// logic fires on each seeded violation shape; this proves the gate is actually plugged into a run.
//
// ONE orchestrator run per test, not two per test: each of the three `it` blocks below runs the
// real ten-module orchestrator once via the CLI, so the seeded module fails while every other
// module passes in the same output — a gate that failed on everything (or on nothing) is equally
// visible.
//
// #1105: even isolated in its own CI step (not sharing a worker with the rest of the suite), a
// single one of these runs can still block its vitest worker long enough to starve the RPC channel
// back to the main process (`[vitest-worker]: Timeout calling "onTaskUpdate"`, exit 1 with zero
// failing tests). Vitest exposes no config knob for that RPC timeout (checked
// node_modules/vitest/dist/chunks/index.B521nVV-.js — DEFAULT_TIMEOUT is hardcoded to 60s), and
// vitest's file `exclude` also blocks an explicitly-named path from running at all (TRIED
// 2026-07-26: `pnpm exec vitest run src/cli/validate-conservation.test.ts` on an excluded path
// prints "No test files found, exiting with code 1"). So instead of excluding the file, the block
// below gates on HARVEY_CONSERVATION_E2E, unset (and therefore skipped) everywhere except the
// isolated "vitest wiring test" step in .github/workflows/conservation.yml, which sets it and runs
// only this file with the mechanical toolchain already on PATH and no other heavy suite alongside
// it. Run it locally the same way: HARVEY_CONSERVATION_E2E=1 pnpm exec vitest run
// src/cli/validate-conservation.test.ts. The clean-pass direction is measured in
// docs/design/conservation-of-findings.md and is what `--seed-loss` is measured against.
//
// #1168: isolation alone was not enough. MEASURED 2026-07-26 — reproduced by running this file
// under artificial CPU load (8 busy-loop processes saturating all cores, approximating a loaded CI
// runner): 2 of 2 runs failed on the exact `onTaskUpdate` signature (85.9s and 106.0s total; a clean
// unloaded run is ~56s). The three `it` blocks each drove `runGate` through a synchronous
// `execFileSync`, and each individually blocks the worker's event loop for ~20-30s unloaded, more
// under load — the same mechanism #1120/#1133 found in run-audit.test.ts's beforeAll (a single
// blocking window approaching or exceeding the hardcoded 60s ack window). `runGate` now spawns the
// CLI and awaits it instead, so the event loop stays free for the RPC ack during each run — the
// fix #1133 applied to run-audit.test.ts, applied here to the same failure mode.

import { execFileSync, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { readNamesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "validate-conservation.ts");

function hasBinary(name: string): boolean {
  try {
    execFileSync("which", [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// REASON: this end-to-end block cannot run under the CI `verify` job — it needs HARVEY_CONSERVATION_E2E=1 plus the mechanical tier and the vitals plugin, and no verify-gated ci.yml job sets that env var or runs this file (heavy-cli installs the binaries but its include list excludes this file); it is exercised by .github/workflows/conservation.yml instead
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-26 (#1072: the old falsifier grepped ci.yml for the scanner binary names as a proxy for "verify installs them"; #1120's heavy-cli job now installs them for a DIFFERENT set of files, so that grep went stale while the claim held. Re-read ci.yml + vitest.config.ts: the block gates on HARVEY_CONSERVATION_E2E, which only conservation.yml:135 sets)
// FALSIFIER: grep -q HARVEY_CONSERVATION_E2E .github/workflows/ci.yml
// TOUCHES: .github/workflows/ci.yml
const MECHANICAL_BINARIES_PRESENT = ["semgrep", "trufflehog", "gitleaks", "osv-scanner"].every(hasBinary);

// M3's plant is a truck-factor-1 row, which only vitals' FULL tier produces — without the plugin
// hotspot-scan drops to the reduced churn×complexity tier (#807) and the M3 assertion below fails
// for a missing toolchain rather than a real conservation break. Mirrors resolveVitals() in
// src/cli/hotspot-scan.ts (PATH first, then the #507 plugin install locations); that CLI stays the
// source of truth for where vitals lives.
function vitalsAvailable(): boolean {
  if (hasBinary("vitals_cli.py")) return true;
  const plugins = resolve(homedir(), ".claude/plugins");
  if (existsSync(resolve(plugins, "marketplaces/vitals/scripts/vitals_cli.py"))) return true;
  const cache = resolve(plugins, "cache/vitals");
  return existsSync(cache) && readNamesSafe(cache).some((v) => existsSync(resolve(cache, v, "vitals/scripts/vitals_cli.py")));
}

// REASON: this end-to-end block cannot run under the CI `verify` job — beyond the mechanical tier it asserts M3's plant, and M3's truck-factor-1 signal comes from the `vitals` plugin, which is a Claude Code plugin rather than a package `pnpm install` brings in
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-26 (ran `HOME=<empty dir> pnpm exec tsx src/cli/hotspot-scan.ts targets/calibration`: "M3 REDUCED TIER", 0 rows, no Knowledge-risk findings; with the plugin resolvable, 2× truck-factor-1)
// FALSIFIER: grep -q vitals .github/workflows/ci.yml
// TOUCHES: .github/workflows/ci.yml .github/workflows/conservation.yml
const VITALS_PRESENT = vitalsAvailable();

// REASON: this block is unset (and the end-to-end test skipped) under `pnpm verify` and any plain local run — it exists only so the isolated CI step can opt in without a second vitest config file
// KIND: decisional
// PROVENANCE: TRIED 2026-07-26 (a vitest.config.ts `exclude` entry was tried first and rejected: `pnpm exec vitest run src/cli/validate-conservation.test.ts` on an excluded path prints "No test files found, exiting with code 1", which would have left .github/workflows/conservation.yml with no way to run this file in isolation either)
// OWNER: #1105
// DECISION: gate the RPC-timeout-prone block behind an env var the default `pnpm verify` path never sets, rather than a vitest `exclude`
const CONSERVATION_E2E_REQUESTED = process.env.HARVEY_CONSERVATION_E2E === "1";

if (!CONSERVATION_E2E_REQUESTED || !MECHANICAL_BINARIES_PRESENT || !VITALS_PRESENT) {
  const reason = !CONSERVATION_E2E_REQUESTED
    ? "HARVEY_CONSERVATION_E2E is not set to \"1\" — this block is opt-in (#1105) to keep its ~30-50s child-process run out of `pnpm verify`'s shared vitest worker pool"
    : !MECHANICAL_BINARIES_PRESENT
      ? "semgrep/trufflehog/gitleaks/osv-scanner are not all on PATH, so the ten-module run cannot be driven here"
      : "the `vitals` plugin is not installed, so M3 runs in its reduced tier (#807) and cannot produce its planted truck-factor-1 row";
  console.warn(
    `⚠ conservation gate end-to-end block SKIPPED — ${reason}. The gate itself is \`pnpm exec tsx src/cli/validate-conservation.ts\`; its logic is still covered by src/audit-conservation.test.ts, and .github/workflows/conservation.yml runs it with the full toolchain.`,
  );
}

// Exit code AND output, because a gate that fails for an unrelated reason (a crash, a bad flag) is
// indistinguishable from one that caught the seeded defect if only the code is checked.
//
// spawn + await, NOT execFileSync (#1168, mirroring #1120/#1133's run-audit.test.ts fix):
// execFileSync blocks the vitest worker's event loop for the run's full duration, and a blocked
// worker cannot service the birpc ack for the task update it already sent — that ack has the
// hardcoded 60s window. Awaiting a spawned child leaves the loop free, so the ack lands regardless
// of how long the child itself takes.
function runGate(args: string[]): Promise<{ code: number; output: string }> {
  return new Promise((res, rej) => {
    const child = spawn("node_modules/.bin/tsx", [CLI, ...args], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (chunk: Buffer) => (output += chunk.toString("utf8")));
    child.stderr.on("data", (chunk: Buffer) => (output += chunk.toString("utf8")));
    child.on("error", rej);
    child.on("close", (code) => res({ code: code ?? -1, output }));
  });
}

describe.skipIf(!CONSERVATION_E2E_REQUESTED || !MECHANICAL_BINARIES_PRESENT || !VITALS_PRESENT)("validate-conservation CLI — end-to-end against targets/calibration", () => {
  // 240s: a full ten-module run of the real orchestrator as a child process.
  it("FAILS on a seeded loss and only on it — every unseeded module still delivers its plant", async () => {
    const { code, output } = await runGate(["--seed-loss", "M7"]);
    expect(code).toBe(1);
    expect(output).toContain("GATE FAIL — M7 produced NOTHING");
    // The gate reads each module's OWN probe attribution (findingsByModule), not the merged
    // document — that is why it catches this loss. Before #1084 M9 captured detect-static UNFILTERED
    // and re-delivered M7's rows, so a seeded M7 loss stayed visible in the deliverable (delivered≥1)
    // while M7 produced nothing — the #1062 masking, which the gate still caught via produced=0.
    // #1084 makes M9 collect only the complement of M6/M7/M8, so nothing re-delivers M7's discarded
    // rows and the loss is now visible in the document too (delivered=0). The gate fails on produced=0
    // either way — the produced/delivered split is what's asserted, not the delivered count.
    expect(output).toMatch(/GONE\s+M7\s+produced=0\s+delivered=0/);
    // The other direction, in the same run: a gate that fails on everything proves nothing, so the
    // nine unseeded plants must all have travelled probe → deliverable intact (M2's offline plant,
    // the injected #416 dynamic-pass artifact, included since #1155).
    for (const module of ["M1", "M2", "M3", "M4", "M5", "M6", "M8", "M9", "M10"]) {
      expect(output).toMatch(new RegExp(`PASS\\s+${module}\\s+produced=[1-9]`));
    }
    expect(output).not.toContain("GATE FAIL — M1");
    // #1146: the baseline ledger runs on every gate invocation (empty baseline), so an unseeded run
    // proves it is wired and passing on the real deliverable.
    expect(output).toContain("BASELINE LEDGER PASS");
  }, 240000);

  // #1146, the 4b seam: a finding dropped during baseline application produces a ledger row and a
  // non-zero exit — the guard against silently deleting a NEW finding after assembly.
  it("FAILS when the baseline diff drops a finding (--seed-baseline-loss)", async () => {
    const { code, output } = await runGate(["--seed-baseline-loss"]);
    expect(code).toBe(1);
    expect(output).toContain("BASELINE LEDGER FAIL");
    expect(output).toMatch(/DELETED\s+\S+/);
  }, 240000);

  // #1146, the 4a seam: a disposition column credited against a finding that still ships fails —
  // the producer path for suppressed/capped/not-applicable cannot close the arithmetic on a fiction.
  it("FAILS when a disposition is declared against a still-delivered finding (--seed-misdeclared)", async () => {
    const { code, output } = await runGate(["--seed-misdeclared"]);
    expect(code).toBe(1);
    expect(output).toContain("did not actually go missing");
  }, 240000);
});
