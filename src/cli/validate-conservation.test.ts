// #1064 (4)+(5), the WIRING proof: the real CLI, driving the real ten-module orchestrator against
// targets/calibration and the real assembler. src/audit-conservation.test.ts proves the gate's
// logic fires on each seeded violation shape; this proves the gate is actually plugged into a run.
//
// ONE orchestrator run, not two, and it carries both directions: the seeded module fails while
// every other module passes in the same output, so a gate that failed on everything (or on nothing)
// is equally visible. The second run was dropped deliberately — each is a ~30-50s synchronous
// execFileSync that blocks its vitest worker for the duration.
//
// #1105: even one such block running as part of `pnpm verify`'s default project, alongside this
// suite's other heavy child-process files, intermittently starved the worker RPC channel back to
// the main process (`[vitest-worker]: Timeout calling "onTaskUpdate"`, exit 1 with zero failing
// tests — MEASURED 2026-07-26: reproduced in 1 of 5 consecutive `pnpm verify` runs on a clean
// main). Vitest exposes no config knob for that RPC timeout (checked
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

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
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

// REASON: this end-to-end block cannot run under the CI `verify` job — it drives the mechanical tier (semgrep/trufflehog/gitleaks/osv-scanner) as child processes and that job deliberately installs none of them, which is why dry-run-drift and corpus-drift are separate workflows too
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-26 (read .github/workflows/ci.yml: the `build` job runs `pnpm install --frozen-lockfile` then `pnpm verify`, with no binary-install step; the dry-run-drift workflow installs them explicitly)
// FALSIFIER: grep -Eq "semgrep|trufflehog|gitleaks|osv-scanner" .github/workflows/ci.yml
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
  return existsSync(cache) && readdirSync(cache).some((v) => existsSync(resolve(cache, v, "vitals/scripts/vitals_cli.py")));
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
function runGate(args: string[]): { code: number; output: string } {
  try {
    return { code: 0, output: execFileSync("node_modules/.bin/tsx", [CLI, ...args], { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { code: e.status ?? -1, output: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

describe.skipIf(!CONSERVATION_E2E_REQUESTED || !MECHANICAL_BINARIES_PRESENT || !VITALS_PRESENT)("validate-conservation CLI — end-to-end against targets/calibration", () => {
  // 240s: a full ten-module run of the real orchestrator as a child process.
  it("FAILS on a seeded loss and only on it — every unseeded module still delivers its plant", () => {
    const { code, output } = runGate(["--seed-loss", "M7"]);
    expect(code).toBe(1);
    expect(output).toContain("GATE FAIL — M7 produced NOTHING");
    // The deliverable still carries an M7 row (M9 captures detect-static unfiltered), so a check
    // that only read the document would pass here. That it does not is the whole point (#1062).
    expect(output).toMatch(/GONE\s+M7\s+produced=0\s+delivered=[1-9]/);
    // The other direction, in the same run: a gate that fails on everything proves nothing, so the
    // eight unseeded plants must all have travelled probe → deliverable intact.
    for (const module of ["M1", "M3", "M4", "M5", "M6", "M8", "M9", "M10"]) {
      expect(output).toMatch(new RegExp(`PASS\\s+${module}\\s+produced=[1-9]`));
    }
    expect(output).not.toContain("GATE FAIL — M1");
    // #1146: the baseline ledger runs on every gate invocation (empty baseline), so an unseeded run
    // proves it is wired and passing on the real deliverable.
    expect(output).toContain("BASELINE LEDGER PASS");
  }, 240000);

  // #1146, the 4b seam: a finding dropped during baseline application produces a ledger row and a
  // non-zero exit — the guard against silently deleting a NEW finding after assembly.
  it("FAILS when the baseline diff drops a finding (--seed-baseline-loss)", () => {
    const { code, output } = runGate(["--seed-baseline-loss"]);
    expect(code).toBe(1);
    expect(output).toContain("BASELINE LEDGER FAIL");
    expect(output).toMatch(/DELETED\s+\S+/);
  }, 240000);

  // #1146, the 4a seam: a disposition column credited against a finding that still ships fails —
  // the producer path for suppressed/capped/not-applicable cannot close the arithmetic on a fiction.
  it("FAILS when a disposition is declared against a still-delivered finding (--seed-misdeclared)", () => {
    const { code, output } = runGate(["--seed-misdeclared"]);
    expect(code).toBe(1);
    expect(output).toContain("did not actually go missing");
  }, 240000);
});
