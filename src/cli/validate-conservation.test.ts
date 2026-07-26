// #1064 (4)+(5), the WIRING proof: the real CLI, driving the real ten-module orchestrator against
// targets/calibration and the real assembler. src/audit-conservation.test.ts proves the gate's
// logic fires on each seeded violation shape; this proves the gate is actually plugged into a run.
//
// ONE orchestrator run, not two, and it carries both directions: the seeded module fails while
// every other module passes in the same output, so a gate that failed on everything (or on nothing)
// is equally visible. The second run was dropped deliberately — each is a ~30s synchronous
// execFileSync that blocks its vitest worker, and two of them alongside the suite's existing heavy
// child-process files starved the worker RPC (`Timeout calling "onTaskUpdate"`, twice in three
// `pnpm verify` runs, 2026-07-26; clean with this file excluded). The clean-pass direction is
// measured in docs/design/conservation-of-findings.md and is what `--seed-loss` is measured against.

import { execFileSync } from "node:child_process";
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
if (!MECHANICAL_BINARIES_PRESENT) {
  console.warn(
    "⚠ conservation gate end-to-end block SKIPPED — semgrep/trufflehog/gitleaks/osv-scanner are not all on PATH, so the ten-module run cannot be driven here. The gate itself is `pnpm exec tsx src/cli/validate-conservation.ts`; its logic is still covered by src/audit-conservation.test.ts.",
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

describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("validate-conservation CLI — end-to-end against targets/calibration", () => {
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
  }, 240000);
});
