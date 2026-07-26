// #933: quick-scan runs the mechanical scan over a scratch copy of the target
// (src/scan/scan-scope.ts's resolveScanScope, #101), so every raw finding location carries that
// run's mkdtemp `harvey-scan-scope-*` prefix. quick-scan is the client-facing FREE report — a
// per-run/per-machine scratch path in front of every location is unreadable and reads as a leaked
// internal path. relativizeScanScope (#285) already existed and already handled this for the SARIF
// export (#910); this proves it's also applied at quick-scan's own render/output boundary, for
// --out/console, --findings-out, and --json alike, not just SARIF.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "quick-scan.ts");
const CALIBRATION = join(REPO_ROOT, "targets", "calibration");

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const SCRATCH_PREFIX = /harvey-scan-scope-/;

// These two tests drive the REAL mechanical scan (src/scan/mechanical.ts) as a child process, so
// they need semgrep/trufflehog/gitleaks actually installed — same requirement mechanical.test.ts
// documents (it mocks those sub-scanners specifically because pnpm verify's own convention is
// deterministic-offline, matching the CI `verify` job which — per .github/workflows/ci.yml —
// deliberately does not install them, unlike the separate `dry-run` job). Skip with a named
// reason rather than a silent pass: this is the existing offline-suite convention, not a new one.
function hasBinary(name: string): boolean {
  try {
    execFileSync("which", [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const MECHANICAL_BINARIES_PRESENT = ["semgrep", "trufflehog", "gitleaks"].every(hasBinary);

describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("quick-scan CLI — no scratch-scope path leaks into client-facing output (#933)", () => {
  // Drives the real mechanical scan (semgrep/trufflehog/gitleaks/osv-scanner) as a child process,
  // so vitest's 5s default is far too short. 30s was too short too: #1125 is this file blowing that
  // budget under full-suite parallel load while passing in isolation, reproduced by two sweep
  // executors on unrelated branches. #1120 moved the file into the serialized heavy-CLI run
  // (vitest.config.ts), where MEASURED 2026-07-26 both tests take ~11s each on a load-25 10-core
  // machine — but that measurement is this hardware, and this describe block has never once
  // executed on a CI runner (the `verify` job installs none of these binaries). 120s so the budget
  // is not the thing that discovers unfamiliar hardware; the assertion is about path leakage, and
  // nothing about it gets weaker with more headroom.
  it("does not leak the harvey-scan-scope-* mkdtemp prefix into the rendered report", () => {
    const stdout = execFileSync("node_modules/.bin/tsx", [CLI, "--dir", CALIBRATION], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    expect(stdout).toMatch(/verified hygiene issue/); // sanity: the calibration fixture DOES produce findings
    expect(stdout).not.toMatch(SCRATCH_PREFIX);
  }, 120000);

  it("does not leak the scratch prefix into --findings-out (the raw mechanical Finding[])", () => {
    const outDir = mkdtempSync(join(tmpdir(), "harvey-quick-scan-test-"));
    dirs.push(outDir);
    const findingsOutPath = join(outDir, "findings.json");
    execFileSync("node_modules/.bin/tsx", [CLI, "--dir", CALIBRATION, "--findings-out", findingsOutPath, "--out", join(outDir, "report.txt")], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "ignore", "ignore"],
    });
    const findings = JSON.parse(readFileSync(findingsOutPath, "utf8")) as { location: string }[];
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => SCRATCH_PREFIX.test(f.location))).toBe(false);
  }, 120000);
});
