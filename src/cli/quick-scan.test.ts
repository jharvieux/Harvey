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

describe("quick-scan CLI — no scratch-scope path leaks into client-facing output (#933)", () => {
  // 30s: drives the real mechanical scan (semgrep/trufflehog/gitleaks/osv-scanner) as a child
  // process, well over vitest's 5s default under load.
  it("does not leak the harvey-scan-scope-* mkdtemp prefix into the rendered report", () => {
    const stdout = execFileSync("node_modules/.bin/tsx", [CLI, "--dir", CALIBRATION], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    expect(stdout).toMatch(/verified hygiene issue/); // sanity: the calibration fixture DOES produce findings
    expect(stdout).not.toMatch(SCRATCH_PREFIX);
  }, 30000);

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
  }, 30000);
});
