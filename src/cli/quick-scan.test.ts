// #933: quick-scan runs the mechanical scan over a scratch copy of the target
// (src/scan/scan-scope.ts's resolveScanScope, #101), so every raw finding location carries that
// run's mkdtemp `harvey-scan-scope-*` prefix. quick-scan is the client-facing FREE report — a
// per-run/per-machine scratch path in front of every location is unreadable and reads as a leaked
// internal path. relativizeScanScope (#285) already existed and already handled this for the SARIF
// export (#910); this proves it's also applied at quick-scan's own render/output boundary, for
// --out/console, --findings-out, and --json alike, not just SARIF.

import { execFileSync, spawn } from "node:child_process";
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

// #1134: awaited spawn, not execFileSync. execFileSync blocks the vitest worker's event loop for the
// call's duration, and a blocked worker cannot service the birpc ack for a task update it already
// sent — vitest hardcodes a 60s window for that ack (see vitest.config.ts's HEAVY_CLI_TESTS comment,
// and #1120/#1133 which found run-audit.test.ts's beforeAll actually over that line). MEASURED
// 2026-07-26 each call here takes ~10s on this hardware, comfortably under the 60s ceiling either
// way, but the standing constraint is "no single blocking window may approach 60s" for every heavy
// CLI test — awaiting a spawned child leaves the loop free regardless of how slow the call gets.
function run(args: string[]): Promise<{ stdout: string }> {
  return new Promise((res, rej) => {
    const child = spawn("node_modules/.bin/tsx", args, { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "ignore"] });
    let stdout = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d));
    child.on("error", rej);
    child.on("close", (code) => (code === 0 ? res({ stdout }) : rej(new Error(`quick-scan ${args.join(" ")} exited ${code}`))));
  });
}

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
  it("does not leak the harvey-scan-scope-* mkdtemp prefix into the rendered report", async () => {
    const { stdout } = await run([CLI, "--dir", CALIBRATION]);
    expect(stdout).toMatch(/verified hygiene issue/); // sanity: the calibration fixture DOES produce findings
    expect(stdout).not.toMatch(SCRATCH_PREFIX);
  }, 120000);

  it("does not leak the scratch prefix into --findings-out (the raw mechanical Finding[])", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "harvey-quick-scan-test-"));
    dirs.push(outDir);
    const findingsOutPath = join(outDir, "findings.json");
    await run([CLI, "--dir", CALIBRATION, "--findings-out", findingsOutPath, "--out", join(outDir, "report.txt")]);
    const findings = JSON.parse(readFileSync(findingsOutPath, "utf8")) as { location: string }[];
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => SCRATCH_PREFIX.test(f.location))).toBe(false);
  }, 120000);
});


// #1237(a) — the loop-copy allowlist sanitizer, driven through the REAL semgrep run rather than a
// recorded fixture, because what it has to prove is the sanitizer's behaviour and a recording
// does not. It lives here rather than in the calibration entries alone for a measured reason:
// `validate-calibration` scores all three rows correctly, but at the time this landed that gate
// printed a review-tier miss as a tracked NON-FATAL gap and still exited 0. MEASURED 2026-07-31 —
// with the sanitizer's identifier constraint deleted, both adversarial positives went silent, both
// rows read FAIL, and the gate still printed GATE PASS and exited 0. #1628 closed that hole the
// same day: a review-tier miss is a GATE FAIL now, so the corpus rows would bite on their own. This
// block stays because it is not the same test — it drives the sanitizer through a real semgrep run
// and asserts WHICH fixtures it spares, which a recall count leaves unsaid.
describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("harvey-jsx-prop-spread-injection: the loop-copy allowlist (#1237)", () => {
  const FIXTURES = join(CALIBRATION, "src", "owasp-react");

  async function propSpreadHits(): Promise<string[]> {
    const outDir = mkdtempSync(join(tmpdir(), "harvey-propspread-test-"));
    dirs.push(outDir);
    const findingsOutPath = join(outDir, "findings.json");
    await run([CLI, "--dir", CALIBRATION, "--findings-out", findingsOutPath, "--out", join(outDir, "report.txt")]);
    const findings = JSON.parse(readFileSync(findingsOutPath, "utf8")) as { taxonomy: string; location: string }[];
    return findings
      .filter((f) => f.taxonomy.includes("prop-spread-injection"))
      .map((f) => f.location.split("/").pop() ?? f.location);
  }

  it("clears the named-allowlist loop and still fires on both shapes that spoof it", async () => {
    const hit = await propSpreadHits();
    // Sanity: the rule ran at all. Without this the three assertions below all pass on an empty set.
    expect(hit.some((l) => l.startsWith("prop-spread-injection.tsx"))).toBe(true);
    expect(FIXTURES).toBeTruthy();

    // The fix: `for (const k of ALLOWED_PROPS) if (k in raw) safe[k] = raw[k]` is the sheet's own
    // remedy written imperatively, and the rule was reporting it at High.
    expect(hit.some((l) => l.startsWith("prop-spread-loop-allowlist.tsx"))).toBe(false);

    // The two shapes a looser version of that sanitizer would clear silently. Neither is a
    // hypothetical: dropping the `$ALLOW` identifier constraint makes both of these go dark.
    expect(hit.some((l) => l.startsWith("prop-spread-loop-own-keys.tsx"))).toBe(true);
    expect(hit.some((l) => l.startsWith("prop-spread-loop-tainted-list.tsx"))).toBe(true);
  }, 120000);
});
