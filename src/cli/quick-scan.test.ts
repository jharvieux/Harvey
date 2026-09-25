// #933: quick-scan runs the mechanical scan over a scratch copy of the target
// (src/scan/scan-scope.ts's resolveScanScope, #101), so every raw finding location carries that
// run's mkdtemp `harvey-scan-scope-*` prefix. quick-scan is the client-facing FREE report — a
// per-run/per-machine scratch path in front of every location is unreadable and reads as a leaked
// internal path. relativizeScanScope (#285) already existed and already handled this for the SARIF
// export (#910); this proves it's also applied at quick-scan's own render/output boundary, for
// --out/console, --findings-out, and --json alike, not just SARIF.

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CALIBRATION, CLI, MECHANICAL_BINARIES_PRESENT, createQuickScanTestHarness } from "./quick-scan-test-support.js";

const { dirs, run, cleanup } = createQuickScanTestHarness();
afterEach(cleanup);
const SCRATCH_PREFIX = /harvey-scan-scope-/;


// Both export-path and prop-spread assertions consume this exact CLI invocation. Retain an
// immutable serialized snapshot after the first run; the separate console-mode test still
// exercises its own output branch. This avoids repeating the entire real calibration scan.
let calibrationExport: Promise<string> | undefined;
function calibrationFindings(): Promise<string> {
  return calibrationExport ??= (async () => {
    const outDir = mkdtempSync(join(tmpdir(), "harvey-quick-calibration-export-"));
    dirs.push(outDir);
    const findingsOutPath = join(outDir, "findings.json");
    await run([CLI, "--dir", CALIBRATION, "--findings-out", findingsOutPath, "--out", join(outDir, "report.txt")]);
    return readFileSync(findingsOutPath, "utf8");
  })();
}

describe("quick-scan SBOM shipping export (#2059)", () => {
  it("delivers unresolved alias identity and incompleteness through --sbom-out", async () => {
    const target = mkdtempSync(join(tmpdir(), "harvey-quick-sbom-alias-"));
    dirs.push(target);
    writeFileSync(join(target, "package.json"), JSON.stringify({ dependencies: { alias: "npm:@actual/pkg@^2.0.0" } }));
    writeFileSync(join(target, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: {
      "": { dependencies: { alias: "npm:@actual/pkg@^2.0.0" } },
      "node_modules/alias": { version: "2.0.0" },
    } }));
    const sbomOut = join(target, "inventory.cdx.json");
    const previousPath = process.env.PATH;
    process.env.PATH = "/nonexistent";
    try {
      await run([CLI, "--dir", target, "--sbom-out", sbomOut, "--out", join(target, "report.txt")]);
    } finally {
      process.env.PATH = previousPath;
    }
    const bom = JSON.parse(readFileSync(sbomOut, "utf8")) as {
      components: Array<{ name: string; purl?: string }>;
      compositions: Array<{ aggregate: string }>;
      metadata: { properties: Array<{ name: string; value: string }> };
    };
    expect(bom.components.some((component) => component.name === "alias" || component.purl?.startsWith("pkg:npm/alias@"))).toBe(false);
    expect(bom.compositions[0]?.aggregate).toBe("incomplete");
    expect(bom.metadata.properties.find((property) => property.name === "harvey:unresolved-alias")?.value).toContain("@actual/pkg");
  }, 120000);
});

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
    const findings = JSON.parse(await calibrationFindings()) as { location: string }[];
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
    const findings = JSON.parse(await calibrationFindings()) as { taxonomy: string; location: string }[];
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
