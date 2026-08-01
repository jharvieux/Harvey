// Periodic schema-drift check for the committed osv-scanner fixture (conservation invariant 3,
// criterion 3 of #1130). Re-runs the PINNED osv-scanner against the same lockfile the fixture was
// captured from and asserts the FRESH output still satisfies the schema contract the committed
// fixture demonstrates and parseOsvFindings depends on (src/scan/osv-fixture-contract.ts). It also
// re-checks the committed fixture itself, so a hand-edit that broke it is caught even here.
//
// Why not a byte diff: osv.dev adds advisories over time, so the vulnerability CONTENT churns
// legitimately. #1063 was a SHAPE change (a CVSS vector string read as a bare number), so this
// diffs the shape/contract, not the bytes.
//
// This needs the osv-scanner binary, so — like dry-run-drift / corpus-drift / validate-conservation
// — it is NOT part of `pnpm verify`; the contract logic and its negative controls are, via
// src/scan/osv-fixture-contract.test.ts. Intended to run on the dry-run-drift / conservation
// cadence (CI wiring is issue-tracked separately — .github/workflows is operator-owned).
//
//   pnpm exec tsx src/cli/osv-fixture-drift.ts

import "./sync-stdio.js";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import type { OsvScanResult } from "../scan/dependencies.js";
import { OSV_CALIBRATION_LOCKFILE, OSV_SCANNER_PINNED_VERSION, checkOsvSchemaContract } from "../scan/osv-fixture-contract.js";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const lockfile = join(repoRoot, OSV_CALIBRATION_LOCKFILE);
const fixturePath = join(repoRoot, "src/scan/__fixtures__/osv/osv-scanner-2.3.8-report.json");

function fail(message: string): never {
  console.error(`✗ osv-fixture-drift: ${message}`);
  process.exit(1);
}

function osvVersion(): string {
  let out: string;
  try {
    out = execFileSync("osv-scanner", ["--version"], { encoding: "utf8" });
  } catch (err) {
    const e = err as { code?: string; message?: string };
    fail(e.code === "ENOENT" ? "osv-scanner not on PATH — this drift check requires it (CI installs the mechanical binaries)" : (e.message ?? "osv-scanner --version failed"));
  }
  // "osv-scanner version: 2.3.8\nosv-scalibr version: 0.4.5"
  const m = out.match(/osv-scanner version:\s*([0-9]+\.[0-9]+\.[0-9]+)/);
  if (!m) fail(`could not parse a version from osv-scanner --version output: ${JSON.stringify(out.trim())}`);
  return m[1]!;
}

function runOsvScanner(): OsvScanResult {
  let out: string;
  try {
    out = execFileSync("osv-scanner", ["--format", "json", "--lockfile", lockfile], { encoding: "utf8", maxBuffer: 1024 * 1024 * 64 });
  } catch (err) {
    // osv-scanner exits 1 when it finds vulnerabilities — stdout still carries the report.
    const e = err as { stdout?: string; message?: string };
    if (typeof e.stdout === "string" && e.stdout.trim().length > 0) out = e.stdout;
    else fail(`osv-scanner produced no report: ${e.message ?? "unknown failure"}`);
  }
  return JSON.parse(out) as OsvScanResult;
}

const version = osvVersion();
if (version !== OSV_SCANNER_PINNED_VERSION) {
  fail(
    `installed osv-scanner is ${version}, the committed fixture was captured from ${OSV_SCANNER_PINNED_VERSION}. ` +
      `A drift check on a different version cannot vouch for the fixture — re-verify src/scan/__fixtures__/osv/ against ${version} (update its PROVENANCE.md and OSV_SCANNER_PINNED_VERSION), or pin ${OSV_SCANNER_PINNED_VERSION}.`,
  );
}

const committed = JSON.parse(readFileSync(fixturePath, "utf8")) as OsvScanResult;
const committedViolations = checkOsvSchemaContract(committed);
if (committedViolations.length > 0) {
  fail(`the COMMITTED fixture violates its own schema contract (a hand-edit?):\n  - ${committedViolations.join("\n  - ")}`);
}

const fresh = runOsvScanner();
const freshViolations = checkOsvSchemaContract(fresh);
if (freshViolations.length > 0) {
  fail(
    `a fresh osv-scanner ${version} run over ${OSV_CALIBRATION_LOCKFILE} no longer matches the schema the committed fixture assumes:\n  - ${freshViolations.join("\n  - ")}\n` +
      `Re-capture src/scan/__fixtures__/osv/osv-scanner-2.3.8-report.json (see its PROVENANCE.md) and re-verify parseOsvFindings against the new shape.`,
  );
}

const freshVulnCount = (fresh.results ?? []).flatMap((r) => r.packages ?? []).flatMap((p) => p.vulnerabilities ?? []).length;
console.log(`✓ osv-fixture-drift: osv-scanner ${version} over ${OSV_CALIBRATION_LOCKFILE} — ${freshVulnCount} vulnerabilities, schema contract holds (committed fixture and fresh run both compliant).`);
process.exit(0);
