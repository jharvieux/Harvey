// Schema-drift contract for the committed osv-scanner fixture (conservation invariant 3, #1130).
//
// src/scan/__fixtures__/osv/osv-scanner-2.3.8-report.json is a CAPTURED artifact (see its
// PROVENANCE.md). A frozen capture protects the parser from the #1063 regression — but only until
// osv-scanner's own output schema drifts underneath it, at which point the fixture and the tool
// disagree and the frozen capture is a lie. The periodic drift check (src/cli/osv-fixture-drift.ts)
// re-runs the pinned osv-scanner against the same lockfile and asserts the FRESH output still
// satisfies the contract below — the exact contract the committed fixture demonstrates and
// parseOsvFindings depends on. A byte diff is not usable here: osv.dev adds advisories over time, so
// the vulnerability CONTENT legitimately churns. What must NOT change is the SHAPE, and #1063 was a
// shape change (a CVSS vector string read as a bare number).

import type { OsvScanResult, OsvVulnerability } from "./dependencies.js";

// The version the committed fixture was captured from (src/scan/__fixtures__/osv/PROVENANCE.md) and
// that dependencies.ts's severity mapping was MEASURED against (#1063/#1079). A drift check run
// against a different version cannot vouch for the fixture — it must fail loud and prompt a
// re-verification, not silently pass.
export const OSV_SCANNER_PINNED_VERSION = "2.3.8";

// The lockfile the fixture was captured against — the drift check re-runs osv-scanner here.
export const OSV_CALIBRATION_LOCKFILE = "targets/calibration/package-lock.json";

function allVulnerabilities(result: OsvScanResult): OsvVulnerability[] {
  const vulns: OsvVulnerability[] = [];
  for (const src of result.results ?? []) {
    for (const pkg of src.packages ?? []) {
      for (const vuln of pkg.vulnerabilities ?? []) vulns.push(vuln);
    }
  }
  return vulns;
}

// Returns the list of contract VIOLATIONS ([] means the schema still holds). The invariants are
// exactly what parseOsvFindings reads and what #1063 broke:
//   1. the run found vulnerabilities at all (else there is nothing to check — lockfile/DB drift);
//   2. every `severity[].score` is a CVSS VECTOR STRING, never a bare number (the #1063 shape);
//   3. at least one advisory carries `database_specific.severity` (the primary severity basis).
export function checkOsvSchemaContract(result: OsvScanResult): string[] {
  const violations: string[] = [];
  const vulns = allVulnerabilities(result);

  if (vulns.length === 0) {
    violations.push(
      "no vulnerabilities in the osv-scanner output — the schema contract cannot be verified (lockfile or advisory-database drift?)",
    );
    return violations;
  }

  let sawDbSeverity = false;
  for (const vuln of vulns) {
    const id = vuln.id ?? "(no id)";
    for (const sev of vuln.severity ?? []) {
      if (sev.score === undefined) continue;
      if (!/^CVSS:/.test(sev.score)) {
        violations.push(
          `${id}: severity[].score is ${JSON.stringify(sev.score)}, not a CVSS vector string ("CVSS:.../...") — this is the #1063 shape (a vector string read as a bare number nulls every severity)`,
        );
      }
    }
    const dbSev = vuln.database_specific?.severity;
    if (typeof dbSev === "string" && dbSev.length > 0) sawDbSeverity = true;
  }

  if (!sawDbSeverity) {
    violations.push(
      "no advisory carried database_specific.severity — the primary severity basis parseOsvFindings reads is gone from the output",
    );
  }

  return violations;
}
