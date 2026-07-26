import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { OsvScanResult } from "./dependencies.js";
import { checkOsvSchemaContract } from "./osv-fixture-contract.js";

// The committed capture (src/scan/__fixtures__/osv/) — the same file dependencies.test.ts asserts
// against. This test guards the SHAPE the drift check enforces; the drift check (needs the binary)
// applies the identical contract to a FRESH run.
const fixture: OsvScanResult = JSON.parse(
  readFileSync(new URL("./__fixtures__/osv/osv-scanner-2.3.8-report.json", import.meta.url), "utf8"),
) as OsvScanResult;

describe("checkOsvSchemaContract", () => {
  it("passes the committed osv-scanner 2.3.8 fixture with no violations", () => {
    expect(checkOsvSchemaContract(fixture)).toEqual([]);
  });

  // #1063 negative control: the exact bare-number score that nulled every severity. A gate that has
  // never fired on a known-bad input is not evidence.
  it("fires on a bare-number severity score (the #1063 shape)", () => {
    const broken: OsvScanResult = {
      results: [
        {
          packages: [
            {
              package: { name: "lodash", version: "4.17.19" },
              vulnerabilities: [
                { id: "GHSA-broken", severity: [{ type: "CVSS_V3", score: "7.5" }], database_specific: { severity: "HIGH" } },
              ],
            },
          ],
        },
      ],
    };
    const violations = checkOsvSchemaContract(broken);
    expect(violations.length).toBeGreaterThan(0);
    expect(violations.join("\n")).toContain("#1063");
    expect(violations.join("\n")).toContain("GHSA-broken");
  });

  it("fires when the run found no vulnerabilities (lockfile/advisory-DB drift)", () => {
    expect(checkOsvSchemaContract({ results: [] })).toContain(
      "no vulnerabilities in the osv-scanner output — the schema contract cannot be verified (lockfile or advisory-database drift?)",
    );
  });

  it("fires when database_specific.severity has disappeared from every advisory", () => {
    const noDbSev: OsvScanResult = {
      results: [
        {
          packages: [
            {
              package: { name: "elliptic", version: "6.5.4" },
              vulnerabilities: [{ id: "GHSA-x", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }] }],
            },
          ],
        },
      ],
    };
    expect(checkOsvSchemaContract(noDbSev).join("\n")).toContain("database_specific.severity");
  });

  it("accepts a CVSS 4.0 vector string (the fixture carries both v3 and v4)", () => {
    const v4: OsvScanResult = {
      results: [
        {
          packages: [
            {
              package: { name: "next", version: "14.0.0" },
              vulnerabilities: [
                {
                  id: "GHSA-v4",
                  severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N" }],
                  database_specific: { severity: "HIGH" },
                },
              ],
            },
          ],
        },
      ],
    };
    expect(checkOsvSchemaContract(v4)).toEqual([]);
  });
});
