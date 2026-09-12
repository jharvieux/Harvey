import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { assembleEngagementDocument } from "../audit-report.js";
import { renderFidelityBreaches } from "../render-fidelity.js";
import { parseOsvFindings, type OsvScanResult } from "./dependencies.js";
import { buildHtml } from "../../report-template/render.mjs";
import { esc } from "../../report-template/sections.mjs";

const FFLATE_FIXES = ["0.4.9", "0.5.4", "0.6.11", "0.7.5", "0.8.3"];

type TestRange = { type?: string; events?: { introduced?: string; fixed?: string; last_affected?: string; limit?: string }[] };

function report(version: string, ranges: TestRange[]): OsvScanResult {
  return {
    results: [{
      source: { path: "package-lock.json" },
      packages: [{
        package: { name: "fflate", version, ecosystem: "npm" },
        vulnerabilities: [{
          id: "GHSA-px8p-9vwx-vf98",
          aliases: ["CVE-2026-27818"],
          summary: "fflate path traversal",
          details: "A malicious archive can write outside the extraction directory.",
          affected: [{ package: { name: "fflate", ecosystem: "npm" }, ranges }],
          database_specific: { severity: "HIGH", cwe_ids: ["CWE-22"] },
        }],
      }],
    }],
  };
}

const releaseLines: TestRange[] = [{
  type: "SEMVER",
  events: FFLATE_FIXES.flatMap((fixed, index) => [
    { introduced: index === 0 ? "0" : `0.${index + 4}.0` },
    { fixed },
  ]),
}];

function finding(version: string, ranges: TestRange[] = releaseLines): Finding {
  return parseOsvFindings(report(version, ranges))[0]!;
}

describe("OSV release-line remediation (#2042)", () => {
  it.each([
    ["0.6.10", "0.6.11"],
    ["0.7.4", "0.7.5"],
    ["0.8.2", "0.8.3"],
  ])("selects a non-affected fix for retained fflate@%s", (installed, fixed) => {
    const result = finding(installed);
    expect(result.id).toBe(`DEP-OSV-GHSA-px8p-9vwx-vf98-fflate@${installed}`);
    expect(result.dependency).toBe("fflate");
    expect(result.fix).toContain(`Upgrade fflate from ${installed} to ${fixed}`);
    expect(result.fix).not.toContain("0.4.9 or later");
    expect(fixed).not.toBe(installed);
    expect(result.evidence).toContain("GHSA-px8p-9vwx-vf98");
  });

  it("sorts and deduplicates fixed events before choosing the installed release line", () => {
    const scrambled = [{ type: "SEMVER", events: [
      { fixed: "0.8.3" }, { introduced: "0.8.0" },
      { fixed: "0.6.11" }, { fixed: "0.6.11" }, { introduced: "0.6.0" },
      { fixed: "0.4.9" }, { introduced: "0" },
      { fixed: "0.7.5" }, { introduced: "0.7.0" },
      { fixed: "0.5.4" }, { introduced: "0.5.0" },
    ] }];
    const result = finding("0.6.10", scrambled);
    expect(result.fix).toContain("from 0.6.10 to 0.6.11");
    expect(result.title).toContain("fixed in 0.4.9 / 0.5.4 / 0.6.11 / 0.7.5 / 0.8.3");
  });

  it("checks a candidate against every affected range instead of stopping at its own interval", () => {
    const overlapping = [
      { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.1.0" }] },
      { type: "SEMVER", events: [{ introduced: "1.1.0" }, { fixed: "1.2.0" }] },
    ];
    expect(finding("1.0.0", overlapping).fix).toContain("from 1.0.0 to 1.2.0");
  });

  it("discloses an advisory with no published fix", () => {
    const result = finding("1.0.0", [{ type: "SEMVER", events: [{ introduced: "0" }] }]);
    expect(result.fix).toContain("No fixed version is published");
    expect(result.fix).toContain("safe concrete upgrade cannot be established");
  });

  it.each([
    ["non-SEMVER range", "1.0.0", [{ type: "GIT", events: [{ introduced: "deadbeef" }, { fixed: "cafebabe" }] }], "unsupported GIT range"],
    ["missing range type", "1.0.0", [{ events: [{ introduced: "0" }, { fixed: "1.0.1" }] }], "range with no declared type"],
    ["unsupported installed version", "workspace:*", releaseLines, "installed version is not an exact semantic version"],
    ["malformed boundary", "1.0.0", [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: ">=1.0.1" }] }], "not an exact semantic version"],
  ])("discloses why it cannot prove a safe version for %s", (_case, installed, ranges, reason) => {
    const result = finding(installed, ranges);
    expect(result.fix).toContain("safe concrete upgrade cannot be established");
    expect(result.fix).toContain(reason);
    expect(result.fix).not.toMatch(/Upgrade fflate .* or later/);
  });

  it.each([
    {
      label: "safe fflate advice",
      installed: "0.6.10",
      ranges: releaseLines,
      expected: "Upgrade fflate from 0.6.10 to 0.6.11",
    },
    {
      label: "multiple-limit uncertainty",
      installed: "1.0.0",
      ranges: [
        { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.1.0" }] },
        { type: "SEMVER", events: [{ introduced: "0" }, { limit: "1.1.0" }, { introduced: "1.2.0" }, { limit: "2.0.0" }] },
      ],
      expected: "limit-bearing SEMVER ranges are not supported for safe upgrade selection",
    },
    {
      label: "infinite-limit uncertainty",
      installed: "1.0.0",
      ranges: [
        { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.1.0" }] },
        { type: "SEMVER", events: [{ introduced: "0" }, { limit: "*" }] },
      ],
      expected: "limit-bearing SEMVER ranges are not supported for safe upgrade selection",
    },
  ])("delivers $label through the assembled document and rendered HTML", ({ installed, ranges, expected }) => {
    const parsed = finding(installed, ranges);
    const document = assembleEngagementDocument([], { connected: false, dynamic: false, llm: false }, [parsed], {
      client: "Controlled fflate target",
      subtitle: "OSV remediation delivery",
      date: "2026-09-12",
      commit: "a".repeat(40),
      auditor: "Harvey",
      confidential: true,
      overallHealth: 5,
      tenantIsolation: "Unmeasured",
      authModel: "Unmeasured",
      headline: "Dependency remediation",
      scope: "Controlled dependency input",
      methodology: "Production OSV parser, report assembly, and HTML renderer",
      outOfScope: "Live deployment behavior",
    });
    const delivered = document.findings.find((entry) => entry.id === parsed.id)!;
    const html = buildHtml(document);
    expect(delivered.fix).toContain(expected);
    expect(JSON.stringify(document)).toContain(expected);
    if (installed === "1.0.0") {
      expect(delivered.fix).toContain("safe concrete upgrade cannot be established");
      expect(delivered.fix).not.toContain("Upgrade fflate from 1.0.0 to 1.1.0");
      expect(delivered.id).toBe("DEP-OSV-GHSA-px8p-9vwx-vf98-fflate@1.0.0");
    }
    expect(html).toContain(esc(delivered.fix));
    expect(renderFidelityBreaches(document, html)).toEqual([]);
  });
});
