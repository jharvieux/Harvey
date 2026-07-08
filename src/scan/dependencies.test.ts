import { describe, expect, it } from "vitest";
import { checkNextVersionCVEs, parseOsvFindings, type OsvScanResult } from "./dependencies.js";

describe("checkNextVersionCVEs", () => {
  it("flags CVE-2025-29927 for an unpatched 15.x below the fixed version", () => {
    const findings = checkNextVersionCVEs("15.1.0");
    const ids = findings.map((f) => f.id);
    expect(ids).toContain("DEP-CVE-2025-29927");
    expect(findings.find((f) => f.id === "DEP-CVE-2025-29927")?.precisionTier).toBe("high");
  });

  it("does not flag CVE-2025-29927 once patched (15.2.3)", () => {
    const findings = checkNextVersionCVEs("15.2.3");
    expect(findings.map((f) => f.id)).not.toContain("DEP-CVE-2025-29927");
  });

  it("flags the React2Shell RSC RCE for an unpatched minor line (15.2.0 < 15.2.9)", () => {
    const findings = checkNextVersionCVEs("15.2.0");
    expect(findings.map((f) => f.id)).toContain("DEP-CVE-2025-55182");
  });

  it("does not flag React2Shell for a minor line with no known-fixed entry (e.g. 13.x)", () => {
    const findings = checkNextVersionCVEs("13.5.9");
    expect(findings.map((f) => f.id)).not.toContain("DEP-CVE-2025-55182");
  });

  it("flags the WebSocket SSRF for both vulnerable ranges", () => {
    expect(checkNextVersionCVEs("14.0.0").map((f) => f.id)).toContain("DEP-CVE-2026-44578");
    expect(checkNextVersionCVEs("16.1.0").map((f) => f.id)).toContain("DEP-CVE-2026-44578");
    expect(checkNextVersionCVEs("16.2.5").map((f) => f.id)).not.toContain("DEP-CVE-2026-44578");
  });

  it("flags EOL major lines as review-tier, not high", () => {
    const findings = checkNextVersionCVEs("13.5.9");
    const eol = findings.find((f) => f.id === "DEP-NEXT-EOL");
    expect(eol?.precisionTier).toBe("review");
  });

  it("flags nothing extra for a current, fully-patched version", () => {
    const findings = checkNextVersionCVEs("15.5.16");
    expect(findings).toEqual([]);
  });
});

describe("parseOsvFindings", () => {
  it("tags a curated advisory alias as high precision", () => {
    const result: OsvScanResult = {
      results: [
        {
          source: { path: "pnpm-lock.yaml" },
          packages: [
            {
              package: { name: "next", version: "15.1.0" },
              vulnerabilities: [{ id: "CVE-2025-29927", aliases: ["GHSA-f82v-jwr5-mffw"], summary: "middleware bypass" }],
            },
          ],
        },
      ],
    };
    const findings = parseOsvFindings(result);
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("tags a generic transitive-dep CVE as review precision", () => {
    const result: OsvScanResult = {
      results: [
        {
          source: { path: "pnpm-lock.yaml" },
          packages: [
            {
              package: { name: "lodash", version: "4.17.15" },
              vulnerabilities: [{ id: "GHSA-xxxx-yyyy-zzzz", summary: "prototype pollution", severity: [{ type: "CVSS_V3", score: "7.5" }] }],
            },
          ],
        },
      ],
    };
    const findings = parseOsvFindings(result);
    expect(findings[0]?.precisionTier).toBe("review");
    expect(findings[0]?.severity).toBe("High");
  });
});
