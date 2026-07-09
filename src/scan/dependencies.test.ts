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
  it("drops an OSV hit whose alias matches an already-curated advisory (dedup)", () => {
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
    expect(parseOsvFindings(result)).toEqual([]);
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

  it("degrades gracefully to no findings for a target with no lockfile (mechanical.ts's runOsvScanner returns {})", () => {
    expect(parseOsvFindings({})).toEqual([]);
  });
});

describe("curated + OSV dedup (issue #73)", () => {
  it("merges to exactly one finding when OSV independently resolves the same GHSA as a curated CVE", () => {
    // Reproduces #73: committing a lockfile lets OSV-Scanner resolve next@14.2.35, which falls
    // in both the curated WebSocket-SSRF range and OSV's own GHSA-c4j6-fc7j-m34r match.
    const curated = checkNextVersionCVEs("14.2.35");
    const osvResult: OsvScanResult = {
      results: [
        {
          source: { path: "package-lock.json" },
          packages: [
            {
              package: { name: "next", version: "14.2.35" },
              vulnerabilities: [
                { id: "GHSA-c4j6-fc7j-m34r", summary: "WebSocket-upgrade SSRF", severity: [{ type: "CVSS_V3", score: "8.6" }] },
              ],
            },
          ],
        },
      ],
    };
    const merged = [...curated, ...parseOsvFindings(osvResult)];
    expect(merged).toHaveLength(1);
    expect(merged[0]?.id).toBe("DEP-CVE-2026-44578");
  });

  it("preserves two genuinely distinct CVEs on the same package", () => {
    const osvResult: OsvScanResult = {
      results: [
        {
          source: { path: "package-lock.json" },
          packages: [
            {
              package: { name: "next", version: "14.2.35" },
              vulnerabilities: [
                // Curated advisory: deduped away by parseOsvFindings.
                { id: "GHSA-c4j6-fc7j-m34r", summary: "WebSocket-upgrade SSRF", severity: [{ type: "CVSS_V3", score: "8.6" }] },
                // Unrelated CVE on the same package: not curated, must survive.
                { id: "GHSA-aaaa-bbbb-cccc", summary: "unrelated prototype pollution", severity: [{ type: "CVSS_V3", score: "6.1" }] },
              ],
            },
          ],
        },
      ],
    };
    const curated = checkNextVersionCVEs("14.2.35");
    const merged = [...curated, ...parseOsvFindings(osvResult)];
    const ids = merged.map((f) => f.id);
    expect(ids).toContain("DEP-CVE-2026-44578");
    expect(ids).toContain("DEP-OSV-GHSA-aaaa-bbbb-cccc");
    expect(merged).toHaveLength(2);
  });
});
