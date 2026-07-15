import { describe, expect, it } from "vitest";
import { checkKnownDependencyCVEs, checkNextVersionCVEs, parseOsvFindings, type OsvScanResult } from "./dependencies.js";

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

  it("flags the RSC RCE for an unpatched minor line (15.2.0 < 15.2.6)", () => {
    const findings = checkNextVersionCVEs("15.2.0");
    expect(findings.map((f) => f.id)).toContain("DEP-CVE-2025-55182");
  });

  it("does not flag the RSC RCE for a minor line outside the advisory's ranges (e.g. 13.x)", () => {
    const findings = checkNextVersionCVEs("13.5.9");
    expect(findings.map((f) => f.id)).not.toContain("DEP-CVE-2025-55182");
  });

  // #212: the RSC ranges (GHSA-9qr9-h5gf-34mp) open at 14.3.0-canary.77, so no RELEASED 14.x is
  // affected. An earlier table wrongly listed a "14.2" line, making every next@14.2.x a Critical
  // false positive — the exact credibility-fatal shape this corpus is provenance-checked against.
  it("does not flag the RSC RCE on the stable 14.2 line (unaffected per the advisory)", () => {
    expect(checkNextVersionCVEs("14.2.5").map((f) => f.id)).not.toContain("DEP-CVE-2025-55182");
  });

  it("clears the RSC RCE at each line's OSV-stated fixed version", () => {
    for (const v of ["15.0.5", "15.1.9", "15.2.6", "15.3.6", "15.4.8", "15.5.7", "16.0.7"]) {
      expect(checkNextVersionCVEs(v).map((f) => f.id), v).not.toContain("DEP-CVE-2025-55182");
    }
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

  it("EOL is the only finding for a major that sits at/above its curated fixes (12.3.5)", () => {
    // The P-NEXT-EOL fixture version: EOL fires, but 12.3.5 isn't below any curated fixed version
    // for major 12, and major 12 is outside the WS-SSRF / RSC ranges — so nothing else fires.
    const ids = checkNextVersionCVEs("12.3.5").map((f) => f.id);
    expect(ids).toEqual(["DEP-NEXT-EOL"]);
  });

  it("encodes the manifest path into the finding location", () => {
    const finding = checkNextVersionCVEs("12.3.5", "fixtures/legacy-app/package.json")[0];
    expect(finding?.location).toBe("fixtures/legacy-app/package.json (next)");
  });

  it("flags CVE-2026-27978 (null-origin CSRF) for the 16.0.1–16.1.6 range, at high", () => {
    for (const v of ["16.0.1", "16.0.5", "16.1.6"]) {
      const f = checkNextVersionCVEs(v).find((x) => x.id === "DEP-CVE-2026-27978");
      expect(f, v).toBeDefined();
      expect(f?.precisionTier).toBe("high");
      // Medium, not High: the advisory rates it MODERATE (CVSS v4, user-interaction required).
      expect(f?.severity, v).toBe("Medium");
    }
  });

  it("does not flag null-origin once patched (16.1.7) or above the WS-SSRF fix (16.2.5)", () => {
    expect(checkNextVersionCVEs("16.1.7").map((f) => f.id)).not.toContain("DEP-CVE-2026-27978");
    expect(checkNextVersionCVEs("16.2.5").map((f) => f.id)).not.toContain("DEP-CVE-2026-27978");
  });

  it("16.2.5 is the fully-clean patched next-16 (no null-origin, RSC, or WS-SSRF)", () => {
    expect(checkNextVersionCVEs("16.2.5")).toEqual([]);
  });
});

describe("checkKnownDependencyCVEs", () => {
  it("flags minimist below the fix as a critical, free-count (high) finding", () => {
    const findings = checkKnownDependencyCVEs({ minimist: "1.2.5" });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("DEP-CVE-2021-44906");
    expect(findings[0]?.severity).toBe("Critical");
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("does not flag minimist once patched (1.2.6)", () => {
    expect(checkKnownDependencyCVEs({ minimist: "1.2.6" })).toEqual([]);
  });

  it("flags a vulnerable react-dom at review tier (approximate range)", () => {
    const findings = checkKnownDependencyCVEs({ "react-dom": "16.4.0" });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("DEP-CVE-2018-6341");
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("does not flag a supported react-dom (18.x) — the implicit negative", () => {
    expect(checkKnownDependencyCVEs({ "react-dom": "^18.3.1" })).toEqual([]);
  });

  it("strips a caret/tilde range prefix before matching", () => {
    expect(checkKnownDependencyCVEs({ minimist: "~1.2.5" })).toHaveLength(1);
  });

  it("encodes the manifest path and package name into the location", () => {
    const finding = checkKnownDependencyCVEs({ minimist: "1.2.5" }, "fixtures/legacy-app/package.json")[0];
    expect(finding?.location).toBe("fixtures/legacy-app/package.json (minimist)");
  });

  // Batch B10 (#71) — each crisp <fixed boundary fires high on the vulnerable pin and clears on the patch.
  it.each([
    ["jsonwebtoken", "8.5.1", "9.0.2", "DEP-CVE-2022-23540"],
    ["next-auth", "4.19.0", "4.24.12", "DEP-CVE-2023-27490"],
    ["next-auth", "4.24.5", "4.24.12", "DEP-GHSA-5jpx-9hw9-2fx4"],
    ["follow-redirects", "1.15.4", "1.15.6", "DEP-CVE-2024-28849"],
    ["axios", "1.7.2", "1.8.2", "DEP-CVE-2025-27152"],
    ["cookie", "0.5.0", "0.7.0", "DEP-CVE-2024-47764"],
    ["ws", "7.4.5", "7.4.6", "DEP-CVE-2021-32640"],
    ["sharp", "0.31.3", "0.32.6", "DEP-CVE-2023-4863"],
  ])("flags vulnerable %s@%s at high and clears the patched @%s", (name, vuln, patched, id) => {
    const hit = checkKnownDependencyCVEs({ [name]: vuln }).find((f) => f.id === id);
    expect(hit, `${name}@${vuln}`).toBeDefined();
    expect(hit?.precisionTier).toBe("high");
    expect(checkKnownDependencyCVEs({ [name]: patched }).map((f) => f.id)).not.toContain(id);
  });

  it("yields the two-CVE undici cluster on one vulnerable pin, both cleared by the patch", () => {
    const vuln = checkKnownDependencyCVEs({ undici: "5.7.0" }).map((f) => f.id);
    expect(vuln).toContain("DEP-CVE-2022-35949");
    expect(vuln).toContain("DEP-CVE-2024-24758");
    expect(checkKnownDependencyCVEs({ undici: "5.28.3" })).toEqual([]);
  });

  // #212: OSV puts the CVE-2022-35949 fix at 5.8.2, not 5.8.1 — 5.8.1 is still vulnerable.
  it("treats undici 5.8.1 as still vulnerable to the pathname SSRF (fixed in 5.8.2)", () => {
    expect(checkKnownDependencyCVEs({ undici: "5.8.1" }).map((f) => f.id)).toContain("DEP-CVE-2022-35949");
    expect(checkKnownDependencyCVEs({ undici: "5.8.2" }).map((f) => f.id)).not.toContain("DEP-CVE-2022-35949");
  });

  // #212: an unverifiable CVE id in a client report is credibility-fatal, so every curated entry
  // carries the OSV advisory its id and range were checked against, surfaced in the evidence.
  it("cites the OSV advisory it was verified against in the evidence", () => {
    const finding = checkKnownDependencyCVEs({ minimist: "1.2.5" })[0];
    expect(finding?.evidence).toContain("https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h");
  });

  it("scopes the ws range to the 7.x line so a patched 6.x isn't mis-flagged for a 7.4.6 fix", () => {
    expect(checkKnownDependencyCVEs({ ws: "6.2.2" }).map((f) => f.id)).not.toContain("DEP-CVE-2021-32640");
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
