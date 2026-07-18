import { describe, expect, it } from "vitest";
import {
  assertDisclosedDivergence,
  checkKnownDependencyCVEs,
  checkNextVersionCVEs,
  type CuratedDepCve,
  CURATED_CLAIMS,
  osvUnavailableFinding,
  parseOsvFindings,
  type OsvScanResult,
} from "./dependencies.js";

// The staleness check (src/cli/osv-staleness.ts, #247) verifies CURATED_CLAIMS against OSV over the
// network, so it can't run in verify. These offline tests guard the list it reads: an advisory
// whose claim silently vanishes would never be re-verified again.
describe("CURATED_CLAIMS (the OSV-verifiable restatement of the curated corpus)", () => {
  it("carries a real advisory id and fix boundary for every claim", () => {
    for (const claim of CURATED_CLAIMS) {
      expect(claim.advisory, claim.note).toMatch(/^GHSA-/);
      expect(claim.fixed, claim.note).toMatch(/^\d+\.\d+\.\d+/);
      expect(claim.pkg, claim.note).not.toBe("");
    }
  });

  // The #212 regression: the corpus asserted an RSC-RCE fix on the 14.2 line. No released 14.x is
  // affected (GHSA-9qr9-h5gf-34mp opens at 14.3.0-canary.77), so no 14.x fix may be claimed.
  it("claims no RSC-RCE fix on any next 14.x line", () => {
    const rsc = CURATED_CLAIMS.filter((c) => c.advisory === "GHSA-9qr9-h5gf-34mp");
    expect(rsc.length).toBeGreaterThan(0);
    expect(rsc.filter((c) => c.fixed.startsWith("14."))).toEqual([]);
  });

  // #271: a multi-range entry asserts a fix per line. Restating only one would leave the other
  // boundary hardcoded but never re-verified against OSV — the gap that let #212 ship.
  it("restates every range of a multi-range advisory, so no boundary goes unverified", () => {
    const fixesFor = (advisory: string, pkg: string) => CURATED_CLAIMS.filter((c) => c.advisory === advisory && c.pkg === pkg).map((c) => c.fixed);
    expect(fixesFor("GHSA-xvch-5gv4-984h", "minimist")).toEqual(expect.arrayContaining(["0.2.4", "1.2.6"]));
    expect(fixesFor("GHSA-5jpx-9hw9-2fx4", "next-auth")).toEqual(expect.arrayContaining(["4.24.12", "5.0.0-beta.30"]));
    expect(fixesFor("GHSA-3787-6prv-h9w3", "undici")).toEqual(expect.arrayContaining(["5.28.3", "6.6.1"]));
    // #292: axios's older 0.x line and ws's older 6.x/5.x lines each get their own claim.
    expect(fixesFor("GHSA-jr5f-v2jv-69x6", "axios")).toEqual(expect.arrayContaining(["0.30.0", "1.8.2"]));
    expect(fixesFor("GHSA-6fc8-4gx4-v693", "ws")).toEqual(expect.arrayContaining(["5.2.3", "6.2.2", "7.4.6"]));
  });

  it("restates every curated Next.js fix boundary, so none goes unverified", () => {
    const nextFixes = CURATED_CLAIMS.filter((c) => c.pkg === "next").map((c) => c.fixed);
    // The middleware-bypass table's four lines plus the seven RSC minors.
    expect(nextFixes).toEqual(expect.arrayContaining(["12.3.5", "13.5.9", "14.2.25", "15.2.3", "15.0.5", "16.0.7"]));
  });
});

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

// The prerelease comparator (#271) is only reachable through the curated ranges, but it decides
// whether a beta pin is flagged at all — so the semver §11 rules it rests on get asserted directly
// via the one curated entry that bounds a prerelease line (next-auth's 5.0.0-beta range).
describe("prerelease version ordering", () => {
  const vulnerable = (v: string) => checkKnownDependencyCVEs({ "next-auth": v }).some((f) => f.id === "DEP-GHSA-5jpx-9hw9-2fx4");

  it("orders numeric prerelease identifiers numerically, not as strings", () => {
    // The string compare that "beta.9" > "beta.30" would produce puts beta.9 outside the range.
    expect(vulnerable("5.0.0-beta.9"), "5.0.0-beta.9 < 5.0.0-beta.30").toBe(true);
    expect(vulnerable("5.0.0-beta.100"), "5.0.0-beta.100 > 5.0.0-beta.30").toBe(false);
  });

  it("ranks a release above its own prereleases, keeping a stable 5.0.0 out of the beta range", () => {
    expect(vulnerable("5.0.0")).toBe(false);
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

  // #271: GHSA-xvch-5gv4-984h has two disjoint ranges — 0.x below 0.2.4 and 1.x below 1.2.6. The
  // old unbounded "< 1.2.6" got BOTH edges wrong: it missed 0.x entirely (under-flag) and, once
  // widened naively, would call the patched 0.2.4 vulnerable (the #212 fabrication shape).
  it.each([
    ["0.0.8", true],
    ["0.2.3", true],
    ["0.2.4", false], // the 0.x line's own fix — vulnerable only BELOW it
    ["1.0.0", true],
  ])("matches OSV's two minimist ranges: 0.x %s vulnerable=%s", (version, vulnerable) => {
    const ids = checkKnownDependencyCVEs({ minimist: version }).map((f) => f.id);
    expect(ids.includes("DEP-CVE-2021-44906"), `minimist@${version}`).toBe(vulnerable);
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

  it("does not flag a patched 6.x ws (6.2.2) against the 7.4.6 fix on the maintained line", () => {
    expect(checkKnownDependencyCVEs({ ws: "6.2.2" }).map((f) => f.id)).not.toContain("DEP-CVE-2021-32640");
  });

  // #292: OSV lists three disjoint ws lines (5.x, 6.x, 7.x), each with its own fix. The old
  // single-range "7.x only" entry under-flagged a vulnerable 5.x/6.x pin entirely.
  it.each([
    ["4.9.9", false], // below OSV's asserted 5.x floor — not part of this advisory's ranges
    ["5.0.0", true],
    ["5.2.2", true],
    ["5.2.3", false], // the 5.x line's own fix
    ["6.0.0", true],
    ["6.2.1", true],
    ["6.2.2", false], // the 6.x line's own fix
    ["7.4.5", true],
    ["7.4.6", false], // the 7.x line's own fix
  ])("matches OSV's three ws ranges: %s vulnerable=%s", (version, vulnerable) => {
    const ids = checkKnownDependencyCVEs({ ws: version }).map((f) => f.id);
    expect(ids.includes("DEP-CVE-2021-32640"), `ws@${version}`).toBe(vulnerable);
  });

  // #292: OSV's axios 0.x range is unbounded below (introduced "0"), same as minimist's 0.x line.
  it.each([
    ["0.0.1", true],
    ["0.29.1", true],
    ["0.30.0", false], // the 0.x line's own fix
    ["1.0.0", true],
    ["1.8.1", true],
    ["1.8.2", false], // the 1.x line's own fix
  ])("matches OSV's two axios ranges: %s vulnerable=%s", (version, vulnerable) => {
    const ids = checkKnownDependencyCVEs({ axios: version }).map((f) => f.id);
    expect(ids.includes("DEP-CVE-2025-27152"), `axios@${version}`).toBe(vulnerable);
  });

  // #271: both advisories list an unbounded range, so a pre-4.x next-auth is affected too — the
  // old `introduced: "4.0.0"` scoping silently missed it.
  it("flags a next-auth below the 4.x line, which OSV's unbounded range covers", () => {
    const ids = checkKnownDependencyCVEs({ "next-auth": "3.29.0" }).map((f) => f.id);
    expect(ids).toContain("DEP-CVE-2023-27490");
    expect(ids).toContain("DEP-GHSA-5jpx-9hw9-2fx4");
  });

  // #271: GHSA-5jpx also affects the v5 beta line below beta.30. This needs prerelease-aware
  // comparison — on a numeric-triple-only compare every 5.0.0-beta.x collapses to 5.0.0 and the
  // range can never match.
  it.each([
    ["5.0.0-beta.0", true],
    ["5.0.0-beta.29", true],
    ["5.0.0-beta.30", false], // the beta line's own fix
    ["5.0.0-beta.31", false],
  ])("tracks the next-auth 5.0.0-beta line: %s vulnerable=%s", (version, vulnerable) => {
    const ids = checkKnownDependencyCVEs({ "next-auth": version }).map((f) => f.id);
    expect(ids.includes("DEP-GHSA-5jpx-9hw9-2fx4"), `next-auth@${version}`).toBe(vulnerable);
  });

  // #271: the two undici CVEs diverge above 5.x — CVE-2024-24758 has a 6.x range (fixed 6.6.1),
  // CVE-2022-35949 does NOT. Asserting a 6.x range for both would fabricate a finding on 6.x.
  it.each([
    ["6.6.0", true],
    ["6.6.1", false],
  ])("flags undici 6.x for the proxy-auth leak only: %s vulnerable=%s", (version, vulnerable) => {
    const ids = checkKnownDependencyCVEs({ undici: version }).map((f) => f.id);
    expect(ids.includes("DEP-CVE-2024-24758"), `undici@${version}`).toBe(vulnerable);
    expect(ids, `undici@${version} is outside CVE-2022-35949's range (< 5.8.2)`).not.toContain("DEP-CVE-2022-35949");
  });

  // The evidence must cite the range that actually matched, not the entry's first one — a 6.x
  // finding citing "< 5.28.3" would be self-contradicting to the client reading the report.
  it("cites the specific matched range in the evidence for a multi-range entry", () => {
    const finding = checkKnownDependencyCVEs({ undici: "6.6.0" }).find((f) => f.id === "DEP-CVE-2024-24758");
    expect(finding?.evidence).toContain(">= 6.0.0 < 6.6.1");
  });
});

// #255: a curated severity may diverge from OSV's own database_specific rating when we have a
// reasoned basis, but the divergence must never ship silently. assertDisclosedDivergence is the
// mechanical guard; these tests exercise it directly rather than only asserting the current
// corpus is clean, so a future entry that re-rates without disclosing fails here first.
describe("assertDisclosedDivergence (#255 — diverge, but disclose)", () => {
  const base: CuratedDepCve = {
    name: "example-pkg",
    ranges: [{ fixed: "2.0.0" }],
    id: "CVE-0000-00000",
    severity: "High",
    tier: "high",
    summary: "test fixture",
    fix: "upgrade",
    source: "https://osv.dev/vulnerability/GHSA-0000-0000-0000",
  };

  it("passes an entry with no osvSeverity set (no claimed divergence)", () => {
    expect(() => assertDisclosedDivergence(base)).not.toThrow();
  });

  it("passes an entry whose divergence carries a reason", () => {
    expect(() =>
      assertDisclosedDivergence({ ...base, osvSeverity: "Medium", divergenceReason: "auth-focused context raises impact" }),
    ).not.toThrow();
  });

  it("throws when osvSeverity diverges from severity with no divergenceReason", () => {
    expect(() => assertDisclosedDivergence({ ...base, osvSeverity: "Medium" })).toThrow(/requires disclosure/);
  });

  it("throws when divergenceReason is only whitespace", () => {
    expect(() => assertDisclosedDivergence({ ...base, osvSeverity: "Medium", divergenceReason: "   " })).toThrow(/requires disclosure/);
  });

  it("throws when osvSeverity is set equal to severity (not an actual divergence)", () => {
    expect(() => assertDisclosedDivergence({ ...base, osvSeverity: "High", divergenceReason: "redundant" })).toThrow(/not a divergence/);
  });
});

describe("jsonwebtoken CVE-2022-23540 severity disclosure (#255)", () => {
  it("rates the finding High while disclosing OSV's Moderate rating and the reason", () => {
    const finding = checkKnownDependencyCVEs({ jsonwebtoken: "8.5.1" }).find((f) => f.id === "DEP-CVE-2022-23540");
    expect(finding?.severity).toBe("High");
    expect(finding?.evidence).toContain("Harvey rates this High; OSV rates Medium because");
  });

  it("does not append a divergence disclosure to a non-diverging entry (minimist)", () => {
    const finding = checkKnownDependencyCVEs({ minimist: "1.2.5" }).find((f) => f.id === "DEP-CVE-2021-44906");
    expect(finding?.evidence).not.toContain("Harvey rates this");
  });

  // #255 corpus audit: these four entries were unexplained drift (no reasoned basis recorded),
  // so they were aligned to OSV's own rating rather than kept-and-disclosed like jsonwebtoken.
  it.each([
    ["next-auth", "4.19.0", "DEP-CVE-2023-27490", "High"],
    ["undici", "5.7.0", "DEP-CVE-2022-35949", "Medium"],
    ["undici", "5.7.0", "DEP-CVE-2024-24758", "Low"],
    ["ws", "7.4.5", "DEP-CVE-2021-32640", "Medium"],
  ])("%s@%s (%s) is aligned to OSV's severity (%s), no disclosure needed", (name, vuln, id, severity) => {
    const finding = checkKnownDependencyCVEs({ [name]: vuln }).find((f) => f.id === id);
    expect(finding?.severity).toBe(severity);
    expect(finding?.evidence).not.toContain("Harvey rates this");
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

// #512: an osv-scanner that could not run at all previously degraded to an EMPTY result — every
// deliverable then read "zero vulnerable dependencies" instead of "the CVE pass did not run".
// mechanical.ts now substitutes this disclosure finding, same contract as M5-00/M7L-00/M8-00.
describe("osvUnavailableFinding", () => {
  it("discloses the CVE-pass coverage gap without claiming zero vulnerable dependencies", () => {
    const finding = osvUnavailableFinding("osv-scanner not found on PATH");
    expect(finding.id).toBe("DEP-OSV-00");
    expect(finding.severity).toBe("Info");
    expect(finding.confidence).toBe("N/A");
    expect(finding.evidence).toContain("osv-scanner not found on PATH");
    expect(finding.impact).toContain("incomplete");
    expect(finding.impact).toContain("not a finding of zero vulnerable dependencies");
  });
});
