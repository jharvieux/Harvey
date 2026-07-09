// Framework/dependency CVEs: OSV-Scanner over the lockfile, plus curated exact-range checks
// for the named Next.js CVEs from docs/design/scan-coverage-gaps.md §2 (kept independent of
// OSV so a lagging OSV database doesn't silently drop the highest-severity checks).
//
// OSV-Scanner is an external CLI binary, not an npm dependency. Install:
//   https://google.github.io/osv-scanner/installation/ (or `brew install osv-scanner`)
//
// Invocation (from the target repo root):
//   osv-scanner --format json --lockfile pnpm-lock.yaml    (or package-lock.json / yarn.lock)
//
// Trust boundary: a vulnerability whose id/alias is one of the curated CVEs below is already
// reported by checkNextVersionCVEs with a hand-written exploitability narrative, so an OSV hit
// against one of them is a duplicate of that finding and is dropped here (see
// CURATED_ADVISORY_IDS / dedup in parseOsvFindings). Every other OSV hit is "review" — a version
// match isn't proof of exploitability (deployment context, e.g. self-hosted vs. Vercel, matters).

import type { Finding, Severity } from "../findings.js";
import { mechanicalFinding } from "./common.js";

function parseVersion(v: string): [number, number, number] {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(v);
  if (!m) return [0, 0, 0];
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function cmp(a: string, b: string): number {
  const [a1, a2, a3] = parseVersion(a);
  const [b1, b2, b3] = parseVersion(b);
  return a1 - b1 || a2 - b2 || a3 - b3;
}

const lt = (a: string, b: string): boolean => cmp(a, b) < 0;
const gte = (a: string, b: string): boolean => cmp(a, b) >= 0;

// Fixed version per major line for CVE-2025-29927 (middleware auth bypass, GHSA-f82v-jwr5-mffw).
const MIDDLEWARE_BYPASS_FIXED_BY_MAJOR: Record<number, string> = {
  12: "12.3.5",
  13: "13.5.9",
  14: "14.2.25",
  15: "15.2.3",
};

// Fixed version per minor line for CVE-2025-55182/66478 "React2Shell" RSC RCE (CVSS 10, KEV).
// Minor lines not listed here (pre-14.2, or newer than the table) are left to the general OSV
// pass rather than guessed at.
const RSC_RCE_FIXED_BY_MINOR: Record<string, string> = {
  "14.2": "14.2.35",
  "15.0": "15.0.8",
  "15.1": "15.1.12",
  "15.2": "15.2.9",
  "15.3": "15.3.9",
  "15.4": "15.4.11",
  "15.5": "15.5.10",
  "16.0": "16.0.11",
  "16.1": "16.1.5",
};

// EOL threshold: Next major lines below this no longer receive security patches. Flagged as
// "review" (not "high") since exact EOL cutoffs shift — confirm against Next's support policy
// before reporting as a hard fact.
const EOL_BELOW_MAJOR = 14;

export function checkNextVersionCVEs(installedVersion: string): Finding[] {
  const findings: Finding[] = [];
  const [major, minor] = parseVersion(installedVersion);

  const middlewareFix = MIDDLEWARE_BYPASS_FIXED_BY_MAJOR[major];
  if (middlewareFix && lt(installedVersion, middlewareFix)) {
    findings.push(
      mechanicalFinding({
        id: "DEP-CVE-2025-29927",
        title: `next@${installedVersion} vulnerable to CVE-2025-29927 (middleware auth bypass)`,
        severity: "Critical",
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: "package.json (next)",
        evidence: `Installed next@${installedVersion} is below the fixed version ${middlewareFix} for the ${major}.x line. The x-middleware-subrequest header skips middleware entirely (GHSA-f82v-jwr5-mffw).`,
        impact: "If auth is enforced only in middleware.ts (the dominant pattern in vibe-coded apps) and the app is self-hosted (not Vercel, which is auto-patched), this is a full authorization bypass.",
        fix: `Upgrade next to >= ${middlewareFix}.`,
        precisionTier: "high",
      }),
    );
  }

  const rscFix = RSC_RCE_FIXED_BY_MINOR[`${major}.${minor}`];
  if (rscFix && lt(installedVersion, rscFix)) {
    findings.push(
      mechanicalFinding({
        id: "DEP-CVE-2025-55182",
        title: `next@${installedVersion} vulnerable to CVE-2025-55182/66478 "React2Shell" RSC RCE`,
        severity: "Critical",
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: "package.json (next)",
        evidence: `Installed next@${installedVersion} is below the fixed version ${rscFix} for the ${major}.${minor} line (GHSA-9qr9-h5gf-34mp, CVSS 10, CISA KEV).`,
        impact: "Remote code execution via React Server Components; affects nearly every App Router app on the vulnerable range.",
        fix: `Upgrade next to >= ${rscFix} (and react-server-dom-* to the matching fixed release).`,
        precisionTier: "high",
      }),
    );
  }

  const wsSSRFVulnerable =
    (gte(installedVersion, "13.4.13") && lt(installedVersion, "15.5.16")) ||
    (gte(installedVersion, "16.0.0") && lt(installedVersion, "16.2.5"));
  if (wsSSRFVulnerable) {
    findings.push(
      mechanicalFinding({
        id: "DEP-CVE-2026-44578",
        title: `next@${installedVersion} vulnerable to CVE-2026-44578 (WebSocket-upgrade SSRF)`,
        severity: "High",
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: "package.json (next)",
        evidence: `Installed next@${installedVersion} falls in a vulnerable range for GHSA-c4j6-fc7j-m34r (CVSS 8.6).`,
        impact: "Framework-level SSRF via WebSocket upgrade handling; self-hosted Node deployments only.",
        fix: "Upgrade next to >= 15.5.16 (15.x line) or >= 16.2.5 (16.x line).",
        precisionTier: "high",
      }),
    );
  }

  if (major > 0 && major < EOL_BELOW_MAJOR) {
    findings.push(
      mechanicalFinding({
        id: "DEP-NEXT-EOL",
        title: `next@${installedVersion} is on an end-of-life major version line`,
        severity: "Medium",
        category: "Dependency CVE",
        taxonomy: "EOL framework version",
        location: "package.json (next)",
        evidence: `Installed next major ${major} is below the ${EOL_BELOW_MAJOR}.x line still receiving security patches.`,
        impact: "No security patches for newly-discovered CVEs on this line; confirm current EOL status before treating as a hard commitment.",
        fix: `Upgrade to a supported next major (>= ${EOL_BELOW_MAJOR}).`,
        precisionTier: "review",
      }),
    );
  }

  return findings;
}

// OSV-Scanner --format json shape (subset used here).
export interface OsvScanResult {
  results?: {
    source?: { path?: string };
    packages?: {
      package?: { name?: string; version?: string; ecosystem?: string };
      vulnerabilities?: {
        id?: string;
        summary?: string;
        aliases?: string[];
        severity?: { type?: string; score?: string }[];
      }[];
    }[];
  }[];
}

// Advisory ids whose exploitability we've independently curated above (checkNextVersionCVEs) —
// the vuln identity (GHSA id, cross-referenced against OSV's id + aliases) that ties an OSV hit
// back to its curated finding. An OSV hit matching one of these is the SAME underlying CVE as
// the curated finding, not a distinct dependency issue, so parseOsvFindings drops it rather than
// double-reporting: the curated finding is richer (specific fix guidance, deployment-context
// impact) and stays the sole representative. This is a general rule keyed on advisory identity,
// not a one-off for any single GHSA — extend this set whenever a new CVE is added above.
const CURATED_ADVISORY_IDS = new Set(["GHSA-f82v-jwr5-mffw", "GHSA-9qr9-h5gf-34mp", "GHSA-c4j6-fc7j-m34r"]);

function severityFromCvss(score: string | undefined): Severity {
  const n = score ? Number(score.split("/")[0]) : NaN;
  if (!Number.isNaN(n)) {
    if (n >= 9) return "Critical";
    if (n >= 7) return "High";
    if (n >= 4) return "Medium";
    return "Low";
  }
  return "Medium";
}

export function parseOsvFindings(result: OsvScanResult): Finding[] {
  const findings: Finding[] = [];
  for (const src of result.results ?? []) {
    for (const pkg of src.packages ?? []) {
      const name = pkg.package?.name ?? "unknown package";
      const version = pkg.package?.version ?? "unknown version";
      for (const vuln of pkg.vulnerabilities ?? []) {
        const id = vuln.id ?? "unknown-id";
        const ids = new Set([id, ...(vuln.aliases ?? [])]);
        const curated = [...ids].some((a) => CURATED_ADVISORY_IDS.has(a));
        // Same underlying CVE as an already-curated checkNextVersionCVEs finding — drop the
        // OSV duplicate rather than double-reporting the same vuln under two ids.
        if (curated) continue;
        const cvssScore = vuln.severity?.find((s) => s.type === "CVSS_V3")?.score ?? vuln.severity?.[0]?.score;
        findings.push(
          mechanicalFinding({
            id: `DEP-OSV-${id}`,
            title: `${name}@${version}: ${vuln.summary ?? id}`,
            severity: severityFromCvss(cvssScore),
            category: "Dependency CVE",
            taxonomy: "Known-vulnerable dependency",
            location: `${src.source?.path ?? "lockfile"} (${name}@${version})`,
            evidence: `OSV-Scanner matched ${id}${vuln.aliases?.length ? ` (aliases: ${vuln.aliases.join(", ")})` : ""} against ${name}@${version}.`,
            impact: vuln.summary ?? "Known vulnerability in a resolved dependency version.",
            fix: `Upgrade ${name} past the vulnerable range (see ${id}).`,
            precisionTier: "review",
          }),
        );
      }
    }
  }
  return findings;
}
