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
//
// `precisionTier` here ("high" vs "review") is about confidence in the VERSION MATCH itself, a
// different axis from exploitability. Every "Dependency CVE" finding below is a version match
// only, so none set Finding.exploitabilityVerified, and the whole category stays out of the free
// grade (src/quick-scan.ts NON_GRADING_CATEGORIES, #213/#260). If a check is ever added here that
// independently confirms exploitability in the scanned codebase (not just a version overlap), set
// exploitabilityVerified: true on that finding so it grades correctly.

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

// Every curated range below was provenance-checked against OSV (api.osv.dev) on 2026-07-14 (#212):
// the advisory id resolves to a real record and the affected range matches OSV's, exactly.
// Re-verify before adding an entry — a hallucinated CVE id in a client report is credibility-fatal.

// CVE-2025-29927 — middleware auth bypass. https://osv.dev/vulnerability/GHSA-f82v-jwr5-mffw
const MIDDLEWARE_BYPASS_FIXED_BY_MAJOR: Record<number, string> = {
  12: "12.3.5",
  13: "13.5.9",
  14: "14.2.25",
  15: "15.2.3",
};

// CVE-2025-55182 — RSC/React-flight deserialization RCE (CVSS 10, CISA KEV 2025-12-05).
// https://osv.dev/vulnerability/GHSA-9qr9-h5gf-34mp (the Next.js advisory; the upstream React
// advisory is GHSA-fv66-9v8q-g76r). Fixed version per minor line, transcribed from that advisory's
// OSV affected ranges. The stable 14.x line is NOT affected — the range opens at 14.3.0-canary.77,
// so a released 14.2.x draws nothing here. Minor lines absent from this table are outside the
// advisory's ranges (not "unknown"), and are left to the general OSV pass rather than guessed at.
const RSC_RCE_FIXED_BY_MINOR: Record<string, string> = {
  "15.0": "15.0.5",
  "15.1": "15.1.9",
  "15.2": "15.2.6",
  "15.3": "15.3.6",
  "15.4": "15.4.8",
  "15.5": "15.5.7",
  "16.0": "16.0.7",
};

// EOL threshold: Next major lines below this no longer receive security patches. Flagged as
// "review" (not "high") since exact EOL cutoffs shift — confirm against Next's support policy
// before reporting as a hard fact.
const EOL_BELOW_MAJOR = 14;

// `manifestPath` is the manifest's path relative to the scanned root ("package.json" for the
// root manifest, "fixtures/<app>/package.json" for a secondary manifest), so a finding's
// location identifies WHICH manifest it came from — needed once more than one manifest is
// scanned (e.g. the calibration corpus's EOL/supported app fixtures).
export function checkNextVersionCVEs(installedVersion: string, manifestPath = "package.json"): Finding[] {
  const findings: Finding[] = [];
  const [major, minor] = parseVersion(installedVersion);
  const nextLocation = `${manifestPath} (next)`;

  const middlewareFix = MIDDLEWARE_BYPASS_FIXED_BY_MAJOR[major];
  if (middlewareFix && lt(installedVersion, middlewareFix)) {
    findings.push(
      mechanicalFinding({
        id: "DEP-CVE-2025-29927",
        title: `next@${installedVersion} vulnerable to CVE-2025-29927 (middleware auth bypass)`,
        severity: "Critical",
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: nextLocation,
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
        title: `next@${installedVersion} vulnerable to CVE-2025-55182 (React Server Components RCE)`,
        severity: "Critical",
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: nextLocation,
        evidence: `Installed next@${installedVersion} is below the fixed version ${rscFix} for the ${major}.${minor} line (GHSA-9qr9-h5gf-34mp, CVSS 10, CISA KEV added 2025-12-05).`,
        impact: "Pre-authentication remote code execution: Server Function endpoints unsafely deserialize an attacker-supplied React-flight payload. Affects App Router apps on the vulnerable range.",
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
        location: nextLocation,
        evidence: `Installed next@${installedVersion} falls in a vulnerable range for CVE-2026-44578 (GHSA-c4j6-fc7j-m34r, CVSS 8.6).`,
        impact: "Framework-level SSRF via WebSocket upgrade handling; self-hosted Node deployments only.",
        fix: "Upgrade next to >= 15.5.16 (15.x line) or >= 16.2.5 (16.x line).",
        precisionTier: "high",
      }),
    );
  }

  // CVE-2026-27978 — a cross-site request whose Origin header is absent (null) bypasses the Server
  // Actions origin check. https://osv.dev/vulnerability/GHSA-mq59-m269-xvcx — range >=16.0.1
  // <16.1.7, exactly as OSV states. A version in this range also (correctly) trips the RSC/WS-SSRF
  // ranges above; this is an additional, distinct finding, isolated in the corpus by its CVE id.
  // Severity Medium per the advisory's CVSS v4 MODERATE rating (attacker gains limited integrity
  // impact and it requires user interaction) — not the High the range's crispness might suggest.
  if (gte(installedVersion, "16.0.1") && lt(installedVersion, "16.1.7")) {
    findings.push(
      mechanicalFinding({
        id: "DEP-CVE-2026-27978",
        title: `next@${installedVersion} vulnerable to CVE-2026-27978 (Server Actions null-origin CSRF)`,
        severity: "Medium",
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: nextLocation,
        evidence: `Installed next@${installedVersion} falls in the CVE-2026-27978 range (>=16.0.1 <16.1.7, GHSA-mq59-m269-xvcx).`,
        impact: "A cross-site request with an absent (null) Origin header bypasses the Server Actions origin check, letting an attacker invoke authenticated Server Actions cross-site (CSRF).",
        fix: "Upgrade next to >= 16.1.7.",
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
        location: nextLocation,
        evidence: `Installed next major ${major} is below the ${EOL_BELOW_MAJOR}.x line still receiving security patches.`,
        impact: "No security patches for newly-discovered CVEs on this line; confirm current EOL status before treating as a hard commitment.",
        fix: `Upgrade to a supported next major (>= ${EOL_BELOW_MAJOR}).`,
        precisionTier: "review",
      }),
    );
  }

  return findings;
}

// Curated exact-range checks for named non-Next dependency CVEs, kept independent of OSV for
// the same reason as checkNextVersionCVEs: they read the DECLARED range from the manifest, so
// they fire without a resolved lockfile and without OSV's DB, and they carry a hand-written
// exploitability narrative. Each entry is a well-documented CVE with a clean affected range.
// `tier` is "high" only when the affected range is crisp (a single "< fixed" boundary, no
// backported-patch exceptions); an approximate range stays "review" per the free-count doctrine.
interface CuratedDepCve {
  name: string;
  introduced?: string; // inclusive lower bound; omitted = all versions below `fixed`
  fixed: string; // exclusive upper bound (first patched version)
  id: string;
  severity: Severity;
  tier: "high" | "review";
  summary: string;
  fix: string;
  // OSV advisory URL the id and range were verified against (#212). Carried into the finding's
  // evidence so a client can check our provenance rather than take the CVE id on faith.
  source: string;
}

const CURATED_DEP_CVES: CuratedDepCve[] = [
  {
    name: "minimist",
    fixed: "1.2.6",
    id: "CVE-2021-44906",
    severity: "Critical",
    tier: "high",
    summary: "Prototype pollution (CVSS 9.8): a crafted argv key like `--__proto__.x` pollutes Object.prototype, corrupting every object in the process.",
    fix: "Upgrade minimist to >= 1.2.6.",
    source: "https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h",
  },
  {
    name: "react-dom",
    introduced: "16.0.0",
    fixed: "16.4.2",
    id: "CVE-2018-6341",
    severity: "Medium",
    tier: "review",
    summary: "Cross-site scripting via ReactDOMServer when rendering an attacker-controlled attribute name. Range is approximate — the backported patch releases 16.0.1/16.1.2/16.2.1/16.3.3 sit inside the affected majors but are fixed, so this stays review-tier.",
    fix: "Upgrade react-dom to >= 16.4.2 (or the backported patch for your minor line).",
    source: "https://osv.dev/vulnerability/GHSA-mvjj-gqq2-p4hw",
  },
  // --- Batch B10 (#71) — dependency-CVE breadth (docs/design/corpus-roadmap-to-100.md §3b). Each
  // is a single crisp "< fixed" boundary (some scoped to a major line via `introduced` where older
  // majors have their own fix, keeping the range unambiguous) → high. ---
  {
    name: "jsonwebtoken",
    fixed: "9.0.0",
    id: "CVE-2022-23540",
    severity: "High",
    tier: "high",
    summary: "jwt.verify() with no `algorithms` option defaults to accepting `none` / a caller-controlled algorithm, allowing signature-verification bypass (GHSA-qwph-4952-7xr6). All versions below 9.0.0 are affected; 9.0.0 makes `algorithms` mandatory.",
    fix: "Upgrade jsonwebtoken to >= 9.0.0 and pass an explicit `algorithms` allowlist to jwt.verify().",
    source: "https://osv.dev/vulnerability/GHSA-qwph-4952-7xr6",
  },
  {
    name: "next-auth",
    introduced: "4.0.0",
    fixed: "4.20.1",
    id: "CVE-2023-27490",
    severity: "Medium",
    tier: "high",
    summary: "OAuth sign-in CSRF: a missing/replayed state check lets an attacker link a victim's session to the attacker's OAuth account (GHSA-7r7x-4c4q-c4qf). The 4.x line is affected below 4.20.1.",
    fix: "Upgrade next-auth to >= 4.20.1.",
    source: "https://osv.dev/vulnerability/GHSA-7r7x-4c4q-c4qf",
  },
  {
    name: "next-auth",
    introduced: "4.0.0",
    fixed: "4.24.12",
    id: "GHSA-5jpx-9hw9-2fx4",
    severity: "Medium",
    tier: "high",
    summary: "Email-provider sign-in misdelivery: a crafted address like `\"e@attacker.com\"@victim.com` is mis-parsed and the magic-link email is delivered to the attacker's mailbox, an authentication bypass. The 4.x line is affected below 4.24.12.",
    fix: "Upgrade next-auth to >= 4.24.12 (and nodemailer to >= 7.0.7).",
    source: "https://osv.dev/vulnerability/GHSA-5jpx-9hw9-2fx4",
  },
  {
    name: "follow-redirects",
    fixed: "1.15.6",
    id: "CVE-2024-28849",
    severity: "Medium",
    tier: "high",
    summary: "The Proxy-Authorization header is not cleared on a cross-origin redirect, leaking proxy credentials to the redirect target. All versions below 1.15.6 are affected.",
    fix: "Upgrade follow-redirects to >= 1.15.6.",
    source: "https://osv.dev/vulnerability/GHSA-cxjh-pqwp-8mfp",
  },
  {
    name: "axios",
    introduced: "1.0.0",
    fixed: "1.8.2",
    id: "CVE-2025-27152",
    severity: "High",
    tier: "high",
    summary: "An absolute request URL overrides a configured `baseURL`, so attacker-controlled input in the path leads to SSRF and credential leakage (GHSA-jr5f-v2jv-69x6). The 1.x line is affected below 1.8.2.",
    fix: "Upgrade axios to >= 1.8.2.",
    source: "https://osv.dev/vulnerability/GHSA-jr5f-v2jv-69x6",
  },
  {
    name: "undici",
    introduced: "5.0.0",
    fixed: "5.8.2",
    id: "CVE-2022-35949",
    severity: "High",
    tier: "high",
    summary: "SSRF via an absolute URL supplied on `pathname`: `undici.request` sends the request to the absolute host instead of resolving against the intended origin (GHSA-8qr4-xgw6-wmr3). The 5.x line is affected below the 5.8.2 fix.",
    fix: "Upgrade undici to >= 5.8.2.",
    source: "https://osv.dev/vulnerability/GHSA-8qr4-xgw6-wmr3",
  },
  {
    name: "undici",
    introduced: "5.0.0",
    fixed: "5.28.3",
    id: "CVE-2024-24758",
    severity: "Medium",
    tier: "high",
    summary: "The Proxy-Authorization header is not cleared on a cross-origin redirect, leaking proxy credentials to the redirect target (GHSA-3787-6prv-h9w3). The 5.x line is affected below 5.28.3.",
    fix: "Upgrade undici to >= 5.28.3.",
    source: "https://osv.dev/vulnerability/GHSA-3787-6prv-h9w3",
  },
  {
    name: "cookie",
    fixed: "0.7.0",
    id: "CVE-2024-47764",
    severity: "Low",
    tier: "high",
    summary: "Out-of-bounds characters in a cookie name/path/domain let a caller inject additional cookie fields (field injection). All versions below 0.7.0 are affected.",
    fix: "Upgrade cookie to >= 0.7.0.",
    source: "https://osv.dev/vulnerability/GHSA-pxg6-pf52-xh8x",
  },
  {
    name: "ws",
    introduced: "7.0.0",
    fixed: "7.4.6",
    id: "CVE-2021-32640",
    severity: "High",
    tier: "high",
    summary: "ReDoS: a crafted `Sec-Websocket-Protocol` header value triggers catastrophic backtracking, stalling the server (GHSA-6fc8-4gx4-v693). The 7.x line is affected below 7.4.6.",
    fix: "Upgrade ws to >= 7.4.6.",
    source: "https://osv.dev/vulnerability/GHSA-6fc8-4gx4-v693",
  },
  {
    name: "sharp",
    fixed: "0.32.6",
    id: "CVE-2023-4863",
    severity: "High",
    tier: "high",
    summary: "The bundled libwebp (< 1.3.2) has a heap buffer overflow decoding a crafted WebP image, enabling RCE/DoS on image processing (GHSA-54xq-cgqr-rpm3). sharp below 0.32.6 ships the vulnerable libwebp.",
    fix: "Upgrade sharp to >= 0.32.6 (bundles libwebp >= 1.3.2).",
    source: "https://osv.dev/vulnerability/GHSA-54xq-cgqr-rpm3",
  },
];

// Every hardcoded advisory claim in this file, as data an automated check can re-verify against
// OSV (#247). The curated tables above stay the source of truth for scanning; this list restates
// their (advisory, package, fixed-boundary) triples so src/cli/osv-staleness.ts can assert each
// advisory still exists and still names the fix boundary we hardcode.
//
// The verified fact is the FIXED boundary, deliberately not the whole range. It is the boundary
// every check here actually branches on, and it is what #212 caught: the fabricated "14.2 fixed in
// 14.2.35" row asserted a fix version the advisory has never listed. The `introduced` edges are
// intentionally NOT asserted — several curated ranges are knowingly coarser or narrower than OSV's
// (react-dom's is approximate and review-tiered for that reason; the next-auth/undici rows scope to
// one major line), and a narrower range under-flags rather than fabricating a vulnerability. See
// #271 for the coverage gaps that scoping leaves.
export interface CuratedClaim {
  advisory: string; // OSV id to query (GHSA preferred — the record CVE ids alias to)
  pkg: string;
  fixed: string; // first patched version; OSV must list this as a `fixed` event for `pkg`
  note: string;
}

export const CURATED_CLAIMS: CuratedClaim[] = [
  ...Object.entries(MIDDLEWARE_BYPASS_FIXED_BY_MAJOR).map(([major, fixed]) => ({
    advisory: "GHSA-f82v-jwr5-mffw",
    pkg: "next",
    fixed,
    note: `CVE-2025-29927 middleware auth bypass, ${major}.x line`,
  })),
  ...Object.entries(RSC_RCE_FIXED_BY_MINOR).map(([minor, fixed]) => ({
    advisory: "GHSA-9qr9-h5gf-34mp",
    pkg: "next",
    fixed,
    note: `CVE-2025-55182 RSC RCE, ${minor} line`,
  })),
  { advisory: "GHSA-mq59-m269-xvcx", pkg: "next", fixed: "16.1.7", note: "CVE-2026-27978 Server Actions null-origin CSRF" },
  { advisory: "GHSA-c4j6-fc7j-m34r", pkg: "next", fixed: "15.5.16", note: "CVE-2026-44578 WebSocket-upgrade SSRF, 13.4-15.5 line" },
  { advisory: "GHSA-c4j6-fc7j-m34r", pkg: "next", fixed: "16.2.5", note: "CVE-2026-44578 WebSocket-upgrade SSRF, 16.x line" },
  ...CURATED_DEP_CVES.map((c) => ({
    advisory: /^GHSA-/.test(c.id) ? c.id : c.source.replace(/^.*\/vulnerability\//, ""),
    pkg: c.name,
    fixed: c.fixed,
    note: `${c.id} — ${c.name}`,
  })),
];

export function checkKnownDependencyCVEs(deps: Record<string, string>, manifestPath = "package.json"): Finding[] {
  const findings: Finding[] = [];
  for (const cve of CURATED_DEP_CVES) {
    const declared = deps[cve.name];
    if (!declared) continue;
    const version = declared.replace(/^[\^~]/, "");
    const inRange = (cve.introduced ? gte(version, cve.introduced) : true) && lt(version, cve.fixed);
    if (!inRange) continue;
    findings.push(
      mechanicalFinding({
        id: `DEP-${cve.id}`,
        title: `${cve.name}@${version} vulnerable to ${cve.id}`,
        severity: cve.severity,
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: `${manifestPath} (${cve.name})`,
        evidence: `Declared ${cve.name}@${declared} falls in the ${cve.id} affected range (${cve.introduced ? `>= ${cve.introduced} ` : ""}< ${cve.fixed}), per ${cve.source}.`,
        impact: cve.summary,
        fix: cve.fix,
        precisionTier: cve.tier,
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
const CURATED_ADVISORY_IDS = new Set([
  "GHSA-f82v-jwr5-mffw", // CVE-2025-29927 middleware auth bypass
  "GHSA-9qr9-h5gf-34mp", // CVE-2025-55182 RSC RCE (Next.js advisory)
  "GHSA-fv66-9v8q-g76r", // CVE-2025-55182 RSC RCE (upstream React advisory — same vuln, so an OSV
  // hit on a react-server-dom-* package is the same finding we already report against next
  "GHSA-c4j6-fc7j-m34r", // CVE-2026-44578 WebSocket-upgrade SSRF
  "GHSA-mq59-m269-xvcx", // CVE-2026-27978 Server Actions null-origin CSRF
]);

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
