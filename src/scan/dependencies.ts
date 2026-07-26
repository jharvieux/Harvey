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

// Semver §9/§11 prerelease ordering: 5.0.0-beta.2 < 5.0.0-beta.10 < 5.0.0. Needed because a curated
// range can bound a prerelease line (next-auth's 5.0.0-beta.x, #271) — comparing on the numeric
// triple alone collapses every beta to 5.0.0, which would make such a range silently un-matchable.
function prerelease(v: string): string[] {
  const m = /^v?\d+\.\d+\.\d+(?:-([0-9A-Za-z.-]+))?/.exec(v);
  return m?.[1] ? m[1].split(".") : [];
}

function cmpPrerelease(a: string[], b: string[]): number {
  // A version with no prerelease outranks one that has it: 5.0.0 > 5.0.0-beta.30.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i];
    const y = b[i];
    // A longer identifier list outranks its own prefix: beta.1 > beta.
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    // Numeric identifiers compare numerically and always rank below alphanumeric ones.
    if (xNum !== yNum) return xNum ? -1 : 1;
    const d = xNum ? Number(x) - Number(y) : x < y ? -1 : x > y ? 1 : 0;
    if (d !== 0) return d;
  }
  return 0;
}

function cmp(a: string, b: string): number {
  const [a1, a2, a3] = parseVersion(a);
  const [b1, b2, b3] = parseVersion(b);
  return a1 - b1 || a2 - b2 || a3 - b3 || cmpPrerelease(prerelease(a), prerelease(b));
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
        dependency: "next",
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
        dependency: "next",
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
        dependency: "next",
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
        dependency: "next",
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
        dependency: "next",
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
interface CuratedRange {
  introduced?: string; // inclusive lower bound; omitted = all versions below `fixed`
  fixed: string; // exclusive upper bound (first patched version)
}

export interface CuratedDepCve {
  name: string;
  // Every affected range OSV lists for this package, transcribed exactly. An advisory often has
  // more than one (a maintained line and an old line each get their own fix), and the ranges are
  // disjoint, so at most one matches a given version. Modelling only the newest line under-flags
  // the others; flattening them into one span over-flags the patched versions between them (#271).
  ranges: CuratedRange[];
  id: string;
  severity: Severity;
  tier: "high" | "review";
  summary: string;
  fix: string;
  // OSV advisory URL the id and range were verified against (#212). Carried into the finding's
  // evidence so a client can check our provenance rather than take the CVE id on faith.
  source: string;
  // Set ONLY when `severity` diverges from the advisory's own database_specific severity at
  // `source` (verified against api.osv.dev, not recalled — #255). Both fields are required
  // together: assertDisclosedDivergence below throws at import time if a divergent osvSeverity
  // has no reason, or if osvSeverity is set but equal to `severity` (not a divergence — remove
  // it). The operator ruling on #255 is "diverge, but disclose": a curated severity MAY differ
  // from OSV's when we have a reasoned basis, but the finding text must say so, never silently
  // re-rate. Prompted by CVE-2022-23540 shipping High against OSV's MODERATE with no disclosure.
  osvSeverity?: Severity;
  divergenceReason?: string;
}

// #255: throws at import time if any curated entry's divergence from OSV is unrecorded or
// mis-recorded, so a silent (or self-contradictory) re-rating can never ship.
export function assertDisclosedDivergence(cve: CuratedDepCve): void {
  if (cve.osvSeverity === undefined) return;
  if (cve.osvSeverity === cve.severity) {
    throw new Error(`${cve.id}: osvSeverity equals severity (${cve.severity}) — not a divergence, remove osvSeverity/divergenceReason`);
  }
  if (!cve.divergenceReason?.trim()) {
    throw new Error(`${cve.id}: severity (${cve.severity}) diverges from OSV's ${cve.osvSeverity} with no divergenceReason — #255 requires disclosure`);
  }
}

const CURATED_DEP_CVES: CuratedDepCve[] = [
  {
    name: "minimist",
    // Two disjoint lines, each with its own fix. 0.2.4 patched the 0.x line and is NOT vulnerable —
    // an unbounded "< 1.2.6" both missed 0.x below 0.2.4 and mis-flagged the patched 0.2.4 (#271).
    ranges: [{ fixed: "0.2.4" }, { introduced: "1.0.0", fixed: "1.2.6" }],
    id: "CVE-2021-44906",
    severity: "Critical",
    tier: "high",
    summary: "Prototype pollution (CVSS 9.8): a crafted argv key like `--__proto__.x` pollutes Object.prototype, corrupting every object in the process.",
    fix: "Upgrade minimist to >= 1.2.6 (or >= 0.2.4 on the 0.x line).",
    source: "https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h",
  },
  {
    name: "react-dom",
    ranges: [{ introduced: "16.0.0", fixed: "16.4.2" }],
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
    ranges: [{ fixed: "9.0.0" }],
    id: "CVE-2022-23540",
    severity: "High",
    tier: "high",
    summary: "jwt.verify() with no `algorithms` option defaults to accepting `none` / a caller-controlled algorithm, allowing signature-verification bypass (GHSA-qwph-4952-7xr6). All versions below 9.0.0 are affected; 9.0.0 makes `algorithms` mandatory.",
    fix: "Upgrade jsonwebtoken to >= 9.0.0 and pass an explicit `algorithms` allowlist to jwt.verify().",
    source: "https://osv.dev/vulnerability/GHSA-qwph-4952-7xr6",
    // #255 (originally raised as #212 follow-up): OSV's database_specific severity for this
    // advisory is MODERATE, re-verified against api.osv.dev on 2026-07-17. We keep High: an
    // undetected signature-verification bypass on the auth token itself is full account
    // takeover in Harvey's multi-tenant-auth context, worse than the advisory's general-purpose
    // rating assumes.
    osvSeverity: "Medium",
    divergenceReason: "a signature-verification bypass on the auth token is full account takeover in a multi-tenant-auth context, higher-impact than the advisory's general-purpose rating assumes",
  },
  {
    name: "next-auth",
    // OSV lists one unbounded range — every version below 4.20.1, not just the 4.x line (#271).
    ranges: [{ fixed: "4.20.1" }],
    id: "CVE-2023-27490",
    // Was "Medium"; corrected to match OSV's HIGH database_specific severity (#255 corpus
    // audit, verified against api.osv.dev on 2026-07-17). Unlike jsonwebtoken's CVE-2022-23540,
    // no reasoned basis for the old rating exists anywhere in this repo's history — it reads as
    // unexplained drift rather than a deliberate judgment call, so it is aligned rather than
    // kept-and-disclosed.
    severity: "High",
    tier: "high",
    summary: "OAuth sign-in CSRF: a missing/replayed state check lets an attacker link a victim's session to the attacker's OAuth account (GHSA-7r7x-4c4q-c4qf). Every version below 4.20.1 is affected.",
    fix: "Upgrade next-auth to >= 4.20.1.",
    source: "https://osv.dev/vulnerability/GHSA-7r7x-4c4q-c4qf",
  },
  {
    name: "next-auth",
    // The v5 beta line carries its own fix, so it is a second range rather than a widened first one:
    // a released 4.24.12+ must stay clean even though 5.0.0-beta.29 is still vulnerable (#271).
    ranges: [{ fixed: "4.24.12" }, { introduced: "5.0.0-beta.0", fixed: "5.0.0-beta.30" }],
    id: "GHSA-5jpx-9hw9-2fx4",
    severity: "Medium",
    tier: "high",
    summary: "Email-provider sign-in misdelivery: a crafted address like `\"e@attacker.com\"@victim.com` is mis-parsed and the magic-link email is delivered to the attacker's mailbox, an authentication bypass. Affects every version below 4.24.12 and the 5.0.0-beta line below beta.30.",
    fix: "Upgrade next-auth to >= 4.24.12 (or >= 5.0.0-beta.30 on the v5 beta line), and nodemailer to >= 7.0.7.",
    source: "https://osv.dev/vulnerability/GHSA-5jpx-9hw9-2fx4",
  },
  {
    name: "follow-redirects",
    ranges: [{ fixed: "1.15.6" }],
    id: "CVE-2024-28849",
    severity: "Medium",
    tier: "high",
    summary: "The Proxy-Authorization header is not cleared on a cross-origin redirect, leaking proxy credentials to the redirect target. All versions below 1.15.6 are affected.",
    fix: "Upgrade follow-redirects to >= 1.15.6.",
    source: "https://osv.dev/vulnerability/GHSA-cxjh-pqwp-8mfp",
  },
  {
    name: "axios",
    // Two disjoint lines, each with its own fix (#292, re-verified against OSV 2026-07-15). OSV's
    // 0.x event is `introduced: "0"` — no floor below it, same as minimist's 0.x line above — so it
    // stays unbounded rather than carrying a redundant `introduced: "0"`.
    ranges: [{ fixed: "0.30.0" }, { introduced: "1.0.0", fixed: "1.8.2" }],
    id: "CVE-2025-27152",
    severity: "High",
    tier: "high",
    summary: "An absolute request URL overrides a configured `baseURL`, so attacker-controlled input in the path leads to SSRF and credential leakage (GHSA-jr5f-v2jv-69x6). Affects every version below 0.30.0 on the 0.x line and the 1.x line below 1.8.2.",
    fix: "Upgrade axios to >= 1.8.2 (or >= 0.30.0 on the 0.x line).",
    source: "https://osv.dev/vulnerability/GHSA-jr5f-v2jv-69x6",
  },
  {
    name: "undici",
    // One unbounded range below 5.8.2 — no 6.x range, unlike CVE-2024-24758 below (#271).
    ranges: [{ fixed: "5.8.2" }],
    id: "CVE-2022-35949",
    // Was "High"; corrected to match OSV's MODERATE database_specific severity (#255 corpus
    // audit, verified against api.osv.dev on 2026-07-17) — same unexplained-drift reasoning as
    // CVE-2023-27490 above.
    severity: "Medium",
    tier: "high",
    summary: "SSRF via an absolute URL supplied on `pathname`: `undici.request` sends the request to the absolute host instead of resolving against the intended origin (GHSA-8qr4-xgw6-wmr3). Every version below 5.8.2 is affected.",
    fix: "Upgrade undici to >= 5.8.2.",
    source: "https://osv.dev/vulnerability/GHSA-8qr4-xgw6-wmr3",
  },
  {
    name: "undici",
    // The 6.x line has its own fix, so a patched 5.28.3 must not be swept up by the 6.6.1 boundary.
    ranges: [{ fixed: "5.28.3" }, { introduced: "6.0.0", fixed: "6.6.1" }],
    id: "CVE-2024-24758",
    // Was "Medium"; corrected to match OSV's LOW database_specific severity (#255 corpus audit,
    // verified against api.osv.dev on 2026-07-17) — same unexplained-drift reasoning as
    // CVE-2023-27490 above.
    severity: "Low",
    tier: "high",
    summary: "The Proxy-Authorization header is not cleared on a cross-origin redirect, leaking proxy credentials to the redirect target (GHSA-3787-6prv-h9w3). Affects every version below 5.28.3 and the 6.x line below 6.6.1.",
    fix: "Upgrade undici to >= 5.28.3 (or >= 6.6.1 on the 6.x line).",
    source: "https://osv.dev/vulnerability/GHSA-3787-6prv-h9w3",
  },
  {
    name: "cookie",
    ranges: [{ fixed: "0.7.0" }],
    id: "CVE-2024-47764",
    severity: "Low",
    tier: "high",
    summary: "Out-of-bounds characters in a cookie name/path/domain let a caller inject additional cookie fields (field injection). All versions below 0.7.0 are affected.",
    fix: "Upgrade cookie to >= 0.7.0.",
    source: "https://osv.dev/vulnerability/GHSA-pxg6-pf52-xh8x",
  },
  {
    name: "ws",
    // Three disjoint lines, each with its own fix (#292, re-verified against OSV 2026-07-15). Unlike
    // axios/minimist's 0.x lines, OSV bounds the 5.x line at `introduced: "5.0.0"` (not "0") — it
    // does not assert anything about ws below 5.0.0, so that floor is kept rather than dropped.
    ranges: [
      { introduced: "5.0.0", fixed: "5.2.3" },
      { introduced: "6.0.0", fixed: "6.2.2" },
      { introduced: "7.0.0", fixed: "7.4.6" },
    ],
    id: "CVE-2021-32640",
    // Was "High"; corrected to match OSV's MODERATE database_specific severity (#255 corpus
    // audit, verified against api.osv.dev on 2026-07-17) — same unexplained-drift reasoning as
    // CVE-2023-27490 above.
    severity: "Medium",
    tier: "high",
    summary: "ReDoS: a crafted `Sec-Websocket-Protocol` header value triggers catastrophic backtracking, stalling the server (GHSA-6fc8-4gx4-v693). Affects the 5.x line below 5.2.3, the 6.x line below 6.2.2, and the 7.x line below 7.4.6.",
    fix: "Upgrade ws to >= 7.4.6 (or >= 6.2.2 / >= 5.2.3 on the 6.x / 5.x lines).",
    source: "https://osv.dev/vulnerability/GHSA-6fc8-4gx4-v693",
  },
  {
    name: "sharp",
    ranges: [{ fixed: "0.32.6" }],
    id: "CVE-2023-4863",
    severity: "High",
    tier: "high",
    summary: "The bundled libwebp (< 1.3.2) has a heap buffer overflow decoding a crafted WebP image, enabling RCE/DoS on image processing (GHSA-54xq-cgqr-rpm3). sharp below 0.32.6 ships the vulnerable libwebp.",
    fix: "Upgrade sharp to >= 0.32.6 (bundles libwebp >= 1.3.2).",
    source: "https://osv.dev/vulnerability/GHSA-54xq-cgqr-rpm3",
  },
];

for (const cve of CURATED_DEP_CVES) assertDisclosedDivergence(cve);

// Every hardcoded advisory claim in this file, as data an automated check can re-verify against
// OSV (#247). The curated tables above stay the source of truth for scanning; this list restates
// their (advisory, package, fixed-boundary) triples so src/cli/osv-staleness.ts can assert each
// advisory still exists and still names the fix boundary we hardcode.
//
// The verified fact is the FIXED boundary, deliberately not the whole range. It is the boundary
// every check here actually branches on, and it is what #212 caught: the fabricated "14.2 fixed in
// 14.2.35" row asserted a fix version the advisory has never listed. The `introduced` edges are
// still NOT asserted: react-dom's range stays knowingly approximate (review-tiered for that
// reason). #271 closed the next-auth/undici/minimist gaps and #292 closed axios/ws by transcribing
// every OSV range for those entries; a multi-range row restates one claim per line.
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
  // One claim per range: a multi-range advisory asserts a fix boundary per line, and each must be
  // verified against OSV independently — restating only the first would leave the rest unchecked.
  ...CURATED_DEP_CVES.flatMap((c) =>
    c.ranges.map((r) => ({
      advisory: /^GHSA-/.test(c.id) ? c.id : c.source.replace(/^.*\/vulnerability\//, ""),
      pkg: c.name,
      fixed: r.fixed,
      note: `${c.id} — ${c.name} (fixed ${r.fixed})`,
    })),
  ),
];

export function checkKnownDependencyCVEs(deps: Record<string, string>, manifestPath = "package.json"): Finding[] {
  const findings: Finding[] = [];
  for (const cve of CURATED_DEP_CVES) {
    const declared = deps[cve.name];
    if (!declared) continue;
    const version = declared.replace(/^[\^~]/, "");
    // The ranges are disjoint, so at most one matches — the matching one names the fix to cite.
    const hit = cve.ranges.find((r) => (r.introduced ? gte(version, r.introduced) : true) && lt(version, r.fixed));
    if (!hit) continue;
    // #255: a curated severity that diverges from the advisory's own rating must say so in the
    // finding text, never silently — assertDisclosedDivergence (run over CURATED_DEP_CVES above)
    // already guarantees divergenceReason is set whenever osvSeverity differs from severity.
    const disclosure = cve.osvSeverity !== undefined ? ` Harvey rates this ${cve.severity}; OSV rates ${cve.osvSeverity} because ${cve.divergenceReason}.` : "";
    findings.push(
      mechanicalFinding({
        id: `DEP-${cve.id}`,
        title: `${cve.name}@${version} vulnerable to ${cve.id}`,
        severity: cve.severity,
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: `${manifestPath} (${cve.name})`,
        dependency: cve.name,
        evidence: `Declared ${cve.name}@${declared} falls in the ${cve.id} affected range (${hit.introduced ? `>= ${hit.introduced} ` : ""}< ${hit.fixed}), per ${cve.source}.${disclosure}`,
        impact: cve.summary,
        fix: cve.fix,
        precisionTier: cve.tier,
      }),
    );
  }
  return findings;
}

// OSV-Scanner --format json shape (subset used here). Verified against a captured
// osv-scanner 2.3.8 report — src/scan/__fixtures__/osv/, see its PROVENANCE.md.
export interface OsvScanResult {
  results?: {
    source?: { path?: string };
    packages?: {
      package?: { name?: string; version?: string; ecosystem?: string };
      // osv-scanner clusters aliased advisories and pre-computes each cluster's numeric CVSS
      // base score. This is the ONLY numeric severity anywhere in the report — but it is a
      // group MAXIMUM, so it over-rates the lesser advisories in a multi-id group.
      groups?: { ids?: string[]; max_severity?: string }[];
      vulnerabilities?: {
        id?: string;
        summary?: string;
        aliases?: string[];
        // OSV mandates `score` be a CVSS VECTOR STRING ("CVSS:3.1/AV:N/..."), never a number.
        severity?: { type?: string; score?: string }[];
        database_specific?: { severity?: string };
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

const OSV_SEVERITY_LABELS: Record<string, Severity> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MODERATE: "Medium", // GitHub's label for the CVSS "Medium" band
  MEDIUM: "Medium",
  LOW: "Low",
};

function severityFromScore(n: number): Severity {
  if (n >= 9) return "Critical";
  if (n >= 7) return "High";
  if (n >= 4) return "Medium";
  return "Low";
}

// #1063: this used to read `severity[].score`, which OSV mandates be a CVSS VECTOR STRING —
// `Number("CVSS:3.1")` is NaN, so EVERY dependency CVE fell through to the Medium default.
// MEASURED 2026-07-26 by regenerating dry-run/findings.json: all 35 DEP-OSV rows were Medium; the
// fix re-spread them to 1 Critical / 15 High / 16 Medium / 3 Low — 19 of 35 had been misrated.
// The two fields osv-scanner actually emits in a
// machine-readable severity form are used instead, per-vulnerability label first because a
// group's `max_severity` is the maximum over every aliased id in that group.
// `basis` is undefined when the advisory carried neither — the caller must say so rather than
// let an unrated advisory look like a rated Medium, which is the defect this fixed.
function resolveOsvSeverity(
  label: string | undefined,
  groupMaxSeverity: string | undefined,
): { severity: Severity; basis?: string } {
  const upper = label?.toUpperCase();
  const mapped = upper ? OSV_SEVERITY_LABELS[upper] : undefined;
  if (mapped) return { severity: mapped, basis: `the advisory's own ${upper} rating` };
  const n = Number(groupMaxSeverity);
  if (groupMaxSeverity && !Number.isNaN(n)) {
    return { severity: severityFromScore(n), basis: `osv-scanner's CVSS base score ${groupMaxSeverity} for this advisory group` };
  }
  return { severity: "Medium" };
}

// #512: when osv-scanner cannot run at all (binary missing, crash with no report), the CVE pass
// must degrade to this disclosure — previously it degraded to an empty result, which read as
// "zero vulnerable dependencies" in every deliverable. Same contract as M5-00/M7L-00/M8-00.
export function osvUnavailableFinding(reason: string): Finding {
  return {
    id: "DEP-OSV-00",
    title: "Dependency-CVE scan (osv-scanner) did not run",
    severity: "Info",
    confidence: "N/A",
    category: "Dependency CVE",
    taxonomy: "Known-vulnerable dependency — coverage not assessed",
    location: "(repo-wide)",
    status: "Open",
    evidence: `osv-scanner failed to run: ${reason}`,
    impact: "Lockfile CVE coverage for this engagement is incomplete for this pass — a disclosed coverage gap, not a finding of zero vulnerable dependencies. The curated Next.js version checks still ran.",
    fix: "Install osv-scanner on the scanning machine (see this file's header) and re-run the scan.",
    value: 1,
    ease: 3,
    safety: 5,
  };
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
        const group = pkg.groups?.find((g) => g.ids?.includes(id));
        const { severity, basis } = resolveOsvSeverity(vuln.database_specific?.severity, group?.max_severity);
        const rating = basis
          ? ` Rated ${severity} from ${basis}.`
          : ` This advisory carried NO machine-readable severity (no database_specific.severity, no group max_severity), so ${severity} is Harvey's default, not the advisory's rating — treat the rating as unknown and check ${id} by hand.`;
        findings.push(
          mechanicalFinding({
            id: `DEP-OSV-${id}`,
            title: `${name}@${version}: ${vuln.summary ?? id}`,
            severity,
            category: "Dependency CVE",
            taxonomy: "Known-vulnerable dependency",
            location: `${src.source?.path ?? "lockfile"} (${name}@${version})`,
            dependency: name,
            evidence: `OSV-Scanner matched ${id}${vuln.aliases?.length ? ` (aliases: ${vuln.aliases.join(", ")})` : ""} against ${name}@${version}.${rating}`,
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
