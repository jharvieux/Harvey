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
// OSV findings are retained unless the registry supplies an actually emitted representative for
// the same source, package, version and advisory. A curated advisory name alone proves no such
// replacement: nested inputs and alternate lockfiles can resolve different package populations.
// Generic OSV hits are "review" — a version match isn't proof of exploitability (deployment
// context, e.g. self-hosted vs. Vercel, matters).
//
// `precisionTier` here ("high" vs "review") is about confidence in the VERSION MATCH itself, a
// different axis from exploitability. Every "Dependency CVE" finding below is a version match
// only, so none set Finding.exploitabilityVerified, and the whole category stays out of the free
// grade (src/quick-scan.ts NON_GRADING_CATEGORIES, #213/#260). If a check is ever added here that
// independently confirms exploitability in the scanned codebase (not just a version overlap), set
// exploitabilityVerified: true on that finding so it grades correctly.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative } from "node:path";
import type { Finding, PrecisionTier, Severity } from "../findings.js";
import { collectDependencies, parsePackageLock, parsePnpmLock, parseYarnLock } from "../sbom.js";
import { readRecursiveSafe } from "../fs-walk.js";
import { mechanicalFinding } from "./common.js";
import { osvRemediation, type OsvAffectedPackage } from "./osv-remediation.js";

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

// #1471 — WHERE the version number came from, because "Installed next@14.2.5" was printed for a
// number nothing had installed. Three provenances, three different claims:
//   resolved   a lockfile records the version that actually resolves — the only one that earns
//              the word "installed", and the only one an exact-CVE match is HIGH-confidence about.
//   pinned     the manifest declares a bare version with no range, so any install lands there.
//   range      the manifest declares a range and no lockfile resolves it. The number is the
//              range's FLOOR, an install can land on either side of the fix, and the finding is
//              a conditional claim about the declared range — review tier, not high.
type VersionProvenance =
  | { kind: "resolved"; source: string }
  | { kind: "pinned" }
  | { kind: "range"; declared: string };

interface VersionClaim {
  version: string;
  provenance: VersionProvenance;
}

// A resolved dependency tree, keyed by package name. `source` is the lockfile it was parsed from,
// which the finding cites so a client can check the provenance rather than take "installed" on
// faith. Built by resolvedTree() below; undefined when the target ships no parseable lockfile.
export interface ResolvedTree {
  versions: ReadonlyMap<string, string>;
  source: string;
}

const EXACT_VERSION = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

// Caret and tilde only — the two operators whose floor is unambiguous AND whose upper bound stays
// inside one major, which the EOL row below relies on. A specifier outside those two shapes
// (`latest`, `*`, `>=14 <15`, a git URL, `workspace:`) yields no claim at all: the same silence as
// before, since parseVersion read those as 0.0.0 and matched no range.
function declaredFloor(declared: string): string | undefined {
  const stripped = declared.trim().replace(/^[\^~]/, "").trim();
  return EXACT_VERSION.test(stripped) ? stripped.replace(/^v/, "") : undefined;
}

function versionClaim(declared: string | undefined, resolved: ResolvedTree | undefined, name: string): VersionClaim | undefined {
  const fromLock = resolved?.versions.get(name);
  if (fromLock) return { version: fromLock, provenance: { kind: "resolved", source: resolved!.source } };
  if (declared === undefined) return undefined;
  if (EXACT_VERSION.test(declared.trim())) return { version: declared.trim().replace(/^v/, ""), provenance: { kind: "pinned" } };
  const floor = declaredFloor(declared);
  return floor ? { version: floor, provenance: { kind: "range", declared: declared.trim() } } : undefined;
}

// The subject of every evidence sentence below. The BODY ("is below the fixed version …") is
// identical across provenances; only the subject and the tier change, so a wording drift never
// makes one branch quietly assert more than another.
function subject(claim: VersionClaim, pkg: string): string {
  switch (claim.provenance.kind) {
    case "resolved":
      return `Installed ${pkg}@${claim.version} (resolved from ${claim.provenance.source})`;
    case "pinned":
      return `Installed ${pkg}@${claim.version}`;
    case "range":
      return `package.json declares ${pkg}@${claim.provenance.declared}, whose range floor ${claim.version}`;
  }
}

const UNRESOLVED_CAVEAT =
  " No lockfile in this repo resolves it, so an install can land on either side of the fix — this is a claim about the DECLARED RANGE, not a measured installed version.";
const UNRESOLVED_FIX = " Commit a lockfile as well, so the version that actually resolves is auditable.";

function unresolved(claim: VersionClaim): boolean {
  return claim.provenance.kind === "range";
}

function evidenceFor(claim: VersionClaim, pkg: string, body: string): string {
  return `${subject(claim, pkg)} ${body}${unresolved(claim) ? UNRESOLVED_CAVEAT : ""}`;
}

// A vulnerable range FLOOR is not a version match, and `precisionTier` on this whole family is
// documented (file header) as confidence in the VERSION MATCH itself. Severity is left alone:
// it states the weakness's impact if present, which the provenance does not change.
function tierFor(claim: VersionClaim, matchedTier: PrecisionTier): PrecisionTier {
  return unresolved(claim) ? "review" : matchedTier;
}

function titleFor(claim: VersionClaim, pkg: string, rest: string): string {
  return unresolved(claim)
    ? `${pkg}@${(claim.provenance as { declared: string }).declared} (declared range, unresolved) may be vulnerable to ${rest}`
    : `${pkg}@${claim.version} vulnerable to ${rest}`;
}

// Parses the target's lockfile into a name → resolved-version map. Returns undefined when there is
// no lockfile: collectDependencies falls back to the MANIFEST in that case, whose "versions" are
// declared ranges, and treating those as resolved is the exact defect #1471 reports.
export function resolvedTree(dir: string): ResolvedTree | undefined {
  const deps = collectDependencies(dir);
  if (deps.source === "package.json") return undefined;
  const versions = new Map<string, string>();
  for (const c of deps.components) if (c.version && !versions.has(c.name)) versions.set(c.name, c.version);
  return { versions, source: deps.source };
}

// `manifestPath` is the manifest's path relative to the scanned root ("package.json" for the
// root manifest, "fixtures/<app>/package.json" for a secondary manifest), so a finding's
// location identifies WHICH manifest it came from — needed once more than one manifest is
// scanned (e.g. the calibration corpus's EOL/supported app fixtures).
//
// `declared` is the RAW manifest specifier ("^14.2.5"), not a pre-stripped floor: stripping it at
// the call site is what threw the provenance away (#1471).
export function checkNextVersionCVEs(declared: string, manifestPath = "package.json", resolved?: ResolvedTree): Finding[] {
  const claim = versionClaim(declared, resolved, "next");
  if (!claim) return [];
  const findings: Finding[] = [];
  const installedVersion = claim.version;
  const [major, minor] = parseVersion(installedVersion);
  const nextLocation = `${manifestPath} (next)`;

  const middlewareFix = MIDDLEWARE_BYPASS_FIXED_BY_MAJOR[major];
  if (middlewareFix && lt(installedVersion, middlewareFix)) {
    findings.push(
      mechanicalFinding({
        id: "DEP-CVE-2025-29927",
        title: titleFor(claim, "next", "CVE-2025-29927 (middleware auth bypass)"),
        severity: "Critical",
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: nextLocation,
        dependency: "next",
        evidence: evidenceFor(claim, "next", `is below the fixed version ${middlewareFix} for the ${major}.x line. The x-middleware-subrequest header skips middleware entirely (GHSA-f82v-jwr5-mffw).`),
        impact: "If auth is enforced only in middleware.ts (the dominant pattern in vibe-coded apps) and the app is self-hosted (not Vercel, which is auto-patched), this is a full authorization bypass.",
        fix: `Upgrade next to >= ${middlewareFix}.${unresolved(claim) ? UNRESOLVED_FIX : ""}`,
        precisionTier: tierFor(claim, "high"),
      }),
    );
  }

  const rscFix = RSC_RCE_FIXED_BY_MINOR[`${major}.${minor}`];
  if (rscFix && lt(installedVersion, rscFix)) {
    findings.push(
      mechanicalFinding({
        id: "DEP-CVE-2025-55182",
        title: titleFor(claim, "next", "CVE-2025-55182 (React Server Components RCE)"),
        severity: "Critical",
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: nextLocation,
        dependency: "next",
        evidence: evidenceFor(claim, "next", `is below the fixed version ${rscFix} for the ${major}.${minor} line (GHSA-9qr9-h5gf-34mp, CVSS 10, CISA KEV added 2025-12-05).`),
        impact: "Pre-authentication remote code execution: Server Function endpoints unsafely deserialize an attacker-supplied React-flight payload. Affects App Router apps on the vulnerable range.",
        fix: `Upgrade next to >= ${rscFix} (and react-server-dom-* to the matching fixed release).${unresolved(claim) ? UNRESOLVED_FIX : ""}`,
        precisionTier: tierFor(claim, "high"),
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
        title: titleFor(claim, "next", "CVE-2026-44578 (WebSocket-upgrade SSRF)"),
        severity: "High",
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: nextLocation,
        dependency: "next",
        evidence: evidenceFor(claim, "next", "falls in a vulnerable range for CVE-2026-44578 (GHSA-c4j6-fc7j-m34r, CVSS 8.6)."),
        impact: "Framework-level SSRF via WebSocket upgrade handling; self-hosted Node deployments only.",
        fix: `Upgrade next to >= 15.5.16 (15.x line) or >= 16.2.5 (16.x line).${unresolved(claim) ? UNRESOLVED_FIX : ""}`,
        precisionTier: tierFor(claim, "high"),
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
        title: titleFor(claim, "next", "CVE-2026-27978 (Server Actions null-origin CSRF)"),
        severity: "Medium",
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: nextLocation,
        dependency: "next",
        evidence: evidenceFor(claim, "next", "falls in the CVE-2026-27978 range (>=16.0.1 <16.1.7, GHSA-mq59-m269-xvcx)."),
        impact: "A cross-site request with an absent (null) Origin header bypasses the Server Actions origin check, letting an attacker invoke authenticated Server Actions cross-site (CSRF).",
        fix: `Upgrade next to >= 16.1.7.${unresolved(claim) ? UNRESOLVED_FIX : ""}`,
        precisionTier: tierFor(claim, "high"),
      }),
    );
  }

  if (major > 0 && major < EOL_BELOW_MAJOR) {
    findings.push(
      mechanicalFinding({
        id: "DEP-NEXT-EOL",
        title: `next@${unresolved(claim) ? (claim.provenance as { declared: string }).declared : installedVersion} is on an end-of-life major version line`,
        severity: "Medium",
        category: "Dependency CVE",
        taxonomy: "EOL framework version",
        location: nextLocation,
        dependency: "next",
        // No unresolved-range caveat here, unlike the CVE rows above: a caret/tilde range stays
        // inside one major, so the major this row concludes from holds whichever version resolves.
        evidence: `${subject(claim, "next")} is on major ${major}, below the ${EOL_BELOW_MAJOR}.x line still receiving security patches.`,
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

// #1471 — same provenance discipline as checkNextVersionCVEs: a lockfile-resolved version wins
// over the declared specifier (the caller used to prefer the DECLARED range, so a manifest
// declaring ^1.7.2 against a lockfile resolving a patched 1.8.2 drew a High "vulnerable" row for a
// version nothing installs), and a range floor with no lockfile drops to review tier.
export function checkKnownDependencyCVEs(deps: Record<string, string>, manifestPath = "package.json", resolved?: ResolvedTree): Finding[] {
  const findings: Finding[] = [];
  for (const cve of CURATED_DEP_CVES) {
    const claim = versionClaim(deps[cve.name], resolved, cve.name);
    if (!claim) continue;
    const version = claim.version;
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
        title: titleFor(claim, cve.name, cve.id),
        severity: cve.severity,
        category: "Dependency CVE",
        taxonomy: "Known-vulnerable dependency",
        location: `${manifestPath} (${cve.name})`,
        dependency: cve.name,
        evidence: evidenceFor(claim, cve.name, `falls in the ${cve.id} affected range (${hit.introduced ? `>= ${hit.introduced} ` : ""}< ${hit.fixed}), per ${cve.source}.${disclosure}`),
        impact: cve.summary,
        fix: `${cve.fix}${unresolved(claim) ? UNRESOLVED_FIX : ""}`,
        precisionTier: tierFor(claim, cve.tier),
      }),
    );
  }
  return findings;
}

// OSV-Scanner --format json shape (subset used here). Verified against a captured
// osv-scanner 2.3.8 report — src/scan/__fixtures__/osv/, see its PROVENANCE.md. #1079: `affected`,
// `database_specific.cwe_ids`, `references` and `details` were all present in the tool's output and
// all discarded — MEASURED 2026-07-26 with osv-scanner 2.3.8 (osv-scalibr 0.4.5) against
// targets/calibration. The affected range's `fixed` event is the version number the remediation has
// to name; `cwe_ids` is the CWE every other detector carries and no DEP-OSV row did; `details` is
// the advisory's full narrative (3.8k chars on the brace-expansion advisory) where `summary` is one
// line that was being printed twice, as both title and impact.
export interface OsvScanResult {
  inputReports?: { path: string; metadata: Record<string, unknown> }[];
  results?: {
    source?: { path?: string };
    packages?: {
      package?: { name?: string; version?: string; ecosystem?: string };
      // osv-scanner clusters aliased advisories and pre-computes each cluster's numeric CVSS
      // base score. This is the ONLY numeric severity anywhere in the report — but it is a
      // group MAXIMUM, so it over-rates the lesser advisories in a multi-id group.
      groups?: { ids?: string[]; max_severity?: string }[];
      vulnerabilities?: OsvVulnerability[];
    }[];
  }[];
}

const OSV_LOCKFILES = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock"];
const OSV_RESOLVED_VERSION = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const OSV_INPUT_NAME = /^(?:package\.json|.*\.lock|bun\.lockb|pnpm-(?:lock|workspace)\.yaml|package-lock\.json|npm-shrinkwrap\.json|requirements[^/]*\.txt|go\.mod|pom\.xml|composer\.json|Gemfile|pyproject\.toml|Cargo\.toml|pubspec\.yaml)$/;

export interface OsvInputInventory {
  schema: 1;
  inputs: {
    path: string;
    sha256: string;
    kind: "manifest" | "lockfile";
    disposition: "selected" | "covered" | "unselected" | "unsupported" | "missing-input" | "not-applicable";
    reason: string;
    selectedBy?: string;
    resolvedPackages?: string[];
    unresolvedPackages?: string[];
    workspacePackages?: string[];
    providerNormalization?: {
      kind: "pnpm-v6-scoped-peer-metadata";
      normalizedEntries: number;
      normalizedSha256: string;
    };
  }[];
  sha256: string;
}

export interface OsvAssessment {
  schema: 1;
  inventory: OsvInputInventory;
  status: "assessed" | "partial" | "not-assessed" | "not-applicable";
  invocations: { path: string; sha256: string; status: "assessed" | "partial" | "not-assessed"; examinedPackages: string[]; unassessedPackages: string[]; ambiguousPackages: string[]; unversionedPackages: string[]; notApplicablePackages: string[]; reason?: string }[];
  reason: string;
  provenance: string;
  falsifier: string;
}

export interface OsvExecutionReceipt {
  inventorySha256: string;
  inputs: { path: string; sha256: string; status: "completed" | "input-not-assessed" | "failed"; inputGap?: { code: "unresolved-versions" | "incomplete-parse" | "no-resolved-packages"; unresolved: number; unmatched: number; resolved: number }; reason?: string }[];
}

interface OsvScanRun {
  execution: OsvExecutionReceipt;
  result: OsvScanResult;
  assessment: OsvAssessment;
  failure?: string;
}

const inputHash = (value: string | Uint8Array): string => createHash("sha256").update(value).digest("hex");
const packageIdentity = (name: string, version: string): string => `npm:${name}@${version}`;
const osvFalsifier = "Re-run osv-scanner with --all-packages for every selected lockfile and reconcile its source paths and package identities with this inventory; assess each disclosed input before claiming full coverage.";

interface NormalizedPnpmInput {
  text: string;
  normalizedEntries: number;
  normalizedSha256: string;
}

// osv-scanner 2.3.8 embeds scalibr's pre-v9 pnpm parser at 9293bfa4f86f. That parser splits a
// package key on every slash before it removes peer context. A v6 key such as
// `/plain@1.0.0(@types/react@18.0.0)` therefore mistakes `react@18.0.0)` for the package version
// and drops the package. The parser already gives explicit entry metadata precedence, so add only
// the exact name/version the lock key itself encodes to a disposable provider copy. Package keys,
// peer contexts, dev/optional flags, and the client input bytes remain unchanged.
export function normalizePnpmV6ForOsv(text: string): NormalizedPnpmInput {
  const version = /^lockfileVersion:\s*['"]?([\d.]+)['"]?\s*$/m.exec(text)?.[1];
  if (!version || Number(version) < 6 || Number(version) >= 9) {
    return { text, normalizedEntries: 0, normalizedSha256: inputHash(text) };
  }
  const lines = text.split("\n");
  let inPackages = false;
  let normalizedEntries = 0;
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!;
    if (line === "packages:") { inPackages = true; continue; }
    if (inPackages && /^\S/.test(line)) { inPackages = false; continue; }
    if (!inPackages || !/^\s{2}\S.*:\s*$/.test(line)) continue;
    const key = /^\s{2}'?\/?(@?[^'@\s]+(?:\/[^'@\s]+)?)[@/]([0-9][^'\s:(]*)'?(?:\([^)]*\))*'?:\s*$/.exec(line);
    const peerContext = line.slice(line.indexOf("(") + 1);
    if (!key?.[1] || !key[2] || !line.includes("(") || !peerContext.includes("/")) continue;
    let end = index + 1;
    while (end < lines.length && !/^\s{0,2}\S/.test(lines[end]!)) end++;
    const block = lines.slice(index + 1, end);
    const existingName = block.find((entry) => /^\s{4}name:\s*/.test(entry));
    const existingVersion = block.find((entry) => /^\s{4}version:\s*/.test(entry));
    if (existingName || existingVersion) {
      const quotedName = JSON.stringify(key[1]);
      const quotedVersion = JSON.stringify(key[2]);
      if (existingName !== `    name: ${quotedName}` || existingVersion !== `    version: ${quotedVersion}`) {
        throw new Error(`pnpm v6 peer-context entry ${key[1]}@${key[2]} carries conflicting explicit provider metadata`);
      }
      continue;
    }
    lines.splice(index + 1, 0, `    name: ${JSON.stringify(key[1])}`, `    version: ${JSON.stringify(key[2])}`);
    normalizedEntries++;
    index += 2;
  }
  const normalized = lines.join("\n");
  return { text: normalized, normalizedEntries, normalizedSha256: inputHash(normalized) };
}

/** Inventory the already prepared target. Selection preserves OSV's precedence per directory. */
export function inventoryOsvInputs(dir: string, paths: readonly string[] = readRecursiveSafe(dir)): OsvInputInventory {
  const candidates = paths.filter((path) => OSV_INPUT_NAME.test(basename(path))).sort();
  const bytesByPath = new Map(candidates.map((path) => [path, readFileSync(join(dir, path))]));
  const textByPath = new Map([...bytesByPath].map(([path, bytes]) => [path, bytes.toString("utf8")]));
  const selected = new Map<string, string>();
  for (const path of candidates) {
    if (!OSV_LOCKFILES.includes(basename(path))) continue;
    const prior = selected.get(dirname(path));
    if (!prior || OSV_LOCKFILES.indexOf(basename(path)) < OSV_LOCKFILES.indexOf(basename(prior))) selected.set(dirname(path), path);
  }
  const workspaceSources = new Map<string, string>();
  for (const path of selected.values()) {
    const text = textByPath.get(path)!;
    if (basename(path) === "pnpm-lock.yaml") {
      const importers = /^importers:\s*\n([\s\S]*?)(?=^\S|$(?![\s\S]))/m.exec(text)?.[1] ?? "";
      for (const match of importers.matchAll(/^ {2}['"]?([^'"\n]+?)['"]?:\s*$/gm)) workspaceSources.set(join(dirname(path), match[1]!, "package.json"), path);
    } else if (basename(path) === "package-lock.json") {
      try {
        const raw = JSON.parse(text) as { packages?: Record<string, unknown> };
        for (const owner of Object.keys(raw.packages ?? {})) if (owner && !owner.includes("node_modules")) workspaceSources.set(join(dirname(path), owner, "package.json"), path);
      } catch { /* The invocation reports an unreadable selected lockfile below. */ }
    }
  }
  const inputs: OsvInputInventory["inputs"] = candidates.map((path) => {
    const text = textByPath.get(path)!;
    const own = selected.get(dirname(path));
    const base = { path, sha256: inputHash(bytesByPath.get(path)!), kind: ["package.json", "pnpm-workspace.yaml"].includes(basename(path)) ? "manifest" as const : "lockfile" as const };
    if (OSV_LOCKFILES.includes(basename(path))) {
      if (path !== own) return { ...base, disposition: "unselected", selectedBy: own!, reason: `Not assessed: ${own} takes precedence for this dependency root; equivalence of this alternate resolved tree was not established.` };
      let resolvedPackages: string[] = [];
      let unresolvedPackages: string[] = [];
      const workspacePackages: string[] = [];
      try {
        const parsed = basename(path) === "pnpm-lock.yaml" ? parsePnpmLock(text) : basename(path) === "yarn.lock" ? parseYarnLock(text) : parsePackageLock(text);
        resolvedPackages = parsed.components.filter((component) => OSV_RESOLVED_VERSION.test(component.version)).map((component) => packageIdentity(component.name, component.version)).sort();
        unresolvedPackages = parsed.components.filter((component) => !OSV_RESOLVED_VERSION.test(component.version)).map((component) => packageIdentity(component.name, component.version));
        if (basename(path) === "package-lock.json") {
          const raw: unknown = JSON.parse(text);
          if (record(raw) && record(raw.packages)) {
            resolvedPackages = [];
            unresolvedPackages = [];
            for (const [installPath, meta] of Object.entries(raw.packages)) {
              if (!record(meta) || !installPath) continue;
              if (!installPath.includes("node_modules/")) { if (typeof meta.name === "string") workspacePackages.push(packageIdentity(meta.name, typeof meta.version === "string" && meta.version ? meta.version : "unresolved")); continue; }
              const name = typeof meta.name === "string" ? meta.name : installPath.replace(/^(?:.*\/)?node_modules\//, "");
              if (meta.link) { workspacePackages.push(packageIdentity(name, "unresolved")); continue; }
              if (typeof meta.version === "string" && OSV_RESOLVED_VERSION.test(meta.version)) resolvedPackages.push(packageIdentity(name, meta.version));
              else unresolvedPackages.push(packageIdentity(name, typeof meta.version === "string" ? meta.version : "unresolved"));
            }
          }
        }
        resolvedPackages = [...new Set(resolvedPackages)].sort();
      } catch { /* The selected input retains its failed invocation and reason. */ }
      const normalization = basename(path) === "pnpm-lock.yaml" ? normalizePnpmV6ForOsv(text) : undefined;
      const providerNormalization = normalization?.normalizedEntries
        ? { kind: "pnpm-v6-scoped-peer-metadata" as const, normalizedEntries: normalization.normalizedEntries, normalizedSha256: normalization.normalizedSha256 }
        : undefined;
      return { ...base, disposition: "selected", resolvedPackages, unresolvedPackages: [...new Set(unresolvedPackages)].sort(), workspacePackages: [...new Set(workspacePackages)].sort(), ...(providerNormalization ? { providerNormalization } : {}), reason: "Selected supported lockfile for this dependency root." };
    }
    if (basename(path) === "pnpm-workspace.yaml") return { ...base, disposition: own ? "covered" : "not-applicable", ...(own ? { selectedBy: own } : {}), reason: `Supporting pnpm workspace metadata; not passed to OSV --lockfile and contributes zero resolved examined units. ${own ? `Resolved packages and workspace importers are assessed through ${own}.` : "No selected supported lockfile belongs to this metadata root."}` };
    if (basename(path) !== "package.json") return { ...base, disposition: "unsupported", reason: "Not assessed: this input format is outside Harvey's pnpm/package-lock/yarn OSV invocation policy." };
    const source = own ?? workspaceSources.get(path);
    if (source) return { ...base, disposition: "covered", selectedBy: source, reason: `Resolved package assessment uses ${source}; declared ranges are not counted as resolved packages.` };
    try {
      const pkg = JSON.parse(text) as Record<string, unknown>;
      if (pkg && typeof pkg === "object" && ["dependencies", "devDependencies", "optionalDependencies"].every((section) => !pkg[section] || Object.keys(pkg[section] as object).length === 0)) {
        return { ...base, disposition: "not-applicable", reason: "No external dependency declarations or selected lockfile in this manifest root." };
      }
    } catch { /* Malformed manifests remain explicitly unassessed. */ }
    return { ...base, disposition: "missing-input", reason: "Not assessed: this manifest has no selected supported lockfile or recorded workspace importer; manifest ranges are not resolved versions." };
  });
  return { schema: 1, inputs, sha256: inputHash(JSON.stringify(inputs)) };
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Validate the provider envelope before a permissive parser can turn malformed data into zero. */
function validateOsvResult(value: unknown): asserts value is OsvScanResult {
  if (!record(value) || (value.results !== undefined && !Array.isArray(value.results))) throw new Error("invalid OSV report object/results");
  for (const source of (value.results ?? []) as unknown[]) {
    if (!record(source) || !record(source.source) || typeof source.source.path !== "string" || !Array.isArray(source.packages)) throw new Error("invalid OSV source/package population");
    for (const row of source.packages) {
      if (!record(row) || !record(row.package) || typeof row.package.name !== "string" || !row.package.name || typeof row.package.version !== "string" || row.package.ecosystem !== "npm") throw new Error("invalid OSV package identity/ecosystem");
      if (row.package.version && !OSV_RESOLVED_VERSION.test(row.package.version)) throw new Error(`OSV package ${row.package.name} has a non-concrete resolved version`);
      for (const field of ["groups", "vulnerabilities"] as const) if (row[field] !== undefined && !Array.isArray(row[field])) throw new Error(`invalid OSV ${field}`);
      for (const group of (row.groups ?? []) as unknown[]) if (!record(group) || (group.ids !== undefined && (!Array.isArray(group.ids) || group.ids.some((id) => typeof id !== "string"))) || (group.max_severity !== undefined && typeof group.max_severity !== "string")) throw new Error("invalid OSV advisory group");
      for (const vuln of (row.vulnerabilities ?? []) as unknown[]) {
        if (!record(vuln) || typeof vuln.id !== "string" || !vuln.id) throw new Error("invalid OSV advisory identity");
        for (const field of ["aliases", "affected", "references", "severity"] as const) if (vuln[field] !== undefined && !Array.isArray(vuln[field])) throw new Error(`invalid OSV advisory ${field}`);
        for (const field of ["summary", "details"] as const) if (vuln[field] !== undefined && typeof vuln[field] !== "string") throw new Error(`invalid OSV advisory ${field}`);
        if ((vuln.aliases as unknown[] | undefined)?.some((alias) => typeof alias !== "string")) throw new Error("invalid OSV advisory aliases");
        for (const reference of (vuln.references ?? []) as unknown[]) if (!record(reference) || (reference.type !== undefined && typeof reference.type !== "string") || (reference.url !== undefined && typeof reference.url !== "string")) throw new Error("invalid OSV advisory reference");
        if (vuln.database_specific !== undefined && (!record(vuln.database_specific) || (vuln.database_specific.severity !== undefined && typeof vuln.database_specific.severity !== "string") || (vuln.database_specific.cwe_ids !== undefined && (!Array.isArray(vuln.database_specific.cwe_ids) || vuln.database_specific.cwe_ids.some((cwe) => typeof cwe !== "string"))))) throw new Error("invalid OSV advisory database metadata");
        for (const affected of (vuln.affected ?? []) as unknown[]) {
          if (!record(affected) || (affected.package !== undefined && !record(affected.package)) || (affected.ranges !== undefined && !Array.isArray(affected.ranges))) throw new Error("invalid OSV affected package/ranges");
          for (const range of (affected.ranges ?? []) as unknown[]) {
            if (!record(range) || (range.events !== undefined && !Array.isArray(range.events))) throw new Error("invalid OSV range events");
            for (const event of (range.events ?? []) as unknown[]) if (!record(event) || (event.fixed !== undefined && typeof event.fixed !== "string")) throw new Error("invalid OSV fixed event");
          }
        }
      }
    }
  }
}

function examinedPackages(result: OsvScanResult, path: string, workspacePackages: readonly string[] = []): string[] {
  return [...new Set((result.results ?? []).filter((row) => row.source?.path === path).flatMap((row) => (row.packages ?? []).filter((pkg) => pkg.package?.version && !workspacePackages.includes(packageIdentity(pkg.package.name!, pkg.package.version))).map((pkg) => packageIdentity(pkg.package!.name!, pkg.package!.version!))))].sort();
}

function assessmentFor(inventory: OsvInputInventory, result: OsvScanResult, failures: Map<string, string>): OsvAssessment {
  const invocations: OsvAssessment["invocations"] = inventory.inputs.filter((input) => input.disposition === "selected").map((input) => {
    const packages = failures.has(input.path) ? [] : examinedPackages(result, input.path, input.workspacePackages);
    const unassessedPackages = (input.resolvedPackages ?? []).filter((identity) => !packages.includes(identity));
    const ambiguousPackages = unassessedPackages.filter((identity) => input.workspacePackages?.includes(identity) && examinedPackages(result, input.path).includes(identity));
    const omittedPackages = unassessedPackages.filter((identity) => !ambiguousPackages.includes(identity));
    const unversionedPackages = [...new Set((result.results ?? []).filter((row) => row.source?.path === input.path).flatMap((row) => (row.packages ?? []).filter((pkg) => !pkg.package?.version).map((pkg) => pkg.package!.name!)))].sort();
    const gap = failures.get(input.path) ?? (packages.length === 0 ? "The provider returned no resolved packages for this input; no package examination is claimed."
      : omittedPackages.length > 0 ? `Not assessed: osv-scanner --all-packages omitted ${omittedPackages.length} package identities resolved from this selected lockfile: ${omittedPackages.join(", ")}.` : undefined);
    const notApplicablePackages = [...new Set((result.results ?? []).filter((row) => row.source?.path === input.path).flatMap((row) => (row.packages ?? []).map((pkg) => packageIdentity(pkg.package!.name!, pkg.package!.version || "unresolved")).filter((identity) => input.workspacePackages?.includes(identity) && !ambiguousPackages.includes(identity))))].sort();
    const reason = [gap, ...ambiguousPackages.map((identity) => `${identity}: shared by a first-party workspace and a third-party resolution; the provider coordinate does not distinguish their origins, so third-party coverage is not assessed.`), ...notApplicablePackages.filter((identity) => !ambiguousPackages.includes(identity)).map((identity) => `${identity}: first-party workspace package/link; not applicable to third-party registry dependency assessment and excluded from resolved examination.`), ...unversionedPackages.filter((name) => !(input.workspacePackages ?? []).includes(packageIdentity(name, "unresolved"))).map((name) => `${name}: provider returned no version; not assessed and excluded from resolved examination.`)].filter(Boolean).join(" ");
    const hasUnknownVersion = unversionedPackages.some((name) => !(input.workspacePackages ?? []).includes(packageIdentity(name, "unresolved")));
    return { path: input.path, sha256: input.sha256, status: packages.length === 0 ? "not-assessed" : unassessedPackages.length || hasUnknownVersion ? "partial" : "assessed", examinedPackages: packages, unassessedPackages, ambiguousPackages, unversionedPackages, notApplicablePackages, ...(reason ? { reason } : {}) };
  });
  const assessed = invocations.filter((input) => input.status !== "not-assessed");
  const excluded = inventory.inputs.filter((input) => ["unsupported", "unselected", "missing-input"].includes(input.disposition));
  const status = assessed.length > 0 ? (excluded.length > 0 || invocations.some((input) => input.status !== "assessed") ? "partial" : "assessed")
    : inventory.inputs.some((input) => input.disposition !== "not-applicable") ? "not-assessed" : "not-applicable";
  const details = [...invocations.filter((input) => input.reason).map((input) => `${input.path}: ${input.reason}`), ...excluded.map((input) => `${input.path}: ${input.reason}`)];
  return {
    schema: 1, inventory, status, invocations,
    reason: `${assessed.length} of ${invocations.length} selected lockfile(s) assessed; ${assessed.reduce((sum, input) => sum + input.examinedPackages.length, 0)} exact third-party source/package identities returned by osv-scanner --all-packages.` +
      (details.length ? ` ${details.join(" ")}` : invocations.length === 0 ? " No applicable Node lockfile population was discovered; osv-scanner was not invoked." : ""),
    provenance: `MEASURED prepared-target input inventory SHA-256 ${inventory.sha256}; provider --all-packages output bound to each selected source and input digest.` +
      (inventory.inputs.some((input) => input.providerNormalization)
        ? ` Disposable pnpm v6 provider normalization supplied explicit key-derived name/version metadata for ${inventory.inputs.reduce((sum, input) => sum + (input.providerNormalization?.normalizedEntries ?? 0), 0)} scoped-peer entr${inventory.inputs.reduce((sum, input) => sum + (input.providerNormalization?.normalizedEntries ?? 0), 0) === 1 ? "y" : "ies"}; original lock bytes and identities were preserved.`
        : ""),
    falsifier: osvFalsifier,
  };
}

/** Reconcile a saved receipt with both its raw provider output and the current prepared inputs. */
export function validateOsvAssessment(assessment: OsvAssessment, result: OsvScanResult, expectedInventory?: OsvInputInventory): void {
  validateOsvResult(result);
  if (!assessment || assessment.schema !== 1 || assessment.inventory?.schema !== 1 || !Array.isArray(assessment.inventory.inputs) || !Array.isArray(assessment.invocations)) throw new Error("OSV input assessment provenance is missing or malformed");
  const inventory = assessment.inventory;
  const paths = inventory.inputs.map((input) => input.path);
  if (new Set(paths).size !== paths.length || inventory.inputs.some((input) => typeof input.path !== "string" || isAbsolute(input.path) || input.path.split("/").some((segment) => ["", ".", ".."].includes(segment)) || !/^[a-f0-9]{64}$/.test(input.sha256))) throw new Error("invalid OSV input inventory paths/digests");
  if (inputHash(JSON.stringify(inventory.inputs)) !== inventory.sha256 || (expectedInventory && JSON.stringify(inventory) !== JSON.stringify(expectedInventory))) throw new Error("OSV input inventory differs from the complete prepared-target population");
  const selected = new Set(inventory.inputs.filter((input) => input.disposition === "selected").map((input) => input.path));
  if ((result.results ?? []).some((row) => !selected.has(row.source!.path!))) throw new Error("OSV report contains an unselected source");
  for (const input of inventory.inputs.filter((input) => input.disposition === "selected")) {
    const unexpected = examinedPackages(result, input.path, input.workspacePackages).filter((identity) => !input.resolvedPackages?.includes(identity));
    if (unexpected.length) throw new Error(`OSV report contains package identities absent from selected input ${input.path}: ${unexpected.join(", ")}`);
  }
  const failures = new Map(assessment.invocations.filter((input) => input.status === "not-assessed").map((input) => [input.path, input.reason ?? ""]));
  if (assessment.invocations.some((input) => input.status === "not-assessed" && (!input.reason || examinedPackages(result, input.path, inventory.inputs.find((source) => source.path === input.path)?.workspacePackages).length))) throw new Error("unassessed OSV source has packages or lacks a reason");
  if (JSON.stringify(assessmentFor(inventory, result, failures)) !== JSON.stringify(assessment)) throw new Error("OSV assessment does not reconcile selected sources and exact provider package identities");
}

// Exit 1 is the sole benign nonzero status. Signals, output caps and malformed reports never
// become a clean zero. Each supported root is attempted independently so one failure preserves
// successful observations and leaves its own explicit non-assessment receipt.
export function runOsvScanner(dir: string, inventory = inventoryOsvInputs(dir)): OsvScanRun {
  const result: OsvScanResult = { results: [] };
  const failures = new Map<string, string>();
  const execution: OsvExecutionReceipt = { inventorySha256: inventory.sha256, inputs: [] };
  for (const input of inventory.inputs.filter((entry) => entry.disposition === "selected")) {
    const receipt: OsvExecutionReceipt["inputs"][number] = { path: input.path, sha256: input.sha256, status: "failed" };
    execution.inputs.push(receipt);
    try {
      const bytes = readFileSync(join(dir, input.path));
      if (inputHash(bytes) !== input.sha256) throw new Error("selected lockfile changed after input inventory");
      const text = bytes.toString("utf8");
      const parsed = basename(input.path) === "pnpm-lock.yaml" ? parsePnpmLock(text) : basename(input.path) === "yarn.lock" ? parseYarnLock(text) : parsePackageLock(text);
      const inputGap = input.unresolvedPackages?.length
        ? `selected lockfile contains unresolved package versions: ${input.unresolvedPackages.join(", ")}`
        : parsed.unmatched > 0 || parsed.components.length === 0
          ? `selected lockfile has ${parsed.unmatched} unresolved entries and ${parsed.components.length} resolved packages; input completeness is not established`
          : undefined;
      if (inputGap) {
        receipt.status = "input-not-assessed";
        receipt.inputGap = { code: input.unresolvedPackages?.length ? "unresolved-versions" : parsed.unmatched > 0 ? "incomplete-parse" : "no-resolved-packages", unresolved: input.unresolvedPackages?.length ?? 0, unmatched: parsed.unmatched, resolved: parsed.components.length };
        receipt.reason = inputGap;
        failures.set(input.path, inputGap);
        continue;
      }
      let out: string;
      let providerInput = join(dir, input.path);
      let providerRoot: string | undefined;
      if (input.providerNormalization) {
        const normalized = normalizePnpmV6ForOsv(text);
        if (normalized.normalizedEntries !== input.providerNormalization.normalizedEntries || normalized.normalizedSha256 !== input.providerNormalization.normalizedSha256) throw new Error("pnpm provider normalization differs from the inventoried receipt");
        providerRoot = mkdtempSync(join(tmpdir(), "harvey-osv-pnpm-"));
        providerInput = join(providerRoot, "pnpm-lock.yaml");
        writeFileSync(providerInput, normalized.text);
      }
      try {
        try {
          out = execFileSync("osv-scanner", ["--format", "json", "--all-packages", "--lockfile", providerInput], { encoding: "utf8", maxBuffer: 1024 * 1024 * 64 });
        } catch (err) {
          const e = err as { stdout?: string; code?: string; status?: number | null; signal?: string | null };
          if (e.code === "ENOENT") throw new Error("osv-scanner not found on PATH");
          if (e.signal || e.status !== 1) {
            const how = e.code === "ENOBUFS" ? `report exceeded the 64 MiB stdout cap, killed by signal ${e.signal ?? "unknown"}` : e.signal ? `killed by signal ${e.signal}` : `exited with code ${e.status ?? "unknown"}`;
            throw new Error(`osv-scanner run did not complete (${how})`);
          }
          if (typeof e.stdout !== "string" || !e.stdout.trim()) throw new Error("osv-scanner exited 1 (vulnerabilities found) but printed no report");
          out = e.stdout;
        }
      } finally {
        if (providerRoot) rmSync(providerRoot, { recursive: true, force: true });
      }
      let raw: unknown;
      try { raw = JSON.parse(out); } catch { throw new Error("osv-scanner printed something other than its JSON report — treated as an incomplete run, never as a clean scan"); }
      validateOsvResult(raw);
      const normalized: OsvScanResult = { ...raw, results: raw.results?.map((row) => {
        const sourcePath = row.source!.path!;
        const rebound = input.providerNormalization && (sourcePath === providerInput || sourcePath === basename(providerInput))
          ? input.path
          : isAbsolute(sourcePath) ? relative(dir, sourcePath) : sourcePath;
        return { ...row, source: { ...row.source, path: rebound } };
      }) };
      if ((normalized.results ?? []).some((row) => row.source?.path !== input.path)) throw new Error("OSV returned a source other than the selected input");
      const actual = new Set(examinedPackages(normalized, input.path, input.workspacePackages));
      const unexpected = [...actual].filter((identity) => !input.resolvedPackages?.includes(identity));
      if (unexpected.length) throw new Error(`OSV report contains package identities absent from selected input: ${unexpected.join(", ")}`);
      if (actual.size === 0) throw new Error("OSV --all-packages receipt returned no selected-lock package identities");
      result.results!.push(...normalized.results!);
      (result.inputReports ??= []).push({ path: input.path, metadata: Object.fromEntries(Object.entries(raw).filter(([key]) => key !== "results")) });
      receipt.status = "completed";
    } catch (error) {
      receipt.reason = error instanceof Error ? error.message : String(error);
      failures.set(input.path, receipt.reason);
    }
  }
  const assessment = assessmentFor(inventory, result, failures);
  validateOsvAssessment(assessment, result, inventory);
  return { result, assessment, execution, ...(failures.size ? { failure: [...failures].map(([path, reason]) => `${path}: ${reason}`).join("; ") } : {}) };
}


/** Publishing current artifacts requires completed live calls, not merely a nonzero finding count.
 * Static input gaps have a different cause from failed required calls. */
export function assertOsvExecution(assessment: OsvAssessment, execution?: OsvExecutionReceipt): void {
  if (!execution || execution.inventorySha256 !== assessment.inventory.sha256) throw new Error("OSV live execution receipt is missing or belongs to another input inventory");
  const selected = assessment.inventory.inputs.filter((input) => input.disposition === "selected");
  if (execution.inputs.length !== selected.length) throw new Error("OSV live execution receipt does not cover every selected input");
  for (const input of selected) {
    const rows = execution.inputs.filter((row) => row.path === input.path && row.sha256 === input.sha256);
    if (rows.length !== 1) throw new Error(`OSV live execution receipt has missing or duplicate input ${input.path}`);
    const row = rows[0]!;
    const invocation = assessment.invocations.find((item) => item.path === input.path && item.sha256 === input.sha256);
    if (!invocation) throw new Error(`OSV live execution receipt lacks an assessment for ${input.path}`);
    if (row.status === "failed") throw new Error(`OSV required live execution failed for ${input.path}: ${row.reason ?? "no reason supplied"}`);
    if (row.status === "input-not-assessed") {
      const gap = row.inputGap;
      const validGap = gap && gap.unresolved === (input.unresolvedPackages?.length ?? 0) && (
        gap.code === "unresolved-versions" ? gap.unresolved > 0
          : gap.code === "incomplete-parse" ? gap.unresolved === 0 && gap.unmatched > 0
            : gap.code === "no-resolved-packages" && gap.unresolved === 0 && gap.unmatched === 0 && gap.resolved === 0
      );
      if (!validGap) throw new Error(`OSV static input gap lacks its measured preflight condition for ${input.path}`);
      if (!row.reason || invocation.status !== "not-assessed" || invocation.examinedPackages.length) throw new Error(`OSV static input gap is inconsistent for ${input.path}`);
      continue;
    }
    if (row.status !== "completed") throw new Error(`OSV live execution status is invalid for ${input.path}`);
    const missing = invocation.unassessedPackages.filter((identity) => !invocation.ambiguousPackages.includes(identity));
    const unversioned = invocation.unversionedPackages.filter((name) => !input.workspacePackages?.includes(packageIdentity(name, "unresolved")));
    if (missing.length || unversioned.length || invocation.status === "not-assessed") throw new Error(`OSV required live execution has incomplete provider coverage for ${input.path}`);
  }
}

export interface OsvVulnerability {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  // OSV mandates `score` be a CVSS VECTOR STRING ("CVSS:3.1/AV:N/..."), never a number.
  severity?: { type?: string; score?: string }[];
  affected?: OsvAffected[];
  references?: { type?: string; url?: string }[];
  database_specific?: { cwe_ids?: string[]; severity?: string };
}

type OsvAffected = OsvAffectedPackage;

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
export function osvUnavailableFinding(reason: string | OsvAssessment): Finding {
  const assessment = typeof reason === "string" ? undefined : reason;
  const gaps = assessment ? [
    ...assessment.invocations.filter((input) => input.status !== "assessed").map((input) => {
      const missing = input.unassessedPackages.length ? `${input.unassessedPackages.length - input.ambiguousPackages.length} resolved packages absent from provider output${input.ambiguousPackages.length ? `; ${input.ambiguousPackages.length} workspace/third-party origins ambiguous` : ""}` : `${input.unversionedPackages.length} provider packages lack resolved versions`;
      return `${input.path}: ${input.status === "not-assessed" ? (input.reason ?? "provider examination incomplete").split(/\.\s/)[0]!.slice(0, 160) : missing}`;
    }),
    ...assessment.inventory.inputs.filter((input) => ["unsupported", "unselected", "missing-input"].includes(input.disposition)).map((input) => `${input.path}: ${input.disposition === "unselected" ? "alternate tree not assessed" : input.disposition === "missing-input" ? "no supported resolved input" : "unsupported format"}`),
    ...assessment.invocations.filter((input) => input.notApplicablePackages.length).map((input) => `${input.path}: ${input.notApplicablePackages.length} workspace package/link records excluded from third-party examination`),
  ] : [];
  const summary = gaps.length ? `${gaps.slice(0, 3).join("; ")}${gaps.length > 3 ? `; ${gaps.length - 3} more input gaps` : ""}` : "no applicable Node lockfile population";
  return {
    id: "DEP-OSV-00",
    title: assessment ? `Dependency-CVE assessment ${assessment.status} — ${summary}` : "Dependency-CVE scan (osv-scanner) did not run",
    severity: "Info",
    precisionTier: "high",
    confidence: "N/A",
    category: "Dependency CVE",
    taxonomy: "Known-vulnerable dependency — coverage not assessed",
    location: "(repo-wide)",
    status: "Open",
    evidence: assessment ? `${assessment.reason} ${assessment.provenance} Falsifier: ${assessment.falsifier}` : `osv-scanner failed to run: ${reason}`,
    impact: (assessment ? `${assessment.reason} ` : "") + (assessment?.status === "not-applicable" ? "This prepared target has no applicable Node dependency population; no dependency examination is claimed." : assessment?.status === "assessed" ? "Third-party registry dependency assessment excludes the named first-party workspace metadata and links." : "Lockfile CVE coverage is incomplete for the named inputs; this is not a finding of zero vulnerable dependencies. Curated checks have their own scope."),
    fix: assessment ? "Resolve the named unsupported, unselected or missing-input boundaries and re-run the selected inputs with osv-scanner --all-packages. A target with no applicable ecosystem needs no Node lockfile." : "Install osv-scanner on the scanning machine (see this file's header) and re-run the scan.",
    value: 1,
    ease: 3,
    safety: 5,
  };
}

// Advisory `details` is Markdown and can run to several thousand characters (MEASURED 2026-07-26:
// 13,729 and 2,850 on two axios advisories). Take the first prose paragraph — the part that says
// what the vulnerability actually does — skipping the GitHub advisory template's leading
// "### Summary" heading and any fenced repro code, and fall back to the one-line summary, which is
// all Harvey used to have. The full text stays one click away behind the advisory link.
const OSV_IMPACT_CHARS = 600;

function osvImpact(vuln: OsvVulnerability): string {
  const paragraph = (vuln.details ?? "")
    .split(/\n\s*\n/)
    .map((p) => p.trim())
    .find((p) => p.length > 0 && !p.startsWith("#") && !p.startsWith("```"));
  if (!paragraph) return vuln.summary ?? "Known vulnerability in a resolved dependency version.";
  const body = paragraph.length > OSV_IMPACT_CHARS ? `${paragraph.slice(0, OSV_IMPACT_CHARS).trimEnd()}…` : paragraph;
  return vuln.summary && !body.startsWith(vuln.summary) ? `${vuln.summary} — ${body}` : body;
}

interface OsvEmittedRepresentatives {
  entries: readonly { source: string; sourceSha256: string; name: string; version: string; finding: Finding }[];
  record: (representativeId: string, reason: string) => void;
}

export function parseOsvFindings(result: OsvScanResult, represented?: OsvEmittedRepresentatives): Finding[] {
  const findings: Finding[] = [];
  for (const src of result.results ?? []) {
    for (const pkg of src.packages ?? []) {
      const name = pkg.package?.name ?? "unknown package";
      const version = pkg.package?.version ?? "unknown version";
      if (version === "") continue; // Unversioned provider rows are disclosed by the input assessment.
      for (const vuln of pkg.vulnerabilities ?? []) {
        const id = vuln.id ?? "unknown-id";
        const ids = new Set([id, ...(vuln.aliases ?? [])]);
        const representative = represented?.entries.find((entry) =>
          entry.source === src.source?.path && entry.name === name && entry.version === version &&
          entry.finding.dependency === name && entry.finding.taxonomy === "Known-vulnerable dependency" &&
          ids.has(entry.finding.id.replace(/^DEP-/, "")));
        if (representative) {
          represented!.record(representative.finding.id, `OSV also matched ${id}${vuln.aliases?.length ? ` (aliases: ${vuln.aliases.join(", ")})` : ""} against npm:${name}@${version} from ${representative.source} (input SHA-256 ${representative.sourceSha256}). This exact source/package/version/advisory occurrence is represented by this emitted ${representative.finding.id} finding, so the duplicate OSV row is not delivered separately.`);
          continue;
        }
        const group = pkg.groups?.find((g) => g.ids?.includes(id));
        const { severity, basis } = resolveOsvSeverity(vuln.database_specific?.severity, group?.max_severity);
        const rating = basis
          ? ` Rated ${severity} from ${basis}.`
          : ` This advisory carried NO machine-readable severity (no database_specific.severity, no group max_severity), so ${severity} is Harvey's default, not the advisory's rating — treat the rating as unknown and check ${id} by hand.`;
        // #1079: every one of these came out of the tool and was thrown away. The fixed version is
        // the difference between a remediation an engineer can act on and "upgrade past the
        // vulnerable range"; the CWE is what #455 routes tickets on, and no DEP-OSV row carried one.
        const remediation = osvRemediation(name, version, id, vuln.affected, pkg.package?.ecosystem);
        const fixedVersions = remediation.fixedVersions;
        const cwe = vuln.database_specific?.cwe_ids;
        const advisoryLinks = (vuln.references ?? [])
          .filter((r) => r.type === "ADVISORY" && r.url)
          .map((r) => r.url as string)
          .slice(0, 3);
        findings.push(
          mechanicalFinding({
            // #1175: the id used to be the advisory alone. OSV routinely reports one advisory
            // (e.g. a monorepo-wide dependency) against MULTIPLE packages — id-ing on the advisory
            // alone collided for the second package and validateFindings' unique-id check refused
            // to export the whole document. name+version make the id unique per affected instance
            // while staying stable for a genuine repeat of the same advisory/package/version, which
            // still collapses in dedupeFindings (byte-identical content, not just a matching id).
            id: `DEP-OSV-${id}-${name}@${version}${src.source?.path && !isAbsolute(src.source.path) && src.source.path.includes("/") ? `#${src.source.path}` : ""}`,
            // The summary stays in the title — it is the one line that says what the vuln IS. The
            // #1079 defect was that it was ALSO the impact; the fix is to give impact real content
            // (osvImpact below), not to strip the title down to an advisory id.
            title: `${name}@${version}: ${vuln.summary ?? id}${fixedVersions.length > 0 ? ` (advisory fix boundaries: ${fixedVersions.join(" / ")})` : ""}`,
            severity,
            category: "Dependency CVE",
            taxonomy: "Known-vulnerable dependency",
            location: `${src.source?.path ?? "lockfile"} (${name}@${version})`,
            dependency: name,
            ...(cwe?.length ? { cwe } : {}),
            evidence:
              `OSV-Scanner matched ${id}${vuln.aliases?.length ? ` (aliases: ${vuln.aliases.join(", ")})` : ""} against ${name}@${version}.${rating}` +
              (fixedVersions.length > 0 ? ` The advisory reports fixed-event boundaries at ${fixedVersions.join(" / ")}. These boundaries alone do not establish a safe upgrade; the remediation checks the complete affected-version set.` : " The advisory names no fixed version.") +
              (advisoryLinks.length > 0 ? ` Advisory: ${advisoryLinks.join(", ")}.` : ""),
            // The one-line summary was being used as BOTH title and impact while `details` — the
            // advisory's actual narrative — was discarded. Prefer details, capped: it runs to
            // several thousand characters and the report renders it inline.
            impact: osvImpact(vuln),
            fix: remediation.fix,
            precisionTier: "review",
          }),
        );
      }
    }
  }
  return findings;
}
