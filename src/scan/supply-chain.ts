// Supply chain: typosquat/slopsquat name check + unpinned-dependency / missing-lockfile checks
// + a live npm-registry existence cross-check (issue #66) for nonexistent/hallucinated deps.
//
// checkSlopsquat is the first live external network call in this repo's scan modules other than
// src/scan/supabase.ts and src/pentest/client.ts — it sends dependency NAMES only (never source)
// to https://registry.npmjs.org, matching the privacy pitch's "no code egress" (a name-only
// registry lookup is a smaller ask than code egress, but still noted as a scope decision).

import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../findings.js";
import type { LicenseScope } from "../sbom.js";
import { mechanicalFinding } from "./common.js";

// High-traffic npm packages a typosquat/slopsquat target would mimic. Not exhaustive.
const POPULAR_PACKAGES = [
  "react", "react-dom", "next", "express", "lodash", "axios", "chalk", "commander",
  "typescript", "eslint", "webpack", "babel", "vite", "vitest", "jest", "postgres",
  "supabase", "@supabase/supabase-js", "zod", "prisma", "stripe", "tailwindcss",
  "dotenv", "uuid", "moment", "dayjs", "request", "async", "underscore", "jquery",
  "socket.io", "mongoose", "sequelize", "graphql", "apollo-server", "passport",
  "bcrypt", "jsonwebtoken", "nodemailer", "multer", "cors", "helmet", "morgan",
];

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i]![0] = i;
  for (let j = 0; j <= b.length; j++) dp[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i]![j] = a[i - 1] === b[j - 1] ? dp[i - 1]![j - 1]! : 1 + Math.min(dp[i - 1]![j]!, dp[i]![j - 1]!, dp[i - 1]![j - 1]!);
    }
  }
  return dp[a.length]![b.length]!;
}

// Flags a dependency name that's edit-distance 1 from a popular package but not an exact
// match — the classic typosquat/slopsquat shape ("expres", "raect", "zodd"). Offline corpus
// match, not a live-registry lookup → always "review" precision.
export function checkTyposquat(depNames: string[]): Finding[] {
  const findings: Finding[] = [];
  const popularSet = new Set(POPULAR_PACKAGES);
  for (const name of depNames) {
    if (popularSet.has(name)) continue;
    const closest = POPULAR_PACKAGES.find((p) => levenshtein(name, p) === 1);
    if (closest) {
      findings.push(
        mechanicalFinding({
          id: `SUP-TYPO-${name}`,
          title: `Dependency "${name}" is one edit from popular package "${closest}"`,
          severity: "High",
          category: "Supply chain",
          taxonomy: "Possible typosquat/slopsquat",
          location: "package.json",
          evidence: `"${name}" has Levenshtein distance 1 from "${closest}" (offline corpus match, not a live-registry lookup).`,
          impact: "If this is a typosquat, install pulls attacker-controlled code with full build/runtime access.",
          fix: `Confirm "${name}" is the package you intend; if not, replace with "${closest}".`,
          precisionTier: "review",
        }),
      );
    }
  }
  return findings;
}

const NPM_REGISTRY = "https://registry.npmjs.org";

// #1067: both registry-backed checks used to `console.warn(...); continue;` per package — a
// message on the OPERATOR'S TERMINAL, not in the deliverable. Offline, behind a proxy, or
// rate-limited, every package goes indeterminate and both checks return `[]`, which in the report
// is indistinguishable from "checked, nothing wrong". These two rows are the established
// DEP-OSV-00 / SEM-00 / M5-00 contract applied to the tier that was missing it, and the same rows
// ship when a lookup is deliberately skipped — a skipped tier is still an unassessed tier.
const NAME_SAMPLE = 20;

const REGISTRY_FIX = `Re-run the scan from a machine with direct access to ${NPM_REGISTRY} (no proxy interception, no rate limit in effect) so this tier reports a verdict instead of a coverage gap.`;

function sampleNames(names: readonly string[]): string {
  return names.length <= NAME_SAMPLE ? names.join(", ") : `${names.slice(0, NAME_SAMPLE).join(", ")} … and ${names.length - NAME_SAMPLE} more`;
}

function coverageFinding(args: { id: string; title: string; taxonomy: string; evidence: string; impact: string; fix: string }): Finding {
  return {
    ...args,
    severity: "Info",
    confidence: "N/A",
    category: "Supply chain",
    location: "package.json",
    status: "Open",
    value: 1,
    ease: 4,
    safety: 5,
    mechanical: true,
  };
}

export function slopsquatCoverageFinding(names: readonly string[], reason: string): Finding {
  return coverageFinding({
    id: "SUP-SLOPSQUAT-00",
    title: `Hallucinated-dependency (slopsquat) existence check did not run for ${names.length} dependenc${names.length === 1 ? "y" : "ies"}`,
    taxonomy: "Coverage — npm-registry existence check not assessed",
    evidence: `${reason} Not assessed: ${sampleNames(names)}.`,
    impact:
      "The registry 404 is the only deterministic proof that a dependency name was never published. Without it, a hallucinated package name in this manifest would draw no finding — a disclosed coverage gap, NOT a finding that every dependency exists.",
    fix: REGISTRY_FIX,
  });
}

// #1213: this row used to be scoped to the DIRECT dependencies whose registry lookup failed, which
// made the defect it was supposed to disclose invisible — the transitive tree was not merely
// unassessed, it was never a candidate, and the row said nothing about it. It now always states the
// scope it worked over (how many resolved packages, how many declared vs transitive-only, and which
// lockfile they came from) and fires even with zero indeterminate names whenever that scope is
// itself incomplete — a manifest-only fallback means the whole transitive tier went unexamined, and
// an unstated limitation reads as a clean license bill.
export function licenseCoverageFinding(names: readonly string[], reason: string, scope?: LicenseScope): Finding {
  const scopeSentence = scope
    ? `License scope: ${scope.candidates.length} package${scope.candidates.length === 1 ? "" : "s"} (${scope.direct} declared in a manifest, ${scope.transitive} reached only through the resolved tree) from ${scope.source}.` +
      (scope.completeness === "complete" ? "" : ` The dependency inventory itself is ${scope.completeness}: ${scope.note}`)
    : undefined;
  const treeIncomplete = scope !== undefined && scope.completeness !== "complete";
  return coverageFinding({
    id: "SUP-LICENSE-00",
    title:
      names.length === 0
        ? "Dependency license-compliance check could not see the whole dependency tree"
        : `Dependency license-compliance check did not run for ${names.length} package${names.length === 1 ? "" : "s"}`,
    taxonomy: "Coverage — dependency license not assessed",
    evidence: [scopeSentence, reason, names.length > 0 ? `Not assessed: ${sampleNames(names)}.` : undefined].filter(Boolean).join(" "),
    impact:
      "License classification reads the license the lockfile or the registry records; without it no copyleft or unlicensed dependency can be identified. The absence of license findings for these packages is a disclosed coverage gap, NOT a clean license bill.",
    fix: treeIncomplete
      ? `Commit a lockfile Harvey can parse (package-lock.json, pnpm-lock.yaml or yarn.lock) so the transitive tree is in scope. ${REGISTRY_FIX}`
      : REGISTRY_FIX,
  });
}

export const NETWORK_SKIPPED_REASON =
  "The live npm-registry existence check was deliberately skipped for this pass (skipNetworkChecks), so no registry lookup was made at all.";

// #1213: the license check's OWN half of the skip above. It is no longer all-or-nothing, because a
// package-lock.json target answers most of the tree offline (MEASURED 2026-07-27 on
// targets/calibration: 390 of 395 components carry a `license`) — only the registry FALLBACK is
// nondeterministic. So the classification runs and the packages the lockfile cannot answer are
// disclosed, instead of the whole tier going silent.
const REGISTRY_SKIPPED_REASON =
  "the live npm-registry fallback was deliberately skipped for this pass (skipNetworkChecks), so packages whose license the lockfile does not record could not be classified";

// Live npm-registry existence cross-check (P-SLOPSQUAT): an AI coding assistant can hallucinate
// a plausible-looking package name that was never published. A 404 from the registry is
// deterministic ground truth for "this name doesn't exist" — not a heuristic corpus match — so
// it's "high" precision, unlike the offline edit-distance check above. A network error can't
// distinguish "doesn't exist" from "registry unreachable", so it's left unflagged (indeterminate)
// rather than risk a false positive on a real dependency; typo/edit-distance-to-a-real-package
// detection (the "review" half of P-SLOPSQUAT's tier split) stays in checkTyposquat above, not
// duplicated here.
export async function checkSlopsquat(depNames: string[], fetchImpl: typeof fetch = fetch): Promise<Finding[]> {
  const findings: Finding[] = [];
  const indeterminate: string[] = [];
  const reasons = new Set<string>();
  for (const name of depNames) {
    let res: Response;
    try {
      res = await fetchImpl(`${NPM_REGISTRY}/${encodeURIComponent(name)}`, { method: "HEAD" });
    } catch (err) {
      indeterminate.push(name);
      reasons.add(`registry unreachable (${err instanceof Error ? err.message : String(err)})`);
      continue;
    }
    if (res.status === 404) {
      findings.push(
        mechanicalFinding({
          id: `SUP-SLOPSQUAT-${name}`,
          title: `Dependency "${name}" does not exist on the npm registry`,
          severity: "High",
          category: "Supply chain",
          taxonomy: "Slopsquatted/hallucinated dependency",
          location: `package.json (${name})`,
          evidence: `HEAD ${NPM_REGISTRY}/${name} returned 404 — no package named "${name}" has ever been published.`,
          impact: "A hallucinated dependency name is a hijack-in-waiting: whoever publishes it first captures every future install. This is confirmed nonexistent, not a heuristic guess.",
          fix: `Confirm "${name}" is the package you intend. If it's hallucinated, find the real package or vendor the code directly.`,
          precisionTier: "high",
        }),
      );
      continue;
    }
    if (!res.ok) {
      indeterminate.push(name);
      reasons.add(`registry returned HTTP ${res.status}`);
    }
  }
  if (indeterminate.length > 0) {
    findings.push(slopsquatCoverageFinding(indeterminate, `The npm-registry existence check could not reach a verdict: ${[...reasons].join("; ")}.`));
  }
  return findings;
}

export type DependencyMap = Record<string, string>;

// Unpinned = the declared range can resolve to more than one published version. Syntactic
// check on the range string → deterministic, "high" precision (whether an unpinned range is
// *acceptable* is a severity/triage judgment, not this check's confidence).
export function checkUnpinnedDependencies(deps: DependencyMap): Finding[] {
  const unpinned = Object.entries(deps).filter(([, range]) => {
    const r = range.trim();
    return r === "" || /^[\^~*]/.test(r) || /latest$/i.test(r) || /x$/i.test(r);
  });
  if (unpinned.length === 0) return [];
  return [
    mechanicalFinding({
      id: "SUP-UNPINNED",
      title: `${unpinned.length} dependencies declared with an unpinned version range`,
      severity: "Low",
      category: "Supply chain",
      taxonomy: "Unpinned dependency",
      location: "package.json",
      evidence: `Unpinned: ${unpinned.map(([n, r]) => `${n}@${r}`).join(", ")}.`,
      impact: "A compromised upstream publish (or the next semver-compatible release) can land in installs without review, unless a lockfile is committed and enforced in CI.",
      fix: "Pin exact versions, or rely on a committed, CI-enforced lockfile (frozen install) as the actual pin.",
      precisionTier: "high",
    }),
  ];
}

// A dependency range that resolves from somewhere other than the npm registry — a git/ssh/http
// URL, a github: shorthand, or a file: path. Deterministic syntactic fact (the protocol prefix),
// but whether it's a *problem* is a judgment (a private git dep can be intentional), and such a
// source is unpinned-by-default with no registry integrity/provenance → "review" tier. The
// vibe-code risk: an AI pastes `npm install some-git-url`, bypassing registry auditing entirely.
const NON_REGISTRY_RANGE = /^(git\+|git:|git@|ssh:|https?:|file:|github:|gitlab:|bitbucket:)/i;

export function checkNonRegistryDependencies(deps: DependencyMap): Finding[] {
  const nonRegistry = Object.entries(deps).filter(([, range]) => NON_REGISTRY_RANGE.test(range.trim()));
  if (nonRegistry.length === 0) return [];
  return [
    mechanicalFinding({
      id: "SUP-NON-REGISTRY",
      title: `${nonRegistry.length} dependencies resolve from a non-registry source (git/url/file)`,
      severity: "Medium",
      category: "Supply chain",
      taxonomy: "Non-registry dependency source",
      location: "package.json",
      evidence: `Non-registry: ${nonRegistry.map(([n, r]) => `${n}@${r}`).join(", ")}.`,
      impact: "A git/url/file dependency bypasses the npm registry's auditing and integrity checks and is unpinned by default — a compromised or rewritten upstream lands in installs without review.",
      fix: "Prefer a registry-published, version-pinned dependency; if a git source is required, pin it to a commit SHA and vendor-review it.",
      precisionTier: "review",
    }),
  ];
}

// Install-time lifecycle scripts (preinstall/install/postinstall) run arbitrary code on every
// `npm install`, so a compromised or malicious dependency (or the project itself) uses them as
// the execution foothold — the Shai-Hulud npm worm class. Presence is a deterministic fact but
// not proof of malice (many legit packages build native addons here) → always "review" tier.
const INSTALL_SCRIPT_HOOKS = ["preinstall", "install", "postinstall"];

export function checkInstallScripts(scripts: Record<string, string>): Finding[] {
  const present = INSTALL_SCRIPT_HOOKS.filter((h) => typeof scripts[h] === "string");
  if (present.length === 0) return [];
  return [
    mechanicalFinding({
      id: "SUP-INSTALL-SCRIPT",
      title: `package.json defines install lifecycle script(s): ${present.join(", ")}`,
      severity: "Medium",
      category: "Supply chain",
      taxonomy: "Install lifecycle script",
      location: "package.json (scripts)",
      evidence: present.map((h) => `${h}: ${scripts[h]}`).join("; "),
      impact: "Install-time scripts run on every `npm install` before any code review — the standard execution foothold for supply-chain worms (Shai-Hulud). Confirm each is expected.",
      fix: "Confirm the script is intentional; install with --ignore-scripts in CI where the build doesn't need it.",
      precisionTier: "review",
    }),
  ];
}

// `label` is the project-root path reported in the finding's location; it defaults to the real
// `projectDir` (existsSync always runs against `projectDir`). A caller scanning a secondary
// manifest from a scratch copy passes a stable relative label (e.g. "fixtures/legacy-app") so
// the finding's location doesn't leak the throwaway scratch path.
// Curated indicator-of-compromise feed: npm package NAMES that were published purely as
// malware (credential/crypto stealers), not legitimate packages that had a single compromised
// release. Keyed on name because these packages ARE the payload — any version is malicious — so
// an exact name match is ground truth ("high"), unlike the edit-distance heuristic above. Sources
// (public, historical): npm's 2017 "crossenv" typosquat takedown and the 2018 event-stream /
// flatmap-stream incident. These are DATA ONLY — never fetched, installed, or vendored. Legit
// packages that merely share a risky trait (e.g. a postinstall build script) are deliberately
// absent, so a name like `esbuild` clears — the FP a "package has install scripts = malicious"
// heuristic would throw.
const KNOWN_MALICIOUS_PACKAGES = new Set([
  "flatmap-stream", // event-stream incident (2018): crypto-wallet stealer, published solely as the payload.
  "crossenv", // npm 2017 takedown: typosquat of cross-env, exfiltrated env vars on install.
  "babelcli", // same 2017 campaign (typosquat of babel-cli).
  "mssql-node", // same 2017 campaign.
  "nodesqlite", // same 2017 campaign.
  "node-fabric", // same 2017 campaign.
]);

export function checkKnownIoc(depNames: string[], manifestPath = "package.json"): Finding[] {
  const findings: Finding[] = [];
  for (const name of depNames) {
    if (!KNOWN_MALICIOUS_PACKAGES.has(name)) continue;
    findings.push(
      mechanicalFinding({
        id: `SUP-IOC-${name}`,
        title: `Dependency "${name}" is a known-malicious package (IOC feed match)`,
        severity: "Critical",
        category: "Supply chain",
        taxonomy: "Known-malicious dependency",
        location: `${manifestPath} (${name})`,
        evidence: `"${name}" matches a curated indicator-of-compromise feed of packages published as malware (credential/crypto stealers). Any version is malicious.`,
        impact: "This package's install/runtime code exfiltrates secrets or wallet keys. Its presence in the manifest is a confirmed compromise, not a heuristic guess.",
        fix: `Remove "${name}" immediately, rotate any secrets reachable from the build/runtime, and audit for the real package this was meant to be.`,
        precisionTier: "high",
      }),
    );
  }
  return findings;
}

// #456 — license compliance. SPDX identifiers a proprietary/commercial distribution can adopt
// without a reciprocal source-disclosure obligation. Not exhaustive, but every id here is an
// uncontroversial, widely-used permissive license.
const PERMISSIVE_SPDX = new Set([
  "MIT", "MIT-0", "ISC", "0BSD", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear",
  "Apache-2.0", "Unlicense", "CC0-1.0", "WTFPL", "Zlib", "BlueOak-1.0.0", "Python-2.0",
  "PostgreSQL", "OpenSSL", "Artistic-2.0",
]);

// Strong/network copyleft: reciprocal source-disclosure obligations that conflict with a closed,
// proprietary distribution — the class the issue asks us to flag. LGPL is weaker (a dynamic-
// linking carve-out) but a bundled Next.js/npm dependency doesn't get that carve-out in practice,
// so it's included per the issue's "GPL/AGPL/LGPL and similar strong-copyleft" wording.
const COPYLEFT_SPDX = new Set([
  "GPL-1.0", "GPL-1.0-only", "GPL-1.0-or-later",
  "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-2.0+",
  "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "GPL-3.0+",
  "AGPL-1.0", "AGPL-1.0-only", "AGPL-1.0-or-later",
  "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
  "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
  "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
  "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
  "SSPL-1.0", "OSL-3.0", "EUPL-1.1", "EUPL-1.2", "CPAL-1.0",
]);

type LicenseClass = "permissive" | "copyleft" | "unknown";

// A bare SPDX id, or a simple SPDX expression ("(MIT OR Apache-2.0)", "GPL-2.0 OR MIT"). An OR
// expression is a CHOICE, so it's permissive if any alternative is; anything else (a single id,
// or an AND-combined multi-license that must satisfy every term) is copyleft if any term is.
// "UNLICENSED" is npm's own convention for "no grant to use this" — treated as unknown, never a
// permissive default.
export function classifyLicense(raw: string | undefined): LicenseClass {
  const trimmed = raw?.trim();
  if (!trimmed || /^UNLICENSED$/i.test(trimmed)) return "unknown";
  const isOr = /\bOR\b/i.test(trimmed);
  const terms = trimmed
    .replace(/[()]/g, "")
    .split(/\s+(?:OR|AND)\s+/i)
    .map((t) => t.trim())
    .filter(Boolean);
  const classes = terms.map((t): LicenseClass => (PERMISSIVE_SPDX.has(t) ? "permissive" : COPYLEFT_SPDX.has(t) ? "copyleft" : "unknown"));
  if (classes.every((c) => c === "unknown")) return "unknown";
  if (isOr) return classes.includes("permissive") ? "permissive" : "copyleft";
  return classes.includes("copyleft") ? "copyleft" : classes.includes("permissive") ? "permissive" : "unknown";
}

// npm registry packument shape (subset used here) — `license`/`licenses` at the TOP LEVEL are a
// denormalized snapshot of the LATEST publish, not necessarily the version actually installed;
// `versions[<v>]` carries each release's own metadata. (#1099)
interface NpmPackageMeta {
  license?: string | { type?: string };
  licenses?: { type?: string }[];
}
interface NpmPackument extends NpmPackageMeta {
  versions?: Record<string, NpmPackageMeta>;
}

function extractLicenseFrom(meta: NpmPackageMeta): string | undefined {
  if (typeof meta.license === "string") return meta.license;
  if (meta.license && typeof meta.license.type === "string") return meta.license.type;
  if (Array.isArray(meta.licenses)) {
    const ids = meta.licenses.map((l) => l.type).filter((t): t is string => typeof t === "string");
    if (ids.length > 0) return ids.join(" OR "); // pre-npm5 array = a choice of alternatives
  }
  return undefined;
}

// #1099: prefer the INSTALLED version's own license (`versions[<v>]`) when the caller knows which
// version resolved — the top-level `license` is the latest publish's, which can differ from (and,
// for a package whose license changed between releases, actively mislead about) the version a
// project actually depends on. Falls back to the top-level snapshot when no version is known or
// the packument has no per-version entry for it (some registries/mirrors omit `versions`).
function extractLicenseId(pkg: NpmPackument, version?: string): string | undefined {
  const versioned = version !== undefined ? pkg.versions?.[version] : undefined;
  return (versioned && extractLicenseFrom(versioned)) ?? extractLicenseFrom(pkg);
}

// #1213: a registry lookup costs one live request per package, and the candidate set is now the
// whole resolved tree — for a pnpm target, whose lockfile format records no `license` at all, that
// is EVERY package. Unbounded, a large monorepo would issue thousands of requests. Bounded, some
// packages go unclassified — which is fine only because the cap is DISCLOSED in SUP-LICENSE-00 by
// name, and because candidates are ordered declared-first so the budget is never starved by the
// transitive tail.
const REGISTRY_LOOKUP_CAP = 300;

// License lookup over the RESOLVED DEPENDENCY TREE (src/sbom.ts's `licenseScope`, the same parse
// the SBOM uses). package-lock.json records `license` on essentially every entry (MEASURED
// 2026-07-27 on targets/calibration: 390 of 395), so for that format the classification is entirely
// offline and the registry is queried only for the remainder; pnpm-lock.yaml and yarn.lock record
// none, so for those every candidate needs the network fallback and the cap above binds.
//
// The network path keeps its old trust boundary, same as checkSlopsquat above: a name-only request
// (no code egress). It asks for the INSTALLED version's own manifest (`/<name>/<version>`) when the
// tree resolved one — the version's license, not the latest publish's (#1099), and a few KB instead
// of a whole packument — falling back to the packument when the version is unknown or that route
// answers non-OK. A network failure or non-OK status leaves that package's license indeterminate —
// which is not the same as "no license", and since #1067 is not the same as silence either: the
// indeterminate names are counted into SUP-LICENSE-00. `licenseTier` on each returned finding is
// "high" for a copyleft match (the SPDX id itself is deterministic, self-declared registry data)
// and "review" for an unknown/missing/UNLICENSED license (the `license` field can be simply absent
// from otherwise-fine metadata, so it needs a human look before treating it as a real gap).
// Non-grading regardless of tier (src/quick-scan.ts) — a license conflict is a legal judgment, not
// a security verdict.
export async function checkLicenseCompliance(
  scope: LicenseScope,
  opts: { fetchImpl?: typeof fetch; skipRegistry?: boolean } = {},
): Promise<Finding[]> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const findings: Finding[] = [];
  const indeterminate: string[] = [];
  const reasons = new Set<string>();
  let lookups = 0;
  const ordered = [...scope.candidates].sort((a, b) => Number(b.direct) - Number(a.direct));
  for (const candidate of ordered) {
    const { name, version } = candidate;
    const coordinate = version ? `${name}@${version}` : name;
    let licenseId = candidate.license;
    let source = "the lockfile";
    if (licenseId === undefined) {
      if (opts.skipRegistry) {
        indeterminate.push(coordinate);
        reasons.add(REGISTRY_SKIPPED_REASON);
        continue;
      }
      if (lookups >= REGISTRY_LOOKUP_CAP) {
        indeterminate.push(coordinate);
        reasons.add(`the per-run registry-lookup cap of ${REGISTRY_LOOKUP_CAP} packages was reached (declared dependencies are looked up first)`);
        continue;
      }
      lookups++;
      const meta = await fetchLicenseMeta(fetchImpl, name, version);
      if ("error" in meta) {
        indeterminate.push(coordinate);
        reasons.add(meta.error);
        continue;
      }
      licenseId = extractLicenseId(meta.body, version);
      source = "the npm registry";
    }
    const cls = classifyLicense(licenseId);
    if (cls === "permissive") continue;
    const reach = candidate.direct ? "declared in a manifest" : "reached only through the resolved dependency tree";
    if (cls === "unknown") {
      findings.push(
        mechanicalFinding({
          id: `SUP-LICENSE-UNKNOWN-${coordinate}`,
          title: `Dependency "${coordinate}" has no clear license — review`,
          severity: "Low",
          category: "License compliance",
          taxonomy: "Unknown/missing dependency license",
          location: `package.json (${coordinate})`,
          evidence: licenseId
            ? `${source} reports license "${licenseId}" for "${coordinate}" (${reach}), which does not resolve to a recognized SPDX identifier.`
            : `${source} has no license field for "${coordinate}" (${reach}).`,
          impact: "A dependency with no confirmed license (missing, ambiguous, or npm's UNLICENSED marker) carries no confirmed grant to use, modify, or redistribute it — a legal exposure in a distributed/commercial product, distinct from a security bug.",
          fix: `Confirm "${name}"'s actual license (its repository/README, or the maintainer directly) and record the finding; replace it if no usable license exists.`,
          precisionTier: "review",
        }),
      );
      continue;
    }
    findings.push(
      mechanicalFinding({
        id: `SUP-LICENSE-COPYLEFT-${coordinate}`,
        title: `Dependency "${coordinate}" is licensed ${licenseId} — possible copyleft conflict`,
        severity: "Medium",
        category: "License compliance",
        taxonomy: "Copyleft license conflict",
        location: `package.json (${coordinate})`,
        evidence: `${source} reports "${coordinate}" under "${licenseId}" (SPDX), a strong-copyleft license. This package is ${reach}.`,
        impact: "Strong-copyleft licenses (GPL/AGPL/LGPL and similar) impose reciprocal source-disclosure obligations that typically conflict with a closed/proprietary distribution — this needs a legal review before shipping, not just a code fix.",
        fix: `Confirm the actual distribution/linking model with counsel, or replace "${name}" with a permissively-licensed alternative.`,
        precisionTier: "high",
      }),
    );
  }
  if (indeterminate.length > 0 || scope.completeness !== "complete") {
    const reason = indeterminate.length > 0 ? `The dependency license lookup could not reach a verdict: ${[...reasons].join("; ")}.` : "";
    findings.push(licenseCoverageFinding(indeterminate, reason, scope));
  }
  return findings;
}

// `/<name>/<version>` returns that release's own manifest — the license of the version actually
// installed, in a few KB rather than a whole packument. Not every registry mirror serves it, so a
// non-OK answer falls back to the packument rather than being recorded as a coverage gap.
async function fetchLicenseMeta(fetchImpl: typeof fetch, name: string, version?: string): Promise<{ body: NpmPackument } | { error: string }> {
  const base = `${NPM_REGISTRY}/${encodeURIComponent(name)}`;
  const urls = version ? [`${base}/${encodeURIComponent(version)}`, base] : [base];
  let lastStatus = 0;
  for (const url of urls) {
    let res: Response;
    try {
      res = await fetchImpl(url);
    } catch (err) {
      return { error: `registry unreachable (${err instanceof Error ? err.message : String(err)})` };
    }
    if (res.ok) return { body: (await res.json()) as NpmPackument };
    lastStatus = res.status;
  }
  return { error: `registry returned HTTP ${lastStatus}` };
}

export function checkLockfilePresence(projectDir: string, label = projectDir): Finding[] {
  const lockfiles = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock"];
  const present = lockfiles.some((f) => existsSync(join(projectDir, f)));
  if (present) return [];
  return [
    mechanicalFinding({
      id: "SUP-NO-LOCKFILE",
      title: "No lockfile found",
      severity: "Medium",
      category: "Supply chain",
      taxonomy: "Missing lockfile",
      location: label,
      evidence: `None of ${lockfiles.join(", ")} present.`,
      impact: "Every install can resolve different transitive versions — no reproducible, reviewable dependency tree.",
      fix: "Commit a lockfile and run installs with --frozen-lockfile / npm ci in CI.",
      precisionTier: "high",
    }),
  ];
}
