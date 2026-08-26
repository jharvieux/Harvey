// Supply chain: typosquat/slopsquat name check + unpinned-dependency / missing-lockfile checks
// + a live npm-registry existence cross-check (issue #66) for nonexistent/hallucinated deps.
//
// checkSlopsquat is the first live external network call in this repo's scan modules other than
// src/scan/supabase.ts and src/pentest/client.ts — it sends dependency NAMES only (never source)
// to https://registry.npmjs.org, matching the privacy pitch's "no code egress" (a name-only
// registry lookup is a smaller ask than code egress, but still noted as a scope decision).

import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { normalizeDependencyUrlInput, redactDependencyRange, type DependencyRangeEvidence, type Finding } from "../findings.js";
import { dependencyRangeEdge, type DependencyRangeEdge, type LicenseCandidate, type LicenseScope } from "../sbom.js";
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

// #1231 — the resolved-tree half of a widened check's input: which of the submitted names a
// manifest actually declares, and which lockfile the rest were reached through. Omitted entirely by
// a caller that only has a manifest, in which case every name is treated as declared.
interface TreeScope {
  declared: ReadonlySet<string>;
  source: string;
}

function reachedThroughTree(name: string, tree: TreeScope | undefined): string | undefined {
  return tree && !tree.declared.has(name) ? tree.source : undefined;
}

// Flags a dependency name that's edit-distance 1 from a popular package but not an exact
// match — the classic typosquat/slopsquat shape ("expres", "raect", "zodd"). Offline corpus
// match, not a live-registry lookup → always "review" precision.
//
// #1231 WIDENED TO THE RESOLVED TREE. The stated worry was review-tier noise over a few hundred
// transitive packages. MEASURED 2026-07-27 over three real resolved trees — targets/calibration
// (363 unique names), this repo's own pnpm-lock.yaml (495) and the AoP app's (336) — the widening
// produced ZERO additional rows beyond the planted `expres`. An edit-distance-1 collision with a
// 44-package popular corpus is simply rare. The declared/transitive distinction is carried into the
// finding anyway, because a typosquat a client can fix by editing their own manifest and one buried
// in someone else's dependency are different remediations.
export function checkTyposquat(depNames: readonly string[], tree?: TreeScope): Finding[] {
  const findings: Finding[] = [];
  const popularSet = new Set(POPULAR_PACKAGES);
  for (const name of depNames) {
    if (popularSet.has(name)) continue;
    const closest = POPULAR_PACKAGES.find((p) => levenshtein(name, p) === 1);
    if (closest) {
      const via = reachedThroughTree(name, tree);
      findings.push(
        mechanicalFinding({
          id: `SUP-TYPO-${name}`,
          title: `Dependency "${name}" is one edit from popular package "${closest}"`,
          severity: "High",
          category: "Supply chain",
          taxonomy: "Possible typosquat/slopsquat",
          location: via ? `${via} (${name})` : "package.json",
          evidence:
            `"${name}" has Levenshtein distance 1 from "${closest}" (offline corpus match, not a live-registry lookup).` +
            (via ? ` It is reached only through the resolved dependency tree in ${via}, not declared in any manifest.` : ""),
          impact: "If this is a typosquat, install pulls attacker-controlled code with full build/runtime access.",
          fix: via
            ? `Confirm "${name}" is the package the depending dependency intends; it is not yours to edit, so trace which package pulls it in (npm ls ${name}) before acting.`
            : `Confirm "${name}" is the package you intend; if not, replace with "${closest}".`,
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

// #1213: a registry lookup costs one live request per package, and the license candidate set is now
// the whole resolved tree — for a pnpm target, whose lockfile format records no `license` at all,
// that is EVERY package. Unbounded, a large monorepo would issue thousands of requests. Bounded,
// some packages go unclassified — which is fine only because the cap is DISCLOSED by name in
// SUP-LICENSE-00 / SUP-SLOPSQUAT-00, and because candidates are ordered declared-first so the
// budget is never starved by the transitive tail. #1231 applies the same bound to checkSlopsquat,
// whose input widened from the root manifest to every workspace member's.
const REGISTRY_LOOKUP_CAP = 300;

const REGISTRY_FIX = `Re-run the scan from a machine with direct access to ${NPM_REGISTRY} (no proxy interception, no rate limit in effect) so this tier reports a verdict instead of a coverage gap.`;

function sampleNames(names: readonly string[]): string {
  return names.length <= NAME_SAMPLE ? names.join(", ") : `${names.slice(0, NAME_SAMPLE).join(", ")} … and ${names.length - NAME_SAMPLE} more`;
}

function coverageFinding(args: { id: string; title: string; taxonomy: string; evidence: string; impact: string; fix: string; location?: string }): Finding {
  return {
    location: "package.json",
    ...args,
    severity: "Info",
    confidence: "N/A",
    category: "Supply chain",
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
      ` The declared half was read from ${describeManifestSources(scope.declaredFrom)}.` +
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

// #1232: a monorepo whose globs Harvey could not resolve degrades silently to the root manifest —
// same coverage either way (the root lockfile already resolves every member's packages), but the
// declared/transitive LABEL flips, which is what orders the registry-lookup budget and what the
// finding text tells the client. So the manifest count, and any glob that resolved to nothing, are
// stated rather than inferred from a number that looks plausible for a single-package repo.
function describeManifestSources(from: LicenseScope["declaredFrom"]): string {
  return (
    `${from.manifests} manifest${from.manifests === 1 ? "" : "s"} (${from.source})` +
    (from.unresolvedGlobs.length > 0 ? `; ${from.unresolvedGlobs.length} declared workspace glob(s) matched no package.json and were skipped: ${from.unresolvedGlobs.join(", ")}` : "") +
    (from.unreadable.length > 0 ? `; ${from.unreadable.length} manifest(s) could not be parsed and contributed nothing: ${from.unreadable.join(", ")}` : "")
  );
}

// #1774: declare range coverage from the parser's actual format/version receipts. Resolved
// component coverage and declared-range coverage are different populations; neither proves the other.
//
// #1350/#1351 corrected a similar false limit for dependency install scripts. Keep each scope
// claim tied to the format actually read, rather than inheriting the earlier blanket reasoning.
//
// #1351 closed the gap the false reason had excused: SUP-INSTALL-SCRIPT-DEP (checkDependencyInstallScripts,
// below) now reads `hasInstallScript` off every RESOLVED package, transitive ones included — but only
// when the lockfile is package-lock.json. pnpm-lock.yaml and yarn.lock carry no equivalent per-package
// flag in the form Harvey parses (MEASURED 2026-07-30: this repo's own pnpm-lock.yaml has zero
// `hasInstallScript`/`requiresBuild` occurrences despite esbuild — a package with a real postinstall —
// resolving twice), so that half stays a disclosed, tested gap rather than a silent zero.
export function supplyChainScopeFinding(s: {
  license: LicenseScope;
  treeNames: number;
  declaredNames: number;
  manifestDeclarations?: number;
  /** #1344 — workspace members depended on by their siblings. Never registry packages. */
  workspaceInternalNames: readonly string[];
  osvRan: boolean;
}): Finding {
  const treeWide = ["SUP-TYPO-* (typosquat)", "SUP-IOC-* (known-malicious names)", "SUP-LICENSE-* (license compliance)"];
  const manifestOnly = [
    `SUP-SLOPSQUAT-* over ${s.declaredNames} declared name${s.declaredNames === 1 ? "" : "s"}, because a package the lockfile resolved carries an integrity hash against a published tarball and has by construction been published — a registry HEAD over the transitive tree would spend thousands of live requests confirming what the lockfile already proves`,
  ];
  const rangeScopes = s.license.rangeScopes;
  const rangeDescription = rangeScopes.length === 0
    ? "No supported lockfile range source was found; only manifest declarations were assessed."
    : rangeScopes.map((scope) => `${scope.source} (${scope.format} version ${scope.sourceVersion}, ${scope.status}): ` +
      `${scope.edges.length} admitted third-party range edges, ${scope.examined} input unit(s) examined, ${scope.unread} present/unread unit(s), ${scope.unsupported} unsupported source schema(s). ` +
      `Excluded copies/constraints: root ${scope.excluded.root}, workspace ${scope.excluded.workspace}, link ${scope.excluded.link}, peer ${scope.excluded.peer}. ${scope.detail}`).join(" ");
  if (s.license.source === "package-lock.json") {
    treeWide.push("SUP-INSTALL-SCRIPT-DEP (a RESOLVED package's own install-time lifecycle script, transitive ones included), because package-lock.json v2/v3 records `hasInstallScript` per resolved entry (#1351)");
  } else {
    manifestOnly.push(`SUP-INSTALL-SCRIPT-DEP, not computable against ${s.license.source}: neither pnpm-lock.yaml nor yarn.lock records a per-package install-script flag in the form Harvey parses (MEASURED 2026-07-30 against this repo's own pnpm-lock.yaml — falsifier: \`grep -c hasInstallScript <the lockfile>\` returning >0 on a real pnpm/yarn project)`);
  }
  if (s.osvRan) {
    manifestOnly.push("DEP-CVE-* (the curated offline CVE table), because osv-scanner walked the whole lockfile this pass and widening the curated table would double-report its rows");
  } else {
    treeWide.push("DEP-CVE-* (the curated offline CVE table), widened for this pass because osv-scanner did not run");
  }
  return coverageFinding({
    id: "SUP-SCOPE-00",
    title: `Supply-chain scope: ${treeWide.length} resolved-tree check families; declaration ranges assessed separately`,
    taxonomy: "Coverage — supply-chain check scope",
    // Not "package.json": this row is a statement about every manifest AND the lockfile, and a
    // package.json location makes it substring-match the corpus entries keyed to that file — it
    // tripped P-UNPINNED-DEP's `match: ["unpinned"]` on its own "SUP-UNPINNED" mention.
    location: "(repo-wide)",
    evidence:
      `Declared set: ${s.declaredNames} package name${s.declaredNames === 1 ? "" : "s"} from ${describeManifestSources(s.license.declaredFrom)}. ` +
      `Resolved tree: ${s.treeNames} package name${s.treeNames === 1 ? "" : "s"} from ${s.license.source}. ` +
      `Read the whole resolved tree: ${treeWide.join("; ")}. ` +
      `Limited to the declared manifests: ${manifestOnly.join("; ")}.` +
      ` SUP-UNPINNED and SUP-NON-REGISTRY examine ${s.manifestDeclarations === undefined ? "root/workspace manifest" : s.manifestDeclarations + " manifest"} declarations plus admitted npm v2/v3 dependency/devDependency/optionalDependency edges. ${rangeDescription} ` +
      "Falsifier for an unread-format limit: a parser/registry replay of the named file that emits validated owner-path declaration edges and reports zero unread/unsupported units. Peer ranges are intentionally excluded compatibility constraints; the peer-only control in src/scan/mechanical.test.ts guards that boundary." +
      (s.workspaceInternalNames.length > 0
        ? ` Excluded from the registry-backed name checks (SUP-SLOPSQUAT-*, SUP-TYPO-*, SUP-IOC-*): ${s.workspaceInternalNames.length} workspace-internal package name(s) — ${s.workspaceInternalNames.join(", ")} — which resolve from inside this repo and are not published, so a registry lookup cannot say anything about them. Their CONTENTS are still scanned as first-party source; only the registry existence/name questions are skipped.`
        : ""),
    impact:
      "A manifest-scoped check cannot see a package reached only through the resolved dependency tree. The absence of its findings across that tree is a disclosed scope boundary, NOT a verdict that the tree is clean.",
    fix:
      "Keep root/workspace manifests authoritative and enforce a committed lockfile with frozen installs. npm v2/v3 declaration ranges are assessed; unread, unsupported or malformed range sources above need a validated format-specific parser/consumer before their absence of findings can count as coverage. For third-party declarations, update or override the owning dependency rather than editing generated lock metadata. Declare every workspace member so its manifest is included.",
  });
}

export const NETWORK_SKIPPED_REASON =
  "The live npm-registry existence check was deliberately skipped for this pass (skipNetworkChecks), so no registry lookup was made at all.";

// #1213: the license check's OWN half of the skip above. It is no longer all-or-nothing, because a
// package-lock.json target answers most of the tree offline (MEASURED 2026-07-27 on
// targets/calibration: 390 of 396 components carry a `license`) — only the registry FALLBACK is
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
//
// #1231 NOT WIDENED TO THE RESOLVED TREE, on the premise rather than the cost. A package that the
// lockfile resolved carries an integrity hash against a published tarball — it has, by
// construction, been published, so a registry HEAD over the transitive tree spends thousands of
// live requests confirming what the lockfile already proves. The names where the premise still
// holds are the DECLARED ones (a hallucinated name can sit in a manifest that was never installed),
// and those now come from every workspace member, not the root alone. That set is still unbounded
// in principle, so it takes the same cap-and-disclose treatment #1213 gave licensing: the cap is
// named in SUP-SLOPSQUAT-00 and the caller orders the root manifest's names first.
export async function checkSlopsquat(depNames: readonly string[], fetchImpl: typeof fetch = fetch): Promise<Finding[]> {
  const findings: Finding[] = [];
  const indeterminate: string[] = [];
  const reasons = new Set<string>();
  let lookups = 0;
  for (const name of depNames) {
    if (lookups >= REGISTRY_LOOKUP_CAP) {
      indeterminate.push(name);
      reasons.add(`the per-run registry-lookup cap of ${REGISTRY_LOOKUP_CAP} packages was reached (the root manifest's dependencies are looked up first)`);
      continue;
    }
    lookups++;
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

// Manifest declarations remain authoritative for first-party packages. npm v2/v3 also carries
// third-party declarations, each with its own owner path and section (#1774).
export interface DeclaredDependency {
  manifest: string;
  name: string;
  range: string;
  edge?: DependencyRangeEdge;
}

function declaredLabel({ manifest, name, range, edge }: DeclaredDependency): string {
  const label = `${name}@${redactDependencyRange(range)}`;
  if (edge && !edge.direct) return `${label} (${edge.source}#${edge.ownerPath}, ${edge.section})`;
  return manifest === "package.json" ? label : `${label} (${manifest})`;
}

// A finding aggregated over several manifests cannot claim one file as its location, and it must
// not silently claim the root's either — a monorepo reader would look in the wrong file.
function manifestLocation(deps: readonly DeclaredDependency[]): string {
  const manifests = [...new Set(deps.map((d) => d.manifest))];
  if (deps.some((dependency) => dependency.edge && !dependency.edge.direct)) return `${manifests.sort().join("; ")} (third-party declaration ranges)`;
  return manifests.length === 1 ? manifests[0]! : `${manifests.length} workspace manifests`;
}

// A third-party declaration must not be attributed to the client's manifest. Keep the original
// direct finding identities and a separate, stable tree rollup even when both populations match.
function declarationPopulations(deps: readonly DeclaredDependency[]): { direct: boolean; declarations: DeclaredDependency[] }[] {
  return [true, false].map((direct) => ({ direct, declarations: deps.filter((dependency) => (dependency.edge?.direct !== false) === direct) }));
}

function rangeEvidence(deps: readonly DeclaredDependency[], matched: readonly DeclaredDependency[], label: string): { evidence: string; artifact: DependencyRangeEvidence } {
  const groups = new Map<string, DeclaredDependency[]>();
  for (const dependency of matched) {
    const key = JSON.stringify([dependency.name, dependency.range]);
    const entries = groups.get(key) ?? [];
    entries.push(dependency);
    groups.set(key, entries);
  }
  const sorted = [...groups].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, entries]) => entries);
  const displayed = sorted.slice(0, 20);
  const abbreviate = (value: string): string => value.length > 240 ? `${value.slice(0, 240)}… (full value in dependencyRangeEvidence)` : value;
  const prose = displayed.map((entries) => {
    if (entries.length === 1) return abbreviate(declaredLabel(entries[0]!));
    const owners = [...new Set(entries.map((entry) => entry.edge && !entry.edge.direct ? `${entry.edge.source}#${entry.edge.ownerPath}` : entry.manifest))].sort();
    return `${abbreviate(`${entries[0]!.name}@${redactDependencyRange(entries[0]!.range)}`)} (${entries.length} declarations across ${owners.length} owners: ${owners.slice(0, 3).map(abbreviate).join(", ")}${owners.length > 3 ? `; ${owners.length - 3} more owners in dependencyRangeEvidence` : ""})`;
  });
  const edges: DependencyRangeEvidence["edges"] = matched.map((dependency) => {
    const edge = dependency.edge ?? dependencyRangeEdge({ source: dependency.manifest, format: "package-json", sourceVersion: "unversioned",
      ownerPath: dependency.manifest, ownerName: dependency.manifest, name: dependency.name, range: dependency.range, section: "dependencies", direct: true });
    const range = redactDependencyRange(edge.range);
    const ownerName = redactDependencyRange(edge.ownerName);
    const ownerVersion = edge.ownerVersion === undefined ? undefined : redactDependencyRange(edge.ownerVersion);
    return { identity: createHash("sha256").update(edge.identity).digest("hex"),
      source: edge.source, format: edge.format, sourceVersion: edge.sourceVersion,
      ownerPath: edge.ownerPath, ownerName, ...(ownerVersion === undefined ? {} : { ownerVersion }),
      name: edge.name, range, section: edge.section, direct: edge.direct,
      redacted: range !== edge.range || ownerName !== edge.ownerName || ownerVersion !== edge.ownerVersion };
  }).sort((a, b) => a.identity < b.identity ? -1 : a.identity > b.identity ? 1 : 0);
  const omitted = matched.length - displayed.reduce((n, entries) => n + entries.length, 0);
  return {
    evidence: `${label}: ${prose.join(", ")}. ` +
      `${matched.length} matching declarations in ${sorted.length} distinct name/range specifications; showing ${displayed.length} specifications${omitted > 0 ? ` (${omitted} declarations omitted from prose)` : ""}. ` +
      "The complete sorted matching-edge artifact, including owner paths and sections, is retained in this finding's dependencyRangeEvidence in findings JSON; URL credentials and query values are redacted.",
    artifact: { schemaVersion: 1, examined: deps.length, matched: matched.length, distinctSpecifications: sorted.length, displayedSpecifications: displayed.length, edges },
  };
}

// Unpinned = the declared range can resolve to more than one published version. Syntactic
// check on the range string → deterministic, "high" precision (whether an unpinned range is
// *acceptable* is a severity/triage judgment, not this check's confidence).
//
// Decision #1774: both range checks consume manifest declarations and validated npm v2/v3
// dependency/devDependency/optionalDependency edges. Other format limits come from parser receipts.
// Peer ranges remain excluded compatibility constraints; their observed population is disclosed.
// Falsifier for the widening: `pnpm exec vitest run src/scan/mechanical.test.ts -t "npm lockfile range edges"`
// fails when the shipping registry is reverted to manifest-only input.
export function checkUnpinnedDependencies(deps: readonly DeclaredDependency[]): Finding[] {
  return declarationPopulations(deps).flatMap(({ direct, declarations }) => {
    const unpinned = declarations.filter(({ range }) => {
      const r = range.trim();
      return r === "" || /^[\^~*]/.test(r) || /latest$/i.test(r) || /x$/i.test(r);
    });
    if (unpinned.length === 0) return [];
    const report = rangeEvidence(declarations, unpinned, direct ? "Unpinned" : "Third-party unpinned");
    return [{ ...mechanicalFinding({
      id: direct ? "SUP-UNPINNED" : "SUP-UNPINNED-TREE",
      title: `${unpinned.length} ${direct ? "direct" : "third-party"} dependency declarations use an unpinned version range`,
      severity: "Low",
      category: "Supply chain",
      taxonomy: "Unpinned dependency",
      location: manifestLocation(unpinned),
      evidence: report.evidence,
      impact: "A compromised upstream publish (or the next semver-compatible release) can land in installs without review, unless a lockfile is committed and enforced in CI.",
      fix: direct
        ? "Pin exact direct versions, or enforce a committed lockfile with frozen installs."
        : "Enforce a committed lockfile with frozen installs. Update or override the owning dependency when a third-party range needs tighter control; do not hand-edit generated lockfile ranges.",
      precisionTier: "high",
    }), dependencyRangeEvidence: report.artifact }];
  });
}

// A dependency range that resolves from somewhere other than the npm registry — a git/ssh/http
// URL, a github: shorthand, or a file: path. Deterministic syntactic fact (the protocol prefix),
// but whether it's a *problem* is a judgment (a private git dep can be intentional), and such a
// source is unpinned-by-default with no registry integrity/provenance → "review" tier. The
// vibe-code risk: an AI pastes `npm install some-git-url`, bypassing registry auditing entirely.
const NON_REGISTRY_RANGE = /^(git\+|git:|git@|ssh:|https?:|file:|github:|gitlab:|bitbucket:|[/\\]{2})/i;

// The same declared-range population and widening falsifier as checkUnpinnedDependencies apply;
// a resolved version is never substituted for the parent's raw protocol/range declaration.
export function checkNonRegistryDependencies(deps: readonly DeclaredDependency[]): Finding[] {
  return declarationPopulations(deps).flatMap(({ direct, declarations }) => {
    const nonRegistry = declarations.filter(({ range }) => NON_REGISTRY_RANGE.test(normalizeDependencyUrlInput(range)));
    if (nonRegistry.length === 0) return [];
    const report = rangeEvidence(declarations, nonRegistry, direct ? "Non-registry" : "Third-party non-registry");
    return [{ ...mechanicalFinding({
      id: direct ? "SUP-NON-REGISTRY" : "SUP-NON-REGISTRY-TREE",
      title: `${nonRegistry.length} ${direct ? "direct" : "third-party"} dependency declarations use a non-registry source (git/url/file)`,
      severity: "Medium",
      category: "Supply chain",
      taxonomy: "Non-registry dependency source",
      location: manifestLocation(nonRegistry),
      evidence: report.evidence,
      impact: "A git/url/file dependency bypasses the npm registry's auditing and integrity checks and is unpinned by default — a compromised or rewritten upstream lands in installs without review.",
      fix: direct
        ? "Prefer a registry-published, version-pinned dependency; if a git source is required, pin it to a commit SHA and vendor-review it."
        : "Review the owning dependency's source choice and update or override that dependency if needed; do not hand-edit generated lockfile ranges. Require immutable commit references for intentional git sources.",
      precisionTier: "review",
    }), dependencyRangeEvidence: report.artifact }];
  });
}

// Install-time lifecycle scripts (preinstall/install/postinstall) run arbitrary code on every
// `npm install`, so a compromised or malicious dependency (or the project itself) uses them as
// the execution foothold — the Shai-Hulud npm worm class. Presence is a deterministic fact but
// not proof of malice (many legit packages build native addons here) → always "review" tier.
const INSTALL_SCRIPT_HOOKS = ["preinstall", "install", "postinstall"];

// #1231: a lifecycle script only ever exists in a manifest, so there is no tree to widen to — but a
// workspace member's postinstall runs on the same `pnpm install` as the root's, and the root-only
// read never saw it. Aggregated into the one row because the id is fixed.
export function checkInstallScripts(manifests: readonly { label: string; scripts?: Record<string, string> }[]): Finding[] {
  const present = manifests.flatMap((m) => INSTALL_SCRIPT_HOOKS.filter((h) => typeof m.scripts?.[h] === "string").map((h) => ({ manifest: m.label, hook: h, cmd: m.scripts![h]! })));
  if (present.length === 0) return [];
  const hooks = [...new Set(present.map((p) => p.hook))];
  const declaring = [...new Set(present.map((p) => p.manifest))];
  return [
    mechanicalFinding({
      id: "SUP-INSTALL-SCRIPT",
      title: `package.json defines install lifecycle script(s): ${hooks.join(", ")}`,
      severity: "Medium",
      category: "Supply chain",
      taxonomy: "Install lifecycle script",
      location: declaring.length === 1 ? `${declaring[0]} (scripts)` : `${declaring.length} workspace manifests (scripts)`,
      evidence: present.map((p) => (p.manifest === "package.json" ? `${p.hook}: ${p.cmd}` : `${p.manifest} → ${p.hook}: ${p.cmd}`)).join("; "),
      impact: "Install-time scripts run on every `npm install` before any code review — the standard execution foothold for supply-chain worms (Shai-Hulud). Confirm each is expected.",
      fix: "Confirm the script is intentional; install with --ignore-scripts in CI where the build doesn't need it.",
      precisionTier: "review",
    }),
  ];
}

// #1351: checkInstallScripts (above) reads only the WORKSPACE's own manifest `scripts` blocks — it
// answers "does this project define an install hook", never "does a package this project depends on
// define one". That second question is the Shai-Hulud propagation path (a compromised or malicious
// package's own postinstall running on `npm install`), and it was previously disclosed as
// unanswerable ("a lifecycle script only ever exists in a manifest") — false: npm's package-lock.json
// v2/v3 records `hasInstallScript: true` per RESOLVED package, transitive ones included. This reads
// that field off the whole tree. Always "review": a resolved package running a build/native-addon
// script during install is common and mostly benign (esbuild, fsevents, sharp, …), so presence alone
// is not evidence of compromise — matching checkInstallScripts' own posture and how mainstream SCA
// tools report this class.
export function checkDependencyInstallScripts(candidates: readonly LicenseCandidate[]): Finding[] {
  const flagged = candidates.filter((c) => c.hasInstallScript === true);
  if (flagged.length === 0) return [];
  const names = flagged.map((c) => (c.version ? `${c.name}@${c.version}` : c.name)).sort();
  return [
    mechanicalFinding({
      id: "SUP-INSTALL-SCRIPT-DEP",
      title: `${flagged.length} resolved dependenc${flagged.length === 1 ? "y" : "ies"} declare an install-time lifecycle script`,
      severity: "Medium",
      category: "Supply chain",
      taxonomy: "Install lifecycle script (dependency)",
      location: "package-lock.json (resolved tree)",
      evidence: names.join(", "),
      impact: "Install-time scripts run on every `npm install` before any code review — the standard execution foothold for supply-chain worms (Shai-Hulud). This reads the RESOLVED tree, so a transitive dependency's own postinstall is included, not just this project's. Confirm each is expected.",
      fix: "Audit each listed package's install script; install with --ignore-scripts in CI and allowlist only the packages whose build genuinely needs one.",
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

// #1231 WIDENED TO THE RESOLVED TREE — the highest-value widening of the six, and the cheapest: an
// exact name match against a curated feed, offline, with no false-positive surface to grow. The
// event-stream incident is the canonical shape and it is a TRANSITIVE one: nobody declared
// flatmap-stream, event-stream pulled it in. Restricting the feed match to the root manifest looks
// for the payload in the one place the delivery mechanism does not put it.
export function checkKnownIoc(depNames: readonly string[], manifestPath = "package.json", tree?: TreeScope): Finding[] {
  const findings: Finding[] = [];
  for (const name of depNames) {
    if (!KNOWN_MALICIOUS_PACKAGES.has(name)) continue;
    const via = reachedThroughTree(name, tree);
    findings.push(
      mechanicalFinding({
        id: `SUP-IOC-${name}`,
        title: `Dependency "${name}" is a known-malicious package (IOC feed match)`,
        severity: "Critical",
        category: "Supply chain",
        taxonomy: "Known-malicious dependency",
        location: `${via ?? manifestPath} (${name})`,
        evidence:
          `"${name}" matches a curated indicator-of-compromise feed of packages published as malware (credential/crypto stealers). Any version is malicious.` +
          (via ? ` It is reached only through the resolved dependency tree in ${via}, not declared in any manifest — the event-stream delivery shape.` : ""),
        impact: "This package's install/runtime code exfiltrates secrets or wallet keys. Its presence in the manifest is a confirmed compromise, not a heuristic guess.",
        fix: via
          ? `Trace which dependency pulls "${name}" in (npm ls ${name}), remove or pin around it, and rotate any secrets reachable from the build/runtime.`
          : `Remove "${name}" immediately, rotate any secrets reachable from the build/runtime, and audit for the real package this was meant to be.`,
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

// License lookup over the RESOLVED DEPENDENCY TREE (src/sbom.ts's `licenseScope`, the same parse
// the SBOM uses). package-lock.json records `license` on essentially every entry (MEASURED
// 2026-07-27 on targets/calibration: 390 of 396), so for that format the classification is entirely
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
