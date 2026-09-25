// CycloneDX 1.5 SBOM export (#887) — the procurement artifact. Not a detection capability: an SBOM
// finds nothing. It exists because enterprise and public-sector buyers require one contractually
// and it is a line on every vendor security questionnaire. Hand-rolled: CycloneDX is plain JSON.
//
// ── Where the component list comes from ──────────────────────────────────────────────────────────
// The issue that asked for this assumed Harvey already parses lockfiles. It does not — measured
// 2026-07-23: `checkLockfilePresence` only checks that a lockfile EXISTS, and osv-scanner (an
// external binary) does the parsing, reporting back only the packages that have vulnerabilities
// (7 of 393 on targets/calibration). So the parsing is here, dependency-free, per format.
//
// ── Completeness is the whole risk with an SBOM ──────────────────────────────────────────────────
// An SBOM's failure mode is identical to the coverage ledger's: a partial one presented as whole is
// worse than none, because the buyer's tooling will treat the missing components as absent rather
// than unlisted. So completeness is stated in the document, three ways:
//   • `compositions[].aggregate` — CycloneDX's own field for exactly this ("complete" only when a
//     lockfile was fully parsed; "incomplete" for a manifest-only fallback; "unknown" otherwise).
//   • `metadata.properties` — a plain-text "harvey:completeness" note naming the source and, when
//     the tree is not resolved, saying so in a sentence a human reads.
//   • buildSbom returns `warning`, so the CLI prints it and the operator sees it at generation time.
// A lockfile Harvey cannot parse never yields a silently-thinner BOM: it degrades to the manifest's
// direct dependencies and says that is what happened. #1079 closed the remaining hole: completeness
// used to be `components.length > 0`, so a parser recovering 1 of 900 entries still said "complete".
// Each parser now COUNTS the entries it could not resolve and completeness is derived from that.
//
// ── What the BOM carries per component ───────────────────────────────────────────────────────────
// name, version, purl, dev scope, plus (#1079) CycloneDX `licenses[]` and `hashes[]` — the two
// fields an enterprise buyer's checklist actually looks for. Both come from the lockfile Harvey
// already parses (MEASURED 2026-07-27 on targets/calibration/package-lock.json: 396 resolved
// components, 390 with `license`, 395 with `integrity` — the single entry carrying neither is
// #1231's deliberately name-only `crossenv` IOC plant), so they cost nothing and require no network.

import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, posix } from "node:path";
import { parse as parseYaml } from "yaml";
import parseSpdxExpression from "spdx-expression-parse";
import { collectWorkspaceManifests } from "./workspaces.js";

const SPEC_VERSION = "1.5";

type SbomCompleteness = "complete" | "incomplete" | "unknown";

interface SbomComponent {
  name: string;
  version: string;
  dev?: boolean;
  // #1079: both sit in the lockfile Harvey already parses, and both are on the checklist an
  // enterprise buyer runs against a delivered SBOM. `license` is npm's SPDX string (id or
  // expression); `integrity` is the Subresource-Integrity string (`sha512-<base64>`) that lets a
  // consumer verify the artifact they have is the one this BOM describes.
  license?: string;
  integrity?: string;
  // #1351: npm's package-lock.json v2/v3 records this per RESOLVED package, transitive ones
  // included — carried through so checkDependencyInstallScripts can flag the tree, not just this
  // project's own manifests. pnpm-lock.yaml and yarn.lock do not carry an equivalent per-package
  // flag Harvey can parse (MEASURED 2026-07-30: this repo's own pnpm-lock.yaml has zero
  // `hasInstallScript`/`requiresBuild` occurrences despite esbuild, which ships a real postinstall,
  // resolving twice), so it stays undefined for those formats.
  hasInstallScript?: boolean;
}

// The parser's public component identity is the package that npm resolved, while package-lock
// records where npm installed it separately. License scope needs both facts: a manifest can
// declare `alias: npm:actual@version`, and that declaration applies only when that alias path
// actually resolved. Parser metadata retains this provenance; buildSbom emits the components.
interface DependencyInstallation {
  path: string;
  // Unresolved entries and links occupy a path and stop resolution before farther ancestors.
  // Resolved published packages carry their identity here.
  name?: string;
  version?: string;
  /** Repo-relative workspace directory proven by a package-lock `link` entry. */
  localPath?: string;
}

interface LicenseOrigin {
  component: SbomComponent;
  path?: string;
  // An npm path fallback does not prove the package's published name when an alias
  // declaration reaches that installation. Yarn selectors likewise need resolution.
  explicitName: boolean;
  aliasSpecifier?: string;
}

interface UnresolvedLockAlias {
  name: string;
  declared: string;
  path: string;
}

// #1079: `unmatched` is the whole point of this shape. Completeness used to be derived from
// `components.length > 0`, so a parser that recovered 1 of 900 entries still reported "complete"
// — the partial-presented-as-whole failure the module header calls THE risk with an SBOM. Every
// parser now counts the lockfile entries it saw and could not resolve, and completeness is
// derived from that count.
interface ParsedLock {
  components: SbomComponent[];
  installations: DependencyInstallation[];
  licenseOrigins: LicenseOrigin[];
  unresolvedLockAliases: UnresolvedLockAlias[];
  unmatched: number;
  ranges: DependencyRangeScope;
}

interface DependencySource {
  components: SbomComponent[];
  installations: DependencyInstallation[];
  licenseOrigins: LicenseOrigin[];
  unresolvedLockAliases: UnresolvedLockAlias[];
  source: string; // the file the components came from
  completeness: SbomCompleteness;
  note: string;
  rangeScopes: DependencyRangeScope[];
}

export type DependencyRangeSection = "dependencies" | "devDependencies" | "optionalDependencies";
export type DependencyRangeFormat = "package-json" | "package-lock" | "pnpm" | "yarn" | "npm-shrinkwrap";

/** A declaration edge, not the resolved component at its destination (#1774). */
export interface DependencyRangeEdge {
  schemaVersion: 1;
  identity: string;
  source: string;
  format: DependencyRangeFormat;
  sourceVersion: string;
  ownerPath: string;
  ownerName: string;
  ownerVersion?: string;
  name: string;
  range: string;
  section: DependencyRangeSection;
  direct: boolean;
}

export interface DependencyRangeScope {
  schemaVersion: 1;
  source: string;
  format: DependencyRangeFormat;
  sourceVersion: string;
  status: "read" | "partial" | "present-but-unread" | "unsupported" | "unreadable";
  edges: DependencyRangeEdge[];
  /** Candidate range values, including malformed maps counted as one unread unit. */
  examined: number;
  unread: number;
  /** Unsupported source schemas, not a guessed count of missing dependency edges. */
  unsupported: number;
  excluded: { root: number; workspace: number; link: number; peer: number };
  detail: string;
}

const RANGE_SECTIONS: readonly DependencyRangeSection[] = ["dependencies", "devDependencies", "optionalDependencies"];
const PACKAGE_NAME = /^(?:@[a-z0-9_.~-]+\/)?[a-z0-9_.~-]+$/i;
const validPackageName = (name: string): boolean => PACKAGE_NAME.test(name) && name.split("/").every((part) => part !== "." && part !== "..");
// npm installs aliases under the alias path, but records the package's registry identity in
// metadata. A path remains the fallback for ordinary entries and older lockfile shapes that do
// not carry `name`.
function packageMetadataName(meta: { name?: unknown }, pathName: string): string {
  return typeof meta.name === "string" && validPackageName(meta.name) ? meta.name : pathName;
}

function npmAliasTarget(specifier: unknown): { name: string; range: string } | undefined {
  if (typeof specifier !== "string" || !specifier.startsWith("npm:")) return undefined;
  const target = specifier.slice("npm:".length);
  const versionAt = target.lastIndexOf("@");
  const name = versionAt > 0 ? target.slice(0, versionAt) : target;
  return validPackageName(name) ? { name, range: versionAt > 0 ? target.slice(versionAt + 1) : "*" } : undefined;
}

interface AliasVersion {
  parts: number[];
  prerelease: string[];
}

function aliasVersion(text: string): AliasVersion | undefined {
  // npm's version parser rejects strings longer than 256 characters.
  if (text.length > 256) return undefined;
  const match = /^v?([\dxX*]+)(?:\.([\dxX*]+))?(?:\.([\dxX*]+))?(?:-([\w.-]+))?(?:\+([\w.-]+))?$/.exec(text);
  if (!match) return undefined;
  const parts: number[] = [];
  let wildcard = false;
  for (const part of match.slice(1, 4)) {
    if (part === undefined || /^[xX*]$/.test(part)) { wildcard = true; continue; }
    if (wildcard || !/^(0|[1-9]\d*)$/.test(part) || !Number.isSafeInteger(Number(part))) return undefined;
    parts.push(Number(part));
  }
  const prerelease = match[4]?.split(".") ?? [];
  if ((match[4] || match[5]) && parts.length !== 3) return undefined;
  if ([...prerelease, ...(match[5]?.split(".") ?? [])].some((part) => !/^[0-9A-Za-z-]+$/.test(part))) return undefined;
  // Larger numeric prerelease identifiers can round together in npm's comparisons;
  // this offline proof leaves those declarations unresolved.
  if (prerelease.some((part) => /^\d+$/.test(part) && (!/^(0|[1-9]\d*)$/.test(part) || !Number.isSafeInteger(Number(part))))) return undefined;
  return { parts, prerelease };
}

function compareAliasVersions(a: AliasVersion, b: AliasVersion): number {
  for (let i = 0; i < 3; i++) {
    const diff = (a.parts[i] ?? 0) - (b.parts[i] ?? 0);
    if (diff) return diff;
  }
  if (a.prerelease.length === 0 || b.prerelease.length === 0) return b.prerelease.length - a.prerelease.length;
  for (let i = 0; i < Math.max(a.prerelease.length, b.prerelease.length); i++) {
    const x = a.prerelease[i], y = b.prerelease[i];
    if (x === y) continue;
    if (x === undefined || y === undefined) return x === undefined ? -1 : 1;
    const xNumeric = /^\d+$/.test(x), yNumeric = /^\d+$/.test(y);
    if (xNumeric !== yNumeric) return xNumeric ? -1 : 1;
    if (xNumeric && x.length !== y.length) return x.length - y.length;
    return x < y ? -1 : 1;
  }
  return 0;
}

// Offline proof for npm alias version/range declarations. Dist-tags and unfamiliar syntax do
// not prove which version was selected; they keep the unresolved-declaration candidate. This
// deliberately does not use a transitive tool dependency as a production semver dependency.
function aliasVersionMatches(version: string, range: string): boolean {
  const actual = aliasVersion(version);
  if (!actual || actual.parts.length !== 3) return false;
  type Comparator = { operator: string; version: AliasVersion };
  const alternatives = range.split("||").map((branch): Comparator[] | undefined => {
    const comparators: Comparator[] = [];
    // npm expands a hyphen range only when it occupies the whole alternative.
    const tokens = branch.trim().replace(/^(\S+)\s+-\s+(\S+)$/, ">=$1 <=$2").replace(/([<>=~^]+)\s+/g, "$1").split(/\s+/).filter(Boolean);
    for (const token of tokens) {
      const match = /^(<=|>=|<|>|=|\^|~>?)?(.*)$/.exec(token)!;
      const operator = match[1] ?? "=", value = aliasVersion(match[2]!);
      if (!value) return undefined;
      const size = value.parts.length;
      const floor: AliasVersion = { parts: [0, 1, 2].map((i) => value.parts[i] ?? 0), prerelease: value.prerelease };
      const upper = (index: number): AliasVersion => ({ parts: floor.parts.map((part, i) => i < index ? part : i === index ? part + 1 : 0), prerelease: ["0"] });
      const add = (op: string, v: AliasVersion, collapseZero = true): void => {
        if (collapseZero && op === ">=" && !v.prerelease.length && v.parts.every((part) => part === 0)) return;
        comparators.push({ operator: op, version: v });
      };
      if (size === 0) {
        if (operator === "<" || operator === ">") add("<", { parts: [0, 0, 0], prerelease: ["0"] });
      } else if (operator === "^" || operator.startsWith("~")) {
        add(">=", floor);
        const firstNonzero = value.parts.findIndex((part) => part !== 0);
        add("<", upper(operator === "^" ? firstNonzero < 0 ? size - 1 : firstNonzero : Math.min(size - 1, 1)));
      } else if (size === 3) {
        // npm preserves the full v-prefixed comparator instead of collapsing >=0.0.0.
        add(operator, floor, !match[2]!.startsWith("v"));
      } else if (operator === "=") {
        add(">=", floor); add("<", upper(size - 1));
      } else if (operator === ">") {
        add(">=", { ...upper(size - 1), prerelease: [] });
      } else if (operator === "<=") {
        add("<", upper(size - 1));
      } else {
        add(operator, operator === "<" ? { ...floor, prerelease: ["0"] } : floor);
      }
    }
    return comparators.some(({ version: bound }) => bound.parts.some((part) => !Number.isSafeInteger(part))) ? undefined : comparators;
  });
  if (alternatives.some((comparators) => comparators === undefined)) return false;
  // npm collapses a union containing an unconstrained alternative to *, which excludes prereleases.
  if (alternatives.some((comparators) => comparators!.length === 0)) return actual.prerelease.length === 0;
  return alternatives.some((comparators) => {
    if (actual.prerelease.length && !comparators!.some(({ version: bound }) => bound.prerelease.length &&
      actual.parts.every((part, i) => part === bound.parts[i]))) return false;
    return comparators!.every(({ operator, version: bound }) => {
      const comparison = compareAliasVersions(actual, bound);
      return operator === ">=" ? comparison >= 0 : operator === ">" ? comparison > 0 :
        operator === "<=" ? comparison <= 0 : operator === "<" ? comparison < 0 : comparison === 0;
    });
  });
}

function visibleInstallation(installations: Map<string, DependencyInstallation>, manifest: string, name: string): DependencyInstallation | undefined {
  if (!validPackageName(name)) return undefined;
  let directory = posix.dirname(manifest);
  for (;;) {
    if (posix.basename(directory) !== "node_modules") {
      const installation = installations.get(posix.join(directory, "node_modules", name));
      if (installation) return installation;
    }
    if (directory === ".") return undefined;
    directory = posix.dirname(directory);
  }
}
const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const rangeSlots = (value: unknown): number => value === undefined ? 0 : isRecord(value) ? Object.keys(value).length : 1;
const rangeCount = (value: Record<string, unknown>): number => RANGE_SECTIONS.reduce((n, section) => n + rangeSlots(value[section]), 0);

export function dependencyRangeEdge(input: Omit<DependencyRangeEdge, "schemaVersion" | "identity">): DependencyRangeEdge {
  // The tuple avoids delimiter collisions. Digests keep credentials in arbitrary package metadata
  // and ranges out of receipt identities; raw values are projected safely for client output.
  const digest = (value: string): string => createHash("sha256").update(value).digest("hex");
  const identity = JSON.stringify([1, input.source, input.format, input.sourceVersion, input.ownerPath,
    digest(input.ownerName), input.ownerVersion === undefined ? null : digest(input.ownerVersion), input.section, input.name,
    digest(input.range), input.direct]);
  return { schemaVersion: 1, identity, ...input };
}

function rangeScope(source: string, format: DependencyRangeFormat, sourceVersion: string): DependencyRangeScope {
  return { schemaVersion: 1, source, format, sourceVersion, status: "read", edges: [], examined: 0,
    unread: 0, unsupported: 0, excluded: { root: 0, workspace: 0, link: 0, peer: 0 }, detail: "" };
}

function packageLockRanges(lock: Record<string, unknown>): DependencyRangeScope {
  const version = typeof lock.lockfileVersion === "number" ? String(lock.lockfileVersion) : "unknown";
  const scope = rangeScope("package-lock.json", "package-lock", version);
  const supported = version === "2" || version === "3";
  if (!supported) {
    scope.status = "unsupported";
    scope.unsupported = 1;
    const walk = (value: unknown): void => {
      if (!isRecord(value)) return;
      for (const entry of Object.values(value)) {
        if (!isRecord(entry)) { scope.unread++; continue; }
        scope.unread += rangeSlots(entry.requires);
        walk(entry.dependencies);
      }
    };
    if (isRecord(lock.packages)) for (const value of Object.values(lock.packages)) {
      if (isRecord(value)) { scope.unread += rangeCount(value); scope.excluded.peer += rangeSlots(value.peerDependencies); }
      else scope.unread++;
    }
    walk(lock.dependencies);
    scope.examined = scope.unread;
    scope.detail = `npm lockfile version ${version} is not admitted by the v2/v3 range parser; ${scope.unread} observed range value(s) or malformed record(s) are present but unread. v1 requires maps can retain declared ranges.`;
    return scope;
  }
  if (!isRecord(lock.packages)) {
    scope.status = "unreadable";
    scope.examined = scope.unread = 1;
    scope.detail = "The npm v2/v3 packages map is missing or malformed; declared ranges were not assessed.";
    return scope;
  }
  const workspacePaths = new Set(Object.values(lock.packages).flatMap((entry) =>
    isRecord(entry) && entry.link === true && typeof entry.resolved === "string" ? [entry.resolved.replace(/^\.\//, "")] : []));
  for (const [path, value] of Object.entries(lock.packages)) {
    if (!isRecord(value)) { scope.examined++; scope.unread++; continue; }
    const count = rangeCount(value);
    const peers = rangeSlots(value.peerDependencies);
    scope.excluded.peer += peers;
    if (path === "") { scope.excluded.root += count; continue; }
    if (value.link === true) { scope.excluded.link += count; continue; }
    if (workspacePaths.has(path)) { scope.excluded.workspace += count; continue; }
    const owners = path.startsWith("node_modules/") ? path.slice("node_modules/".length).split("/node_modules/") : [];
    const pathName = owners.length > 0 && owners.every(validPackageName) ? owners.at(-1) : undefined;
    const name = pathName === undefined ? undefined : packageMetadataName(value, pathName);
    const ownerValid = name !== undefined && typeof value.version === "string" && value.version.length > 0 &&
      (value.link === undefined || value.link === false);
    if (!ownerValid) { scope.examined += Math.max(count, 1); scope.unread += Math.max(count, 1); continue; }
    for (const section of RANGE_SECTIONS) {
      const map = value[section];
      if (map === undefined) continue;
      if (!isRecord(map)) { scope.examined++; scope.unread++; continue; }
      for (const [child, raw] of Object.entries(map)) {
        scope.examined++;
        if (typeof raw !== "string" || !validPackageName(child)) { scope.unread++; continue; }
        scope.edges.push(dependencyRangeEdge({ source: scope.source, format: scope.format, sourceVersion: version,
          ownerPath: path, ownerName: name!, ownerVersion: value.version as string, name: child, range: raw, section, direct: false }));
      }
    }
  }
  scope.edges.sort((a, b) => a.identity < b.identity ? -1 : a.identity > b.identity ? 1 : 0);
  scope.status = scope.unread > 0 ? "partial" : "read";
  scope.detail = "Read npm v2/v3 third-party dependency, devDependency and optionalDependency declarations. Root/workspace/link copies are excluded because manifests are authoritative; peer ranges are intentionally excluded compatibility constraints.";
  return scope;
}

function pnpmRanges(text: string): DependencyRangeScope {
  const scope = rangeScope("pnpm-lock.yaml", "pnpm", "unknown");
  try {
    const value: unknown = parseYaml(text);
    if (!isRecord(value)) throw new Error("missing YAML mapping");
    scope.sourceVersion = typeof value.lockfileVersion === "string" || typeof value.lockfileVersion === "number" ? String(value.lockfileVersion) : "unknown";
    let malformedMaps = 0;
    const mapEntries = (map: unknown): [string, unknown][] => {
      if (map === undefined) return [];
      if (!isRecord(map)) { malformedMaps++; return []; }
      return Object.entries(map);
    };
    const importers: [string, unknown][] = value.importers === undefined ? [[".", value]] : mapEntries(value.importers);
    let orphanSpecifiers = 0;
    for (const [importerPath, importer] of importers) {
      if (!isRecord(importer)) { malformedMaps++; continue; }
      const legacySpecifiers = isRecord(importer.specifiers) ? importer.specifiers : {};
      const consumedLegacySpecifiers = new Set<string>();
      if (importer.specifiers !== undefined && !isRecord(importer.specifiers)) malformedMaps++;
      for (const section of RANGE_SECTIONS) {
        for (const [name, dependency] of mapEntries(importer[section])) {
          scope.examined++;
          const specifier = isRecord(dependency) && typeof dependency.specifier === "string"
            ? dependency.specifier
            : typeof legacySpecifiers[name] === "string" ? legacySpecifiers[name] : undefined;
          if (typeof legacySpecifiers[name] === "string") consumedLegacySpecifiers.add(name);
          if (!validPackageName(name) || specifier === undefined) { scope.unread++; continue; }
          const ownerPath = importerPath === "." ? "package.json" : `${importerPath.replace(/^\.\//, "")}/package.json`;
          scope.edges.push(dependencyRangeEdge({ source: scope.source, format: scope.format, sourceVersion: scope.sourceVersion,
            ownerPath, ownerName: importerPath, name, range: specifier, section, direct: true }));
        }
      }
      orphanSpecifiers += Object.keys(legacySpecifiers).filter((name) => !consumedLegacySpecifiers.has(name)).length;
    }
    let resolvedReferences = 0;
    for (const section of ["packages", "snapshots"]) {
      for (const [, entry] of mapEntries(value[section])) {
        if (!isRecord(entry)) { malformedMaps++; continue; }
        resolvedReferences += RANGE_SECTIONS.reduce((count, field) => count + mapEntries(entry[field]).length, 0);
        scope.excluded.peer += mapEntries(entry.peerDependencies).length;
      }
    }
    scope.unread += resolvedReferences + malformedMaps + orphanSpecifiers;
    scope.examined += resolvedReferences + malformedMaps + orphanSpecifiers;
    scope.unsupported = resolvedReferences > 0 ? 1 : 0;
    scope.edges.sort((a, b) => a.identity.localeCompare(b.identity));
    scope.status = scope.unread > 0 ? "partial" : "read";
    scope.detail = `pnpm ${scope.sourceVersion}: ${scope.edges.length} importer/root specifier value(s) were validated and admitted as declaration edges. ${orphanSpecifiers} orphan importer/root specifier value(s) had no dependency declaration to bind and remain present but unread. ${malformedMaps} malformed map ${malformedMaps === 1 ? "boundary was" : "boundaries were"} counted as present but unread input units, not guessed dependency edges. ${resolvedReferences} package/snapshot dependency reference(s) lack declaration specifiers and remain explicitly present but unread; resolved versions were not substituted as ranges. ${scope.excluded.peer} peer range(s) are intentionally excluded compatibility constraints.`;
  } catch {
    scope.status = "unreadable";
    scope.examined = scope.unread = 1;
    scope.detail = "pnpm YAML is unreadable; declared-range coverage is not assessed, not empty.";
  }
  return scope;
}

function yarnRanges(text: string): DependencyRangeScope {
  const berry = /^__metadata:/m.test(text) || /^\s+version:/m.test(text);
  const metadata = /^__metadata:\s*\n((?:[ \t]+[^\n]*\n?)*)/m.exec(text)?.[1] ?? "";
  const metadataVersion = /^\s{2}version:\s*["']?([\d.]+)/m.exec(metadata)?.[1];
  const scope = rangeScope("yarn.lock", "yarn", berry ? `Berry ${metadataVersion ?? "unknown"}` : "classic v1");
  scope.status = "present-but-unread";
  scope.unsupported = 1;
  let selectors = 0;
  let requested = 0;
  let section = "";
  for (const line of text.split("\n")) {
    if (/^\S.*:\s*$/.test(line)) {
      section = "";
      if (/^"?(@?[^@"\s][^@"]*)@/.test(line)) selectors += line.replace(/:\s*$/, "").split(/,\s*/).length;
    }
    const header = /^\s{2}(dependencies|optionalDependencies|peerDependencies):\s*$/.exec(line);
    if (header) { section = header[1]!; continue; }
    if (/^\s{2}\S/.test(line)) section = "";
    if (section && /^\s{4}\S/.test(line)) {
      if (section === "peerDependencies") scope.excluded.peer++;
      else requested++;
    }
  }
  scope.examined = scope.unread = selectors + requested;
  if (selectors === 0) { scope.status = "unreadable"; scope.examined = scope.unread = 1; }
  scope.detail = `Yarn ${scope.sourceVersion}: ${selectors} selector range(s) and ${requested} dependency-block value(s) are present but unread by the declared-range consumer; the component line parser discards their declaration provenance. ${scope.excluded.peer} peer range(s) are intentionally excluded compatibility constraints. No Yarn range edges are admitted.`;
  return scope;
}

// package-lock.json v2/v3 keys every installed package by its node_modules path; v1 nests them
// under `dependencies`. Both carry the RESOLVED version, which is what an SBOM needs.
export function parsePackageLock(text: string): ParsedLock {
  interface LockEntry {
    name?: unknown;
    version?: string;
    dev?: boolean;
    // npm normally records an SPDX string here, but older/generated package-lock files can
    // preserve package.json's deprecated `{ type, url }` license object. Keep the parse boundary
    // honest: JSON is untrusted and must not smuggle an object into LicenseCandidate's string.
    license?: unknown;
    integrity?: string;
    link?: boolean;
    resolved?: unknown;
    hasInstallScript?: boolean;
    dependencies?: Record<string, unknown>;
  }
  const raw: unknown = JSON.parse(text);
  if (!isRecord(raw)) throw new Error("package-lock.json is not an object");
  const lock = raw as { packages?: Record<string, LockEntry>; dependencies?: Record<string, LockEntry> };
  const out = new Map<string, SbomComponent>();
  const installations = new Map<string, DependencyInstallation>();
  const licenseOrigins: LicenseOrigin[] = [];
  const unresolvedLockAliases: UnresolvedLockAlias[] = [];
  let unmatched = 0;
  const licenseId = (raw: unknown): string | undefined => {
    if (typeof raw === "string") return raw.trim() || undefined;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
    const type = (raw as { type?: unknown }).type;
    return typeof type === "string" ? type.trim() || undefined : undefined;
  };
  const add = (name: string, meta: LockEntry, path: string): void => {
    const license = licenseId(meta.license);
    const component: SbomComponent = {
      name,
      version: meta.version ?? "",
      ...(meta.dev ? { dev: true } : {}),
      ...(license ? { license } : {}),
      ...(meta.integrity ? { integrity: meta.integrity } : {}),
      ...(typeof meta.hasInstallScript === "boolean" ? { hasInstallScript: meta.hasInstallScript } : {}),
    };
    out.set(`${name}@${meta.version ?? ""}`, component);
    licenseOrigins.push({ component, path, explicitName: typeof meta.name === "string" && validPackageName(meta.name) });
    if (meta.version) installations.set(path, { path, name, version: meta.version });
  };

  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    // "" is the root project itself, not a dependency; it is the BOM's subject, not a component.
    // A `link: true` entry is a workspace symlink, not a published artifact — also not a component.
    if (path === "") continue;
    if (!isRecord(meta)) { installations.set(path, { path }); unmatched++; continue; }
    installations.set(path, {
      path,
      ...(meta.link === true && typeof meta.resolved === "string" && !posix.isAbsolute(meta.resolved) && !posix.normalize(meta.resolved).startsWith("../")
        ? { localPath: posix.normalize(meta.resolved).replace(/^\.\//, "") }
        : {}),
    });
    if (meta.link) continue;
    const pathName = path.replace(/^(?:.*\/)?node_modules\//, "");
    if (!pathName || !meta.version) {
      unmatched++;
      continue;
    }
    if (typeof meta.version === "string" && meta.version.startsWith("npm:")) {
      unresolvedLockAliases.push({ name: pathName, declared: meta.version, path });
      unmatched++;
      continue;
    }
    add(packageMetadataName(meta, pathName), meta, path);
  }

  const walkV1 = (deps: Record<string, LockEntry>, owner = "."): void => {
    for (const [name, meta] of Object.entries(deps)) {
      const path = `${owner === "." ? "" : `${owner}/`}node_modules/${name}`;
      installations.set(path, { path });
      if (!isRecord(meta)) { unmatched++; continue; }
      if (typeof meta.version === "string" && meta.version.startsWith("npm:")) {
        // A v1 alias descriptor is not a selected package version. Its target and
        // selected release remain unproved even when the string contains a version.
        unresolvedLockAliases.push({ name, declared: meta.version, path });
        unmatched++;
      } else if (meta.version) add(packageMetadataName(meta, name), meta, path);
      else unmatched++;
      if (meta.dependencies) walkV1(meta.dependencies as Record<string, LockEntry>, path);
    }
  };
  if (!lock.packages && lock.dependencies) walkV1(lock.dependencies);

  return { components: [...out.values()], installations: [...installations.values()], licenseOrigins, unresolvedLockAliases, unmatched, ranges: packageLockRanges(raw) };
}

// pnpm-lock.yaml, `packages:` section only. Three key shapes across lockfile versions:
//   v5: /braces/2.3.2:      v6: /braces@2.3.2:      v9: 'braces@2.3.2':
// Parsed by line rather than with a YAML dependency (adding one is an operator decision, and the
// section's grammar is this narrow). pnpm carries no license field, but every entry's
// `resolution: {integrity: …}` is the same SRI hash package-lock records (#1079).
export function parsePnpmLock(text: string): ParsedLock {
  const out = new Map<string, SbomComponent>();
  const installations = new Map<string, DependencyInstallation>();
  const selectedPackages = new Map<string, { name: string; selected: string }>();
  try {
    const lock: unknown = parseYaml(text);
    if (isRecord(lock)) {
      const importers = isRecord(lock.importers) ? lock.importers : { ".": lock };
      for (const [importerPath, rawImporter] of Object.entries(importers)) {
        if (!isRecord(rawImporter)) continue;
        const ownerDir = importerPath === "." ? "" : importerPath.replace(/^\.\//, "");
        for (const section of RANGE_SECTIONS) {
          const dependencies = rawImporter[section];
          if (!isRecord(dependencies)) continue;
          for (const [name, rawDependency] of Object.entries(dependencies)) {
            if (!validPackageName(name)) continue;
            const selected = isRecord(rawDependency) ? rawDependency.version : rawDependency;
            const path = posix.join(ownerDir, "node_modules", name);
            if (typeof selected !== "string") continue;
            if (!selected.startsWith("link:")) {
              installations.delete(path);
              selectedPackages.set(path, { name, selected });
              continue;
            }
            selectedPackages.delete(path);
            const target = selected.slice("link:".length);
            if (!target || posix.isAbsolute(target)) continue;
            const localPath = posix.normalize(posix.join(ownerDir, target));
            if (localPath.startsWith("../")) continue;
            installations.set(path, { path, localPath });
          }
        }
      }
    }
  } catch {
    // The range parser records malformed YAML in completeness; no link is proved here.
  }
  let inPackages = false;
  let unmatched = 0;
  let current: SbomComponent | undefined;
  for (const line of text.split("\n")) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    // Any other column-0 key ends the section.
    if (inPackages && /^\S/.test(line)) break;
    if (!inPackages) continue;

    const integrity = /^\s{4}resolution:\s*\{\s*integrity:\s*([^,}\s]+)/.exec(line);
    if (current && integrity?.[1]) {
      current.integrity = integrity[1];
      continue;
    }

    // A key line is at exactly two spaces of indent and ends with a colon. One that the version
    // regex cannot resolve is a package this parser did not recover — counted, not ignored.
    if (!/^\s{2}\S.*:\s*$/.test(line)) continue;
    const key = /^\s{2}'?\/?(@?[^'@\s]+(?:\/[^'@\s]+)?)[@/]([0-9][^'\s:(]*)'?(?:\([^)]*\))*'?:\s*$/.exec(line);
    if (key?.[1] && key[2]) {
      current = { name: key[1], version: key[2] };
      out.set(`${key[1]}@${key[2]}`, current);
    } else {
      current = undefined;
      unmatched++;
    }
  }
  for (const { name, selected } of selectedPackages.values()) {
    const alias = npmAliasTarget(selected);
    const selectedName = alias?.name ?? name;
    const rawVersion = alias?.range ?? selected;
    const version = /^([0-9][^:(]*)/.exec(rawVersion)?.[1];
    if (!version || !out.has(`${selectedName}@${version}`)) unmatched++;
  }
  return { components: [...out.values()], installations: [...installations.values()], licenseOrigins: [...out.values()].map((component) => ({ component, explicitName: true })), unresolvedLockAliases: [], unmatched, ranges: pnpmRanges(text) };
}

// yarn.lock — both the v1 format (`braces@^2.3.1:` / `  version "2.3.2"`) and Berry's
// (`"braces@npm:^2.3.1":` / `  version: 2.3.2`). v1 records `integrity`, Berry records `checksum`.
export function parseYarnLock(text: string): ParsedLock {
  const out = new Map<string, SbomComponent>();
  const licenseOrigins: LicenseOrigin[] = [];
  const isBerry = /^__metadata:\s*$/m.test(text);
  let name: string | undefined;
  let aliasSpecifier: string | undefined;
  let current: SbomComponent | undefined;
  let currentOrigin: LicenseOrigin | undefined;
  let unmatched = 0;
  for (const line of text.split("\n")) {
    if (line.startsWith("__metadata:")) continue;
    const header = /^"?(@?[^@"\s][^@"]*)@/.exec(line);
    if (/^\S/.test(line) && line.trimEnd().endsWith(":")) {
      // A header that never reaches a `version` line yielded no component — count it when the
      // next header arrives, so a truncated or unfamiliar entry cannot pass as a clean parse.
      if (name) unmatched++;
      name = header?.[1];
      const selector = line.trim().replace(/:$/, "").split(/,\s*/)[0]!.replace(/^"|"$/g, "");
      const range = name ? selector.slice(name.length + 1) : "";
      // Berry uses npm: for ordinary ranges/tags; classic also allows the shorthand npm:name alias.
      aliasSpecifier = range.startsWith("npm:") && (!isBerry || /^npm:(?:@[^/,\s]+\/)?[^@,\s]+@/.test(range)) ? range : undefined;
      current = undefined;
      currentOrigin = undefined;
      if (!name) unmatched++;
      continue;
    }
    const integrity = /^\s+(?:integrity|checksum):?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (current && integrity?.[1]) {
      current.integrity = integrity[1];
      continue;
    }
    const resolution = /^\s+resol(?:ution|ved):?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (current && currentOrigin?.aliasSpecifier && resolution?.[1]) {
      const target = npmAliasTarget(currentOrigin.aliasSpecifier);
      const selected = resolution[1];
      let resolvedName: string | undefined;
      let resolvedVersion: string | undefined;
      const berry = /^(@?[^@\s]+(?:\/[^@\s]+)?)@npm:([^@\s]+)$/.exec(selected);
      if (berry) { resolvedName = berry[1]; resolvedVersion = berry[2]; }
      else {
        try {
          const url = new URL(selected);
          if (url.hostname === "registry.npmjs.org" && url.protocol === "https:") {
            const path = decodeURIComponent(url.pathname);
            const match = /^\/(@[^/]+\/[^/]+|[^/]+)\/-\/([^/]+)-([^/]+)\.tgz$/.exec(path);
            if (match && match[2] === match[1]!.split("/").at(-1)) {
              resolvedName = match[1]; resolvedVersion = match[3];
            }
          }
        } catch { /* A non-registry locator cannot establish published identity. */ }
      }
      if (target && resolvedName === target.name && resolvedVersion === current.version && aliasVersionMatches(current.version, target.range)) {
        out.delete(`${current.name}@${current.version}`);
        current.name = resolvedName;
        out.set(`${current.name}@${current.version}`, current);
        currentOrigin.explicitName = true;
      }
      continue;
    }
    const version = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (name && version?.[1]) {
      current = { name, version: version[1] };
      out.set(`${name}@${version[1]}`, current);
      currentOrigin = { component: current, explicitName: !aliasSpecifier, ...(aliasSpecifier ? { aliasSpecifier } : {}) };
      licenseOrigins.push(currentOrigin);
      name = undefined;
    }
  }
  if (name) unmatched++;
  return { components: [...out.values()], installations: [], licenseOrigins, unresolvedLockAliases: [], unmatched, ranges: yarnRanges(text) };
}

const PARSERS: { file: string; parse: (text: string) => ParsedLock }[] = [
  { file: "package-lock.json", parse: parsePackageLock },
  { file: "pnpm-lock.yaml", parse: parsePnpmLock },
  { file: "yarn.lock", parse: parseYarnLock },
];

function unreadRangeSource(source: string, format: DependencyRangeFormat, detail: string): DependencyRangeScope {
  return { ...rangeScope(source, format, "unknown"), status: "unreadable", examined: 1, unread: 1, detail };
}

function unselectedRangeSources(dir: string, selected?: string): DependencyRangeScope[] {
  const scopes: DependencyRangeScope[] = [];
  for (const { file, parse } of [...PARSERS, { file: "npm-shrinkwrap.json", parse: parsePackageLock }]) {
    if (file === selected || !existsSync(join(dir, file))) continue;
    const format: DependencyRangeFormat = file === "npm-shrinkwrap.json" ? "npm-shrinkwrap" : file === "package-lock.json" ? "package-lock" : file === "pnpm-lock.yaml" ? "pnpm" : "yarn";
    try {
      const ranges = parse(readFileSync(join(dir, file), "utf8")).ranges;
      scopes.push({ ...ranges, source: file, format, status: "present-but-unread", edges: [],
        examined: ranges.examined, unread: ranges.unread + ranges.edges.length, unsupported: 1,
        detail: `${file} version ${ranges.sourceVersion} is present but not selected as the dependency source${selected ? ` (${selected} has precedence)` : " (this filename is not supported)"}; ${ranges.edges.length + ranges.unread} observed declaration value(s) remain unread by these checks. ${ranges.excluded.peer} peer range(s) are intentionally excluded compatibility constraints.` });
    } catch {
      scopes.push(unreadRangeSource(file, format, `${file} is present but unreadable and contributes no declaration edges.`));
    }
  }
  return scopes;
}

// The manifest fallback. Direct dependencies only and the declared RANGE rather than a resolved
// version — a real but plainly-labelled degradation, never presented as the resolved tree.
function manifestComponents(dir: string): SbomComponent[] {
  const path = join(dir, "package.json");
  if (!existsSync(path)) return [];
  const pkg = JSON.parse(readFileSync(path, "utf8")) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  return [
    ...Object.entries(pkg.dependencies ?? {}).map(([name, version]) => ({ name, version })),
    ...Object.entries(pkg.devDependencies ?? {}).map(([name, version]) => ({ name, version, dev: true })),
  ];
}

export function collectDependencies(dir: string): DependencySource {
  for (const { file, parse } of PARSERS) {
    const path = join(dir, file);
    if (!existsSync(path)) continue;
    let components: SbomComponent[] = [];
    let installations: DependencyInstallation[] = [];
    let licenseOrigins: LicenseOrigin[] = [];
    let unresolvedLockAliases: UnresolvedLockAlias[] = [];
    let unmatched = 0;
    let parseError: string | undefined;
    let ranges = unreadRangeSource(file, file === "package-lock.json" ? "package-lock" : file === "pnpm-lock.yaml" ? "pnpm" : "yarn",
      `${file} is present but could not be parsed; its declaration ranges are not assessed.`);
    try {
      ({ components, installations, licenseOrigins, unresolvedLockAliases, unmatched, ranges } = parse(readFileSync(path, "utf8")));
    } catch (err) {
      parseError = (err as Error).message;
    }
    const rangeScopes = [ranges, ...unselectedRangeSources(dir, file)];
    if (components.length > 0 || installations.length > 0) {
      // #1079: a parser that resolved SOME entries and skipped others is exactly the
      // partial-presented-as-whole case. Say how many were missed rather than calling it complete
      // because the array was non-empty.
      if (unmatched > 0) {
        return {
          components,
          installations,
          licenseOrigins,
          unresolvedLockAliases,
          source: file,
          completeness: "incomplete",
          rangeScopes,
          note:
            `${file} was parsed, but ${unmatched} of ${components.length + unmatched} entries could not be resolved to a name and version and are MISSING from this BOM. ` +
            "Treat the component list as partial: an absent component here means unlisted, not absent from the project.",
        };
      }
      return { components, installations, licenseOrigins, unresolvedLockAliases, source: file, completeness: "complete", note: `Resolved dependency tree parsed from ${file}.`, rangeScopes };
    }
    // A lockfile that is present but yields nothing is the dangerous case: it looks like a clean
    // parse. Degrade to the manifest and say the lockfile was not understood.
    const fallback = manifestComponents(dir);
    return {
      components: fallback,
      installations: [],
      licenseOrigins: fallback.map((component) => ({ component, explicitName: !component.version.startsWith("npm:") })),
      unresolvedLockAliases,
      source: "package.json",
      completeness: "incomplete",
      rangeScopes,
      note:
        `${file} is present but Harvey could not extract components from it${parseError ? ` (${parseError})` : ""}. ` +
        "This BOM lists the manifest's DIRECT dependencies at their declared version RANGES only — the transitive tree is NOT included and the versions are not resolved. Do not treat it as a complete inventory.",
    };
  }

  const fallback = manifestComponents(dir);
  const rangeScopes = unselectedRangeSources(dir);
  const unsupportedLockfiles = rangeScopes.length > 0
    ? `Lockfile source(s) ${rangeScopes.map((scope) => scope.source).join(", ")} are present, but no supported resolved-tree parser selected them.`
    : undefined;
  if (fallback.length === 0) {
    return { components: [], installations: [], licenseOrigins: [], unresolvedLockAliases: [], source: "(none)", completeness: "unknown", note: unsupportedLockfiles
      ? `${unsupportedLockfiles} No manifest dependency inventory was available. This is an empty BOM, not a dependency-free project.`
      : "No lockfile and no package.json were found, so no dependency inventory could be built. This is an empty BOM, not a dependency-free project.", rangeScopes };
  }
  return {
    components: fallback,
    installations: [],
    licenseOrigins: fallback.map((component) => ({ component, explicitName: !component.version.startsWith("npm:") })),
    unresolvedLockAliases: [],
    source: "package.json",
    completeness: "incomplete",
    note: `${unsupportedLockfiles ?? "No lockfile was found."} This BOM lists the manifest's DIRECT dependencies at their declared version RANGES only — the transitive tree is NOT included and the versions are not resolved.`,
    rangeScopes,
  };
}

export interface LicenseCandidate {
  name: string;
  version?: string;
  // A manifest's npm alias key is not a published-package identity until a matching
  // installation proves the target and selected version. Keep the declaration intact
  // so the license consumer can disclose this gap without querying the alias key.
  unresolvedAlias?: { declared: string; targetName?: string; range?: string; ownerPath?: string };
  // The license the lockfile records, when its format has the field. package-lock.json does;
  // pnpm-lock.yaml and yarn.lock do not, so for those every candidate needs a registry lookup.
  license?: string;
  // Declared in a manifest (any of dependencies/devDependencies/optionalDependencies/
  // peerDependencies) rather than reached only through the resolved tree. Ordering, not
  // filtering: declared packages are processed first in each bounded metadata run.
  direct: boolean;
  // #1351 — carried from SbomComponent so checkDependencyInstallScripts can read the whole
  // resolved tree (npm only; see SbomComponent's comment on the same field).
  hasInstallScript?: boolean;
  /** Metadata read from a package owned by this target. It outranks registry metadata. */
  localMetadata?: {
    manifest: string;
    private: boolean;
    license?: string;
    hasInstallScript: boolean;
  };
}

/** Stable receipt identity for one metadata candidate, including proved local provenance. */
export function licenseCandidateIdentity(candidate: LicenseCandidate): string {
  if (candidate.localMetadata) return `${candidate.name}@local:${candidate.localMetadata.manifest}`;
  if (candidate.unresolvedAlias) return `${candidate.name}@unresolved:${JSON.stringify([candidate.unresolvedAlias.ownerPath ?? null, candidate.unresolvedAlias.declared])}`;
  return `${candidate.name}@${candidate.version ?? "unresolved"}`;
}

export interface LicenseScope {
  candidates: LicenseCandidate[];
  source: string;
  completeness: SbomCompleteness;
  note: string;
  direct: number;
  transitive: number;
  rangeScopes: DependencyRangeScope[];
  /** #1232 — how the DECLARED half of the scope was resolved, so a monorepo can say so. */
  declaredFrom: { manifests: number; source: string; unresolvedGlobs: string[]; unreadable: string[] };
}

// #1213: the candidate set for checkLicenseCompliance, from the same parse the SBOM uses — so the
// BOM a client receives and the license findings can never disagree. It is the RESOLVED TREE, not
// the manifest: before #1213 the check read `{...dependencies, ...devDependencies}`, so a copyleft
// package reached only transitively (measured on ATC 2026-07-27: `sharp` is declared by no manifest
// in the workspace, yet `@img/sharp-*` appears 82 times in pnpm-lock.yaml, three of them
// LGPL-3.0-or-later) was never submitted to the check at all.
//
// Keyed by name@version, so a tree holding two versions of one package under different licenses
// yields both — the name-keyed map this replaced silently kept whichever entry parsed last.
// A manifest-declared ordinary name the tree never resolved is still a candidate (no lockfile at
// all, or an optionalDependency the lockfile skipped); it carries no version and no license for
// registry lookup. An unresolved npm alias instead retains its declaration for a coverage row.
//
// #1232: the DECLARED half now comes from every workspace member's manifest, not the root's alone.
// That is not a coverage change — the root lockfile already resolves each member's packages, so
// they were candidates either way — but it fixes the two things that follow from the label: the
// registry population is processed declared-first, so a monorepo's own dependencies are recorded
// before the transitive tail, and a copyleft row no longer tells a client a package they
// directly chose was "reached only through the resolved dependency tree".
export function licenseScope(dir: string): LicenseScope {
  const deps = collectDependencies(dir);
  const workspace = collectWorkspaceManifests(dir);
  const installations = new Map(deps.installations.map((installation) => [installation.path, installation]));
  const componentsByName = new Map<string, SbomComponent[]>();
  for (const component of deps.components) {
    const entries = componentsByName.get(component.name) ?? [];
    entries.push(component);
    componentsByName.set(component.name, entries);
  }
  const npmTree = deps.source === "package-lock.json";
  type LocalPackage = { name: string; dir: string; metadata: NonNullable<LicenseCandidate["localMetadata"]> };
  const localPackagesByName = new Map<string, LocalPackage[]>();
  const localPackagesByDir = new Map<string, LocalPackage>();
  for (const manifest of workspace.manifests) {
    if (!manifest.name) continue;
    try {
      const raw = JSON.parse(readFileSync(join(dir, manifest.label), "utf8")) as { private?: unknown; license?: unknown; scripts?: unknown };
      const scripts = isRecord(raw.scripts) ? raw.scripts : undefined;
      const local: LocalPackage = { name: manifest.name, dir: posix.dirname(manifest.label), metadata: {
        manifest: manifest.label,
        private: raw.private === true,
        ...(typeof raw.license === "string" ? { license: raw.license } : {}),
        hasInstallScript: scripts !== undefined && ["preinstall", "install", "postinstall"].some((name) => typeof scripts[name] === "string"),
      } };
      localPackagesByDir.set(local.dir, local);
      localPackagesByName.set(local.name, [...(localPackagesByName.get(local.name) ?? []), local]);
    } catch {
      // collectWorkspaceManifests already records unreadable manifests in the scope receipt.
    }
  }
  const unresolved = new Map<string, LicenseCandidate>();
  const directResolved = new Set<string>();
  const ordinaryDeclaredNames = new Set<string>();
  const localWorkspaceNames = new Set<string>();
  const uncertainAliasPaths = new Set<string>();
  const ordinaryProvenPaths = new Set<string>();
  const aliasCandidate = (name: string, declared: string, direct: boolean, ownerPath?: string): LicenseCandidate => {
    const target = npmAliasTarget(declared);
    return { name, direct, unresolvedAlias: { declared, ...(target ? { targetName: target.name, range: target.range } : {}), ...(ownerPath ? { ownerPath } : {}) } };
  };
  const localDeclaration = (manifest: string, name: string, specifier: string, installation?: DependencyInstallation): LocalPackage | undefined => {
    if (specifier.startsWith("workspace:")) {
      const matches = localPackagesByName.get(name) ?? [];
      return matches.length === 1 ? matches[0] : undefined;
    }
    const localPrefix = /^(?:file|link|portal):(.*)$/.exec(specifier);
    if (localPrefix) {
      const target = localPrefix[1]!;
      if (target.length === 0 || posix.isAbsolute(target)) return undefined;
      const targetDir = posix.normalize(posix.join(posix.dirname(manifest), target));
      if (targetDir.startsWith("../")) return undefined;
      const local = localPackagesByDir.get(targetDir);
      return local?.name === name ? local : undefined;
    }
    if (installation?.localPath) {
      const local = localPackagesByDir.get(installation.localPath);
      return local?.name === name ? local : undefined;
    }
    return undefined;
  };
  for (const manifest of workspace.manifests) {
    for (const section of [...RANGE_SECTIONS, "peerDependencies"] as const) {
      for (const [name, specifier] of Object.entries(manifest[section] ?? {})) {
        // npm's optionalDependencies override the same key in dependencies.
        if (section === "dependencies" && Object.hasOwn(manifest.optionalDependencies ?? {}, name)) continue;
        if (typeof specifier === "string" && specifier.startsWith("npm:")) {
          const target = npmAliasTarget(specifier);
          const installation = npmTree ? visibleInstallation(installations, manifest.label, name) : undefined;
          const origin = installation && deps.licenseOrigins.find((entry) => entry.path === installation.path);
          if (target && installation?.version && origin?.explicitName && installation.name === target.name && aliasVersionMatches(installation.version, target.range)) {
            directResolved.add(`${installation.name}\u0000${installation.version}`);
          } else {
            // Success in another manifest never erases this declaration's unresolved coverage.
            unresolved.set(`alias\u0000${name}\u0000${specifier}`, aliasCandidate(name, specifier, true));
          }
          if (installation && !origin?.explicitName) uncertainAliasPaths.add(installation.path);
          if (!npmTree && target) {
            const resolved = deps.licenseOrigins.find((entry) => entry.aliasSpecifier === specifier && entry.explicitName &&
              entry.component.name === target.name && aliasVersionMatches(entry.component.version, target.range));
            if (resolved) {
              directResolved.add(`${resolved.component.name}\u0000${resolved.component.version}`);
              unresolved.delete(`alias\u0000${name}\u0000${specifier}`);
            }
          }
        } else {
          // Ordinary declarations retain their existing name-based reach.
          ordinaryDeclaredNames.add(name);
          const matches = componentsByName.get(name) ?? [];
          const selectedInstallation = visibleInstallation(installations, manifest.label, name);
          const installation = npmTree ? selectedInstallation : undefined;
          const local = typeof specifier === "string" ? localDeclaration(manifest.label, name, specifier, selectedInstallation) : undefined;
          if (local) {
            localWorkspaceNames.add(name);
            // A root and one or more workspace consumers can all declare the same owned package.
            // The metadata population is the proved package manifest, not the number of incoming
            // declarations, so bind repeated references to one stable local identity.
            unresolved.set(`local\u0000${local.metadata.manifest}`, { name, direct: true, localMetadata: local.metadata });
            continue;
          }
          if (typeof specifier === "string" && (/^(?:workspace|file|link|portal):/.test(specifier) || selectedInstallation?.localPath)) {
            localWorkspaceNames.add(name);
            unresolved.set(`ordinary\u0000${manifest.label}\u0000${name}`, aliasCandidate(name, specifier, true, manifest.label));
            continue;
          }
          if (matches.length === 0) unresolved.set(`ordinary\u0000${name}`, { name, direct: true });
          for (const component of matches) directResolved.add(`${component.name}\u0000${component.version}`);
          if (npmTree) {
            if (installation?.version && installation.name === name && typeof specifier === "string" && aliasVersionMatches(installation.version, specifier)) ordinaryProvenPaths.add(installation.path);
          }
        }
      }
    }
  }
  if (npmTree) {
    for (const edge of deps.rangeScopes[0]?.edges ?? []) {
      const installation = visibleInstallation(installations, `${edge.ownerPath}/package.json`, edge.name);
      if (!edge.range.startsWith("npm:")) {
        if (installation?.version && installation.name === edge.name && aliasVersionMatches(installation.version, edge.range)) ordinaryProvenPaths.add(installation.path);
        continue;
      }
      const target = npmAliasTarget(edge.range);
      const origin = installation && deps.licenseOrigins.find((entry) => entry.path === installation.path);
      if (target && installation?.version && origin?.explicitName && installation.name === target.name && aliasVersionMatches(installation.version, target.range)) continue;
      unresolved.set(`transitive\u0000${edge.ownerPath}\u0000${edge.name}\u0000${edge.range}`, aliasCandidate(edge.name, edge.range, false, edge.ownerPath));
      if (installation && !origin?.explicitName) uncertainAliasPaths.add(installation.path);
    }
  }
  for (const alias of deps.unresolvedLockAliases) {
    if (alias.path === `node_modules/${alias.name}` && workspace.manifests.some((manifest) =>
      manifest.label === "package.json" && ([...RANGE_SECTIONS, "peerDependencies"] as const).some((section) =>
        manifest[section]?.[alias.name]?.startsWith("npm:")))) continue;
    if (![...unresolved.values()].some((candidate) => candidate.name === alias.name && candidate.unresolvedAlias?.declared === alias.declared)) {
      unresolved.set(`lock\u0000${alias.path}\u0000${alias.declared}`, aliasCandidate(alias.name, alias.declared, false, alias.path));
    }
  }
  const candidates: LicenseCandidate[] = [];
  const accepted = new Map<string, SbomComponent>();
  for (const origin of deps.licenseOrigins) {
    const c = origin.component;
    if (origin.path && localPackagesByDir.has(origin.path)) continue;
    // The manifest-only inventory records declaration specifiers in `version`; an npm:
    // value is not an installed version or a license lookup coordinate.
    if (deps.source === "package.json" && typeof c.version === "string" && c.version.startsWith("npm:")) continue;
    if (deps.source === "package.json" && localWorkspaceNames.has(c.name)) continue;
    if (origin.aliasSpecifier && !origin.explicitName) {
      if (![...unresolved.values()].some((candidate) => candidate.name === c.name && candidate.unresolvedAlias?.declared === origin.aliasSpecifier)) {
        unresolved.set(`yarn\u0000${c.name}\u0000${origin.aliasSpecifier}`, aliasCandidate(c.name, origin.aliasSpecifier, false));
      }
      continue;
    }
    if (origin.path && uncertainAliasPaths.has(origin.path) && !origin.explicitName && !ordinaryProvenPaths.has(origin.path)) continue;
    accepted.set(`${c.name}\u0000${c.version}`, c);
  }
  for (const name of ordinaryDeclaredNames) {
    const key = `ordinary\u0000${name}`;
    if (![...accepted.values()].some((component) => component.name === name) && ![...unresolved.values()].some((candidate) => candidate.name === name)) unresolved.set(key, { name, direct: true });
  }
  for (const c of accepted.values()) {
    candidates.push({
      name: c.name,
      ...(c.version ? { version: c.version } : {}),
      ...(c.license ? { license: c.license } : {}),
      ...(c.hasInstallScript !== undefined ? { hasInstallScript: c.hasInstallScript } : {}),
      direct: directResolved.has(`${c.name}\u0000${c.version}`),
    });
  }
  candidates.push(...unresolved.values());
  return {
    candidates,
    source: deps.source,
    completeness: deps.completeness,
    note: deps.note,
    direct: candidates.filter((c) => c.direct).length,
    transitive: candidates.filter((c) => !c.direct).length,
    rangeScopes: deps.rangeScopes,
    declaredFrom: {
      manifests: workspace.manifests.length,
      source: workspace.source,
      unresolvedGlobs: workspace.unresolvedGlobs,
      unreadable: workspace.unreadable,
    },
  };
}

// purl (package-URL) for an npm component. The scope's leading "@" is percent-encoded; the "/"
// separating namespace from name is not. Every other character valid in an npm name is URL-safe.
function purl(c: SbomComponent): string {
  return `pkg:npm/${c.name.replace(/^@/, "%40")}@${encodeURIComponent(c.version)}`;
}

// The pinned CycloneDX 1.5 enum owns ID admission. Other lockfile labels stay names;
// whitespace alone establishes neither an SPDX ID nor a valid compound expression.
const CYCLONEDX_SPDX_IDS = new Set<string>((JSON.parse(readFileSync(
  new URL("./__fixtures__/schemas/cyclonedx-1.5/spdx.schema.json", import.meta.url), "utf8",
)) as { enum: string[] }).enum);

function supportedLicenseExpression(value: string): boolean {
  // Keep exceptionally large package metadata as a literal name instead of parsing it.
  if (value.length > 4096) return false;
  try { parseSpdxExpression(value); return true; }
  catch { return false; }
}

function licenses(c: SbomComponent): object[] | undefined {
  if (!c.license) return undefined;
  if (CYCLONEDX_SPDX_IDS.has(c.license)) return [{ license: { id: c.license } }];
  if (supportedLicenseExpression(c.license)) return [{ expression: c.license }];
  return [{ license: { name: c.license } }];
}

// npm records Subresource Integrity (`sha512-<base64>`); CycloneDX wants an algorithm name and a
// hex digest. A hash Harvey cannot convert is omitted rather than emitted in the wrong encoding —
// a consumer verifying against a malformed digest gets a mismatch, which is worse than no hash.
const SRI_ALG: Record<string, string> = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
const SRI_BYTES: Record<string, number> = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 };

function hashes(c: SbomComponent): object[] | undefined {
  const [, alg, b64] = /^(sha1|sha256|sha384|sha512)-(.+)$/.exec(c.integrity ?? "") ?? [];
  if (!alg || !b64) return undefined;
  // Buffer's base64 decoder is deliberately forgiving: it silently ignores invalid characters
  // and accepts truncated input. An SBOM digest is a verification claim, so require standard,
  // canonical base64 and the exact byte length for the named algorithm before publishing it.
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b64)) return undefined;
  const digest = Buffer.from(b64, "base64");
  if (digest.length !== SRI_BYTES[alg] || digest.toString("base64") !== b64) return undefined;
  return [{ alg: SRI_ALG[alg], content: digest.toString("hex") }];
}

export function buildSbom(dir: string, opts: { targetName?: string; timestamp?: string } = {}): { bom: object; warning?: string } {
  const deps = collectDependencies(dir);
  // Alias declarations name an install path, not necessarily the package published at that path.
  // licenseScope owns that proof boundary for every supported lockfile format; reuse its accepted
  // coordinates to distinguish the installation path from the published package identity.
  const scope = licenseScope(dir);
  const acceptedCoordinates = new Set(scope.candidates
    .filter((candidate) => candidate.version && !candidate.unresolvedAlias)
    .map((candidate) => `${candidate.name}\u0000${candidate.version}`));
  const components = deps.components.filter((component) => acceptedCoordinates.has(`${component.name}\u0000${component.version}`));
  const aliasGaps = [...new Map(scope.candidates
    .filter((candidate) => candidate.unresolvedAlias)
    .map((candidate) => {
      const alias = candidate.unresolvedAlias!;
      const owner = alias.ownerPath ? ` at ${alias.ownerPath}` : "";
      const reach = candidate.direct ? "direct" : "transitive";
      const value = `${reach} alias ${candidate.name} declares ${alias.declared}${owner}; published identity and selected version are unproved`;
      return [`${candidate.name}\u0000${alias.declared}\u0000${alias.ownerPath ?? ""}`, value] as const;
    })).values()];
  const completeness: SbomCompleteness = aliasGaps.length > 0 && deps.completeness === "complete" ? "incomplete" : deps.completeness;
  const note = aliasGaps.length > 0 ? `${deps.note} Unresolved alias identity: ${aliasGaps.join("; ")}.` : deps.note;
  const ref = (c: SbomComponent): string => `${c.name}@${c.version}`;
  const componentHashes = new Map(components.map((component) => [component, hashes(component)]));

  const bom = {
    $schema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
    bomFormat: "CycloneDX",
    specVersion: SPEC_VERSION,
    version: 1,
    metadata: {
      timestamp: opts.timestamp ?? new Date().toISOString(),
      tools: { components: [{ type: "application", name: "Harvey", publisher: "Harvey" }] },
      component: { type: "application", "bom-ref": "root", name: opts.targetName ?? "target" },
      properties: [
        { name: "harvey:completeness", value: completeness },
        { name: "harvey:source", value: deps.source },
        { name: "harvey:note", value: note },
        ...aliasGaps.map((value) => ({ name: "harvey:unresolved-alias", value })),
        // #1079: licenses and hashes are the two fields a buyer checks, and how many components
        // actually carry them depends on the lockfile format (package-lock records both; pnpm and
        // yarn record only the integrity hash). State the coverage rather than letting a
        { name: "harvey:license-coverage", value: `${components.filter((c) => c.license).length}/${components.length} components carry a license from ${deps.source}` },
        { name: "harvey:hash-coverage", value: `${components.filter((c) => componentHashes.get(c)).length}/${components.length} components carry a valid integrity hash from ${deps.source}` },
      ],
    },
    components: components.map((c) => ({
      type: "library",
      "bom-ref": ref(c),
      name: c.name,
      version: c.version,
      purl: purl(c),
      // CycloneDX scope: dev-only dependencies are not part of the shipped artifact.
      ...(c.dev ? { scope: "optional" as const } : {}),
      ...(licenses(c) ? { licenses: licenses(c) } : {}),
      ...(componentHashes.get(c) ? { hashes: componentHashes.get(c) } : {}),
    })),
    // CycloneDX's own completeness statement. Kept alongside the properties above because a
    // consumer that ignores compositions must still be told, and vice versa.
    compositions: [{ aggregate: completeness, dependencies: ["root"] }],
  };

  return { bom, ...(completeness === "complete" ? {} : { warning: note }) };
}
