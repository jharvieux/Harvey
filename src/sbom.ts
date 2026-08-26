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
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
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

// #1079: `unmatched` is the whole point of this shape. Completeness used to be derived from
// `components.length > 0`, so a parser that recovered 1 of 900 entries still reported "complete"
// — the partial-presented-as-whole failure the module header calls THE risk with an SBOM. Every
// parser now counts the lockfile entries it saw and could not resolve, and completeness is
// derived from that count.
interface ParsedLock {
  components: SbomComponent[];
  unmatched: number;
  ranges: DependencyRangeScope;
}

interface DependencySource {
  components: SbomComponent[];
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
    const name = owners.length > 0 && owners.every(validPackageName) ? owners.at(-1) : undefined;
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
  scope.status = "present-but-unread";
  scope.unsupported = 1;
  try {
    const value: unknown = parseYaml(text);
    if (!isRecord(value)) throw new Error("missing YAML mapping");
    scope.sourceVersion = typeof value.lockfileVersion === "string" || typeof value.lockfileVersion === "number" ? String(value.lockfileVersion) : "unknown";
    let specifiers = rangeSlots(value.specifiers);
    const importers = isRecord(value.importers) ? Object.values(value.importers) : [value];
    for (const importer of importers) {
      if (!isRecord(importer)) { scope.unread++; continue; }
      specifiers += importer === value ? 0 : rangeSlots(importer.specifiers);
      for (const section of RANGE_SECTIONS) {
        if (!isRecord(importer[section])) continue;
        for (const dependency of Object.values(importer[section])) {
          if (isRecord(dependency) && Object.hasOwn(dependency, "specifier")) specifiers++;
        }
      }
    }
    let resolvedReferences = 0;
    for (const section of ["packages", "snapshots"]) {
      if (!isRecord(value[section])) continue;
      for (const entry of Object.values(value[section])) {
        if (!isRecord(entry)) { scope.unread++; continue; }
        resolvedReferences += rangeCount(entry);
        scope.excluded.peer += rangeSlots(entry.peerDependencies);
      }
    }
    scope.unread += specifiers;
    scope.examined = scope.unread;
    scope.detail = `pnpm ${scope.sourceVersion}: ${specifiers} importer/root specifier value(s) are present but unread by the lockfile range consumer; root/workspace manifests remain authoritative for direct declarations. ${resolvedReferences} package/snapshot dependency reference(s) were observed, not promoted from resolved identities to declared ranges. ${scope.excluded.peer} peer range(s) are intentionally excluded compatibility constraints. No pnpm transitive range edges are admitted.`;
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
    version?: string;
    dev?: boolean;
    // npm normally records an SPDX string here, but older/generated package-lock files can
    // preserve package.json's deprecated `{ type, url }` license object. Keep the parse boundary
    // honest: JSON is untrusted and must not smuggle an object into LicenseCandidate's string.
    license?: unknown;
    integrity?: string;
    link?: boolean;
    hasInstallScript?: boolean;
    dependencies?: Record<string, unknown>;
  }
  const raw: unknown = JSON.parse(text);
  if (!isRecord(raw)) throw new Error("package-lock.json is not an object");
  const lock = raw as { packages?: Record<string, LockEntry>; dependencies?: Record<string, LockEntry> };
  const out = new Map<string, SbomComponent>();
  let unmatched = 0;
  const licenseId = (raw: unknown): string | undefined => {
    if (typeof raw === "string") return raw.trim() || undefined;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
    const type = (raw as { type?: unknown }).type;
    return typeof type === "string" ? type.trim() || undefined : undefined;
  };
  const add = (name: string, meta: LockEntry): void => {
    const license = licenseId(meta.license);
    out.set(`${name}@${meta.version ?? ""}`, {
      name,
      version: meta.version ?? "",
      ...(meta.dev ? { dev: true } : {}),
      ...(license ? { license } : {}),
      ...(meta.integrity ? { integrity: meta.integrity } : {}),
      ...(meta.hasInstallScript ? { hasInstallScript: true } : {}),
    });
  };

  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    // "" is the root project itself, not a dependency; it is the BOM's subject, not a component.
    // A `link: true` entry is a workspace symlink, not a published artifact — also not a component.
    if (path === "") continue;
    if (!isRecord(meta)) { unmatched++; continue; }
    if (meta.link) continue;
    const name = path.replace(/^(?:.*\/)?node_modules\//, "");
    if (!name || !meta.version) {
      unmatched++;
      continue;
    }
    add(name, meta);
  }

  const walkV1 = (deps: Record<string, LockEntry>): void => {
    for (const [name, meta] of Object.entries(deps)) {
      if (!isRecord(meta)) { unmatched++; continue; }
      if (meta.version) add(name, meta);
      else unmatched++;
      if (meta.dependencies) walkV1(meta.dependencies as Record<string, LockEntry>);
    }
  };
  if (!lock.packages && lock.dependencies) walkV1(lock.dependencies);

  return { components: [...out.values()], unmatched, ranges: packageLockRanges(raw) };
}

// pnpm-lock.yaml, `packages:` section only. Three key shapes across lockfile versions:
//   v5: /braces/2.3.2:      v6: /braces@2.3.2:      v9: 'braces@2.3.2':
// Parsed by line rather than with a YAML dependency (adding one is an operator decision, and the
// section's grammar is this narrow). pnpm carries no license field, but every entry's
// `resolution: {integrity: …}` is the same SRI hash package-lock records (#1079).
export function parsePnpmLock(text: string): ParsedLock {
  const out = new Map<string, SbomComponent>();
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
  return { components: [...out.values()], unmatched, ranges: pnpmRanges(text) };
}

// yarn.lock — both the v1 format (`braces@^2.3.1:` / `  version "2.3.2"`) and Berry's
// (`"braces@npm:^2.3.1":` / `  version: 2.3.2`). v1 records `integrity`, Berry records `checksum`.
export function parseYarnLock(text: string): ParsedLock {
  const out = new Map<string, SbomComponent>();
  let name: string | undefined;
  let current: SbomComponent | undefined;
  let unmatched = 0;
  for (const line of text.split("\n")) {
    const header = /^"?(@?[^@"\s][^@"]*)@/.exec(line);
    if (/^\S/.test(line) && line.trimEnd().endsWith(":")) {
      // A header that never reaches a `version` line yielded no component — count it when the
      // next header arrives, so a truncated or unfamiliar entry cannot pass as a clean parse.
      if (name) unmatched++;
      name = header?.[1];
      current = undefined;
      if (!name) unmatched++;
      continue;
    }
    const integrity = /^\s+(?:integrity|checksum):?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (current && integrity?.[1]) {
      current.integrity = integrity[1];
      continue;
    }
    const version = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (name && version?.[1]) {
      current = { name, version: version[1] };
      out.set(`${name}@${version[1]}`, current);
      name = undefined;
    }
  }
  if (name) unmatched++;
  return { components: [...out.values()], unmatched, ranges: yarnRanges(text) };
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
    let unmatched = 0;
    let parseError: string | undefined;
    let ranges = unreadRangeSource(file, file === "package-lock.json" ? "package-lock" : file === "pnpm-lock.yaml" ? "pnpm" : "yarn",
      `${file} is present but could not be parsed; its declaration ranges are not assessed.`);
    try {
      ({ components, unmatched, ranges } = parse(readFileSync(path, "utf8")));
    } catch (err) {
      parseError = (err as Error).message;
    }
    const rangeScopes = [ranges, ...unselectedRangeSources(dir, file)];
    if (components.length > 0) {
      // #1079: a parser that resolved SOME entries and skipped others is exactly the
      // partial-presented-as-whole case. Say how many were missed rather than calling it complete
      // because the array was non-empty.
      if (unmatched > 0) {
        return {
          components,
          source: file,
          completeness: "incomplete",
          rangeScopes,
          note:
            `${file} was parsed, but ${unmatched} of ${components.length + unmatched} entries could not be resolved to a name and version and are MISSING from this BOM. ` +
            "Treat the component list as partial: an absent component here means unlisted, not absent from the project.",
        };
      }
      return { components, source: file, completeness: "complete", note: `Resolved dependency tree parsed from ${file}.`, rangeScopes };
    }
    // A lockfile that is present but yields nothing is the dangerous case: it looks like a clean
    // parse. Degrade to the manifest and say the lockfile was not understood.
    const fallback = manifestComponents(dir);
    return {
      components: fallback,
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
    return { components: [], source: "(none)", completeness: "unknown", note: unsupportedLockfiles
      ? `${unsupportedLockfiles} No manifest dependency inventory was available. This is an empty BOM, not a dependency-free project.`
      : "No lockfile and no package.json were found, so no dependency inventory could be built. This is an empty BOM, not a dependency-free project.", rangeScopes };
  }
  return {
    components: fallback,
    source: "package.json",
    completeness: "incomplete",
    note: `${unsupportedLockfiles ?? "No lockfile was found."} This BOM lists the manifest's DIRECT dependencies at their declared version RANGES only — the transitive tree is NOT included and the versions are not resolved.`,
    rangeScopes,
  };
}

export interface LicenseCandidate {
  name: string;
  version?: string;
  // The license the lockfile records, when its format has the field. package-lock.json does;
  // pnpm-lock.yaml and yarn.lock do not, so for those every candidate needs a registry lookup.
  license?: string;
  // Declared in a manifest (any of dependencies/devDependencies/optionalDependencies/
  // peerDependencies) rather than reached only through the resolved tree. Ordering, not
  // filtering: the registry-lookup budget is spent on declared packages first.
  direct: boolean;
  // #1351 — carried from SbomComponent so checkDependencyInstallScripts can read the whole
  // resolved tree (npm only; see SbomComponent's comment on the same field).
  hasInstallScript?: boolean;
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
// A manifest-declared name the tree never resolved is still a candidate (no lockfile at all, or an
// optionalDependency the lockfile skipped); it carries no version and no license, so it falls
// through to the registry lookup exactly as it did before.
//
// #1232: the DECLARED half now comes from every workspace member's manifest, not the root's alone.
// That is not a coverage change — the root lockfile already resolves each member's packages, so
// they were candidates either way — but it fixes the two things that follow from the label: the
// registry-lookup budget is spent declared-first, so a monorepo's own 200 dependencies no longer
// lose the cap to the transitive tail, and a copyleft row no longer tells a client a package they
// directly chose was "reached only through the resolved dependency tree".
export function licenseScope(dir: string): LicenseScope {
  const deps = collectDependencies(dir);
  const workspace = collectWorkspaceManifests(dir);
  const declared = new Set(
    workspace.manifests.flatMap((m) => Object.keys({ ...m.dependencies, ...m.devDependencies, ...m.optionalDependencies, ...m.peerDependencies })),
  );
  const candidates: LicenseCandidate[] = [];
  const resolved = new Set<string>();
  for (const c of deps.components) {
    resolved.add(c.name);
    candidates.push({
      name: c.name,
      ...(c.version ? { version: c.version } : {}),
      ...(c.license ? { license: c.license } : {}),
      ...(c.hasInstallScript ? { hasInstallScript: true } : {}),
      direct: declared.has(c.name),
    });
  }
  for (const name of declared) {
    if (!resolved.has(name)) candidates.push({ name, direct: true });
  }
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

// CycloneDX splits a single SPDX id (`licenses[].license.id`) from a compound expression
// (`licenses[].expression`) — "(MIT OR Apache-2.0)" in the id field fails schema validation, which
// is the one thing a procurement pipeline will actually notice.
function licenses(c: SbomComponent): object[] | undefined {
  if (!c.license) return undefined;
  return /[\s()]/.test(c.license) ? [{ expression: c.license }] : [{ license: { id: c.license } }];
}

// npm records Subresource Integrity (`sha512-<base64>`); CycloneDX wants an algorithm name and a
// hex digest. A hash Harvey cannot convert is omitted rather than emitted in the wrong encoding —
// a consumer verifying against a malformed digest gets a mismatch, which is worse than no hash.
const SRI_ALG: Record<string, string> = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };

function hashes(c: SbomComponent): object[] | undefined {
  const [, alg, b64] = /^(sha1|sha256|sha384|sha512)-(.+)$/.exec(c.integrity ?? "") ?? [];
  if (!alg || !b64) return undefined;
  return [{ alg: SRI_ALG[alg], content: Buffer.from(b64, "base64").toString("hex") }];
}

export function buildSbom(dir: string, opts: { targetName?: string; timestamp?: string } = {}): { bom: object; warning?: string } {
  const deps = collectDependencies(dir);
  const ref = (c: SbomComponent): string => `${c.name}@${c.version}`;

  const bom = {
    bomFormat: "CycloneDX",
    specVersion: SPEC_VERSION,
    version: 1,
    metadata: {
      timestamp: opts.timestamp ?? new Date().toISOString(),
      tools: { components: [{ type: "application", name: "Harvey", publisher: "Harvey" }] },
      component: { type: "application", "bom-ref": "root", name: opts.targetName ?? "target" },
      properties: [
        { name: "harvey:completeness", value: deps.completeness },
        { name: "harvey:source", value: deps.source },
        { name: "harvey:note", value: deps.note },
        // #1079: licenses and hashes are the two fields a buyer checks, and how many components
        // actually carry them depends on the lockfile format (package-lock records both; pnpm and
        // yarn record only the integrity hash). State the coverage rather than letting a
        // half-populated field read as the whole picture.
        { name: "harvey:license-coverage", value: `${deps.components.filter((c) => c.license).length}/${deps.components.length} components carry a license from ${deps.source}` },
        { name: "harvey:hash-coverage", value: `${deps.components.filter((c) => c.integrity).length}/${deps.components.length} components carry an integrity hash from ${deps.source}` },
      ],
    },
    components: deps.components.map((c) => ({
      type: "library",
      "bom-ref": ref(c),
      name: c.name,
      version: c.version,
      purl: purl(c),
      // CycloneDX scope: dev-only dependencies are not part of the shipped artifact.
      ...(c.dev ? { scope: "optional" as const } : {}),
      ...(licenses(c) ? { licenses: licenses(c) } : {}),
      ...(hashes(c) ? { hashes: hashes(c) } : {}),
    })),
    // CycloneDX's own completeness statement. Kept alongside the properties above because a
    // consumer that ignores compositions must still be told, and vice versa.
    compositions: [{ aggregate: deps.completeness, dependencies: ["root"] }],
  };

  return { bom, ...(deps.completeness === "complete" ? {} : { warning: deps.note }) };
}
