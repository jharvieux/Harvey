// Workspace resolution — which package.json manifests a target actually OWNS.
//
// #1231/#1232: the supply-chain checks read the root manifest alone, so in a monorepo every
// workspace member's declared dependencies were invisible to the range-based checks and were
// labelled transitive-only in the license scope. The members have to come from the DECLARED GLOBS
// (`pnpm-workspace.yaml` `packages:`, or `package.json#workspaces` as an array or `{ packages }`).
// A blind filesystem sweep for "every package.json not under node_modules" is the trap: it pulls in
// examples/, templates/ and standalone fixture roots — targets/calibration/fixtures/* is exactly
// that shape, deliberately pinning vulnerable versions — and reports their dependencies as the
// application's own.
//
// The glob expander here was already in src/pentest/targets.ts, where #548 fixed it to handle `**`;
// it is moved rather than reimplemented so M2 target discovery and the supply-chain scope can never
// disagree about what a workspace member is.

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, join, posix, relative, resolve, sep, win32 } from "node:path";
import { readEntriesSafe } from "./fs-walk.js";

interface WorkspaceManifest {
  /** Path relative to the target root — "package.json" for the root manifest. */
  label: string;
  /** The package's own name — how sibling members depend on it (#1344). */
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

interface WorkspaceScope {
  /** Root manifest first, then members in glob order. */
  manifests: WorkspaceManifest[];
  /** Where the globs came from, for the disclosure row. */
  source: string;
  /** Declared globs that matched no directory holding a package.json. */
  unresolvedGlobs: string[];
  /** Manifests that exist but could not be parsed — counted, never silently treated as empty. */
  unreadable: string[];
}

/** A workspace member as an IMPORT TARGET: the package name a sibling writes, and its directory. */
interface WorkspacePackage {
  name: string;
  /** Repo-relative directory holding the manifest ("" for the root package). */
  dir: string;
  /** Entry-module bases to try for a bare `import … from "<name>"`, best guess first. */
  entryBases: string[];
  /**
   * Subpath prefixes for `import … from "<name>/<sub>"`, most specific first: the specifier prefix
   * to strip and the repo-relative dir the remainder resolves under. A wildcard `exports` entry is
   * why this is not simply the package dir — `"./*": "./src/*.ts"` (rallly's @rallly/utils) puts
   * `@rallly/utils/encryption` at packages/utils/SRC/encryption.ts, and resolving it against the
   * package dir finds nothing at all.
   */
  subpaths: { prefix: string; baseDir: string }[];
}

/** Stable, repository-relative identity shared by readiness and downstream discovery. */
export type WorkspaceId = `workspace:${string}`;

export interface WorkspaceDiscoveryEvidence {
  kind: "root-manifest" | "workspace-glob";
  /** Repository-relative POSIX path. */
  sourcePath: string;
  /** The declaration surface within sourcePath; deliberately independent of array order. */
  sourceField: "root" | "packages" | "workspaces" | "workspaces.packages";
  glob?: string;
}

export interface WorkspaceScriptEvidence {
  name: string;
  /** Retained only as provenance. Consumers must not parse or execute this shell body. */
  body: string;
  source: { path: string; pointer: string };
}

export interface WorkspaceInventoryPackage {
  id: WorkspaceId;
  /** Repository-relative POSIX directory; "." is the repository root. */
  dir: string;
  /** Repository-relative POSIX manifest path. */
  manifestPath: string;
  name?: string;
  scripts: WorkspaceScriptEvidence[];
  discoveredBy: WorkspaceDiscoveryEvidence[];
}

export type WorkspaceInventoryObservation =
  | {
      kind: "excluded";
      path: string;
      glob: string;
      sourcePath: string;
      reason: "negative-workspace-glob";
    }
  | {
      kind: "unresolved-glob" | "invalid-glob";
      glob: string;
      sourcePath: string;
      reason: string;
    }
  | {
      kind: "unreadable-manifest";
      path: string;
      reason: string;
    };

/**
 * The single evidence-bearing workspace census.
 *
 * `packages` includes a readable root manifest exactly once plus every declared member.
 * `applicationWorkspaceIds` preserves the existing audit-app view: it contains packages reached
 * by positive workspace globs (the root only for a single-package repo or an explicit `.` glob).
 */
export interface WorkspaceInventoryV1 {
  schemaVersion: 1;
  repoRootId: "workspace:root";
  declarationSource: string;
  packages: WorkspaceInventoryPackage[];
  applicationWorkspaceIds: WorkspaceId[];
  observations: WorkspaceInventoryObservation[];
}

// #1353: the import-graph side of the same question collectWorkspaceManifests answers from disk.
// M7/M9 reachability runs over an in-memory SourceInput[] (the loader already reads every
// package.json — see CONFIG_FILE in src/detectors/load-sources.ts), so it has no repo root to walk, and
// the two must not grow separate ideas of what a member is. `workspacePackagesTest` in
// src/workspaces.test.ts pins them to the same answer on a real two-member tree.
//
// Deliberate difference from collectWorkspaceManifests, which gates on the DECLARED globs: that
// discipline exists to stop a fixtures/ or examples/ package's dependencies being counted as the
// application's own. Resolution has no such exposure — a manifest is only ever reached here because
// some file in the tree imports it BY NAME, which is exactly the edge the reachability graph wants
// to follow. Gating on globs would also mean reading pnpm-workspace.yaml, which the source loader
// does not load, so every pnpm monorepo (rallly, documenso — the targets #1353 measured) would
// silently resolve nothing.
export function workspacePackages(manifests: { path: string; text: string }[]): WorkspacePackage[] {
  const out: WorkspacePackage[] = [];
  for (const m of manifests) {
    if (!/(^|\/)package\.json$/.test(m.path)) continue;
    let pkg: { name?: string; main?: string; module?: string; exports?: unknown };
    try {
      pkg = JSON.parse(m.text) as typeof pkg;
    } catch {
      continue;
    }
    if (typeof pkg.name !== "string" || !pkg.name) continue;
    const dir = m.path.includes("/") ? m.path.slice(0, m.path.lastIndexOf("/")) : "";
    const subpaths = [
      ...exportsWildcards(pkg.exports).map((w) => ({ prefix: `${pkg.name}/${w.from}`, baseDir: joinRepoPath(dir, w.to) })),
      // #1501: EXACT (non-wildcard) exports subpaths. #1353 shipped the wildcard form because that
      // is what rallly declares; an exports map made of literal keys is at least as common and was
      // skipped entirely. MEASURED 2026-07-31 on crbnos/carbon @92e19c04, whose `packages/auth`
      // declares eleven `exports` entries — TEN literal subpaths such as
      // `"./auth.server": "./src/services/auth.server.ts"`, plus `"."`, which exportsExact skips
      // because entryBasesFor already handles the package entry:
      // `resolveImport(…, "@carbon/auth/auth.server")` returned UNRESOLVED while
      // packages/auth/src/services/auth.server.ts was present in the loaded tree, so every route
      // action gated by `requirePermissions` imported from there read as ungated — 113 High
      // `route action missing authorization check` rows, of which #1501's triage records 107 false
      // for this cause and 4 true-to-shape (see carbon's M1-boundary note in external-corpus.ts).
      ...exportsExact(pkg.exports).map((e) => ({ prefix: `${pkg.name}/${e.from}`, baseDir: joinRepoPath(dir, e.to) })),
    ]
      // Longest specifier prefix first, so `./server-only/*` beats a catch-all `./*`, and an exact
      // key beats a wildcard that also covers it.
      .sort((a, b) => b.prefix.length - a.prefix.length);
    // A package with no wildcard exports still takes `<name>/<file>` against its own directory —
    // the pre-exports convention, and what a `"files"`-only internal package relies on.
    subpaths.push({ prefix: `${pkg.name}/`, baseDir: dir });
    out.push({ name: pkg.name, dir, entryBases: entryBasesFor(pkg, dir).bases, subpaths });
  }
  return out;
}

// The declared entry (main/module/exports["."], PLUS every literal — non-wildcard — exports
// subpath), extension-stripped, plus the src/index / index / src/main fallbacks a source-only
// view of a built package needs — candidatePaths() appends the extensions and /index, so a
// literal `main: "./dist/index.js"` never matches a source tree that only has src/index.ts.
// Shared by workspacePackages above (import resolution, where the fallback always applies — a
// bare workspace import has to resolve to SOMETHING) and by perf-code.ts's own-declared-entry
// exclusion (#1526/#1542/#1554), which gates its USE of `bases` on whether `declared` is
// non-empty: import resolution and "is this script building the package's own entry" are
// different questions, and only the first wants a guess when nothing was declared.
//
// #1641 — a package that declares ONLY subpath exports (no `"."` key, and often no main/module —
// a `"files"`-only internal workspace member, e.g. `@carbon/dev`'s `{"./vite": "./src/vite.ts"}`)
// used to read as `declared: []` here, because `exportsDot` only ever reads the `"."` key. That
// silently reintroduced #1526's tooling-mask defect for exactly that shape: a `dev`/`build` script
// building one of the package's own subpath targets was not recognised as "the package building
// itself" and its whole import closure was wrongly swept into `devToolingModules`, dropping real
// findings. MEASURED 2026-07-31 over the pinned M5-slop corpus (17 targets, every package.json,
// not just `targets/**`, which had zero): 14 packages across 4 targets (saas-lite 6, carbon 5,
// rallly 2, inbox-zero 1) declare `exports` with no `"."` key — non-zero, so this is restored
// rather than left as a recorded gap. Every literal (non-wildcard) subpath target now joins
// `declared` via `exportsExact`; a WILDCARD-only subpath (`@rallly/utils`'s `"./*": "./src/*.ts"`,
// 1 of the 14) names a directory prefix, not a single file, so it still contributes nothing here —
// there is no one entry for a script to "be building".
export function entryBasesFor(pkg: { main?: unknown; module?: unknown; exports?: unknown }, dir: string): { declared: string[]; bases: string[] } {
  const declared = [pkg.main, pkg.module, exportsDot(pkg.exports), ...exportsExact(pkg.exports).map((e) => e.to)].filter((e): e is string => typeof e === "string" && e.length > 0);
  const bases = [...declared.map((e) => e.replace(/\.[cm]?[jt]sx?$/, "")), "src/index", "index", "src/main"];
  return { declared, bases: [...new Set(bases.map((b) => joinRepoPath(dir, b)))] };
}

// `exports` keys carrying a `*`, reduced to the literal prefix on each side: `"./*": "./src/*.ts"`
// → { from: "", to: "src/" }, `"./server-only/*": "./dist/server-only/*.js"` →
// { from: "server-only/", to: "dist/server-only/" }. Everything after the `*` is dropped, because
// candidatePaths() re-adds the extension set — a `.js` target in an internal TypeScript package
// names a file that only exists after a build, and the source tree has the `.ts`.
function exportsWildcards(exp: unknown): { from: string; to: string }[] {
  if (!exp || typeof exp !== "object") return [];
  const out: { from: string; to: string }[] = [];
  for (const [key, value] of Object.entries(exp as Record<string, unknown>)) {
    if (!key.startsWith("./") || !key.includes("*")) continue;
    const target = typeof value === "string" ? value : exportsDot(value);
    if (typeof target !== "string" || !target.includes("*")) continue;
    out.push({ from: key.slice(2, key.indexOf("*")), to: target.slice(0, target.indexOf("*")) });
  }
  return out;
}

// `exports` keys with NO `*` — `"./auth.server": "./src/services/auth.server.ts"` →
// { from: "auth.server", to: "src/services/auth.server" }. The extension is stripped for the same
// reason exportsWildcards drops everything after the `*`: candidatePaths() re-adds the extension
// set, so a `.js` target in an internal TypeScript package still finds the `.ts` source. `"."` is
// excluded — that is the package entry, handled by entryBasesFor.
function exportsExact(exp: unknown): { from: string; to: string }[] {
  if (!exp || typeof exp !== "object") return [];
  const out: { from: string; to: string }[] = [];
  for (const [key, value] of Object.entries(exp as Record<string, unknown>)) {
    if (!key.startsWith("./") || key.includes("*")) continue;
    const target = typeof value === "string" ? value : exportsDot(value);
    if (typeof target !== "string" || target.includes("*")) continue;
    out.push({ from: key.slice(2), to: target.replace(/^\.\//, "").replace(/\.[cm]?[jt]sx?$/, "") });
  }
  return out;
}

function exportsDot(exp: unknown): string | undefined {
  if (typeof exp === "string") return exp;
  if (!exp || typeof exp !== "object") return undefined;
  const dot = (exp as Record<string, unknown>)["."] ?? exp;
  if (typeof dot === "string") return dot;
  if (!dot || typeof dot !== "object") return undefined;
  const c = dot as Record<string, unknown>;
  for (const key of ["import", "default", "require"]) if (typeof c[key] === "string") return c[key] as string;
  return undefined;
}

function joinRepoPath(dir: string, rest: string): string {
  return `${dir}/${rest}`
    .split("/")
    .filter((p) => p !== "" && p !== ".")
    .join("/");
}

function parseWorkspaceGlobs(repoRoot: string): {
  globs: string[];
  source: string;
  sourceField: WorkspaceDiscoveryEvidence["sourceField"];
} {
  const pnpm = join(repoRoot, "pnpm-workspace.yaml");
  if (existsSync(pnpm)) {
    const globs: string[] = [];
    let inPackages = false;
    for (const raw of readFileSync(pnpm, "utf8").split("\n")) {
      if (/^packages:\s*$/.test(raw)) { inPackages = true; continue; }
      if (inPackages && /^\S/.test(raw)) break; // dedented → left the packages block
      const m = raw.match(/^\s*-\s*["']?([^"'\s]+)["']?\s*$/);
      if (inPackages && m) globs.push(m[1]!);
    }
    if (globs.length) return { globs, source: "pnpm-workspace.yaml", sourceField: "packages" };
  }
  const pkgPath = join(repoRoot, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { workspaces?: string[] | { packages?: string[] } };
      const ws = Array.isArray(pkg.workspaces) ? pkg.workspaces : pkg.workspaces?.packages;
      if (ws?.length) {
        return {
          globs: ws,
          source: "package.json#workspaces",
          sourceField: Array.isArray(pkg.workspaces) ? "workspaces" : "workspaces.packages",
        };
      }
    } catch { /* not a workspace root */ }
  }
  return { globs: ["."], source: "no workspace globs declared", sourceField: "root" }; // single-package repo
}

// Dirs a glob walk never descends into — build output, deps, VCS internals — so a `**` can't
// wander into node_modules and enumerate every dependency as a "workspace".
const GLOB_SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", ".turbo", ".vercel",
  "generated", "vendor", "fixtures", "fixture", "examples",
]);

function physicalPathWithin(root: string, candidate: string): string | undefined {
  try {
    const physical = realpathSync(candidate);
    const rel = relative(root, physical);
    return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel)) ? physical : undefined;
  } catch {
    return undefined;
  }
}

function globSegments(glob: string): string[] | undefined {
  // Workspace declarations are repository-relative on every host. Treat both platform separators
  // as separators, but fail closed on rooted paths or any parent segment rather than normalizing an
  // attacker-controlled escape back into (or beyond) the target.
  const normalized = glob.replaceAll("\\", "/");
  if (posix.isAbsolute(normalized) || win32.isAbsolute(glob)) return undefined;
  const segments = normalized.split("/").filter((segment) => segment !== "" && segment !== ".");
  return segments.includes("..") ? undefined : segments;
}

function childDirs(dir: string, physicalRoot: string): string[] {
  try {
    return readEntriesSafe(dir).entries
      .filter((e) => e.isDirectory && !GLOB_SKIP_DIRS.has(e.name))
      // readEntriesSafe deliberately follows resolvable directory symlinks. A workspace walk has
      // the stronger constraint that their physical targets remain inside this repository.
      .filter((e) => physicalPathWithin(physicalRoot, e.path) !== undefined)
      // Declared glob order is semantic; the filesystem's encounter order within one glob is not.
      .sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)
      .map((e) => join(dir, e.name));
  } catch {
    return [];
  }
}

// Expand a pnpm/npm workspace glob into candidate directories, matching fast-glob's segment
// semantics: a literal segment descends into that name, `*` matches exactly one path segment (any
// dir), and `**` matches zero or more segments (recursive). This is what lets `packages/**` reach a
// nested workspace like packages/features/auth — the single-level `/*`-only expansion dropped every
// `**` glob (#548), silently under-enumerating both M5-knip workspaces and M2 pentest targets.
// Callers filter the candidates to those carrying a package.json. Lexical parent/root escapes and
// physical symlink escapes are rejected here before a candidate directory is enumerated.
function expandGlob(repoRoot: string, glob: string): string[] {
  const logicalRoot = resolve(repoRoot);
  const segments = globSegments(glob);
  if (!segments) return [];
  let physicalRoot: string;
  try {
    physicalRoot = realpathSync(logicalRoot);
  } catch {
    return [];
  }
  if (segments.length === 0) return existsSync(logicalRoot) ? [logicalRoot] : [];
  const out = new Set<string>();
  const walk = (dir: string, segs: string[], ancestors: ReadonlySet<string>): void => {
    const physical = physicalPathWithin(physicalRoot, dir);
    if (!physical) return;
    const state = `${physical}\0${segs.join("/")}`;
    if (ancestors.has(state)) return;
    const nextAncestors = new Set(ancestors).add(state);
    if (segs.length === 0) {
      if (existsSync(dir)) out.add(dir);
      return;
    }
    const [head, ...rest] = segs;
    if (head === "**") {
      walk(dir, rest, nextAncestors); // ** matches zero segments here
      for (const child of childDirs(dir, physicalRoot)) walk(child, segs, nextAncestors); // …or one-plus, keeping ** for depth
    } else if (head === "*") {
      for (const child of childDirs(dir, physicalRoot)) walk(child, rest, nextAncestors);
    } else {
      walk(join(dir, head!), rest, nextAncestors);
    }
  };
  walk(logicalRoot, segments, new Set());
  return [...out];
}

// pnpm and npm both let a workspace subtract with a leading "!". expandGlob has no notion of one, so
// a `!examples/**` entry would otherwise be walked as a literal directory named "!examples" — a
// no-op that silently keeps the excluded members in scope.
interface WorkspaceRecord extends WorkspaceInventoryPackage {
  manifest: WorkspaceManifest;
}

function workspaceSourceDetails(
  source: string,
  sourceField: WorkspaceDiscoveryEvidence["sourceField"],
): Pick<WorkspaceDiscoveryEvidence, "sourcePath" | "sourceField"> {
  return { sourcePath: source === "pnpm-workspace.yaml" ? source : "package.json", sourceField };
}

function canonicalWorkspaceDir(logicalRoot: string, candidate: string): string | undefined {
  let physicalRoot: string;
  try {
    physicalRoot = realpathSync(logicalRoot);
  } catch {
    return undefined;
  }
  const physical = physicalPathWithin(physicalRoot, candidate);
  if (!physical) return undefined;
  const rel = relative(physicalRoot, physical).split(sep).join("/");
  return rel || ".";
}

export function workspaceIdForDir(dir: string): WorkspaceId {
  return `workspace:${dir === "." ? "root" : dir}`;
}

function scriptEvidence(manifestPath: string, scripts: WorkspaceManifest["scripts"]): WorkspaceScriptEvidence[] {
  if (!scripts || typeof scripts !== "object" || Array.isArray(scripts)) return [];
  return Object.entries(scripts)
    .filter((entry): entry is [string, string] => typeof entry[1] === "string")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, body]) => ({
      name,
      body,
      source: { path: manifestPath, pointer: `/scripts/${name.replaceAll("~", "~0").replaceAll("/", "~1")}` },
    }));
}

function discoverWorkspaceRecords(repoRoot: string): {
  inventory: WorkspaceInventoryV1;
  records: WorkspaceRecord[];
  unresolvedGlobs: string[];
  unreadable: string[];
} {
  const logicalRoot = resolve(repoRoot);
  const { globs, source, sourceField } = parseWorkspaceGlobs(logicalRoot);
  const sourceDetails = workspaceSourceDetails(source, sourceField);
  const observations: WorkspaceInventoryObservation[] = [];
  const excluded = new Set<string>();
  for (const declared of globs.filter((glob) => glob.startsWith("!"))) {
    const glob = declared.slice(1);
    if (!globSegments(glob)) {
      observations.push({ kind: "invalid-glob", glob: declared, sourcePath: sourceDetails.sourcePath, reason: "workspace glob is rooted or escapes through a parent segment" });
      continue;
    }
    for (const candidate of expandGlob(logicalRoot, glob)) {
      if (!existsSync(join(candidate, "package.json"))) continue;
      const dir = canonicalWorkspaceDir(logicalRoot, candidate);
      if (!dir) continue;
      excluded.add(dir);
      const path = dir === "." ? "package.json" : `${dir}/package.json`;
      if (!observations.some((row) => row.kind === "excluded" && row.path === path && row.glob === declared)) {
        observations.push({ kind: "excluded", path, glob: declared, sourcePath: sourceDetails.sourcePath, reason: "negative-workspace-glob" });
      }
    }
  }
  const records: WorkspaceRecord[] = [];
  const inventoryPackages: WorkspaceInventoryPackage[] = [];
  const unresolvedGlobs: string[] = [];
  const unreadable: string[] = [];
  const byId = new Map<WorkspaceId, WorkspaceInventoryPackage>();
  const applicationWorkspaceIds = new Set<WorkspaceId>();
  const observedUnreadable = new Set<string>();

  const read = (candidate: string, discoveredBy: WorkspaceDiscoveryEvidence, application: boolean): boolean => {
    const dir = canonicalWorkspaceDir(logicalRoot, candidate);
    if (!dir) return false;
    const id = workspaceIdForDir(dir);
    const manifestPath = dir === "." ? "package.json" : `${dir}/package.json`;
    const existing = byId.get(id);
    if (existing) {
      if (!existing.discoveredBy.some((entry) => JSON.stringify(entry) === JSON.stringify(discoveredBy))) existing.discoveredBy.push(discoveredBy);
      if (application) applicationWorkspaceIds.add(id);
      return true;
    }
    try {
      const manifest = JSON.parse(readFileSync(join(candidate, "package.json"), "utf8")) as WorkspaceManifest;
      const inventoryPackage: WorkspaceInventoryPackage = {
        id,
        dir,
        manifestPath,
        ...(typeof manifest.name === "string" ? { name: manifest.name } : {}),
        scripts: scriptEvidence(manifestPath, manifest.scripts),
        discoveredBy: [discoveredBy],
      };
      const record: WorkspaceRecord = { ...inventoryPackage, manifest: { ...manifest, label: manifestPath } };
      inventoryPackages.push(inventoryPackage);
      records.push(record);
      byId.set(id, inventoryPackage);
      if (application) applicationWorkspaceIds.add(id);
      return true;
    } catch {
      const inventoryPackage: WorkspaceInventoryPackage = {
        id,
        dir,
        manifestPath,
        scripts: [],
        discoveredBy: [discoveredBy],
      };
      inventoryPackages.push(inventoryPackage);
      byId.set(id, inventoryPackage);
      if (application) applicationWorkspaceIds.add(id);
      if (!observedUnreadable.has(manifestPath)) {
        observedUnreadable.add(manifestPath);
        unreadable.push(manifestPath);
        observations.push({ kind: "unreadable-manifest", path: manifestPath, reason: "manifest could not be read as JSON" });
      }
      return true;
    }
  };

  if (existsSync(join(logicalRoot, "package.json"))) {
    read(logicalRoot, { kind: "root-manifest", sourcePath: "package.json", sourceField: "root" }, false);
  } else {
    const rootPackage: WorkspaceInventoryPackage = {
      id: workspaceIdForDir("."),
      dir: ".",
      manifestPath: "package.json",
      scripts: [],
      discoveredBy: [{ kind: "root-manifest", sourcePath: "package.json", sourceField: "root" }],
    };
    inventoryPackages.push(rootPackage);
    byId.set(rootPackage.id, rootPackage);
    observations.push({ kind: "unreadable-manifest", path: "package.json", reason: "root manifest is missing" });
  }
  for (const glob of globs) {
    if (glob.startsWith("!")) continue;
    if (!globSegments(glob)) {
      observations.push({ kind: "invalid-glob", glob, sourcePath: sourceDetails.sourcePath, reason: "workspace glob is rooted or escapes through a parent segment" });
      unresolvedGlobs.push(glob);
      continue;
    }
    let matched = 0;
    for (const candidate of expandGlob(logicalRoot, glob)) {
      if (!existsSync(join(candidate, "package.json"))) continue;
      const dir = canonicalWorkspaceDir(logicalRoot, candidate);
      if (!dir) continue;
      if (excluded.has(dir)) continue;
      matched += 1;
      const discoveredBy: WorkspaceDiscoveryEvidence = source === "no workspace globs declared"
        ? { kind: "root-manifest", sourcePath: "package.json", sourceField: "root" }
        : { kind: "workspace-glob", ...sourceDetails, glob };
      read(candidate, discoveredBy, true);
    }
    if (matched === 0) {
      unresolvedGlobs.push(glob);
      observations.push({ kind: "unresolved-glob", glob, sourcePath: sourceDetails.sourcePath, reason: "glob matched no included directory containing package.json" });
    }
  }
  const packages = inventoryPackages.map((entry) => ({
    id: entry.id,
    dir: entry.dir,
    manifestPath: entry.manifestPath,
    ...(entry.name ? { name: entry.name } : {}),
    scripts: entry.scripts,
    discoveredBy: [...entry.discoveredBy].sort((a, b) => `${a.sourcePath}\0${a.sourceField}\0${a.glob ?? ""}`.localeCompare(`${b.sourcePath}\0${b.sourceField}\0${b.glob ?? ""}`)),
  }));
  return {
    inventory: {
      schemaVersion: 1,
      repoRootId: "workspace:root",
      declarationSource: source,
      packages,
      applicationWorkspaceIds: [...applicationWorkspaceIds].sort(),
      observations: observations.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    },
    records,
    unresolvedGlobs,
    unreadable,
  };
}

export function discoverWorkspaceInventory(repoRoot: string): WorkspaceInventoryV1 {
  return discoverWorkspaceRecords(repoRoot).inventory;
}

export function collectWorkspaceManifests(repoRoot: string): WorkspaceScope {
  const { inventory, records, unresolvedGlobs, unreadable } = discoverWorkspaceRecords(repoRoot);
  return { manifests: records.map((record) => record.manifest), source: inventory.declarationSource, unresolvedGlobs, unreadable };
}
