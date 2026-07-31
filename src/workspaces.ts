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

import { existsSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
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

// The declared entry (main/module/exports["."]), extension-stripped, plus the src/index / index /
// src/main fallbacks a source-only view of a built package needs — candidatePaths() appends the
// extensions and /index, so a literal `main: "./dist/index.js"` never matches a source tree that
// only has src/index.ts. Shared by workspacePackages above (import resolution, where the fallback
// always applies — a bare workspace import has to resolve to SOMETHING) and by perf-code.ts's
// own-declared-entry exclusion (#1526/#1542/#1554), which gates its USE of `bases` on whether
// `declared` is non-empty: import resolution and "is this script building the package's own
// entry" are different questions, and only the first wants a guess when nothing was declared.
export function entryBasesFor(pkg: { main?: unknown; module?: unknown; exports?: unknown }, dir: string): { declared: string[]; bases: string[] } {
  const declared = [pkg.main, pkg.module, exportsDot(pkg.exports)].filter((e): e is string => typeof e === "string");
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

export function parseWorkspaceGlobs(repoRoot: string): { globs: string[]; source: string } {
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
    if (globs.length) return { globs, source: "pnpm-workspace.yaml" };
  }
  const pkgPath = join(repoRoot, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { workspaces?: string[] | { packages?: string[] } };
      const ws = Array.isArray(pkg.workspaces) ? pkg.workspaces : pkg.workspaces?.packages;
      if (ws?.length) return { globs: ws, source: "package.json#workspaces" };
    } catch { /* not a workspace root */ }
  }
  return { globs: ["."], source: "no workspace globs declared" }; // single-package repo
}

// Dirs a glob walk never descends into — build output, deps, VCS internals — so a `**` can't
// wander into node_modules and enumerate every dependency as a "workspace".
const GLOB_SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", ".turbo", ".vercel"]);

function childDirs(dir: string): string[] {
  try {
    return readEntriesSafe(dir).entries
      .filter((e) => e.isDirectory && !GLOB_SKIP_DIRS.has(e.name))
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
// Callers filter the candidates to those carrying a package.json, so a generous match is safe.
export function expandGlob(repoRoot: string, glob: string): string[] {
  const segments = glob.split("/").filter((s) => s !== "" && s !== ".");
  if (segments.length === 0) return existsSync(repoRoot) ? [repoRoot] : [];
  const out = new Set<string>();
  const walk = (dir: string, segs: string[]): void => {
    if (segs.length === 0) {
      if (existsSync(dir)) out.add(dir);
      return;
    }
    const [head, ...rest] = segs;
    if (head === "**") {
      walk(dir, rest); // ** matches zero segments here
      for (const child of childDirs(dir)) walk(child, segs); // …or one-plus, keeping ** for depth
    } else if (head === "*") {
      for (const child of childDirs(dir)) walk(child, rest);
    } else {
      walk(join(dir, head!), rest);
    }
  };
  walk(repoRoot, segments);
  return [...out];
}

// pnpm and npm both let a workspace subtract with a leading "!". expandGlob has no notion of one, so
// a `!examples/**` entry would otherwise be walked as a literal directory named "!examples" — a
// no-op that silently keeps the excluded members in scope.
export function collectWorkspaceManifests(repoRoot: string): WorkspaceScope {
  const { globs, source } = parseWorkspaceGlobs(repoRoot);
  const excluded = new Set(globs.filter((g) => g.startsWith("!")).flatMap((g) => expandGlob(repoRoot, g.slice(1))));
  const manifests: WorkspaceManifest[] = [];
  const unresolvedGlobs: string[] = [];
  const unreadable: string[] = [];
  const seen = new Set<string>();

  const read = (dir: string): void => {
    if (seen.has(dir)) return;
    seen.add(dir);
    const path = join(dir, "package.json");
    const label = relative(repoRoot, path) || "package.json";
    try {
      manifests.push({ ...(JSON.parse(readFileSync(path, "utf8")) as WorkspaceManifest), label });
    } catch {
      unreadable.push(label);
    }
  };

  if (existsSync(join(repoRoot, "package.json"))) read(repoRoot);
  for (const glob of globs) {
    if (glob.startsWith("!")) continue;
    const matched = expandGlob(repoRoot, glob).filter((d) => !excluded.has(d) && existsSync(join(d, "package.json")));
    if (matched.length === 0) unresolvedGlobs.push(glob);
    for (const dir of matched) read(dir);
  }
  return { manifests, source, unresolvedGlobs, unreadable };
}
