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

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

interface WorkspaceManifest {
  /** Path relative to the target root — "package.json" for the root manifest. */
  label: string;
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
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && !GLOB_SKIP_DIRS.has(e.name))
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
