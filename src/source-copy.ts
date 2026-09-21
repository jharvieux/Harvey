import { copyFileSync, existsSync, lstatSync, mkdirSync, realpathSync, symlinkSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { readEntriesLstatSafe } from "./fs-walk.js";

export class SourceCopyError extends Error {}

const inside = (root: string, path: string): boolean => {
  const rel = relative(root, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
};
const posix = (path: string): string => path.split(sep).join("/");

/** Copy selected source while keeping resolvable source aliases inside the disposable tree. */
export function copyFilteredSourceTree(
  source: string,
  destination: string,
  include: (relativePath: string) => boolean,
  tracked?: readonly string[],
): void {
  const root = realpathSync(source);
  const dest = realpathSync(destination);
  if (inside(root, dest)) throw new SourceCopyError("Source scratch destination must be outside the target tree");
  const included = (path: string): boolean => {
    const parts = posix(path).split("/");
    return include("") && parts.every((_, index) => include(parts.slice(0, index + 1).join("/")));
  };
  const links: Array<{ path: string; target: string; directory: boolean }> = [];
  const files = new Map<string, string>();
  const selected = tracked ? new Set(tracked) : undefined;
  const canonicalTarget = (src: string, path: string): string | undefined => {
    let real: string;
    try {
      real = realpathSync(src);
    } catch (error) {
      if (["ENOENT", "ENOTDIR", "ELOOP"].includes((error as NodeJS.ErrnoException).code ?? "")) return undefined;
      throw error;
    }
    if (!inside(root, real)) throw new SourceCopyError(`Cannot stage source alias ${path}: its target is outside the selected source tree`);
    return real;
  };
  const copyEntry = (src: string, path: string): void => {
    if (!included(path)) return;
    const stat = lstatSync(src);
    if (stat.isSymbolicLink()) {
      const target = canonicalTarget(src, path);
      if (!target) return; // Unresolvable links follow the existing unread-source disclosure path.
      const targetPath = posix(relative(root, target));
      if (included(targetPath)) links.push({ path, target: targetPath, directory: lstatSync(target).isDirectory() });
    } else if (stat.isDirectory()) {
      mkdirSync(join(dest, path), { recursive: true });
      for (const entry of readEntriesLstatSafe(src)) copyEntry(entry.path, path ? `${path}/${entry.name}` : entry.name);
    } else if (stat.isFile()) {
      mkdirSync(dirname(join(dest, path)), { recursive: true });
      copyFileSync(src, join(dest, path));
      files.set(path, src);
    }
  };
  if (tracked) {
    for (const path of tracked) {
      const src = resolve(root, path);
      if (!inside(root, src)) throw new SourceCopyError(`Tracked source path leaves the selected tree: ${path}`);
      if (existsSync(src)) copyEntry(src, path);
    }
  } else {
    copyEntry(root, "");
  }

  // A link to an ancestor or a cycle through sibling directories would send scanner walks
  // around the staged tree repeatedly. Check the link graph before creating any of its edges.
  const visited = new Set<string>();
  const checkCycle = (link: typeof links[number], ancestors: Set<string>): void => {
    if (ancestors.has(link.path)) throw new SourceCopyError(`Cannot stage cyclic source directory alias ${link.path}`);
    if (visited.has(link.path) || !link.directory) return;
    const next = new Set([...ancestors, link.path]);
    for (const child of links) if (inside(join(root, link.target), join(root, child.path))) checkCycle(child, next);
    visited.add(link.path);
  };
  for (const link of links) checkCycle(link, new Set());

  const materialize = (src: string, path: string, ancestors: Set<string>): void => {
    if (!included(path)) return;
    const real = canonicalTarget(src, path);
    if (!real) return;
    const target = posix(relative(root, real));
    if (!included(target)) return;
    const stat = lstatSync(real);
    if (stat.isDirectory()) {
      if (ancestors.has(real)) throw new SourceCopyError(`Cannot stage cyclic source directory alias ${path}`);
      mkdirSync(join(dest, path), { recursive: true });
      for (const entry of readEntriesLstatSafe(real)) materialize(entry.path, `${path}/${entry.name}`, new Set([...ancestors, real]));
    } else if (stat.isFile() && (!selected || selected.has(target))) {
      mkdirSync(dirname(join(dest, path)), { recursive: true });
      copyFileSync(real, join(dest, path));
    }
  };
  for (const link of links) {
    const target = join(dest, link.target);
    if (!existsSync(target)) continue; // A tracked alias does not pull an untracked target into scope.
    const population = [...files.keys(), ...links.map((item) => item.path)].filter((path) => inside(join(root, link.target), join(root, path)));
    if (link.directory && population.some((path) => !included(posix(join(link.path, relative(link.target, path)))))) {
      // Different exclusions at the alias path need their own filtered directory population.
      materialize(join(root, link.target), link.path, new Set());
      continue;
    }
    mkdirSync(dirname(join(dest, link.path)), { recursive: true });
    symlinkSync(relative(dirname(join(dest, link.path)), target), join(dest, link.path), link.directory ? "dir" : "file");
  }
}
