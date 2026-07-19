// M8 stub-check disposable worktree (#600/#607). --stub-check mutates a COPY of the target so the
// live checkout is never opened for writing; node_modules is not re-copied but wired back in.
//
// #607: on a workspace monorepo, `node_modules/<pkg>` (or `node_modules/@scope/<pkg>`) is a symlink
// pointing back at the target's OWN `packages/*` source. Symlinking node_modules wholesale would
// resolve those workspace packages to the ORIGINAL (unstubbed) source, so a stub applied to a file
// in `packages/foo` is silently bypassed by any cross-package import. mirrorNodeModules instead
// rebuilds node_modules as a real directory: ordinary entries (third-party packages, the pnpm
// store, `.bin`) symlink straight back to the original install, but a workspace-package symlink is
// re-pointed at the COPY of that source so stubs are honored across package boundaries.

import { existsSync, lstatSync, mkdirSync, readdirSync, realpathSync, symlinkSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";

// Callers receive this as the inferred return of mirrorNodeModules — no name needs exporting.
interface NodeModulesMirror {
  // Workspace-package symlinks re-pointed at the copy (path relative to node_modules).
  repointed: string[];
  // Workspace-package symlinks whose source was NOT in the copy, so they still resolve to the
  // ORIGINAL source — a stub in them can be bypassed. Disclosed to the caller, never silent.
  unresolvedWorkspacePkgs: string[];
}

// A symlink is a workspace package when its real path lives inside the target tree but outside
// node_modules — i.e. it points at first-party source the copy already mirrors.
function classifyLink(real: string, targetDir: string): { workspaceRel: string } | undefined {
  const relFromTarget = relative(targetDir, real);
  const insideTarget = relFromTarget !== "" && !relFromTarget.startsWith("..") && !isAbsolute(relFromTarget);
  const insideNodeModules = relFromTarget.split(sep)[0] === "node_modules";
  return insideTarget && !insideNodeModules ? { workspaceRel: relFromTarget } : undefined;
}

export function mirrorNodeModules(targetDir: string, copyDir: string): NodeModulesMirror {
  const targetNM = join(targetDir, "node_modules");
  const copyNM = join(copyDir, "node_modules");
  // realpathSync (below, on each symlink) canonicalizes through OS-level symlinks (e.g. macOS
  // /var → /private/var), so the base we measure "inside the target?" against must be canonical too.
  const realTargetDir = realpathSync(targetDir);
  const mirror: NodeModulesMirror = { repointed: [], unresolvedWorkspacePkgs: [] };
  mkdirSync(copyNM, { recursive: true });

  const linkEntry = (rel: string) => {
    const src = join(targetNM, rel);
    const dest = join(copyNM, rel);
    let stat;
    try {
      stat = lstatSync(src);
    } catch {
      return;
    }
    if (stat.isSymbolicLink()) {
      let real: string;
      try {
        real = realpathSync(src);
      } catch {
        symlinkSync(src, dest); // broken link — mirror it as-is, resolution stays the original's problem
        return;
      }
      const workspace = classifyLink(real, realTargetDir);
      if (workspace) {
        const copyPath = join(copyDir, workspace.workspaceRel);
        if (existsSync(copyPath)) {
          symlinkSync(copyPath, dest, "dir");
          mirror.repointed.push(rel);
          // The copied workspace package has no node_modules of its own (excluded from the copy);
          // give it the original's so its local (non-hoisted) deps still resolve.
          const realNM = join(real, "node_modules");
          const copyPkgNM = join(copyPath, "node_modules");
          if (existsSync(realNM) && !existsSync(copyPkgNM)) symlinkSync(realNM, copyPkgNM, "dir");
        } else {
          symlinkSync(src, dest, "dir"); // copy missing (excluded dir?) — fall back to original, disclosed below
          mirror.unresolvedWorkspacePkgs.push(rel);
        }
        return;
      }
      symlinkSync(src, dest, "dir"); // ordinary symlink (pnpm store link, etc.) — resolve through the original
      return;
    }
    if (stat.isDirectory() && rel.startsWith("@") && !rel.includes(sep)) {
      // An @scope directory holds the actual packages one level down (some of which are workspace
      // symlinks) — recurse so those are classified individually rather than symlinked as a block.
      mkdirSync(dest, { recursive: true });
      for (const child of readdirSync(src)) linkEntry(join(rel, child));
      return;
    }
    symlinkSync(src, dest, stat.isDirectory() ? "dir" : "file");
  };

  for (const entry of readdirSync(targetNM)) linkEntry(entry);
  return mirror;
}
