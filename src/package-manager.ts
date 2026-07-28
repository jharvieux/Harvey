// #1284/#1268: every place Harvey provisions packages into a target's own tree (mutation-scan's
// --install rung, corpus-drift's per-target provisioning) hardcoded `npm install`. MEASURED against
// three real pnpm-workspace clones (src/scan/external-corpus.ts's recorded M8 not-run reasons for
// inbox-zero, rallly, carbon): `npm install` at a pnpm-workspace root resolves ONLY the root
// packages, leaving every workspace member without node_modules at all — or, when the tree uses a
// pnpm catalog (`catalog:` protocol, carbon), fails outright with EUNSUPPORTEDPROTOCOL. npm was
// never a safe default for a target it did not choose. The target's own lockfile says which package
// manager actually resolves its tree.

import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// Not exported: nothing outside this file needs to name this type — callers get it as the inferred
// return of detectPackageManager, or infer it structurally when passing "npm"/"pnpm"/"yarn" literals.
type PackageManager = "npm" | "pnpm" | "yarn";

export function detectPackageManager(dir: string): PackageManager {
  if (existsSync(join(dir, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(join(dir, "yarn.lock"))) return "yarn";
  return "npm";
}

// Installs the target's OWN already-declared dependency tree (no extra packages) — what
// corpus-drift's installTargetDeps needs so knip/M8 can resolve the target's config, and, for a
// pnpm workspace, so its WORKSPACE MEMBERS get node_modules too (a bare `pnpm install` at the root
// installs every workspace member; a bare `npm install` there does not — the #1268 fix).
export function installAllCommand(pm: PackageManager, flags: readonly string[] = []): { bin: string; args: string[] } {
  if (pm === "pnpm") return { bin: "pnpm", args: ["install", ...flags] };
  if (pm === "yarn") return { bin: "yarn", args: ["install", ...flags] };
  return { bin: "npm", args: ["install", "--no-audit", "--no-fund", ...flags] };
}

// Adds specific EXTRA packages (Stryker + its runner plugin) on top of whatever the target already
// declares. npm's `--no-save` leaves package.json/package-lock.json untouched; pnpm's `add` and
// yarn's `add` have no equivalent (MEASURED 2026-07-28: `pnpm add --help` / `yarn add --help` list
// no `--no-save`/`--no-lockfile`-style flag for this), so callers that need the same "provision
// node_modules, leave the manifest as found" guarantee on a pnpm/yarn target must wrap the install
// in withRestoredManifest below.
export function installExtraCommand(pm: PackageManager, packages: readonly string[]): { bin: string; args: string[] } {
  if (pm === "pnpm") return { bin: "pnpm", args: ["add", "-D", ...packages] };
  if (pm === "yarn") return { bin: "yarn", args: ["add", "-D", ...packages] };
  return { bin: "npm", args: ["install", "--no-save", "--no-audit", "--no-fund", "-D", ...packages] };
}

// The lockfile (if any) `installExtraCommand` writes to for a given package manager — used by
// withRestoredManifest to know which second file (besides package.json) to snapshot/restore.
function lockfileFor(pm: PackageManager): string | undefined {
  if (pm === "pnpm") return "pnpm-lock.yaml";
  if (pm === "yarn") return "yarn.lock";
  return undefined;
}

// The pnpm/yarn equivalent of npm's `--no-save`: snapshots package.json + the package manager's own
// lockfile (whichever exist) before running `fn`, then restores both to their EXACT original bytes
// afterward (success or failure) — so an extra-package install leaves node_modules provisioned but
// the target's manifest/lockfile byte-identical to what an operator or client would see, the same
// guarantee npm's own flag gives natively. A file absent before stays absent after (removed, not
// written back as empty), so a target with no lockfile at all is never handed a phantom one.
export function withRestoredManifest<T>(dir: string, pm: PackageManager, fn: () => T): T {
  if (pm === "npm") return fn(); // npm's own --no-save already leaves nothing to restore
  const pkgPath = join(dir, "package.json");
  const lockName = lockfileFor(pm);
  const lockPath = lockName ? join(dir, lockName) : undefined;
  const pkgBefore = existsSync(pkgPath) ? readFileSync(pkgPath) : undefined;
  const lockBefore = lockPath && existsSync(lockPath) ? readFileSync(lockPath) : undefined;
  try {
    return fn();
  } finally {
    if (pkgBefore !== undefined) writeFileSync(pkgPath, pkgBefore);
    if (lockPath) {
      if (lockBefore !== undefined) writeFileSync(lockPath, lockBefore);
      else rmSync(lockPath, { force: true });
    }
  }
}
