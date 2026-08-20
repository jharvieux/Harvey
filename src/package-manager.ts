// #1284/#1268: every place Harvey provisions packages into a target's own tree (mutation-scan's
// --install rung, corpus-drift's per-target provisioning) hardcoded `npm install`. MEASURED against
// three real pnpm-workspace clones (src/scan/external-corpus.ts's recorded M8 not-run reasons for
// inbox-zero, rallly, carbon): `npm install` at a pnpm-workspace root resolves ONLY the root
// packages, leaving every workspace member without node_modules at all — or, when the tree uses a
// pnpm catalog (`catalog:` protocol, carbon), fails outright with EUNSUPPORTEDPROTOCOL. npm was
// never a safe default for a target it did not choose. The target's own lockfile says which package
// manager actually resolves its tree.

import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

// Not exported: nothing outside this file needs to name this type — callers get it as the inferred
// return of detectPackageManager, or infer it structurally when passing "npm"/"pnpm"/"yarn" literals.
export type PackageManager = "npm" | "pnpm" | "yarn";

export interface PackageManagerEvidenceSource {
  kind: "lockfile" | "package-manager-field";
  path: string;
  manager?: PackageManager;
  requestedVersion?: string;
  raw?: string;
}

export type PackageManagerNotAssessedReason =
  | "missing-evidence"
  | "conflicting-evidence"
  | "unsupported-manager"
  | "unsupported-version"
  | "unreadable-manifest";

export type PackageManagerResolution =
  | {
      status: "selected";
      manager: PackageManager;
      /** Exact version requested by package.json#packageManager; absent when no version was declared. */
      requestedVersion?: string;
      lockfile?: string;
      evidence: PackageManagerEvidenceSource[];
    }
  | {
      status: "not-assessed";
      reason: PackageManagerNotAssessedReason;
      detail: string;
      evidence: PackageManagerEvidenceSource[];
    };

const LOCKFILE_MANAGERS = [
  ["npm-shrinkwrap.json", "npm"],
  ["package-lock.json", "npm"],
  ["pnpm-lock.yaml", "pnpm"],
  ["yarn.lock", "yarn"],
] as const satisfies readonly (readonly [string, PackageManager])[];

const EXACT_PACKAGE_MANAGER = /^(npm|pnpm|yarn)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/;

/**
 * Resolve a target's package manager from retained files only. This stricter planning API never
 * inherits detectPackageManager's historical npm fallback and never runs a version probe.
 */
export function resolvePackageManagerEvidence(dir: string): PackageManagerResolution {
  const evidence: PackageManagerEvidenceSource[] = LOCKFILE_MANAGERS
    .filter(([path]) => existsSync(join(dir, path)))
    .map(([path, manager]) => ({ kind: "lockfile" as const, path, manager }));

  const manifestPath = join(dir, "package.json");
  if (existsSync(manifestPath)) {
    let pkg: { packageManager?: unknown };
    try {
      pkg = JSON.parse(readFileSync(manifestPath, "utf8")) as typeof pkg;
    } catch {
      return { status: "not-assessed", reason: "unreadable-manifest", detail: "package.json could not be read as JSON", evidence };
    }
    if (pkg.packageManager !== undefined) {
      if (typeof pkg.packageManager !== "string") {
        return {
          status: "not-assessed",
          reason: "unsupported-version",
          detail: "package.json#packageManager must be an exact <manager>@<semver> string",
          evidence,
        };
      }
      const raw = pkg.packageManager;
      const managerName = raw.slice(0, raw.indexOf("@") < 0 ? undefined : raw.indexOf("@"));
      if (!(["npm", "pnpm", "yarn"] as string[]).includes(managerName)) {
        evidence.push({ kind: "package-manager-field", path: "package.json", raw });
        return { status: "not-assessed", reason: "unsupported-manager", detail: `unsupported package manager declaration: ${raw}`, evidence };
      }
      const parsed = raw.match(EXACT_PACKAGE_MANAGER);
      if (!parsed) {
        evidence.push({ kind: "package-manager-field", path: "package.json", manager: managerName as PackageManager, raw });
        return {
          status: "not-assessed",
          reason: "unsupported-version",
          detail: `package.json#packageManager is not an exact supported version: ${raw}`,
          evidence,
        };
      }
      evidence.push({
        kind: "package-manager-field",
        path: "package.json",
        manager: parsed[1] as PackageManager,
        requestedVersion: parsed[2],
        raw,
      });
    }
  }

  const lockfiles = evidence.filter((source) => source.kind === "lockfile");
  if (lockfiles.length > 1) {
    return {
      status: "not-assessed",
      reason: "conflicting-evidence",
      detail: `multiple package-manager lockfiles are present: ${lockfiles.map((source) => source.path).join(", ")}`,
      evidence,
    };
  }
  const field = evidence.find((source) => source.kind === "package-manager-field");
  const lock = lockfiles[0];
  if (field?.manager && lock?.manager && field.manager !== lock.manager) {
    return {
      status: "not-assessed",
      reason: "conflicting-evidence",
      detail: `package.json#packageManager selects ${field.manager} but ${lock.path} selects ${lock.manager}`,
      evidence,
    };
  }
  const manager = field?.manager ?? lock?.manager;
  if (!manager) {
    return {
      status: "not-assessed",
      reason: "missing-evidence",
      detail: "no supported packageManager declaration or package-manager lockfile was found",
      evidence,
    };
  }
  return {
    status: "selected",
    manager,
    ...(field?.requestedVersion ? { requestedVersion: field.requestedVersion } : {}),
    ...(lock ? { lockfile: basename(lock.path) } : {}),
    evidence,
  };
}

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

/** Tokenize the package-manager wrapper, never the target's shell script body. */
export function runPackageScriptCommand(pm: PackageManager, scriptName: string): { bin: PackageManager; args: string[] } {
  return { bin: pm, args: ["run", scriptName] };
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

// Flags a caller recorded against npm — `--legacy-peer-deps` and friends, which exist because npm
// REFUSES an install on a peer-range conflict. MEASURED (CI run 30362638379, 2026-07-28): pnpm 11
// and yarn do not ignore an unknown option, they exit 1 on it ("Unknown option: 'legacy-peer-deps'"),
// so detecting the right package manager and then handing it another one's command line provisions
// nothing at all — worse than the npm-everywhere default it replaced. Dropping them is the correct
// resolution rather than a translation: neither pnpm nor yarn has npm's peer-conflict error class
// to suppress in the first place.
export function npmOnlyFlags(pm: PackageManager, flags: readonly string[]): string[] {
  return pm === "npm" ? [...flags] : [];
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
