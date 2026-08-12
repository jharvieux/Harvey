import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { readEntriesSafe } from "./fs-walk.js";
import { detectPackageManager, type PackageManager } from "./package-manager.js";

const DEPENDENCY_PREPARATION_SCHEMA = 2;

const PNPM_PORTABLE_STORE_FLAGS = ["--config.enableGlobalVirtualStore=false"] as const;

export type DependencyPreparationStatus = "hit" | "miss" | "non-cacheable" | "incomplete";

export interface DependencyPreparationResult {
  status: DependencyPreparationStatus;
  complete: boolean;
  cacheable: boolean;
  key?: string;
  packageManager: PackageManager;
  packageManagerVersion: string;
  lockfileDigest?: string;
  reason: string;
}

interface PreparationIdentity {
  targetRevision: string;
  targetTree: string;
  sourceRoot: string;
  lockfile: { path: string; digest: string };
  installConfiguration: string;
  packageManager: PackageManager;
  packageManagerVersion: string;
  node: string;
  abi: string;
  platform: string;
  architecture: string;
  installFlags: string[];
  environment: Record<string, string>;
}

interface PreparationReceipt {
  schema: 2;
  key: string;
  identity: PreparationIdentity;
  payloadDigest: string;
}

interface InstallInvocation {
  bin: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
}

interface DependencyPreparationOptions {
  targetDir: string;
  sourceRoot?: string;
  cacheDir: string;
  targetRevision: string;
  targetTree: string;
  installFlags?: readonly string[];
  onEvent?: (message: string) => void;
  runInstall?: (invocation: InstallInvocation) => void;
  packageManagerVersion?: string;
  environment?: NodeJS.ProcessEnv;
}

const INSTALL_INPUT_NAMES = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "yarn.lock",
  ".npmrc",
  ".yarnrc",
  ".yarnrc.yml",
  ".pnpmfile.cjs",
  "pnpmfile.cjs",
]);

const SKIP_DIRS = new Set([".git", "node_modules", ".next", "dist", "build", "coverage", ".yarn-cache"]);
const INSTALL_LIFECYCLE_HOOKS = new Set(["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"]);
const EXECUTABLE_KNIP_CONFIGS = new Set(["knip.ts", "knip.js", "knip.config.ts", "knip.config.js"]);

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function digestValue(value: unknown): string {
  return digest(stable(value));
}

function preparationEnvironment(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  // The install subprocess receives only this bounded environment. That makes the receipt cover
  // every environment value the package manager can observe without binding it to GitHub run ids,
  // checkout paths, or unrelated secrets. PATH/HOME/TMPDIR are retained because the package-manager
  // shims and native package selection need them; platform/ABI are separate identity components.
  return {
    CI: "true",
    HOME: source.HOME ?? "",
    PATH: source.PATH ?? "",
    TMPDIR: source.TMPDIR ?? tmpdir(),
  };
}

function preparationEnvironmentIdentity(environment: NodeJS.ProcessEnv): Record<string, string> {
  return {
    CI: environment.CI ?? "",
    HOME: environment.HOME ?? "",
    PATH: environment.PATH ?? "",
    TMPDIR: environment.TMPDIR ?? "",
  };
}

function qualityNonCacheableReason(root: string): string | undefined {
  const lifecycle: string[] = [];
  const executableConfigs: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readEntriesSafe(dir).entries) {
      if (entry.isDirectory) {
        if (!SKIP_DIRS.has(entry.name)) walk(entry.path);
        continue;
      }
      const rel = relative(root, entry.path).replaceAll("\\", "/");
      if (EXECUTABLE_KNIP_CONFIGS.has(entry.name)) executableConfigs.push(rel);
      if (entry.name !== "package.json") continue;
      try {
        const pkg = JSON.parse(readFileSync(entry.path, "utf8")) as { scripts?: Record<string, unknown> };
        const hooks = Object.keys(pkg.scripts ?? {}).filter((name) => INSTALL_LIFECYCLE_HOOKS.has(name));
        if (hooks.length > 0) lifecycle.push(`${rel} (${hooks.sort().join(", ")})`);
      } catch {
        // The package manager owns malformed-manifest failure. Installation then stays
        // non-cacheable, so this preflight need not invent a second parse verdict.
      }
    }
  };
  walk(root);
  const reasons = [
    ...(lifecycle.length > 0 ? [`install lifecycle scripts can observe time/network state: ${lifecycle.sort().join(", ")}`] : []),
    ...(executableConfigs.length > 0 ? [`executable Knip config can observe time/network state: ${executableConfigs.sort().join(", ")}`] : []),
  ];
  return reasons.length > 0 ? reasons.join("; ") : undefined;
}

function installInputs(root: string): string[] {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readEntriesSafe(dir).entries) {
      if (entry.isDirectory) {
        if (!SKIP_DIRS.has(entry.name)) walk(entry.path);
        continue;
      }
      const rel = relative(root, entry.path).replaceAll("\\", "/");
      if (INSTALL_INPUT_NAMES.has(entry.name) || rel.startsWith(".yarn/patches/") || rel.startsWith(".yarn/plugins/") || rel.startsWith(".yarn/releases/") || rel.startsWith("patches/")) files.push(entry.path);
    }
  };
  walk(root);
  return files.sort();
}

function digestInstallInputs(root: string): string {
  const hash = createHash("sha256");
  for (const path of installInputs(root)) {
    hash.update(relative(root, path).replaceAll("\\", "/"));
    hash.update("\0");
    hash.update(readFileSync(path));
    hash.update("\0");
  }
  return hash.digest("hex");
}

function lockfilePath(dir: string, manager: PackageManager): string | undefined {
  if (manager === "pnpm") return existsSync(join(dir, "pnpm-lock.yaml")) ? join(dir, "pnpm-lock.yaml") : undefined;
  if (manager === "yarn") return existsSync(join(dir, "yarn.lock")) ? join(dir, "yarn.lock") : undefined;
  if (existsSync(join(dir, "npm-shrinkwrap.json"))) return join(dir, "npm-shrinkwrap.json");
  return existsSync(join(dir, "package-lock.json")) ? join(dir, "package-lock.json") : undefined;
}

function npmLockIsReproducible(text: string): boolean {
  try {
    const lock = JSON.parse(text) as { lockfileVersion?: number; packages?: Record<string, { link?: boolean; integrity?: string; resolved?: string }> };
    if (!lock.lockfileVersion || !lock.packages) return false;
    return Object.entries(lock.packages).every(([path, value]) => {
      if (path === "" || value.link || !path.includes("node_modules/")) return true;
      if (typeof value.integrity === "string" && value.integrity.length > 0) return true;
      const resolved = value.resolved ?? "";
      return resolved.startsWith("file:") || /#[0-9a-f]{7,}$/i.test(resolved);
    });
  } catch {
    return false;
  }
}

function pnpmLockIsReproducible(text: string): boolean {
  try {
    const lock = parseYaml(text) as { lockfileVersion?: string | number; packages?: Record<string, { resolution?: Record<string, unknown> }> };
    if (lock.lockfileVersion === undefined || !lock.packages) return false;
    return Object.values(lock.packages).every((value) => {
      const resolution = value.resolution;
      if (!resolution) return false;
      return typeof resolution.integrity === "string"
        || typeof resolution.commit === "string"
        || (typeof resolution.tarball === "string" && (resolution.tarball.startsWith("file:") || /#[0-9a-f]{7,}$/i.test(resolution.tarball)));
    });
  } catch {
    return false;
  }
}

function yarnLockIsReproducible(text: string): boolean {
  if (!/^# yarn lockfile v1/m.test(text)) return false;
  const blocks = text.match(/^[^\s#][^\n]*:\n(?:[ \t].*(?:\n|$))*/gm) ?? [];
  return blocks.every((block) => /\n\s+integrity\s+\S+/.test(block) || /\n\s+resolved\s+"?(?:file:|[^"\n]*#[0-9a-f]{7,})/i.test(block));
}

function reproducibleLock(manager: PackageManager, text: string): boolean {
  if (manager === "npm") return npmLockIsReproducible(text);
  if (manager === "pnpm") return pnpmLockIsReproducible(text);
  return yarnLockIsReproducible(text);
}

function managerVersion(manager: PackageManager, cwd: string, environment: NodeJS.ProcessEnv): string {
  try {
    return execFileSync(manager, ["--version"], { cwd, encoding: "utf8", timeout: 10_000, env: environment }).trim();
  } catch {
    return "unavailable";
  }
}

function managerArgs(manager: PackageManager, storeDir: string, flags: readonly string[], offline: boolean): string[] {
  if (manager === "pnpm") return ["install", "--frozen-lockfile", "--store-dir", storeDir, offline ? "--offline" : "--prefer-offline", ...flags];
  if (manager === "yarn") return ["install", "--frozen-lockfile", "--non-interactive", "--cache-folder", storeDir, ...(offline ? ["--offline"] : [])];
  return ["ci", "--no-audit", "--no-fund", "--cache", storeDir, ...(offline ? ["--offline"] : []), ...flags];
}

/**
 * pnpm's content store is relocatable, but pnpm 10/11 also writes a versioned `projects` symlink
 * back to each checkout. A target can additionally opt into the global virtual store, whose
 * versioned `links`
 * tree is an installed dependency graph rather than content-addressed package bytes. Neither is
 * needed for a subsequent `--offline` materialization. Remove both after every attempt so the
 * Actions transport contains only the portable content/index store and never an archived install.
 */
function sanitizePnpmStore(storeDir: string): number {
  let removed = 0;
  if (!existsSync(storeDir)) return removed;
  for (const entry of readEntriesSafe(storeDir).entries) {
    if (!entry.isDirectory || !/^v\d+$/.test(entry.name)) continue;
    for (const name of ["projects", "links"] as const) {
      const path = join(entry.path, name);
      if (!existsSync(path)) continue;
      rmSync(path, { recursive: true, force: true });
      removed += 1;
    }
  }
  return removed;
}

function removeInstalledTrees(root: string): void {
  const walk = (dir: string): void => {
    for (const entry of readEntriesSafe(dir).entries) {
      if (!entry.isDirectory || entry.name === ".git") continue;
      if (entry.name === "node_modules") rmSync(entry.path, { recursive: true, force: true });
      else walk(entry.path);
    }
  };
  walk(root);
}

function parseReceipt(text: string, expectedKey: string, expectedIdentity: PreparationIdentity): PreparationReceipt {
  const receipt = JSON.parse(text) as Partial<PreparationReceipt>;
  if (receipt.schema !== DEPENDENCY_PREPARATION_SCHEMA || receipt.key !== expectedKey || stable(receipt.identity) !== stable(expectedIdentity)) {
    throw new Error("receipt identity/schema mismatch");
  }
  if (receipt.payloadDigest !== digestValue({ schema: receipt.schema, key: receipt.key, identity: receipt.identity })) {
    throw new Error("receipt checksum mismatch");
  }
  return receipt as PreparationReceipt;
}

function writeReceipt(path: string, key: string, identity: PreparationIdentity): void {
  const receipt: PreparationReceipt = {
    schema: DEPENDENCY_PREPARATION_SCHEMA,
    key,
    identity,
    payloadDigest: digestValue({ schema: DEPENDENCY_PREPARATION_SCHEMA, key, identity }),
  };
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  writeFileSync(temp, `${JSON.stringify(receipt, null, 2)}\n`);
  renameSync(temp, path);
  parseReceipt(readFileSync(path, "utf8"), key, identity);
}

export function prepareCorpusDependencies(options: DependencyPreparationOptions): DependencyPreparationResult {
  const cacheDir = resolve(options.cacheDir);
  const environment = preparationEnvironment(options.environment);
  const manager = detectPackageManager(options.targetDir);
  const version = options.packageManagerVersion ?? managerVersion(manager, options.targetDir, environment);
  const lockPath = lockfilePath(options.targetDir, manager);
  const lockText = lockPath ? readFileSync(lockPath, "utf8") : undefined;
  const lockDigest = lockText ? digest(lockText) : undefined;
  const runInstall = options.runInstall ?? ((invocation: InstallInvocation) => {
    execFileSync(invocation.bin, invocation.args, { cwd: invocation.cwd, env: invocation.env, stdio: ["ignore", "ignore", "inherit"] });
  });
  const installFlags = manager === "npm"
    ? [...(options.installFlags ?? [])]
    : manager === "pnpm"
      ? [...PNPM_PORTABLE_STORE_FLAGS]
      : [];

  const legacyInstall = (reason: string): DependencyPreparationResult => {
    try {
      const args = manager === "pnpm"
        ? ["install"]
        : manager === "yarn"
          ? ["install"]
          : ["install", "--no-audit", "--no-fund", ...installFlags];
      runInstall({ bin: manager, args, cwd: options.targetDir, env: { ...process.env, ...options.environment, CI: "true" } });
      options.onEvent?.(`DEPENDENCY PREP BYPASS ${manager}: ${reason}; legacy install completed and quality-scan remains non-cacheable`);
      return { status: "non-cacheable", complete: true, cacheable: false, packageManager: manager, packageManagerVersion: version, lockfileDigest: lockDigest, reason };
    } catch {
      removeInstalledTrees(options.targetDir);
      const failure = `${reason}; ${manager} install failed`;
      options.onEvent?.(`DEPENDENCY PREP INCOMPLETE ${manager}: ${failure}; M5-knip will preserve its did-not-run/degraded semantics`);
      return { status: "incomplete", complete: false, cacheable: false, packageManager: manager, packageManagerVersion: version, lockfileDigest: lockDigest, reason: failure };
    }
  };

  if (version === "unavailable") return legacyInstall("exact package-manager version is unavailable");
  if (!lockPath || !lockText) return legacyInstall("target has no package-manager lockfile");
  if (!reproducibleLock(manager, lockText)) return legacyInstall(`${basename(lockPath)} has no reproducible integrity identity for every installed package`);

  const identity: PreparationIdentity = {
    targetRevision: digest(options.targetRevision),
    targetTree: digest(options.targetTree),
    sourceRoot: options.sourceRoot ?? ".",
    lockfile: { path: basename(lockPath), digest: lockDigest! },
    installConfiguration: digestInstallInputs(options.targetDir),
    packageManager: manager,
    packageManagerVersion: version,
    node: process.version,
    abi: `${process.versions.modules ?? "unknown"}/${process.versions.napi ?? "unknown"}`,
    platform: process.platform,
    architecture: process.arch,
    installFlags,
    environment: preparationEnvironmentIdentity(environment),
  };
  const key = digestValue({ schema: DEPENDENCY_PREPARATION_SCHEMA, identity });
  const receiptPath = join(cacheDir, "dependency-preparation", "receipts", `${key}.json`);
  const storeDir = join(cacheDir, "dependency-preparation", "stores", `${process.platform}-${process.arch}`, manager);
  const nonCacheableQuality = qualityNonCacheableReason(options.targetDir);
  let hit: PreparationReceipt | undefined;
  if (existsSync(receiptPath)) {
    try {
      hit = parseReceipt(readFileSync(receiptPath, "utf8"), key, identity);
    } catch (error) {
      options.onEvent?.(`DEPENDENCY PREP REJECT ${manager} ${key.slice(0, 12)}: ${error instanceof Error ? error.message : String(error)}; performing clean install`);
      rmSync(receiptPath, { force: true });
    }
  }

  mkdirSync(storeDir, { recursive: true });
  if (hit) {
    try {
      runInstall({ bin: manager, args: managerArgs(manager, storeDir, installFlags, true), cwd: options.targetDir, env: environment });
      if (manager === "pnpm") {
        const removed = sanitizePnpmStore(storeDir);
        if (removed > 0) options.onEvent?.(`DEPENDENCY PREP SANITIZE pnpm ${key.slice(0, 12)}: removed ${removed} path-bound project/global-link tree(s) after offline materialization`);
      }
      options.onEvent?.(`DEPENDENCY PREP HIT ${manager} ${key.slice(0, 12)}: receipt, lockfile, manager ${version}, and offline materialization verified`);
      return {
        status: "hit", complete: true, cacheable: !nonCacheableQuality, key, packageManager: manager,
        packageManagerVersion: version, lockfileDigest: lockDigest,
        reason: nonCacheableQuality ? `validated receipt and offline materialization; quality-scan remains non-cacheable because ${nonCacheableQuality}` : "validated receipt and offline materialization",
      };
    } catch {
      options.onEvent?.(`DEPENDENCY PREP REJECT ${manager} ${key.slice(0, 12)}: offline materialization failed from restored store; performing clean install`);
      rmSync(receiptPath, { force: true });
      removeInstalledTrees(options.targetDir);
    }
  }

  try {
    runInstall({ bin: manager, args: managerArgs(manager, storeDir, installFlags, false), cwd: options.targetDir, env: environment });
    if (manager === "pnpm") {
      const removed = sanitizePnpmStore(storeDir);
      if (removed > 0) options.onEvent?.(`DEPENDENCY PREP SANITIZE pnpm ${key.slice(0, 12)}: removed ${removed} path-bound project/global-link tree(s) after clean materialization`);
    }
    writeReceipt(receiptPath, key, identity);
    options.onEvent?.(`DEPENDENCY PREP MISS ${manager} ${key.slice(0, 12)}: clean install completed; receipt stored and reread`);
    return {
      status: "miss", complete: true, cacheable: !nonCacheableQuality, key, packageManager: manager,
      packageManagerVersion: version, lockfileDigest: lockDigest,
      reason: nonCacheableQuality ? `clean content-addressed preparation; quality-scan remains non-cacheable because ${nonCacheableQuality}` : "clean content-addressed preparation",
    };
  } catch {
    rmSync(receiptPath, { force: true });
    if (manager === "pnpm") sanitizePnpmStore(storeDir);
    // A manager can fail after it has populated part of node_modules (pnpm's ignored-builds error
    // is one real corpus example). Do not let quality-scan mistake that rejected population for a
    // complete preparation; restore the same explicit no-dependencies degraded tier the caller had
    // before content-addressed preparation.
    removeInstalledTrees(options.targetDir);
    options.onEvent?.(`DEPENDENCY PREP REJECT ${manager} ${key.slice(0, 12)}: content-addressed clean install failed; no receipt written; restoring the legacy install/degradation path`);
    return legacyInstall("content-addressed clean install failed after rejecting its partial installed tree");
  }
}
