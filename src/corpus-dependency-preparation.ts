import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { readEntriesLstatSafe, readEntriesSafe } from "./fs-walk.js";
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
  /** False when install lifecycle code could have rewritten target-owned source/configuration. */
  sourceTreeCacheable?: boolean;
  sourceTreeReason?: string;
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

interface KnipExecutableConfigDiscovery {
  executable: string[];
  unknown: string[];
}

// Knip's provider catalog is the authority on which framework/tool configuration files it may
// load. Keeping another filename list here is unsafe: that is exactly how vite.config.js escaped
// the first quality-cache guard. The trusted child imports Harvey's installed Knip version, asks
// every resolver plugin for its real config globs, adds static per-scope Knip overrides, and uses
// Knip's own glob implementation to resolve them. A future Knip layout or plugin-shape enumeration
// failure is returned to the caller, which records the uncertainty and keeps quality fresh.
const KNIP_CONFIG_DISCOVERY_SCRIPT = String.raw`
import { existsSync, readFileSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const dist = process.env.HARVEY_KNIP_DIST;
const requestText = process.env.HARVEY_KNIP_CONFIG_REQUEST;
if (!dist || !requestText) throw new Error("missing Knip config discovery request");
const request = JSON.parse(requestText);
const requestedRoot = resolve(request.root);
const [{ PluginEntries }, { KNIP_CONFIG_LOCATIONS }, { _dirGlob, _glob }, { parseJSONC }] = await Promise.all([
  import(pathToFileURL(join(dist, "plugins.js")).href),
  import(pathToFileURL(join(dist, "constants.js")).href),
  import(pathToFileURL(join(dist, "util", "glob.js")).href),
  import(pathToFileURL(join(dist, "util", "fs.js")).href),
]);
const executableExtension = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);
const resolverPlugins = new Map(PluginEntries.filter(([, plugin]) => typeof plugin.resolveConfig === "function"));
const roots = new Set([requestedRoot]);
const unknown = [...request.workspaceUnknown];
const staticConfigs = new Map();

// Package-manager workspaces are part of Knip's config-loading surface. Resolve their complete glob
// language with Knip's own implementation, rather than Harvey's intentionally small source-loader
// glob helper; otherwise a valid brace/extglob can hide an executable provider config from the
// quality cacheability decision while Knip itself still loads it.
try {
  for (const workspace of await _dirGlob({ cwd: requestedRoot, patterns: request.workspacePatterns, gitignore: false })) {
    const absolute = resolve(requestedRoot, workspace);
    if (existsSync(join(absolute, "package.json"))) roots.add(absolute);
  }
} catch (error) {
  unknown.push("package-manager workspace globs could not be resolved with Knip's glob implementation: " + (error instanceof Error ? error.message : String(error)));
}

const readStaticConfig = (root) => {
  const configs = [];
  for (const name of ["knip.json", "knip.jsonc", ".knip.json", ".knip.jsonc"]) {
    const path = join(root, name);
    if (!existsSync(path)) continue;
    try {
      const text = readFileSync(path, "utf8");
      configs.push(name.endsWith("jsonc") ? parseJSONC(path, text) : JSON.parse(text));
    } catch (error) {
      unknown.push(relative(requestedRoot, path) + " could not be parsed: " + (error instanceof Error ? error.message : String(error)));
    }
  }
  const manifestPath = join(root, "package.json");
  if (existsSync(manifestPath)) {
    try {
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
      if (manifest && typeof manifest === "object" && manifest.knip !== undefined) configs.push(manifest.knip);
    } catch (error) {
      unknown.push(relative(requestedRoot, manifestPath) + " could not be parsed while enumerating Knip inputs: " + (error instanceof Error ? error.message : String(error)));
    }
  }
  return configs;
};

// Static Knip configuration may declare Knip-only workspaces beyond the package-manager roots.
// Add those scopes before resolving provider defaults so their local configs remain visible.
for (;;) {
  let added = false;
  for (const root of [...roots]) {
    const configs = staticConfigs.get(root) ?? readStaticConfig(root);
    staticConfigs.set(root, configs);
    for (const config of configs) {
      const workspacePatterns = config && typeof config === "object" && config.workspaces && typeof config.workspaces === "object"
        ? Object.keys(config.workspaces)
        : [];
      if (workspacePatterns.length === 0) continue;
      try {
        for (const workspace of await _dirGlob({ cwd: root, patterns: workspacePatterns, gitignore: false })) {
          const absolute = resolve(root, workspace);
          if (!roots.has(absolute)) {
            roots.add(absolute);
            added = true;
          }
        }
      } catch (error) {
        unknown.push(relative(requestedRoot, root) + " has workspace config globs Knip input discovery could not resolve: " + (error instanceof Error ? error.message : String(error)));
      }
    }
  }
  if (!added) break;
}

const customPatterns = (value, patterns, trail = "knip config") => {
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    if (resolverPlugins.has(key) && item !== true && item !== false && item !== null) {
      const configured = typeof item === "string" || Array.isArray(item)
        ? item
        : typeof item === "object" && "config" in item
          ? item.config
          : undefined;
      if (configured !== undefined && configured !== null) {
        const values = Array.isArray(configured) ? configured : [configured];
        if (values.every((entry) => typeof entry === "string")) patterns.push(...values);
        else unknown.push(trail + " has a non-string " + key + ".config pattern");
      }
    }
    customPatterns(item, patterns, trail + "." + key);
  }
};

const executable = new Set();
for (const root of roots) {
  const patterns = [];
  for (const [name, plugin] of resolverPlugins) {
    try {
      const configured = typeof plugin.config === "function" ? plugin.config({ cwd: root }) : plugin.config;
      if (configured === undefined || configured === null) continue;
      if (!Array.isArray(configured) || !configured.every((entry) => typeof entry === "string")) {
        unknown.push(name + " exposes an unrecognized Knip config pattern shape");
        continue;
      }
      patterns.push(...configured);
    } catch (error) {
      unknown.push(name + " config pattern discovery failed: " + (error instanceof Error ? error.message : String(error)));
    }
  }
  for (const config of staticConfigs.get(root) ?? []) customPatterns(config, patterns);
  try {
    for (const path of await _glob({ cwd: root, dir: root, patterns: [...new Set(patterns)], gitignore: false, label: "Knip executable config discovery" })) {
      if (executableExtension.has(extname(path))) executable.add(resolve(path));
    }
  } catch (error) {
    unknown.push(relative(requestedRoot, root) + " provider config globs could not be resolved: " + (error instanceof Error ? error.message : String(error)));
  }
  for (const name of KNIP_CONFIG_LOCATIONS) {
    const path = join(root, name);
    if (existsSync(path) && executableExtension.has(extname(path))) executable.add(resolve(path));
  }
}
process.stdout.write(JSON.stringify({ executable: [...executable].sort(), unknown: [...new Set(unknown)].sort() }));
`;

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

function qualityWorkspaceRequest(root: string): { root: string; workspacePatterns: string[]; workspaceUnknown: string[] } {
  const pnpmWorkspace = join(root, "pnpm-workspace.yaml");
  if (existsSync(pnpmWorkspace)) {
    try {
      const parsed = parseYaml(readFileSync(pnpmWorkspace, "utf8")) as { packages?: unknown } | null;
      if (!parsed || !Array.isArray(parsed.packages) || !parsed.packages.every((pattern) => typeof pattern === "string")) {
        return { root: resolve(root), workspacePatterns: ["."], workspaceUnknown: ["pnpm-workspace.yaml does not contain a statically enumerable string packages array"] };
      }
      return { root: resolve(root), workspacePatterns: parsed.packages, workspaceUnknown: [] };
    } catch (error) {
      return { root: resolve(root), workspacePatterns: ["."], workspaceUnknown: [`pnpm-workspace.yaml could not be parsed while enumerating package-manager workspaces: ${error instanceof Error ? error.message : String(error)}`] };
    }
  }

  const manifestPath = join(root, "package.json");
  if (!existsSync(manifestPath)) return { root: resolve(root), workspacePatterns: ["."], workspaceUnknown: [] };
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { workspaces?: unknown };
    const value = manifest.workspaces;
    if (value === undefined) return { root: resolve(root), workspacePatterns: ["."], workspaceUnknown: [] };
    const patterns = Array.isArray(value)
      ? value
      : value && typeof value === "object" && Array.isArray((value as { packages?: unknown }).packages)
        ? (value as { packages: unknown[] }).packages
        : undefined;
    if (!patterns || !patterns.every((pattern) => typeof pattern === "string")) {
      return { root: resolve(root), workspacePatterns: ["."], workspaceUnknown: ["package.json#workspaces is not a statically enumerable string array"] };
    }
    return { root: resolve(root), workspacePatterns: patterns as string[], workspaceUnknown: [] };
  } catch (error) {
    return { root: resolve(root), workspacePatterns: ["."], workspaceUnknown: [`package.json could not be parsed while enumerating package-manager workspaces: ${error instanceof Error ? error.message : String(error)}`] };
  }
}

function knipDiscoveryFailure(error: unknown): string {
  if (!error || typeof error !== "object") return String(error);
  const failure = error as { code?: string; signal?: string; status?: number; stderr?: Buffer | string };
  const stderr = failure.stderr?.toString().trim();
  if (stderr) {
    const lines = stderr.split("\n").map((line) => line.trim()).filter(Boolean);
    return lines.slice(-3).join(" ").slice(0, 600);
  }
  return `discovery process failed (status ${failure.status ?? "unknown"}, signal ${failure.signal ?? "none"}, code ${failure.code ?? "none"})`;
}

function discoverKnipExecutableConfigs(root: string): KnipExecutableConfigDiscovery {
  try {
    const require = createRequire(import.meta.url);
    const knipDist = dirname(require.resolve("knip"));
    const stdout = execFileSync(process.execPath, ["--input-type=module", "--eval", KNIP_CONFIG_DISCOVERY_SCRIPT], {
      encoding: "utf8",
      timeout: 30_000,
      maxBuffer: 1024 * 1024 * 8,
      env: {
        ...process.env,
        HARVEY_KNIP_DIST: knipDist,
        HARVEY_KNIP_CONFIG_REQUEST: JSON.stringify(qualityWorkspaceRequest(root)),
      },
    });
    const parsed = JSON.parse(stdout) as Partial<KnipExecutableConfigDiscovery>;
    if (!Array.isArray(parsed.executable) || !parsed.executable.every((path) => typeof path === "string")) {
      throw new Error("discovery returned no executable-input list");
    }
    if (!Array.isArray(parsed.unknown) || !parsed.unknown.every((reason) => typeof reason === "string")) {
      throw new Error("discovery returned no unknown-input list");
    }
    return { executable: parsed.executable, unknown: parsed.unknown };
  } catch (error) {
    return {
      executable: [],
      unknown: [`Knip's installed provider/config catalog could not be enumerated (${knipDiscoveryFailure(error)})`],
    };
  }
}

function qualityNonCacheableReason(root: string): string | undefined {
  const lifecycle: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readEntriesSafe(dir).entries) {
      if (entry.isDirectory) {
        if (!SKIP_DIRS.has(entry.name)) walk(entry.path);
        continue;
      }
      const rel = relative(root, entry.path).replaceAll("\\", "/");
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
  const knipInputs = discoverKnipExecutableConfigs(root);
  const executableConfigs = knipInputs.executable.map((path) => relative(root, path).replaceAll("\\", "/"));
  const reasons = [
    ...(lifecycle.length > 0 ? [`install lifecycle scripts can observe time/network state: ${lifecycle.sort().join(", ")}`] : []),
    ...(executableConfigs.length > 0 ? [`executable framework/plugin configuration Knip may load can observe time/network/unkeyed state: ${executableConfigs.sort().join(", ")}`] : []),
    ...(knipInputs.unknown.length > 0 ? [`Knip's complete executable configuration input set could not be proven: ${knipInputs.unknown.join("; ")}`] : []),
  ];
  return reasons.length > 0 ? reasons.join("; ") : undefined;
}

function projectLifecycleReason(root: string): string | undefined {
  const lifecycle: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readEntriesSafe(dir).entries) {
      if (entry.isDirectory) {
        if (!SKIP_DIRS.has(entry.name)) walk(entry.path);
        continue;
      }
      if (entry.name !== "package.json") continue;
      try {
        const pkg = JSON.parse(readFileSync(entry.path, "utf8")) as { scripts?: Record<string, unknown> };
        const hooks = Object.keys(pkg.scripts ?? {}).filter((name) => INSTALL_LIFECYCLE_HOOKS.has(name));
        if (hooks.length > 0) lifecycle.push(`${relative(root, entry.path).replaceAll("\\", "/")} (${hooks.sort().join(", ")})`);
      } catch {
        return;
      }
    }
  };
  walk(root);
  return lifecycle.length > 0 ? `target install lifecycle scripts may rewrite source/configuration: ${lifecycle.sort().join(", ")}` : undefined;
}

function lockfileLifecycleReason(manager: PackageManager, text: string): string | undefined {
  try {
    if (manager === "npm") {
      const lock = JSON.parse(text) as { packages?: Record<string, { hasInstallScript?: boolean; name?: string }> };
      const scripted = Object.entries(lock.packages ?? {})
        .filter(([, pkg]) => pkg.hasInstallScript === true)
        .map(([path, pkg]) => pkg.name ?? path)
        .sort();
      return scripted.length > 0 ? `resolved npm packages declare lifecycle execution in the lockfile: ${scripted.join(", ")}` : undefined;
    }
    if (manager === "pnpm") {
      const lock = parseYaml(text) as { packages?: Record<string, { requiresBuild?: boolean }>; snapshots?: Record<string, { requiresBuild?: boolean }> };
      const scripted = [...Object.entries(lock.packages ?? {}), ...Object.entries(lock.snapshots ?? {})]
        .filter(([, pkg]) => pkg.requiresBuild === true)
        .map(([name]) => name)
        .sort();
      return scripted.length > 0 ? `resolved pnpm packages declare lifecycle execution in the lockfile: ${[...new Set(scripted)].join(", ")}` : undefined;
    }
  } catch {
    return "resolved dependency lifecycle metadata could not be read from the lockfile";
  }
  return undefined;
}

function lockfileHasInstalledPackages(manager: PackageManager, text: string): boolean {
  try {
    if (manager === "npm") {
      const lock = JSON.parse(text) as { packages?: Record<string, { link?: boolean }> };
      return Object.entries(lock.packages ?? {}).some(([path, pkg]) => path.includes("node_modules/") && pkg.link !== true);
    }
    if (manager === "pnpm") {
      const lock = parseYaml(text) as { packages?: Record<string, unknown> };
      return Object.keys(lock.packages ?? {}).length > 0;
    }
    return (/^[^\s#][^\n]*:\n(?:[ \t].*(?:\n|$))*/gm.exec(text) ?? []).length > 0;
  } catch {
    return true;
  }
}

// Inspect package metadata only; this never imports installed code or target/provider config.
// Physical packages are visited through each package manager's node_modules layout. Workspace
// symlinks are covered by qualityNonCacheableReason's project-tree walk, while pnpm's backing
// .pnpm packages are inspected here.
function installedLifecycleReason(root: string, manager: PackageManager, lockText: string): string | undefined {
  const lifecycle: string[] = [];
  const unknown: string[] = [];
  let manifests = 0;

  const inspectPackage = (dir: string): void => {
    const manifest = join(dir, "package.json");
    if (!existsSync(manifest)) {
      unknown.push(`${relative(root, dir).replaceAll("\\", "/")} has no readable package.json`);
      return;
    }
    manifests += 1;
    try {
      const pkg = JSON.parse(readFileSync(manifest, "utf8")) as { name?: string; version?: string; scripts?: Record<string, unknown> };
      const hooks = Object.keys(pkg.scripts ?? {}).filter((name) => INSTALL_LIFECYCLE_HOOKS.has(name));
      const label = `${pkg.name ?? relative(root, dir).replaceAll("\\", "/")}${pkg.version ? `@${pkg.version}` : ""}`;
      if (hooks.length > 0) lifecycle.push(`${label} (${hooks.sort().join(", ")})`);
      if (existsSync(join(dir, "binding.gyp")) && !hooks.includes("install")) lifecycle.push(`${label} (implicit node-gyp install from binding.gyp)`);
    } catch (error) {
      unknown.push(`${relative(root, manifest).replaceAll("\\", "/")} could not be parsed: ${error instanceof Error ? error.message : String(error)}`);
    }
    const nested = join(dir, "node_modules");
    if (existsSync(nested)) scanNodeModules(nested);
  };

  const scanPnpmStore = (dir: string): void => {
    for (const slot of readEntriesLstatSafe(dir)) {
      if (!slot.isDirectory || slot.isSymbolicLink) continue;
      const nested = join(slot.path, "node_modules");
      if (existsSync(nested)) scanNodeModules(nested);
    }
  };

  const scanNodeModules = (dir: string): void => {
    for (const entry of readEntriesLstatSafe(dir)) {
      if (!entry.isDirectory || entry.isSymbolicLink || entry.name === ".bin") continue;
      if (entry.name === ".pnpm") {
        scanPnpmStore(entry.path);
      } else if (entry.name.startsWith("@")) {
        for (const scoped of readEntriesLstatSafe(entry.path)) {
          if (scoped.isDirectory && !scoped.isSymbolicLink) inspectPackage(scoped.path);
        }
      } else if (!entry.name.startsWith(".")) {
        inspectPackage(entry.path);
      }
    }
  };

  const findInstallRoots = (dir: string): void => {
    for (const entry of readEntriesLstatSafe(dir)) {
      if (!entry.isDirectory || entry.isSymbolicLink) continue;
      if (entry.name === "node_modules") scanNodeModules(entry.path);
      else if (!SKIP_DIRS.has(entry.name)) findInstallRoots(entry.path);
    }
  };

  try {
    findInstallRoots(root);
  } catch (error) {
    unknown.push(`installed dependency lifecycle surface could not be enumerated: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (manifests === 0 && lockfileHasInstalledPackages(manager, lockText)) {
    unknown.push("lockfile resolves installed packages but no physical installed package manifests were enumerable");
  }
  const reasons = [
    ...(lifecycle.length > 0 ? [`installed dependency lifecycle scripts can observe or mutate project state: ${[...new Set(lifecycle)].sort().join(", ")}`] : []),
    ...(unknown.length > 0 ? [`installed dependency lifecycle reachability could not be proven: ${[...new Set(unknown)].sort().join("; ")}`] : []),
  ];
  return reasons.length > 0 ? reasons.join("; ") : undefined;
}

function combineReasons(...reasons: (string | undefined)[]): string | undefined {
  const present = reasons.filter((reason): reason is string => Boolean(reason));
  return present.length > 0 ? present.join("; ") : undefined;
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

function packageManagerEvidenceReason(dir: string, detected: PackageManager, actualVersion: string): string | undefined {
  const locks = [
    ...(existsSync(join(dir, "pnpm-lock.yaml")) ? ["pnpm"] : []),
    ...(existsSync(join(dir, "yarn.lock")) ? ["yarn"] : []),
    ...(existsSync(join(dir, "package-lock.json")) || existsSync(join(dir, "npm-shrinkwrap.json")) ? ["npm"] : []),
  ] as PackageManager[];
  const reasons: string[] = [];
  if (new Set(locks).size > 1) reasons.push(`multiple package-manager lockfile families are present (${[...new Set(locks)].sort().join(", ")})`);
  const manifestPath = join(dir, "package.json");
  if (existsSync(manifestPath)) {
    try {
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { packageManager?: unknown };
      if (manifest.packageManager !== undefined) {
        if (typeof manifest.packageManager !== "string" || !/^(npm|pnpm|yarn)@[^\s]+$/.test(manifest.packageManager)) {
          reasons.push("package.json#packageManager is not an exact supported manager declaration");
        } else {
          const [declaredManager, declaredRaw] = manifest.packageManager.split("@") as [PackageManager, string];
          const declaredVersion = declaredRaw.split("+")[0]!;
          if (declaredManager !== detected) reasons.push(`package.json declares ${declaredManager} but lockfile detection selected ${detected}`);
          if (actualVersion !== "unavailable" && declaredVersion !== actualVersion) reasons.push(`package.json declares ${declaredManager}@${declaredVersion} but the executable is ${actualVersion}`);
        }
      }
    } catch (error) {
      reasons.push(`package.json could not be parsed while validating package-manager identity: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return reasons.length > 0 ? reasons.join("; ") : undefined;
}

export function inspectCorpusDependencyInputs(
  dir: string,
  detected: PackageManager,
  actualVersion: string,
): { installConfiguration: string; packageManagerReason?: string } {
  return {
    installConfiguration: digestInstallInputs(dir),
    packageManagerReason: packageManagerEvidenceReason(dir, detected, actualVersion),
  };
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
  const inputInspection = inspectCorpusDependencyInputs(options.targetDir, manager, version);

  const legacyInstall = (reason: string): DependencyPreparationResult => {
    try {
      const args = manager === "pnpm"
        ? ["install"]
        : manager === "yarn"
          ? ["install"]
          : ["install", "--no-audit", "--no-fund", ...installFlags];
      runInstall({ bin: manager, args, cwd: options.targetDir, env: { ...process.env, ...options.environment, CI: "true" } });
      options.onEvent?.(`DEPENDENCY PREP BYPASS ${manager}: ${reason}; legacy install completed and quality-scan remains non-cacheable`);
      return { status: "non-cacheable", complete: true, cacheable: false, packageManager: manager, packageManagerVersion: version, lockfileDigest: lockDigest, reason, sourceTreeCacheable: false, sourceTreeReason: `unkeyed legacy ${manager} install may execute lifecycle code` };
    } catch {
      removeInstalledTrees(options.targetDir);
      const failure = `${reason}; ${manager} install failed`;
      options.onEvent?.(`DEPENDENCY PREP INCOMPLETE ${manager}: ${failure}; M5-knip will preserve its did-not-run/degraded semantics`);
      return { status: "incomplete", complete: false, cacheable: false, packageManager: manager, packageManagerVersion: version, lockfileDigest: lockDigest, reason: failure, sourceTreeCacheable: false, sourceTreeReason: `failed ${manager} install may have executed lifecycle code before rejection` };
    }
  };

  const managerEvidence = inputInspection.packageManagerReason;
  if (managerEvidence) return legacyInstall(managerEvidence);
  if (version === "unavailable") return legacyInstall("exact package-manager version is unavailable");
  if (!lockPath || !lockText) return legacyInstall("target has no package-manager lockfile");
  if (!reproducibleLock(manager, lockText)) return legacyInstall(`${basename(lockPath)} has no reproducible integrity identity for every installed package`);

  const identity: PreparationIdentity = {
    targetRevision: digest(options.targetRevision),
    targetTree: digest(options.targetTree),
    sourceRoot: options.sourceRoot ?? ".",
    lockfile: { path: basename(lockPath), digest: lockDigest! },
    installConfiguration: inputInspection.installConfiguration,
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
  // Keep the relocatable manager store inside the same preparation identity as its receipt.
  // A manager-level "latest" directory is a mutable pointer: it can combine bytes prepared for
  // different target trees even though the receipt itself is content-addressed. The key namespace
  // makes every transported store answer exactly one preparation identity.
  const storeDir = join(cacheDir, "dependency-preparation", "stores", `${process.platform}-${process.arch}`, manager, key);
  const preInstallNonCacheableQuality = combineReasons(
    qualityNonCacheableReason(options.targetDir),
    lockfileLifecycleReason(manager, lockText),
  );
  const preInstallSourceTreeReason = combineReasons(
    projectLifecycleReason(options.targetDir),
    lockfileLifecycleReason(manager, lockText),
  );
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
      const nonCacheableQuality = combineReasons(
        preInstallNonCacheableQuality,
        installedLifecycleReason(options.targetDir, manager, lockText),
      );
      const sourceTreeReason = combineReasons(preInstallSourceTreeReason, installedLifecycleReason(options.targetDir, manager, lockText));
      options.onEvent?.(`DEPENDENCY PREP HIT ${manager} ${key.slice(0, 12)}: receipt, lockfile, manager ${version}, and offline materialization verified`);
      return {
        status: "hit", complete: true, cacheable: !nonCacheableQuality, key, packageManager: manager,
        packageManagerVersion: version, lockfileDigest: lockDigest,
        reason: nonCacheableQuality ? `validated receipt and offline materialization; quality-scan remains non-cacheable because ${nonCacheableQuality}` : "validated receipt and offline materialization",
        sourceTreeCacheable: !sourceTreeReason,
        sourceTreeReason,
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
    const nonCacheableQuality = combineReasons(
      preInstallNonCacheableQuality,
      installedLifecycleReason(options.targetDir, manager, lockText),
    );
    const sourceTreeReason = combineReasons(preInstallSourceTreeReason, installedLifecycleReason(options.targetDir, manager, lockText));
    writeReceipt(receiptPath, key, identity);
    options.onEvent?.(`DEPENDENCY PREP MISS ${manager} ${key.slice(0, 12)}: clean install completed; receipt stored and reread`);
    return {
      status: "miss", complete: true, cacheable: !nonCacheableQuality, key, packageManager: manager,
      packageManagerVersion: version, lockfileDigest: lockDigest,
      reason: nonCacheableQuality ? `clean content-addressed preparation; quality-scan remains non-cacheable because ${nonCacheableQuality}` : "clean content-addressed preparation",
      sourceTreeCacheable: !sourceTreeReason,
      sourceTreeReason,
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
