import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, existsSync, lstatSync, openSync, readFileSync, readlinkSync, readSync, realpathSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { readEntriesSafe, statSafe } from "./fs-walk.js";
import { binaryVersion, digestFiles, digestParts } from "./scan/mechanical-phase-cache.js";
import { discoverTransitiveImplementationFiles } from "./scan/mechanical-phase-identity.js";
import type { CorpusScanner, CorpusScannerCacheMode, CorpusScannerCacheOptions } from "./corpus-scanner-cache.js";

const ENTRY: Record<CorpusScanner, string> = {
  "detect-static": "src/cli/static-detect.ts",
  "quality-scan": "src/cli/quality-scan.ts",
  "mutation-detect-only": "src/cli/mutation-scan.ts",
};

const TOOL: Record<CorpusScanner, readonly string[]> = {
  "detect-static": [],
  "quality-scan": ["jscpd", "knip"],
  "mutation-detect-only": [],
};

const INSTALL_INPUT = /(^|\/)package\.json$|(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|pnpm-workspace\.yaml|\.npmrc)$/;
const PREPARATION_FILES = ["node_modules/.modules.yaml", "node_modules/.package-lock.json", "node_modules/.yarn-integrity", ".pnp.cjs", ".pnp.data.json"];
const INSTALL_ROOTS = ["node_modules", ".yarn"];

// MEASURED 2026-08-12 against the installed pinned corpus trees that broke the first hosted run:
// Carbon's earlier entry-only population exposed 9,376 logical paths but only 3,685 physical files
// (253,647,541 bytes) because 36 workspace manifests reach the same pnpm packages through different
// symlinks. That entry closure was not exhaustive: Knip can execute an unexported config/provider
// descendant. The identity therefore walks the complete installed population now. MEASURED
// 2026-08-12 through this production identity: 40,743 physical files / 589,858,742 bytes.
// These ceilings leave >3x file and byte headroom while remaining finite and fail-loud. Logical
// aliases and directories have their own traversal caps, bounding symlink fan-out separately from
// physical bounds. The thrown diagnostics print the measured population for evidence-led tuning.
export const CORPUS_INSTALL_IDENTITY_BOUNDS = {
  maxFiles: 131_072,
  maxBytes: 2 * 1024 * 1024 * 1024,
  maxLogicalFiles: 524_288,
  maxDirectories: 262_144,
  basis: "bounded above Harvey's 40,743-file / 589,858,742-byte full pnpm install, measured 2026-08-12",
} as const;

interface ObservedInstallFile {
  logicalPath: string;
  physicalPath: string;
}

interface InstallIdentityBounds {
  maxFiles: number;
  maxBytes: number;
  maxLogicalFiles?: number;
  maxDirectories?: number;
}

interface InstallLink {
  logicalPath: string;
  target: string;
}

function dependencyNames(manifest: Record<string, unknown>): { required: string[]; optional: string[] } {
  const names = (field: string): string[] => {
    const value = manifest[field];
    return value && typeof value === "object" ? Object.keys(value as Record<string, unknown>) : [];
  };
  return {
    required: [...new Set([...names("dependencies"), ...names("devDependencies")])].sort(),
    optional: [...new Set(names("optionalDependencies"))].sort(),
  };
}

function findInstalledPackage(targetDir: string, manifestDir: string, name: string): string | undefined {
  const root = resolve(targetDir);
  let current = resolve(manifestDir);
  while (current === root || relative(root, current).split(/[\\/]/).every((part) => part !== "..")) {
    const candidate = join(current, "node_modules", ...name.split("/"));
    if (statSafe(join(candidate, "package.json"))?.isFile()) return candidate;
    if (current === root) break;
    current = dirname(current);
  }
  return undefined;
}

function observeInstallFile(path: string): ObservedInstallFile | undefined {
  if (!statSafe(path)?.isFile()) return undefined;
  return { logicalPath: path, physicalPath: realpathSync(path) };
}

function collectInstalledPopulation(
  targetDir: string,
  roots: readonly string[],
  bounds: InstallIdentityBounds = CORPUS_INSTALL_IDENTITY_BOUNDS,
): { files: ObservedInstallFile[]; links: InstallLink[] } {
  const observed: ObservedInstallFile[] = [];
  const links: InstallLink[] = [];
  const physicalFiles = new Map<string, number>();
  const visitedDirectories = new Set<string>();
  let physicalBytes = 0;
  let logicalFiles = 0;
  let directories = 0;
  const maxLogicalFiles = bounds.maxLogicalFiles ?? bounds.maxFiles * 4;
  const maxDirectories = bounds.maxDirectories ?? bounds.maxFiles * 2;
  const physicalTargetRoot = realpathSync(targetDir);

  const linkTarget = (path: string): string => {
    const raw = readlinkSync(path).replaceAll("\\", "/");
    try {
      const physical = realpathSync(path);
      const rel = relative(physicalTargetRoot, physical).replaceAll("\\", "/");
      if (rel !== "" && rel !== ".." && !rel.startsWith("../")) return `target:${rel}`;
      return `external:${raw}`;
    } catch {
      return `dangling:${raw}`;
    }
  };

  const countDirectory = (): void => {
    directories += 1;
    if (directories > maxDirectories) {
      throw new Error(`corpus scanner install identity walked ${directories} logical directories, exceeding the ${maxDirectories}-directory bound`);
    }
  };

  const recordLink = (logicalPath: string): void => {
    links.push({ logicalPath, target: linkTarget(logicalPath) });
    if (links.length > maxLogicalFiles) {
      throw new Error(`corpus scanner install identity walked ${links.length} logical links, exceeding the ${maxLogicalFiles}-link bound`);
    }
  };

  const walk = (dir: string): void => {
    const listing = readEntriesSafe(dir);
    for (const name of listing.dangling.sort()) recordLink(join(dir, name));
    for (const entry of listing.entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const logicalPath = entry.path;
      const lstat = lstatSync(logicalPath, { throwIfNoEntry: false });
      if (!lstat) continue;
      if (lstat.isSymbolicLink()) recordLink(logicalPath);
      const stat = statSafe(logicalPath);
      if (!stat) continue;
      const physicalKey = `${stat.dev}:${stat.ino}`;
      if (stat.isDirectory()) {
        countDirectory();
        if (visitedDirectories.has(physicalKey)) continue;
        visitedDirectories.add(physicalKey);
        walk(logicalPath);
        continue;
      }
      if (!stat.isFile()) continue;
      logicalFiles += 1;
      if (logicalFiles > maxLogicalFiles) {
        throw new Error(`corpus scanner install identity walked ${logicalFiles} logical files, exceeding the ${maxLogicalFiles}-logical-file bound`);
      }
      if (!physicalFiles.has(physicalKey)) {
        physicalFiles.set(physicalKey, stat.size);
        physicalBytes += stat.size;
        if (physicalFiles.size > bounds.maxFiles) {
          throw new Error(`corpus scanner install identity observed ${physicalFiles.size} physical files, exceeding the ${bounds.maxFiles}-file bound`);
        }
        if (physicalBytes > bounds.maxBytes) {
          throw new Error(`corpus scanner install identity observed ${physicalBytes} physical bytes, exceeding the ${bounds.maxBytes}-byte bound`);
        }
      }
      observed.push({ logicalPath, physicalPath: realpathSync(logicalPath) });
    }
  };

  for (const root of [...new Set(roots.map((path) => resolve(path)))].sort()) {
    const lstat = lstatSync(root, { throwIfNoEntry: false });
    if (lstat?.isSymbolicLink()) recordLink(root);
    const stat = statSafe(root);
    if (!stat?.isDirectory()) continue;
    countDirectory();
    const key = `${stat.dev}:${stat.ino}`;
    if (visitedDirectories.has(key)) continue;
    visitedDirectories.add(key);
    walk(root);
  }
  return { files: observed, links };
}

function installLinkDigest(targetDir: string, links: readonly InstallLink[]): string {
  const parts: string[] = [];
  for (const link of [...links].sort((a, b) => a.logicalPath.localeCompare(b.logicalPath))) {
    const label = relative(targetDir, link.logicalPath).replaceAll("\\", "/");
    if (label === "" || label === ".." || label.startsWith("../")) {
      throw new Error(`corpus scanner install identity link is outside target: ${link.logicalPath}`);
    }
    parts.push(label, link.target);
  }
  return digestParts(parts.length > 0 ? parts : ["no installed symlinks"]);
}

function digestFile(path: string): string {
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  const fd = openSync(path, "r");
  try {
    for (;;) {
      const bytes = readSync(fd, buffer, 0, buffer.length, null);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest("hex");
}

export function observedInstallDigest(
  targetDir: string,
  files: readonly ObservedInstallFile[],
  bounds: InstallIdentityBounds = CORPUS_INSTALL_IDENTITY_BOUNDS,
): { digest: string; files: number; logicalFiles: number; bytes: number } {
  const parts: (string | Buffer)[] = [];
  const byPhysical = new Map<string, { physicalPath: string; logicalPaths: Set<string> }>();
  for (const file of files) {
    const stat = statSafe(file.physicalPath);
    if (!stat?.isFile()) throw new Error(`corpus scanner install identity input disappeared: ${file.logicalPath}`);
    const key = `${stat.dev}:${stat.ino}`;
    const prior = byPhysical.get(key);
    if (prior) prior.logicalPaths.add(file.logicalPath);
    else byPhysical.set(key, { physicalPath: file.physicalPath, logicalPaths: new Set([file.logicalPath]) });
  }
  const unique = [...byPhysical.values()].map((file) => {
    const labels = [...file.logicalPaths].map((logicalPath) => {
      const label = relative(targetDir, logicalPath).replaceAll("\\", "/");
      if (label === "" || label === ".." || label.startsWith("../")) throw new Error(`corpus scanner install identity logical path is outside target: ${logicalPath}`);
      return label;
    }).sort();
    const stat = statSafe(file.physicalPath);
    if (!stat?.isFile()) throw new Error(`corpus scanner install identity input disappeared: ${labels[0] ?? file.physicalPath}`);
    return { ...file, labels, bytes: stat.size };
  }).sort((a, b) => (a.labels[0] ?? "").localeCompare(b.labels[0] ?? ""));
  const bytes = unique.reduce((sum, file) => sum + file.bytes, 0);
  const logicalFiles = unique.reduce((sum, file) => sum + file.labels.length, 0);
  if (unique.length > bounds.maxFiles) {
    throw new Error(`corpus scanner install identity observed ${unique.length} physical files, exceeding the ${bounds.maxFiles}-file bound`);
  }
  if (bytes > bounds.maxBytes) {
    throw new Error(`corpus scanner install identity observed ${bytes} physical bytes, exceeding the ${bounds.maxBytes}-byte bound`);
  }
  for (const file of unique) {
    const digest = digestFile(file.physicalPath);
    for (const label of file.labels) parts.push(label, String(file.bytes), digest);
  }
  return { digest: digestParts(parts), files: unique.length, logicalFiles, bytes };
}

export function dependencyInstallIdentity(targetDir: string): string {
  const allTracked = execFileSync("git", ["-C", targetDir, "ls-files", "-z", "--", "."], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).split("\0").filter((path) => path !== "" && existsSync(join(targetDir, path))).sort();
  const tracked = allTracked.filter((path) => INSTALL_INPUT.test(path));
  const manifests = tracked.filter((path) => path.endsWith("package.json"));
  const inputsDigest = tracked.length > 0 ? digestFiles(tracked.map((path) => join(targetDir, path)), targetDir) : digestParts(["no tracked package/install inputs"]);
  const required: string[] = [];
  const optional: string[] = [];
  const installed: string[] = [];
  const installRoots = new Set<string>();
  const preparationFiles = new Set(PREPARATION_FILES.map((path) => join(targetDir, path)));
  let hasInstallRoot = false;
  for (const manifestPath of manifests) {
    const absoluteManifest = join(targetDir, manifestPath);
    const manifest = JSON.parse(readFileSync(absoluteManifest, "utf8")) as Record<string, unknown>;
    const names = dependencyNames(manifest);
    const manifestDir = dirname(absoluteManifest);
    for (const path of INSTALL_ROOTS) {
      const candidate = join(manifestDir, path);
      if (statSafe(candidate)?.isDirectory()) installRoots.add(candidate);
    }
    hasInstallRoot ||= INSTALL_ROOTS.some((path) => statSafe(join(manifestDir, path))?.isDirectory()) || existsSync(join(manifestDir, ".pnp.cjs"));
    for (const name of names.required) required.push(`${manifestPath}:${name}`);
    for (const name of names.optional) optional.push(`${manifestPath}:${name}`);
    for (const name of [...names.required, ...names.optional]) {
      const packageDir = findInstalledPackage(targetDir, manifestDir, name);
      if (!packageDir) continue;
      installed.push(`${manifestPath}:${name}`);
    }
    for (const path of PREPARATION_FILES) {
      preparationFiles.add(join(manifestDir, path));
    }
  }
  if (manifests.length === 0) {
    for (const path of INSTALL_ROOTS) {
      const candidate = join(targetDir, path);
      if (statSafe(candidate)?.isDirectory()) installRoots.add(candidate);
    }
    hasInstallRoot = installRoots.size > 0 || existsSync(join(targetDir, ".pnp.cjs"));
  }
  const population = collectInstalledPopulation(targetDir, [...installRoots]);
  const observedFiles = population.files;
  for (const path of preparationFiles) {
    const observed = observeInstallFile(path);
    if (observed) observedFiles.push(observed);
  }
  if (manifests.length === 0 && !hasInstallRoot && observedFiles.length === 0) {
    return JSON.stringify({ schema: 3, state: "not-applicable-no-package", reason: "target has no tracked package.json or installed population; dependency installation is not an assessed-clean claim", inputsDigest });
  }
  const installedSet = new Set(installed);
  const missingRequired = [...new Set(required)].filter((name) => !installedSet.has(name)).sort();
  const state = manifests.length === 0 ? "unmanifested-install" : !hasInstallRoot ? "not-installed" : missingRequired.length > 0 ? "partial" : "complete";
  const observed = { ...observedInstallDigest(targetDir, observedFiles), links: population.links.length, layoutDigest: installLinkDigest(targetDir, population.links) };
  return JSON.stringify({
    schema: 3,
    state,
    inputsDigest,
    required: [...new Set(required)].sort(),
    optional: [...new Set(optional)].sort(),
    installed: [...installedSet].sort(),
    missingRequired,
    observed,
    bounds: CORPUS_INSTALL_IDENTITY_BOUNDS,
  });
}

export function buildCorpusScannerCache(options: {
  repoRoot: string;
  cacheDir: string;
  mode: CorpusScannerCacheMode;
  scanner: CorpusScanner;
  targetDir: string;
  targetRevision: string;
  targetTree: string;
  targetConfig: string;
  onEvent?: (message: string) => void;
}): CorpusScannerCacheOptions {
  const entry = join(options.repoRoot, ENTRY[options.scanner]);
  const closure = discoverTransitiveImplementationFiles([entry]);
  const toolchain = digestFiles([join(options.repoRoot, "package.json"), join(options.repoRoot, "pnpm-lock.yaml")], options.repoRoot);
  const versions = Object.fromEntries(TOOL[options.scanner].map((tool) => [tool, binaryVersion(tool)]));
  const externalInputs: Record<string, string> = {
    node: process.version,
    toolchain,
    tools: JSON.stringify(versions),
    targetConfig: options.targetConfig,
  };
  // quality-scan's knip pass resolves the installed graph. detect-static and mutation
  // --detect-only read source/manifests only, so install bytes must not invalidate them.
  if (options.scanner === "quality-scan") externalInputs.dependencyInstall = dependencyInstallIdentity(options.targetDir);
  return {
    dir: options.cacheDir,
    mode: options.mode,
    scanner: options.scanner,
    targetRevision: options.targetRevision,
    targetTree: options.targetTree,
    implementation: digestParts([digestFiles(closure, options.repoRoot), readFileSync(entry)]),
    externalInputs,
    pathRoot: options.targetDir,
    onEvent: options.onEvent,
  };
}
