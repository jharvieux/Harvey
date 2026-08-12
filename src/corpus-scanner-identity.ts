import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, existsSync, openSync, readFileSync, readSync, realpathSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { statSafe } from "./fs-walk.js";
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

// MEASURED 2026-08-12 against the installed pinned corpus trees that broke the first hosted run:
// Carbon exposed 9,376 logical paths but only 3,685 physical files (253,647,541 bytes) because 36
// workspace manifests reach the same pnpm packages through different symlinks. BoxyHQ exposed 499
// physical files (40,665,455 bytes). The old logical-path union reread Carbon's installed bytes as
// 1,988,844,028 bytes and breached both arbitrary 8,192-file / 32-MiB caps. Canonicalizing physical
// files makes the bound describe installed state instead of workspace alias count. The production
// ceiling is deliberately about 2x the largest measured physical population: enough for a pinned
// corpus target to grow materially, still finite and fail-loud rather than an unbounded node_modules
// walk. The thrown diagnostic prints the observed population so the next adjustment is evidence-led.
export const CORPUS_INSTALL_IDENTITY_BOUNDS = {
  maxFiles: 8_192,
  maxBytes: 512 * 1024 * 1024,
  basis: "2x headroom over pinned Carbon's 3,685 physical files / 253,647,541 bytes, measured 2026-08-12",
} as const;

interface ObservedInstallFile {
  logicalPath: string;
  physicalPath: string;
}

interface InstallIdentityBounds {
  maxFiles: number;
  maxBytes: number;
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

function packageEntryCandidates(packageDir: string, manifest: Record<string, unknown>): string[] {
  const values: string[] = [];
  const collect = (value: unknown): void => {
    if (typeof value === "string") values.push(value);
    else if (Array.isArray(value)) value.forEach(collect);
    else if (value && typeof value === "object") Object.values(value as Record<string, unknown>).forEach(collect);
  };
  for (const field of ["main", "module", "types", "typings", "bin", "exports"]) collect(manifest[field]);
  values.push("index.js");
  return [...new Set(values)]
    .filter((value) => !value.includes("*") && !value.startsWith("node:"))
    .map((value) => join(packageDir, value.replace(/^\.\//, "")))
    .filter((path) => statSafe(path)?.isFile())
    .sort();
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
): { digest: string; files: number; bytes: number } {
  const parts: (string | Buffer)[] = [];
  const byPhysical = new Map<string, ObservedInstallFile>();
  for (const file of files) {
    const prior = byPhysical.get(file.physicalPath);
    if (!prior || file.logicalPath.localeCompare(prior.logicalPath) < 0) byPhysical.set(file.physicalPath, file);
  }
  const unique = [...byPhysical.values()].map((file) => {
    const label = relative(targetDir, file.logicalPath).replaceAll("\\", "/");
    if (label === "" || label === ".." || label.startsWith("../")) throw new Error(`corpus scanner install identity logical path is outside target: ${file.logicalPath}`);
    const stat = statSafe(file.physicalPath);
    if (!stat?.isFile()) throw new Error(`corpus scanner install identity input disappeared: ${file.logicalPath}`);
    return { ...file, label, bytes: stat.size };
  }).sort((a, b) => a.label.localeCompare(b.label));
  const bytes = unique.reduce((sum, file) => sum + file.bytes, 0);
  if (unique.length > bounds.maxFiles) {
    throw new Error(`corpus scanner install identity observed ${unique.length} physical files, exceeding the ${bounds.maxFiles}-file bound`);
  }
  if (bytes > bounds.maxBytes) {
    throw new Error(`corpus scanner install identity observed ${bytes} physical bytes, exceeding the ${bounds.maxBytes}-byte bound`);
  }
  for (const file of unique) parts.push(file.label, String(file.bytes), digestFile(file.physicalPath));
  return { digest: digestParts(parts), files: unique.length, bytes };
}

export function dependencyInstallIdentity(targetDir: string): string {
  const tracked = execFileSync("git", ["-C", targetDir, "ls-files", "-z", "--", "."], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).split("\0").filter((path) => path !== "" && INSTALL_INPUT.test(path) && existsSync(join(targetDir, path))).sort();
  const manifests = tracked.filter((path) => path.endsWith("package.json"));
  const inputsDigest = tracked.length > 0 ? digestFiles(tracked.map((path) => join(targetDir, path)), targetDir) : digestParts(["no tracked package/install inputs"]);
  if (manifests.length === 0) {
    return JSON.stringify({ schema: 2, state: "not-applicable-no-package", reason: "target has no tracked package.json; dependency installation is not an assessed-clean claim", inputsDigest });
  }

  const required: string[] = [];
  const optional: string[] = [];
  const installed: string[] = [];
  const observedFiles: ObservedInstallFile[] = PREPARATION_FILES.map((path) => observeInstallFile(join(targetDir, path))).filter((file): file is ObservedInstallFile => file !== undefined);
  let hasInstallRoot = existsSync(join(targetDir, "node_modules")) || existsSync(join(targetDir, ".pnp.cjs"));
  for (const manifestPath of manifests) {
    const absoluteManifest = join(targetDir, manifestPath);
    const manifest = JSON.parse(readFileSync(absoluteManifest, "utf8")) as Record<string, unknown>;
    const names = dependencyNames(manifest);
    const manifestDir = dirname(absoluteManifest);
    hasInstallRoot ||= existsSync(join(manifestDir, "node_modules"));
    for (const name of names.required) required.push(`${manifestPath}:${name}`);
    for (const name of names.optional) optional.push(`${manifestPath}:${name}`);
    for (const name of [...names.required, ...names.optional]) {
      const packageDir = findInstalledPackage(targetDir, manifestDir, name);
      if (!packageDir) continue;
      installed.push(`${manifestPath}:${name}`);
      const packageManifestPath = join(packageDir, "package.json");
      const observedManifest = observeInstallFile(packageManifestPath);
      if (observedManifest) observedFiles.push(observedManifest);
      const packageManifest = JSON.parse(readFileSync(packageManifestPath, "utf8")) as Record<string, unknown>;
      observedFiles.push(...packageEntryCandidates(packageDir, packageManifest).map(observeInstallFile).filter((file): file is ObservedInstallFile => file !== undefined));
    }
    for (const path of PREPARATION_FILES) {
      const candidate = join(manifestDir, path);
      const observedCandidate = observeInstallFile(candidate);
      if (observedCandidate) observedFiles.push(observedCandidate);
    }
  }
  const installedSet = new Set(installed);
  const missingRequired = [...new Set(required)].filter((name) => !installedSet.has(name)).sort();
  const state = !hasInstallRoot ? "not-installed" : missingRequired.length > 0 ? "partial" : "complete";
  const observed = observedInstallDigest(targetDir, observedFiles);
  return JSON.stringify({
    schema: 2,
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
