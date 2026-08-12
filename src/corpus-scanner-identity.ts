import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
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

export function dependencyInstallIdentity(targetDir: string): string {
  const tracked = execFileSync("git", ["-C", targetDir, "ls-files", "-z", "--", "."], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).split("\0").filter((path) => path !== "" && INSTALL_INPUT.test(path)).sort();
  if (tracked.length === 0) throw new Error(`corpus scanner target has no tracked package/install inputs: ${targetDir}`);
  const installPresence = tracked
    .filter((path) => path.endsWith("package.json"))
    .map((path) => `${path}:${existsSync(join(targetDir, dirname(path), "node_modules")) ? "installed" : "absent"}`);
  return digestParts([digestFiles(tracked.map((path) => join(targetDir, path)), targetDir), JSON.stringify(installPresence)]);
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
  return {
    dir: options.cacheDir,
    mode: options.mode,
    scanner: options.scanner,
    targetRevision: options.targetRevision,
    targetTree: options.targetTree,
    implementation: digestParts([digestFiles(closure, options.repoRoot), readFileSync(entry)]),
    externalInputs: {
      node: process.version,
      toolchain,
      tools: JSON.stringify(versions),
      targetConfig: options.targetConfig,
      dependencyInstall: dependencyInstallIdentity(options.targetDir),
    },
    pathRoot: options.targetDir,
    onEvent: options.onEvent,
  };
}
