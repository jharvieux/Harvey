import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { CorpusCacheableScanner, CorpusScannerCacheMode, CorpusScannerCacheOptions } from "./corpus-scanner-cache.js";
import { digestFiles, digestParts } from "./scan/mechanical-phase-cache.js";
import { discoverTransitiveImplementationFiles } from "./scan/mechanical-phase-identity.js";

const ENTRY: Record<CorpusCacheableScanner, string> = {
  "detect-static": "src/cli/static-detect.ts",
  "mutation-detect-only": "src/cli/mutation-scan.ts",
};

export function buildCorpusScannerCache(options: {
  repoRoot: string;
  cacheDir: string;
  mode: CorpusScannerCacheMode;
  scanner: CorpusCacheableScanner;
  targetDir: string;
  targetRevision: string;
  targetTree: string;
  targetConfig: string;
  onEvent?: (message: string) => void;
}): CorpusScannerCacheOptions {
  const entry = join(options.repoRoot, ENTRY[options.scanner]);
  const closure = discoverTransitiveImplementationFiles([entry]);
  const toolchain = digestFiles(
    [join(options.repoRoot, "package.json"), join(options.repoRoot, "pnpm-lock.yaml")],
    options.repoRoot,
  );
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
      targetConfig: options.targetConfig,
    },
    pathRoot: options.targetDir,
    onEvent: options.onEvent,
  };
}
