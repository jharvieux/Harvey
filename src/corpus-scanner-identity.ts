import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CorpusCacheableScanner, CorpusScannerCacheMode, CorpusScannerCacheOptions } from "./corpus-scanner-cache.js";
import { binaryVersion, digestFiles, digestParts } from "./scan/mechanical-phase-cache.js";
import { discoverTransitiveImplementationFiles } from "./scan/mechanical-phase-identity.js";

const ENTRY: Record<CorpusCacheableScanner, string> = {
  "detect-static": "src/cli/static-detect.ts",
  "quality-scan": "src/cli/quality-scan.ts",
  "mutation-detect-only": "src/cli/mutation-scan.ts",
};

export function corpusQualityEnvironment(): NodeJS.ProcessEnv {
  return {
    CI: "true",
    HOME: process.env.HOME ?? "",
    NO_COLOR: "1",
    PATH: process.env.PATH ?? "",
    TMPDIR: process.env.TMPDIR ?? tmpdir(),
  };
}

function corpusQualityEnvironmentIdentity(): Record<string, string> {
  return { CI: "true", NO_COLOR: "1" };
}

export function buildCorpusScannerCache(options: {
  repoRoot: string;
  cacheDir: string;
  mode: CorpusScannerCacheMode;
  scanner: CorpusCacheableScanner;
  targetDir: string;
  targetRevision: string;
  targetTree: string;
  targetConfig: string;
  dependencyPreparationKey?: string;
  onEvent?: (message: string) => void;
}): CorpusScannerCacheOptions {
  const entry = join(options.repoRoot, ENTRY[options.scanner]);
  const closure = discoverTransitiveImplementationFiles([entry]);
  const toolchain = digestFiles(
    [join(options.repoRoot, "package.json"), join(options.repoRoot, "pnpm-lock.yaml")],
    options.repoRoot,
  );
  if (options.scanner === "quality-scan" && !options.dependencyPreparationKey) {
    throw new Error("quality-scan: a complete reproducible dependency-preparation receipt is required for caching");
  }
  return {
    dir: options.cacheDir,
    mode: options.mode,
    scanner: options.scanner,
    targetRevision: options.targetRevision,
    targetTree: options.targetTree,
    implementation: digestParts([digestFiles(closure, options.repoRoot), readFileSync(entry)]),
    externalInputs: {
      node: process.version,
      abi: `${process.versions.modules ?? "unknown"}/${process.versions.napi ?? "unknown"}`,
      platform: `${process.platform}/${process.arch}`,
      toolchain,
      targetConfig: options.targetConfig,
      ...(options.scanner === "quality-scan" ? {
        dependencyPreparation: options.dependencyPreparationKey!,
        environment: JSON.stringify(corpusQualityEnvironmentIdentity()),
        jscpd: binaryVersion(join(options.repoRoot, "node_modules", ".bin", "jscpd")),
        knip: binaryVersion(join(options.repoRoot, "node_modules", ".bin", "knip")),
      } : {}),
    },
    pathRoot: options.targetDir,
    onEvent: options.onEvent,
  };
}
