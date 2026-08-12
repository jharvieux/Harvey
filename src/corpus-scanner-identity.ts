import { existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { CorpusCacheableScanner, CorpusScannerCacheMode, CorpusScannerCacheOptions } from "./corpus-scanner-cache.js";
import { statSafe } from "./fs-walk.js";
import { binaryVersion, digestFiles, digestParts, digestTree } from "./scan/mechanical-phase-cache.js";
import { discoverTransitiveImplementationFiles } from "./scan/mechanical-phase-identity.js";

const ENTRY: Record<CorpusCacheableScanner, string> = {
  "detect-static": "src/cli/static-detect.ts",
  "quality-scan": "src/cli/quality-scan.ts",
  "mutation-detect-only": "src/cli/mutation-scan.ts",
};

const PATH_ARGUMENTS = new Set(["--build", "--stats", "--config", "--report", "--hotspots"]);

function invocationArtifactIdentity(args: readonly string[], targetDir: string): string {
  const identities: string[] = [];
  for (let index = 0; index < args.length - 1; index += 1) {
    const flag = args[index]!;
    if (!PATH_ARGUMENTS.has(flag)) continue;
    const argument = args[index + 1]!;
    const path = resolve(targetDir, argument);
    if (!existsSync(path)) {
      identities.push(`${flag}:missing`);
    } else if (statSafe(path)?.isDirectory()) {
      identities.push(`${flag}:tree:${digestTree(path)}`);
    } else {
      identities.push(`${flag}:file:${digestParts([readFileSync(path)])}`);
    }
  }
  return digestParts(identities.length > 0 ? identities : ["no-external-invocation-artifacts"]);
}

export function corpusQualityEnvironment(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return {
    CI: "true",
    HOME: source.HOME ?? "",
    NO_COLOR: "1",
    PATH: source.PATH ?? "",
    TMPDIR: source.TMPDIR ?? tmpdir(),
  };
}

function corpusQualityEnvironmentIdentity(environment: NodeJS.ProcessEnv): Record<string, string> {
  return {
    CI: environment.CI ?? "",
    HOME: environment.HOME ?? "",
    NO_COLOR: environment.NO_COLOR ?? "",
    PATH: environment.PATH ?? "",
    TMPDIR: environment.TMPDIR ?? "",
  };
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
  invocationArgs: readonly string[];
  dependencyPreparationKey?: string;
  environment?: NodeJS.ProcessEnv;
  onEvent?: (message: string) => void;
}): CorpusScannerCacheOptions {
  const environment = corpusQualityEnvironment(options.environment);
  const entry = join(options.repoRoot, ENTRY[options.scanner]);
  const closure = discoverTransitiveImplementationFiles([entry]);
  const toolchain = digestFiles(
    [join(options.repoRoot, "package.json"), join(options.repoRoot, "pnpm-lock.yaml")],
    options.repoRoot,
  );
  if (options.scanner === "quality-scan" && !options.dependencyPreparationKey) {
    throw new Error("quality-scan: a complete reproducible dependency-preparation receipt is required for caching");
  }
  const targetRoots = [...new Set([resolve(options.targetDir), options.targetDir])].sort((a, b) => b.length - a.length);
  const invocation = options.invocationArgs.map((argument) => targetRoots.reduce(
    (normalized, root) => normalized.replaceAll(root, "<CORPUS_TARGET_ROOT>"),
    argument,
  ));
  return {
    dir: resolve(options.cacheDir),
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
      invocation: JSON.stringify(invocation),
      invocationArtifacts: invocationArtifactIdentity(options.invocationArgs, options.targetDir),
      ...(options.scanner === "quality-scan" ? {
        dependencyPreparation: options.dependencyPreparationKey!,
        environment: JSON.stringify(corpusQualityEnvironmentIdentity(environment)),
        jscpd: binaryVersion(join(options.repoRoot, "node_modules", ".bin", "jscpd")),
        knip: binaryVersion(join(options.repoRoot, "node_modules", ".bin", "knip")),
      } : {}),
    },
    pathRoot: options.targetDir,
    onEvent: options.onEvent,
  };
}
