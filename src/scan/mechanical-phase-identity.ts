import { existsSync } from "node:fs";
import { join } from "node:path";
import { readRecursiveSafe, statSafe } from "../fs-walk.js";
import { binaryVersion, digestFiles, digestParts, digestTree, type MechanicalPhase, type MechanicalPhaseCacheOptions } from "./mechanical-phase-cache.js";
import { materializeRegistryPacks } from "./semgrep.js";

function productionTsFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readRecursiveSafe(dir)
    .filter((rel) => rel.endsWith(".ts") && !rel.endsWith(".test.ts") && statSafe(join(dir, rel))?.isFile())
    .map((rel) => join(dir, rel));
}

interface PhaseIdentityOptions {
  repoRoot: string;
  cacheDir: string;
  mode: MechanicalPhaseCacheOptions["mode"];
  targetRevision: string;
  targetTree: string;
  optionIdentity: string;
  onEvent?: (message: string) => void;
  registryPackIdentity?: { identity?: string; files?: string[]; failure?: string };
}

export function buildMechanicalPhaseCache(options: PhaseIdentityOptions): MechanicalPhaseCacheOptions {
  const scanDir = join(options.repoRoot, "src", "scan");
  const mechanical = join(scanDir, "mechanical.ts");
  const semgrepRules = join(scanDir, "rules", "semgrep");
  const gitleaksConfig = join(scanDir, "rules", "gitleaks-supabase.toml");
  const allScanFiles = productionTsFiles(scanDir);
  const structuralFiles = allScanFiles.filter((path) => ![
    "semgrep.ts",
    "secrets.ts",
    "dependencies.ts",
    "supply-chain.ts",
    "mechanical-phase-cache.ts",
    "mechanical-phase-identity.ts",
  ].includes(path.slice(scanDir.length + 1)));
  const orchestration = digestFiles([mechanical]);
  const registry = options.registryPackIdentity ?? materializeRegistryPacks(options.cacheDir);
  const implementation: Partial<Record<MechanicalPhase, string>> = {
    "secrets-history": digestParts([orchestration, digestFiles([join(scanDir, "secrets.ts"), gitleaksConfig])]),
    semgrep: digestParts([orchestration, digestFiles([join(scanDir, "semgrep.ts")]), digestTree(semgrepRules)]),
    configuration: digestParts([orchestration, digestFiles(structuralFiles)]),
    "structural-ast": digestParts([orchestration, digestFiles(structuralFiles)]),
  };
  const externalInputs: MechanicalPhaseCacheOptions["externalInputs"] = {
    "secrets-history": {
      gitleaks: binaryVersion("gitleaks"),
      trufflehog: binaryVersion("trufflehog"),
      options: options.optionIdentity,
    },
    semgrep: {
      semgrep: binaryVersion("semgrep"),
      registryPacks: registry.identity ? digestParts([registry.identity]) : "unresolved",
      options: options.optionIdentity,
    },
    configuration: { node: process.version, options: options.optionIdentity },
    "structural-ast": { node: process.version, options: options.optionIdentity },
  };
  return {
    dir: options.cacheDir,
    mode: options.mode,
    targetRevision: options.targetRevision,
    targetTree: options.targetTree,
    implementation,
    externalInputs,
    disabled: registry.failure ? { semgrep: `${registry.failure}; phase is explicitly non-cacheable for this run` } : undefined,
    materializedInputs: registry.files ? { semgrep: registry.files } : undefined,
    onEvent: options.onEvent,
  };
}
