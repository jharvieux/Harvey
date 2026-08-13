import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DependencyPreparationResult } from "./corpus-dependency-preparation.js";
import {
  executeCorpusScanner,
  type CorpusScannerCacheMode,
  type CorpusScannerRecord,
} from "./corpus-scanner-cache.js";
import { buildCorpusScannerCache, corpusQualityEnvironment } from "./corpus-scanner-identity.js";
import { readCorpusScannerScope } from "./corpus-scanner-scope.js";
import type { Finding } from "./findings.js";

const QUALITY_FRESH_REASON = "quality-scan executes fresh because no complete reproducible dependency-preparation receipt is available";

interface CommonScannerRunOptions {
  repoRoot: string;
  scriptArgs: string[];
  targetDir: string;
  targetConfig: string;
  onEvent?: (message: string) => void;
}

interface ScannerCacheIdentity {
  dir: string;
  mode: CorpusScannerCacheMode;
  targetRevision: string;
  targetTree: string;
  dependencyPreparation?: DependencyPreparationResult;
}

type CorpusScannerRunOptions = CommonScannerRunOptions & (
  | { script: "detect-static"; scanner: "detect-static"; cache?: ScannerCacheIdentity }
  | { script: "mutation-scan"; scanner: "mutation-detect-only"; cache?: ScannerCacheIdentity }
  | { script: "quality-scan"; scanner: "quality-scan"; cache?: ScannerCacheIdentity }
);

interface CorpusScannerRunResult {
  findings: Finding[];
  cacheRecord: CorpusScannerRecord;
}

function freshRecord(
  scanner: CorpusScannerRunOptions["scanner"],
  value: { findings: Finding[]; scope: CorpusScannerRecord["scope"] },
  reason: string,
): CorpusScannerRecord {
  return { scanner, findings: value.findings, scope: value.scope, cache: "non-cacheable", reason };
}

export async function runCorpusScanner(options: CorpusScannerRunOptions): Promise<CorpusScannerRunResult> {
  const outputDir = mkdtempSync(join(tmpdir(), "harvey-corpus-"));
  const out = join(outputDir, "findings.json");
  const scopeOut = join(outputDir, "scope.json");
  const qualityPreparation = options.cache?.dependencyPreparation;
  const qualityEnvironment = corpusQualityEnvironment();
  const execute = (): { findings: Finding[]; scope: { unitsExamined: number; description: string }; completed: boolean; failure?: string } => {
    try {
      const quality = options.scanner === "quality-scan";
      const bin = quality ? join(options.repoRoot, "node_modules", ".bin", "tsx") : "pnpm";
      const args = quality
        ? [
            join(options.repoRoot, "src", "cli", "quality-scan.ts"),
            ...options.scriptArgs,
            ...(qualityPreparation?.complete === false ? ["--degraded-knip-reason", `dependency preparation incomplete: ${qualityPreparation.reason}`] : []),
            ...(qualityPreparation?.complete === false && qualityPreparation.lockfileDigest === undefined
              ? ["--degraded-knip-unresolved-dependency-surface"]
              : []),
            "--out", out, "--scope-out", scopeOut,
          ]
        : [options.script, ...options.scriptArgs, "--out", out, "--scope-out", scopeOut];
      execFileSync(bin, args, {
        cwd: options.repoRoot,
        stdio: ["ignore", "ignore", "inherit"],
        ...(quality ? { env: qualityEnvironment } : {}),
      });
      const parsed = JSON.parse(readFileSync(out, "utf8")) as Finding[] | { finding: Finding };
      return {
        findings: Array.isArray(parsed) ? parsed : [parsed.finding],
        scope: readCorpusScannerScope(scopeOut, options.scanner),
        completed: true,
      };
    } catch (error) {
      return {
        findings: [],
        scope: { unitsExamined: 0, description: `${options.scanner} emitted no valid scanner-owned scope receipt over ${options.targetConfig}` },
        completed: false,
        failure: error instanceof Error ? error.message : String(error),
      };
    }
  };

  const cacheAllowed = options.scanner === "quality-scan"
    ? Boolean(qualityPreparation?.complete === true && qualityPreparation.cacheable && qualityPreparation.key)
    : qualityPreparation?.sourceTreeCacheable !== false;
  if (!options.cache || !cacheAllowed) {
    const value = execute();
    const qualityFreshReason = qualityPreparation
      ? `quality-scan executes fresh because ${qualityPreparation.reason}`
      : QUALITY_FRESH_REASON;
    const reason = value.failure ?? (options.scanner === "quality-scan"
      ? qualityFreshReason
      : qualityPreparation?.sourceTreeReason ?? "corpus scanner cache disabled");
    options.onEvent?.(`SCANNER ${options.scanner} — ${value.completed ? "fresh" : "incomplete"}; ${value.scope.unitsExamined} unit(s); ${reason}`);
    return { findings: value.findings, cacheRecord: freshRecord(options.scanner, value, reason) };
  }

  let cache;
  try {
    cache = buildCorpusScannerCache({
      repoRoot: options.repoRoot,
      cacheDir: options.cache.dir,
      mode: options.cache.mode,
      scanner: options.scanner,
      targetDir: options.targetDir,
      targetRevision: options.cache.targetRevision,
      targetTree: options.cache.targetTree,
      targetConfig: options.targetConfig,
      invocationArgs: options.scriptArgs,
      dependencyPreparationKey: options.scanner === "quality-scan" ? qualityPreparation!.key : undefined,
      environment: options.scanner === "quality-scan" ? qualityEnvironment : undefined,
      onEvent: options.onEvent,
    });
  } catch (error) {
    const value = execute();
    const reason = `scanner implementation closure is non-cacheable: ${error instanceof Error ? error.message : String(error)}`;
    options.onEvent?.(`SCANNER ${options.scanner} — ${value.completed ? "fresh" : "incomplete"}; ${value.scope.unitsExamined} unit(s); ${reason}`);
    return { findings: value.findings, cacheRecord: freshRecord(options.scanner, value, reason) };
  }
  const record = await executeCorpusScanner(cache, execute);
  options.onEvent?.(`SCANNER ${options.scanner} — ${record.cache}; ${record.scope.unitsExamined} unit(s); ${record.reason}`);
  return { findings: record.findings, cacheRecord: record };
}
