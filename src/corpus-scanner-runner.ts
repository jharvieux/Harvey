import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
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
import { assertNoSecretInArgv, SecretInArgvError } from "./secret-argv.js";

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
  cacheRecord?: CorpusScannerRecord;
}

function waitForScannerChild(bin: string, args: string[], options: SpawnOptions, input?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, options);
    let settled = false;
    let stdinError: Error | undefined;
    const cleanup = (): void => {
      child.removeListener("error", onError);
      child.removeListener("close", onClose);
      child.stdin?.removeListener("error", onStdinError);
    };
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve();
    };
    const onError = (error: Error): void => {
      if (stdinError === undefined) finish(error);
    };
    const onStdinError = (error: Error): void => {
      stdinError ??= error;
      if (!child.killed) {
        try {
          child.kill();
        } catch {
          // The stdin failure remains primary; close is the process-lifecycle boundary.
        }
      }
    };
    const onClose = (code: number | null, signal: NodeJS.Signals | null): void => {
      if (stdinError !== undefined) finish(stdinError);
      else if (signal !== null) finish(new Error(`${bin} was killed by signal ${signal}`));
      else if (code !== 0) finish(new Error(`${bin} exited with code ${code ?? "unknown"}`));
      else finish();
    };
    child.on("error", onError);
    child.once("close", onClose);
    if (input !== undefined) {
      const stdin = child.stdin as ChildProcess["stdin"];
      if (!stdin) {
        if (!child.killed) child.kill();
        finish(new Error(`${bin} did not expose the requested stdin pipe`));
        return;
      }
      stdin.once("error", onStdinError);
      stdin.end(input);
    }
  });
}

export async function runCorpusScanner(options: CorpusScannerRunOptions): Promise<CorpusScannerRunResult> {
  const outputDir = mkdtempSync(join(tmpdir(), "harvey-corpus-"));
  const out = join(outputDir, "findings.json");
  const scopeOut = join(outputDir, "scope.json");
  const qualityPreparation = options.cache?.dependencyPreparation;
  const qualityEnvironment = corpusQualityEnvironment();
  const execute = async (): Promise<{ findings: Finding[]; scope: { unitsExamined: number; description: string }; completed: boolean; failure?: string }> => {
    try {
      const quality = options.scanner === "quality-scan";
      const bin = quality ? join(options.repoRoot, "node_modules", ".bin", "tsx") : "pnpm";
      const degradedReason = quality && qualityPreparation?.complete === false
        ? `dependency preparation incomplete: ${qualityPreparation.reason}`
        : undefined;
      const args = quality
        ? [
            join(options.repoRoot, "src", "cli", "quality-scan.ts"),
            ...options.scriptArgs,
            ...(degradedReason === undefined ? [] : ["--degraded-knip-reason-stdin"]),
            ...(qualityPreparation?.complete === false && qualityPreparation.lockfileDigest === undefined
              ? ["--degraded-knip-unresolved-dependency-surface"]
              : []),
            "--out", out, "--scope-out", scopeOut,
          ]
        : [options.script, ...options.scriptArgs, "--out", out, "--scope-out", scopeOut];
      assertNoSecretInArgv("corpus-scanner-runner.execute", [bin, ...args], [qualityPreparation?.reason, degradedReason]);
      await waitForScannerChild(bin, args, {
        cwd: options.repoRoot,
        stdio: [degradedReason === undefined ? "ignore" : "pipe", "ignore", "inherit"],
        ...(quality ? { env: qualityEnvironment } : {}),
      }, degradedReason);
      const parsed = JSON.parse(readFileSync(out, "utf8")) as Finding[] | { finding: Finding };
      return {
        findings: Array.isArray(parsed) ? parsed : [parsed.finding],
        scope: readCorpusScannerScope(scopeOut, options.scanner),
        completed: true,
      };
    } catch (error) {
      if (error instanceof SecretInArgvError) throw error;
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
    const value = await execute();
    const qualityFreshReason = qualityPreparation
      ? `quality-scan executes fresh because ${qualityPreparation.reason}`
      : QUALITY_FRESH_REASON;
    const reason = value.failure ?? (options.scanner === "quality-scan"
      ? qualityFreshReason
      : qualityPreparation?.sourceTreeReason ?? "corpus scanner cache disabled");
    options.onEvent?.(`SCANNER ${options.scanner} — ${value.completed ? "fresh" : "incomplete"}; ${value.scope.unitsExamined} unit(s); ${reason}`);
    return { findings: value.findings };
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
    const value = await execute();
    const reason = `scanner implementation closure is non-cacheable: ${error instanceof Error ? error.message : String(error)}`;
    options.onEvent?.(`SCANNER ${options.scanner} — ${value.completed ? "fresh" : "incomplete"}; ${value.scope.unitsExamined} unit(s); ${reason}`);
    return { findings: value.findings };
  }
  const record = await executeCorpusScanner(cache, execute);
  options.onEvent?.(`SCANNER ${options.scanner} — ${record.cache}; ${record.scope.unitsExamined} unit(s); ${record.reason}`);
  return { findings: record.findings, cacheRecord: record };
}
