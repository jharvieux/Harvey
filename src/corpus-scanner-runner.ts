import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  executeCorpusScanner,
  type CorpusScannerCacheMode,
  type CorpusScannerRecord,
} from "./corpus-scanner-cache.js";
import { buildCorpusScannerCache } from "./corpus-scanner-identity.js";
import { countCorpusScannerUnits } from "./corpus-scanner-scope.js";
import type { Finding } from "./findings.js";

const QUALITY_FRESH_REASON =
  "quality-scan executes fresh because installed dependency/preparation state has no bounded cheap reproducible identity (#1871/#1872)";

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
}

type CorpusScannerRunOptions = CommonScannerRunOptions & (
  | { script: "detect-static"; scanner: "detect-static"; cache?: ScannerCacheIdentity }
  | { script: "mutation-scan"; scanner: "mutation-detect-only"; cache?: ScannerCacheIdentity }
  | { script: "quality-scan"; scanner: "quality-scan"; cache?: never }
);

interface CorpusScannerRunResult {
  findings: Finding[];
  cacheRecord?: CorpusScannerRecord;
}

export async function runCorpusScanner(options: CorpusScannerRunOptions): Promise<CorpusScannerRunResult> {
  const out = join(mkdtempSync(join(tmpdir(), "harvey-corpus-")), "findings.json");
  const unitsExamined = countCorpusScannerUnits(options.targetDir);
  const execute = (): { findings: Finding[]; scope: { unitsExamined: number; description: string }; completed: boolean; failure?: string } => {
    try {
      execFileSync("pnpm", [options.script, ...options.scriptArgs, "--out", out], {
        cwd: options.repoRoot,
        stdio: ["ignore", "ignore", "inherit"],
      });
      const parsed = JSON.parse(readFileSync(out, "utf8")) as Finding[] | { finding: Finding };
      return {
        findings: Array.isArray(parsed) ? parsed : [parsed.finding],
        scope: { unitsExamined, description: `${options.scanner} over ${options.targetConfig}` },
        completed: true,
      };
    } catch (error) {
      return {
        findings: [],
        scope: { unitsExamined, description: `${options.scanner} incomplete over ${options.targetConfig}` },
        completed: false,
        failure: error instanceof Error ? error.message : String(error),
      };
    }
  };

  if (options.scanner === "quality-scan" || !options.cache) {
    const value = execute();
    const reason = value.failure ?? (options.scanner === "quality-scan" ? QUALITY_FRESH_REASON : "corpus scanner cache disabled");
    options.onEvent?.(`SCANNER ${options.scanner} — ${value.completed ? "fresh" : "incomplete"}; ${value.scope.unitsExamined} unit(s); ${reason}`);
    return { findings: value.findings };
  }

  const cache = buildCorpusScannerCache({
    repoRoot: options.repoRoot,
    cacheDir: options.cache.dir,
    mode: options.cache.mode,
    scanner: options.scanner,
    targetDir: options.targetDir,
    targetRevision: options.cache.targetRevision,
    targetTree: options.cache.targetTree,
    targetConfig: options.targetConfig,
    onEvent: options.onEvent,
  });
  const record = await executeCorpusScanner(cache, execute);
  options.onEvent?.(`SCANNER ${options.scanner} — ${record.cache}; ${record.scope.unitsExamined} unit(s); ${record.reason}`);
  return { findings: record.findings, cacheRecord: record };
}
