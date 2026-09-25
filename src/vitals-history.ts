import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import type { Finding } from "./findings.js";
import { vitalsScope, type VitalsReport } from "./hotspot-scan.js";

type VitalsAvailabilityStatus = "examined" | "not-assessed" | "failed";

interface VitalsSignalAvailability {
  status: VitalsAvailabilityStatus;
  unitsExamined: number;
  reason?: string;
}

interface VitalsAvailability {
  currentHealth: VitalsSignalAvailability;
  historyTrend: VitalsSignalAvailability;
  knowledgeRisk: VitalsSignalAvailability;
  aiProvenance: VitalsSignalAvailability;
}

interface VitalsMeasuredPopulations {
  historyComparableFiles: number;
  knowledgeCandidateFiles: number;
  knowledgeFilesWithAuthorship: number;
  aiFilesInWindow: number;
}

export interface VitalsHistoryBinding {
  sourceRevision?: string;
  sourceDirty: boolean;
  capturedAt: string;
  toolVersion: string;
  windows: { churnDays: 90; couplingDays: 180; knowledgeDays: 730; provenanceDays: 30 };
  history: {
    status: "usable" | "missing" | "failed";
    source: "audit-cache" | "client-checkout" | "none";
    sha256?: string;
    reason?: string;
  };
  cacheKey: string;
  populations?: VitalsMeasuredPopulations;
}

export interface PreparedVitalsRun {
  targetDir: string;
  historyDbPath: string;
  cacheDbPath: string;
  binding: VitalsHistoryBinding;
  markHistoryFailed(reason: string): void;
  removeScratchHistory(): void;
  measurePopulations(report: VitalsReport): VitalsMeasuredPopulations;
  publishHistory(report: VitalsReport): "published" | "retained";
  cleanup(): void;
}

const digestFile = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");

const SQLITE_BACKUP = [
  "import sqlite3, sys",
  "src = sqlite3.connect(sys.argv[1])",
  "dst = sqlite3.connect(sys.argv[2])",
  "src.backup(dst)",
  "dst.close()",
  "src.close()",
].join("\n");

const PRIOR_HISTORY_FILES = [
  "import json, sqlite3, sys",
  "from datetime import datetime",
  "scope = None if sys.argv[2] == '__NULL__' else sys.argv[2]",
  "conn = sqlite3.connect(sys.argv[1])",
  "conn.row_factory = sqlite3.Row",
  "today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()",
  "row = conn.execute('SELECT snapshot_id FROM health_snapshots WHERE timestamp < ? AND (scope IS ? OR scope = ?) ORDER BY timestamp DESC LIMIT 1', (today, scope, scope)).fetchone()",
  "files = [] if row is None else [r['file_path'] for r in conn.execute('SELECT file_path FROM file_snapshots WHERE snapshot_id = ?', (row['snapshot_id'],)).fetchall()]",
  "print(json.dumps(files))",
  "conn.close()",
].join("\n");

function backupSqlite(source: string, destination: string): void {
  rmSync(destination, { force: true });
  const stagedSource = `${destination}.source`;
  rmSync(stagedSource, { force: true });
  rmSync(`${stagedSource}-wal`, { force: true });
  rmSync(`${stagedSource}-shm`, { force: true });
  try {
    // Copy the main DB and any WAL sidecars into audit scratch first. SQLite may need to create a
    // shared-memory file even for a read-only WAL source; opening this local copy guarantees that
    // recovery/checkpoint work can never touch the client checkout.
    copyFileSync(source, stagedSource);
    if (existsSync(`${source}-wal`)) copyFileSync(`${source}-wal`, `${stagedSource}-wal`);
    if (existsSync(`${source}-shm`)) copyFileSync(`${source}-shm`, `${stagedSource}-shm`);
    chmodSync(stagedSource, 0o600);
    execFileSync("python3", ["-c", SQLITE_BACKUP, stagedSource, destination], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    // sqlite3 creates the destination before discovering a malformed/read-only source. Leaving
    // that empty file would make Vitals take its migration path instead of initializing a new DB.
    rmSync(destination, { force: true });
    throw error;
  } finally {
    rmSync(stagedSource, { force: true });
    rmSync(`${stagedSource}-wal`, { force: true });
    rmSync(`${stagedSource}-shm`, { force: true });
  }
}

const noGitLocks = { ...process.env, GIT_OPTIONAL_LOCKS: "0" };

const gitText = (cwd: string, args: string[]): string | undefined => {
  try {
    const output = execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: noGitLocks });
    return args.includes("-z") ? output : output.trim();
  } catch {
    return undefined;
  }
};

function priorHistoryFiles(dbPath: string, scope: string): string[] {
  if (!existsSync(dbPath)) return [];
  try {
    const raw = execFileSync("python3", ["-c", PRIOR_HISTORY_FILES, dbPath, scope || "__NULL__"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) && parsed.every((value) => typeof value === "string") ? parsed : [];
  } catch {
    return [];
  }
}

function knowledgePopulations(repoRoot: string, report: VitalsReport): Pick<VitalsMeasuredPopulations, "knowledgeCandidateFiles" | "knowledgeFilesWithAuthorship"> {
  const candidates = Object.keys(report.file_health ?? {}).slice(0, 50);
  if (!candidates.length) return { knowledgeCandidateFiles: 0, knowledgeFilesWithAuthorship: 0 };
  try {
    const raw = execFileSync("git", ["log", "--format=", "--name-only", "--no-merges", "--no-renames", "--since=2.years.ago", "--", ...candidates], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: noGitLocks,
      maxBuffer: 64 * 1024 * 1024,
    });
    const observed = new Set(raw.split("\n").map((line) => line.trim()).filter(Boolean));
    return { knowledgeCandidateFiles: candidates.length, knowledgeFilesWithAuthorship: candidates.filter((path) => observed.has(path)).length };
  } catch {
    return { knowledgeCandidateFiles: candidates.length, knowledgeFilesWithAuthorship: 0 };
  }
}

function copyCurrentCheckout(sourceRoot: string, scratchRoot: string): void {
  cpSync(sourceRoot, scratchRoot, {
    recursive: true,
    force: true,
    filter: (source) => {
      const rel = relative(sourceRoot, source);
      if (!rel) return true;
      const first = rel.split(sep)[0];
      return first !== ".git" && first !== ".vitals" && first !== "node_modules";
    },
  });
}

/**
 * Prepare a writable, audit-owned Vitals checkout. Vitals 0.2.0 always changes SQLite's journal
 * mode and saves a snapshot, so it must never receive the client checkout as its working tree.
 */
export function prepareVitalsRun(input: {
  targetDir: string;
  toolVersion: string;
  cacheRoot?: string;
  now?: Date;
}): PreparedVitalsRun {
  const requestedTarget = realpathSync(input.targetDir);
  const gitRootText = gitText(requestedTarget, ["rev-parse", "--show-toplevel"]);
  const sourceRoot = gitRootText ? realpathSync(gitRootText) : requestedTarget;
  const targetRelative = gitRootText ? relative(sourceRoot, requestedTarget) : "";
  const sourceRevision = gitRootText ? gitText(requestedTarget, ["rev-parse", "HEAD"]) : undefined;
  const sourceDirty = gitRootText ? Boolean(gitText(requestedTarget, ["status", "--porcelain", "--untracked-files=normal"])) : false;
  const cacheKey = createHash("sha256").update(sourceRoot).digest("hex");
  const cacheRoot = resolve(input.cacheRoot ?? process.env.HARVEY_VITALS_HISTORY_DIR ?? join(homedir(), ".cache", "harvey", "vitals-history"));
  const cacheDbPath = join(cacheRoot, cacheKey, "store.db");

  // Publication is part of the live M3 prerequisite, not a best-effort epilogue after Vitals has
  // already run. Prove the exact cache directory writable before creating the analysis scratch.
  try {
    const cacheDir = dirname(cacheDbPath);
    mkdirSync(cacheDir, { recursive: true });
    const probe = join(cacheDir, `.harvey-write-probe-${process.pid}-${Date.now()}`);
    writeFileSync(probe, "ok", { flag: "wx" });
    rmSync(probe);
  } catch (error) {
    throw new Error(`Vitals history cache preflight failed for ${cacheDbPath}: ${error instanceof Error ? error.message : String(error)}`);
  }

  // macOS exposes $TMPDIR through /var -> /private/var. Vitals compares its handed target path
  // literally with git's resolved toplevel, so hand it the canonical path from the start.
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), "harvey-vitals-")));
  const scratchRepo = join(scratch, "checkout");
  try {
    if (gitRootText) {
      execFileSync("git", ["clone", "--quiet", "--no-hardlinks", sourceRoot, scratchRepo], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        env: noGitLocks,
      });
      copyCurrentCheckout(sourceRoot, scratchRepo);
      // Overlaying additions/modifications onto a HEAD clone is insufficient: a tracked file
      // deleted in the live checkout otherwise survives from HEAD and is audited as current code.
      const deleted = gitText(sourceRoot, ["diff", "--name-only", "--no-renames", "--diff-filter=D", "-z", "HEAD", "--"]);
      if (deleted === undefined) throw new Error("Could not resolve HEAD-to-checkout deletions for the Vitals snapshot");
      for (const path of deleted?.split("\0").filter(Boolean) ?? []) rmSync(join(scratchRepo, path), { recursive: true, force: true });
    } else {
      mkdirSync(scratchRepo, { recursive: true });
      copyCurrentCheckout(sourceRoot, scratchRepo);
    }
    const probe = join(scratch, ".write-probe");
    writeFileSync(probe, "ok");
    rmSync(probe);
  } catch (error) {
    rmSync(scratch, { recursive: true, force: true });
    throw new Error(`Vitals scratch preflight failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  const scratchTarget = targetRelative ? join(scratchRepo, targetRelative) : scratchRepo;
  const scratchVitals = join(scratchRepo, ".vitals");
  const scratchDb = join(scratchVitals, "store.db");
  mkdirSync(scratchVitals, { recursive: true });

  const clientDb = join(sourceRoot, ".vitals", "store.db");
  const historySource = existsSync(cacheDbPath) ? cacheDbPath : existsSync(clientDb) ? clientDb : undefined;
  const historyKind = historySource === cacheDbPath ? "audit-cache" : historySource ? "client-checkout" : "none";
  let history: VitalsHistoryBinding["history"] = historySource
    ? { status: "usable", source: historyKind, sha256: digestFile(historySource) }
    : { status: "missing", source: "none", reason: "no prior Vitals history cache or client snapshot was found" };
  if (historySource) {
    try {
      // SQLite backup reads a transactionally consistent view, including a live WAL, without
      // changing the client's journal mode or checkpointing its database.
      backupSqlite(historySource, scratchDb);
      chmodSync(scratchDb, 0o600);
    } catch (error) {
      history = {
        status: "failed",
        source: historyKind,
        reason: `prior Vitals history could not be copied into audit scratch: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }
  const priorFiles = history.status === "usable" ? priorHistoryFiles(scratchDb, targetRelative) : [];

  let cleaned = false;
  const binding: VitalsHistoryBinding = {
    ...(sourceRevision ? { sourceRevision } : {}),
    sourceDirty,
    capturedAt: (input.now ?? new Date()).toISOString(),
    toolVersion: input.toolVersion,
    windows: { churnDays: 90, couplingDays: 180, knowledgeDays: 730, provenanceDays: 30 },
    history,
    cacheKey,
  };

  return {
    targetDir: scratchTarget,
    historyDbPath: scratchDb,
    cacheDbPath,
    binding,
    markHistoryFailed(reason) {
      binding.history = { ...binding.history, status: "failed", reason };
    },
    removeScratchHistory() {
      rmSync(scratchDb, { force: true });
      rmSync(`${scratchDb}-wal`, { force: true });
      rmSync(`${scratchDb}-shm`, { force: true });
    },
    measurePopulations(report) {
      const currentFiles = new Set(Object.keys(report.file_health ?? {}));
      const knowledge = knowledgePopulations(scratchRepo, report);
      const populations: VitalsMeasuredPopulations = {
        historyComparableFiles: priorFiles.filter((path) => currentFiles.has(path)).length,
        ...knowledge,
        aiFilesInWindow: report.provenance?.ai_files?.length ?? 0,
      };
      binding.populations = populations;
      return populations;
    },
    publishHistory(report) {
      const currentUnits = report.file_health ? Object.keys(report.file_health).length : (report.files_analyzed ?? 0);
      if (currentUnits <= 0 || !existsSync(scratchDb)) return "retained";
      mkdirSync(dirname(cacheDbPath), { recursive: true });
      const pending = `${cacheDbPath}.${process.pid}.tmp`;
      backupSqlite(scratchDb, pending);
      renameSync(pending, cacheDbPath);
      return "published";
    },
    cleanup() {
      if (cleaned) return;
      cleaned = true;
      rmSync(scratch, { recursive: true, force: true });
    },
  };
}

export function vitalsAvailability(report: VitalsReport, binding?: VitalsHistoryBinding, reduced = false, measured?: VitalsMeasuredPopulations): VitalsAvailability {
  const scope = vitalsScope(report);
  const currentUnits = scope.scored ?? report.files_analyzed ?? 0;
  const historyFailure = binding?.history.status === "failed" ? binding.history.reason : undefined;
  return {
    currentHealth: reduced
      ? { status: "not-assessed", unitsExamined: 0, reason: "the reduced tier does not compute Vitals file health" }
      : currentUnits > 0
        ? { status: "examined", unitsExamined: currentUnits }
        : { status: "failed", unitsExamined: 0, reason: "Vitals reported no files for current health" },
    historyTrend: report.trends && (measured?.historyComparableFiles ?? 0) > 0
      ? { status: "examined", unitsExamined: measured!.historyComparableFiles }
      : {
          status: historyFailure ? "failed" : "not-assessed",
          unitsExamined: 0,
          reason: historyFailure ?? (binding?.history.status === "missing"
            ? binding.history.reason
            : report.trends && measured
              ? "the prior snapshot and current file-health population have no comparable files"
              : "no measured comparable prior snapshot population was available"),
        },
    knowledgeRisk: !reduced && report.mode !== "complexity-only" && (measured?.knowledgeFilesWithAuthorship ?? 0) > 0
      ? { status: "examined", unitsExamined: measured!.knowledgeFilesWithAuthorship }
      : { status: "not-assessed", unitsExamined: 0, reason: measured?.knowledgeCandidateFiles
        ? `none of ${measured.knowledgeCandidateFiles} knowledge-risk candidate file(s) had authorship inside Vitals' 730-day window`
        : "full Git history knowledge-risk population was unavailable" },
    aiProvenance: (measured?.aiFilesInWindow ?? report.provenance?.ai_files?.length ?? 0) > 0
      ? { status: "examined", unitsExamined: measured?.aiFilesInWindow ?? report.provenance!.ai_files!.length }
      : { status: "not-assessed", unitsExamined: 0, reason: "no Vitals AI provenance files were present inside the 30-day window" },
  };
}

export function vitalsAvailabilityFinding(availability: VitalsAvailability): Finding {
  const line = (label: string, value: VitalsSignalAvailability) =>
    `${label}: ${value.status}; ${value.unitsExamined} unit(s) examined${value.reason ? `; ${value.reason}` : ""}.`;
  return {
    id: "M3-AVAILABILITY-00",
    taxonomy: "M3 — Signal availability",
    title: "M3 signal availability and examined populations",
    severity: "Info",
    confidence: "Confirmed",
    category: "Maintainability",
    status: "Open",
    evidence: [
      line("Current health", availability.currentHealth),
      line("History trend", availability.historyTrend),
      line("Knowledge risk", availability.knowledgeRisk),
      line("AI provenance", availability.aiProvenance),
    ].join("\n"),
    impact: "Separates an examined clean result from a signal that was unavailable or failed.",
    fix: "Restore the named history or runtime prerequisite before treating an unavailable signal as assessed.",
    location: "(repository-wide)",
    value: 1,
    ease: 5,
    safety: 5,
    mechanical: true,
  };
}
