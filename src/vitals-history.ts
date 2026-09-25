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
}

export interface PreparedVitalsRun {
  targetDir: string;
  historyDbPath: string;
  cacheDbPath: string;
  binding: VitalsHistoryBinding;
  markHistoryFailed(reason: string): void;
  removeScratchHistory(): void;
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

const gitText = (cwd: string, args: string[]): string | undefined => {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch {
    return undefined;
  }
};

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

  // macOS exposes $TMPDIR through /var -> /private/var. Vitals compares its handed target path
  // literally with git's resolved toplevel, so hand it the canonical path from the start.
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), "harvey-vitals-")));
  const scratchRepo = join(scratch, "checkout");
  try {
    if (gitRootText) {
      execFileSync("git", ["clone", "--quiet", "--no-hardlinks", sourceRoot, scratchRepo], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
      copyCurrentCheckout(sourceRoot, scratchRepo);
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

export function vitalsAvailability(report: VitalsReport, binding?: VitalsHistoryBinding, reduced = false): VitalsAvailability {
  const scope = vitalsScope(report);
  const currentUnits = scope.scored ?? report.files_analyzed ?? 0;
  const historyFailure = binding?.history.status === "failed" ? binding.history.reason : undefined;
  return {
    currentHealth: reduced
      ? { status: "not-assessed", unitsExamined: 0, reason: "the reduced tier does not compute Vitals file health" }
      : currentUnits > 0
        ? { status: "examined", unitsExamined: currentUnits }
        : { status: "failed", unitsExamined: 0, reason: "Vitals reported no files for current health" },
    historyTrend: report.trends
      ? { status: "examined", unitsExamined: currentUnits }
      : {
          status: historyFailure ? "failed" : "not-assessed",
          unitsExamined: 0,
          reason: historyFailure ?? (binding?.history.status === "missing" ? binding.history.reason : "no comparable prior snapshot was available"),
        },
    knowledgeRisk: !reduced && report.mode !== "complexity-only" && scope.knowledgePopulation !== undefined
      ? { status: "examined", unitsExamined: Math.min(50, scope.knowledgePopulation) }
      : { status: "not-assessed", unitsExamined: 0, reason: "full Git history knowledge-risk analysis was unavailable" },
    aiProvenance: report.provenance?.has_data
      ? { status: "examined", unitsExamined: report.provenance.summary?.unique_files ?? report.provenance.ai_files?.length ?? 0 }
      : { status: "not-assessed", unitsExamined: 0, reason: "no Vitals AI provenance history was available" },
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
