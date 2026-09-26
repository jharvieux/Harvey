import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  CORPUS_ADVISORY_SNAPSHOT_DIR,
  loadCorpusAdvisorySnapshot,
  parseCorpusAdvisorySnapshotManifest,
} from "./corpus-advisory-snapshot.js";

interface AdvisoryFreshnessTarget {
  slug: string;
  commit: string;
}

interface AdvisoryFreshnessRow {
  slug: string;
  status: "current" | "warning" | "run-window" | "expired" | "invalid";
  capturedAt?: string;
  expiresAt?: string;
  sha256?: string;
  targetCommit?: string;
  reason: string;
}

interface AdvisoryFreshnessReceipt {
  schema: 1;
  checkedAt: string;
  requiredThrough: string;
  warningThrough: string;
  expectedCount: number;
  rows: AdvisoryFreshnessRow[];
  readyForRun: boolean;
  warning: boolean;
}

/** Inspect every pinned input without contacting OSV or treating an expired payload as current. */
export function inspectCorpusAdvisoryFreshness(
  expected: readonly AdvisoryFreshnessTarget[],
  options: { dir?: string; now: Date; runDurationMs: number; warningLeadMs: number },
): AdvisoryFreshnessReceipt {
  const { now, runDurationMs, warningLeadMs } = options;
  if (!Number.isFinite(now.getTime()) || !Number.isFinite(runDurationMs) || runDurationMs < 0 ||
    !Number.isFinite(warningLeadMs) || warningLeadMs < runDurationMs) {
    throw new Error("advisory freshness requires a valid clock and warning horizon at least as long as the run window");
  }
  const dir = options.dir ?? CORPUS_ADVISORY_SNAPSHOT_DIR;
  const manifestPath = join(dir, "manifest.json");
  if (!existsSync(manifestPath)) throw new Error(`corpus advisory snapshot manifest is missing: ${manifestPath}`);
  const manifest = parseCorpusAdvisorySnapshotManifest(JSON.parse(readFileSync(manifestPath, "utf8")));
  const seen = new Set<string>();
  const rows: AdvisoryFreshnessRow[] = expected.map(({ slug, commit }) => {
    if (seen.has(slug)) return { slug, status: "invalid", reason: "duplicate expected target" };
    seen.add(slug);
    const entry = manifest.targets[slug];
    if (!entry) return { slug, status: "invalid", reason: "snapshot entry is missing" };
    const provenance = { capturedAt: entry.capturedAt, expiresAt: entry.expiresAt, sha256: entry.sha256, targetCommit: entry.targetCommit };
    const expiresAt = Date.parse(entry.expiresAt);
    const capturedAt = Date.parse(entry.capturedAt);
    if (!Number.isFinite(expiresAt) || !Number.isFinite(capturedAt) || expiresAt <= capturedAt || capturedAt > now.getTime()) {
      return { slug, status: "invalid", ...provenance, reason: "capture or expiry timestamp is invalid" };
    }
    try {
      // The loader checks pin, digest, compressed payload and assessment. Its historical clock
      // permits integrity inspection after expiry; the classification below uses the real clock.
      loadCorpusAdvisorySnapshot(slug, commit, { dir, now: new Date(capturedAt) });
    } catch (error) {
      return { slug, status: "invalid", ...provenance, reason: error instanceof Error ? error.message : String(error) };
    }
    if (expiresAt <= now.getTime()) return { slug, status: "expired", ...provenance, reason: "snapshot has expired" };
    if (expiresAt <= now.getTime() + runDurationMs) return { slug, status: "run-window", ...provenance, reason: "snapshot can expire during the hosted run" };
    if (expiresAt <= now.getTime() + warningLeadMs) return { slug, status: "warning", ...provenance, reason: "refresh is due before the warning horizon" };
    return { slug, status: "current", ...provenance, reason: "snapshot covers the run and warning horizons" };
  });
  for (const slug of Object.keys(manifest.targets).sort()) {
    if (!seen.has(slug)) rows.push({ slug, status: "invalid", reason: "snapshot entry has no pinned corpus target" });
  }
  return {
    schema: 1,
    checkedAt: now.toISOString(),
    requiredThrough: new Date(now.getTime() + runDurationMs).toISOString(),
    warningThrough: new Date(now.getTime() + warningLeadMs).toISOString(),
    expectedCount: expected.length,
    rows,
    readyForRun: rows.every((row) => row.status === "current" || row.status === "warning"),
    warning: rows.some((row) => row.status !== "current"),
  };
}
