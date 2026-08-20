import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { existsSync, readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import type { OsvScanResult } from "./scan/dependencies.js";

export interface CorpusAdvisorySnapshotEntry {
  file: string;
  sha256: string;
  targetCommit: string;
  capturedAt: string;
  expiresAt: string;
  osvScannerVersion: string;
}

export interface CorpusAdvisorySnapshotManifest {
  schema: 2;
  targets: Record<string, CorpusAdvisorySnapshotEntry>;
}

interface LegacyCorpusAdvisorySnapshotManifest {
  schema: 1;
  capturedAt: string;
  expiresAt: string;
  osvScannerVersion: string;
  targets: Record<string, Pick<CorpusAdvisorySnapshotEntry, "file" | "sha256" | "targetCommit">>;
}

interface LoadedCorpusAdvisorySnapshot {
  result: OsvScanResult;
  digest: string;
  capturedAt: string;
  expiresAt: string;
  osvScannerVersion: string;
  targetCommit: string;
}

export const CORPUS_ADVISORY_SNAPSHOT_DIR = resolve("src/scan/__fixtures__/corpus-advisories");

export function canonicalizeCorpusOsvInput(result: OsvScanResult): OsvScanResult {
  return {
    ...result,
    results: result.results?.map((row) => ({
      ...row,
      source: row.source?.path ? { ...row.source, path: basename(row.source.path) } : row.source,
    })),
  };
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function isoMillis(value: string, field: string): number {
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) throw new Error(`corpus advisory snapshot ${field} is not an ISO timestamp`);
  return millis;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function entryFromUnknown(slug: string, value: unknown): CorpusAdvisorySnapshotEntry {
  if (!isRecord(value)) throw new Error(`corpus advisory snapshot entry for ${slug} is not an object`);
  for (const field of ["file", "sha256", "targetCommit", "capturedAt", "expiresAt", "osvScannerVersion"] as const) {
    if (typeof value[field] !== "string" || value[field].length === 0) {
      throw new Error(`corpus advisory snapshot entry for ${slug} has an invalid ${field}`);
    }
  }
  return value as unknown as CorpusAdvisorySnapshotEntry;
}

export function parseCorpusAdvisorySnapshotManifest(value: unknown): CorpusAdvisorySnapshotManifest {
  if (!isRecord(value) || value.schema !== 2 || !isRecord(value.targets)) {
    throw new Error("corpus advisory snapshot manifest has an unsupported or incomplete schema");
  }
  const targets = Object.fromEntries(Object.entries(value.targets).map(([slug, entry]) => [slug, entryFromUnknown(slug, entry)]));
  return { schema: 2, targets };
}

/**
 * Upgrade is intentionally generator-only. The loader rejects schema 1 because its global epoch can
 * be relabelled by a target-only refresh. During an actual migration, the old global provenance is
 * copied onto every old entry before any selected target receives a new capture epoch.
 */
export function migrateCorpusAdvisorySnapshotManifest(value: unknown): CorpusAdvisorySnapshotManifest {
  if (isRecord(value) && value.schema === 2) return parseCorpusAdvisorySnapshotManifest(value);
  if (!isRecord(value) || value.schema !== 1 || !isRecord(value.targets)) {
    throw new Error("corpus advisory snapshot manifest has an unsupported or incomplete schema");
  }
  const legacy = value as unknown as LegacyCorpusAdvisorySnapshotManifest;
  isoMillis(legacy.capturedAt ?? "", "capturedAt");
  isoMillis(legacy.expiresAt ?? "", "expiresAt");
  if (typeof legacy.osvScannerVersion !== "string" || legacy.osvScannerVersion.length === 0) {
    throw new Error("corpus advisory snapshot manifest has an invalid osvScannerVersion");
  }
  const targets = Object.fromEntries(
    Object.entries(legacy.targets).map(([slug, entry]) => [
      slug,
      entryFromUnknown(slug, {
        ...entry,
        capturedAt: legacy.capturedAt,
        expiresAt: legacy.expiresAt,
        osvScannerVersion: legacy.osvScannerVersion,
      }),
    ]),
  );
  return { schema: 2, targets };
}

export function mergeCorpusAdvisorySnapshotEntries(
  prior: CorpusAdvisorySnapshotManifest | undefined,
  refreshed: Record<string, CorpusAdvisorySnapshotEntry>,
): CorpusAdvisorySnapshotManifest {
  return { schema: 2, targets: { ...(prior?.targets ?? {}), ...refreshed } };
}

export function loadCorpusAdvisorySnapshot(
  slug: string,
  expectedCommit: string,
  options: { dir?: string; now?: Date } = {},
): LoadedCorpusAdvisorySnapshot {
  const dir = options.dir ?? CORPUS_ADVISORY_SNAPSHOT_DIR;
  const manifestPath = join(dir, "manifest.json");
  if (!existsSync(manifestPath)) throw new Error(`corpus advisory snapshot manifest is missing: ${manifestPath}`);
  const manifest = parseCorpusAdvisorySnapshotManifest(JSON.parse(readFileSync(manifestPath, "utf8")));
  const entry = manifest.targets[slug];
  if (!entry) throw new Error(`corpus advisory snapshot has no entry for ${slug}`);
  const capturedAt = isoMillis(entry.capturedAt, `${slug}.capturedAt`);
  const expiresAt = isoMillis(entry.expiresAt, `${slug}.expiresAt`);
  if (expiresAt <= capturedAt) throw new Error(`corpus advisory snapshot expiresAt for ${slug} is not after capturedAt`);
  if ((options.now ?? new Date()).getTime() > expiresAt) throw new Error(`corpus advisory snapshot for ${slug} expired at ${entry.expiresAt}; PR regression cannot report stale advisories as current`);
  if (entry.targetCommit !== expectedCommit) throw new Error(`corpus advisory snapshot for ${slug} covers ${entry.targetCommit}, not pinned target ${expectedCommit}`);
  if (!/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error(`corpus advisory snapshot for ${slug} has an invalid digest`);
  const path = join(dir, entry.file);
  if (!existsSync(path)) throw new Error(`corpus advisory snapshot payload is missing: ${path}`);
  const bytes = readFileSync(path);
  const actual = sha256(bytes);
  if (actual !== entry.sha256) throw new Error(`corpus advisory snapshot payload for ${slug} hashes to ${actual}, not ${entry.sha256}`);
  let result: OsvScanResult;
  try {
    result = canonicalizeCorpusOsvInput(JSON.parse(gunzipSync(bytes).toString("utf8")) as OsvScanResult);
  } catch (error) {
    throw new Error(`corpus advisory snapshot payload for ${slug} is corrupt: ${error instanceof Error ? error.message : String(error)}`);
  }
  return {
    result,
    digest: entry.sha256,
    capturedAt: entry.capturedAt,
    expiresAt: entry.expiresAt,
    osvScannerVersion: entry.osvScannerVersion,
    targetCommit: entry.targetCommit,
  };
}
