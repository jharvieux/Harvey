import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { existsSync, readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import type { OsvScanResult } from "./scan/dependencies.js";

export interface CorpusAdvisorySnapshotEntry {
  file: string;
  sha256: string;
  targetCommit: string;
}

export interface CorpusAdvisorySnapshotManifest {
  schema: 1;
  capturedAt: string;
  expiresAt: string;
  osvScannerVersion: string;
  targets: Record<string, CorpusAdvisorySnapshotEntry>;
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

export function loadCorpusAdvisorySnapshot(
  slug: string,
  expectedCommit: string,
  options: { dir?: string; now?: Date } = {},
): LoadedCorpusAdvisorySnapshot {
  const dir = options.dir ?? CORPUS_ADVISORY_SNAPSHOT_DIR;
  const manifestPath = join(dir, "manifest.json");
  if (!existsSync(manifestPath)) throw new Error(`corpus advisory snapshot manifest is missing: ${manifestPath}`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Partial<CorpusAdvisorySnapshotManifest>;
  if (manifest.schema !== 1 || !manifest.targets || typeof manifest.osvScannerVersion !== "string") throw new Error("corpus advisory snapshot manifest has an unsupported or incomplete schema");
  const capturedAt = isoMillis(manifest.capturedAt ?? "", "capturedAt");
  const expiresAt = isoMillis(manifest.expiresAt ?? "", "expiresAt");
  if (expiresAt <= capturedAt) throw new Error("corpus advisory snapshot expiresAt is not after capturedAt");
  if ((options.now ?? new Date()).getTime() > expiresAt) throw new Error(`corpus advisory snapshot expired at ${manifest.expiresAt}; PR regression cannot report stale advisories as current`);
  const entry = manifest.targets[slug];
  if (!entry) throw new Error(`corpus advisory snapshot has no entry for ${slug}`);
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
    capturedAt: manifest.capturedAt!,
    expiresAt: manifest.expiresAt!,
    osvScannerVersion: manifest.osvScannerVersion,
    targetCommit: entry.targetCommit,
  };
}
