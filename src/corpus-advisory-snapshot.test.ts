import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadCorpusAdvisorySnapshot, type CorpusAdvisorySnapshotManifest } from "./corpus-advisory-snapshot.js";

describe("immutable corpus advisory snapshots (#1876)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const fixture = (): { dir: string; payload: string; manifest: CorpusAdvisorySnapshotManifest } => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-advisory-snapshot-"));
    dirs.push(dir);
    const payload = "target.osv.json.gz";
    const bytes = gzipSync(JSON.stringify({ results: [] }));
    writeFileSync(join(dir, payload), bytes);
    const manifest: CorpusAdvisorySnapshotManifest = {
      schema: 1,
      capturedAt: "2026-08-11T00:00:00.000Z",
      expiresAt: "2026-08-18T00:00:00.000Z",
      osvScannerVersion: "2.3.8",
      targets: { target: { file: payload, sha256: createHash("sha256").update(bytes).digest("hex"), targetCommit: "commit-a" } },
    };
    writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest));
    return { dir, payload, manifest };
  };

  it("loads exact compressed bytes with digest, target pin, version, and expiry provenance", () => {
    const { dir, manifest } = fixture();
    expect(loadCorpusAdvisorySnapshot("target", "commit-a", { dir, now: new Date("2026-08-12T00:00:00Z") })).toEqual({
      result: { results: [] },
      digest: manifest.targets.target!.sha256,
      capturedAt: manifest.capturedAt,
      expiresAt: manifest.expiresAt,
      osvScannerVersion: "2.3.8",
      targetCommit: "commit-a",
    });
  });

  it("fails loud on missing, expired, wrong-target, tampered, and corrupt inputs", () => {
    const { dir, payload, manifest } = fixture();
    expect(() => loadCorpusAdvisorySnapshot("missing", "commit-a", { dir, now: new Date("2026-08-12") })).toThrow("no entry");
    expect(() => loadCorpusAdvisorySnapshot("target", "commit-a", { dir, now: new Date("2026-08-19") })).toThrow("expired");
    expect(() => loadCorpusAdvisorySnapshot("target", "commit-b", { dir, now: new Date("2026-08-12") })).toThrow("not pinned target");
    writeFileSync(join(dir, payload), "tampered");
    expect(() => loadCorpusAdvisorySnapshot("target", "commit-a", { dir, now: new Date("2026-08-12") })).toThrow("hashes to");
    const corrupt = Buffer.from("not-gzip");
    writeFileSync(join(dir, payload), corrupt);
    manifest.targets.target!.sha256 = createHash("sha256").update(corrupt).digest("hex");
    writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest));
    expect(() => loadCorpusAdvisorySnapshot("target", "commit-a", { dir, now: new Date("2026-08-12") })).toThrow("is corrupt");
  });

  it("loads every committed free-tier snapshot before its declared expiry", async () => {
    const { EXTERNAL_CORPUS, FREE_TIER_EXPECTATIONS } = await import("./scan/external-corpus.js");
    for (const expected of FREE_TIER_EXPECTATIONS) {
      const target = EXTERNAL_CORPUS.find((candidate) => candidate.slug === expected.slug)!;
      const loaded = loadCorpusAdvisorySnapshot(target.slug, target.commit, { now: new Date("2026-08-12T02:00:00Z") });
      expect(loaded.digest).toMatch(/^[a-f0-9]{64}$/);
      expect(loaded.osvScannerVersion).toContain("2.3.8");
    }
  });
});
