import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { inspectCorpusAdvisoryFreshness } from "./corpus-advisory-freshness.js";
import type { CorpusAdvisorySnapshotManifest } from "./corpus-advisory-snapshot.js";
import { runOsvScanner } from "./scan/dependencies.js";

describe("corpus advisory freshness (#2148)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  function fixture() {
    const dir = mkdtempSync(join(tmpdir(), "harvey-advisory-freshness-"));
    dirs.push(dir);
    const file = "target.osv.json.gz";
    const bytes = gzipSync(JSON.stringify({ schema: 1, ...runOsvScanner(dir) }));
    writeFileSync(join(dir, file), bytes);
    const entry = {
      file,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      targetCommit: "pinned",
      capturedAt: "2026-09-24T00:00:00.000Z",
      expiresAt: "2026-09-26T12:00:00.000Z",
      osvScannerVersion: "2.3.8",
    };
    const manifest: CorpusAdvisorySnapshotManifest = { schema: 2, targets: { target: entry } };
    const save = () => writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest));
    save();
    const inspect = (now: string) => inspectCorpusAdvisoryFreshness([{ slug: "target", commit: "pinned" }], {
      dir, now: new Date(now), runDurationMs: 4 * 3_600_000, warningLeadMs: 48 * 3_600_000,
    });
    return { dir, file, manifest, save, inspect };
  }

  it("classifies exact expiry, hosted run window and advance warning at injected boundaries", () => {
    const { inspect } = fixture();
    expect(inspect("2026-09-24T11:59:59.999Z").rows[0]?.status).toBe("current");
    expect(inspect("2026-09-24T12:00:00.000Z").rows[0]?.status).toBe("warning");
    expect(inspect("2026-09-24T12:00:00.000Z").rows[0]).toMatchObject({
      capturedAt: "2026-09-24T00:00:00.000Z",
      expiresAt: "2026-09-26T12:00:00.000Z",
      sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    expect(inspect("2026-09-26T07:59:59.999Z").readyForRun).toBe(true);
    expect(inspect("2026-09-26T08:00:00.000Z").rows[0]?.status).toBe("run-window");
    expect(inspect("2026-09-26T08:00:00.000Z").readyForRun).toBe(false);
    expect(inspect("2026-09-26T12:00:00.000Z").rows[0]?.status).toBe("expired");
  });

  it("accounts for the complete pinned population, invalid pins, corrupt bytes and stray rows", () => {
    const { dir, file, manifest, save, inspect } = fixture();
    const now = "2026-09-24T00:00:00.000Z";
    const missing = inspectCorpusAdvisoryFreshness([{ slug: "target", commit: "pinned" }, { slug: "missing", commit: "pin" }], {
      dir, now: new Date(now), runDurationMs: 1, warningLeadMs: 2,
    });
    expect(missing.rows.map((row) => [row.slug, row.status])).toEqual([["target", "current"], ["missing", "invalid"]]);
    expect(missing.readyForRun).toBe(false);
    expect(inspectCorpusAdvisoryFreshness([{ slug: "target", commit: "wrong" }], {
      dir, now: new Date(now), runDurationMs: 1, warningLeadMs: 2,
    }).rows[0]?.reason).toContain("not pinned target");
    manifest.targets.extra = { ...manifest.targets.target!, file: "extra.gz" };
    save();
    expect(inspect(now).rows.at(-1)).toMatchObject({ slug: "extra", status: "invalid" });
    delete manifest.targets.extra;
    save();
    writeFileSync(join(dir, file), "tampered");
    expect(inspect(now).rows[0]).toMatchObject({ status: "invalid" });
    expect(inspect(now).rows[0]?.reason).toContain("hashes to");
  });
});
