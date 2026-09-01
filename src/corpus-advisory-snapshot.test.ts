import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  compareCorpusAdvisoryState,
  loadCorpusAdvisorySnapshot,
  mergeCorpusAdvisorySnapshotEntries,
  migrateCorpusAdvisorySnapshotManifest,
  parseCorpusAdvisorySnapshotManifest,
  writeCorpusAdvisoryObservation,
  type CorpusAdvisoryObservationArtifact,
  type CorpusAdvisorySnapshotEntry,
  type CorpusAdvisorySnapshotManifest,
} from "./corpus-advisory-snapshot.js";
import { parseOsvFindings, type OsvScanResult } from "./scan/dependencies.js";

function advisoryInput(overrides: Record<string, unknown> = {}): OsvScanResult {
  return {
    results: [{
      source: { path: "/tmp/capture/package-lock.json" },
      packages: [{
        package: { name: "fast-uri", version: "3.1.0", ecosystem: "npm" },
        groups: [{ ids: ["GHSA-v39h-62p7-jpjc"], max_severity: "7.5" }],
        vulnerabilities: [{
          id: "GHSA-v39h-62p7-jpjc",
          summary: "fast-uri can exhaust memory",
          details: "A crafted URI can cause excessive memory use.",
          aliases: ["CVE-2026-0001"],
          affected: [{ package: { name: "fast-uri", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "3.1.1" }] }] }],
          references: [{ type: "ADVISORY", url: "https://example.test/advisory" }],
          database_specific: { severity: "HIGH", cwe_ids: ["CWE-400"] },
          ...overrides,
        }],
      }],
    }],
  };
}

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
      schema: 2,
      targets: {
        target: {
          file: payload,
          sha256: createHash("sha256").update(bytes).digest("hex"),
          targetCommit: "commit-a",
          capturedAt: "2026-08-11T00:00:00.000Z",
          expiresAt: "2026-08-18T00:00:00.000Z",
          osvScannerVersion: "2.3.8",
        },
      },
    };
    writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest));
    return { dir, payload, manifest };
  };

  it("loads exact compressed bytes with digest, target pin, version, and expiry provenance", () => {
    const { dir, manifest } = fixture();
    expect(loadCorpusAdvisorySnapshot("target", "commit-a", { dir, now: new Date("2026-08-12T00:00:00Z") })).toEqual({
      result: { results: [] },
      digest: manifest.targets.target!.sha256,
      capturedAt: manifest.targets.target!.capturedAt,
      expiresAt: manifest.targets.target!.expiresAt,
      osvScannerVersion: "2.3.8",
      targetCommit: "commit-a",
    });
  });

  it("rejects the legacy global-epoch format and incomplete per-target provenance", () => {
    const legacy = {
      schema: 1,
      capturedAt: "2026-08-11T00:00:00.000Z",
      expiresAt: "2026-08-18T00:00:00.000Z",
      osvScannerVersion: "2.3.8",
      targets: { target: { file: "target.gz", sha256: "a".repeat(64), targetCommit: "commit-a" } },
    };
    expect(() => parseCorpusAdvisorySnapshotManifest(legacy)).toThrow("unsupported or incomplete schema");
    expect(() => parseCorpusAdvisorySnapshotManifest({ schema: 2, targets: legacy.targets })).toThrow("invalid capturedAt");
    expect(migrateCorpusAdvisorySnapshotManifest(legacy).targets.target).toMatchObject({
      capturedAt: legacy.capturedAt,
      expiresAt: legacy.expiresAt,
      osvScannerVersion: legacy.osvScannerVersion,
    });
  });

  it("keeps untouched target epochs during a target-only refresh and rejects them once stale", () => {
    const { dir, manifest } = fixture();
    const old = manifest.targets.target!;
    const untouchedBytes = gzipSync(JSON.stringify({ results: [] }));
    writeFileSync(join(dir, "untouched.osv.json.gz"), untouchedBytes);
    const untouched: CorpusAdvisorySnapshotEntry = {
      ...old,
      file: "untouched.osv.json.gz",
      sha256: createHash("sha256").update(untouchedBytes).digest("hex"),
      targetCommit: "commit-untouched",
    };
    const refreshed = mergeCorpusAdvisorySnapshotEntries(
      { schema: 2, targets: { target: old, untouched } },
      {
        target: {
          ...old,
          capturedAt: "2026-08-19T00:00:00.000Z",
          expiresAt: "2026-08-26T00:00:00.000Z",
        },
      },
    );
    writeFileSync(join(dir, "manifest.json"), JSON.stringify(refreshed));

    expect(loadCorpusAdvisorySnapshot("target", "commit-a", { dir, now: new Date("2026-08-20") }).capturedAt).toBe("2026-08-19T00:00:00.000Z");
    expect(() => loadCorpusAdvisorySnapshot("untouched", "commit-untouched", { dir, now: new Date("2026-08-20") })).toThrow(
      "for untouched expired at 2026-08-18T00:00:00.000Z",
    );
    expect(refreshed.targets.untouched).toEqual(untouched);
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

  it("loads a committed snapshot for every pinned corpus target before its declared expiry", async () => {
    const { EXTERNAL_CORPUS } = await import("./scan/external-corpus.js");
    for (const target of EXTERNAL_CORPUS) {
      const loaded = loadCorpusAdvisorySnapshot(target.slug, target.commit, { now: new Date("2026-08-21T02:00:00Z") });
      expect(loaded.digest).toMatch(/^[a-f0-9]{64}$/);
      expect(loaded.osvScannerVersion).toContain("2.3.8");
    }
  });

  it("classifies provider-only modified and WEB-reference churn as metadata-only", () => {
    const snapshotRaw = advisoryInput({ modified: "2026-08-27T00:00:00Z" });
    const liveRaw = advisoryInput({
      modified: "2026-08-28T00:00:00Z",
      references: [
        { type: "WEB", url: "https://access.redhat.com/errata/RHSA-2026:60520" },
        { type: "ADVISORY", url: "https://example.test/advisory" },
      ],
    });
    const receipt = compareCorpusAdvisoryState({
      liveRaw,
      snapshotRaw,
      liveFindings: parseOsvFindings(liveRaw),
      snapshotFindings: parseOsvFindings(snapshotRaw),
    });
    expect(receipt.status).toBe("metadata-only");
    expect(receipt.raw.equal).toBe(false);
    expect(receipt.raw.livePayload.results?.[0]?.source?.path).toBe("package-lock.json");
    expect(receipt.raw.population).toEqual({
      liveResults: 1,
      snapshotResults: 1,
      livePackages: 1,
      snapshotPackages: 1,
      liveVulnerabilities: 1,
      snapshotVulnerabilities: 1,
    });
    expect(receipt.semantic).toMatchObject({ equal: true, added: [], removed: [], changed: [] });
  });

  it.each([
    ["aliases", { aliases: ["CVE-2026-0001", "CVE-2026-0002"] }, "evidence"],
    ["fixed range", { affected: [{ package: { name: "fast-uri", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "3.1.2" }] }] }] }, "fix"],
    ["summary", { summary: "fast-uri can exhaust CPU" }, "title"],
    ["details", { details: "A crafted URI can cause excessive CPU use." }, "impact"],
    ["severity", { database_specific: { severity: "CRITICAL", cwe_ids: ["CWE-400"] } }, "severity"],
    ["CWE", { database_specific: { severity: "HIGH", cwe_ids: ["CWE-400", "CWE-770"] } }, "cwe"],
    ["ADVISORY link", { references: [{ type: "ADVISORY", url: "https://example.test/changed" }] }, "evidence"],
  ])("classifies a client-visible %s change as a finding change", (_label, override, changedField) => {
    const snapshotRaw = advisoryInput();
    const liveRaw = advisoryInput(override);
    const receipt = compareCorpusAdvisoryState({
      liveRaw,
      snapshotRaw,
      liveFindings: parseOsvFindings(liveRaw),
      snapshotFindings: parseOsvFindings(snapshotRaw),
    });
    expect(receipt.status).toBe("finding-change");
    expect(receipt.semantic.equal).toBe(false);
    expect(receipt.semantic.changed).toHaveLength(1);
    expect(receipt.semantic.changed[0]?.fields).toContain(changedField);
  });

  it("reports exact added and removed delivered findings", () => {
    const snapshotRaw = advisoryInput();
    const liveRaw = structuredClone(snapshotRaw);
    liveRaw.results![0]!.packages![0]!.vulnerabilities!.push({
      ...liveRaw.results![0]!.packages![0]!.vulnerabilities![0]!,
      id: "GHSA-added",
      summary: "new advisory",
      aliases: [],
    });
    const added = compareCorpusAdvisoryState({
      liveRaw,
      snapshotRaw,
      liveFindings: parseOsvFindings(liveRaw),
      snapshotFindings: parseOsvFindings(snapshotRaw),
    });
    expect(added.status).toBe("finding-change");
    expect(added.semantic.added.map((finding) => finding.id)).toEqual(["DEP-OSV-GHSA-added-fast-uri@3.1.0"]);
    expect(added.semantic.removed).toEqual([]);

    const removed = compareCorpusAdvisoryState({
      liveRaw: snapshotRaw,
      snapshotRaw: liveRaw,
      liveFindings: parseOsvFindings(snapshotRaw),
      snapshotFindings: parseOsvFindings(liveRaw),
    });
    expect(removed.semantic.removed.map((finding) => finding.id)).toEqual(["DEP-OSV-GHSA-added-fast-uri@3.1.0"]);
    expect(removed.semantic.added).toEqual([]);
  });

  it("atomically replaces a final-LF observation artifact", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-advisory-observation-"));
    dirs.push(dir);
    const path = join(dir, "observation.json");
    const artifact: CorpusAdvisoryObservationArtifact = {
      schema: 1,
      mode: "live-verify",
      startedAt: "2026-09-01T00:00:00.000Z",
      completedAt: null,
      populationComplete: false,
      liveOsvScannerVersion: "osv-scanner version: 2.3.8",
      expectedTargets: [{ slug: "target", repo: "owner/repo", pin: "abc" }],
      targets: {},
    };
    writeCorpusAdvisoryObservation(path, artifact);
    const first = readFileSync(path, "utf8");
    expect(first.endsWith("\n")).toBe(true);
    expect(JSON.parse(first)).toEqual(artifact);

    artifact.populationComplete = true;
    artifact.completedAt = "2026-09-01T00:01:00.000Z";
    writeCorpusAdvisoryObservation(path, artifact);
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual(artifact);
    expect(existsSync(`${path}.${process.pid}.tmp`)).toBe(false);
  });
});
