import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { mergeCorpusAdvisoryObservations } from "./corpus-advisory-observation.js";
import { compareCorpusAdvisoryState, type CorpusAdvisoryComparisonReceipt, type CorpusAdvisoryObservationArtifact, type CorpusAdvisorySnapshotEntry } from "./corpus-advisory-snapshot.js";
import { partitionTargets } from "./scan/corpus-shards.js";
import { runOsvScanner, type OsvAssessment } from "./scan/dependencies.js";
import { EXTERNAL_CORPUS } from "./scan/external-corpus.js";

const directories: string[] = [];
afterEach(() => directories.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "corpus-advisory-merge-"));
  directories.push(dir);
  // No supported dependency inputs: the real scanner emits a complete not-applicable inventory
  // without contacting OSV. Its evidence must survive aggregation just like assessed targets.
  const input = runOsvScanner(dir);
  const comparison = compareCorpusAdvisoryState({ liveRaw: input.result, snapshotRaw: input.result, liveFindings: [], snapshotFindings: [], liveAssessment: input.assessment, snapshotAssessment: input.assessment });
  const expected = EXTERNAL_CORPUS.map(({ slug, repo, commit }) => ({ slug, repo, pin: commit }));
  const provenance = { headSha: "a".repeat(40), runId: "123", runAttempt: "1", registrySha256: "b".repeat(64), snapshotManifestSha256: "c".repeat(64) };
  const snapshots: Record<string, CorpusAdvisorySnapshotEntry & { rawSha256: string; assessment: OsvAssessment }> = Object.fromEntries(expected.map(({ slug, pin }) => [slug, {
    file: `${slug}.osv.json.gz`, sha256: "d".repeat(64), targetCommit: pin,
    capturedAt: "2026-09-20T00:00:00Z", expiresAt: "2026-09-27T00:00:00Z", osvScannerVersion: "2.3.8",
    rawSha256: createHash("sha256").update(JSON.stringify(input.result)).digest("hex"),
    assessment: input.assessment,
  }]));
  const parts: CorpusAdvisoryObservationArtifact[] = partitionTargets(expected.map(({ slug }) => slug), 4).map((slugs, index) => ({
    schema: 1, mode: "live-verify", provenance, shard: { index: index + 1, count: 4 },
    startedAt: "2026-09-22T00:00:00Z", completedAt: "2026-09-22T00:05:00Z", populationComplete: true, liveOsvScannerVersion: "2.3.8",
    expectedTargets: expected.filter(({ slug }) => slugs.includes(slug)),
    targets: Object.fromEntries(expected.filter(({ slug }) => slugs.includes(slug)).map((target) => [target.slug, {
      ...target, startedAt: "2026-09-22T00:00:00Z", observedAt: "2026-09-22T00:04:00Z", status: "equal",
      snapshot: { artifactSha256: snapshots[target.slug]!.sha256, capturedAt: snapshots[target.slug]!.capturedAt, expiresAt: snapshots[target.slug]!.expiresAt, osvScannerVersion: "2.3.8" },
      comparison: structuredClone(comparison),
    }])),
  }));
  return { parts, expected, provenance, snapshots, merge: (selected: readonly unknown[] = parts) => mergeCorpusAdvisoryObservations(selected, expected, provenance, snapshots) };
}

describe("complete live corpus observation delivery (#2153)", () => {
  it("delivers each complete raw/semantic receipt and its input coverage exactly once", () => {
    const { merge, expected, provenance, parts } = fixture();
    const merged = merge();
    expect(merged.populationComplete).toBe(true);
    expect(merged.provenance).toEqual(provenance);
    expect(merged.expectedTargets).toEqual(expected);
    expect(merged.targets).toEqual(Object.assign({}, ...parts.map(({ targets }) => targets)));
    expect(merged.assessmentCoverage).toEqual({ inventoryComplete: true, assessed: 0, partial: 0, notAssessed: 0, notApplicable: expected.length });
  });

  it.each(["headSha", "runId", "runAttempt", "registrySha256", "snapshotManifestSha256"] as const)("rejects another %s rather than merging unrelated evidence", (field) => {
    const { parts, merge } = fixture();
    parts[0]!.provenance = { ...parts[0]!.provenance!, [field]: "wrong" };
    expect(() => merge()).toThrow("exact head, attempt, registry and advisory snapshot inputs");
  });

  it.each(["missing", "duplicate", "extra", "reassigned", "pin", "repo", "version"])("rejects %s shard population/provenance", (mutation) => {
    const { parts, merge } = fixture();
    const part = parts[0]!;
    if (mutation === "missing") parts.pop();
    if (mutation === "duplicate") parts[1] = structuredClone(part);
    if (mutation === "extra") parts.push(structuredClone(part));
    if (mutation === "reassigned") part.expectedTargets = parts[1]!.expectedTargets;
    if (mutation === "pin") part.expectedTargets[0] = { ...part.expectedTargets[0]!, pin: "wrong" };
    if (mutation === "repo") part.expectedTargets[0] = { ...part.expectedTargets[0]!, repo: "wrong" };
    if (mutation === "version") part.liveOsvScannerVersion = "other";
    expect(() => merge()).toThrow();
  });

  it.each(["artifactSha256", "capturedAt", "expiresAt", "osvScannerVersion"] as const)("rejects changed per-target snapshot %s", (field) => {
    const { parts, merge } = fixture();
    Object.values(parts[0]!.targets)[0]!.snapshot![field] = "wrong";
    expect(() => merge()).toThrow("snapshot provenance differs");
  });

  it.each(["raw", "snapshotRaw", "assessment", "status", "unowned"])("rejects %s evidence corruption", (mutation) => {
    const { parts, merge } = fixture();
    const observation = Object.values(parts[0]!.targets)[0]!;
    if (mutation === "raw") observation.comparison!.raw.liveSha256 = "wrong";
    if (mutation === "snapshotRaw") observation.comparison!.raw.snapshotSha256 = "wrong";
    if (mutation === "assessment") delete observation.comparison!.assessment;
    if (mutation === "status") observation.status = "finding-change";
    if (mutation === "unowned") parts[0]!.targets["unowned"] = observation;
    expect(() => merge()).toThrow();
  });

  it.each(["missing", "started", "failed", "unfinished", "invented-completion"])("retains %s diagnostics with an explicitly incomplete population", (mutation) => {
    const { parts, merge } = fixture();
    const part = parts[0]!;
    const slug = Object.keys(part.targets)[0]!;
    if (mutation === "missing") delete part.targets[slug];
    if (mutation === "started" || mutation === "failed") part.targets[slug]!.status = mutation;
    if (mutation === "unfinished") part.completedAt = null;
    if (mutation === "invented-completion") { delete part.targets[slug]; part.populationComplete = true; }
    const merged = merge();
    expect(merged.populationComplete).toBe(false);
    expect(merged.targets).toEqual(Object.assign({}, ...parts.map(({ targets }) => targets)));
  });

  it("preserves real finding-change evidence without misclassifying complete coverage as setup failure", () => {
    const { parts, merge } = fixture();
    const observation = Object.values(parts[0]!.targets)[0]!;
    observation.status = "finding-change";
    observation.comparison!.status = "finding-change";
    observation.comparison!.semantic.equal = false;
    observation.comparison!.semantic.liveSha256 = "e".repeat(64);
    observation.comparison!.semantic.changed = [{ id: "changed-row", fields: ["severity"], before: { severity: "Medium" }, after: { severity: "High" } }] as CorpusAdvisoryComparisonReceipt["semantic"]["changed"];
    const merged = merge();
    expect(merged.populationComplete).toBe(true);
    expect(merged.targets[observation.slug]).toEqual(observation);
  });
});
