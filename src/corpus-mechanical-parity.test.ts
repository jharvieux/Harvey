import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Finding } from "./findings.js";
import {
  assertCorpusMechanicalExternalState,
  buildCorpusMechanicalParityBaseline,
  compareCorpusMechanicalParity,
  formatCorpusMechanicalParityDifference,
  MECHANICAL_CORPUS_POPULATION,
  mechanicalFindingRecords,
  mechanicalFindingsFromCorpusArtifact,
  mechanicalMigrationReplayArtifact,
  replayParityProvenance,
  serializeCorpusMechanicalParityBaseline,
  type MechanicalMigrationReplayArtifact,
  type CorpusMechanicalParityBaseline,
  type CorpusMechanicalParityProvenance,
} from "./corpus-mechanical-parity.js";

const finding = (id: string): Finding => ({ id, title: id, severity: "Low", confidence: "Likely", category: "test", taxonomy: "test", location: `${id}.ts:1`, status: "Open", evidence: "fixture", impact: "fixture", fix: "fixture", value: 1, ease: 1, safety: 1, mechanical: true });
const digest = "a".repeat(64);
const externalState = { target: { advisorySha256: digest, secretCandidateIdentity: digest, semgrepRegistrySha256: digest, networkFallbacksDisabled: true, bundleScanPinnedOff: true } } as const;
const provenance: CorpusMechanicalParityProvenance = {
  replayContract: "pinned-advisories+frozen-semgrep+network-off+bundle-off",
  harnessSha256: digest,
  targetPinsSha256: digest,
  advisoryManifestSha256: digest,
  semgrepRegistrySha256: digest,
  base: { artifactSha256: digest, engineCommit: "a".repeat(40), orchestrator: "manual", engineAmendmentPaths: [] },
  migration: { artifactSha256: digest, engineCommit: "b".repeat(40), orchestrator: "registry", engineAmendmentPaths: [] },
  externalState,
};
const baseline = (rows: Finding[]): CorpusMechanicalParityBaseline => buildCorpusMechanicalParityBaseline(provenance, { target: rows });
const replay = (orchestrator: "manual" | "registry", rows = [finding("a")]): MechanicalMigrationReplayArtifact => ({
  schema: 1,
  population: MECHANICAL_CORPUS_POPULATION,
  engineCommit: orchestrator === "manual" ? "a".repeat(40) : "b".repeat(40),
  orchestrator,
  engineAmendmentPaths: [],
  harnessSha256: digest,
  targetPinsSha256: digest,
  advisoryManifestSha256: digest,
  semgrepRegistrySha256: digest,
  targetCount: 1,
  targets: ["target"],
  externalState: structuredClone(externalState),
  mechanicalFindings: { target: rows },
});

describe("ordered pinned-corpus mechanical parity", () => {
  it("gates the required aggregate job and retains producer records in its operator artifact", () => {
    const workflow = readFileSync(fileURLToPath(new URL("../.github/workflows/corpus-drift.yml", import.meta.url)), "utf8");
    const runner = readFileSync(fileURLToPath(new URL("./cli/corpus-drift.ts", import.meta.url)), "utf8");
    expect(workflow).toContain("detectors: (map(.detectors // {}) | add)");
    expect(workflow).toContain("mechanicalFindings: (map(.mechanicalFindings // {}) | add)");
    expect(workflow).toContain("mechanicalExternalState: (map(.mechanicalExternalState // {}) | add)");
    expect(workflow).toContain("package_json_file: source/package.json");
    expect(workflow).toContain("pnpm validate:mechanical-corpus-parity --current ../corpus-drift.json");
    expect(runner).toContain("mechanicalFindingsBySlug[target.slug] = mechanicalRun.findings");
    expect(runner).toContain("mechanicalPopulation: MECHANICAL_CORPUS_POPULATION");
    expect(runner).toContain("const snapshot = externalStateMode !== \"live\" ? loadCorpusAdvisorySnapshot(target.slug, target.commit) : undefined");
    expect(runner).toContain("mechanicalExternalState: mechanicalExternalStateBySlug");
  });

  it("refuses the unrelated scorecard population and detects replacement mechanical rows", () => {
    expect(() => mechanicalFindingsFromCorpusArtifact({
      mechanicalPopulation: MECHANICAL_CORPUS_POPULATION,
      mechanicalFindings: undefined,
    }, "fixture.json")).toThrow("no runMechanicalScanDetailed findings population");
    const unrelated = mechanicalFindingsFromCorpusArtifact({
      mechanicalPopulation: MECHANICAL_CORPUS_POPULATION,
      mechanicalFindings: { target: [{ ...finding("unrelated"), mechanical: false }] },
    }, "fixture.json");
    expect(compareCorpusMechanicalParity(baseline([finding("registry-row")]), unrelated).map((difference) => difference.kind)).toEqual(["removed", "added"]);
  });

  it("reports every added, removed, moved, and modified row using only client-safe digests", () => {
    const before = [finding("a"), finding("b"), finding("c")];
    const changed = { ...finding("b"), evidence: "changed" };
    const differences = compareCorpusMechanicalParity(baseline(before), { target: [changed, finding("d"), finding("a")] });
    expect(differences.map((difference) => difference.kind)).toEqual(["moved", "modified", "moved", "removed", "added"]);
    for (const difference of differences) {
      const output = formatCorpusMechanicalParityDifference(difference);
      expect(output).toMatch(/^target (?:ADDED|REMOVED|MOVED|MODIFIED) identity=sha256:[a-f0-9]{64} /);
      expect(output).not.toContain(".ts:1");
    }
  });

  it("hashes sensitive evidence without collapsing rows that differ only in that evidence", () => {
    const sensitiveBefore = ["pass", "word=", "first-sensitive-value"].join("");
    const sensitiveAfter = ["pass", "word=", "second-sensitive-value"].join("");
    const prior = { ...finding("sensitive"), evidence: sensitiveBefore };
    const current = { ...prior, evidence: sensitiveAfter };
    const beforeRecord = mechanicalFindingRecords("target", [prior])[0]!;
    const afterRecord = mechanicalFindingRecords("target", [current])[0]!;
    expect(afterRecord.identityDigest).toBe(beforeRecord.identityDigest);
    expect(afterRecord.contentDigest).not.toBe(beforeRecord.contentDigest);
    const differences = compareCorpusMechanicalParity(baseline([prior]), { target: [current] });
    expect(differences.map((difference) => difference.kind)).toEqual(["modified"]);
    const storedAndPrinted = `${serializeCorpusMechanicalParityBaseline(baseline([prior]))}\n${differences.map(formatCorpusMechanicalParityDifference).join("\n")}`;
    expect(storedAndPrinted).not.toContain(sensitiveBefore);
    expect(storedAndPrinted).not.toContain(sensitiveAfter);
  });

  it("stores only digest-shaped row values in the committed fixture", () => {
    const fixtureText = readFileSync(fileURLToPath(new URL("./scan/__fixtures__/mechanical-registry-corpus-parity.json", import.meta.url)), "utf8");
    const fixture = JSON.parse(fixtureText) as CorpusMechanicalParityBaseline;
    expect(fixture.schema).toBe(4);
    expect(fixture.population).toBe(MECHANICAL_CORPUS_POPULATION);
    expect(fixtureText).not.toContain('"identity":');
    for (const target of Object.values(fixture.targets)) for (const row of target.rows) {
      expect(Object.keys(row).sort()).toEqual(["contentDigest", "identityDigest", "orderedDigest", "ordinal"]);
      expect([row.identityDigest, row.contentDigest, row.orderedDigest]).toEqual([
        expect.stringMatching(/^[a-f0-9]{64}$/),
        expect.stringMatching(/^[a-f0-9]{64}$/),
        expect.stringMatching(/^[a-f0-9]{64}$/),
      ]);
    }
  });

  it("proves one pinned manual-to-registry replay before baseline construction", () => {
    const base = mechanicalMigrationReplayArtifact(replay("manual"), "base.json", ["target"]);
    const migration = mechanicalMigrationReplayArtifact(replay("registry"), "migration.json", ["target"]);
    const replayProvenance = replayParityProvenance(base, migration, { base: digest, migration: "b".repeat(64) });
    expect(replayProvenance.base.orchestrator).toBe("manual");
    expect(replayProvenance.migration.orchestrator).toBe("registry");
    expect(replayProvenance.externalState.target?.networkFallbacksDisabled).toBe(true);
  });

  it("refuses fallback state, incomplete populations, and reversed deletion timing", () => {
    const fallback = replay("manual") as unknown as { externalState: Record<string, { networkFallbacksDisabled: boolean }> };
    fallback.externalState.target!.networkFallbacksDisabled = false;
    expect(() => mechanicalMigrationReplayArtifact(fallback, "fallback.json", ["target"])).toThrow("did not disable every live/network fallback");
    expect(() => mechanicalMigrationReplayArtifact(replay("manual"), "short.json", ["target", "missing"])).toThrow("target population differs");
    const manual = mechanicalMigrationReplayArtifact(replay("manual"), "manual.json", ["target"]);
    expect(() => replayParityProvenance(manual, manual, { base: digest, migration: digest })).toThrow("expected registry");
  });

  it("gates all-target snapshot identity while permitting the scheduled live-verify lane", () => {
    const expected = baseline([finding("a")]);
    const snapshot = { target: { mode: "snapshot", advisoryDigest: digest, networkFallbacksDisabled: true, secretCandidateIdentity: digest } };
    expect(() => assertCorpusMechanicalExternalState(expected, snapshot, "scorecard.json")).not.toThrow();
    expect(() => assertCorpusMechanicalExternalState(expected, { target: { ...snapshot.target, networkFallbacksDisabled: false } }, "scorecard.json")).toThrow("permitted a live/network fallback");
    expect(() => assertCorpusMechanicalExternalState(expected, { target: { mode: "live" } }, "scorecard.json")).toThrow("without snapshot or live-verify");
    expect(() => assertCorpusMechanicalExternalState(expected, { target: { mode: "live-verify" } }, "scorecard.json")).not.toThrow();
  });

  it("regenerates byte-for-byte deterministically regardless of target object insertion order", () => {
    const first = buildCorpusMechanicalParityBaseline(provenance, { zed: [finding("z")], alpha: [finding("a")] });
    const second = buildCorpusMechanicalParityBaseline(provenance, { alpha: [finding("a")], zed: [finding("z")] });
    expect(serializeCorpusMechanicalParityBaseline(first)).toBe(serializeCorpusMechanicalParityBaseline(second));
  });

  it("canonicalizes ephemeral clone roots without hiding row content changes", () => {
    const prior = { ...finding("a"), evidence: "at /tmp/harvey-carbon-Ab12/file.ts" };
    const current = { ...finding("a"), evidence: "at /tmp/harvey-carbon-Zz99/file.ts" };
    expect(compareCorpusMechanicalParity(baseline([prior]), { target: [current] })).toEqual([]);
  });
});
