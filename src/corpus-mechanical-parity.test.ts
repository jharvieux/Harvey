import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Finding } from "./findings.js";
import {
  buildCorpusMechanicalParityBaseline,
  compareCorpusMechanicalParity,
  formatCorpusMechanicalParityDifference,
  mechanicalFindingRecords,
  serializeCorpusMechanicalParityBaseline,
  type CorpusMechanicalParityBaseline,
} from "./corpus-mechanical-parity.js";

const finding = (id: string): Finding => ({ id, title: id, severity: "Low", confidence: "Likely", category: "test", taxonomy: "test", location: `${id}.ts:1`, status: "Open", evidence: "fixture", impact: "fixture", fix: "fixture", value: 1, ease: 1, safety: 1, mechanical: true });
const provenance = { baseCommit: "base", baseRun: 1, migrationHead: "head", migrationRun: 2 };
const baseline = (rows: Finding[]): CorpusMechanicalParityBaseline => buildCorpusMechanicalParityBaseline(provenance, { target: rows });

describe("ordered pinned-corpus mechanical parity", () => {
  it("gates the required aggregate job and retains producer records in its operator artifact", () => {
    const workflow = readFileSync(fileURLToPath(new URL("../.github/workflows/corpus-drift.yml", import.meta.url)), "utf8");
    expect(workflow).toContain("detectors: (map(.detectors // {}) | add)");
    expect(workflow).toContain("package_json_file: source/package.json");
    expect(workflow).toContain("pnpm validate:mechanical-corpus-parity --current ../corpus-drift.json");
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
    expect(fixture.schema).toBe(2);
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
