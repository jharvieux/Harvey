// #1677 — the `expectedTier: "none"` graduation guard, scored by neighbour taxonomy. The live gate
// (src/cli/validate-calibration.ts) runs the same function against a real scan and carries its own
// two negative controls; this is the binary-free venue, so the contract rides inside `pnpm verify`.

import { describe, expect, it } from "vitest";
import { misplacedNeighbourDeclarations, scoreGraduationGuards } from "./graduation.js";
import { CORPUS, type CorpusEntry } from "../calibration.js";
import type { Finding } from "../../findings.js";

const finding = (taxonomy: string, location: string): Finding => ({
  id: `F-${taxonomy}-${location}`,
  status: "Open",
  category: "Security",
  title: taxonomy,
  severity: "Medium",
  confidence: "Review",
  precisionTier: "review",
  taxonomy,
  location,
  evidence: "synthetic",
  impact: "n/a",
  fix: "n/a",
  value: 1,
  ease: 1,
  safety: 1,
});

const noneRow: CorpusEntry = {
  id: "P-TEST-NONE",
  kind: "positive",
  cls: "test",
  location: "pages/api/shared.js",
  // Deliberately narrow, the shape #1677 exists to stop being load-bearing: the guard must fire on a
  // graduation whose wording this key does not anticipate.
  match: ["replay"],
  expectedTier: "none",
  neighbourTaxonomies: ["neighbour-class"],
  note: "test",
};

describe("#1677 graduation guard", () => {
  it("holds when only the declared neighbour fires", () => {
    const rows = scoreGraduationGuards([noneRow], [finding("neighbour-class", "pages/api/shared.js:3")]);
    expect(rows[0]?.pass).toBe(true);
    expect(rows[0]?.confirmed).toEqual(["neighbour-class"]);
  });

  it("fires on an undeclared taxonomy that the row's own `match` key would have missed", () => {
    const graduated = finding("some-new-rule-nobody-anticipated", "pages/api/shared.js:9");
    const rows = scoreGraduationGuards([noneRow], [finding("neighbour-class", "pages/api/shared.js:3"), graduated]);
    expect(rows[0]?.pass).toBe(false);
    expect(rows[0]?.graduated).toEqual(["some-new-rule-nobody-anticipated"]);
    // The point of the re-scope: nothing in this finding matches `["replay"]`, so the narrow-key
    // guard in scoreEntry's `none` branch stays silent on exactly this case.
    expect(graduated.taxonomy.includes("replay")).toBe(false);
  });

  it("fires on a declared neighbour that has stopped firing — a decayed measurement", () => {
    const rows = scoreGraduationGuards([noneRow], []);
    expect(rows[0]?.pass).toBe(false);
    expect(rows[0]?.stale).toEqual(["neighbour-class"]);
  });

  it("without the declaration, the neighbour alone reads as a graduation", () => {
    const rows = scoreGraduationGuards([{ ...noneRow, neighbourTaxonomies: undefined }], [finding("neighbour-class", "pages/api/shared.js:3")]);
    expect(rows[0]?.pass).toBe(false);
    expect(rows[0]?.graduated).toEqual(["neighbour-class"]);
  });

  it("scores only `none` positives", () => {
    const rows = scoreGraduationGuards([{ ...noneRow, expectedTier: "review" }, { ...noneRow, id: "N-X", kind: "negative" }], []);
    expect(rows).toEqual([]);
  });

  it("rejects a neighbour declaration on a row that has no graduation guard to scope", () => {
    expect(misplacedNeighbourDeclarations(CORPUS)).toEqual([]);
    expect(misplacedNeighbourDeclarations([{ ...noneRow, expectedTier: "review" }]).map((e) => e.id)).toEqual(["P-TEST-NONE"]);
  });

  it("every `none` row in the real corpus is covered by the guard", () => {
    const noneRows = CORPUS.filter((e) => e.kind === "positive" && e.expectedTier === "none");
    expect(noneRows.length).toBeGreaterThan(0);
    expect(scoreGraduationGuards(CORPUS, []).map((r) => r.id).sort()).toEqual(noneRows.map((e) => e.id).sort());
  });
});
