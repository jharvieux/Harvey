// The `pnpm verify` gate for the M7/M8 heuristic precision corpus (#823): every planted class
// fires, every catalogued FP lookalike stays silent, and both modules report 100% corpus
// precision AND recall. The detectors are pure TS, so unlike the M1 gate this runs binary-less
// in CI. Numbers here are corpus numbers — see heuristic-precision.ts's header for what that
// does and does not claim.

import { describe, expect, it } from "vitest";
import { HEURISTIC_CORPUS, measureHeuristicPrecision } from "./heuristic-precision.js";

const matrix = measureHeuristicPrecision();

describe("M7/M8 heuristic precision gate (#823)", () => {
  it("catches every planted positive", () => {
    const missed = matrix.rows.filter((r) => r.kind === "positive" && !r.pass).map((r) => `${r.id}: ${r.detail}`);
    expect(missed).toEqual([]);
  });

  it("stays silent on every benign negative (the triage FP catalog)", () => {
    const fired = matrix.rows.filter((r) => r.kind === "negative" && !r.pass).map((r) => `${r.id}: ${r.detail}`);
    expect(fired).toEqual([]);
  });

  it("measures both M7 and M8 at 100% corpus precision and recall", () => {
    expect(matrix.modules.map((m) => m.module).sort()).toEqual(["M7", "M8"]);
    for (const m of matrix.modules) {
      expect.soft(m.precision, `${m.module} precision`).toBe(1);
      expect.soft(m.recall, `${m.module} recall`).toBe(1);
    }
    expect(matrix.ok).toBe(true);
  });
});

describe("corpus hygiene", () => {
  it("entry ids are unique", () => {
    const ids = HEURISTIC_CORPUS.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every taxonomy-scoped negative has a sibling positive of the same taxonomy — a typo'd taxonomy must not pass vacuously", () => {
    const positiveTaxonomies = new Set(HEURISTIC_CORPUS.filter((e) => e.kind === "positive").map((e) => e.taxonomy));
    const orphans = HEURISTIC_CORPUS.filter((e) => e.kind === "negative" && e.taxonomy !== undefined && !positiveTaxonomies.has(e.taxonomy)).map((e) => e.id);
    expect(orphans).toEqual([]);
  });

  it("every positive names its taxonomy — an any-taxonomy positive would pass on ANY class firing", () => {
    expect(HEURISTIC_CORPUS.filter((e) => e.kind === "positive" && e.taxonomy === undefined).map((e) => e.id)).toEqual([]);
  });
});
