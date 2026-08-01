// The `pnpm verify` half of the M6 indicator corpus (#1371). detectHandrolledFindings is pure TS,
// so the whole corpus scores here with no mechanical binaries — the live gate
// (cli/validate-calibration.ts) runs the same scorer against the same fixtures.
//
// What these tests are FOR is the #1428 defect, not the detector: handrolled.test.ts already gates
// the detector class-by-class. What had never been established is that an M6 CORPUS ROW can fail.
// So the negative controls below matter more than the pass: each one forces the exact silent shape
// the issue exists to prevent and asserts the scorer goes red.

import { describe, expect, it } from "vitest";
import { declaredIndicatorClasses, scoreM6IndicatorCorpus } from "./m6-indicator-corpus.js";
import { m6HandrolledEntries } from "./calibration/m6-handrolled.entries.js";
import { CORPUS, corpusMatchKeyedRows, moduleCensus, parityVerdict, selfMatchingKeys } from "./calibration.js";
import type { CorpusEntry } from "./calibration/types.js";

describe("M6 indicator corpus (#1371)", () => {
  const result = scoreM6IndicatorCorpus();

  it("catches every planted indicator positive and clears every boundary negative", () => {
    const failures = result.rows.filter((r) => !r.pass).map((r) => `${r.id}: ${r.detail}`);
    expect(failures).toEqual([]);
    expect(result.positivesCaught).toBe(result.positivesTotal);
    expect(result.negativesCleared).toBe(result.negativesTotal);
  });

  it("covers every indicator class handrolled.ts declares", () => {
    // Derived from the source, the same way `pnpm detector-census` derives M6's count — so a new
    // detector landing without a fixture pair fails here instead of quietly widening the module.
    expect(result.uncovered).toEqual([]);
    expect(result.classesDeclared).toBeGreaterThan(0);
    expect(new Set(m6HandrolledEntries.filter((e) => e.kind === "positive").map((e) => e.cls))).toEqual(
      // Plus the WHY-suppression pair, which is makeIndicator's shared branch rather than a class.
      new Set([...declaredIndicatorClasses(), "WHY-comment suppression: an un-narrated shape still fires"]),
    );
  });

  it("keeps every indicator non-grading (Info) and off the free count (review tier)", () => {
    // The free/paid split of #267 lives in the severity and the tier as much as in the wording:
    // a high-tier M6 finding would enter the client-facing free count, and a graded severity would
    // turn a hedged indicator into a verdict.
    expect(result.severityMismatches).toEqual([]);
    for (const r of result.rows.filter((r) => r.kind === "positive")) {
      expect(r.caughtTier, r.id).toBe("review");
      expect(r.highFlagged, r.id).toBe(false);
    }
  });

  it("gives every positive a match key that is not vacuous against its own fixture path (#1355/#1388)", () => {
    for (const e of m6HandrolledEntries.filter((e) => e.kind === "positive")) {
      expect(e.match?.length, `${e.id} needs a narrow match key — without one it accepts any finding planted at its location`).toBeGreaterThan(0);
    }
    expect(selfMatchingKeys(corpusMatchKeyedRows(m6HandrolledEntries))).toEqual([]);
  });

  // --- Negative controls: the corpus must be able to FAIL (#1428) ---

  it("FAILS when the class under test stops firing but a sibling class still does", () => {
    // The masking shape (#1062) reached through a corpus. The cookie pair is the real instance: the
    // parse class's benign negative writes a cookie, so a `match`-less positive on cookie/positive
    // would be satisfied by the serialization class alone. Scoring the entry against ONLY the
    // sibling's findings must miss.
    const parse = m6HandrolledEntries.find((e) => e.id === "M6-P-COOKIE");
    expect(parse).toBeDefined();
    const sibling = scoreM6IndicatorCorpus([{ ...parse!, cls: "cookie serialization", match: ["Indicator: cookie serialization"] }]);
    expect(sibling.positivesCaught).toBe(0);
    expect(sibling.ok).toBe(false);
  });

  it("FAILS when a benign negative draws an unrecorded indicator (#1344)", () => {
    // Drop the measured cross-class hit off the cookie negative's reviewTierHits and the row must
    // go red — before #1344 a review-tier hit on a planted negative scored "cleared".
    const neg = m6HandrolledEntries.find((e) => e.id === "M6-N-COOKIE");
    expect(neg?.reviewTierHits).toEqual(["M6 — Indicator: cookie serialization"]);
    const stripped: CorpusEntry = { ...neg!, reviewTierHits: undefined };
    const scored = scoreM6IndicatorCorpus([stripped]);
    expect(scored.negativesCleared).toBe(0);
    expect(scored.rows[0]?.detail).toContain("REVIEW-TIER REGRESSION");
  });

  it("FAILS loud rather than scoring zero when a fixture directory was never read", () => {
    // CLAUDE.md rule (3): an unread fixture reports zero findings exactly like one that was scanned
    // and cleared — and for a negative that reads as a pass. The loader throws instead.
    const ghost: CorpusEntry = { ...m6HandrolledEntries[0]!, location: "m6-corpus/json-equal/does-not-exist" };
    expect(() => scoreM6IndicatorCorpus([ghost])).toThrow();
  });

  it("FAILS when a declared indicator class has no positive row", () => {
    const withoutOne = m6HandrolledEntries.filter((e) => e.id !== "M6-P-JSON-EQUAL");
    const scored = scoreM6IndicatorCorpus(withoutOne);
    expect(scored.uncovered).toEqual(["JSON deep-equal"]);
    expect(scored.ok).toBe(false);
  });
});

describe("M6 joins the census and the parity minimum for real (#341/#427/#1314)", () => {
  it("counts M6 in the per-module census on its own fixtures", () => {
    const m6 = moduleCensus(CORPUS).find((c) => c.module === "M6");
    expect(m6).toBeDefined();
    expect(m6!.positivesStatic).toBe(m6HandrolledEntries.filter((e) => e.kind === "positive").length);
    expect(m6!.negatives).toBe(m6HandrolledEntries.filter((e) => e.kind === "negative").length);
  });

  it("retires M6's parity exemption — neither thin, nor exempt, nor stale", () => {
    // #1314 built the `stale` check for exactly this transition: an exemption asserts its module
    // has no fixtures to stand on, and M6 now has 73 of them.
    const parity = parityVerdict(CORPUS);
    expect(parity.thin.map((t) => t.module)).not.toContain("M6");
    expect(parity.exempt.map((e) => e.module)).not.toContain("M6");
    expect(parity.stale).toEqual([]);
  });
});
