import { describe, expect, it } from "vitest";
import { unnamedRecallMisses } from "./calibration-verdict.js";
import { CORPUS, fatalRecallMisses, type MatrixRow } from "./scan/calibration.js";

const row = (id: string, expectedTier?: MatrixRow["expectedTier"]): MatrixRow => ({
  id,
  kind: "positive",
  cls: "seeded",
  expectedTier,
  highFlagged: false,
  reviewFlagged: false,
  pass: false,
  detail: "seeded",
  severityMismatch: false,
  notScored: false,
});

describe("unnamedRecallMisses — the #1765 catch-all", () => {
  it("is empty when every fatal miss belongs to a printed subset", () => {
    const high = [row("P-A", "high")];
    const review = [row("P-B", "review")];
    expect(unnamedRecallMisses([...high, ...review], [high, review])).toEqual([]);
  });

  it("names a fatal miss that no tier-specific branch would print", () => {
    const high = [row("P-A", "high")];
    const untiered = row("P-UNTIERED");
    const live = row("P-LIVE", "local");
    expect(unnamedRecallMisses([...high, untiered, live], [high]).map((r) => r.id)).toEqual(["P-UNTIERED", "P-LIVE"]);
  });

  // The verdict's own list is what it must be fed. Passing the printed subsets by value rather than
  // by predicate is what keeps this from drifting: a new branch above it appears in `named`.
  it("takes the same list the verdict gates on, so a real corpus row round-trips", () => {
    const scored = fatalRecallMisses(
      CORPUS.filter((e) => e.id === "P-RLS-DISABLED").map((e) => ({ ...row(e.id, "local"), cls: e.cls })),
    );
    expect(scored).toHaveLength(1);
    expect(unnamedRecallMisses(scored, [[], []]).map((r) => r.id)).toEqual(["P-RLS-DISABLED"]);
  });
});
