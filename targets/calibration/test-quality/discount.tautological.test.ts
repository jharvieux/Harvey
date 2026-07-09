import { describe, expect, it } from "vitest";
import { applyDiscount } from "./discount.js";

// M8-P-TAUTOLOGICAL (#72 §M8) — planted WEAK test: a single happy-path assertion that never
// exercises the non-member branch, the negative-total guard, or the <100 member boundary.
// "If you deleted or inverted the logic it covers, would this test go red?" (quality-extras.txt
// M8 litmus test) — no, for every line but the one it happens to hit. Left deliberately weak so
// Stryker's mutation run leaves surviving/no-coverage mutants on this file (the false-confidence
// signal src/mutation-scan.ts is meant to surface).
describe("applyDiscount (weak)", () => {
  it("gives members a discount on a big order", () => {
    expect(applyDiscount(100, true)).toBe(80);
  });
});
