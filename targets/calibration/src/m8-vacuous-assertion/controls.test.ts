import { expect, test } from "vitest";

function calibrateDiscount(total: number): number {
  return total >= 100 ? total * 0.9 : total;
}

test("M8VAC-N-JS production-derived observation", () => {
  expect(calibrateDiscount(100)).toBe(90);
});

test("M8VAC-N-JS documented smoke check", () => {
  // Deliberate smoke check: verifies the calibration test runner wiring is active.
  expect(true).toBe(true);
});
