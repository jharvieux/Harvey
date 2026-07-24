// #881 — the metric arithmetic the calibration gates report. Held to the properties that make
// Youden worth adding: it must punish a detector that fires on everything, which raw recall does not.

import { describe, expect, it } from "vitest";
import { detectionMetrics, formatMetrics } from "./detection-metrics.js";

describe("detectionMetrics", () => {
  it("scores a perfect corpus run at 1 across the board", () => {
    const m = detectionMetrics({ tp: 10, fn: 0, fp: 0, tn: 10 });
    expect(m.precision).toBe(1);
    expect(m.recall).toBe(1);
    expect(m.f1).toBe(1);
    expect(m.fpr).toBe(0);
    expect(m.youden).toBe(1);
  });

  it("gives a fires-on-everything detector perfect recall but a Youden of 0 — the reason to report it", () => {
    const m = detectionMetrics({ tp: 10, fn: 0, fp: 10, tn: 0 });
    expect(m.recall).toBe(1);
    expect(m.youden).toBe(0);
    expect(m.precision).toBe(0.5);
  });

  it("reports zero, not NaN, when a side of the corpus is empty", () => {
    const m = detectionMetrics({ tp: 0, fn: 0, fp: 0, tn: 0 });
    expect(m.precision).toBe(0);
    expect(m.recall).toBe(0);
    expect(m.f1).toBe(0);
    expect(m.youden).toBe(0);
  });

  it("carries the counts alongside the rates, so a rate never prints without its denominator", () => {
    const line = formatMetrics(detectionMetrics({ tp: 3, fn: 1, fp: 1, tn: 5 }));
    expect(line).toContain("TP 3 FN 1 FP 1 TN 5");
    expect(line).toContain("recall 75.0%");
    expect(line).toContain("Youden's J 0.583");
  });
});
