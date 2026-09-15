import { describe, expect, it } from "vitest";
import { buildHealthScorecard } from "../health-scorecard.js";
import { renderScorecard } from "./quick-scan.js";

describe("quick-scan scorecard consumer", () => {
  it("renders a wholly unsupported M9 scope as unassessed with no earned grade", () => {
    const scorecard = buildHealthScorecard({
      m1: { grade: "B", score: 80, gradedCount: 1, indicatorCount: 0 },
      sources: [{ path: "src/main.ts", text: "export const value = 1;\n" }],
      kloc: 1,
      framework: "astro",
      handrolledClasses: 0,
      handrolledTotal: 0,
    });
    const output = renderScorecard(scorecard).join("\n");
    const m9Line = output.split("\n").find((line) => line.includes("M9") && line.includes("Framework-boundary correctness"));

    expect(m9Line).toContain("NOT ASSESSED by this scan");
    expect(m9Line).not.toMatch(/[A-F] \(\d+\/100\)/);
    expect(output).toContain("Why: M9 not assessed");
    expect(output).toContain("Astro");
    expect(output).toContain("How the grade was composed:");
    expect(output).not.toContain("M9 100");
  });
});
