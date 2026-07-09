import { describe, expect, it } from "vitest";
import {
  duplicationSummary,
  jscpdToFindings,
  knipToFindings,
  type JscpdReport,
  type KnipReport,
} from "./quality-scan.js";

// Fixtures shaped from real `jscpd --reporters json` / `knip --reporter json`
// output (captured against a throwaway two-file clone and a dead-export fixture),
// not hand-guessed — jscpd's json reporter emits duplicates out of size order.
const jscpdReport: JscpdReport = {
  statistics: { total: { percentage: 12.5, duplicatedLines: 40, lines: 320 } },
  duplicates: [
    {
      format: "typescript",
      lines: 11,
      tokens: 113,
      fragment: "function calculateTotal(items) {\n  let total = 0;\n  return total;\n}",
      firstFile: { name: "src/a.ts", start: 1, end: 11 },
      secondFile: { name: "src/b.ts", start: 1, end: 11 },
    },
    {
      format: "typescript",
      lines: 60,
      tokens: 900,
      fragment: "x".repeat(300),
      firstFile: { name: "src/big1.ts", start: 5, end: 65 },
      secondFile: { name: "src/big2.ts", start: 10, end: 70 },
    },
  ],
};

describe("jscpdToFindings", () => {
  it("sorts worst clone clusters first regardless of report order", () => {
    const findings = jscpdToFindings(jscpdReport);
    expect(findings[0]?.location).toContain("big1.ts");
    expect(findings[1]?.location).toContain("a.ts");
  });

  it("scales severity with duplicated line count", () => {
    const [big, small] = jscpdToFindings(jscpdReport);
    expect(big?.severity).toBe("Medium"); // 60 lines >= 50
    expect(small?.severity).toBe("Info"); // 11 lines < 15
  });

  it("truncates long fragments and reports exact line/token counts in impact", () => {
    const [big] = jscpdToFindings(jscpdReport);
    expect(big?.evidence.length).toBeLessThanOrEqual(241);
    expect(big?.impact).toBe("60 duplicated lines (900 tokens) — a fix in one copy is a fix missed in the other.");
  });

  it("assigns unique sequential M4 ids", () => {
    const findings = jscpdToFindings(jscpdReport);
    expect(findings.map((f) => f.id)).toEqual(["M4-01", "M4-02"]);
  });

  it("tags every clone at the high precision tier (issue #72 calibration)", () => {
    const findings = jscpdToFindings(jscpdReport);
    expect(findings.every((f) => f.precisionTier === "high")).toBe(true);
  });
});

describe("duplicationSummary", () => {
  it("passes through the report's overall percentage for the narrative section", () => {
    expect(duplicationSummary(jscpdReport).percentage).toBe(12.5);
  });
});

// Shaped from a real knip fixture: one fully-dead file + one file with two
// unreferenced exports (a function and a const).
const knipReport: KnipReport = {
  files: ["src/dead.ts"],
  issues: [
    {
      file: "src/mixed.ts",
      exports: [{ name: "neverImported", line: 4 }],
      types: [{ name: "UnusedType", line: 9 }],
    },
    {
      file: "src/clean.ts",
      exports: [],
      types: [],
    },
  ],
};

describe("knipToFindings", () => {
  it("reports a fully-unused file with a measured line count when supplied", () => {
    const findings = knipToFindings(knipReport, { "src/dead.ts": 12 });
    const fileFinding = findings.find((f) => f.location === "src/dead.ts");
    expect(fileFinding?.impact).toBe("Entire file (12 lines) is unreferenced.");
  });

  it("never fabricates a line count when none was measured", () => {
    const findings = knipToFindings(knipReport);
    const fileFinding = findings.find((f) => f.location === "src/dead.ts");
    expect(fileFinding?.impact).toBe("Entire file is unreferenced.");
  });

  it("groups unused exports and types per file, and skips files with none", () => {
    const findings = knipToFindings(knipReport);
    const mixed = findings.find((f) => f.location === "src/mixed.ts");
    expect(mixed?.evidence).toContain("neverImported");
    expect(mixed?.evidence).toContain("UnusedType");
    expect(findings.find((f) => f.location === "src/clean.ts")).toBeUndefined();
  });

  it("does not claim a precise line reduction for partial dead exports", () => {
    const findings = knipToFindings(knipReport);
    const mixed = findings.find((f) => f.location === "src/mixed.ts");
    expect(mixed?.impact).toContain("manual look");
  });

  it("tags every finding at the high precision tier (issue #72 calibration)", () => {
    const findings = knipToFindings(knipReport);
    expect(findings.every((f) => f.precisionTier === "high")).toBe(true);
  });
});
