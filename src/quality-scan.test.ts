import { describe, expect, it } from "vitest";
import {
  duplicationSummary,
  JSCPD_IGNORE_GLOBS,
  jscpdToFindings,
  knipToFindings,
  knipUnavailableFinding,
  type JscpdReport,
  type KnipReport,
} from "./quality-scan.js";

// Base two entries shaped from real `jscpd --reporters json` output (captured against a
// throwaway two-file clone) — jscpd's json reporter emits duplicates out of size order. The
// self-clone and tiny-header entries below are hand-built negative fixtures standing in for the
// #232 FP shapes (icon-table self-repetition, shared import headers), not captured tool output.
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
    // #232: same file both sides — jscpd flagging icons.tsx's own repeated SVG path literals
    // against itself, not cross-file logic duplication a client could extract.
    {
      format: "typescript",
      lines: 40,
      tokens: 500,
      fragment: "<path d=\"M10 10L20 20\" />".repeat(10),
      firstFile: { name: "src/icons.tsx", start: 1, end: 40 },
      secondFile: { name: "src/icons.tsx", start: 50, end: 90 },
    },
    // #232: a 6-line shared import header — real cross-file overlap, but under
    // MIN_SIGNIFICANT_LINES, not worth a maintainability finding on its own.
    {
      format: "typescript",
      lines: 6,
      tokens: 80,
      fragment: "import { a } from \"./a\";\nimport { b } from \"./b\";",
      firstFile: { name: "src/c.ts", start: 1, end: 6 },
      secondFile: { name: "src/d.ts", start: 1, end: 6 },
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

  it("excludes same-file clones — self-repeated data, not extractable cross-file logic (#232)", () => {
    const findings = jscpdToFindings(jscpdReport);
    expect(findings.some((f) => f.location.includes("icons.tsx"))).toBe(false);
  });

  it("excludes clusters under the significant-lines gate — e.g. a shared import header (#232)", () => {
    const findings = jscpdToFindings(jscpdReport);
    expect(findings.some((f) => f.location.includes("src/c.ts"))).toBe(false);
  });
});

describe("duplicationSummary", () => {
  it("recomputes the percentage from only significant clusters, excluding self-file and sub-threshold noise (#232)", () => {
    // Only the 11-line and 60-line cross-file clusters count; the self-file (40) and tiny (6)
    // ones are excluded. round(10000 * 71/320) / 100 = 22.19 — jscpd's own percentage formula.
    const summary = duplicationSummary(jscpdReport);
    expect(summary.duplicatedLines).toBe(71);
    expect(summary.percentage).toBe(22.19);
  });
});

describe("JSCPD_IGNORE_GLOBS", () => {
  it("excludes the #232-evidenced generated/vendored/demo FP shapes on top of the standard build dirs", () => {
    expect(JSCPD_IGNORE_GLOBS).toEqual(expect.arrayContaining(["**/node_modules/**", "**/dist/**", "**/.next/**", "**/generated/**"]));
    expect(JSCPD_IGNORE_GLOBS.some((g) => g.includes("database.types.ts"))).toBe(true);
    expect(JSCPD_IGNORE_GLOBS.some((g) => g.includes("vendor"))).toBe(true);
    expect(JSCPD_IGNORE_GLOBS.some((g) => g.includes("demo"))).toBe(true);
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

// #226: dead code in auth/guard/security paths is a stronger signal than routine slop — the
// atc cross-tenant Critical was preceded by exactly this shape (a guard helper written and never
// wired in). Not shaped from a captured knip run; hand-built to cover the elevation paths.
const securityKnipReport: KnipReport = {
  files: ["src/middleware/AuthGuard.tsx", "src/blog/authors.ts"],
  issues: [
    {
      file: "lib/security/guards.ts",
      exports: [{ name: "requireTenantMatch", line: 3 }],
      types: [],
    },
  ],
};

describe("knipToFindings — security-path elevation (#226)", () => {
  it("elevates unused exports in a security-relevant file above routine Low and cross-links the authz review", () => {
    const findings = knipToFindings(securityKnipReport);
    const guard = findings.find((f) => f.location === "lib/security/guards.ts");
    expect(guard?.severity).toBe("Medium");
    expect(guard?.impact).toContain("authz");
    expect(guard?.impact).toContain("M1 authorization review");
  });

  it("elevates a fully-unused file in an auth/guard path, including camelCase/PascalCase names", () => {
    const findings = knipToFindings(securityKnipReport, { "src/middleware/AuthGuard.tsx": 40 });
    const authGuard = findings.find((f) => f.location === "src/middleware/AuthGuard.tsx");
    expect(authGuard?.severity).toBe("Medium");
    expect(authGuard?.impact).toContain("authorization is actually enforced");
  });

  it("does not false-positive elevate a file that merely contains 'auth' as a substring (authors.ts)", () => {
    const findings = knipToFindings(securityKnipReport);
    const authors = findings.find((f) => f.location === "src/blog/authors.ts");
    expect(authors?.severity).toBe("Low");
  });

  it("leaves routine (non-security-path) unused exports at Low, unchanged", () => {
    const findings = knipToFindings(knipReport);
    const mixed = findings.find((f) => f.location === "src/mixed.ts");
    expect(mixed?.severity).toBe("Low");
  });
});

// #223: a knip failure (e.g. target's node_modules isn't installed) must not crash the whole
// quality-scan and drop M4's jscpd findings — the CLI substitutes this disclosure finding instead.
describe("knipUnavailableFinding", () => {
  it("discloses the M5 coverage gap without claiming zero dead code", () => {
    const finding = knipUnavailableFinding("Cannot find module 'vitest/config'");
    expect(finding.severity).toBe("Info");
    expect(finding.confidence).toBe("N/A");
    expect(finding.taxonomy).toContain("M5");
    expect(finding.evidence).toContain("Cannot find module 'vitest/config'");
    expect(finding.impact).toContain("incomplete");
  });
});
