import { describe, expect, it } from "vitest";
import { completenessStatement, deriveCompleteness, headlineClaimsCompletion } from "./audit-completeness.js";
import type { CoverageRow } from "./findings.js";

const ranRow = (module: string): CoverageRow => ({ module, name: module, status: "ran" });
const gapRow = (module: string, status: CoverageRow["status"], reason: string): CoverageRow => ({ module, name: module, status, reason });

describe("deriveCompleteness", () => {
  it("is complete only when every row is ran", () => {
    const rows = [ranRow("M1"), ranRow("M2")];
    expect(deriveCompleteness(rows)).toEqual({ complete: true, ranCount: 2, total: 2, gaps: [] });
  });

  it("reports the ATC incident shape: 8 ran, M2/M3 requires-live-run, M4/M5 partial", () => {
    const rows = [
      ...["M1", "M6", "M7", "M8", "M9", "M10"].map(ranRow),
      gapRow("M2", "requires-live-run", "no local supabase stack"),
      gapRow("M3", "requires-live-run", "vitals not on PATH"),
      gapRow("M4", "partial", "jscpd only, no near-miss pass"),
      gapRow("M5", "partial", "knip needs target npm install"),
    ];
    const v = deriveCompleteness(rows);
    expect(v.complete).toBe(false);
    expect(v.ranCount).toBe(6);
    expect(v.total).toBe(10);
    expect(v.gaps.map((g) => g.module)).toEqual(["M2", "M3", "M4", "M5"]);
  });
});

describe("completenessStatement", () => {
  it("states a full audit plainly", () => {
    expect(completenessStatement([ranRow("M1"), ranRow("M2")])).toBe("Full 2-module audit — all modules assessed.");
  });

  it("names the count and the specific gaps for a partial ledger", () => {
    const stmt = completenessStatement([ranRow("M1"), gapRow("M2", "requires-live-run", "no local supabase stack")]);
    expect(stmt).toContain("Partial audit — 1/2 modules fully assessed.");
    expect(stmt).toContain("M2 (requires-live-run: no local supabase stack)");
  });

  it("does not silently guess completeness for an empty ledger", () => {
    expect(completenessStatement([])).toBe("No coverage ledger — completeness unknown.");
  });
});

describe("headlineClaimsCompletion — the actual ATC incident phrasing (#509)", () => {
  it("catches 'the full audit is done and the deliverable is rendered'", () => {
    expect(headlineClaimsCompletion("The full audit is done and the deliverable is rendered.")).toBe(true);
  });

  it("catches 'audit is complete'", () => {
    expect(headlineClaimsCompletion("Audit is complete — no further action needed.")).toBe(true);
  });

  it("does not flag an honest partial headline", () => {
    expect(headlineClaimsCompletion("Partial audit — M2/M3 require a live run, M4/M5 partial.")).toBe(false);
  });

  it("does not flag unrelated prose", () => {
    expect(headlineClaimsCompletion("Tenant isolation holds — no critical or high security exposure.")).toBe(false);
  });
});
