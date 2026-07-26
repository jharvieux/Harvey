// #1099: report-template/render.mjs (546 lines assembling the client-facing HTML — cover, grid,
// findings pages) had no test at all. sections.mjs and rollup.mjs already have one each
// (report-sections.test.ts, report-rollup.test.ts) — this is render.mjs's, covering the five
// functions with no other home: completenessBanner, coverageSection, limitationsSection,
// healthGauge, severityDonut. Importing render.mjs used to also RUN it (argv parsing, launching a
// real Chromium) as a side effect — render.mjs now guards that behind `isMain` so the exports can
// be imported here without driving the CLI.

import { describe, expect, it } from "vitest";
import { completenessBanner, coverageSection, healthGauge, limitationsSection, severityDonut } from "../report-template/render.mjs";
import type { CoverageRow, ReportMeta } from "./findings.js";

const meta = (over: Partial<ReportMeta> = {}): ReportMeta => ({
  client: "Acme", subtitle: "Q3 audit", date: "2026-07-25", commit: "abc1234", auditor: "Harvey",
  confidential: true, overallHealth: 7, tenantIsolation: "Verified", authModel: "Supabase",
  headline: "Partial audit", scope: "the app repo at abc1234", methodology: "ten modules",
  outOfScope: "infrastructure", ...over,
});

const row = (over: Partial<CoverageRow> = {}): CoverageRow => ({ module: "M1", name: "Multi-tenant security", status: "ran", ...over });

describe("healthGauge", () => {
  it("shows the numeric score and colors green at/above 7", () => {
    const svg = healthGauge(8);
    expect(svg).toContain(">8<");
    expect(svg).toContain("#15803d");
  });

  it("colors amber for a mid score and red below 4", () => {
    expect(healthGauge(5)).toContain("#ca8a04");
    expect(healthGauge(2)).toContain("#b3261e");
  });
});

describe("severityDonut", () => {
  it("totals only the severities present, ignoring zero-count entries", () => {
    const svg = severityDonut({ Critical: 2, High: 0, Medium: 1 });
    expect(svg).toContain(">3<"); // 2 + 1, not 3 entries
  });

  it("does not throw (divide-by-zero) when every count is zero or the map is empty", () => {
    expect(() => severityDonut({})).not.toThrow();
    expect(() => severityDonut({ Critical: 0 })).not.toThrow();
  });
});

describe("completenessBanner (#349)", () => {
  it("renders nothing when there is no coverage ledger (a hand-authored legacy doc)", () => {
    expect(completenessBanner(undefined)).toBe("");
    expect(completenessBanner([])).toBe("");
  });

  it("declares a full audit when every module ran", () => {
    const html = completenessBanner([row({ module: "M1" }), row({ module: "M2" })]);
    expect(html).toContain("Full 2-module audit");
    expect(html).toContain("all modules assessed");
  });

  it("names every module that did not fully run, and never silently drops one (#345)", () => {
    const html = completenessBanner([
      row({ module: "M1", status: "ran" }),
      row({ module: "M2", status: "requires-live-run" }),
      row({ module: "M3", status: "partial" }),
    ]);
    expect(html).toContain("1/3 modules fully assessed");
    expect(html).toContain("M2 (requires-live-run)");
    expect(html).toContain("M3 (partial)");
  });
});

describe("coverageSection (#349)", () => {
  it("badges a fully-assessed module distinctly from one that never ran, and states the reason", () => {
    const html = coverageSection(
      [row({ module: "M1", status: "ran", detail: "mechanical + connected" }), row({ module: "M2", status: "requires-live-run", reason: "no live target provided" })],
      meta(),
    );
    expect(html).toContain("Assessed");
    expect(html).toContain("mechanical + connected");
    expect(html).toContain("Not assessed");
    expect(html).toContain("no live target provided");
    expect(html).toContain("this is not a clean result"); // #349: a not-assessed row must not read as clean
  });

  it("badges a blocked sub-step distinctly from an ordinary partial (#682)", () => {
    const html = coverageSection([row({ module: "M2", status: "partial", subStatus: "sub-step-blocked", reason: "seed step blocked" })], meta());
    expect(html).toContain("Partial — sub-step blocked");
  });

  it("names the per-instance app/DB on a monorepo row instead of folding it into the module headline (#506)", () => {
    const html = coverageSection([row({ module: "M1", instance: "apps/web" })], meta());
    expect(html).toContain("apps/web");
  });

  it("carries the report's outOfScope note", () => {
    const html = coverageSection([row()], meta({ outOfScope: "infrastructure code (Dockerfiles, Terraform)" }));
    expect(html).toContain("infrastructure code (Dockerfiles, Terraform)");
  });
});

describe("limitationsSection (#822)", () => {
  it("renders only the modules present in the coverage ledger, not the full ten", () => {
    const html = limitationsSection([row({ module: "M1" }), row({ module: "M7" })]);
    expect(html).toContain("Multi-tenant security");
    expect(html).toContain("Performance");
    expect(html).not.toContain("Data classification"); // M10's name — not in this ledger
  });

  it("states what a module's result does and does not prove, independent of whether it ran", () => {
    const html = limitationsSection([row({ module: "M8" })]);
    expect(html).toContain("scoped run is not a whole-repo coverage claim");
  });
});
