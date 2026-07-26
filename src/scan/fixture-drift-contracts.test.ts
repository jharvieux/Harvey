import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { JscpdReport, KnipReport } from "../quality-scan.js";
import type { TruffleHogResult } from "./secrets.js";
import type { VitalsReport } from "../hotspot-scan.js";
import type { StrykerReport } from "../mutation-scan.js";
import type { LighthouseResult } from "../lighthouse.js";
import {
  checkJscpdContract,
  checkKnipContract,
  checkTruffleHogContract,
  checkVitalsContract,
  checkStrykerContract,
  checkLighthouseContract,
} from "./fixture-drift-contracts.js";

// These guard the SHAPE the drift check (src/cli/fixture-drift.ts, needs the binaries) enforces on a
// FRESH run: each contract passes its own committed fixture with no violations, and FIRES on the
// specific #1063-class shape drift its parser would be silently killed by. A gate that has never
// fired on a known-bad input is not evidence.

function load<T>(path: string): T {
  const parsed = JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as T & { _note?: string };
  delete parsed._note;
  return parsed;
}

describe("checkJscpdContract", () => {
  const fixture = load<JscpdReport>("./__fixtures__/jscpd/jscpd-4.2.5-report.json");
  it("passes the committed jscpd 4.2.5 fixture", () => {
    expect(checkJscpdContract(fixture)).toEqual([]);
  });
  it("fires when a duplicate's line count is a string, not a number", () => {
    const broken = { ...fixture, duplicates: fixture.duplicates.map((d) => ({ ...d, lines: String(d.lines) as unknown as number })) };
    expect(checkJscpdContract(broken).join("\n")).toContain(".lines is");
  });
  it("fires when duplicates is empty (corpus produced no clones)", () => {
    expect(checkJscpdContract({ ...fixture, duplicates: [] }).join("\n")).toContain("duplicates is empty");
  });
});

describe("checkKnipContract", () => {
  const fixture = load<KnipReport>("./__fixtures__/knip/knip-5.88.1-report.json");
  it("passes the committed knip 5.88.1 fixture", () => {
    expect(checkKnipContract(fixture)).toEqual([]);
  });
  it("fires when an export record is a bare string instead of {name,line}", () => {
    const broken: KnipReport = { ...fixture, issues: fixture.issues.map((i) => ({ ...i, exports: ["neverImported"] as unknown as typeof i.exports })) };
    expect(checkKnipContract(broken).join("\n")).toContain("not a {name:string, line:number} record");
  });
  it("fires when no dead files are reported", () => {
    expect(checkKnipContract({ ...fixture, files: [] }).join("\n")).toContain("files is not a non-empty array");
  });
});

describe("checkTruffleHogContract", () => {
  const rows8 = load<TruffleHogResult[]>("./__fixtures__/trufflehog/trufflehog-3.96.0-git-unverified.json");
  const rows10 = load<TruffleHogResult[]>("./__fixtures__/trufflehog-git-history/trufflehog-3.96.0-git-history.json");
  it("passes both committed trufflehog 3.96.0 fixtures", () => {
    expect(checkTruffleHogContract(rows8)).toEqual([]);
    expect(checkTruffleHogContract(rows10)).toEqual([]);
  });
  it("fires when Verified is a string, not a boolean", () => {
    const broken = rows8.map((r) => ({ ...r, Verified: "false" as unknown as boolean }));
    expect(checkTruffleHogContract(broken).join("\n")).toContain(".Verified is not a boolean");
  });
  it("fires when the #1078 rotation_guide is gone", () => {
    const broken = rows8.map((r) => ({ ...r, ExtraData: {} }));
    expect(checkTruffleHogContract(broken).join("\n")).toContain("rotation_guide");
  });
  it("fires when no record sits at the planted path", () => {
    expect(checkTruffleHogContract([]).join("\n")).toContain("no TruffleHog records");
  });
});

describe("checkVitalsContract", () => {
  const fixture = load<VitalsReport>("../__fixtures__/vitals-report.json");
  it("passes the committed vitals 0.2.0 fixture", () => {
    expect(checkVitalsContract(fixture)).toEqual([]);
  });
  it("fires when risk_score is a string, not a number (the sort key)", () => {
    const broken: VitalsReport = { ...fixture, hotspots: fixture.hotspots.map((h) => ({ ...h, risk_score: String(h.risk_score) as unknown as number })) };
    expect(checkVitalsContract(broken).join("\n")).toContain(".risk_score is");
  });
  it("fires when a top-level array is missing", () => {
    expect(checkVitalsContract({ ...fixture, hotspots: undefined as unknown as VitalsReport["hotspots"] }).join("\n")).toContain("hotspots is not an array");
  });
});

describe("checkStrykerContract", () => {
  const fixture = load<StrykerReport>("./__fixtures__/stryker/stryker-9.6.1-m8-calibration.json");
  it("passes the committed Stryker 9.6.1 fixture", () => {
    expect(checkStrykerContract(fixture)).toEqual([]);
  });
  it("fires when a mutant status is not a string", () => {
    const files = Object.fromEntries(
      Object.entries(fixture.files).map(([k, f]) => [k, { ...f, mutants: f.mutants.map((m) => ({ ...m, status: 1 as unknown as typeof m.status })) }]),
    );
    expect(checkStrykerContract({ ...fixture, files }).join("\n")).toContain(".status is");
  });
  it("fires when files is empty", () => {
    expect(checkStrykerContract({ ...fixture, files: {} }).join("\n")).toContain("files is empty");
  });
});

describe("checkLighthouseContract", () => {
  const fixture = load<LighthouseResult>("../__fixtures__/lighthouse-report.json");
  it("passes the committed Lighthouse 13.4.0 fixture", () => {
    expect(checkLighthouseContract(fixture)).toEqual([]);
  });
  it("fires when a numeric audit's numericValue is a string (the #1063 shape)", () => {
    const broken: LighthouseResult = {
      ...fixture,
      audits: { ...fixture.audits, "largest-contentful-paint": { ...fixture.audits!["largest-contentful-paint"], numericValue: "4650" as unknown as number } },
    };
    expect(checkLighthouseContract(broken).join("\n")).toContain("numericValue is");
  });
  it("fires when categories.performance.score is missing", () => {
    expect(checkLighthouseContract({ ...fixture, categories: {} }).join("\n")).toContain("categories.performance.score");
  });
});
