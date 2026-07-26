// #1064 (4)+(5). The CLI proves the WIRING against the real fixture (it needs the mechanical
// binaries, so it is not part of `pnpm verify`); this file proves the LOGIC, by seeding each
// violation shape and asserting the gate fails on it. A gate nobody has watched fail is not
// evidence that it can — #350's guard was true of the code and could never fire for nine months.

import { describe, expect, it } from "vitest";
import { CALIBRATION_PLANTS, checkConservation, formatConservation, UNEXERCISED } from "./audit-conservation.js";
import { AUDIT_MODULES, type AuditModule, type ModuleCoverage } from "./audit-coverage.js";
import type { Finding } from "./findings.js";

const M7_PLANT = CALIBRATION_PLANTS.find((p) => p.module === "M7")!;

function planted(plant: { taxonomy: string; location: string }, id = "F-1"): Finding {
  return {
    id, title: "planted", severity: "Medium", confidence: "Confirmed", category: "Performance",
    taxonomy: plant.taxonomy, location: `${plant.location}:14`, status: "Open",
    evidence: "e", impact: "i", fix: "f", value: 3, ease: 3, safety: 3,
  };
}

// Every module produces and delivers its plant — the shape a healthy run has.
function healthy(): { findingsByModule: Partial<Record<AuditModule, Finding[]>>; recorded: ModuleCoverage[]; delivered: Finding[] } {
  const findingsByModule: Partial<Record<AuditModule, Finding[]>> = {};
  const delivered: Finding[] = [];
  for (const plant of CALIBRATION_PLANTS) {
    const f = planted(plant, `${plant.module}-plant`);
    findingsByModule[plant.module] = [f];
    delivered.push(f);
  }
  return { findingsByModule, recorded: AUDIT_MODULES.map((module) => ({ module, status: "ran", detail: "probe ran" })), delivered };
}

describe("conservation gate — the registry cannot silently omit a module", () => {
  it("accounts for every one of M1–M10 as either planted or explicitly unexercised", () => {
    const covered = [...CALIBRATION_PLANTS.map((p) => p.module), ...UNEXERCISED.map((u) => u.module)].sort();
    expect(covered).toEqual([...AUDIT_MODULES].sort());
  });

  it("names an executable falsifier for every unexercised module, so the excuse can expire", () => {
    for (const u of UNEXERCISED) expect(u.reason).toMatch(/validate-conservation\.ts --require/);
  });
});

describe("conservation gate — seeded violations", () => {
  it("passes when every module's plant is produced and delivered", () => {
    const report = checkConservation(healthy());
    expect(report.ok).toBe(true);
    expect(report.rows.filter((r) => r.verdict === "delivered")).toHaveLength(CALIBRATION_PLANTS.length);
    expect(report.rows.filter((r) => r.verdict === "unexercised").map((r) => r.module)).toEqual(UNEXERCISED.map((u) => u.module));
  });

  it("FAILS when a module produced its plant and the deliverable carries none (#1040/#1061 — lost in assembly)", () => {
    const input = healthy();
    input.delivered = input.delivered.filter((f) => f.id !== "M7-plant");
    const report = checkConservation(input);
    expect(report.ok).toBe(false);
    expect(report.rows.find((r) => r.module === "M7")?.verdict).toBe("lost-in-assembly");
    expect(formatConservation(report)).toContain("GATE FAIL — M7 produced 1 finding(s)");
  });

  it("FAILS when a module produced nothing for its plant, even though the fixture plants one (#1064 (5) — zero is suspicious)", () => {
    const input = healthy();
    input.findingsByModule.M5 = [];
    input.delivered = input.delivered.filter((f) => f.id !== "M5-plant");
    input.recorded = input.recorded.map((r) => (r.module === "M5" ? { module: "M5", status: "partial", detail: "knip ran", reason: "no node_modules" } : r));
    const report = checkConservation(input);
    expect(report.ok).toBe(false);
    const row = report.rows.find((r) => r.module === "M5");
    expect(row?.verdict).toBe("not-produced");
    // The probe's own words travel with the failure, so the row says WHY rather than only WHAT.
    expect(formatConservation(report)).toContain("no node_modules");
  });

  it("FAILS a module that produced nothing even when another probe's unfiltered capture delivers the identical row (#1062)", () => {
    // The exact shape that hid #1062: M9 captures detect-static unfiltered, so M7's rows are in the
    // deliverable whether or not M7 itself captured anything. A deliverable-only check passes here.
    const input = healthy();
    input.findingsByModule.M7 = [];
    const report = checkConservation(input);
    expect(report.ok).toBe(false);
    const row = report.rows.find((r) => r.module === "M7");
    expect(row).toMatchObject({ verdict: "not-produced", produced: 0, delivered: 1 });
  });

  it("does not accept a same-class finding from somewhere else as the plant", () => {
    const input = healthy();
    const elsewhere = planted({ taxonomy: M7_PLANT.taxonomy, location: "some/other/file.tsx" }, "M7-elsewhere");
    input.findingsByModule.M7 = [elsewhere];
    input.delivered = [...input.delivered.filter((f) => f.id !== "M7-plant"), elsewhere];
    expect(checkConservation(input).rows.find((r) => r.module === "M7")?.verdict).toBe("not-produced");
  });

  it("M2's UNEXERCISED reason expired — it is now planted and delivers offline (#1155)", () => {
    // M2 used to be the one UNEXERCISED module, falsifier `--require M2`. #1155 planted the offline
    // half of the M2 delivery path (the #416 dynamic-pass-artifact consume→assemble seam), so M2
    // now produces + delivers its plant in a healthy run with no --require, and UNEXERCISED is empty.
    expect(UNEXERCISED).toHaveLength(0);
    expect(checkConservation(healthy()).rows.find((r) => r.module === "M2")?.verdict).toBe("delivered");

    // --require stays wired for a future UNEXERCISED module; on an already-planted module it is a
    // harmless no-op (still held to the plant signature), and a required module that produces
    // nothing still fails not-produced — the property that makes an UNEXERCISED excuse falsifiable.
    expect(checkConservation({ ...healthy(), required: ["M2"] }).ok).toBe(true);
    const empty = healthy();
    empty.findingsByModule.M2 = [];
    empty.delivered = empty.delivered.filter((f) => f.id !== "M2-plant");
    const held = checkConservation({ ...empty, required: ["M2"] });
    expect(held.ok).toBe(false);
    expect(held.rows.find((r) => r.module === "M2")?.verdict).toBe("not-produced");
  });
});
