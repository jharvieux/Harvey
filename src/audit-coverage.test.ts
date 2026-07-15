import { describe, expect, it } from "vitest";
import {
  assertAuditComplete,
  AUDIT_MODULES,
  buildAuditCoverage,
  formatAuditCoverage,
  type ModuleCoverage,
} from "./audit-coverage.js";

const ran = (module: ModuleCoverage["module"]): ModuleCoverage => ({ module, status: "ran" });
const allTen = (): ModuleCoverage[] => AUDIT_MODULES.map(ran);

describe("buildAuditCoverage", () => {
  it("reports complete when every module is accounted for", () => {
    const report = buildAuditCoverage(allTen());
    expect(report.complete).toBe(true);
    expect(report.ranCount).toBe(10);
    expect(report.gaps).toEqual([]);
  });

  // The #229 failure this gate exists to catch: a security-only subset shipped as an audit.
  it("names every module the caller never mentioned", () => {
    const securityOnlySubset = [ran("M1"), ran("M4"), ran("M7"), ran("M9")];
    const report = buildAuditCoverage(securityOnlySubset);
    expect(report.complete).toBe(false);
    expect(report.gaps.map((g) => g.module)).toEqual(["M2", "M3", "M5", "M6", "M8", "M10"]);
  });

  it("always emits a row per module, so an unrun module can't vanish from the matrix", () => {
    const report = buildAuditCoverage([ran("M1")]);
    expect(report.rows.map((r) => r.module)).toEqual([...AUDIT_MODULES]);
  });

  // Mirrors coverage-scorecard.ts's moduleRan: never guess that something executed.
  it("scores an unmentioned module requires-live-run, never ran", () => {
    const missing = buildAuditCoverage([ran("M1")]).rows.find((r) => r.module === "M8");
    expect(missing?.status).toBe("requires-live-run");
    expect(missing?.reason).toMatch(/not accounted for/);
  });

  it("accepts a module that could not run when it carries a reason", () => {
    const recorded: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M8").map(ran),
      { module: "M8", status: "requires-live-run", reason: "target ships no test suite (#224)" },
    ];
    expect(buildAuditCoverage(recorded).complete).toBe(true);
    expect(buildAuditCoverage(recorded).ranCount).toBe(9);
  });

  // A reason-less excuse is a silent skip wearing a label.
  it("rejects a non-ran module whose reason is missing or blank", () => {
    for (const reason of [undefined, "", "   "]) {
      const recorded: ModuleCoverage[] = [
        ...AUDIT_MODULES.filter((m) => m !== "M2").map(ran),
        { module: "M2", status: "requires-live-run", reason },
      ];
      const report = buildAuditCoverage(recorded);
      expect(report.complete, `reason=${JSON.stringify(reason)}`).toBe(false);
      expect(report.gaps[0]?.problem).toMatch(/no reason/);
    }
  });

  // An untouched `--template` must never pass as an audit: the prompt to write a reason is not
  // a reason. The gate can't verify a reason is TRUE, but it can reject the unfilled placeholder.
  it("rejects a reason left as the template's TODO placeholder", () => {
    const untouched: ModuleCoverage[] = AUDIT_MODULES.map((module) => ({
      module,
      status: "requires-live-run",
      reason: `TODO: run ${module} — or state why it could not run`,
    }));
    const report = buildAuditCoverage(untouched);
    expect(report.complete).toBe(false);
    expect(report.gaps).toHaveLength(AUDIT_MODULES.length);
    expect(report.gaps[0]?.problem).toMatch(/placeholder/);
  });

  it("does not mistake a genuine reason that merely mentions a TODO for a placeholder", () => {
    const recorded: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M6").map(ran),
      { module: "M6", status: "requires-live-run", reason: "no LLM budget for this engagement; TODO tracked in #123" },
    ];
    expect(buildAuditCoverage(recorded).complete).toBe(true);
  });

  it("does not demand a reason from a module that fully ran", () => {
    expect(buildAuditCoverage(allTen()).gaps).toEqual([]);
  });

  it("treats a partial module as a gap unless it names the shortfall", () => {
    const withReason: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M7").map(ran),
      { module: "M7", status: "partial", reason: "code tier only — no DB creds for the advisors" },
    ];
    expect(buildAuditCoverage(withReason).complete).toBe(true);
    // ...and a partial never counts as a full run.
    expect(buildAuditCoverage(withReason).ranCount).toBe(9);
  });

  it("flags a module recorded twice rather than trusting either verdict", () => {
    const conflicting: ModuleCoverage[] = [
      ...allTen(),
      { module: "M5", status: "requires-live-run", reason: "target deps not installed" },
    ];
    const report = buildAuditCoverage(conflicting);
    expect(report.complete).toBe(false);
    expect(report.gaps[0]?.problem).toMatch(/twice/);
  });
});

describe("assertAuditComplete", () => {
  it("passes a fully-accounted-for audit", () => {
    expect(() => assertAuditComplete(allTen())).not.toThrow();
  });

  it("throws naming the skipped modules, so a partial audit can't ship as complete", () => {
    expect(() => assertAuditComplete([ran("M1")])).toThrow(/M2.*M3.*M4/s);
  });

  it("throws on an empty run rather than vacuously passing", () => {
    expect(() => assertAuditComplete([])).toThrow(/Incomplete audit coverage/);
  });
});

describe("formatAuditCoverage", () => {
  it("renders a line per module and surfaces the gaps", () => {
    const out = formatAuditCoverage(buildAuditCoverage([ran("M1")]));
    for (const m of AUDIT_MODULES) expect(out).toContain(m);
    expect(out).toContain("COVERAGE FAIL");
  });

  it("shows the reason a module could not run", () => {
    const recorded: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M2").map(ran),
      { module: "M2", status: "requires-live-run", reason: "no local supabase stack" },
    ];
    const out = formatAuditCoverage(buildAuditCoverage(recorded));
    expect(out).toContain("no local supabase stack");
    expect(out).not.toContain("COVERAGE FAIL");
  });
});
