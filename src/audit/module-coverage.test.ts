import { describe, expect, it } from "vitest";
import { assertModuleCoverage, assessModuleCoverage, AUDIT_MODULES, type ModuleRecord } from "./module-coverage.js";

const ranAll = (): Record<string, ModuleRecord> => Object.fromEntries(AUDIT_MODULES.map((m) => [m.id, { status: "ran" as const }]));

describe("assessModuleCoverage", () => {
  it("is complete only when every module is run or validly marked na", () => {
    expect(assessModuleCoverage(ranAll()).complete).toBe(true);
  });

  it("flags a missing module as a gap (the M8/test-health omission this guards against)", () => {
    const rec = ranAll();
    delete rec.M8;
    const cov = assessModuleCoverage(rec);
    expect(cov.complete).toBe(false);
    expect(cov.gaps).toContain("M8");
  });

  it("counts an explicit na-with-reason as accounted", () => {
    const rec = ranAll();
    rec.M6 = { status: "na", note: "simplification LLM pass not purchased this round" };
    const cov = assessModuleCoverage(rec);
    expect(cov.complete).toBe(true);
    expect(cov.na).toContainEqual({ id: "M6", note: "simplification LLM pass not purchased this round" });
  });

  it("rejects na without a reason, and a bare skipped, as gaps", () => {
    const noReason = { ...ranAll(), M2: { status: "na" as const } };
    expect(assessModuleCoverage(noReason).gaps).toContain("M2");
    const skipped = { ...ranAll(), M6: { status: "skipped" as const } };
    expect(assessModuleCoverage(skipped).gaps).toContain("M6");
  });

  it("annotates an environment-gated gap with what it needs", () => {
    const rec = ranAll();
    delete rec.M2; // M2 needs dynamic
    const cov = assessModuleCoverage(rec, { connected: true, dynamic: false, llm: true });
    expect(cov.gaps.find((g) => g.startsWith("M2"))).toMatch(/needs dynamic/);
  });

  it("models a source-only run: M7's code layer runs, its DB-advisor layer is a disclosed partial (#170)", () => {
    // Security + M3/M4/M5/M8/M9 over source; M7's code-level detectors also run on source.
    const rec: Record<string, ModuleRecord> = {
      M1: { status: "ran" }, M3: { status: "ran" }, M4: { status: "ran" },
      M5: { status: "ran" }, M8: { status: "ran" }, M9: { status: "ran" },
    };
    const env = { connected: false, dynamic: false, llm: true };
    expect(assessModuleCoverage(rec, env).complete).toBe(false); // M2, M6, M7 unaccounted

    rec.M2 = { status: "na", note: "no running app / self-hosted clone in scope" };
    rec.M7 = { status: "partial", note: "code-level detectors ran; DB performance advisor n/a — no live database in scope" };
    rec.M6 = { status: "na", note: "simplification LLM pass not purchased this round" };
    const cov = assessModuleCoverage(rec, env);
    expect(cov.gaps).toEqual([]); // everything is accounted for…
    expect(cov.complete).toBe(false); // …but the report cannot claim full coverage while M7 is partial
    expect(cov.partial).toContainEqual({ id: "M7", note: expect.stringContaining("no live database") });
    expect(() => assertModuleCoverage(rec, env)).not.toThrow();
  });
});

describe("partial coverage (the M2 'no test app' case)", () => {
  it("a partial module is disclosed, not a silent gap — but the audit is NOT complete", () => {
    const rec = ranAll();
    rec.M2 = { status: "partial", note: "DB-level RLS ran vs the test DB; app-route + seam probes not run — no deployed test app" };
    const cov = assessModuleCoverage(rec);
    expect(cov.complete).toBe(false); // a partial means not fully complete
    expect(cov.partial).toContainEqual({ id: "M2", note: expect.stringContaining("no deployed test app") });
    expect(cov.gaps).toEqual([]); // but it's disclosed, so not a gap
  });

  it("assertModuleCoverage does not throw on a disclosed partial (only on silent gaps)", () => {
    const rec = ranAll();
    rec.M2 = { status: "partial", note: "app-probe classes need a running app" };
    expect(() => assertModuleCoverage(rec)).not.toThrow();
  });

  it("a partial WITHOUT a note is a gap (must say what's missing)", () => {
    const rec = { ...ranAll(), M2: { status: "partial" as const } };
    expect(assessModuleCoverage(rec).gaps).toContain("M2");
    expect(() => assertModuleCoverage(rec)).toThrow(/M2/);
  });
});

describe("assertModuleCoverage", () => {
  it("throws loud, naming the unaccounted modules", () => {
    const rec = ranAll();
    delete rec.M8;
    expect(() => assertModuleCoverage(rec)).toThrow(/M8/);
    expect(() => assertModuleCoverage(rec)).toThrow(/unaccounted/);
  });
});
