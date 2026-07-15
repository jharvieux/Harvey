import { describe, expect, it } from "vitest";
import { assertAuditComplete, AUDIT_MODULES, buildAuditCoverage, type AuditModule } from "./audit-coverage.js";
import { assertRegistryComplete, formatFailures, type ModuleRunner, type ProbeOutcome, type RunContext } from "./audit-runner.js";
import { runAudit } from "./audit-runner.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";

const ctx = (over: Partial<RunContext> = {}): RunContext => ({
  targetDir: "/target",
  env: { connected: false, dynamic: false, llm: false },
  exec: () => ({ ok: true, output: "" }),
  exists: () => true,
  ...over,
});

const probe = (module: AuditModule, outcome: ProbeOutcome): ModuleRunner => ({ module, run: () => outcome });
const allRan = (): ModuleRunner[] => AUDIT_MODULES.map((m) => probe(m, { status: "ran", detail: `ran ${m}` }));

describe("assertRegistryComplete (#229 — a module with no runner is the skip itself)", () => {
  it("throws naming every module that has no runner", () => {
    const missingFive = allRan().filter((r) => r.module !== "M5");
    expect(() => assertRegistryComplete(missingFive)).toThrow(/M5 \(Slop \/ dead code\)/);
  });

  it("throws before any module runs, so a short registry can't produce a partial ledger", () => {
    // The failure #229 exists to prevent: a registry that simply omits a module. If this were
    // permissive, runAudit would return nine honest rows and the tenth would never be mentioned.
    expect(() => runAudit(allRan().filter((r) => r.module !== "M8"), ctx())).toThrow(/registry is incomplete/);
  });

  it("rejects a module registered twice — two probes, two answers to 'did it run'", () => {
    expect(() => assertRegistryComplete([...allRan(), probe("M4", { status: "ran", detail: "again" })])).toThrow(/M4.*more than once/);
  });

  it("accepts a registry covering exactly the ten modules", () => {
    expect(() => assertRegistryComplete(allRan())).not.toThrow();
  });
});

describe("runAudit derives the ledger from execution (#229/#284)", () => {
  it("records a row per module, in the enumeration's order, never the registry's", () => {
    const shuffled = [...allRan()].reverse();
    expect(runAudit(shuffled, ctx()).recorded.map((r) => r.module)).toEqual([...AUDIT_MODULES]);
  });

  // The core property: a probe's report is the ONLY source of a row. A module that did not execute
  // cannot be recorded "ran" by anyone — there is no parameter through which to claim it.
  it("records what the probe reported, not what a caller wishes had run", () => {
    const runners = [
      ...allRan().filter((r) => r.module !== "M5"),
      probe("M5", { status: "requires-live-run", reason: "target has no node_modules" }),
    ];
    const m5 = runAudit(runners, ctx()).recorded.find((r) => r.module === "M5");
    expect(m5?.status).toBe("requires-live-run");
    expect(m5?.reason).toBe("target has no node_modules");
  });

  it("carries a partial's reason through, so a half-run module never reads as complete", () => {
    const runners = [
      ...allRan().filter((r) => r.module !== "M7"),
      probe("M7", { status: "partial", detail: "code tier", reason: "no DB creds for the advisors" }),
    ];
    const report = buildAuditCoverage(runAudit(runners, ctx()).recorded);
    expect(report.rows.find((r) => r.module === "M7")?.reason).toMatch(/no DB creds/);
    expect(report.ranCount).toBe(9);
  });

  // A crashed scanner is a bug, not a tier. If a throw were laundered into a reasoned
  // requires-live-run, a broken M4 would sail through the gate as a legitimate environment gap.
  it("routes a crashed runner to failures instead of excusing it as an environment gap", () => {
    const runners = [
      ...allRan().filter((r) => r.module !== "M4"),
      { module: "M4" as const, run: () => { throw new Error("jscpd binary missing"); } },
    ];
    const { recorded, failures } = runAudit(runners, ctx());
    expect(failures).toEqual([{ module: "M4", error: "jscpd binary missing" }]);
    // The ledger stays honest about the absence of output...
    expect(recorded.find((r) => r.module === "M4")?.reason).toMatch(/runner failed: jscpd binary missing/);
    // ...and crucially the crash is not silently survivable: the reason alone would satisfy the
    // coverage gate, so `failures` is what must stop the run.
    expect(() => assertAuditComplete(recorded)).not.toThrow();
    expect(failures).toHaveLength(1);
  });

  it("keeps running the remaining modules after one crashes, so one bug can't truncate the audit", () => {
    const runners = [
      ...allRan().filter((r) => r.module !== "M1"),
      { module: "M1" as const, run: () => { throw new Error("boom"); } },
    ];
    const { recorded } = runAudit(runners, ctx());
    expect(recorded).toHaveLength(10);
    expect(recorded.filter((r) => r.status === "ran")).toHaveLength(9);
  });

  it("produces a ledger the coverage gate accepts when every probe truly ran", () => {
    const { recorded, failures } = runAudit(allRan(), ctx());
    expect(failures).toEqual([]);
    // M6 is in MODULES_NEVER_EXECUTED, so a real all-ran run is what clears it — see #284 below.
    expect(buildAuditCoverage(recorded).complete).toBe(true);
  });
});

describe("the real ten probes (AUDIT_RUNNERS)", () => {
  it("registers every module of M1–M10", () => {
    expect(() => assertRegistryComplete(AUDIT_RUNNERS)).not.toThrow();
  });

  // Each probe must gather its OWN evidence. These drive the real probes against a fake environment
  // and assert the prereq actually gates the outcome.
  it("M5 refuses to run without the target's installed deps, naming the prereq", () => {
    const noDeps = ctx({ exists: (p) => !p.endsWith("node_modules") });
    const m5 = runAudit(AUDIT_RUNNERS, noDeps).recorded.find((r) => r.module === "M5");
    expect(m5?.status).toBe("requires-live-run");
    expect(m5?.reason).toMatch(/no node_modules/);
  });

  it("M5 runs once the target's deps are present — the prereq gates it, not a flag", () => {
    expect(runAudit(AUDIT_RUNNERS, ctx()).recorded.find((r) => r.module === "M5")?.status).toBe("ran");
  });

  it("M2 is requires-live-run without a dynamic stack, and never silently absent", () => {
    const m2 = runAudit(AUDIT_RUNNERS, ctx()).recorded.find((r) => r.module === "M2");
    expect(m2?.status).toBe("requires-live-run");
    expect(m2?.reason).toMatch(/no local supabase stack/);
  });

  it("M7 without DB creds is partial — it loses the advisor layer but still ran on source", () => {
    const m7 = runAudit(AUDIT_RUNNERS, ctx()).recorded.find((r) => r.module === "M7");
    expect(m7?.status).toBe("partial");
    expect(m7?.reason).toMatch(/advisors/);
  });

  // A non-zero exit is the tool saying it produced nothing. Recording that as "ran" is precisely
  // the false-positive coverage claim the gate exists to prevent.
  it("records a module whose CLI exits non-zero as requires-live-run, not ran", () => {
    const failing = ctx({ exec: () => ({ ok: false, output: "jscpd: command not found" }) });
    const m4 = runAudit(AUDIT_RUNNERS, failing).recorded.find((r) => r.module === "M4");
    expect(m4?.status).toBe("requires-live-run");
    expect(m4?.reason).toMatch(/command not found/);
  });

  it("M10 falls back to schema-tier when there is no live DB, and says what it missed", () => {
    const m10 = runAudit(AUDIT_RUNNERS, ctx()).recorded.find((r) => r.module === "M10");
    expect(m10?.status).toBe("partial");
    expect(m10?.reason).toMatch(/schema tier only/);
  });

  it("M10 has nothing to classify with neither a DB nor migrations", () => {
    const bare = ctx({ exists: (p) => !p.includes("migrations") });
    const m10 = runAudit(AUDIT_RUNNERS, bare).recorded.find((r) => r.module === "M10");
    expect(m10?.status).toBe("requires-live-run");
    expect(m10?.reason).toMatch(/nothing to classify/);
  });

  // The whole-audit shape of #229's original failure: a source-tier engagement. Every module is
  // still accounted for — nothing is silently missing — but the tier-gated ones say why.
  it("accounts for all ten modules on a source-only engagement, with reasons", () => {
    const { recorded, failures } = runAudit(AUDIT_RUNNERS, ctx());
    expect(failures).toEqual([]);
    expect(recorded.map((r) => r.module)).toEqual([...AUDIT_MODULES]);
    for (const row of recorded) {
      if (row.status !== "ran") expect(row.reason, `${row.module} must say why`).toBeTruthy();
    }
    expect(buildAuditCoverage(recorded, ctx().env).gaps).toEqual([]);
  });
});

describe("formatFailures", () => {
  it("names each crashed module and calls the crash a bug, not a tier", () => {
    const out = formatFailures([{ module: "M4", error: "jscpd binary missing" }]);
    expect(out).toMatch(/M4 \(Duplication\): jscpd binary missing/);
    expect(out).toMatch(/not a tier/);
  });
});
