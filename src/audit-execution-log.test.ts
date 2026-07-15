import { describe, expect, it } from "vitest";
import { AUDIT_MODULES, type AuditModule, MODULES_NEVER_EXECUTED } from "./audit-coverage.js";
import { type ExecutionRecord, neverExecutedModules, readExecutionLog, recordExecutions } from "./audit-execution-log.js";

const record = (module: AuditModule): ExecutionRecord => ({ module, firstRan: "2026-07-01", target: "t", evidence: "e" });

describe("neverExecutedModules (#284 — derived, not hand-kept)", () => {
  it("calls a module never-run when no record claims it ran", () => {
    const log = AUDIT_MODULES.filter((m) => m !== "M6").map(record);
    expect([...neverExecutedModules(AUDIT_MODULES, log)]).toEqual(["M6"]);
  });

  // The staleness #284 describes: someone runs M6 and forgets to delete the "M6" entry, leaving a
  // false "never run" alarm. Derivation makes forgetting impossible — the record IS the removal.
  it("clears a module's never-run status the moment an execution record exists for it", () => {
    const log = AUDIT_MODULES.map(record);
    expect([...neverExecutedModules(AUDIT_MODULES, log)]).toEqual([]);
  });

  // The worse half of #284: a module added to AUDIT_MODULES that nobody thinks to add to the Set.
  // Under the hand-kept ledger it silently never got the loud treatment. Derived, it is never-run
  // by DEFAULT — absence of evidence is the alarm, which is the fail-loud direction.
  it("treats a newly-enumerated module with no record as never-run without anyone listing it", () => {
    const brandNew = [...AUDIT_MODULES, "M11" as AuditModule];
    const log = AUDIT_MODULES.map(record); // every existing module has run; M11 is brand new
    expect([...neverExecutedModules(brandNew, log)]).toEqual(["M11"]);
  });

  it("derives never-run from an empty log rather than vacuously passing", () => {
    expect([...neverExecutedModules(AUDIT_MODULES, [])]).toEqual([...AUDIT_MODULES]);
  });
});

describe("the committed execution log", () => {
  it("records only real modules, so a typo can't bank evidence for a module that doesn't exist", () => {
    const ids = new Set<string>(AUDIT_MODULES);
    expect(readExecutionLog().filter((r) => !ids.has(r.module))).toEqual([]);
  });

  it("carries provenance on every entry — an unevidenced record is the hand-kept Set again", () => {
    for (const r of readExecutionLog()) {
      expect(r.evidence.length, `${r.module} must cite evidence`).toBeGreaterThan(20);
      expect(r.target, `${r.module} must name a target`).toBeTruthy();
      expect(r.firstRan, `${r.module} must date its first run`).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });

  it("does not record M6 — the module that has never produced output (#266)", () => {
    expect(readExecutionLog().map((r) => r.module)).not.toContain("M6");
  });

  // The behaviour the gate depends on: the derived Set must still make M6 fail loud.
  it("derives the same alarm the hand-kept ledger asserted: M6 never-run, M10 not", () => {
    expect(MODULES_NEVER_EXECUTED.has("M6")).toBe(true);
    expect(MODULES_NEVER_EXECUTED.has("M10")).toBe(false);
  });
});

describe("recordExecutions", () => {
  it("banks a module's first execution, which is what retires its never-run alarm", () => {
    const log = recordExecutions(AUDIT_MODULES, [], ["M6"], "targets/acme", "2026-07-15", "pnpm run-audit");
    expect(log).toEqual([{ module: "M6", firstRan: "2026-07-15", target: "targets/acme", evidence: "pnpm run-audit" }]);
    expect([...neverExecutedModules(["M6"], log)]).toEqual([]);
  });

  // "Never run" is a claim about EVER, so the first date is the one that answers it. A later run
  // overwriting it would quietly destroy the earliest evidence.
  it("keeps the first execution date when a module runs again", () => {
    const existing = [{ module: "M4" as const, firstRan: "2026-06-27", target: "atc", evidence: "self-audit" }];
    const log = recordExecutions(AUDIT_MODULES, existing, ["M4"], "targets/acme", "2026-07-15", "later run");
    expect(log).toEqual(existing);
  });

  it("does not bank modules that did not run", () => {
    const log = recordExecutions(AUDIT_MODULES, [], ["M1"], "t", "2026-07-15", "e");
    expect(log.map((r) => r.module)).toEqual(["M1"]);
  });
});
