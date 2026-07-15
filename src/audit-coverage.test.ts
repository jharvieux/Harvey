import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  assertAuditComplete,
  AUDIT_MODULES,
  buildAuditCoverage,
  formatAuditCoverage,
  MODULES,
  MODULES_NEVER_EXECUTED,
  type ModuleCoverage,
} from "./audit-coverage.js";

const ran = (module: ModuleCoverage["module"]): ModuleCoverage => ({ module, status: "ran" });
const allTen = (): ModuleCoverage[] => AUDIT_MODULES.map(ran);

// #275: the dead guard shipped enumerating only M1–M9 while the product sold ten, so M10 could
// never be a gap or a never-run — it was absent from the definition of "complete" itself. No test
// caught it because every test derived its fixture FROM the guard's own list (see allTen), which
// makes the enumeration true by construction: the one thing a guard cannot check about itself is
// its own list. So this reads the SCOPE AUTHORITY — docs/audit-modules.md, the doc CLAUDE.md and
// this gate both cite — rather than restating the module set here. A second hand-kept list would
// just be the two-list drift of #288 again, one layer up: the doc and the code cannot disagree if
// only one of them is written down.
const documentedModules = (): string[] => {
  const doc = readFileSync(fileURLToPath(new URL("../docs/audit-modules.md", import.meta.url)), "utf8");
  const ids = [...doc.matchAll(/^\|\s*(M\d+)\s*\|/gm)].map((m) => m[1]).filter((id): id is string => id !== undefined);
  // A doc whose table stopped parsing would make every assertion below vacuously true — the exact
  // "true by construction" failure (#275) this test exists to break.
  if (ids.length === 0) throw new Error("parsed no modules from docs/audit-modules.md — the table's shape changed");
  return ids;
};

describe("the module enumeration itself (#275)", () => {
  it("enumerates exactly the modules docs/audit-modules.md documents — read, not restated", () => {
    expect([...AUDIT_MODULES]).toEqual(documentedModules());
  });

  it("enumerates M10 — the module the dead guard was blind to", () => {
    expect([...AUDIT_MODULES]).toContain("M10");
  });

  it("sells one module count: the doc's prose agrees with its own table (#289)", () => {
    // The root defect of #289: the scope authority said 7 in its prose, ten in its table, and
    // M1–M9 in its Packaging section. A count in prose can drift from the table silently, so pin
    // the two claims that a reader actually acts on to the table's real length.
    const doc = readFileSync(fileURLToPath(new URL("../docs/audit-modules.md", import.meta.url)), "utf8");
    expect(doc).toContain(`A full audit is ten modules (M1–M${documentedModules().length})`);
    expect(doc).toContain(`**Full codebase audit** (M1–M${documentedModules().length}`);
  });

  it("describes every module it enumerates, so a new module can't ship nameless", () => {
    expect(Object.keys(MODULES).sort()).toEqual([...AUDIT_MODULES].sort());
  });

  it("keeps the never-executed ledger to real modules, so a typo can't silently never fire", () => {
    const ids = new Set<string>(AUDIT_MODULES);
    expect([...MODULES_NEVER_EXECUTED].filter((id) => !ids.has(id))).toEqual([]);
  });
});

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
    // M3, not M6: M6 is in MODULES_NEVER_EXECUTED, which blocks `complete` regardless of reason.
    const recorded: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M3").map(ran),
      { module: "M3", status: "requires-live-run", reason: "no hotspot budget for this engagement; TODO tracked in #123" },
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

// #266, carried over from the deleted src/audit/module-coverage.ts (#288). A reason answers "why
// not THIS engagement". For a module whose environment is absent by default in every engagement,
// that answer is legitimately "no" every single time — so the module can have zero output ever
// while each individual record is correct. These pin the distinction: a well-reasoned excuse must
// NOT be able to launder "never executed once" into routine.
describe("never-run modules (#266)", () => {
  // #284: these two facts are now DERIVED from audit-execution-log.json (the log has no M6 entry
  // and does have an M10 one) rather than hand-curated here. The ledger's own derivation is pinned
  // in audit-execution-log.test.ts; these assert the gate still reads the alarm it depends on.
  it("M6 is in the never-executed ledger — the module absorbed as a routine excuse", () => {
    expect(MODULES_NEVER_EXECUTED.has("M6")).toBe(true);
  });

  it("M10 is NOT in the ledger — unlike M6, it has actually executed", () => {
    // Established from evidence, not assumed (#275): the dry-run calibration ran M10 for real
    // against parsed migration columns — 3 tables / 31 columns, artifact dry-run/pii-data-map.json,
    // recorded in docs/runbooks/dry-run-calibration.md §2. A module with output is not never-run,
    // and listing it here would be a false alarm — which costs the ledger the credibility that
    // makes M6's entry worth throwing on.
    expect(MODULES_NEVER_EXECUTED.has("M10")).toBe(false);
  });

  it("a perfectly-reasoned skip of a never-run module still fails loud, unlike the same on M2", () => {
    const recorded: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M6").map(ran),
      { module: "M6", status: "requires-live-run", reason: "paid LLM tier not in scope — a true and correct reason" },
    ];
    const report = buildAuditCoverage(recorded);
    // The reason is valid, so this is NOT a gap — the gate without the ledger stopped here.
    expect(report.gaps).toEqual([]);
    // But it has never run in any engagement, so coverage is not complete and the gate throws.
    expect(report.neverRun).toEqual(["M6"]);
    expect(report.complete).toBe(false);
    expect(() => assertAuditComplete(recorded)).toThrow(/NEVER executed/);
  });

  it("no reason clears never-run — only running the module does", () => {
    expect(buildAuditCoverage(allTen()).neverRun).toEqual([]);
    expect(buildAuditCoverage(allTen()).complete).toBe(true);
    expect(() => assertAuditComplete(allTen())).not.toThrow();
  });

  it("the never-run error names the runner, so the reader knows how to clear it", () => {
    const recorded: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M6").map(ran),
      { module: "M6", status: "requires-live-run", reason: "not purchased" },
    ];
    expect(() => assertAuditComplete(recorded)).toThrow(/simplify-scan/);
  });

  it("does not double-count a never-run module as a gap (a gap is fixable by a reason; this isn't)", () => {
    const recorded: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M6").map(ran),
      { module: "M6", status: "requires-live-run", reason: "not purchased" },
    ];
    expect(buildAuditCoverage(recorded).gaps).toEqual([]);
  });
});

// Carried over from the deleted guard (#288): the env annotation tells a reader WHY a module was
// missing without excusing it — an unrecorded module is a gap whether or not the environment was
// there to run it.
describe("environment-gated gaps", () => {
  it("annotates an unaccounted module with the environment it needed", () => {
    const recorded = AUDIT_MODULES.filter((m) => m !== "M2").map(ran);
    const report = buildAuditCoverage(recorded, { connected: true, dynamic: false, llm: true });
    expect(report.gaps.find((g) => g.module === "M2")?.problem).toMatch(/needs dynamic/);
  });

  it("still calls a missing module a gap when the environment WAS available", () => {
    const recorded = AUDIT_MODULES.filter((m) => m !== "M2").map(ran);
    const report = buildAuditCoverage(recorded, { connected: true, dynamic: true, llm: true });
    expect(report.gaps.map((g) => g.module)).toContain("M2");
    expect(report.gaps.find((g) => g.module === "M2")?.problem).not.toMatch(/needs/);
  });

  it("a missing environment never excuses the module — it is a gap either way", () => {
    const recorded = AUDIT_MODULES.filter((m) => m !== "M2").map(ran);
    expect(buildAuditCoverage(recorded, { connected: false, dynamic: false, llm: false }).complete).toBe(false);
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
