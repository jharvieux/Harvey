import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  assertAuditComplete,
  AUDIT_MODULES,
  type AuditModule,
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
// its own list. So this reads the SCOPE AUTHORITY — briefs/audit-modules.md, the doc CLAUDE.md and
// this gate both cite — rather than restating the module set here. A second hand-kept list would
// just be the two-list drift of #288 again, one layer up: the doc and the code cannot disagree if
// only one of them is written down.
const documentedModules = (): string[] => {
  const doc = readFileSync(fileURLToPath(new URL("../briefs/audit-modules.md", import.meta.url)), "utf8");
  const ids = [...doc.matchAll(/^\|\s*(M\d+)\s*\|/gm)].map((m) => m[1]).filter((id): id is string => id !== undefined);
  // A doc whose table stopped parsing would make every assertion below vacuously true — the exact
  // "true by construction" failure (#275) this test exists to break.
  if (ids.length === 0) throw new Error("parsed no modules from briefs/audit-modules.md — the table's shape changed");
  return ids;
};

describe("the module enumeration itself (#275)", () => {
  it("enumerates exactly the modules briefs/audit-modules.md documents — read, not restated", () => {
    expect([...AUDIT_MODULES]).toEqual(documentedModules());
  });

  it("enumerates M10 — the module the dead guard was blind to", () => {
    expect([...AUDIT_MODULES]).toContain("M10");
  });

  it("sells one module count: the doc's prose agrees with its own table (#289)", () => {
    // The root defect of #289: the scope authority said 7 in its prose, ten in its table, and
    // M1–M9 in its Packaging section. A count in prose can drift from the table silently, so pin
    // the two claims that a reader actually acts on to the table's real length.
    const doc = readFileSync(fileURLToPath(new URL("../briefs/audit-modules.md", import.meta.url)), "utf8");
    expect(doc).toContain(`A full audit is ten modules (M1–M${documentedModules().length})`);
    expect(doc).toContain(`**Full codebase audit** (M1–M${documentedModules().length}`);
  });

  it("describes every module it enumerates, so a new module can't ship nameless", () => {
    expect(Object.keys(MODULES).sort()).toEqual([...AUDIT_MODULES].sort());
  });

  // #1071: MODULES[].freeTier marked M3/M5/M6 paid-only while docs/free-tier-scope.md — the file
  // the constant's own comment names as its source of truth — and the site both advertise all
  // three as free. Nothing read the field, so nothing could disagree with it. Same fix as #275
  // one field over: derive the split from the document instead of restating it, so the constant
  // cannot be wrong in silence while it waits for its first consumer.
  //
  // #1296: freeTier alone didn't catch a real drift, because nothing gates behaviour on freeTier —
  // `needs` does (envGated in audit-coverage.ts), and M6 had needs:"llm" while freeTier:true and
  // the doc both said M6 is free. One field wider: a free-tier module's minimum can never be "llm"
  // (or "connected"/"dynamic" — the free tier is source-only by definition, docs/free-tier-scope.md's
  // "no database, no credentials, no contact with production"), so assert that too.
  it("splits free from paid exactly as docs/free-tier-scope.md does — read, not restated", () => {
    const doc = readFileSync(fileURLToPath(new URL("../docs/free-tier-scope.md", import.meta.url)), "utf8");
    const table = doc.split("## What the free scan delivers")[1]?.split("\n## ")[0] ?? "";
    const free = new Set([...table.matchAll(/^\|\s*\*\*(M\d+)\b/gm)].map((m) => m[1]));
    if (free.size === 0) throw new Error("parsed no modules from the free-tier table in docs/free-tier-scope.md — its shape changed");
    for (const id of AUDIT_MODULES) {
      expect(MODULES[id].freeTier, `${id} (${MODULES[id].name})`).toBe(free.has(id));
      if (free.has(id)) {
        expect(MODULES[id].needs, `${id} (${MODULES[id].name}) is documented free but needs its paid-only tier to run at all`).toBe("source");
      }
    }
    // The one module the doc deliberately withholds from the free tier — pinned so a table that
    // stopped parsing (every module "paid") cannot pass this test by accident.
    expect(free.has("M2")).toBe(false);
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
    // M3 (a genuine reason mentioning a TODO) rather than a never-run module, so `complete` turns
    // purely on the placeholder check and not on the never-run ledger.
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
  // A synthetic ledger so the fail-loud WIRING stays tested independent of the live log. Since #283
  // cleared M6 (the last holdout), the derived live ledger is empty — no real module triggers the
  // never-run path anymore, so the behavior is exercised through the injected set (#283).
  const synthNeverRun: ReadonlySet<AuditModule> = new Set<AuditModule>(["M6"]);

  // #284: this fact is DERIVED from audit-execution-log.json. #283 recorded M6's first real-target
  // run (the reviewed simplify-scan verdict over stoimera/Cravab), so the ledger no longer flags it.
  it("has no never-executed modules left — #283 cleared M6, the final holdout", () => {
    expect([...MODULES_NEVER_EXECUTED]).toEqual([]);
    expect(MODULES_NEVER_EXECUTED.has("M6")).toBe(false);
    expect(MODULES_NEVER_EXECUTED.has("M10")).toBe(false);
  });

  it("a perfectly-reasoned skip of a never-run module still fails loud, unlike the same on M2", () => {
    const recorded: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M6").map(ran),
      { module: "M6", status: "requires-live-run", reason: "paid LLM tier not in scope — a true and correct reason" },
    ];
    const report = buildAuditCoverage(recorded, undefined, synthNeverRun);
    // The reason is valid, so this is NOT a gap — the gate without the ledger stopped here.
    expect(report.gaps).toEqual([]);
    // But it has never run in any engagement, so coverage is not complete and the gate throws.
    expect(report.neverRun).toEqual(["M6"]);
    expect(report.complete).toBe(false);
    expect(() => assertAuditComplete(recorded, undefined, synthNeverRun)).toThrow(/NEVER executed/);
  });

  it("no reason clears never-run — only running the module does", () => {
    expect(buildAuditCoverage(allTen(), undefined, synthNeverRun).neverRun).toEqual([]);
    expect(buildAuditCoverage(allTen(), undefined, synthNeverRun).complete).toBe(true);
    expect(() => assertAuditComplete(allTen(), undefined, synthNeverRun)).not.toThrow();
  });

  it("the never-run error names the runner, so the reader knows how to clear it", () => {
    const recorded: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M6").map(ran),
      { module: "M6", status: "requires-live-run", reason: "not purchased" },
    ];
    expect(() => assertAuditComplete(recorded, undefined, synthNeverRun)).toThrow(/simplify-scan/);
  });

  it("does not double-count a never-run module as a gap (a gap is fixable by a reason; this isn't)", () => {
    const recorded: ModuleCoverage[] = [
      ...AUDIT_MODULES.filter((m) => m !== "M6").map(ran),
      { module: "M6", status: "requires-live-run", reason: "not purchased" },
    ];
    expect(buildAuditCoverage(recorded, undefined, synthNeverRun).gaps).toEqual([]);
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

// #506: a monorepo per-app/per-DB tier records one row per (module × instance). Two instances of a
// module is legitimate coverage, not the ambiguous double-record; only a duplicate (module,instance)
// is. And an uncovered instance must be an explicit reasoned row, never absent.
describe("per-instance coverage rows (#506)", () => {
  const withM5 = (extra: ModuleCoverage[]): ModuleCoverage[] => [...AUDIT_MODULES.filter((m) => m !== "M5").map(ran), ...extra];

  it("keeps two app instances of one module as two rows, not a gap", () => {
    const report = buildAuditCoverage(withM5([
      { module: "M5", status: "ran", detail: "a", instance: "apps/main" },
      { module: "M5", status: "requires-live-run", reason: "no node_modules", instance: "apps/rag" },
    ]));
    expect(report.rows.filter((r) => r.module === "M5").map((r) => r.instance)).toEqual(["apps/main", "apps/rag"]);
    expect(report.gaps).toEqual([]);
  });

  it("still flags a duplicate (module, instance) as ambiguous bookkeeping", () => {
    const report = buildAuditCoverage(withM5([
      { module: "M5", status: "ran", detail: "a", instance: "apps/main" },
      { module: "M5", status: "ran", detail: "b", instance: "apps/main" },
    ]));
    expect(report.gaps.some((g) => /recorded twice/.test(g.problem))).toBe(true);
  });

  it("makes a reasonless non-ran instance row a gap that names the instance", () => {
    const report = buildAuditCoverage(withM5([
      { module: "M5", status: "ran", detail: "a", instance: "apps/main" },
      { module: "M5", status: "partial", instance: "apps/rag" },
    ]));
    expect(report.gaps.some((g) => g.problem.includes("apps/rag"))).toBe(true);
  });

  it("counts a module ran-in-full only when EVERY instance ran", () => {
    const full = buildAuditCoverage(withM5([
      { module: "M5", status: "ran", detail: "a", instance: "apps/main" },
      { module: "M5", status: "ran", detail: "b", instance: "apps/rag" },
    ]));
    expect(full.ranCount).toBe(AUDIT_MODULES.length);
    const partial = buildAuditCoverage(withM5([
      { module: "M5", status: "ran", detail: "a", instance: "apps/main" },
      { module: "M5", status: "partial", reason: "no node_modules", instance: "apps/rag" },
    ]));
    expect(partial.ranCount).toBe(AUDIT_MODULES.length - 1);
  });

  it("renders the instance label in the coverage lines", () => {
    const out = formatAuditCoverage(buildAuditCoverage(withM5([
      { module: "M5", status: "ran", detail: "a", instance: "apps/main" },
      { module: "M5", status: "ran", detail: "b", instance: "apps/rag" },
    ])));
    expect(out).toContain("[apps/rag]");
  });
});
