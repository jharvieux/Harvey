import { describe, expect, it } from "vitest";
import { assertAuditComplete, AUDIT_MODULES, buildAuditCoverage, MODULES_NEVER_EXECUTED, type AuditModule } from "./audit-coverage.js";
import { assertRegistryComplete, formatFailures, type ModuleRunner, type ProbeOutcome, type RunContext } from "./audit-runner.js";
import { runAudit } from "./audit-runner.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";

// A tool run that produced real, positive evidence for whichever CLI the probe shelled out to.
// #350: exit 0 is no longer enough — a probe reads the tool's OUTPUT, so the "everything ran
// cleanly" baseline must emit the evidence a clean run actually prints (a knip-clean Finding[], a
// Stryker summary, a non-zero detect-static file count, an M3 hotspot table).
const cleanOutput = (argv: string[]): string => {
  const cmd = argv.join(" ");
  if (cmd.includes("quality-scan")) return "[]"; // Finding[] with no M5-00 → knip ran clean
  if (cmd.includes("mutation-scan")) return JSON.stringify({ summary: { overall: {} }, reportRows: [] });
  if (cmd.includes("detect-static")) return "loaded 42 source files (30 product-code) from /target\n\n3 findings across 2 classes:";
  if (cmd.includes("hotspot-scan.ts")) return "M3 hotspot table — /target (5 rows, worst first)";
  if (cmd.includes("pentest.ts")) return JSON.stringify({ findings: [] });
  return "";
};

const ctx = (over: Partial<RunContext> = {}): RunContext => ({
  targetDir: "/target",
  env: { connected: false, dynamic: false, llm: false },
  exec: (_command, argv) => ({ ok: true, output: cleanOutput(argv) }),
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

  // #401: the free-tier test-intent detectors are source-only AST passes (src/detectors/test-intent.ts)
  // — no installed deps needed — so a target without node_modules should read partial (source tier
  // covered), not the blanket requires-live-run StrykerJS alone would justify.
  it("M8 falls back to the test-intent tier without node_modules, reporting partial not requires-live-run", () => {
    const noDeps = ctx({ exists: (p) => !p.endsWith("node_modules") });
    const m8 = runAudit(AUDIT_RUNNERS, noDeps).recorded.find((r) => r.module === "M8");
    expect(m8?.status).toBe("partial");
    expect(m8?.reason).toMatch(/test-intent/i);
  });

  it("M8 stays requires-live-run without node_modules when the test-intent pass itself found nothing to scan", () => {
    const emptyNoDeps = ctx({
      exists: (p) => !p.endsWith("node_modules"),
      exec: (_c, argv) => (argv.includes("detect-static") ? { ok: true, output: "loaded 0 source files (0 product-code) from /empty" } : { ok: true, output: cleanOutput(argv) }),
    });
    const m8 = runAudit(AUDIT_RUNNERS, emptyNoDeps).recorded.find((r) => r.module === "M8");
    expect(m8?.status).toBe("requires-live-run");
    expect(m8?.reason).toMatch(/no node_modules/);
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

  // #434: --connected is intent, not a reachable project — perf-scan needs a ref as its positional
  // arg. Without one threaded through ctx.supabaseRef, the advisor call has nothing to reach.
  it("M7 with --connected but no project ref stays partial, naming the missing ref", () => {
    const connectedNoRef = ctx({ env: { connected: true, dynamic: false, llm: false } });
    const m7 = runAudit(AUDIT_RUNNERS, connectedNoRef).recorded.find((r) => r.module === "M7");
    expect(m7?.status).toBe("partial");
    expect(m7?.reason).toMatch(/project ref/);
  });

  // #527: code + advisors both run, but the orchestrator never fires the Lighthouse/CWV tier, so a
  // successful advisor run is `partial` naming the unmeasured tier — never a bare `ran`.
  it("M7 threads ctx.supabaseRef to perf-scan and, on advisor success, is partial (Lighthouse tier not run)", () => {
    const connectedWithRef = ctx({
      env: { connected: true, dynamic: false, llm: false },
      supabaseRef: "my-project-ref",
      exec: (_c, argv) => (argv.includes("perf-scan") ? { ok: argv.includes("my-project-ref"), output: "" } : { ok: true, output: cleanOutput(argv) }),
    });
    const m7 = runAudit(AUDIT_RUNNERS, connectedWithRef).recorded.find((r) => r.module === "M7");
    expect(m7?.status).toBe("partial");
    expect(m7?.status).not.toBe("ran");
    expect(m7?.reason).toMatch(/Lighthouse\/CWV tier not run/);
    expect(m7?.detail).toMatch(/perf-scan my-project-ref/);
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

// A RunContext whose exec succeeds (exit 0) but returns the no-op OUTPUT each tool prints when it
// scanned nothing — the exact shape #350 proved slips past an exit-code check.
const status = (runners: typeof AUDIT_RUNNERS, over: Partial<RunContext>, module: AuditModule) =>
  runAudit(runners, ctx(over)).recorded.find((r) => r.module === module);

describe("probes derive status from evidence, not the exit code (#350)", () => {
  it("M5 — knip did not run (M5-00 disclosure emitted, exit 0) is NOT recorded ran", () => {
    // quality-scan exits 0 by design (#223) so M4 keeps its findings; the M5-00 finding is the tell.
    const knipFailed = { exec: () => ({ ok: true, output: JSON.stringify([{ id: "M4-00" }, { id: "M5-00", title: "M5 dead-code scan (knip) did not run" }]) }) };
    const m5 = status(AUDIT_RUNNERS, knipFailed, "M5");
    expect(m5?.status).not.toBe("ran");
    expect(m5?.status).toBe("partial");
    expect(m5?.reason).toMatch(/knip did not run/);
  });

  // #505: a monorepo target where jscpd timed out on one workspace — quality-scan still exits 0
  // (the gap is disclosed as a finding, not a crash) so this is exactly the #350 shape: the exit
  // code says nothing, the M4-99 finding is the tell.
  it("M4 — jscpd did not complete on every workspace (M4-99 disclosure emitted, exit 0) is NOT recorded ran", () => {
    const jscpdTimedOut = { exec: () => ({ ok: true, output: JSON.stringify([{ id: "M5-01" }, { id: "M4-99", title: "M4 duplication scan (jscpd) did not complete for every workspace" }]) }) };
    const m4 = status(AUDIT_RUNNERS, jscpdTimedOut, "M4");
    expect(m4?.status).not.toBe("ran");
    expect(m4?.status).toBe("partial");
    expect(m4?.reason).toMatch(/jscpd did not complete/);
  });

  it("M8 — no test suite (moduleRecord partial, exit 0) is NOT recorded ran", () => {
    // mutation-scan's #224 branch: the correct verdict is serialized and must be read, not discarded.
    const noSuite = { exec: () => ({ ok: true, output: JSON.stringify({ finding: { id: "M8-00" }, moduleRecord: { status: "partial", note: "No automated test suite found (no scripts.test) — mutation scan could not run." } }) }) };
    const m8 = status(AUDIT_RUNNERS, noSuite, "M8");
    expect(m8?.status).not.toBe("ran");
    expect(m8?.status).toBe("partial");
    expect(m8?.reason).toMatch(/no automated test suite/i);
  });

  // #504: the coverage-honesty guard — a scoped mutation run emits its summary AND a partial
  // moduleRecord, and the moduleRecord must win. A subset score that read `ran` is exactly how
  // the ATC run silently invalidated M8.
  it("M8 — a deliberately-scoped mutation run (summary + moduleRecord) scores partial with its scope, never ran", () => {
    const scopedRun = {
      exec: (_c: string, argv: string[]) =>
        argv.includes("mutation-scan")
          ? { ok: true, output: JSON.stringify({ summary: { overall: { mutationScore: 91.2 } }, reportRows: [], moduleRecord: { status: "partial", note: "Scoped mutation run — run covered 263 file(s) but the configured mutate globs match 812 — 549 file(s) were never mutated (e.g. src/other.ts). A subset measurement is not M8's result: recorded partial, never ran (#504)." } }) }
          : { ok: true, output: cleanOutput(argv) },
    };
    const m8 = status(AUDIT_RUNNERS, scopedRun, "M8");
    expect(m8?.status).not.toBe("ran");
    expect(m8?.status).toBe("partial");
    expect(m8?.reason).toMatch(/Scoped mutation run/);
    expect(m8?.reason).toMatch(/263 file/);
  });

  // #503: a failed Stryker dry run (the target's own suite failing unmutated) emits the same
  // machine-readable moduleRecord shape — the probe must surface its distinct reason, not a
  // generic requires-live-run and never a silent zero.
  it("M8 — a failed Stryker dry run (moduleRecord partial, exit 0) reads partial with the dry-run reason", () => {
    const dryRunFailed = {
      exec: (_c: string, argv: string[]) =>
        argv.includes("mutation-scan")
          ? { ok: true, output: JSON.stringify({ finding: { id: "M8-03" }, moduleRecord: { status: "partial", note: "Stryker's initial dry run FAILED — the target suite does not pass under the invoked environment (TZ=UTC (from ci.yml)): × format-date.test.ts. M8 mutation scoring could not run (#503); the suite must pass an unmutated run first." } }) }
          : { ok: true, output: cleanOutput(argv) },
    };
    const m8 = status(AUDIT_RUNNERS, dryRunFailed, "M8");
    expect(m8?.status).toBe("partial");
    expect(m8?.reason).toMatch(/dry run FAILED/);
    expect(m8?.reason).toMatch(/format-date\.test\.ts/);
  });

  // #523: --install (provisioning Stryker into the target, running its npm lifecycle scripts) is
  // gated on explicit operator consent threaded via ctx.allowTargetInstall. The flag decides whether
  // the M8 probe appends --install to mutation-scan — consent unlocks the attempt, nothing else.
  it("M8 appends --install to mutation-scan only when ctx.allowTargetInstall is set (#523)", () => {
    const mutationArgv = (over: Partial<RunContext>): string[] => {
      let seen: string[] = [];
      runAudit(AUDIT_RUNNERS, ctx({
        ...over,
        exec: (_c, argv) => {
          if (argv.includes("mutation-scan")) seen = argv;
          return { ok: true, output: cleanOutput(argv) };
        },
      }));
      return seen;
    };
    expect(mutationArgv({ allowTargetInstall: true })).toContain("--install");
    expect(mutationArgv({})).not.toContain("--install");
    expect(mutationArgv({ allowTargetInstall: false })).not.toContain("--install");
  });

  it("M9 — an empty directory (detect-static: loaded 0 source files, exit 0) is NOT recorded ran", () => {
    const emptyDir = { exec: () => ({ ok: true, output: "loaded 0 source files (0 product-code) from /empty\n\n0 findings across 0 classes:" }) };
    const m9 = status(AUDIT_RUNNERS, emptyDir, "M9");
    expect(m9?.status).not.toBe("ran");
    expect(m9?.reason).toMatch(/0 source files/);
  });

  it("M9 records ran only when the tool reports a non-zero file count", () => {
    expect(status(AUDIT_RUNNERS, {}, "M9")?.status).toBe("ran");
  });
});

describe("a flag is intent, not evidence — no flag alone produces ran (#311/#356)", () => {
  // Every tier flag set, but the flag-gated operator/live passes leave nothing the orchestrator can
  // observe. None of the modules whose `ran` was previously flag-derived may read ran.
  const allFlags = { env: { connected: true, dynamic: true, llm: true } };

  it("M1 stays partial with --connected --llm — the mechanical tier is all the orchestrator ran (#311)", () => {
    const m1 = status(AUDIT_RUNNERS, allFlags, "M1");
    expect(m1?.status).toBe("partial");
    expect(m1?.reason).toMatch(/mechanical tier only/);
  });

  it("M2 stays requires-live-run with --dynamic — a flag is not a reachable stack (#356)", () => {
    const m2 = status(AUDIT_RUNNERS, allFlags, "M2");
    expect(m2?.status).toBe("requires-live-run");
    expect(m2?.reason).toMatch(/flag is not a reachable stack/);
  });

  it("no module reads ran off the flags when the flag-gated passes produced no evidence", () => {
    const flagGated = runAudit(AUDIT_RUNNERS, ctx(allFlags)).recorded.filter((r) => ["M1", "M2", "M6"].includes(r.module));
    expect(flagGated.every((r) => r.status !== "ran")).toBe(true);
  });
});

describe("M6's never-run alarm is not cleared by a review packet (#351)", () => {
  it("M6 with --llm reports partial, never ran — a packet is not a verdict", () => {
    const m6 = status(AUDIT_RUNNERS, { env: { connected: false, dynamic: false, llm: true } }, "M6");
    expect(m6?.status).toBe("partial");
    expect(m6?.status).not.toBe("ran");
    expect(m6?.reason).toMatch(/not a verdict/);
  });

  it("M6 stays in the never-executed ledger after an --llm run — no `ran` was banked to clear it", () => {
    // M6 is the one module absent from audit-execution-log.json; the packet run must not change that.
    expect(MODULES_NEVER_EXECUTED.has("M6")).toBe(true);
    const { recorded } = runAudit(AUDIT_RUNNERS, ctx({ env: { connected: false, dynamic: false, llm: true } }));
    expect(buildAuditCoverage(recorded).neverRun).toContain("M6");
  });
});

// #397: the free indicator layer (src/detectors/handrolled.ts) runs inside detect-static whenever
// M7/M9 do, but the M6 row previously credited none of it — a source-only engagement produced real
// M6 Info findings and still read requires-live-run. Operator ruling: the indicator layer alone is
// `partial` coverage, never a silent requires-live-run when it demonstrably ran, and never `ran`
// (that stays gated on a reviewed verdict per #351).
describe("M6 credits its free indicator layer without a --llm flag (#397)", () => {
  it("reads partial, not requires-live-run, when detect-static confirms the indicator layer ran", () => {
    // Default ctx()'s detect-static fake reports a positive file count (see cleanOutput above).
    const m6 = status(AUDIT_RUNNERS, {}, "M6");
    expect(m6?.status).toBe("partial");
    expect(m6?.reason).toMatch(/free indicator layer ran/i);
  });

  it("never reads `ran` off the indicator layer alone — #351's never-run alarm still needs a verdict", () => {
    const { recorded } = runAudit(AUDIT_RUNNERS, ctx());
    expect(recorded.find((r) => r.module === "M6")?.status).not.toBe("ran");
    expect(buildAuditCoverage(recorded).neverRun).toContain("M6");
  });

  it("stays requires-live-run when detect-static could not confirm a scan (0 files, no llm)", () => {
    const emptyDir = { exec: () => ({ ok: true, output: "loaded 0 source files (0 product-code) from /empty\n\n0 findings across 0 classes:" }) };
    const m6 = status(AUDIT_RUNNERS, emptyDir, "M6");
    expect(m6?.status).toBe("requires-live-run");
    expect(m6?.reason).toMatch(/could not confirm the free indicator layer ran/i);
  });

  it("stays requires-live-run when detect-static's CLI itself fails, no llm", () => {
    const failing = { exec: () => ({ ok: false, output: "detect-static crashed" }) };
    const m6 = status(AUDIT_RUNNERS, failing, "M6");
    expect(m6?.status).toBe("requires-live-run");
    expect(m6?.reason).toMatch(/paid LLM tier not in scope/);
  });

  it("collects the captured M6 — Indicator findings into the deliverable when the layer ran", () => {
    const capturing = ctx({
      captureDir: "/cap",
      readFindings: (p) =>
        p.endsWith("M6.json")
          ? [
              { id: "M6IND-01", title: "t", severity: "Info", confidence: "Confirmed", category: "Maintainability", taxonomy: "M6 — Indicator: JSON deep-equal", location: "l", status: "Open", evidence: "e", impact: "i", fix: "f", value: 1, ease: 1, safety: 1 },
              { id: "OTHER-01", title: "t", severity: "Info", confidence: "Confirmed", category: "c", taxonomy: "not-an-indicator", location: "l", status: "Open", evidence: "e", impact: "i", fix: "f", value: 1, ease: 1, safety: 1 },
            ]
          : [],
    });
    const { recorded, findings } = runAudit(AUDIT_RUNNERS, capturing);
    const m6 = recorded.find((r) => r.module === "M6");
    expect(m6?.status).toBe("partial");
    expect(findings.map((f) => f.id)).toContain("M6IND-01");
    expect(findings.map((f) => f.id)).not.toContain("OTHER-01");
  });
});

describe("M3 derives ran from a real vitals parse, never a no-op exit (#314)", () => {
  it("records ran when hotspot-scan emits the ranked table (vitals report parsed)", () => {
    expect(status(AUDIT_RUNNERS, {}, "M3")?.status).toBe("ran");
  });

  it("records requires-live-run when vitals_cli.py is not on PATH", () => {
    const noVitals = { exec: () => ({ ok: false, output: "vitals_cli.py not found on PATH (#314)" }) };
    const m3 = status(AUDIT_RUNNERS, noVitals, "M3");
    expect(m3?.status).toBe("requires-live-run");
    expect(m3?.reason).toMatch(/vitals/);
  });

  // #515: M3 surfaces its top-K ranking so runAudit can hand it to the assembler for cross-module
  // enrichment. The whole path: probe reads the M3 artifact's topK → runAudit result.hotspots.
  it("surfaces the captured top-K hotspot ranking on the run result", () => {
    const withM3Artifact = ctx({
      captureDir: "/cap",
      readArtifact: (p: string) => (p.endsWith("M3.json") ? { topK: ["core/checkout.ts", "core/pay.ts"], findings: [] } : undefined),
    });
    const { hotspots } = runAudit(AUDIT_RUNNERS, withM3Artifact);
    expect(hotspots).toEqual(["core/checkout.ts", "core/pay.ts"]);
  });
});

// #416: the out-of-orchestrator passes (M1 semantic/live, M2 dynamic, M3 vitals, M6 verdict) leave
// a dated <module>.pass.json; the probe derives `ran` ONLY from a fresh, target-matching one.
describe("probes derive ran from a fresh pass artifact, never a flag (#416)", () => {
  const NOW = Date.parse("2026-07-17T12:00:00Z");
  const DAY = 24 * 60 * 60 * 1000;
  const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();

  // A context whose artifacts dir holds a <module>.pass.json for `module` with the given fields.
  const withPass = (module: AuditModule, fields: Record<string, unknown>, over: Partial<RunContext> = {}) =>
    ctx({
      artifactsDir: "/artifacts",
      now: NOW,
      readArtifact: (p: string) =>
        p.endsWith(`${module}.pass.json`) ? { module, target: "/target", pass: "results", generatedAt: iso(DAY), ...fields } : undefined,
      ...over,
    });

  it("M1 reads ran when a fresh semantic-pass artifact proves the LLM/live tier ran", () => {
    const m1 = status(AUDIT_RUNNERS, withPass("M1", { pass: "semantic" }), "M1");
    expect(m1?.status).toBe("ran");
    expect(m1?.detail).toMatch(/semantic pass/);
  });

  it("M1 carries the pass's triage findings into the deliverable", () => {
    const withFindings = withPass("M1", { findings: [{ id: "TRIAGE-1" }] });
    const { findings } = runAudit(AUDIT_RUNNERS, withFindings);
    expect(findings.some((f) => (f as { id?: string }).id === "TRIAGE-1")).toBe(true);
  });

  // #502: the M3→M1 hotspot focus is a designed dependency — an un-focused semantic pass silently
  // degrades review to un-prioritized, so the ledger detail must make its presence/absence visible.
  it("M1 flags a semantic pass that ran WITHOUT an M3 hotspot focus", () => {
    const noFocus = withPass("M1", { pass: "semantic" }); // hotspotFocus absent
    const m1 = status(AUDIT_RUNNERS, noFocus, "M1");
    expect(m1?.status).toBe("ran");
    expect(m1?.detail).toMatch(/no M3 hotspot focus/i);
  });

  it("M1 records a semantic pass that WAS hotspot-focused", () => {
    const focused = withPass("M1", { pass: "semantic", hotspotFocus: true });
    const m1 = status(AUDIT_RUNNERS, focused, "M1");
    expect(m1?.status).toBe("ran");
    expect(m1?.detail).toMatch(/hotspot-focused/i);
    expect(m1?.detail).not.toMatch(/WARNING/);
  });

  it("M2 reads ran when a fresh dynamic pen-test artifact exists — the reachable-stack evidence #356 wanted", () => {
    expect(status(AUDIT_RUNNERS, withPass("M2", { pass: "dynamic" }), "M2")?.status).toBe("ran");
  });

  it("M6 reads ran when a fresh verdict artifact exists — the one thing that clears its never-run alarm", () => {
    // Note: no --llm flag. A recorded verdict is evidence; the flag is not.
    expect(status(AUDIT_RUNNERS, withPass("M6", { pass: "verdict" }), "M6")?.status).toBe("ran");
  });

  it("M3 reads ran from a captured-vitals artifact when vitals is not on PATH", () => {
    const vitalsDown = withPass("M3", { pass: "vitals" }, { exec: () => ({ ok: false, output: "vitals_cli.py not found" }) });
    expect(status(AUDIT_RUNNERS, vitalsDown, "M3")?.status).toBe("ran");
  });

  // The core guard: a stale or mismatched artifact must NOT yield ran — the probe falls back to its
  // honest not-run status and says the artifact was rejected.
  it("a STALE artifact does not yield ran — M1 falls back to partial and reports the rejection", () => {
    const stale = withPass("M1", { generatedAt: iso(400 * DAY) });
    const m1 = status(AUDIT_RUNNERS, stale, "M1");
    expect(m1?.status).toBe("partial");
    expect(m1?.reason).toMatch(/rejected: pass artifact for M1 is stale/);
  });

  it("a WRONG-TARGET artifact does not yield ran — M2 stays requires-live-run and flags the mismatch", () => {
    const wrong = withPass("M2", { target: "/some-other-app" });
    const m2 = status(AUDIT_RUNNERS, wrong, "M2");
    expect(m2?.status).toBe("requires-live-run");
    expect(m2?.reason).toMatch(/rejected:.*not the audited target/);
  });

  it("no artifacts dir ⇒ the #311/#356/#351 behaviour is exactly unchanged", () => {
    // Regression guard for the existing flag-is-not-evidence tests: without an artifacts dir the
    // four probes must report precisely what they did before #416.
    const bare = runAudit(AUDIT_RUNNERS, ctx({ env: { connected: true, dynamic: true, llm: true } })).recorded;
    expect(bare.find((r) => r.module === "M1")?.status).toBe("partial");
    expect(bare.find((r) => r.module === "M2")?.status).toBe("requires-live-run");
    expect(bare.find((r) => r.module === "M6")?.status).toBe("partial");
  });
});

// #436: pii-classify emits report-schema Finding[] to --out, so a capturing run collects M10
// findings; the live tier can finally read `ran`, and the schema tier's partial reason shrinks to
// the honest gap that remains (rows not sampled), not a collection gap.
describe("M10 captures its classification findings (#436)", () => {
  const capture: Partial<RunContext> = {
    captureDir: "/cap",
    readFindings: (p: string) => (p.endsWith("M10.json") ? [{ id: "M10-01" } as never] : []),
  };

  it("schema tier stays partial for the live-DB gap alone, with its findings captured", () => {
    const { recorded, findings } = runAudit(AUDIT_RUNNERS, ctx(capture));
    const m10 = recorded.find((r) => r.module === "M10");
    expect(m10?.status).toBe("partial");
    expect(m10?.reason).toMatch(/schema tier only/);
    expect(m10?.reason).not.toMatch(/collected into this deliverable/);
    expect(findings.some((f) => (f as { id?: string }).id === "M10-01")).toBe(true);
  });

  it("live tier reads ran once its findings are captured — the #420 non-collection partial is retired", () => {
    const m10 = status(AUDIT_RUNNERS, { ...capture, env: { connected: true, dynamic: false, llm: false } }, "M10");
    expect(m10?.status).toBe("ran");
  });

  it("a coverage-only run (no capture) still discloses that findings were not collected", () => {
    const m10 = status(AUDIT_RUNNERS, {}, "M10");
    expect(m10?.status).toBe("partial");
    expect(m10?.reason).toMatch(/not-collected, not clean/);
  });
});

// #506: on a monorepo the per-app tiers (M4/M5/M9, M10 schema) and the per-DB tier (M7 advisors)
// fan out — one probe run and one ledger row per enumerated instance. A single-app/single-DB target
// enumerates one instance and behaves exactly as before (no per-instance rows).
describe("monorepo per-instance fan-out (#506)", () => {
  const apps = [
    { name: "apps/main", path: "/target/apps/main" },
    { name: "apps/rag", path: "/target/apps/rag" },
  ];

  it("M4/M5/M9 record one row per enumerated app, tagged with the app name", () => {
    const rec = runAudit(AUDIT_RUNNERS, ctx({ apps })).recorded;
    for (const m of ["M4", "M5", "M9"] as const) {
      const rows = rec.filter((r) => r.module === m);
      expect(rows.map((r) => r.instance).sort()).toEqual(["apps/main", "apps/rag"]);
    }
  });

  it("runs each per-app probe against that app's own directory, not the repo root", () => {
    const seen: string[] = [];
    runAudit(AUDIT_RUNNERS, ctx({
      apps,
      exec: (_c, argv) => {
        if (argv.includes("quality-scan")) seen.push(argv[argv.indexOf("quality-scan") + 1]!);
        return { ok: true, output: cleanOutput(argv) };
      },
    }));
    expect(seen).toEqual(expect.arrayContaining(["/target/apps/main", "/target/apps/rag"]));
  });

  it("an app missing node_modules is an explicit requires-live-run row for THAT app, never absent (M5)", () => {
    const rec = runAudit(AUDIT_RUNNERS, ctx({ apps, exists: (p) => p !== "/target/apps/rag/node_modules" })).recorded;
    const m5 = rec.filter((r) => r.module === "M5");
    expect(m5).toHaveLength(2);
    expect(m5.find((r) => r.instance === "apps/rag")?.status).toBe("requires-live-run");
    expect(m5.find((r) => r.instance === "apps/rag")?.reason).toMatch(/no node_modules/);
    expect(m5.find((r) => r.instance === "apps/main")?.status).toBe("ran");
  });

  it("M7 advisors record one row per enumerated Supabase project", () => {
    const m7 = runAudit(AUDIT_RUNNERS, ctx({
      env: { connected: true, dynamic: false, llm: false },
      supabaseRefs: ["proj-main", "proj-rag"],
      exec: (_c, argv) => (argv.includes("perf-scan") ? { ok: true, output: "" } : { ok: true, output: cleanOutput(argv) }),
    })).recorded.filter((r) => r.module === "M7");
    expect(m7.map((r) => r.instance).sort()).toEqual(["proj-main", "proj-rag"]);
    // #527: advisor success is `partial` (Lighthouse/CWV tier unmeasured), never `ran`.
    expect(m7.every((r) => r.status === "partial")).toBe(true);
    expect(m7.every((r) => /Lighthouse\/CWV tier not run/.test(r.reason ?? ""))).toBe(true);
  });

  it("a failed advisor for one project names the advisor failure; the other names the Lighthouse gap", () => {
    const m7 = runAudit(AUDIT_RUNNERS, ctx({
      env: { connected: true, dynamic: false, llm: false },
      supabaseRefs: ["proj-main", "proj-rag"],
      exec: (_c, argv) => {
        if (argv.includes("perf-scan")) return { ok: !argv.includes("proj-rag"), output: "advisors 500" };
        return { ok: true, output: cleanOutput(argv) };
      },
    })).recorded.filter((r) => r.module === "M7");
    // #527: both rows are partial now, but for different reasons — the coverage guard needs each row
    // to say why it fell short, so distinguish by reason, not status.
    expect(m7.find((r) => r.instance === "proj-rag")?.status).toBe("partial");
    expect(m7.find((r) => r.instance === "proj-rag")?.reason).toMatch(/advisors failed/);
    expect(m7.find((r) => r.instance === "proj-main")?.status).toBe("partial");
    expect(m7.find((r) => r.instance === "proj-main")?.reason).toMatch(/Lighthouse\/CWV tier not run/);
  });

  it("M10 live tier names every extra Supabase project it could not reach, never dropping one", () => {
    const m10 = runAudit(AUDIT_RUNNERS, ctx({
      env: { connected: true, dynamic: false, llm: false },
      supabaseRefs: ["proj-main", "proj-rag"],
    })).recorded.filter((r) => r.module === "M10");
    expect(m10.map((r) => r.instance).sort()).toEqual(["proj-main", "proj-rag"]);
    const rag = m10.find((r) => r.instance === "proj-rag");
    expect(rag?.status).toBe("requires-live-run");
    expect(rag?.reason).toMatch(/env-bound to one DB/);
  });

  it("M10 schema tier fans out one partial row per app", () => {
    const m10 = runAudit(AUDIT_RUNNERS, ctx({ apps })).recorded.filter((r) => r.module === "M10");
    expect(m10.map((r) => r.instance).sort()).toEqual(["apps/main", "apps/rag"]);
    expect(m10.every((r) => r.status === "partial")).toBe(true);
  });

  it("a single-app / single-DB target is unchanged — one untagged row per module", () => {
    const rec = runAudit(AUDIT_RUNNERS, ctx({ apps: [{ name: "root", path: "/target" }] })).recorded;
    expect(rec.filter((r) => r.module === "M5")).toHaveLength(1);
    expect(rec.find((r) => r.module === "M5")?.instance).toBeUndefined();
  });

  it("the whole per-instance ledger still passes the coverage gate with no gaps", () => {
    const rec = runAudit(AUDIT_RUNNERS, ctx({ apps })).recorded;
    expect(buildAuditCoverage(rec, ctx().env).gaps).toEqual([]);
  });
});

describe("formatFailures", () => {
  it("names each crashed module and calls the crash a bug, not a tier", () => {
    const out = formatFailures([{ module: "M4", error: "jscpd binary missing" }]);
    expect(out).toMatch(/M4 \(Duplication\): jscpd binary missing/);
    expect(out).toMatch(/not a tier/);
  });
});
