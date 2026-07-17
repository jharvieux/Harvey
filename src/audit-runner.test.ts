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

  it("M7 threads ctx.supabaseRef through to perf-scan's positional arg, reaching ran", () => {
    const connectedWithRef = ctx({
      env: { connected: true, dynamic: false, llm: false },
      supabaseRef: "my-project-ref",
      exec: (_c, argv) => (argv.includes("perf-scan") ? { ok: argv.includes("my-project-ref"), output: "" } : { ok: true, output: cleanOutput(argv) }),
    });
    const m7 = runAudit(AUDIT_RUNNERS, connectedWithRef).recorded.find((r) => r.module === "M7");
    expect(m7?.status).toBe("ran");
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

  it("M8 — no test suite (moduleRecord partial, exit 0) is NOT recorded ran", () => {
    // mutation-scan's #224 branch: the correct verdict is serialized and must be read, not discarded.
    const noSuite = { exec: () => ({ ok: true, output: JSON.stringify({ finding: { id: "M8-00" }, moduleRecord: { status: "partial", note: "No automated test suite found (no scripts.test) — mutation scan could not run." } }) }) };
    const m8 = status(AUDIT_RUNNERS, noSuite, "M8");
    expect(m8?.status).not.toBe("ran");
    expect(m8?.status).toBe("partial");
    expect(m8?.reason).toMatch(/no automated test suite/i);
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

describe("formatFailures", () => {
  it("names each crashed module and calls the crash a bug, not a tier", () => {
    const out = formatFailures([{ module: "M4", error: "jscpd binary missing" }]);
    expect(out).toMatch(/M4 \(Duplication\): jscpd binary missing/);
    expect(out).toMatch(/not a tier/);
  });
});
