import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assertAuditComplete, AUDIT_MODULES, buildAuditCoverage, type AuditModule } from "./audit-coverage.js";
import { assertRegistryComplete, formatFailures, type ModuleRunner, type ProbeOutcome, type RunContext } from "./audit-runner.js";
import { discoverSchemaFiles } from "./dynamic-validate.js";
import type { Finding } from "./findings.js";
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
  if (cmd.includes("detect-static")) return "loaded 42 source files (30 product source, 2 config, 10 test/story) from /target\n\n3 findings across 2 classes:";
  if (cmd.includes("hotspot-scan.ts")) return "M3 hotspot table — /target (5 rows, worst first)";
  if (cmd.includes("pentest.ts")) return JSON.stringify({ findings: [] });
  return "";
};

const ctx = (over: Partial<RunContext> = {}): RunContext => ({
  targetDir: "/target",
  env: { connected: false, dynamic: false, llm: false },
  exec: (_command, argv) => ({ ok: true, output: cleanOutput(argv) }),
  exists: () => true,
  isGitRepoRoot: () => true,
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
    // Every module reports `ran`, so the coverage gate is satisfied and the never-run ledger (now
    // empty since #283 cleared M6) has nothing to block on — see #284 below.
    expect(buildAuditCoverage(recorded).complete).toBe(true);
  });
});

describe("the real ten probes (AUDIT_RUNNERS)", () => {
  it("registers every module of M1–M10", () => {
    expect(() => assertRegistryComplete(AUDIT_RUNNERS)).not.toThrow();
  });

  // Each probe must gather its OWN evidence. These drive the real probes against a fake environment
  // and assert the prereq actually gates the outcome.
  // #1035: a deps-free target is a REDUCED tier, not an unrunnable one — #810 built the fallback
  // and this probe used to refuse to reach it. The distinction it was protecting survives as a
  // status: quality-scan is invoked, M5 records partial, and file-level dead code stays review-tier.
  it("M5 without the target's installed deps still invokes quality-scan and records partial, not requires-live-run", () => {
    const invoked: string[] = [];
    const noDeps = ctx({
      exists: (p) => !p.endsWith("node_modules"),
      exec: (_c, argv) => {
        if (argv.includes("quality-scan")) invoked.push(argv.join(" "));
        return { ok: true, output: cleanOutput(argv) };
      },
    });
    const m5 = runAudit(AUDIT_RUNNERS, noDeps).recorded.find((r) => r.module === "M5");
    expect(invoked.length).toBeGreaterThan(0);
    expect(m5?.status).toBe("partial");
    expect(m5?.reason).toMatch(/review-tier, not confirmed/);
  });

  // The #810 reduced tier discloses itself with an M5-98 row; the orchestrator must surface THAT
  // reason rather than a generic partial, so a reader knows plugins were disabled.
  it("M5 reports the #810 reduced tier when quality-scan emitted M5-98", () => {
    const reduced = ctx({
      exists: (p) => !p.endsWith("node_modules"),
      exec: (_c, argv) => (argv.includes("quality-scan") ? { ok: true, output: JSON.stringify([{ id: "M5-98" }]) } : { ok: true, output: cleanOutput(argv) }),
    });
    const m5 = runAudit(AUDIT_RUNNERS, reduced).recorded.find((r) => r.module === "M5");
    expect(m5?.status).toBe("partial");
    expect(m5?.reason).toMatch(/reduced \(no-dependencies\) tier/);
  });

  it("M5 runs once the target's deps are present — the prereq gates it, not a flag", () => {
    expect(runAudit(AUDIT_RUNNERS, ctx()).recorded.find((r) => r.module === "M5")?.status).toBe("ran");
  });

  // #771: mutation-scan's own suite-absence check is a static package.json/test-file read — no
  // installed deps needed — so it must be invoked (and its verdict trusted) whether or not
  // node_modules exists. A target that genuinely HAS a suite but no node_modules degrades through
  // mutation-scan's own ladder (partial, naming --install) rather than a blanket M8-probe fallback.
  it("M8 without node_modules still invokes mutation-scan, reading its suite-exists-no-install verdict as partial", () => {
    const noDeps = ctx({
      exists: (p) => !p.endsWith("node_modules"),
      exec: (_c, argv) =>
        argv.includes("mutation-scan")
          ? { ok: true, output: JSON.stringify({ moduleRecord: { status: "partial", note: "Mutation scoring did not run: the target has a vitest suite but no Stryker install (@stryker-mutator/core, @stryker-mutator/vitest-runner missing) — re-run with --install to provision them." } }) }
          : { ok: true, output: cleanOutput(argv) },
    });
    const m8 = runAudit(AUDIT_RUNNERS, noDeps).recorded.find((r) => r.module === "M8");
    expect(m8?.status).toBe("partial");
    expect(m8?.reason).toMatch(/--install/);
  });

  // #771: the bug this regression guards — a no-package.json / no-tests target has no node_modules
  // EITHER, and the M8 probe used to short-circuit before ever calling mutation-scan, so the M8-00
  // zero-coverage finding was never emitted (a bare "partial, add node_modules" with no verdict).
  // mutation-scan's suite-absence detection needs no installed deps, so it must run regardless and
  // its `noSuite` verdict must read `ran` with the M8-00 finding captured into the deliverable —
  // exactly the #754 no-suite mapping, now reachable from a target with no node_modules too.
  it("M8 — a no-package.json / no-tests target (no node_modules) still reads ran with the M8-00 finding (#771)", () => {
    const noSuiteRecord = { status: "partial" as const, noSuite: true, note: "No automated test suite found (no package.json found; no known test-runner dependency; no stryker.conf.*) — mutation scan could not run." };
    const artifact = { finding: { id: "M8-00" }, moduleRecord: noSuiteRecord };
    const noPackageJson = ctx({
      exists: (p) => !p.endsWith("node_modules"),
      captureDir: "/capture",
      readArtifact: () => artifact,
      exec: (_c, argv) => (argv.includes("mutation-scan") ? { ok: true, output: JSON.stringify(artifact) } : { ok: true, output: cleanOutput(argv) }),
    });
    const { recorded, findings } = runAudit(AUDIT_RUNNERS, noPackageJson);
    const m8 = recorded.find((r) => r.module === "M8");
    expect(m8?.status).toBe("ran");
    expect(findings.map((f) => f.id)).toContain("M8-00");
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

  it("M10 has nothing to classify with neither a DB nor any conventional schema layout", () => {
    // #529/#758: the probe now tries supabase/migrations, prisma/migrations, drizzle/, db/,
    // schema.sql, schema.prisma — so "nothing to classify" means none of them exist, and the
    // reason lists what was probed.
    const bare = ctx({ exists: (p) => !/(migrations|drizzle|\/db$|schema\.(sql|prisma))/.test(p) });
    const m10 = runAudit(AUDIT_RUNNERS, bare).recorded.find((r) => r.module === "M10");
    expect(m10?.status).toBe("requires-live-run");
    expect(m10?.reason).toMatch(/nothing to classify/);
    expect(m10?.reason).toMatch(/Probed:/);
    expect(m10?.reason).toMatch(/prisma\/migrations/);
  });

  // #529: a non-Supabase target (Prisma/Drizzle/pg_dump) whose schema is not at supabase/migrations
  // still gets real M10 schema classification, not a bare "nothing to classify".
  it("M10 classifies a Prisma-layout target (prisma/migrations, no supabase/migrations)", () => {
    const prismaOnly = ctx({ exists: (p) => !p.includes(join("supabase", "migrations")) });
    const m10 = runAudit(AUDIT_RUNNERS, prismaOnly).recorded.find((r) => r.module === "M10");
    expect(m10?.status).toBe("partial");
    expect(m10?.detail).toMatch(/prisma[/\\]migrations/);
  });

  // #529: an explicit --schema hint (ctx.schemaHint) wins over the conventional-location probe.
  it("M10 uses the --schema hint ahead of the conventional-location probe", () => {
    const seen: string[] = [];
    runAudit(AUDIT_RUNNERS, ctx({
      schemaHint: "/given/schema.sql",
      exec: (_c, argv) => {
        if (argv.includes("pii-classify")) seen.push(argv[argv.indexOf("--schema") + 1]!);
        return { ok: true, output: cleanOutput(argv) };
      },
    }));
    expect(seen).toContain("/given/schema.sql");
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

// #770: the schema tier's candidate probe only recognized conventionally-named/located schema DDL
// (supabase/migrations, prisma/migrations, drizzle, db/migrations, db, migrations, schema.sql) — a
// target shipping it anywhere else (launch-mvp's root `initial_supabase_table_schema.sql`,
// nocode-rescue's nested `before/schema.sql`) got a misleading "nothing to classify" even though real
// schema DDL sat right there on disk. Real temp-dir fixtures (not the fake in-memory ctx() above)
// prove discovery finds them and the probe actually uses what it found.
describe("M10 discovers schema DDL beyond the conventional locations (#770)", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("finds a root-level, unconventionally-named schema file (launch-mvp shape) and classifies it", () => {
    const app = mkdtempSync(join(tmpdir(), "harvey-m10-launch-mvp-"));
    dirs.push(app);
    writeFileSync(join(app, "initial_supabase_table_schema.sql"), "create table customers (id uuid primary key, email text not null);");

    const seenArgv: string[][] = [];
    const m10 = runAudit(AUDIT_RUNNERS, ctx({
      targetDir: app,
      exists: existsSync,
      discoverSchemaFiles,
      exec: (_c, argv) => {
        if (argv.includes("pii-classify")) seenArgv.push(argv);
        return { ok: true, output: cleanOutput(argv) };
      },
    })).recorded.find((r) => r.module === "M10");

    expect(m10?.status).toBe("partial");
    expect(m10?.reason).toMatch(/schema tier only/);
    expect(seenArgv[0]).toContain(join(app, "initial_supabase_table_schema.sql"));
  });

  it("finds a nested schema.sql under a non-conventional directory (nocode-rescue shape)", () => {
    const app = mkdtempSync(join(tmpdir(), "harvey-m10-nocode-rescue-"));
    dirs.push(app);
    mkdirSync(join(app, "before"));
    writeFileSync(join(app, "before", "schema.sql"), "create table applicants (id uuid primary key, customer_ssn text);");

    const m10 = runAudit(AUDIT_RUNNERS, ctx({ targetDir: app, exists: existsSync, discoverSchemaFiles })).recorded.find((r) => r.module === "M10");

    expect(m10?.status).toBe("partial");
    expect(m10?.detail).toMatch(/before[/\\]schema\.sql/);
  });

  // The exact pre-#770 symptom: without discovery wired, the SAME fixture the fix above classifies
  // goes right back to "nothing to classify" — proving discovery (not the parser) closed the gap.
  it("without discovery wired, the same launch-mvp-shaped fixture reverts to the pre-#770 'nothing to classify' gap", () => {
    const app = mkdtempSync(join(tmpdir(), "harvey-m10-no-discovery-"));
    dirs.push(app);
    writeFileSync(join(app, "initial_supabase_table_schema.sql"), "create table customers (id uuid primary key, email text not null);");

    const m10 = runAudit(AUDIT_RUNNERS, ctx({ targetDir: app, exists: existsSync })).recorded.find((r) => r.module === "M10");
    expect(m10?.status).toBe("requires-live-run");
    expect(m10?.reason).toMatch(/nothing to classify/);
  });

  it("feeds every discovered file to pii-classify when schema DDL is scattered across more than one unconventional location", () => {
    const app = mkdtempSync(join(tmpdir(), "harvey-m10-multi-"));
    dirs.push(app);
    writeFileSync(join(app, "initial_supabase_table_schema.sql"), "create table customers (id uuid primary key, email text not null);");
    mkdirSync(join(app, "before"));
    writeFileSync(join(app, "before", "schema.sql"), "create table applicants (id uuid primary key, customer_ssn text);");

    const seenArgv: string[][] = [];
    runAudit(AUDIT_RUNNERS, ctx({
      targetDir: app,
      exists: existsSync,
      discoverSchemaFiles,
      exec: (_c, argv) => {
        if (argv.includes("pii-classify")) seenArgv.push(argv);
        return { ok: true, output: cleanOutput(argv) };
      },
    }));
    const schemaArgs = seenArgv[0]!.slice(seenArgv[0]!.indexOf("--schema") + 1);
    expect(schemaArgs).toContain(join(app, "initial_supabase_table_schema.sql"));
    expect(schemaArgs).toContain(join(app, "before", "schema.sql"));
  });
});

// #758: a Prisma app declares its schema in schema.prisma, not SQL migrations — before this, a
// Prisma app that hadn't generated any migrations yet (the common shape for a freshly-scaffolded or
// `prisma db push`-only app) had no candidate the schema-tier probe recognized at all, and fell all
// the way to "nothing to classify" even with a real, readable schema sitting right there.
describe("M10 classifies a Prisma app's schema.prisma when no migrations have been generated (#758)", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("finds prisma/schema.prisma and feeds it to pii-classify --schema", () => {
    const app = mkdtempSync(join(tmpdir(), "harvey-m10-prisma-schema-"));
    dirs.push(app);
    mkdirSync(join(app, "prisma"), { recursive: true });
    writeFileSync(join(app, "prisma", "schema.prisma"), "model Customer {\n  id String @id\n  email String\n}\n");

    const seenArgv: string[][] = [];
    const m10 = runAudit(AUDIT_RUNNERS, ctx({
      targetDir: app,
      exists: existsSync,
      exec: (_c, argv) => {
        if (argv.includes("pii-classify")) seenArgv.push(argv);
        return { ok: true, output: cleanOutput(argv) };
      },
    })).recorded.find((r) => r.module === "M10");

    expect(m10?.status).toBe("partial");
    expect(m10?.detail).toMatch(/prisma[/\\]schema\.prisma/);
    expect(seenArgv[0]).toContain(join(app, "prisma", "schema.prisma"));
  });

  it("finds a root-level schema.prisma too", () => {
    const app = mkdtempSync(join(tmpdir(), "harvey-m10-prisma-root-"));
    dirs.push(app);
    writeFileSync(join(app, "schema.prisma"), "model Customer {\n  id String @id\n  email String\n}\n");

    const m10 = runAudit(AUDIT_RUNNERS, ctx({ targetDir: app, exists: existsSync })).recorded.find((r) => r.module === "M10");
    expect(m10?.status).toBe("partial");
    expect(m10?.detail).toMatch(/schema\.prisma/);
  });

  it("prefers a generated prisma/migrations SQL migration over the raw schema.prisma when both exist", () => {
    const app = mkdtempSync(join(tmpdir(), "harvey-m10-prisma-both-"));
    dirs.push(app);
    mkdirSync(join(app, "prisma", "migrations", "0001_init"), { recursive: true });
    writeFileSync(join(app, "prisma", "migrations", "0001_init", "migration.sql"), 'create table "Customer" (id text primary key, email text);');
    writeFileSync(join(app, "prisma", "schema.prisma"), "model Customer {\n  id String @id\n  email String\n}\n");

    const m10 = runAudit(AUDIT_RUNNERS, ctx({ targetDir: app, exists: existsSync })).recorded.find((r) => r.module === "M10");
    expect(m10?.detail).toMatch(/prisma[/\\]migrations/);
    expect(m10?.detail).not.toMatch(/schema\.prisma/);
  });
});

// #620: on a monorepo, per-app tiers fan out and each app's probe emits the SAME finding ids
// (SLOP-01, M9-01, …). Before the fix the assembled document carried duplicate ids and
// --findings-out failed schema validation, so the engagement findings.json was never written.
describe("monorepo fan-out namespaces finding ids by instance (#620)", () => {
  const withId = (id: string): Finding => ({ id } as unknown as Finding);
  const swap = (module: AuditModule, run: ModuleRunner["run"]) => allRan().map((r) => (r.module === module ? { module, run } : r));

  it("distinguishes the same finding id emitted by two apps so ids stay unique", () => {
    const runners = swap("M5", () => [
      { status: "ran", detail: "knip apps/main", instance: "apps/main", findings: [withId("SLOP-01")] },
      { status: "ran", detail: "knip apps/rag", instance: "apps/rag", findings: [withId("SLOP-01")] },
    ]);
    const ids = runAudit(runners, ctx()).findings.map((f) => f.id);
    expect(ids).toContain("SLOP-01@apps/main");
    expect(ids).toContain("SLOP-01@apps/rag");
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("leaves ids unchanged on a single-target (no instance) run", () => {
    const runners = swap("M5", () => ({ status: "ran", detail: "knip", findings: [withId("SLOP-01")] }));
    expect(runAudit(runners, ctx()).findings.map((f) => f.id)).toContain("SLOP-01");
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

  // #754: "no test suite at all" is a COMPLETE assessment — the M8-00 zero-coverage finding IS the
  // verdict (CLAUDE.md / #224) — so it must read `ran`, not `partial`. `partial` is reserved for a
  // suite that EXISTS but the measurement itself fell short (dry-run failure, degraded ladder,
  // scoped subset — covered below). A `ran` status with no findings captured would silently drop
  // the M8-00 finding from the deliverable, so this also asserts the finding survives capture.
  it("M8 — no test suite at all reads ran, with the M8-00 finding captured (#754)", () => {
    const noSuiteRecord = { status: "partial" as const, noSuite: true, note: "No automated test suite found (no scripts.test) — mutation scan could not run." };
    const artifact = { finding: { id: "M8-00" }, moduleRecord: noSuiteRecord };
    const noSuite = ctx({
      captureDir: "/capture",
      readArtifact: () => artifact,
      exec: (_c, argv) => (argv.includes("mutation-scan") ? { ok: true, output: JSON.stringify(artifact) } : { ok: true, output: cleanOutput(argv) }),
    });
    const { recorded, findings } = runAudit(AUDIT_RUNNERS, noSuite);
    const m8 = recorded.find((r) => r.module === "M8");
    expect(m8?.status).toBe("ran");
    expect(findings.map((f) => f.id)).toContain("M8-00");
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
    const emptyDir = { exec: () => ({ ok: true, output: "loaded 0 source files (0 product source, 0 config, 0 test/story) from /empty\n\n0 findings across 0 classes:" }) };
    const m9 = status(AUDIT_RUNNERS, emptyDir, "M9");
    expect(m9?.status).not.toBe("ran");
    expect(m9?.reason).toMatch(/0 product source files/);
  });

  it("M9 records ran only when the tool reports a non-zero file count", () => {
    expect(status(AUDIT_RUNNERS, {}, "M9")?.status).toBe("ran");
  });

  // #1065: the guard above was unreachable. loadSources reads package.json and next.config.js on
  // every target, so a run that opened nothing BUT those still printed a non-zero total and read
  // `ran`. That is exactly what a plain-JavaScript app produced. Only the PRODUCT SOURCE count is
  // evidence code was read — for M9 and for M6/M7, which share the same output.
  it("M9/M6/M7 — config files alone are not a scan, however many the tool loaded", () => {
    const configOnly = { exec: () => ({ ok: true, output: "loaded 2 source files (0 product source, 2 config, 0 test/story) from /target\n\n0 findings across 0 classes:" }) };
    for (const module of ["M9", "M7"] as const) {
      const row = status(AUDIT_RUNNERS, configOnly, module);
      expect(row?.status).toBe("requires-live-run");
      expect(row?.reason).toMatch(/0 product source files/);
    }
    // M6's indicator tier degrades to its own not-run reason rather than crediting the layer.
    expect(status(AUDIT_RUNNERS, configOnly, "M6")?.status).not.toBe("partial");
  });
});

// #682: M8 has two sub-steps — the source-only test-intent tier and the Stryker mutation tier. When
// the mutation sub-step is BLOCKED (a non-zero exit / unrecognized output, e.g. the #623 harness
// failure) the probe must NOT drop to requires-live-run and discard the test-intent tier's already-
// produced findings (the ATC silent drop). It degrades to partial WITH those findings and flags the
// blocked sub-step — unless the test-intent tier could not scan either, which is a genuine not-run.
describe("a blocked M8 mutation sub-step keeps the test-intent tier's findings (#682)", () => {
  const m8Static = { id: "M8-53", taxonomy: "M8 — Tenant-isolation test mocks the DB client" } as unknown as Finding;
  const withStatic = (over: Partial<RunContext>): RunContext =>
    ctx({
      captureDir: "/cap",
      readFindings: (p: string) => (p.endsWith("M8-static.json") ? [m8Static] : []),
      readArtifact: () => undefined,
      ...over,
    });

  it("a non-zero mutation-scan exit reads partial+sub-step-blocked and keeps the test-intent findings", () => {
    const blocked = withStatic({
      exec: (_c, argv) => (argv.includes("mutation-scan") ? { ok: false, output: "TypeError undefined (harness #623)" } : { ok: true, output: cleanOutput(argv) }),
    });
    const { recorded, findings } = runAudit(AUDIT_RUNNERS, blocked);
    const m8 = recorded.find((r) => r.module === "M8");
    expect(m8?.status).toBe("partial");
    expect(m8?.status).not.toBe("requires-live-run");
    expect(m8?.subStatus).toBe("sub-step-blocked");
    expect(m8?.reason).toMatch(/mutation tier blocked/i);
    // The completed sub-step's findings survive into the deliverable — the silent drop this closes.
    expect(findings.map((f) => f.id)).toContain("M8-53");
  });

  it("an unrecognized mutation verdict also degrades to partial+sub-step-blocked, findings kept", () => {
    const unknown = withStatic({
      exec: (_c, argv) => (argv.includes("mutation-scan") ? { ok: true, output: "not json at all" } : { ok: true, output: cleanOutput(argv) }),
    });
    const { recorded, findings } = runAudit(AUDIT_RUNNERS, unknown);
    const m8 = recorded.find((r) => r.module === "M8");
    expect(m8?.status).toBe("partial");
    expect(m8?.subStatus).toBe("sub-step-blocked");
    expect(findings.map((f) => f.id)).toContain("M8-53");
  });

  it("stays requires-live-run (no findings produced) when the test-intent tier could not scan either", () => {
    const bothDown = ctx({
      exec: (_c, argv) => {
        if (argv.includes("mutation-scan")) return { ok: false, output: "crash" };
        if (argv.includes("detect-static")) return { ok: true, output: "loaded 0 source files (0 product source, 0 config, 0 test/story) from /empty" };
        return { ok: true, output: cleanOutput(argv) };
      },
    });
    const m8 = status(AUDIT_RUNNERS, bothDown, "M8");
    expect(m8?.status).toBe("requires-live-run");
    expect(m8?.subStatus).toBeUndefined();
    expect(m8?.reason).toMatch(/could not scan either/);
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

  it("a packet-only --llm run banks no `ran`, so it could never clear a never-run alarm", () => {
    // #283 recorded a REAL reviewed verdict, so the live ledger no longer flags M6. The invariant
    // #351 protects — that a bare packet run does NOT clear the alarm — is shown against a synthetic
    // ledger: the probe reports a non-`ran` status, so a never-run M6 stays flagged.
    const { recorded } = runAudit(AUDIT_RUNNERS, ctx({ env: { connected: false, dynamic: false, llm: true } }));
    expect(recorded.find((r) => r.module === "M6")?.status).not.toBe("ran");
    expect(buildAuditCoverage(recorded, undefined, new Set<AuditModule>(["M6"])).neverRun).toContain("M6");
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
    // Against a synthetic never-run ledger (the live one is empty since #283), a non-`ran` indicator
    // row leaves M6 flagged — the alarm still turns on the verdict, not the indicator layer.
    expect(buildAuditCoverage(recorded, undefined, new Set<AuditModule>(["M6"])).neverRun).toContain("M6");
  });

  it("stays requires-live-run when detect-static could not confirm a scan (0 files, no llm)", () => {
    const emptyDir = { exec: () => ({ ok: true, output: "loaded 0 source files (0 product source, 0 config, 0 test/story) from /empty\n\n0 findings across 0 classes:" }) };
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

// #683 (sibling of #682): M6's --llm run has two sub-steps — the free indicator tier (detect-static)
// and the paid simplify-scan packet. When simplify-scan is BLOCKED (non-zero exit) the probe must NOT
// drop to requires-live-run and discard the indicator tier's already-collected findings (the same
// silent drop #682 closed for M8). It degrades to partial WITH those findings and flags the blocked
// sub-step — unless the indicator tier could not scan either, which is a genuine not-run.
describe("a blocked M6 simplify-scan keeps the indicator tier's findings (#683)", () => {
  const llmEnv = { env: { connected: false, dynamic: false, llm: true } };
  const m6Indicator = {
    id: "M6IND-01",
    title: "t",
    severity: "Info",
    confidence: "Confirmed",
    category: "Maintainability",
    taxonomy: "M6 — Indicator: JSON deep-equal",
    location: "l",
    status: "Open",
    evidence: "e",
    impact: "i",
    fix: "f",
    value: 1,
    ease: 1,
    safety: 1,
  } as unknown as Finding;
  const withIndicator = (over: Partial<RunContext>): RunContext =>
    ctx({
      ...llmEnv,
      captureDir: "/cap",
      readFindings: (p: string) => (p.endsWith("M6.json") ? [m6Indicator] : []),
      ...over,
    });

  it("a non-zero simplify-scan reads partial+sub-step-blocked and keeps the indicator findings", () => {
    const blocked = withIndicator({
      exec: (_c, argv) => (argv.includes("simplify-scan") ? { ok: false, output: "packet assembly crashed" } : { ok: true, output: cleanOutput(argv) }),
    });
    const { recorded, findings } = runAudit(AUDIT_RUNNERS, blocked);
    const m6 = recorded.find((r) => r.module === "M6");
    expect(m6?.status).toBe("partial");
    expect(m6?.status).not.toBe("requires-live-run");
    expect(m6?.subStatus).toBe("sub-step-blocked");
    expect(m6?.reason).toMatch(/simplify-scan sub-step blocked/i);
    // The completed sub-step's findings survive into the deliverable — the silent drop this closes.
    expect(findings.map((f) => f.id)).toContain("M6IND-01");
  });

  it("stays requires-live-run (no findings) when the indicator tier could not scan either", () => {
    const bothDown = ctx({
      ...llmEnv,
      exec: (_c, argv) => {
        if (argv.includes("simplify-scan")) return { ok: false, output: "crash" };
        if (argv.includes("detect-static")) return { ok: true, output: "loaded 0 source files (0 product source, 0 config, 0 test/story) from /empty" };
        return { ok: true, output: cleanOutput(argv) };
      },
    });
    const m6 = status(AUDIT_RUNNERS, bothDown, "M6");
    expect(m6?.status).toBe("requires-live-run");
    expect(m6?.subStatus).toBeUndefined();
    expect(m6?.reason).toMatch(/could not scan either/);
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

  // #530: the vitals-off-PATH flow — M3 ran via a pass artifact carrying its top-K ranking, so the
  // cross-module enrichment (#515) must fire here too, not only on the in-process capture path.
  it("M3 surfaces the pass artifact's top-K ranking so run-audit hands it to the assembler", () => {
    const withRanking = withPass(
      "M3",
      { pass: "vitals", hotspots: ["core/checkout.ts", "core/pay.ts"] },
      { exec: () => ({ ok: false, output: "vitals_cli.py not found" }) },
    );
    const { recorded, hotspots } = runAudit(AUDIT_RUNNERS, withRanking);
    expect(recorded.find((r) => r.module === "M3")?.status).toBe("ran");
    expect(hotspots).toEqual(["core/checkout.ts", "core/pay.ts"]);
  });

  it("M3 pass artifact without a ranking yields no hotspots — enrichment simply does not fire", () => {
    const noRanking = withPass("M3", { pass: "vitals" }, { exec: () => ({ ok: false, output: "vitals_cli.py not found" }) });
    expect(runAudit(AUDIT_RUNNERS, noRanking).hotspots).toBeUndefined();
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

  // #1042: record-pass accepted all ten modules while only four probes read the artifact, so a
  // recorded M7 Lighthouse pass was written and then silently dropped — no findings in the
  // deliverable, and an M7 row still asserting the tier "not run" while the evidence sat on disk.
  // The intent under test: a recorded pass for ANY module either reaches the deliverable or is
  // visibly rejected — never a silent drop.
  describe("every module record-pass accepts has a consumer (#1042)", () => {
    it("M7 merges a recorded Lighthouse pass's findings and stops asserting the CWV tier did not run", () => {
      const lighthouse = withPass("M7", { pass: "lighthouse", findings: [{ id: "M7L-01" }] });
      const { recorded, findings } = runAudit(AUDIT_RUNNERS, lighthouse);
      const m7 = recorded.find((r) => r.module === "M7");
      expect(findings.some((f) => (f as { id?: string }).id === "M7L-01")).toBe(true);
      expect(m7?.reason).not.toMatch(/Core Web Vitals were not measured/);
      expect(m7?.reason).toMatch(/Core Web Vitals WERE measured/);
    });

    // The status must NOT become `ran`: a Lighthouse pass is one of M7's three tiers.
    it("M7 stays partial on a recorded pass — one tier is not the whole module", () => {
      expect(status(AUDIT_RUNNERS, withPass("M7", { pass: "lighthouse" }), "M7")?.status).toBe("partial");
    });

    it.each(["M4", "M5", "M8", "M9", "M10"] as const)("%s merges a recorded pass's findings and names it on the row", (module) => {
      const recordedPass = withPass(module, { pass: "captured", findings: [{ id: `${module}-PASS-1` }] });
      const { recorded, findings } = runAudit(AUDIT_RUNNERS, recordedPass);
      const row = recorded.find((r) => r.module === module);
      expect(findings.some((f) => (f as { id?: string }).id === `${module}-PASS-1`)).toBe(true);
      expect(`${row?.detail ?? ""} ${row?.reason ?? ""}`).toMatch(/recorded captured pass/);
    });

    // The pass contributes findings; it never UPGRADES the status to `ran` the way M1/M2/M3/M6's
    // does. A probe that could not run its own tiers becomes partial — something ran — not `ran`.
    it("a recorded pass lifts a not-run module to partial, never to ran", () => {
      const noSource = withPass("M9", { pass: "captured", findings: [{ id: "M9-PASS-1" }] }, {
        exec: (_c: string, argv: string[]) => (argv.includes("detect-static") ? { ok: true, output: "loaded 0 source files (0 product source, 0 config, 0 test/story) from /target" } : { ok: true, output: cleanOutput(argv) }),
      });
      const m9 = status(AUDIT_RUNNERS, noSource, "M9");
      expect(m9?.status).toBe("partial");
      expect(m9?.reason).toMatch(/scanned 0 product source files/);
      expect(m9?.reason).toMatch(/not by itself evidence the module ran in full/);
    });

    it("a rejected artifact for a newly-wired module is named on the row, not ignored", () => {
      const stale = withPass("M9", { generatedAt: iso(400 * DAY) });
      const m9 = status(AUDIT_RUNNERS, stale, "M9");
      expect(`${m9?.detail ?? ""} ${m9?.reason ?? ""}`).toMatch(/rejected: pass artifact for M9 is stale/);
    });
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

  // #1043: the schema tier's reason used to name only the row-sampling gap, so a reader saw a longer
  // sensitive-column list and a "partial — rows not sampled" note, and reasonably concluded the
  // protection claim had been honoured. It has to name the protection gap too.
  it("schema tier's reason names the PII-protection gap, not only the row-sampling one", () => {
    const m10 = runAudit(AUDIT_RUNNERS, ctx(capture)).recorded.find((r) => r.module === "M10");
    expect(m10?.reason).toMatch(/protection was not verified/i);
    expect(m10?.reason).toMatch(/M10-PROT-00/);
  });
});

// #1049: the data map is an INPUT to every other module's severity, so the probe has to hand it back
// as well as the findings. A run that captured findings but no map would escalate nothing and say
// nothing about why.
describe("M10 surfaces its data map for the severity join (#1049)", () => {
  const dataMap = { patients: { columns: [], infotypes: ["MRN"], categories: ["PHI"], severityScore: 6, severity: "High" as const } };
  const capturing = (): Partial<RunContext> => ({
    captureDir: "/cap",
    readFindings: () => [],
    readArtifact: (p: string) => (p.endsWith("M10-datamap.json") ? dataMap : undefined),
  });

  it("passes --data-map-out to pii-classify and returns the parsed map", () => {
    const argvSeen: string[][] = [];
    const result = runAudit(AUDIT_RUNNERS, ctx({ ...capturing(), exec: (_c, argv) => (argvSeen.push(argv), { ok: true, output: cleanOutput(argv) }) }));
    expect(argvSeen.some((argv) => argv.includes("pii-classify") && argv.includes("--data-map-out"))).toBe(true);
    expect(result.dataMap).toEqual(dataMap);
  });

  it("returns no map when the classifier wrote none, so the assembler records the gap instead of guessing", () => {
    expect(runAudit(AUDIT_RUNNERS, ctx({ captureDir: "/cap", readFindings: () => [], readArtifact: () => undefined })).dataMap).toBeUndefined();
  });
});

// #1040: quick-scan was the ONE emitter probe invoked without --findings-out, so every mechanical
// M1 finding the scan produced — including live-credential and CVE Criticals — was discarded before
// the deliverable was assembled. The intent under test is that the mechanical tier's output reaches
// --findings-out, and that the two classes the shared detect-static pass also emits are not taken
// twice (their ids are a per-run counter — two different findings under one id would make the
// document invalid).
describe("M1 collects the mechanical tier's findings into the deliverable (#1040)", () => {
  const critical = { id: "SEC-GL-source-2", taxonomy: "Committed credential", severity: "Critical" } as unknown as Finding;
  const indicator = { id: "3", taxonomy: "M6 — Indicator: cookie parsing", severity: "Info" } as unknown as Finding;
  const sfc = { id: "M1-SFC-00", taxonomy: "M1 — Multi-tenant security", severity: "Info" } as unknown as Finding;
  const capturing = () =>
    ctx({
      captureDir: "/cap",
      readFindings: (p: string) => (p.endsWith("M1.json") ? [critical, indicator, sfc] : []),
      exec: (_c, argv) => {
        if (argv.join(" ").includes("quick-scan")) expect(argv).toContain("--findings-out");
        return { ok: true, output: cleanOutput(argv) };
      },
    });

  it("a known mechanical Critical is present in the assembled findings", () => {
    const { findings } = runAudit(AUDIT_RUNNERS, capturing());
    expect(findings.map((f) => f.id)).toContain("SEC-GL-source-2");
  });

  it("does not re-collect the classes the shared detect-static pass already contributes", () => {
    const { findings } = runAudit(AUDIT_RUNNERS, capturing());
    expect(findings.filter((f) => f.taxonomy.startsWith("M6 — Indicator: ")).map((f) => f.id)).not.toContain("3");
    expect(findings.filter((f) => f.id === "M1-SFC-00")).toHaveLength(0);
  });

  it("no longer claims the mechanical tier's findings are uncollected", () => {
    const m1 = runAudit(AUDIT_RUNNERS, capturing()).recorded.find((r) => r.module === "M1");
    expect(m1?.status).toBe("partial");
    expect(m1?.reason).not.toMatch(/No M1 security findings are collected/);
    expect(m1?.reason).toMatch(/MECHANICAL tier's findings ARE collected/);
  });

  it("a coverage-only run says so instead of implying the mechanical tier was collected", () => {
    const m1 = runAudit(AUDIT_RUNNERS, ctx()).recorded.find((r) => r.module === "M1");
    expect(m1?.reason).toMatch(/coverage-only, no --findings-out/);
  });
});

// #528/#537: the mechanical scan emits SEC-TH-GH-00 when the git-history secrets tier could not run
// (non-git archive/subdirectory delivery) — quick-scan derives that from isGitRepoRoot(targetDir).
// #528 originally surfaced the gap only by reading a captured raw-findings feed (capture-only). #537
// switched the M1 probe to check ctx.isGitRepoRoot directly, so a coverage-only run (no captureDir)
// reflects the sub-gap too, and a git-repo-root target is unaffected either way.
describe("M1 surfaces the git-history secrets coverage gap (#528/#537)", () => {
  it("surfaces the git-history-not-assessed note on a coverage-only run against a non-git target", () => {
    const m1 = runAudit(AUDIT_RUNNERS, ctx({ isGitRepoRoot: () => false })).recorded.find((r) => r.module === "M1");
    expect(m1?.status).toBe("partial");
    expect(m1?.reason).toMatch(/git-history secret scan/i);
    expect(m1?.reason).toMatch(/SEC-TH-GH-00/);
  });

  it("still surfaces the note on a capturing run against a non-git target", () => {
    const capturing = ctx({ captureDir: "/cap", readFindings: () => [], isGitRepoRoot: () => false });
    const m1 = runAudit(AUDIT_RUNNERS, capturing).recorded.find((r) => r.module === "M1");
    expect(m1?.reason).toMatch(/SEC-TH-GH-00/);
  });

  it("a git-repo-root target's M1 reason carries no git-history note", () => {
    const m1 = runAudit(AUDIT_RUNNERS, ctx({ isGitRepoRoot: () => true })).recorded.find((r) => r.module === "M1");
    expect(m1?.reason).not.toMatch(/git-history/i);
  });

  it("stays silent on the sub-gap when the signal is not supplied at all", () => {
    const m1 = runAudit(AUDIT_RUNNERS, ctx({ isGitRepoRoot: undefined })).recorded.find((r) => r.module === "M1");
    expect(m1?.reason).not.toMatch(/git-history/i);
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

  it("an app missing node_modules is an explicit reduced-tier row for THAT app, never absent (M5, #1035)", () => {
    const rec = runAudit(AUDIT_RUNNERS, ctx({ apps, exists: (p) => p !== "/target/apps/rag/node_modules" })).recorded;
    const m5 = rec.filter((r) => r.module === "M5");
    expect(m5).toHaveLength(2);
    expect(m5.find((r) => r.instance === "apps/rag")?.status).toBe("partial");
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

  // #520: with no per-DB URLs supplied, EVERY enumerated project is an explicit requires-live-run
  // row naming its missing connection URL — never a silent skip, and no longer a lone auto-run
  // primary.
  it("M10 live tier names every Supabase project with no per-DB URL, never dropping one", () => {
    const m10 = runAudit(AUDIT_RUNNERS, ctx({
      env: { connected: true, dynamic: false, llm: false },
      supabaseRefs: ["proj-main", "proj-rag"],
    })).recorded.filter((r) => r.module === "M10");
    expect(m10.map((r) => r.instance).sort()).toEqual(["proj-main", "proj-rag"]);
    expect(m10.every((r) => r.status === "requires-live-run")).toBe(true);
    expect(m10.find((r) => r.instance === "proj-rag")?.reason).toMatch(/no per-DB connection URL/);
  });

  // #520: given a per-DB URL for each project, each is live-classified against its OWN DB — the URL
  // is threaded onto the child env so pii-classify targets project N, not only the env-configured one.
  it("M10 live tier classifies each project against its own threaded SUPABASE_DB_URL", () => {
    const envByRef = new Map<string, string | undefined>();
    const m10 = runAudit(AUDIT_RUNNERS, ctx({
      env: { connected: true, dynamic: false, llm: false },
      captureDir: "/cap",
      supabaseRefs: ["proj-main", "proj-rag"],
      supabaseDbUrls: { "proj-main": "postgres://main", "proj-rag": "postgres://rag" },
      readFindings: (p: string) => (p.endsWith(".json") ? [{ id: "M10-01" } as never] : []),
      exec: (_c, argv, opts) => {
        if (argv.includes("pii-classify")) {
          const out = argv[argv.indexOf("--out") + 1] ?? "";
          envByRef.set(out, opts?.env?.SUPABASE_DB_URL);
        }
        return { ok: true, output: cleanOutput(argv) };
      },
    })).recorded.filter((r) => r.module === "M10");
    expect(m10.map((r) => r.instance).sort()).toEqual(["proj-main", "proj-rag"]);
    expect(m10.every((r) => r.status === "ran")).toBe(true);
    // Each project's classify ran with ITS url, not a single shared one.
    expect([...envByRef.values()].sort()).toEqual(["postgres://main", "postgres://rag"]);
  });

  // #520: a mixed run — one project has a URL, the other does not — classifies the first and keeps
  // an honest requires-live-run row for the second.
  it("M10 live tier classifies the URL-provided project and keeps the other's requires-live-run row", () => {
    const m10 = runAudit(AUDIT_RUNNERS, ctx({
      env: { connected: true, dynamic: false, llm: false },
      supabaseRefs: ["proj-main", "proj-rag"],
      supabaseDbUrls: { "proj-main": "postgres://main" },
    })).recorded.filter((r) => r.module === "M10");
    expect(m10.find((r) => r.instance === "proj-main")?.status).not.toBe("requires-live-run");
    expect(m10.find((r) => r.instance === "proj-rag")?.status).toBe("requires-live-run");
  });

  it("M10 schema tier fans out one partial row per app", () => {
    const m10 = runAudit(AUDIT_RUNNERS, ctx({ apps })).recorded.filter((r) => r.module === "M10");
    expect(m10.map((r) => r.instance).sort()).toEqual(["apps/main", "apps/rag"]);
    expect(m10.every((r) => r.status === "partial")).toBe(true);
  });

  // #538: a monorepo's per-app schema hint (ctx.schemaHints, keyed by app name) targets that ONE
  // app's schema tier — the other app still falls back to the conventional-location probe, and the
  // single-target ctx.schemaHint (#529) must never leak into either app's fan-out.
  it("M10 schema tier uses each app's OWN per-app --schema hint, not a shared one", () => {
    const schemasSeen: string[] = [];
    runAudit(AUDIT_RUNNERS, ctx({
      apps,
      schemaHint: "/should/not/apply/on/a/monorepo.sql",
      schemaHints: { "apps/rag": "/given/apps-rag-schema.sql" },
      exec: (_c, argv) => {
        if (argv.includes("pii-classify")) schemasSeen.push(argv[argv.indexOf("--schema") + 1]!);
        return { ok: true, output: cleanOutput(argv) };
      },
    }));
    // apps/rag used its own hint; apps/main had none, so it fell back to the conventional probe
    // (ctx.exists() defaults to true, so it resolves the first conventional candidate).
    expect(schemasSeen).toContain("/given/apps-rag-schema.sql");
    expect(schemasSeen.some((s) => s.includes("apps/main") && s.includes("supabase"))).toBe(true);
    expect(schemasSeen).not.toContain("/should/not/apply/on/a/monorepo.sql");
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

// #1062: the M7 code tier shelled out to detect-static with NO --out, so its findings were empty by
// construction — the M7 row asserted `pnpm detect-static (code tier)` ran while carrying zero
// evidence. The intent under test is that the code tier's own findings reach the deliverable on
// every branch that reports it ran, filtered to M7's taxonomy so M9's unfiltered per-app sweep is
// not re-attributed to M7.
describe("M7 collects the code tier's findings into the deliverable (#1062)", () => {
  const perf = { id: "M7C-01", taxonomy: "M7 — Unbounded select", severity: "Perf" } as unknown as Finding;
  const boundary = { id: "M9-01", taxonomy: "M9 — Client/server boundary", severity: "Medium" } as unknown as Finding;
  const capturing = (over: Partial<RunContext> = {}) =>
    ctx({
      captureDir: "/cap",
      readFindings: (p: string) => (p.endsWith("M7.json") ? [perf, boundary] : []),
      ...over,
    });

  it("passes --out to the code tier's detect-static run", () => {
    const argvSeen: string[][] = [];
    runAudit(AUDIT_RUNNERS, capturing({ exec: (_c, argv) => (argvSeen.push(argv), { ok: true, output: cleanOutput(argv) }) }));
    const m7Run = argvSeen.find((argv) => argv.includes("detect-static") && argv.includes("/cap/M7.json"));
    expect(m7Run).toBeDefined();
  });

  it("the source-only branch (no DB creds) carries the code tier's findings, not an empty row", () => {
    const m7 = runAudit(AUDIT_RUNNERS, capturing()).recorded.find((r) => r.module === "M7");
    expect(m7?.status).toBe("partial");
    expect(runAudit(AUDIT_RUNNERS, capturing()).findings.map((f) => f.id)).toContain("M7C-01");
  });

  it("the connected-but-no-project-ref branch carries them too", () => {
    const { findings } = runAudit(AUDIT_RUNNERS, capturing({ env: { connected: true, dynamic: false, llm: false } }));
    expect(findings.map((f) => f.id)).toContain("M7C-01");
  });

  it("the advisor branch carries the code tier's findings alongside the advisors'", () => {
    const advisor = { id: "M7A-01", taxonomy: "M7 — Missing index", severity: "Perf" } as unknown as Finding;
    const { findings } = runAudit(AUDIT_RUNNERS, capturing({
      env: { connected: true, dynamic: false, llm: false },
      supabaseRefs: ["proj-main"],
      readFindings: (p: string) => (p.endsWith("M7.json") ? [perf, boundary] : p.includes("M7-proj-main") ? [advisor] : []),
      exec: (_c, argv) => (argv.includes("perf-scan") ? { ok: true, output: "" } : { ok: true, output: cleanOutput(argv) }),
    }));
    expect(findings.map((f) => f.id)).toEqual(expect.arrayContaining(["M7C-01", "M7A-01"]));
  });

  // The code tier scans the target ONCE, so it must not be multiplied by the number of enumerated
  // databases — same reasoning as #1042's Lighthouse pass. (On a multi-project run the row is
  // instance-tagged, so runAudit namespaces the id by the project it rode in on, per #620.)
  it("the code tier ran once, so its findings appear once even across several Supabase projects", () => {
    const { findings } = runAudit(AUDIT_RUNNERS, capturing({
      env: { connected: true, dynamic: false, llm: false },
      supabaseRefs: ["proj-main", "proj-rag"],
      exec: (_c, argv) => (argv.includes("perf-scan") ? { ok: true, output: "" } : { ok: true, output: cleanOutput(argv) }),
    }));
    expect(findings.filter((f) => f.id.startsWith("M7C-01"))).toHaveLength(1);
  });

  it("does not claim M9's classes from the shared detect-static pass under the M7 row", () => {
    const m7Outcome = AUDIT_RUNNERS.find((r) => r.module === "M7")!.run(capturing());
    const outcome = Array.isArray(m7Outcome) ? m7Outcome[0]! : m7Outcome;
    const collected = outcome.status === "requires-live-run" ? [] : (outcome.findings ?? []);
    expect(collected.map((f) => f.id)).toEqual(["M7C-01"]);
  });

  it("a scan that found nothing to run still carries no findings — capture is not a status", () => {
    const noFiles = capturing({ exec: (_c, argv) => (argv.includes("detect-static") ? { ok: true, output: "loaded 0 source files" } : { ok: true, output: cleanOutput(argv) }) });
    const m7 = runAudit(AUDIT_RUNNERS, noFiles).recorded.find((r) => r.module === "M7");
    expect(m7?.status).toBe("requires-live-run");
  });
});

describe("formatFailures", () => {
  it("names each crashed module and calls the crash a bug, not a tier", () => {
    const out = formatFailures([{ module: "M4", error: "jscpd binary missing" }]);
    expect(out).toMatch(/M4 \(Duplication\): jscpd binary missing/);
    expect(out).toMatch(/not a tier/);
  });
});
