// The ten module probes the #229 orchestrator drives. Each one answers exactly one question about
// its own module — "did I execute, and if not, why not" — from evidence it gathers itself: a probe
// checks the prereq (target deps, test suite, migrations, live DB, tier), runs its CLI, and reports
// the outcome. None of them takes a status from a caller.
//
// Scope (#229): this WIRES the existing runners listed in CLAUDE.md's module table. It does not
// reimplement any scanner — a probe shells out to the same `pnpm <script>` an operator runs by hand
// and reports what happened.

import { join } from "node:path";
import type { AuditModule } from "./audit-coverage.js";
import type { ModuleRunner, ProbeOutcome, RunContext } from "./audit-runner.js";

// Shells out to a module's CLI and maps the exit status onto the probe's own vocabulary. A non-zero
// exit is `requires-live-run` WITH the tool's stderr as the reason, never a silent pass: the module
// produced no usable output, and the reason says so in the tool's own words.
const viaCli = (module: AuditModule, script: string, args: (ctx: RunContext) => string[]) => ({
  module,
  run: (ctx: RunContext): ProbeOutcome => {
    const argv = args(ctx);
    const { ok, output } = ctx.exec("pnpm", [script, ...argv]);
    const command = `pnpm ${script} ${argv.join(" ")}`.trim();
    return ok ? { status: "ran", detail: command } : { status: "requires-live-run", reason: `${command} exited non-zero: ${output.trim().slice(0, 200)}` };
  },
});

// Like viaCli, but for a module whose CLI emits a report-schema Finding[] to --out: when the run
// context is capturing (#312), append `--out <captureDir>/<module>.json`, then read the emitted
// findings back onto the outcome so run-audit can assemble them. Shared CLIs (quality-scan feeds
// M4+M5, detect-static feeds M7+M9) get captured under each module key; the assembler de-dupes.
const capturing = (module: AuditModule, script: string, args: (ctx: RunContext) => string[]) => ({
  module,
  run: (ctx: RunContext): ProbeOutcome => {
    const argv = args(ctx);
    const command = `pnpm ${script} ${argv.join(" ")}`.trim();
    const outPath = ctx.captureDir && ctx.readFindings ? join(ctx.captureDir, `${module}.json`) : undefined;
    const { ok, output } = ctx.exec("pnpm", [script, ...argv, ...(outPath ? ["--out", outPath] : [])]);
    if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${output.trim().slice(0, 200)}` };
    const findings = outPath && ctx.readFindings ? ctx.readFindings(outPath) : [];
    return findings.length ? { status: "ran", detail: command, findings } : { status: "ran", detail: command };
  },
});

const hasNodeModules = (ctx: RunContext): boolean => ctx.exists(join(ctx.targetDir, "node_modules"));

// M1 mechanical tier. The semantic (LLM) and live (detect-deeper) layers are operator-driven passes
// that this orchestrator cannot perform, so a source-tier run is `partial` and names what is absent
// — the module's own docs sell three layers, and claiming "ran" off one would overstate coverage.
const m1: ModuleRunner = {
  module: "M1",
  run: (ctx) => {
    const { ok, output } = ctx.exec("pnpm", ["quick-scan", "--dir", ctx.targetDir]);
    if (!ok) return { status: "requires-live-run", reason: `pnpm quick-scan exited non-zero: ${output.trim().slice(0, 200)}` };
    if (ctx.env.connected && ctx.env.llm) return { status: "ran", detail: "pnpm quick-scan (mechanical); semantic + live layers in scope" };
    const absent = [!ctx.env.llm && "semantic LLM pass (/vuln-scan → /triage)", !ctx.env.connected && "live RLS review (pnpm detect-deeper)"].filter(Boolean).join(" and ");
    return { status: "partial", detail: "pnpm quick-scan (mechanical tier)", reason: `mechanical tier only — ${absent} not in scope` };
  },
};

const m2: ModuleRunner = {
  module: "M2",
  run: (ctx) =>
    ctx.env.dynamic
      ? viaCli("M2", "exec", () => ["tsx", "src/cli/pentest.ts"]).run(ctx)
      : { status: "requires-live-run", reason: "no local supabase stack — M2 probes a running two-tenant stack (see CLAUDE.md's module table)" },
};

// M3 runs the vitals plugin THROUGH the hotspot-scan CLI (#363), so a successful probe means the
// vitals JSON was actually parsed into the M3 deliverable (ranked table + boolean-fact findings),
// not merely that an external binary exited 0. vitals itself stays external (run, don't build):
// when it is not on PATH (#314) the CLI exits non-zero and the probe carries that reason.
const m3: ModuleRunner = capturing("M3", "exec", (ctx) => ["tsx", "src/cli/hotspot-scan.ts", ctx.targetDir]);

// M4 (jscpd) and M5 (knip) share one CLI, but they are two modules with two prereqs: jscpd reads
// source alone, while knip cannot resolve config imports without the target's installed deps. One
// `ran` covering both would be the composite-claim bug the gate exists to catch, so they probe
// separately and M5 owns the node_modules precondition.
const m4: ModuleRunner = capturing("M4", "quality-scan", (ctx) => [ctx.targetDir]);

const m5: ModuleRunner = {
  module: "M5",
  run: (ctx) =>
    hasNodeModules(ctx)
      ? capturing("M5", "quality-scan", (c) => [c.targetDir]).run(ctx)
      : { status: "requires-live-run", reason: "target has no node_modules — knip cannot resolve config imports without the target's installed deps (run `npm install` in the target)" },
};

// M6's runner assembles a review packet; the VERDICT is a paid human/LLM judgment (see
// simplify-scan.ts's header). Without the paid tier the packet has no reviewer, so there is no M6
// output — which is precisely why M6 sits in MODULES_NEVER_EXECUTED.
const m6: ModuleRunner = {
  module: "M6",
  run: (ctx) =>
    ctx.env.llm
      ? viaCli("M6", "simplify-scan", (c) => [c.targetDir]).run(ctx)
      : { status: "requires-live-run", reason: "paid LLM tier not in scope — M6's packet needs a reviewer to produce a verdict (#267)" },
};

// M7 is two layers: code-tier detectors on source (#170) plus the DB advisors. Without creds it
// loses a layer — partial, not a skip.
const m7: ModuleRunner = {
  module: "M7",
  run: (ctx) => {
    const { ok, output } = ctx.exec("pnpm", ["detect-static", ctx.targetDir]);
    if (!ok) return { status: "requires-live-run", reason: `pnpm detect-static exited non-zero: ${output.trim().slice(0, 200)}` };
    if (!ctx.env.connected) return { status: "partial", detail: "pnpm detect-static (code tier)", reason: "code tier only — no DB creds for the advisors (pnpm perf-scan)" };
    const advisors = ctx.exec("pnpm", ["perf-scan"]);
    return advisors.ok
      ? { status: "ran", detail: "pnpm detect-static (code) + pnpm perf-scan (advisors)" }
      : { status: "partial", detail: "pnpm detect-static (code tier)", reason: `advisors failed: ${advisors.output.trim().slice(0, 200)}` };
  },
};

// #224: a target with no tests is a zero-coverage FINDING, not a skipped module. The mutation
// runner owns that verdict, so the probe runs it and lets it speak.
const m8: ModuleRunner = {
  module: "M8",
  run: (ctx) =>
    hasNodeModules(ctx)
      ? capturing("M8", "mutation-scan", (c) => [c.targetDir]).run(ctx)
      : { status: "requires-live-run", reason: "target has no node_modules — StrykerJS needs the target's installed deps and test suite" },
};

const m9: ModuleRunner = capturing("M9", "detect-static", (ctx) => [ctx.targetDir]);

// M10 classifies live columns, or parses migration SQL when there is no DB (#250) — two tiers, so
// a schema-only pass is partial rather than a skip.
const m10: ModuleRunner = {
  module: "M10",
  run: (ctx) => {
    if (ctx.env.connected) return viaCli("M10", "pii-classify", () => []).run(ctx);
    const migrations = join(ctx.targetDir, "supabase", "migrations");
    if (!ctx.exists(migrations)) return { status: "requires-live-run", reason: `no live DB and no migrations at ${migrations} — nothing to classify` };
    const { ok, output } = ctx.exec("pnpm", ["pii-classify", "--schema", migrations]);
    return ok
      ? { status: "partial", detail: `pnpm pii-classify --schema ${migrations}`, reason: "schema tier only — no live DB, so row-level data was not sampled" }
      : { status: "requires-live-run", reason: `pnpm pii-classify --schema exited non-zero: ${output.trim().slice(0, 200)}` };
  },
};

// Exported as the complete set so assertRegistryComplete has something to check — and so a new
// module added to AUDIT_MODULES without a probe fails the registry test rather than shipping silent.
export const AUDIT_RUNNERS: ModuleRunner[] = [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10];
