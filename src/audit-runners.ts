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
import type { Finding } from "./findings.js";

const trimOut = (output: string): string => output.trim().slice(0, 200);

// #312 findings capture. When the run context is capturing, a module whose CLI emits a report-schema
// Finding[] to --out writes it to <captureDir>/<module>.json and reads it back onto the outcome so
// run-audit can assemble one engagement findings.json. Absent capture (the default) → no --out, no
// read: coverage-only runs are unchanged.
const captureOut = (ctx: RunContext, module: AuditModule): string | undefined =>
  ctx.captureDir && ctx.readFindings ? join(ctx.captureDir, `${module}.json`) : undefined;

const readCaptured = (ctx: RunContext, outPath: string | undefined): Finding[] =>
  outPath && ctx.readFindings ? ctx.readFindings(outPath) : [];

// Runs a module's CLI and returns the raw result plus a printable command for the ledger's detail.
const runCli = (ctx: RunContext, script: string, argv: string[]): { ok: boolean; output: string; command: string } => {
  const { ok, output } = ctx.exec("pnpm", [script, ...argv]);
  return { ok, output, command: `pnpm ${script} ${argv.join(" ")}`.trim() };
};

// Shells out to a module's CLI and maps the exit status onto the probe's own vocabulary. A non-zero
// exit is `requires-live-run` WITH the tool's stderr as the reason, never a silent pass: the module
// produced no usable output, and the reason says so in the tool's own words.
//
// #350: exit 0 alone is NOT evidence a module ran — several tools deliberately exit 0 when they
// scanned nothing (knip on unresolved deps, mutation-scan on a target with no test suite,
// detect-static on an empty dir). This helper is therefore reserved for probes whose tool genuinely
// executes whenever it exits 0 (jscpd for M4, pii-classify for M10-live). Probes over the exit-0
// no-op tools DERIVE their status from the machine-readable verdict the tool printed instead.
const viaCli = (module: AuditModule, script: string, args: (ctx: RunContext) => string[]) => ({
  module,
  run: (ctx: RunContext): ProbeOutcome => {
    const { ok, output, command } = runCli(ctx, script, args(ctx));
    return ok ? { status: "ran", detail: command } : { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
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
    const outPath = captureOut(ctx, module);
    const { ok, output } = ctx.exec("pnpm", [script, ...argv, ...(outPath ? ["--out", outPath] : [])]);
    if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
    const findings = readCaptured(ctx, outPath);
    return findings.length ? { status: "ran", detail: command, findings } : { status: "ran", detail: command };
  },
});

const hasNodeModules = (ctx: RunContext): boolean => ctx.exists(join(ctx.targetDir, "node_modules"));

// quality-scan (M4+M5) emits a Finding[] on stdout. When knip could not run, it substitutes an
// M5-00 "did not run" disclosure finding and STILL exits 0 by design (#223, so M4 keeps its jscpd
// findings). Reading the array is how M5 tells "knip ran" from "knip was skipped".
const parseFindings = (output: string): { id?: string }[] | undefined => {
  try {
    const parsed = JSON.parse(output) as unknown;
    return Array.isArray(parsed) ? (parsed as { id?: string }[]) : undefined;
  } catch {
    return undefined;
  }
};

// mutation-scan's no-test-suite branch emits { finding, moduleRecord: { status:"partial", note } }
// and exits 0 (#224); a real Stryker run emits { summary, reportRows }. The moduleRecord is the
// machine-readable verdict #350 says to read instead of the exit code.
const mutationVerdict = (output: string): { kind: "ran" } | { kind: "no-suite"; note: string } | { kind: "unknown" } => {
  try {
    const parsed = JSON.parse(output) as { moduleRecord?: { note?: string }; summary?: unknown };
    if (parsed.moduleRecord && typeof parsed.moduleRecord.note === "string") return { kind: "no-suite", note: parsed.moduleRecord.note };
    if (parsed.summary) return { kind: "ran" };
    return { kind: "unknown" };
  } catch {
    return { kind: "unknown" };
  }
};

// detect-static (M7 code + M9) prints "loaded N source files ..." on stdout. The file count, not the
// exit code, is the evidence a scan happened — the tool exits 0 over an empty directory (#350).
const filesScanned = (output: string): number | undefined => {
  const m = output.match(/loaded (\d+) source files/);
  return m ? Number(m[1]) : undefined;
};

// M1 mechanical tier. #311 DECISION (option 1 — the honest stopgap): M1 is PERMANENTLY `partial`
// under the orchestrator. The semantic (LLM `/vuln-scan → /triage`) and live (`detect-deeper`)
// layers are operator/LLM-driven passes that leave no artifact this probe can read, so the earlier
// `--connected --llm → ran` branch asserted INTENT, not observation — the exact overstatement #229
// exists to prevent, reintroduced inside the enforcer. The flags say which tiers the engagement
// HAS; they are not evidence those passes executed. `ran` becomes reachable only once those passes
// write a durable artifact the probe checks for (option 2, tracked in #416).
const m1: ModuleRunner = {
  module: "M1",
  run: (ctx) => {
    const { ok, output } = ctx.exec("pnpm", ["quick-scan", "--dir", ctx.targetDir]);
    if (!ok) return { status: "requires-live-run", reason: `pnpm quick-scan exited non-zero: ${trimOut(output)}` };
    return {
      status: "partial",
      detail: "pnpm quick-scan (mechanical tier)",
      reason: "mechanical tier only — the semantic (LLM /vuln-scan → /triage) and live (pnpm detect-deeper) layers are operator passes the orchestrator cannot observe; it has no artifact proving they ran, so it will not assert `ran` from the tier flags (#311; artifact path #416)",
    };
  },
};

// M2 (#356): `--dynamic` is the operator's CLAIM that a live two-tenant stack exists — not evidence
// one is reachable, and #229's doctrine is that a status must be derived from what was observed. The
// orchestrator cannot stand up or reach the stack (the pen-test runs via `pentest.ts` with a full
// HARVEY_* harness the operator sets up), so it has NO evidence M2's probes executed and must not
// bank a `ran` off the flag. It was previously saved only by `pentest.ts` exiting non-zero — an
// accident that would break the moment that tool exits 0 on a no-op (#350). M2 therefore reports
// requires-live-run under the orchestrator; run `pentest.ts` directly against a stood-up stack, and
// `ran` becomes derivable once that run writes a durable results artifact (option 2, #416).
const m2: ModuleRunner = {
  module: "M2",
  run: (ctx) => {
    const reason = ctx.env.dynamic
      ? "no local supabase stack confirmed — --dynamic asserts a stack exists but the orchestrator cannot reach or verify one; run `pnpm exec tsx src/cli/pentest.ts` directly against a stood-up two-tenant stack (docs/runbooks/m2-pentest-ops.md). A flag is not a reachable stack (#356; artifact path #416)"
      : "no local supabase stack in scope — M2 probes a running two-tenant stack (see CLAUDE.md's module table)";
    return { status: "requires-live-run", reason };
  },
};

// M3 runs the vitals plugin THROUGH the hotspot-scan CLI (#363), which exits 0 ONLY after parsing a
// schema-valid vitals report into the M3 deliverable (ranked table + boolean-fact findings) — so
// unlike the #350 no-op tools, M3's `ran` is already backed by real output. The probe still DERIVES
// it from that output (the ranked-table header) rather than the bare exit code, so a future no-op
// exit 0 cannot slip through.
//
// #314 — how M3 is invoked for real: the CLI path (hotspot-scan.ts wrapping `vitals_cli.py report
// --json`, or replaying a capture via `--report`). vitals is an external plugin (run, don't build);
// PREREQ to make M3 runnable under the orchestrator: `vitals_cli.py` must be on PATH (install the
// vitals plugin — see the hotspot-scan.ts header). When it is absent the CLI exits non-zero and this
// records requires-live-run with that reason — never a silent skip. `run-audit` does not thread
// per-module args, so a pre-captured report is replayed by running hotspot-scan.ts `--report`
// directly (or via the durable-artifact path, #416); until vitals is on PATH, M3's execution record
// stays the seeded historical one (audit-execution-log.json), which is why refreshing it needs the
// prereq, not a probe change.
//
// #357 (untestable in CI): vitals is not on PATH in this environment, so every M3 probe here has
// only ever recorded requires-live-run — the `ran` branch below is UNEXERCISED. Whether a vitals
// run that analyzed nothing would still read as `ran` is inference from M5/M8/M9's shared
// exit-code pattern (#350), not measurement. Do not upgrade that to a verified claim without a
// real vitals run.
//
// #312 capture: hotspot-scan prints the ranked table to stdout (the status evidence above) AND, with
// --out, writes an M3 artifact. That artifact is an OBJECT ({ hotspots, findings, ... }), not the
// bare Finding[] the assembler's readFindings accepts, so real capturing runs will not yield M3
// findings through this path — M3 reaches the report via its coverage-ledger row until the sidecar
// is reconciled (#420). The readCaptured call is kept for symmetry and is exercised by the assembler
// test's mocked readFindings.
const m3: ModuleRunner = {
  module: "M3",
  run: (ctx) => {
    const outPath = captureOut(ctx, "M3");
    const { ok, output } = ctx.exec("pnpm", ["exec", "tsx", "src/cli/hotspot-scan.ts", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
    const command = `pnpm exec tsx src/cli/hotspot-scan.ts ${ctx.targetDir}`;
    if (!ok) return { status: "requires-live-run", reason: `vitals plugin unavailable or hotspot-scan failed: ${trimOut(output)}` };
    if (!/M3 hotspot table/.test(output)) return { status: "requires-live-run", reason: `hotspot-scan produced no M3 table — vitals report empty or unrecognized: ${trimOut(output)}` };
    const findings = readCaptured(ctx, outPath);
    return findings.length ? { status: "ran", detail: command, findings } : { status: "ran", detail: command };
  },
};

// M4 (jscpd) and M5 (knip) share one CLI, but they are two modules with two prereqs: jscpd reads
// source alone, while knip cannot resolve config imports without the target's installed deps. One
// `ran` covering both would be the composite-claim bug the gate exists to catch, so they probe
// separately and M5 owns the node_modules precondition.
const m4: ModuleRunner = capturing("M4", "quality-scan", (ctx) => [ctx.targetDir]);

// M5 (#350): knip exits 0 even when it could not run — quality-scan then substitutes an M5-00
// disclosure finding (#223). So the exit code is not the evidence; the presence of that finding in
// the emitted array is. A knip that never resolved the target's deps is a coverage gap (partial),
// not a clean `ran`.
const m5: ModuleRunner = {
  module: "M5",
  run: (ctx) => {
    if (!hasNodeModules(ctx)) return { status: "requires-live-run", reason: "target has no node_modules — knip cannot resolve config imports without the target's installed deps (run `npm install` in the target)" };
    const outPath = captureOut(ctx, "M5");
    const command = `pnpm quality-scan ${ctx.targetDir}`;
    const { ok, output } = ctx.exec("pnpm", ["quality-scan", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
    if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
    // The verdict array is read from the captured --out file when capturing (quality-scan writes a
    // bare Finding[] there and stays silent on stdout), else parsed from stdout (#312/#419).
    const findings = outPath && ctx.readFindings ? ctx.readFindings(outPath) : parseFindings(output);
    if (!findings) return { status: "requires-live-run", reason: `could not read quality-scan output to confirm knip ran: ${trimOut(output)}` };
    if (findings.some((f) => (f as { id?: string }).id === "M5-00")) return { status: "partial", detail: command, reason: "knip did not run — quality-scan emitted the M5-00 disclosure finding, so dead-code coverage was skipped this pass (M4 duplication still ran) (#223/#350)" };
    return outPath && findings.length ? { status: "ran", detail: command, findings: findings as Finding[] } : { status: "ran", detail: command };
  },
};

// M6 (#351): `simplify-scan` ASSEMBLES a review packet and exits 0 — it invokes no model and
// produces no verdict (see simplify-scan.ts's header). A packet is the INPUT to a human/LLM pass,
// not evidence one happened, so running it must NEVER clear M6's never-run alarm. M6 therefore never
// reads `ran` under the orchestrator: with the paid tier it reports `partial` (packet built, verdict
// still owed); without it, requires-live-run. Deriving `ran` needs a durable reviewed-verdict
// artifact the probe can check (option 2, #416) — the same mechanism M1's semantic tier needs.
const m6: ModuleRunner = {
  module: "M6",
  run: (ctx) => {
    if (!ctx.env.llm) return { status: "requires-live-run", reason: "paid LLM tier not in scope — M6's packet needs a reviewer to produce a verdict (#267)" };
    const { ok, output, command } = runCli(ctx, "simplify-scan", [ctx.targetDir]);
    if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
    return { status: "partial", detail: command, reason: "review packet assembled, but M6's verdict is a human/LLM pass with no recorded output — a packet is not a verdict, so this does not clear M6's never-run status (#351; artifact path #416)" };
  },
};

// M7 is two layers: code-tier detectors on source (#170) plus the DB advisors. Without creds it
// loses a layer — partial, not a skip. #350: detect-static exits 0 over an empty dir, so the probe
// checks the file count it printed before claiming the code tier ran.
//
// #357 (untestable in CI): with no live DB, the `perf-scan` advisor call has only ever been
// exercised in its FAILURE path (advisors failed → partial). Whether a successful advisor run that
// linted nothing would read as `ran` rather than an honest partial is unverified — same open
// question as M3/M5/M8/M9's exit-code-as-evidence pattern (#350). It fails honestly today; that a
// success stays honest is not yet measured.
const m7: ModuleRunner = {
  module: "M7",
  run: (ctx) => {
    const { ok, output } = ctx.exec("pnpm", ["detect-static", ctx.targetDir]);
    if (!ok) return { status: "requires-live-run", reason: `pnpm detect-static exited non-zero: ${trimOut(output)}` };
    if (!filesScanned(output)) return { status: "requires-live-run", reason: `detect-static scanned 0 source files under ${ctx.targetDir} — no code tier to run (empty or non-source target) (#350)` };
    if (!ctx.env.connected) return { status: "partial", detail: "pnpm detect-static (code tier)", reason: "code tier only — no DB creds for the advisors (pnpm perf-scan)" };
    const advisors = ctx.exec("pnpm", ["perf-scan"]);
    return advisors.ok
      ? { status: "ran", detail: "pnpm detect-static (code) + pnpm perf-scan (advisors)" }
      : { status: "partial", detail: "pnpm detect-static (code tier)", reason: `advisors failed: ${trimOut(advisors.output)}` };
  },
};

// M8 (#224/#350): a target with no tests is a zero-coverage FINDING, not a skipped module — and
// mutation-scan says so in a machine-readable moduleRecord while exiting 0. The probe reads that
// verdict rather than the exit code: no test suite → partial (the zero-coverage finding), a real
// Stryker report → ran.
// #312 capture note: mutation-scan's --out artifact is an OBJECT ({ summary, ... } or { finding,
// moduleRecord }), not the bare Finding[] the assembler reads, and --out silences the stdout verdict
// this probe derives its status from — so real capturing runs surface M8 through its coverage-ledger
// row, not captured findings, until the sidecar is reconciled (#420). readCaptured is kept for
// symmetry and exercised by the assembler test's mocked readFindings.
const m8: ModuleRunner = {
  module: "M8",
  run: (ctx) => {
    if (!hasNodeModules(ctx)) return { status: "requires-live-run", reason: "target has no node_modules — StrykerJS needs the target's installed deps and test suite" };
    const outPath = captureOut(ctx, "M8");
    const command = `pnpm mutation-scan ${ctx.targetDir}`;
    const { ok, output } = ctx.exec("pnpm", ["mutation-scan", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
    if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
    const verdict = mutationVerdict(output);
    if (verdict.kind === "no-suite") return { status: "partial", detail: command, reason: verdict.note };
    if (verdict.kind === "unknown") return { status: "requires-live-run", reason: `mutation-scan produced no recognizable verdict — cannot confirm M8 ran: ${trimOut(output)}` };
    const findings = readCaptured(ctx, outPath);
    return findings.length ? { status: "ran", detail: command, findings } : { status: "ran", detail: command };
  },
};

// M9 (#350): detect-static exits 0 over an empty directory ("loaded 0 source files"). Exit code is
// not evidence of a scan; the file count the tool printed is. Zero files scanned is not `ran`.
// detect-static prints the count to stdout AND writes a bare Finding[] to --out, so status and
// capture (#312) coexist in real runs.
const m9: ModuleRunner = {
  module: "M9",
  run: (ctx) => {
    const outPath = captureOut(ctx, "M9");
    const command = `pnpm detect-static ${ctx.targetDir}`;
    const { ok, output } = ctx.exec("pnpm", ["detect-static", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
    if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
    const scanned = filesScanned(output);
    if (scanned === undefined) return { status: "requires-live-run", reason: `could not read detect-static output to confirm files were scanned: ${trimOut(output)}` };
    if (scanned === 0) return { status: "requires-live-run", reason: `detect-static scanned 0 source files under ${ctx.targetDir} — nothing to analyze (empty or non-source target) (#350)` };
    const findings = readCaptured(ctx, outPath);
    return findings.length ? { status: "ran", detail: command, findings } : { status: "ran", detail: command };
  },
};

// M10 classifies live columns, or parses migration SQL when there is no DB (#250) — two tiers, so
// a schema-only pass is partial rather than a skip.
//
// #357 (untestable in CI): the `connected` branch below (live pii-classify → `ran`) needs real DB
// creds and has only been exercised in its failure path here. Whether a live classify that sampled
// nothing would read as `ran` is unverified — the schema-tier (partial) path is the only one this
// environment can exercise.
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
