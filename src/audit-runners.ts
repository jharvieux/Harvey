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
import { findFreshPass, type PassArtifact, ranFromPass } from "./audit-pass-artifact.js";
import type { ModuleRunner, ProbeOutcome, RunContext } from "./audit-runner.js";
import { type DataClassMap, isDataClassMap } from "./data-class-escalation.js";
import type { Finding } from "./findings.js";

// #416: fold a rejected-pass reason (wrong target, stale, malformed) into a probe's not-run reason,
// so a pass artifact that was present but rejected fails loud rather than being silently ignored.
const withRejectedPass = (base: string, reason: string | undefined): string =>
  reason ? `${base} A pass artifact was found but rejected: ${reason}` : base;

const trimOut = (output: string): string => output.trim().slice(0, 200);

// ---- #1042: the CONSUME side for the six modules record-pass accepts but no probe ever read ----
//
// `record-pass` validates --module against the full M1–M10 list and tells the operator "that module
// derives `ran` from this artifact", but findFreshPass was called for M1/M2/M3/M6 only. A recorded
// M7 Lighthouse pass was therefore accepted, written, and then silently dropped: MEASURED
// 2026-07-25 on targets/calibration, the recorded M7L-01 finding was absent from --findings-out and
// the M7 row still asserted Lighthouse "not run" — a confident negative claim contradicted by
// evidence sitting in the directory run-audit had just read. Operator ruling: wire the consume side
// for all ten rather than make record-pass reject the six.
//
// What a recorded pass does for these six: its findings are folded into the row and the pass is
// named there. What it does NOT do is read `ran` — it covers ONE tier (Lighthouse for M7, a captured
// tool run for the rest) and the orchestrator has no evidence about the others, which is the #229
// derive-don't-assert rule. A requires-live-run does become a partial, because something demonstrably
// ran and produced output. A present-but-rejected artifact (stale, wrong target, malformed) is
// surfaced on the row too, so an unconsumed artifact is never silent either way.
const passLabel = (artifact: PassArtifact): string => `${artifact.pass} pass (${artifact.generatedAt}${artifact.summary ? `: ${artifact.summary}` : ""})`;

const foldPassInto = (outcome: ProbeOutcome, note: string, passFindings: Finding[]): ProbeOutcome => {
  if (outcome.status === "requires-live-run") {
    return {
      status: "partial",
      detail: "recorded pass artifact",
      reason: `${outcome.reason} ${note}.`,
      ...(passFindings.length ? { findings: passFindings } : {}),
      ...(outcome.instance ? { instance: outcome.instance } : {}),
    };
  }
  const findings = [...(outcome.findings ?? []), ...passFindings];
  const merged = { ...outcome, ...(findings.length ? { findings } : {}) };
  return merged.status === "ran" ? { ...merged, detail: `${merged.detail} + ${note}` } : { ...merged, reason: `${merged.reason} ${note}.` };
};

const rejectedPassNote = (outcome: ProbeOutcome, reason: string): ProbeOutcome =>
  outcome.status === "ran" ? { ...outcome, detail: withRejectedPass(outcome.detail, reason) } : { ...outcome, reason: withRejectedPass(outcome.reason, reason) };

const foldRecordedPass = (runner: ModuleRunner): ModuleRunner => ({
  module: runner.module,
  run: (ctx) => {
    const pass = findFreshPass(ctx, runner.module);
    const result = runner.run(ctx);
    if (!pass.fresh && !pass.reason) return result;
    const outcomes = Array.isArray(result) ? result : [result];
    // Folded into the FIRST outcome only: on a per-app fan-out the pass covers the MODULE, not each
    // app, so repeating it per instance would multiply one recorded finding across every row.
    const first = pass.fresh
      ? foldPassInto(
          outcomes[0]!,
          `A recorded ${passLabel(pass.artifact)} contributed ${(pass.artifact.findings ?? []).length} finding(s) to this row; it covers one tier of this module, so it is not by itself evidence the module ran in full (#1042)`,
          pass.artifact.findings ?? [],
        )
      : rejectedPassNote(outcomes[0]!, pass.reason!);
    return [first, ...outcomes.slice(1)];
  },
});

// #312 findings capture. When the run context is capturing, a module whose CLI emits findings to
// --out writes them to <captureDir>/<module>.json and reads them back onto the outcome so run-audit
// can assemble one engagement findings.json. Absent capture (the default) → no --out, no read:
// coverage-only runs are unchanged.
const captureOut = (ctx: RunContext, module: AuditModule): string | undefined =>
  ctx.captureDir ? join(ctx.captureDir, `${module}.json`) : undefined;

// Bare-Finding[] emitters (M4/M5/M7-advisors/M9).
const readCaptured = (ctx: RunContext, outPath: string | undefined): Finding[] =>
  outPath && ctx.readFindings ? ctx.readFindings(outPath) : [];

// #420: object-artifact emitters (M3, M8). Reads the { ... } --out shape and pulls out the
// report-schema Finding[] it embeds — `findings` (M3's fact findings) or a single `finding` (M8's
// no-test-suite disclosure). No object / no capture → []. Kept separate from readCaptured so the
// bare-array emitters keep their strict "not a Finding[]" guard.
const readArtifact = (ctx: RunContext, outPath: string | undefined): Record<string, unknown> | undefined =>
  outPath && ctx.readArtifact ? (ctx.readArtifact(outPath) as Record<string, unknown> | undefined) : undefined;

const artifactFindings = (artifact: Record<string, unknown> | undefined): Finding[] => {
  if (!artifact) return [];
  if (Array.isArray(artifact.findings)) return artifact.findings as Finding[];
  if (artifact.finding && typeof artifact.finding === "object") return [artifact.finding as Finding];
  return [];
};

// Runs a module's CLI and returns the raw result plus a printable command for the ledger's detail.
const runCli = (ctx: RunContext, script: string, argv: string[]): { ok: boolean; output: string; command: string } => {
  const { ok, output } = ctx.exec("pnpm", [script, ...argv]);
  return { ok, output, command: `pnpm ${script} ${argv.join(" ")}`.trim() };
};

const hasNodeModules = (ctx: RunContext): boolean => ctx.exists(join(ctx.targetDir, "node_modules"));

// #506: a per-app tier (M4/M5/M9, M10 schema) runs once per enumerated app on a monorepo. With ≤1
// app (the common single-app target) it runs once against ctx.targetDir, untagged — behaviour is
// exactly as before. With >1, it runs per app dir and tags each outcome with the app's name, so the
// ledger records one row per (module × app) and no second app is silently folded into the first.
const perApp = (base: (ctx: RunContext) => ProbeOutcome) => (ctx: RunContext): ProbeOutcome | ProbeOutcome[] => {
  const apps = ctx.apps;
  if (!apps || apps.length <= 1) return base(ctx);
  return apps.map((app) => ({ ...base({ ...ctx, targetDir: app.path }), instance: app.name }));
};

// #506: the enumerated Supabase project refs for M7's advisor tier. Falls back to the single
// ctx.supabaseRef (#434) when a multi-project list was not enumerated.
const supabaseRefs = (ctx: RunContext): string[] => ctx.supabaseRefs?.length ? ctx.supabaseRefs : ctx.supabaseRef ? [ctx.supabaseRef] : [];
const refSlug = (ref: string): string => ref.replace(/[^a-zA-Z0-9_-]/g, "_");

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

// mutation-scan emits a machine-readable moduleRecord ({ status:"partial", note }) and exits 0
// whenever the mutation tier fell short of a full run: no test suite (#224), a failed Stryker dry
// run (#503), a degraded scaffold rung (#513), or a scoped run that covered less than the
// configured mutate scope (#504 — that artifact carries BOTH a summary and a moduleRecord, and the
// moduleRecord wins: a subset measurement must never read `ran`). Only a summary WITHOUT a
// moduleRecord is a full run. The moduleRecord is the verdict #350 says to read instead of the
// exit code. #420: --out diverts this verdict off stdout into the object artifact, so a capturing
// run passes the parsed object here instead of the stdout string.
// #754: a moduleRecord flagged `noSuite: true` (src/mutation-scan.ts's noTestSuiteModuleRecord) is
// its OWN kind — a target with no test suite has a complete verdict (the M8-00 finding), not a
// stalled measurement — so it must not fall into the same "partial" bucket as a suite that exists
// but couldn't be measured (dry-run failure, degraded ladder, scoped subset).
const mutationVerdict = (
  input: string | Record<string, unknown>,
): { kind: "ran" } | { kind: "partial"; note: string } | { kind: "no-suite"; note: string } | { kind: "unknown" } => {
  try {
    const parsed = (typeof input === "string" ? JSON.parse(input) : input) as { moduleRecord?: { note?: string; noSuite?: boolean }; summary?: unknown };
    if (parsed.moduleRecord && typeof parsed.moduleRecord.note === "string") {
      return parsed.moduleRecord.noSuite ? { kind: "no-suite", note: parsed.moduleRecord.note } : { kind: "partial", note: parsed.moduleRecord.note };
    }
    if (parsed.summary) return { kind: "ran" };
    return { kind: "unknown" };
  } catch {
    return { kind: "unknown" };
  }
};

// detect-static (M7 code + M9) prints "loaded N source files (M product source, …)" on stdout. The
// file count, not the exit code, is the evidence a scan happened — the tool exits 0 over an empty
// directory (#350).
//
// #1065: the TOTAL is not that evidence. package.json and next.config.js are loaded on every target
// (the M9 pass needs them to resolve `paths` aliases), so the total can never be 0 and the
// "nothing scanned" guard below could never fire — it read `loaded 2 source files` as a real scan
// on a 13-file app whose every route was invisible. The PRODUCT SOURCE count is the one that means
// code was read. M8's test-intent tier is the exception: test files are its subject matter, so it
// reads the full set and asks for the total.
const filesScanned = (output: string): number | undefined => {
  const m = output.match(/loaded (\d+) source files/);
  return m ? Number(m[1]) : undefined;
};
const productFilesScanned = (output: string): number | undefined => {
  const m = output.match(/\((\d+) product source[,)]/);
  return m ? Number(m[1]) : undefined;
};

// M1 mechanical tier. #311 DECISION (option 1 — the honest stopgap): M1 is PERMANENTLY `partial`
// under the orchestrator. The semantic (LLM `/vuln-scan → /triage`) and live (`detect-deeper`)
// layers are operator/LLM-driven passes that leave no artifact this probe can read, so the earlier
// `--connected --llm → ran` branch asserted INTENT, not observation — the exact overstatement #229
// exists to prevent, reintroduced inside the enforcer. The flags say which tiers the engagement
// HAS; they are not evidence those passes executed. `ran` becomes reachable only once those passes
// write a durable artifact the probe checks for (option 2, tracked in #416).
// #528/#537: the mechanical scan emits a SEC-TH-GH-00 coverage-disclosure finding when the
// git-history secrets tier could not run (target is not a git repo root — an archive/subdirectory
// delivery). #528 originally surfaced this by reading it back off quick-scan's raw --findings-out
// feed, which only exists on a capturing run (ctx.captureDir set) — a coverage-only run stayed blind
// to the sub-gap. quick-scan derives the SAME fact from isGitRepoRoot(ctx.targetDir) (src/scan/
// secrets.ts, exported in #533), so the M1 probe checks that directly instead: no capture dir, no
// raw-findings file, and it works on every run.
const gitHistoryGapNote = (ctx: RunContext): string => {
  if (!ctx.isGitRepoRoot || ctx.isGitRepoRoot(ctx.targetDir)) return "";
  return " Coverage note: the git-history secret scan (TruffleHog) did not run — this target is not a git repository root (archive/subdirectory delivery), so committed-secret history was not assessed (SEC-TH-GH-00, #528/#537).";
};

// #1040: the mechanical tier's own findings — semgrep `harvey-*` rules, gitleaks/trufflehog
// secrets, dependency CVEs — RAN and were then thrown away: quick-scan was the one emitter probe
// invoked without --findings-out (MEASURED 2026-07-25 on targets/calibration: quick-scan produced
// 386 findings, 47 of them Critical; the assembled deliverable carried 0 of them — after the fix it
// carries 449). Falsifier: `pnpm exec tsx src/cli/run-audit.ts targets/calibration --findings-out
// ra.json` and look for SEC-GL-source-2 / DEP-CVE-2025-29927 in ra.json.
//
// Two classes are deliberately NOT taken from this capture: they run inside BOTH runMechanicalScan
// and detect-static (detectHandrolledFindings, checkUnassessedSfcFiles), and the M6/M9 probes
// already capture the detect-static side. Taking them twice would double-count — and the indicator
// ids are a per-run sequential counter, so the two passes emit the SAME id for DIFFERENT findings
// and validateFindings would refuse to write the deliverable at all.
const m1: ModuleRunner = {
  module: "M1",
  run: (ctx) => {
    const outPath = captureOut(ctx, "M1");
    const { ok, output } = ctx.exec("pnpm", ["quick-scan", "--dir", ctx.targetDir, ...(outPath ? ["--findings-out", outPath] : [])]);
    if (!ok) return { status: "requires-live-run", reason: `pnpm quick-scan exited non-zero: ${trimOut(output)}` };
    const mechanical = readCaptured(ctx, outPath).filter((f) => !f.taxonomy.startsWith(M6_TAXONOMY_PREFIX) && f.id !== "M1-SFC-00");
    // #416: a fresh semantic/live pass artifact is the evidence #311 said `ran` needs. With it, the
    // flagship LLM/live work is proven (and its triage findings flow into the deliverable); without
    // it, M1 stays honestly partial on the mechanical tier alone.
    const pass = findFreshPass(ctx, "M1");
    if (pass.fresh) {
      const ran = ranFromPass(pass.artifact, "pnpm quick-scan (mechanical tier)");
      const findings = [...mechanical, ...(ran.findings ?? [])];
      // #502: the M3→M1 hotspot focus is a designed dependency; an un-focused semantic pass silently
      // degrades the flagship review to un-prioritized. Surface it in the ledger detail either way so
      // a missing focus is visible rather than assumed.
      const focusNote =
        pass.artifact.pass !== "semantic"
          ? ""
          : pass.artifact.hotspotFocus
            ? " [hotspot-focused: M3 → M1 (#502)]"
            : " [WARNING: no M3 hotspot focus — the semantic pass was NOT hotspot-prioritized; run M3 first and feed `pnpm scan-focus` into /vuln-scan (#502)]";
      return { ...ran, detail: `${ran.detail}${focusNote}`, ...(findings.length ? { findings } : {}) };
    }
    return {
      status: "partial",
      detail: "pnpm quick-scan (mechanical tier)",
      reason:
        withRejectedPass(
          "mechanical tier only — the semantic (LLM /vuln-scan → /triage) and live (pnpm detect-deeper) layers are operator passes the orchestrator cannot observe; it has no artifact proving they ran, so it will not assert `ran` from the tier flags (#311; artifact path #416). The MECHANICAL tier's findings ARE collected into this deliverable (#1040); what is missing is the semantic/live tier's output, so absence of THOSE is not-collected, not clean (#420)",
          pass.reason,
        ) +
        (outPath ? "" : " This run captured no findings (coverage-only, no --findings-out), so the mechanical tier's findings are not collected here either — absence is not-collected, not clean (#420).") +
        gitHistoryGapNote(ctx),
      ...(mechanical.length ? { findings: mechanical } : {}),
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
    // #416: a fresh dynamic-pass artifact (pentest.ts explore/verify results written after a real
    // run against a stood-up stack) is the reachable-stack evidence #356 said the flag was not.
    const pass = findFreshPass(ctx, "M2");
    if (pass.fresh) return ranFromPass(pass.artifact, "pnpm exec tsx src/cli/pentest.ts (dynamic)");
    const base = ctx.env.dynamic
      ? "no local supabase stack confirmed — --dynamic asserts a stack exists but the orchestrator cannot reach or verify one; run `pnpm exec tsx src/cli/pentest.ts` directly against a stood-up two-tenant stack (docs/runbooks/m2-pentest-ops.md). A flag is not a reachable stack (#356; artifact path #416). No M2 findings are collected into this deliverable — they come from that live pen-test run, so absence here is not-collected, not clean (#420)"
      : "no local supabase stack in scope — M2 probes a running two-tenant stack (see CLAUDE.md's module table). No M2 findings are collected into this deliverable — they come from a live pen-test run (#420)";
    return { status: "requires-live-run", reason: withRejectedPass(base, pass.reason) };
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
// installing it gives the FULL M3 signal. #807: when vitals is entirely unavailable the CLI no longer
// fails — it drops to a reduced Harvey-side churn×complexity ranking (git + a complexity proxy) and
// prints an "M3 REDUCED TIER" banner, which this probe records as `partial` with that reason (still
// carrying the top-K hotspots for cross-module enrichment), never a silent skip. A fresh full-vitals
// capture pass (#416) still beats the reduced tier. `requires-live-run` now fires only when the CLI
// exits non-zero: vitals present but its report crashed, or the reduced tier's own floor (no git
// history) failed. `run-audit` does not thread per-module args, so a pre-captured report is replayed
// by running hotspot-scan.ts `--report` directly (or via the durable-artifact path, #416).
//
// #808: the CLI asserts the installed vitals reports version 0.2.0 before running, so schema drift
// fails loud with expected/actual rather than as a downstream array-missing parse error.
//
// #312/#420 capture: hotspot-scan prints the ranked table to stdout (the status evidence above) AND,
// with --out, writes an M3 artifact. That artifact is an OBJECT ({ hotspots, findings, ... }), not a
// bare Finding[], so the M3 findings are read via readArtifact (which pulls `findings` out) rather
// than readCaptured. The stdout table still gates the `ran` status, so a no-op vitals exit cannot
// slip through.
const m3: ModuleRunner = {
  module: "M3",
  run: (ctx) => {
    const outPath = captureOut(ctx, "M3");
    const { ok, output } = ctx.exec("pnpm", ["exec", "tsx", "src/cli/hotspot-scan.ts", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
    const command = `pnpm exec tsx src/cli/hotspot-scan.ts ${ctx.targetDir}`;
    if (ok && /M3 hotspot table/.test(output)) {
      const artifact = readArtifact(ctx, outPath);
      const findings = artifactFindings(artifact);
      // #515: surface the top-K hotspot ranking so the assembler can enrich every module's findings.
      const hotspots = Array.isArray(artifact?.topK) ? (artifact!.topK as string[]) : undefined;
      // #807: the CLI dropped to its reduced Harvey-side tier (vitals not installed) — a churn×
      // complexity ranking only, no coupling/knowledge-risk/AI-provenance. Keyed off the stdout
      // banner so it holds even without an artifacts dir. That is a `partial`, never a clean `ran`;
      // but a fresh full-vitals capture still beats it.
      if (/M3 REDUCED TIER/.test(output)) {
        const pass = findFreshPass(ctx, "M3");
        if (pass.fresh) {
          const ran = ranFromPass(pass.artifact, "captured vitals report");
          return pass.artifact.hotspots?.length ? { ...ran, hotspots: pass.artifact.hotspots } : ran;
        }
        return {
          status: "partial",
          detail: command,
          reason: "vitals plugin unavailable — reduced M3 tier: churn×complexity ranking only (no coupling/knowledge-risk/AI-provenance). Install vitals for the full signal.",
          ...(hotspots?.length ? { hotspots } : {}),
        };
      }
      return {
        status: "ran",
        detail: command,
        ...(findings.length ? { findings } : {}),
        ...(hotspots?.length ? { hotspots } : {}),
      };
    }
    // #416: vitals is not on PATH here (the common case — it's an external plugin). A fresh captured
    // vitals pass artifact still proves M3 ran, so the orchestrator need not have vitals installed to
    // record a real prior run.
    const pass = findFreshPass(ctx, "M3");
    if (pass.fresh) {
      // #530: surface the pass artifact's top-K ranking so the cross-module enrichment (#515) fires
      // in the common vitals-off-PATH flow too, not only when M3 was captured in-process.
      const ran = ranFromPass(pass.artifact, "captured vitals report");
      return pass.artifact.hotspots?.length ? { ...ran, hotspots: pass.artifact.hotspots } : ran;
    }
    const base = !ok
      ? `vitals plugin unavailable or hotspot-scan failed: ${trimOut(output)}`
      : `hotspot-scan produced no M3 table — vitals report empty or unrecognized: ${trimOut(output)}`;
    return { status: "requires-live-run", reason: withRejectedPass(base, pass.reason) };
  },
};

// M4 (jscpd) and M5 (knip) share one CLI, but they are two modules with two prereqs: jscpd reads
// source alone, while knip cannot resolve config imports without the target's installed deps. One
// `ran` covering both would be the composite-claim bug the gate exists to catch, so they probe
// separately and M5 owns the node_modules precondition.
//
// M4 (#505): quality-scan now runs jscpd per workspace with a hard timeout, so a monorepo target
// can be a genuine partial — some workspaces scanned, one timed out. Exit 0 alone is no longer
// enough evidence of a clean `ran` (#350's rule): the probe reads the emitted array for the M4-99
// gap-disclosure finding the CLI substitutes for any workspace that didn't complete, the same way
// M5 already reads for M5-00.
// #506: jscpd is also a per-app tier — on a monorepo, perApp runs this once per enumerated app so
// each app's duplication is a distinct row (with #505's per-app M4-99 timeout signal intact), not
// folded into the first app's.
const m4Run = (ctx: RunContext): ProbeOutcome => {
  const outPath = captureOut(ctx, "M4");
  const command = `pnpm quality-scan ${ctx.targetDir}`;
  const { ok, output } = ctx.exec("pnpm", ["quality-scan", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
  if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
  const findings = outPath && ctx.readFindings ? ctx.readFindings(outPath) : parseFindings(output);
  if (!findings) return { status: "requires-live-run", reason: `could not read quality-scan output to confirm jscpd ran: ${trimOut(output)}` };
  if (findings.some((f) => (f as { id?: string }).id === "M4-99")) return { status: "partial", detail: command, reason: "jscpd did not complete on every workspace — quality-scan emitted the M4-99 disclosure finding, so duplication coverage is incomplete for this pass (#505)", findings: findings as Finding[] };
  return findings.length ? { status: "ran", detail: command, findings: findings as Finding[] } : { status: "ran", detail: command };
};
const m4: ModuleRunner = { module: "M4", run: perApp(m4Run) };

// M5 (#350): knip exits 0 even when it could not run — quality-scan then substitutes an M5-00
// disclosure finding (#223). So the exit code is not the evidence; the presence of that finding in
// the emitted array is. A knip that never resolved the target's deps is a coverage gap (partial),
// not a clean `ran`.
//
// #1035: this probe used to early-return requires-live-run whenever the target had no
// node_modules, on the recorded reason that "knip cannot resolve config imports without the
// target's installed deps". #810 (2026-07-23) built the very fallback that reason calls impossible
// — quality-scan re-runs knip with all plugins disabled and Harvey-inferred entries, disclosing an
// M5-98 review-tier row — but it never touched this file, so through the orchestrator the guard
// fired first and the fallback was unreachable. MEASURED 2026-07-25: `pnpm quality-scan
// targets/prisma-xtenant-app` (no node_modules) completes and emits findings, while `run-audit
// targets/calibration` (also no node_modules) recorded M5 requires-live-run. The guard is gone; the
// distinction it was protecting survives as a STATUS rather than a refusal to run — without
// installed deps M5 tops out at `partial`, because dead code found against an inferred entry graph
// is review-tier, never confirmed.
const m5Run = (ctx: RunContext): ProbeOutcome => {
  const depsInstalled = hasNodeModules(ctx);
  const outPath = captureOut(ctx, "M5");
  const command = `pnpm quality-scan ${ctx.targetDir}`;
  const { ok, output } = ctx.exec("pnpm", ["quality-scan", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
  if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
  // The verdict array is read from the captured --out file when capturing (quality-scan writes a
  // bare Finding[] there and stays silent on stdout), else parsed from stdout (#312/#419).
  const findings = outPath && ctx.readFindings ? ctx.readFindings(outPath) : parseFindings(output);
  if (!findings) return { status: "requires-live-run", reason: `could not read quality-scan output to confirm knip ran: ${trimOut(output)}` };
  const emitted = (id: string): boolean => findings.some((f) => (f as { id?: string }).id === id);
  const captured = outPath && findings.length ? { findings: findings as Finding[] } : {};
  if (emitted("M5-00")) return { status: "partial", detail: command, reason: "knip did not run — quality-scan emitted the M5-00 disclosure finding, so dead-code coverage was skipped this pass (M4 duplication still ran) (#223/#350)" };
  if (emitted("M5-98")) {
    return {
      status: "partial",
      detail: command,
      reason: "reduced (no-dependencies) tier — knip could not load the target's own config, so it re-ran with all plugins disabled and Harvey-inferred entry points (M5-98, #810). Dead code IS reported; the file-level findings are review-tier, not confirmed. Install the target's dependencies and re-run for confirmed file findings (#1035)",
      ...captured,
    };
  }
  if (!depsInstalled) {
    return {
      status: "partial",
      detail: command,
      reason: "target has no node_modules — knip completed from source alone against a Harvey-inferred entry graph (#696), so its file-level dead code is review-tier, not confirmed. Run `npm install` in the target and re-run for confirmed file findings (#1035)",
      ...captured,
    };
  }
  return { status: "ran", detail: command, ...captured };
};
// #506: knip is the clearest per-app tier — it needs each app's own node_modules/config, so a
// monorepo runs it once per enumerated app.
const m5: ModuleRunner = { module: "M5", run: perApp(m5Run) };

// M6's free indicator layer (src/detectors/handrolled.ts, taxonomy `M6 — Indicator: …`) runs INSIDE
// detect-static, the same CLI M7/M9 shell out to — same pattern as M8_TAXONOMY_PREFIX below (M8's
// test-intent findings out of the same mixed detect-static Finding[]).
const M6_TAXONOMY_PREFIX = "M6 — Indicator: ";
const handrolledFindings = (findings: Finding[]): Finding[] => findings.filter((f) => f.taxonomy.startsWith(M6_TAXONOMY_PREFIX));

// M6 (#351): `simplify-scan` ASSEMBLES a review packet and exits 0 — it invokes no model and
// produces no verdict (see simplify-scan.ts's header). A packet is the INPUT to a human/LLM pass,
// not evidence one happened, so running it must NEVER clear M6's never-run alarm. M6 therefore never
// reads `ran` under the orchestrator: with the paid tier it reports `partial` (packet built, verdict
// still owed); without it, requires-live-run. Deriving `ran` needs a durable reviewed-verdict
// artifact the probe can check (option 2, #416) — the same mechanism M1's semantic tier needs.
//
// #397: the free indicator layer (handrolled.ts) runs inside detect-static whenever M7/M9 do, but
// until now the M6 row credited none of that — a source-only engagement produced real M6 Info
// findings and still read requires-live-run, the exact "work ran but the ledger says nothing"
// shape the coverage doctrine calls out. Operator ruling: the indicator layer alone is `partial`
// coverage, never `ran` (that stays gated on a reviewed verdict, #351) and never a silent
// requires-live-run when it demonstrably executed. Derived from detect-static's file count
// (#350), not its exit code, so an empty/non-source target still reads requires-live-run honestly.
const m6: ModuleRunner = {
  module: "M6",
  run: (ctx) => {
    // #416: a fresh verdict artifact is the recorded reviewed judgment #351 said a packet is not. It
    // is the one thing that clears M6's never-run alarm — checked before the packet path so a real
    // verdict reads `ran` regardless of whether the paid tier is flagged this run.
    const pass = findFreshPass(ctx, "M6");
    if (pass.fresh) return ranFromPass(pass.artifact, "pnpm simplify-scan (packet)");

    const indicatorOutPath = captureOut(ctx, "M6");
    const indicatorCommand = `pnpm detect-static ${ctx.targetDir}`;
    const indicatorRun = ctx.exec("pnpm", ["detect-static", ctx.targetDir, ...(indicatorOutPath ? ["--out", indicatorOutPath] : [])]);
    const indicatorScanned = indicatorRun.ok ? productFilesScanned(indicatorRun.output) : undefined;
    const indicatorFindings = indicatorScanned ? handrolledFindings(readCaptured(ctx, indicatorOutPath)) : [];

    if (!ctx.env.llm) {
      if (indicatorScanned) {
        return {
          status: "partial",
          detail: indicatorCommand,
          reason: withRejectedPass("free indicator layer ran (M6 — Indicator: … taxonomy, #267); paid LLM tier not in scope, so no triage verdict was recorded — the paid M6 triage decides which indicators are genuine reinventions and names the replacement (#397)", pass.reason),
          ...(indicatorFindings.length ? { findings: indicatorFindings } : {}),
        };
      }
      return { status: "requires-live-run", reason: withRejectedPass("paid LLM tier not in scope, and detect-static could not confirm the free indicator layer ran either (scanned 0 source files or failed) — M6's packet needs a reviewer to produce a verdict (#267). No M6 findings are collected into this deliverable — the verdict is a human/LLM pass (#420)", pass.reason) };
    }
    const { ok, output, command } = runCli(ctx, "simplify-scan", [ctx.targetDir]);
    // #683 (sibling of #682): when the paid simplify-scan sub-step is blocked, the free indicator
    // sub-step above may already have scanned and produced findings. Degrading to requires-live-run
    // would DISCARD them — the silent omission the coverage doctrine forbids — so if the indicator
    // tier scanned, record partial WITH its findings and flag the blocked sub-step; only when it too
    // could not scan is this a not-run.
    if (!ok) {
      const why = `${command} exited non-zero: ${trimOut(output)}`;
      return indicatorScanned
        ? {
            status: "partial",
            subStatus: "sub-step-blocked",
            detail: indicatorCommand,
            reason: withRejectedPass(`simplify-scan sub-step blocked (${why}); the free indicator layer still ran, so its findings are kept rather than dropped (#683)`, pass.reason),
            ...(indicatorFindings.length ? { findings: indicatorFindings } : {}),
          }
        : { status: "requires-live-run", reason: `simplify-scan blocked and the free indicator layer could not scan either — ${why}` };
    }
    return {
      status: "partial",
      detail: command,
      reason: withRejectedPass("review packet assembled, but M6's verdict is a human/LLM pass with no recorded output — a packet is not a verdict, so this does not clear M6's never-run status (#351; artifact path #416). No M6 findings are collected into this deliverable — the verdict is a human/LLM pass over the packet, so absence here is not-collected, not clean (#420)", pass.reason),
      ...(indicatorFindings.length ? { findings: indicatorFindings } : {}),
    };
  },
};

// #527: M7 is THREE tiers — code detectors (#170), DB advisors, and the Lighthouse/CWV run (M7 [L],
// #387). The orchestrator invokes only the first two; the Lighthouse run is a heavy local
// build+serve+Chrome pass, deliberately opt-in (#487, end-to-end validation #488), so run-audit
// never fires it. That means even a code+advisors success is NOT a full M7 — Core Web Vitals were
// never measured. M7 therefore tops out at `partial` under the orchestrator with this reason, so an
// advisors-success can never read as a bare `ran` (a composite claim reading as complete — the exact
// shape the coverage guard exists to catch). Run `pnpm lighthouse-scan` separately for the CWV tier.
const M7_LIGHTHOUSE_NOT_RUN =
  "Lighthouse/CWV tier not run: the orchestrator does not invoke the local build+serve+Chrome Lighthouse pass (opt-in per #487; end-to-end validation #488) — run `pnpm lighthouse-scan` separately. Core Web Vitals were not measured this pass (#527)";

// M7 is two layers: code-tier detectors on source (#170) plus the DB advisors. Without creds it
// loses a layer — partial, not a skip. #350: detect-static exits 0 over an empty dir, so the probe
// checks the file count it printed before claiming the code tier ran.
//
// #357 (untestable in CI): with no live DB, the `perf-scan` advisor call has only ever been
// exercised in its FAILURE path (advisors failed → partial). Whether a successful advisor run that
// linted nothing would read as `ran` rather than an honest partial is unverified — same open
// question as M3/M5/M8/M9's exit-code-as-evidence pattern (#350). It fails honestly today; that a
// success stays honest is not yet measured.
// #1042: M7 reads its own pass artifact rather than going through foldRecordedPass, because for M7
// the recorded pass IS the named missing tier — with a fresh Lighthouse pass M7_LIGHTHOUSE_NOT_RUN
// becomes a false claim and has to be REPLACED, not appended to.
const m7: ModuleRunner = {
  module: "M7",
  run: (ctx) => {
    const lh = findFreshPass(ctx, "M7");
    const cwv = lh.fresh
      ? { note: `Core Web Vitals WERE measured — a recorded ${passLabel(lh.artifact)} supplied ${(lh.artifact.findings ?? []).length} finding(s), merged into this deliverable (#1042)`, findings: lh.artifact.findings ?? [] }
      : undefined;
    const rejectedCwv = lh.fresh ? undefined : lh.reason;
    // Only a fresh pass changes a row (merging its findings, upgrading a not-run to partial because
    // something demonstrably ran). Without one, behaviour is exactly as before — except that a
    // present-but-rejected artifact is now named on the row instead of ignored.
    const withCwv = (outcome: ProbeOutcome): ProbeOutcome =>
      cwv ? foldPassInto(outcome, cwv.note, cwv.findings) : rejectedCwv ? rejectedPassNote(outcome, rejectedCwv) : outcome;
    const { ok, output } = ctx.exec("pnpm", ["detect-static", ctx.targetDir]);
    if (!ok) return withCwv({ status: "requires-live-run", reason: `pnpm detect-static exited non-zero: ${trimOut(output)}` });
    if (!productFilesScanned(output)) return withCwv({ status: "requires-live-run", reason: `detect-static scanned 0 product source files under ${ctx.targetDir} — no code tier to run (empty or non-source target) (#350/#1065)` });
    if (!ctx.env.connected) return withCwv({ status: "partial", detail: "pnpm detect-static (code tier)", reason: "code tier only — no DB creds for the advisors (pnpm perf-scan)" });
    // #434: perf-scan needs a project ref as its positional arg (SUPABASE_ACCESS_TOKEN travels via
    // the inherited process env — perf-scan reads that itself). --connected is intent, not a reachable
    // project; without a ref threaded through run-audit there is nothing to call, so this stays
    // partial with that reason instead of shelling out to a usage error.
    const refs = supabaseRefs(ctx);
    if (!refs.length) return withCwv({ status: "partial", detail: "pnpm detect-static (code tier)", reason: "connected tier flagged but no Supabase project ref was given (run-audit --supabase <ref>) — perf-scan needs a project ref to reach the advisors API (#434)" });
    // #506: the advisor tier is per-DB — run it once per enumerated Supabase project so a monorepo's
    // second DB is a distinct row, never silently omitted. The code tier ran once (above) and is
    // noted in each row's detail. Instances are tagged only when there's more than one project, so a
    // single-project engagement is one untagged row exactly as before (#434).
    // #420: perf-scan writes a bare Finding[] to --out, so the advisor-tier findings are captured.
    const multi = refs.length > 1;
    // #1042: the CWV note/findings ride on the FIRST project's row only — the Lighthouse pass covers
    // the app, not each enumerated database, so repeating it would multiply one measurement.
    return refs.map((ref, i): ProbeOutcome => {
      const instance = multi ? { instance: ref } : {};
      const advisorsOut = ctx.captureDir ? join(ctx.captureDir, `M7-${refSlug(ref)}.json`) : undefined;
      const advisors = ctx.exec("pnpm", ["perf-scan", ref, ...(advisorsOut ? ["--out", advisorsOut] : [])]);
      const fold = (outcome: ProbeOutcome): ProbeOutcome => (i === 0 ? withCwv(outcome) : outcome);
      if (!advisors.ok) return fold({ status: "partial", detail: "pnpm detect-static (code tier)", reason: `advisors failed for ${ref}: ${trimOut(advisors.output)}`, ...instance });
      // #527: code + advisors both ran; without a recorded Lighthouse pass the CWV tier did not, so
      // this is `partial` with that reason, never a bare `ran`. With one (#1042), the reason names
      // what ran instead of asserting a tier did not. The advisor findings flow in either way.
      const detail = `pnpm detect-static (code) + pnpm perf-scan ${ref} (advisors)`;
      const findings = readCaptured(ctx, advisorsOut);
      const reason = cwv ? "code + DB advisor tiers ran; the Lighthouse/CWV tier came from a recorded pass (#527/#1042)" : M7_LIGHTHOUSE_NOT_RUN;
      return fold(findings.length ? { status: "partial", detail, reason, findings, ...instance } : { status: "partial", detail, reason, ...instance });
    });
  },
};

// M8-taxonomy findings out of a mixed detect-static Finding[] (which also carries M6/M7/M9 findings
// from the same source pass) — see src/detectors/test-intent.ts, taxonomy strings "M8 — ...".
const M8_TAXONOMY_PREFIX = "M8 — ";
const testIntentFindings = (findings: Finding[]): Finding[] => findings.filter((f) => f.taxonomy.startsWith(M8_TAXONOMY_PREFIX));

// M8 (#224/#350): a target with no tests is a zero-coverage FINDING, not a skipped module — and
// mutation-scan says so in a machine-readable moduleRecord while exiting 0. The probe reads that
// verdict rather than the exit code: a `noSuite` moduleRecord (no suite at all, #224) → **ran** —
// the M8-00 finding is the complete verdict, there is nothing left to measure (#754); every other
// moduleRecord (dry-run failure #503, degraded ladder rung #513, scoped subset run #504 — a suite
// EXISTS but the measurement fell short) → partial with its note; a full Stryker report with no
// moduleRecord → ran.
// #771: mutation-scan is ALWAYS invoked, node_modules or not — its own suite-absence check
// (detectNoTestSuite) is a static read of package.json/test files, no installed deps required, so
// it already tells "genuinely no tests" (→ noSuite moduleRecord → ran, above) from "a suite exists
// but Stryker isn't installed" (mutation-scan's own scaffold step degrades that case to a partial
// moduleRecord naming `--install`). A prior version of this probe short-circuited on missing
// node_modules BEFORE calling mutation-scan at all, so a target with no tests and no node_modules
// (the common case) never got the M8-00 finding — it read a bare "partial, add node_modules" with
// no verdict. Removed; mutation-scan's own ladder is the single source of truth here.
// #312/#420 capture note: mutation-scan's --out artifact is an OBJECT ({ summary, ... } or
// { finding, moduleRecord }), not a bare Finding[], AND --out diverts the verdict off stdout into
// that object. So when capturing, this probe reads BOTH its status verdict and its findings from the
// object (readArtifact) rather than stdout: the no-test-suite branch's zero-coverage `finding` (M8-00)
// is captured into the deliverable, and a real Stryker run reads `ran`. When not capturing, the
// stdout verdict path (#350) is unchanged.
// #435: a real Stryker run's --out now also carries a `findings` array (denial/boundary-concentrated
// survivors, src/mutation-scan.ts's survivingMutantFindings) — artifactFindings picks it up the same
// way it already does M3's `findings` key, so a real run is no longer a zero-finding "ran".
const m8: ModuleRunner = {
  module: "M8",
  run: (ctx) => {
    // #401: the free-tier test-intent detectors (src/detectors/test-intent.ts) are source-only AST
    // passes — they need no installed deps. Run this first so its status/findings are available
    // whether or not the mutation tier below can proceed (and are kept, not dropped, if it can't).
    const staticOutPath = ctx.captureDir ? join(ctx.captureDir, "M8-static.json") : undefined;
    const staticCmd = `pnpm detect-static ${ctx.targetDir}`;
    const staticRun = ctx.exec("pnpm", ["detect-static", ctx.targetDir, ...(staticOutPath ? ["--out", staticOutPath] : [])]);
    const staticScanned = staticRun.ok ? filesScanned(staticRun.output) : undefined;
    const staticFindings = staticScanned ? testIntentFindings(readCaptured(ctx, staticOutPath)) : [];

    const outPath = captureOut(ctx, "M8");
    // #523: --install (provisioning missing Stryker packages into the target, executing its npm
    // lifecycle scripts) is gated on explicit operator consent — without it a cold target degrades
    // to the loud "re-run with --install" partial rather than the orchestrator silently installing.
    const installArg = ctx.allowTargetInstall ? ["--install"] : [];
    const command = `pnpm mutation-scan ${ctx.targetDir}${ctx.allowTargetInstall ? " --install" : ""}`;
    // #682: when the mutation sub-step is blocked (a non-zero exit or unrecognized output — e.g. the
    // #623 harness failure), the source-only test-intent sub-step above may already have run and
    // produced findings. Degrading to requires-live-run would DISCARD them — the silent omission the
    // coverage doctrine forbids — so if the test-intent tier scanned, record partial WITH its
    // findings and flag the blocked sub-step; only when it too could not scan is this a not-run.
    const mutationBlocked = (why: string): ProbeOutcome =>
      staticScanned
        ? {
            status: "partial",
            subStatus: "sub-step-blocked",
            detail: `${staticCmd} (test-intent tier)`,
            reason: `mutation tier blocked (${why}); the source-only test-intent tier still ran, so its findings are kept rather than dropped (#682)`,
            ...(staticFindings.length ? { findings: staticFindings } : {}),
          }
        : { status: "requires-live-run", reason: `mutation tier blocked and the test-intent tier could not scan either — ${why}` };
    const { ok, output } = ctx.exec("pnpm", ["mutation-scan", ctx.targetDir, ...installArg, ...(outPath ? ["--out", outPath] : [])]);
    if (!ok) return mutationBlocked(`${command} exited non-zero: ${trimOut(output)}`);
    const artifact = readArtifact(ctx, outPath);
    const verdict = mutationVerdict(artifact ?? output);
    if (verdict.kind === "partial") {
      const findings = [...artifactFindings(artifact), ...staticFindings];
      return findings.length ? { status: "partial", detail: command, reason: verdict.note, findings } : { status: "partial", detail: command, reason: verdict.note };
    }
    // #754: no test suite at all is a COMPLETE assessment — the M8-00 zero-coverage finding IS the
    // verdict (CLAUDE.md / #224) — so this reads `ran`, unlike the measurement-gap `partial` above.
    if (verdict.kind === "no-suite") {
      const findings = [...artifactFindings(artifact), ...staticFindings];
      return findings.length ? { status: "ran", detail: command, findings } : { status: "ran", detail: command };
    }
    if (verdict.kind === "unknown") return mutationBlocked(`mutation-scan produced no recognizable verdict: ${trimOut(output)}`);
    const findings = [...artifactFindings(artifact), ...staticFindings];
    return findings.length ? { status: "ran", detail: command, findings } : { status: "ran", detail: command };
  },
};

// M9 (#350): detect-static exits 0 over an empty directory ("loaded 0 source files"). Exit code is
// not evidence of a scan; the file count the tool printed is. Zero files scanned is not `ran`.
// detect-static prints the count to stdout AND writes a bare Finding[] to --out, so status and
// capture (#312) coexist in real runs. #1065: it is the PRODUCT SOURCE count — the total includes
// package.json, which every target has, so this guard was unreachable until 2026-07-25.
const m9Run = (ctx: RunContext): ProbeOutcome => {
  const outPath = captureOut(ctx, "M9");
  const command = `pnpm detect-static ${ctx.targetDir}`;
  const { ok, output } = ctx.exec("pnpm", ["detect-static", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
  if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
  const scanned = productFilesScanned(output);
  if (scanned === undefined) return { status: "requires-live-run", reason: `could not read detect-static output to confirm files were scanned: ${trimOut(output)}` };
  if (scanned === 0) return { status: "requires-live-run", reason: `detect-static scanned 0 product source files under ${ctx.targetDir} — nothing to analyze (empty or non-source target) (#350/#1065)` };
  const findings = readCaptured(ctx, outPath);
  return findings.length ? { status: "ran", detail: command, findings } : { status: "ran", detail: command };
};
// #506: App-Router boundary analysis is per-app — on a monorepo, run detect-static once per app so
// each app's rendering surface is its own row.
const m9: ModuleRunner = { module: "M9", run: perApp(m9Run) };

// M10 classifies live columns, or parses migration SQL when there is no DB (#250) — two tiers, so
// a schema-only pass is partial rather than a skip.
//
// #436 (closes the #420 non-collection gap): pii-classify now emits report-schema Finding[] to
// --out (dataMapToFindings — one finding per PII/PHI/PCI-bearing table, confidence Review), so a
// capturing run collects M10 findings like any other emitter: the live tier reads `ran`, the
// schema tier stays `partial` for the honest reason that remains (no live DB, rows not sampled).
// A coverage-only run (no capture) keeps the explicit not-collected disclosure — findings exist
// only when a capture path was given, and absence must never read as clean.
//
// #357 (untestable in CI): the `connected` branch needs real DB creds and has only ever been
// exercised in its failure path here.
// #1049: the data map itself — the table→PII/PHI/PCI classification every other module's severity is
// weighted by. pii-classify writes it to --data-map-out; a run that captured no map leaves the
// assembler to record M10-ESCALATION-00 rather than escalate nothing silently.
const dataMapOut = (ctx: RunContext, instanceName?: string): string | undefined =>
  ctx.captureDir ? join(ctx.captureDir, instanceName ? `M10-datamap-${refSlug(instanceName)}.json` : "M10-datamap.json") : undefined;

const readDataMap = (ctx: RunContext, path: string | undefined): { dataMap: DataClassMap } | Record<string, never> => {
  const raw = path && ctx.readArtifact ? ctx.readArtifact(path) : undefined;
  return isDataClassMap(raw) ? { dataMap: raw } : {};
};

const M10_NOT_COLLECTED =
  "this run captured no findings (coverage-only, no --findings-out), so no M10 findings are collected into this deliverable — absence here is not-collected, not clean (#436/#420)";

// #529: pii-classify --schema accepts ANY directory of *.sql or a single .sql file, so M10's
// schema tier is not limited to supabase/migrations. Probe the conventional schema locations in
// priority order and classify the first that exists, so a non-Supabase target (Prisma/Drizzle/
// pg_dump) gets real M10 classification instead of a bare "nothing to classify". prisma/migrations
// (the generated migration.sql, which pii-classify's readSchemaSql recurses into) is tried first —
// #758: a Prisma app that hasn't generated any migrations yet (schema.prisma is its only source of
// truth) still gets real classification via the schema.prisma candidates below, lower-priority
// because a generated SQL migration reflects the actually-applied shape when both exist.
const SCHEMA_CANDIDATE_SUBPATHS = [
  join("supabase", "migrations"),
  join("prisma", "migrations"),
  "drizzle",
  join("db", "migrations"),
  "db",
  "migrations",
  "schema.sql",
  "schema.prisma",
  join("prisma", "schema.prisma"),
];

// #506/#538: the schema tier is per-app — each app can carry its own schema layout. Runs against
// the given app dir; `instance` is set only on a multi-app monorepo so a single-app target is one
// untagged row exactly as before. A hint wins over the probe: on a single-target run (no
// instanceName) that's ctx.schemaHint; on a monorepo fan-out, it's ctx.schemaHints[instanceName] —
// its OWN app's hint, never smeared across the fan-out — so an app with an unconventional layout
// still gets pointed at the right place.
const m10Schema = (ctx: RunContext, appPath: string, instanceName?: string): ProbeOutcome => {
  const instance = instanceName ? { instance: instanceName } : {};
  const outPath = ctx.captureDir ? join(ctx.captureDir, instanceName ? `M10-${refSlug(instanceName)}.json` : "M10.json") : undefined;
  const hintPath = instanceName ? ctx.schemaHints?.[instanceName] : ctx.schemaHint;
  const hint = hintPath ? [hintPath] : [];
  const candidates = [...hint, ...SCHEMA_CANDIDATE_SUBPATHS.map((sub) => join(appPath, sub))];
  const conventional = candidates.find((c) => ctx.exists(c));
  // #770: launch-mvp (root `initial_supabase_table_schema.sql`) and nocode-rescue (nested
  // `before/schema.sql`) ship schema DDL under neither a hint nor a conventionally-named location —
  // fall back to a bounded, CREATE-TABLE-filtered discovery before declaring nothing to classify.
  const discovered = conventional ? undefined : ctx.discoverSchemaFiles?.(appPath);
  const schemas = conventional ? [conventional] : (discovered?.files ?? []);
  if (schemas.length === 0) {
    const probed = [...candidates, ...(discovered?.probed ?? [])];
    return { status: "requires-live-run", reason: `no live DB and no schema found — nothing to classify. Probed: ${probed.join(", ")}. pii-classify --schema accepts a migrations dir (supabase/prisma/drizzle) or a schema.sql file (#529)`, ...instance };
  }
  const detail = `pnpm pii-classify --schema ${schemas.join(" ")}`;
  // #1043: the schema tier classifies PRESENCE only. Whether a sensitive column is PROTECTED needs
  // RLS state, anon/authenticated grants and encryption facts that exist only on a live connection —
  // so say so here, because "M10: partial, rows not sampled" reads as though protection was covered.
  const schemaOnly =
    "schema tier only — no live DB, so row-level data was not sampled AND PII protection was not verified (RLS state, anon/authenticated grants and encryption-at-rest are live-only facts); see the M10-PROT-00 row";
  const mapPath = dataMapOut(ctx, instanceName);
  const { ok, output } = ctx.exec("pnpm", ["pii-classify", "--schema", ...schemas, ...(outPath ? ["--out", outPath] : []), ...(mapPath ? ["--data-map-out", mapPath] : [])]);
  if (!ok) return { status: "requires-live-run", reason: `pnpm pii-classify --schema exited non-zero: ${trimOut(output)}`, ...instance };
  if (!outPath) return { status: "partial", detail, reason: `${schemaOnly}. And ${M10_NOT_COLLECTED}`, ...instance };
  const findings = readCaptured(ctx, outPath);
  const dataMap = readDataMap(ctx, mapPath);
  return findings.length ? { status: "partial", detail, reason: schemaOnly, findings, ...dataMap, ...instance } : { status: "partial", detail, reason: schemaOnly, ...dataMap, ...instance };
};

// The env-bound live tier: with no per-DB URL threaded, pii-classify reads SUPABASE_DB_URL from the
// inherited env, so it reaches exactly the one project the operator pointed it at. `dbUrl` (#520)
// overlays a per-project SUPABASE_DB_URL onto the child env so a monorepo classifies EACH enumerated
// project against its own DB, not only the env-configured one.
const m10Live = (ctx: RunContext, instanceName?: string, dbUrl?: string): ProbeOutcome => {
  const instance = instanceName ? { instance: instanceName } : {};
  const outPath = ctx.captureDir ? join(ctx.captureDir, instanceName ? `M10-${refSlug(instanceName)}.json` : "M10.json") : undefined;
  const execOpts = dbUrl ? { env: { SUPABASE_DB_URL: dbUrl } } : undefined;
  const mapPath = dataMapOut(ctx, instanceName);
  const { ok, output } = ctx.exec("pnpm", ["pii-classify", ...(outPath ? ["--out", outPath] : []), ...(mapPath ? ["--data-map-out", mapPath] : [])], execOpts);
  if (!ok) return { status: "requires-live-run", reason: `pnpm pii-classify exited non-zero: ${trimOut(output)}`, ...instance };
  if (!outPath) return { status: "partial", detail: "pnpm pii-classify (live)", reason: `live classification ran, but ${M10_NOT_COLLECTED}`, ...instance };
  const findings = readCaptured(ctx, outPath);
  const dataMap = readDataMap(ctx, mapPath);
  return findings.length ? { status: "ran", detail: "pnpm pii-classify (live)", findings, ...dataMap, ...instance } : { status: "ran", detail: "pnpm pii-classify (live)", ...dataMap, ...instance };
};

const m10: ModuleRunner = {
  module: "M10",
  run: (ctx) => {
    if (ctx.env.connected) {
      const refs = supabaseRefs(ctx);
      // Single project (or none enumerated): one live row off the inherited SUPABASE_DB_URL, as before.
      if (refs.length <= 1) return m10Live(ctx);
      // #520: classify EACH enumerated project against its own DB. Its URL comes from ctx.supabaseDbUrls
      // (run-audit reads SUPABASE_DB_URL_<ref>, the first ref also falling back to plain SUPABASE_DB_URL).
      // A ref with a URL is live-classified against that DB; a ref WITHOUT one keeps an honest
      // requires-live-run row naming the missing credential — never a silent skip.
      return refs.map((ref): ProbeOutcome => {
        const dbUrl = ctx.supabaseDbUrls?.[ref];
        if (!dbUrl) {
          return {
            status: "requires-live-run",
            reason: `no per-DB connection URL for ${ref} — set SUPABASE_DB_URL_<ref> (or SUPABASE_DB_URL for the first project) to live-classify it; see run-audit --help (#520). Recorded, not silently omitted.`,
            instance: ref,
          };
        }
        return { ...m10Live(ctx, ref, dbUrl), instance: ref };
      });
    }
    // Schema tier: per app on a monorepo, single-target otherwise.
    const apps = ctx.apps && ctx.apps.length > 1 ? ctx.apps : undefined;
    if (!apps) return m10Schema(ctx, ctx.targetDir);
    return apps.map((app) => m10Schema(ctx, app.path, app.name));
  },
};

// Exported as the complete set so assertRegistryComplete has something to check — and so a new
// module added to AUDIT_MODULES without a probe fails the registry test rather than shipping silent.
//
// #1042: M1/M2/M3/M6 read their pass artifact inside the probe (a fresh one is their whole missing
// tier, so it derives `ran`); M7 reads its own too (the pass replaces a named not-run claim). The
// remaining five go through foldRecordedPass, which merges a recorded pass's findings and names it
// on the row without ever asserting `ran`. Every module record-pass accepts now has a consumer.
export const AUDIT_RUNNERS: ModuleRunner[] = [m1, m2, m3, foldRecordedPass(m4), foldRecordedPass(m5), m6, m7, foldRecordedPass(m8), foldRecordedPass(m9), foldRecordedPass(m10)];
