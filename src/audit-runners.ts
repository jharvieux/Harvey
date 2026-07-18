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
import { findFreshPass, ranFromPass } from "./audit-pass-artifact.js";
import type { ModuleRunner, RunContext } from "./audit-runner.js";
import type { Finding } from "./findings.js";

// #416: fold a rejected-pass reason (wrong target, stale, malformed) into a probe's not-run reason,
// so a pass artifact that was present but rejected fails loud rather than being silently ignored.
const withRejectedPass = (base: string, reason: string | undefined): string =>
  reason ? `${base} A pass artifact was found but rejected: ${reason}` : base;

const trimOut = (output: string): string => output.trim().slice(0, 200);

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
const mutationVerdict = (input: string | Record<string, unknown>): { kind: "ran" } | { kind: "partial"; note: string } | { kind: "unknown" } => {
  try {
    const parsed = (typeof input === "string" ? JSON.parse(input) : input) as { moduleRecord?: { note?: string }; summary?: unknown };
    if (parsed.moduleRecord && typeof parsed.moduleRecord.note === "string") return { kind: "partial", note: parsed.moduleRecord.note };
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
    // #416: a fresh semantic/live pass artifact is the evidence #311 said `ran` needs. With it, the
    // flagship LLM/live work is proven (and its triage findings flow into the deliverable); without
    // it, M1 stays honestly partial on the mechanical tier alone.
    const pass = findFreshPass(ctx, "M1");
    if (pass.fresh) return ranFromPass(pass.artifact, "pnpm quick-scan (mechanical tier)");
    return {
      status: "partial",
      detail: "pnpm quick-scan (mechanical tier)",
      reason: withRejectedPass("mechanical tier only — the semantic (LLM /vuln-scan → /triage) and live (pnpm detect-deeper) layers are operator passes the orchestrator cannot observe; it has no artifact proving they ran, so it will not assert `ran` from the tier flags (#311; artifact path #416). No M1 security findings are collected into this deliverable — the flagship findings are produced by that paid-LLM pass and src/cli/scan.ts, not the mechanical quick-scan, so absence here is not-collected, not clean (#420)", pass.reason),
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
      const findings = artifactFindings(readArtifact(ctx, outPath));
      return findings.length ? { status: "ran", detail: command, findings } : { status: "ran", detail: command };
    }
    // #416: vitals is not on PATH here (the common case — it's an external plugin). A fresh captured
    // vitals pass artifact still proves M3 ran, so the orchestrator need not have vitals installed to
    // record a real prior run.
    const pass = findFreshPass(ctx, "M3");
    if (pass.fresh) return ranFromPass(pass.artifact, "captured vitals report");
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
const m4: ModuleRunner = {
  module: "M4",
  run: (ctx) => {
    const outPath = captureOut(ctx, "M4");
    const command = `pnpm quality-scan ${ctx.targetDir}`;
    const { ok, output } = ctx.exec("pnpm", ["quality-scan", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
    if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
    const findings = outPath && ctx.readFindings ? ctx.readFindings(outPath) : parseFindings(output);
    if (!findings) return { status: "requires-live-run", reason: `could not read quality-scan output to confirm jscpd ran: ${trimOut(output)}` };
    if (findings.some((f) => (f as { id?: string }).id === "M4-99")) return { status: "partial", detail: command, reason: "jscpd did not complete on every workspace — quality-scan emitted the M4-99 disclosure finding, so duplication coverage is incomplete for this pass (#505)", findings: findings as Finding[] };
    return findings.length ? { status: "ran", detail: command, findings: findings as Finding[] } : { status: "ran", detail: command };
  },
};

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
    const indicatorScanned = indicatorRun.ok ? filesScanned(indicatorRun.output) : undefined;
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
    if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
    return {
      status: "partial",
      detail: command,
      reason: withRejectedPass("review packet assembled, but M6's verdict is a human/LLM pass with no recorded output — a packet is not a verdict, so this does not clear M6's never-run status (#351; artifact path #416). No M6 findings are collected into this deliverable — the verdict is a human/LLM pass over the packet, so absence here is not-collected, not clean (#420)", pass.reason),
      ...(indicatorFindings.length ? { findings: indicatorFindings } : {}),
    };
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
    // #434: perf-scan needs a project ref as its positional arg (SUPABASE_ACCESS_TOKEN travels via
    // the inherited process env — perf-scan reads that itself). --connected is intent, not a reachable
    // project; without a ref threaded through run-audit ctx.supabaseRef there is nothing to call, so
    // this stays partial with that reason instead of shelling out to a usage error.
    if (!ctx.supabaseRef) return { status: "partial", detail: "pnpm detect-static (code tier)", reason: "connected tier flagged but no Supabase project ref was given (run-audit --supabase <ref>) — perf-scan needs a project ref to reach the advisors API (#434)" };
    // #420: perf-scan writes a bare Finding[] to --out, so the advisor-tier findings are captured
    // when the connected pass succeeds (M7's code-tier findings already arrive via the shared
    // detect-static capture under M9).
    const advisorsOut = captureOut(ctx, "M7");
    const advisors = ctx.exec("pnpm", ["perf-scan", ctx.supabaseRef, ...(advisorsOut ? ["--out", advisorsOut] : [])]);
    if (!advisors.ok) return { status: "partial", detail: "pnpm detect-static (code tier)", reason: `advisors failed: ${trimOut(advisors.output)}` };
    const findings = readCaptured(ctx, advisorsOut);
    return findings.length
      ? { status: "ran", detail: "pnpm detect-static (code) + pnpm perf-scan (advisors)", findings }
      : { status: "ran", detail: "pnpm detect-static (code) + pnpm perf-scan (advisors)" };
  },
};

// M8-taxonomy findings out of a mixed detect-static Finding[] (which also carries M6/M7/M9 findings
// from the same source pass) — see src/detectors/test-intent.ts, taxonomy strings "M8 — ...".
const M8_TAXONOMY_PREFIX = "M8 — ";
const testIntentFindings = (findings: Finding[]): Finding[] => findings.filter((f) => f.taxonomy.startsWith(M8_TAXONOMY_PREFIX));

// M8 (#224/#350): a target with no tests is a zero-coverage FINDING, not a skipped module — and
// mutation-scan says so in a machine-readable moduleRecord while exiting 0. The probe reads that
// verdict rather than the exit code: any moduleRecord (no suite #224, dry-run failure #503,
// degraded ladder rung #513, scoped subset run #504) → partial with its note; a full Stryker
// report with no moduleRecord → ran.
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
    // passes — they need no installed deps, so a target without node_modules still gets real M8
    // coverage instead of a blanket requires-live-run. Run this first so its status/findings are
    // available whether or not the mutation tier below can proceed.
    const staticOutPath = ctx.captureDir ? join(ctx.captureDir, "M8-static.json") : undefined;
    const staticCmd = `pnpm detect-static ${ctx.targetDir}`;
    const staticRun = ctx.exec("pnpm", ["detect-static", ctx.targetDir, ...(staticOutPath ? ["--out", staticOutPath] : [])]);
    const staticScanned = staticRun.ok ? filesScanned(staticRun.output) : undefined;
    const staticFindings = staticScanned ? testIntentFindings(readCaptured(ctx, staticOutPath)) : [];

    if (!hasNodeModules(ctx)) {
      if (!staticScanned) return { status: "requires-live-run", reason: `target has no node_modules — StrykerJS needs the target's installed deps and test suite; the source-only test-intent pass also could not confirm a scan: ${trimOut(staticRun.output)}` };
      return {
        status: "partial",
        detail: `${staticCmd} (test-intent tier)`,
        reason: "source (test-intent) tier only — target has no node_modules, so StrykerJS mutation testing could not run (`npm install` in the target to unlock it) (#401)",
        ...(staticFindings.length ? { findings: staticFindings } : {}),
      };
    }

    const outPath = captureOut(ctx, "M8");
    const command = `pnpm mutation-scan ${ctx.targetDir}`;
    const { ok, output } = ctx.exec("pnpm", ["mutation-scan", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
    if (!ok) return { status: "requires-live-run", reason: `${command} exited non-zero: ${trimOut(output)}` };
    const artifact = readArtifact(ctx, outPath);
    const verdict = mutationVerdict(artifact ?? output);
    if (verdict.kind === "partial") {
      const findings = [...artifactFindings(artifact), ...staticFindings];
      return findings.length ? { status: "partial", detail: command, reason: verdict.note, findings } : { status: "partial", detail: command, reason: verdict.note };
    }
    if (verdict.kind === "unknown") return { status: "requires-live-run", reason: `mutation-scan produced no recognizable verdict — cannot confirm M8 ran: ${trimOut(output)}` };
    const findings = [...artifactFindings(artifact), ...staticFindings];
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
// #436 (closes the #420 non-collection gap): pii-classify now emits report-schema Finding[] to
// --out (dataMapToFindings — one finding per PII/PHI/PCI-bearing table, confidence Review), so a
// capturing run collects M10 findings like any other emitter: the live tier reads `ran`, the
// schema tier stays `partial` for the honest reason that remains (no live DB, rows not sampled).
// A coverage-only run (no capture) keeps the explicit not-collected disclosure — findings exist
// only when a capture path was given, and absence must never read as clean.
//
// #357 (untestable in CI): the `connected` branch needs real DB creds and has only ever been
// exercised in its failure path here.
const m10: ModuleRunner = {
  module: "M10",
  run: (ctx) => {
    const outPath = captureOut(ctx, "M10");
    const notCollected =
      "this run captured no findings (coverage-only, no --findings-out), so no M10 findings are collected into this deliverable — absence here is not-collected, not clean (#436/#420)";
    if (ctx.env.connected) {
      const { ok, output } = ctx.exec("pnpm", ["pii-classify", ...(outPath ? ["--out", outPath] : [])]);
      if (!ok) return { status: "requires-live-run", reason: `pnpm pii-classify exited non-zero: ${trimOut(output)}` };
      if (!outPath) return { status: "partial", detail: "pnpm pii-classify (live)", reason: `live classification ran, but ${notCollected}` };
      const findings = readCaptured(ctx, outPath);
      return findings.length ? { status: "ran", detail: "pnpm pii-classify (live)", findings } : { status: "ran", detail: "pnpm pii-classify (live)" };
    }
    const migrations = join(ctx.targetDir, "supabase", "migrations");
    if (!ctx.exists(migrations)) return { status: "requires-live-run", reason: `no live DB and no migrations at ${migrations} — nothing to classify` };
    const detail = `pnpm pii-classify --schema ${migrations}`;
    const schemaOnly = "schema tier only — no live DB, so row-level data was not sampled";
    const { ok, output } = ctx.exec("pnpm", ["pii-classify", "--schema", migrations, ...(outPath ? ["--out", outPath] : [])]);
    if (!ok) return { status: "requires-live-run", reason: `pnpm pii-classify --schema exited non-zero: ${trimOut(output)}` };
    if (!outPath) return { status: "partial", detail, reason: `${schemaOnly}. And ${notCollected}` };
    const findings = readCaptured(ctx, outPath);
    return findings.length ? { status: "partial", detail, reason: schemaOnly, findings } : { status: "partial", detail, reason: schemaOnly };
  },
};

// Exported as the complete set so assertRegistryComplete has something to check — and so a new
// module added to AUDIT_MODULES without a probe fails the registry test rather than shipping silent.
export const AUDIT_RUNNERS: ModuleRunner[] = [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10];
