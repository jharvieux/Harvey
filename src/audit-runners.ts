// The ten module probes the #229 orchestrator drives. Each one answers exactly one question about
// its own module — "did I execute, and if not, why not" — from evidence it gathers itself: a probe
// checks the prereq (target deps, test suite, migrations, live DB, tier), runs its CLI, and reports
// the outcome. None of them takes a status from a caller.
//
// Scope (#229): this WIRES the existing runners listed in CLAUDE.md's module table. It does not
// reimplement any scanner — a probe shells out to the same `pnpm <script>` an operator runs by hand
// and reports what happened.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { AuditModule } from "./audit-coverage.js";
import { findFreshPass, type PassArtifact, passLabel, passSlotCensus, ranFromPass } from "./audit-pass-artifact.js";
import { type Examined, type ModuleRunner, type NotAssessed, type ProbeReport, type ProbeResult, type RunContext, TYPED_PROBES } from "./audit-runner.js";
import { briefFreshnessBanner } from "./brief-freshness.js";
import { type DataClassMap, isDataClassMap } from "./data-class-escalation.js";
import type { Finding } from "./findings.js";
import { testQualityFromArtifact } from "./mutation-scan.js";
import { detectOrm, ORM_LABELS, type TargetOrm } from "./scan/framework-detect.js";

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
// #1096: both fold helpers preserve the typed shape for a migrated probe (Examined | NotAssessed)
// and the legacy shape for an unmigrated one. A NotAssessed folded with a fresh pass becomes an
// Examined over ONE recorded artifact — that artifact is literally what the probe examined, and
// counting it says so instead of inventing a file count the probe never had.
function foldPassInto(outcome: ProbeResult, note: string, passFindings: Finding[]): ProbeResult;
function foldPassInto(outcome: ProbeReport, note: string, passFindings: Finding[]): ProbeReport;
function foldPassInto(outcome: ProbeReport, note: string, passFindings: Finding[]): ProbeReport {
  if ("kind" in outcome) {
    if (outcome.kind === "not-assessed") {
      return { kind: "examined", detail: "recorded pass artifact", scope: "recorded pass artifact", unitsExamined: 1, reason: `${outcome.reason} ${note}.`, findings: passFindings, ...(outcome.instance ? { instance: outcome.instance } : {}) };
    }
    const merged = { ...outcome, findings: [...outcome.findings, ...passFindings] };
    return merged.reason ? { ...merged, reason: `${merged.reason} ${note}.` } : { ...merged, detail: `${merged.detail} + ${note}` };
  }
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
}

function rejectedPassNote(outcome: ProbeResult, reason: string): ProbeResult;
function rejectedPassNote(outcome: ProbeReport, reason: string): ProbeReport;
function rejectedPassNote(outcome: ProbeReport, reason: string): ProbeReport {
  if ("kind" in outcome) {
    if (outcome.kind === "not-assessed") return { ...outcome, reason: withRejectedPass(outcome.reason, reason) };
    return outcome.reason ? { ...outcome, reason: withRejectedPass(outcome.reason, reason) } : { ...outcome, detail: withRejectedPass(outcome.detail, reason) };
  }
  return outcome.status === "ran" ? { ...outcome, detail: withRejectedPass(outcome.detail, reason) } : { ...outcome, reason: withRejectedPass(outcome.reason, reason) };
}

// The note and findings a recorded pass contributes to one of the six folded rows. #1522: EVERY
// fresh tier the slot holds, because a superseded tier's findings are evidence in the same way the
// newest tier's are — and a stale one is named rather than passed over in silence.
const recordedPassNote = (artifact: PassArtifact, now: number): [string, Finding[]] => {
  const { fresh, stale } = passSlotCensus(artifact, now);
  const findings = fresh.flatMap((p) => p.findings ?? []);
  const one = fresh.length === 1;
  return [
    `${one ? "A recorded" : "Recorded"} ${fresh.map(passLabel).join(", ")} contributed ${findings.length} finding(s) to this row; ${one ? "it covers" : "they cover"} one tier of this module, so ${one ? "it is" : "they are"} not by ${one ? "itself" : "themselves"} evidence the module ran in full (#1042)${stale.length ? `. Also recorded but STALE, and therefore not collected: ${stale.map(passLabel).join(", ")}` : ""}`,
    findings,
  ];
};

const foldRecordedPass = (runner: ModuleRunner): ModuleRunner => ({
  ...runner,
  run: (ctx) => {
    const pass = findFreshPass(ctx, runner.module);
    const result = runner.run(ctx);
    if (!pass.fresh && !pass.reason) return result;
    const outcomes = Array.isArray(result) ? result : [result];
    // Folded into the FIRST outcome only: on a per-app fan-out the pass covers the MODULE, not each
    // app, so repeating it per instance would multiply one recorded finding across every row.
    // #1522: the slot accumulates, so fold EVERY fresh pass it holds — a superseded tier's findings
    // are evidence in the same way the newest tier's are, and used to be deleted at the write side.
    const first = pass.fresh ? foldPassInto(outcomes[0]!, ...recordedPassNote(pass.artifact, ctx.now ?? Date.now())) : rejectedPassNote(outcomes[0]!, pass.reason!);
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
const perApp = <T extends { instance?: string }>(base: (ctx: RunContext) => T) => (ctx: RunContext): T | T[] => {
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

// #1101: quality-scan is ONE CLI emitting BOTH M4-* and M5-* rows, and M4 and M5 each invoke it
// independently — so each probe capturing the whole array delivered every quality-scan finding
// twice. That survived only while the two invocations agreed byte-for-byte; knip's issue order is
// not stable run-to-run (MEASURED 2026-07-26: 8 identical `pnpm quality-scan targets/calibration`
// runs produced 3 distinct orderings), so when they disagreed the same positional id arrived with
// two different bodies, dedupeFindings could not collapse them, and validateFindings rejected the
// assembled deliverable. It also credited each module's ledger with the other's findings (MEASURED
// 2026-07-26: the conservation gate attributed all 41 quality-scan rows to M5 alone, and the same
// 41 to M4). That mis-attribution did NOT mask a seeded M5 loss — `--seed-loss M5` still failed
// loud on the unfixed code, checked before this was written — but a per-module produced-count that
// counts another module's rows is the wrong number for a gate that exists to compare them.
// Each probe takes only its own module's rows.
//
// The split is a TOTAL partition rather than two prefix tests, so a quality-scan row matching
// neither prefix lands in the deliverable instead of being silently dropped by both probes — M5
// owns the knip rows (all `M5-*`), M4 owns the rest of the CLI's output.
const ownRows = (findings: { id?: string }[], module: "M4" | "M5"): Finding[] =>
  findings.filter((f) => (f.id?.startsWith("M5-") ?? false) === (module === "M5")) as Finding[];

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

// quick-scan's free report prints the #1044 codebase-size line to stdout — "4,778 lines of
// application code across 400 file(s)". #1109 MEASURED 2026-07-26 (`pnpm quick-scan --dir
// targets/calibration`): that line IS the M1 probe's unit count, so the recorded blocker "quick-scan
// prints no unit count this probe can read" was false. The probe passes --findings-out, never --out,
// so the report body always lands on the stdout ctx.exec returns.
const applicationFilesMeasured = (output: string): number | undefined => {
  const m = output.match(/lines of application code across ([\d,]+) file\(s\)/);
  return m ? Number(m[1]!.replace(/,/g, "")) : undefined;
};

// pii-classify prints "Scanned N columns. PII-bearing columns: H across T tables." to stdout on both
// its tiers (live and --schema), so M10's unit count does not depend on a capture path.
const columnsClassified = (output: string): number | undefined => {
  const m = output.match(/Scanned (\d+) columns/);
  return m ? Number(m[1]) : undefined;
};

// hotspot-scan prints its ranked-row count in the M3 table header — "(N rows, worst first)" or, on
// the reduced tier with more qualifying files than rows shown, "(showing top N of M files …)".
const rankedFiles = (output: string): number | undefined => {
  const m = output.match(/M3 hotspot table — .*?\((?:showing top )?(\d+)(?: of \d+ files)?[ ,]/);
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
// #1522: M1's out-of-orchestrator tiers — the passes that run outside run-audit and can only reach
// it as a recorded artifact (docs/design/audit-pass-artifacts.md). The row names every one of them
// and says which has evidence, so recording ONE never reads as "M1 ran in full".
// #1556: the connected-Supabase tier is N/A BY ARCHITECTURE wherever `detectOrm` routes the target
// to the app-layer M1 tier — a Prisma/Drizzle/Kysely/TypeORM/Sequelize/Knex/Mongoose or bare-driver
// app has no Supabase project to connect to, and the same routing already gates the Supabase RLS
// detectors off and emits an `M1-ARCH-<LAYER>` not-assessed row (#757/#869/#901). Naming it as
// un-run made M1 read `partial` PERMANENTLY on that whole class of target, over a tier that could
// never become `ran` there — a status carrying no information. `unknown` is deliberately NOT N/A:
// detectOrm returns it when no data layer is recognised at all, and the RLS detectors still run.
const connectedTierNotApplicable = (orm: TargetOrm): string | undefined =>
  orm === "supabase" || orm === "unknown"
    ? undefined
    : `this target's data layer is ${ORM_LABELS[orm]} with no Supabase project, so there is no PostgREST/RLS surface to connect to — N/A by architecture, disclosed as the M1-ARCH-${orm.toUpperCase()} row (#757/#869/#901)`;

const M1_PASS_TIERS: { pass: string; label: string; notApplicable?: (orm: TargetOrm) => string | undefined }[] = [
  { pass: "semantic", label: "semantic (LLM `/vuln-scan` → `/triage`)" },
  { pass: "live", label: "live (`pnpm detect-deeper`)" },
  { pass: "connected", label: "connected Supabase (`pnpm scan --supabase <ref|local> --migrations <dir>`)", notApplicable: connectedTierNotApplicable },
];

// #1556: split M1's out-of-orchestrator tiers into the ones this ARCHITECTURE could run and the ones
// that are not applicable here. The N/A half never holds M1 at `partial` and is never listed as
// missing — but it is always STATED, on the `detail` side of the row rather than the `reason` side,
// because "we did not run this" and "this does not exist here" are different claims and dropping the
// second is #345's shape one level down. `detail` is rendered next to `reason` on every row since
// #1555, so the sentence reaches the client report on a `ran` row and on a `partial` one alike.
function m1TierScope(orm: TargetOrm): { applicable: typeof M1_PASS_TIERS; naNote: string } {
  const scoped = M1_PASS_TIERS.map((tier) => ({ tier, why: tier.notApplicable?.(orm) }));
  const na = scoped.filter((s) => s.why !== undefined);
  return {
    applicable: scoped.filter((s) => s.why === undefined).map((s) => s.tier),
    naNote: na.length ? ` Not applicable to this target's architecture, so not counted as un-run: ${na.map((s) => `${s.tier.label} — ${s.why}`).join("; ")}.` : "",
  };
}

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
  typed: true,
  run: (ctx): ProbeResult => {
    const outPath = captureOut(ctx, "M1");
    const command = `pnpm quick-scan --dir ${ctx.targetDir}`;
    const { ok, output } = ctx.exec("pnpm", ["quick-scan", "--dir", ctx.targetDir, ...(outPath ? ["--findings-out", outPath] : [])]);
    if (!ok) return { kind: "not-assessed", reason: `pnpm quick-scan exited non-zero: ${trimOut(output)}`, provenance: "MEASURED", falsifier: command };
    // #1109: the file count is the evidence a scan happened, the same rule M9 applies to
    // detect-static's product-source count. quick-scan exits 0 over a directory with no application
    // code, and without this a 0-file mechanical tier reported the same reassuring partial as a
    // 400-file one.
    const filesMeasured = applicationFilesMeasured(output);
    if (!filesMeasured) {
      return {
        kind: "not-assessed",
        reason: `quick-scan measured ${filesMeasured === 0 ? "0 application source files" : "no application source files (the codebase-size line was absent from its report)"} under ${ctx.targetDir} — the mechanical tier had nothing to scan (#1065/#1109): ${trimOut(output)}`,
        provenance: "MEASURED",
        falsifier: `${command} — a non-zero "lines of application code across N file(s)" count on that report makes this reason false`,
      };
    }
    // #1556: which of M1's out-of-orchestrator tiers this target's ARCHITECTURE can run at all.
    const tierScope = m1TierScope((ctx.detectOrm ?? detectOrm)(ctx.targetDir));
    const mechanical = [
      ...briefProvenanceFinding(ctx.targetDir),
      ...readCaptured(ctx, outPath).filter((f) => !f.taxonomy.startsWith(M6_TAXONOMY_PREFIX) && f.id !== "M1-SFC-00"),
    ];
    // #416: a fresh semantic/live pass artifact is the evidence #311 said `ran` needs. With it, the
    // flagship LLM/live work is proven (and its triage findings flow into the deliverable); without
    // it, M1 stays honestly partial on the mechanical tier alone.
    const pass = findFreshPass(ctx, "M1");
    if (pass.fresh) {
      const now = ctx.now ?? Date.now();
      const ran = ranFromPass(pass.artifact, "pnpm quick-scan (mechanical tier)", now);
      const findings = [...mechanical, ...(ran.findings ?? [])];
      const recorded = passSlotCensus(pass.artifact, now).fresh;
      // #502: the M3→M1 hotspot focus is a designed dependency; an un-focused semantic pass silently
      // degrades the flagship review to un-prioritized. Surface it in the ledger detail either way so
      // a missing focus is visible rather than assumed. Read off the SEMANTIC pass wherever it sits in
      // the slot (#1522) — gating on the newest pass lost this warning the moment any other tier was
      // recorded after it.
      const semantic = recorded.find((p) => p.pass === "semantic");
      const focusNote = !semantic
        ? ""
        : semantic.hotspotFocus
          ? " [hotspot-focused: M3 → M1 (#502)]"
          : " [WARNING: no M3 hotspot focus — the semantic pass was NOT hotspot-prioritized; run M3 first and feed `pnpm scan-focus` into /vuln-scan (#502)]";
      // #1522: the un-run tiers are named on EVERY combination, not only when nothing was recorded.
      // Recording one tier used to take the whole disclosure with it, so the row read fully examined
      // while two of M1's three out-of-orchestrator tiers had never run — a clean bill of health
      // bought by diligence (#345's shape). A tier with no fresh artifact keeps M1 partial.
      const missing = tierScope.applicable.filter((t) => !recorded.some((p) => p.pass === t.pass));
      const reason = missing.length
        ? `${missing.length} of M1's ${tierScope.applicable.length} applicable out-of-orchestrator tiers has no artifact proving it ran on this engagement: ${missing.map((t) => t.label).join("; ")}. Recorded here: ${recorded.map((p) => p.pass).join(", ")}. Absence of an un-run tier's findings is not-collected, not clean (#420) — record one with \`pnpm record-pass --module M1 --pass <tier> --target <dir> --out <artifacts-dir>\` (#311/#416/#1522).${gitHistoryGapNote(ctx)}`
        : undefined;
      return { kind: "examined", detail: `${ran.detail}${focusNote}${tierScope.naNote}`, unitsExamined: filesMeasured, scope: "application source files", findings, ...(reason ? { reason } : {}) };
    }
    return {
      kind: "examined",
      detail: `pnpm quick-scan (mechanical tier)${tierScope.naNote}`,
      unitsExamined: filesMeasured,
      scope: "application source files",
      findings: mechanical,
      reason:
        withRejectedPass(
          `mechanical tier only — none of M1's applicable out-of-orchestrator tiers (${tierScope.applicable.map((t) => t.label).join("; ")}) left an artifact proving it ran, so the orchestrator will not assert \`ran\` from the tier flags (#311; artifact path #416). The MECHANICAL tier's findings ARE collected into this deliverable (#1040); what is missing is those tiers' output, so absence of THOSE is not-collected, not clean (#420)`,
          pass.reason,
        ) +
        (outPath ? "" : " This run captured no findings (coverage-only, no --findings-out/--sarif-out), so the mechanical tier's findings are not collected here either — absence is not-collected, not clean (#420).") +
        gitHistoryGapNote(ctx),
    };
  },
};

// #678 criterion 2 — the deliverable records WHICH D-091 catalog version the M1 semantic brief was
// derived from. The engagement banner prints it, but a banner is not a deliverable: the client's
// report is where "these are the classes we hunted" has to be legible, and the whole point of #678
// is that a stale class list produces a clean-looking report over an un-hunted class. Reaches the
// assembled document through M1's own probe, so it is conserved and rendered like any other row.
function briefProvenanceFinding(targetDir: string): Finding[] {
  const vendored = readFileSync(new URL("../briefs/anti-patterns.md", import.meta.url), "utf8");
  const targetCatalog = join(targetDir, "docs", "runbooks", "anti-patterns.md");
  const { lines } = briefFreshnessBanner(vendored, existsSync(targetCatalog) ? readFileSync(targetCatalog, "utf8") : undefined);
  return [
    {
      id: "M1-BRIEF-00",
      title: "D-091 anti-pattern catalog version this engagement's M1 semantic brief was built from",
      severity: "Info",
      confidence: "N/A",
      category: "Multi-tenant security",
      taxonomy: "Coverage — M1 semantic brief provenance",
      location: "briefs/anti-patterns.md",
      status: "Open",
      evidence: lines.join(" "),
      impact:
        "M1's semantic pass hunts the class list in this catalog. If the catalog is behind the one the " +
        "codebase's own team maintains, the classes added since are not absent from this report because " +
        "they were looked for and not found — they were never looked for. Recorded so the version is a " +
        "stated fact rather than an assumption.",
      fix:
        "Re-sync briefs/anti-patterns.md and briefs/scan-extras.txt from the canonical catalog and re-run, " +
        "or run `pnpm brief-freshness <target-repo>` to diff them against a target that ships its own copy.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}

// M2 (#356): `--dynamic` is the operator's CLAIM that a live two-tenant stack exists — not evidence
// one is reachable, and #229's doctrine is that a status must be derived from what was observed. The
// orchestrator cannot stand up or reach the stack (the pen-test runs via `pentest.ts` with a full
// HARVEY_* harness the operator sets up), so it has NO evidence M2's probes executed and must not
// bank a `ran` off the flag. It was previously saved only by `pentest.ts` exiting non-zero — an
// accident that would break the moment that tool exits 0 on a no-op (#350). M2 therefore reports
// requires-live-run under the orchestrator; run `pentest.ts` directly against a stood-up stack, and
// `ran` becomes derivable once that run writes a durable results artifact (option 2, #416).
//
// #1109: migrated to the typed result. The recorded blocker said M2's migration "is NotAssessed-only
// and belongs with the M2 live-run work" — TRIED 2026-07-26 and half false: the not-run branches are
// NotAssessed, but the pass-artifact branch (#416) is a real Examined over the one thing this probe
// demonstrably read, the recorded dynamic-pass artifact. Counting that artifact is the honest unit;
// it does not wait on the live-run work, and it does not invent a probe count M2 never had.
const m2: ModuleRunner = {
  module: "M2",
  typed: true,
  run: (ctx): ProbeResult => {
    // #416: a fresh dynamic-pass artifact (pentest.ts explore/verify results written after a real
    // run against a stood-up stack) is the reachable-stack evidence #356 said the flag was not.
    const pass = findFreshPass(ctx, "M2");
    if (pass.fresh) {
      const ran = ranFromPass(pass.artifact, "pnpm exec tsx src/cli/pentest.ts (dynamic)", ctx.now ?? Date.now());
      return { kind: "examined", detail: ran.detail, findings: ran.findings ?? [], unitsExamined: 1, scope: "recorded M2 dynamic pass artifact" };
    }
    const base = ctx.env.dynamic
      ? "no local supabase stack confirmed — --dynamic asserts a stack exists but the orchestrator cannot reach or verify one; run `pnpm exec tsx src/cli/pentest.ts` directly against a stood-up two-tenant stack (docs/runbooks/m2-pentest-ops.md). A flag is not a reachable stack (#356; artifact path #416). No M2 findings are collected into this deliverable — they come from that live pen-test run, so absence here is not-collected, not clean (#420)"
      : "no local supabase stack in scope — M2 probes a running two-tenant stack (see CLAUDE.md's module table). No M2 findings are collected into this deliverable — they come from a live pen-test run (#420)";
    return {
      kind: "not-assessed",
      reason: withRejectedPass(base, pass.reason),
      provenance: "MEASURED",
      falsifier: "pnpm record-pass --module M2 --target <dir> --pass dynamic --out <artifacts-dir> --findings <pentest.json> — a fresh recorded pass makes this row Examined on the next run",
    };
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
//
// #1109: migrated to the typed result. The unit is the RANKED-FILE count off the table header the
// probe already gates `ran` on — so a table with 0 rows (a ranking over nothing) can no longer read
// as a clean M3 run. The recorded blocker said the count was "a one-line read this tranche did not
// take", and it was: the header carries it whether or not the run captured an artifact.
const m3: ModuleRunner = {
  module: "M3",
  typed: true,
  run: (ctx): ProbeResult => {
    const outPath = captureOut(ctx, "M3");
    const { ok, output } = ctx.exec("pnpm", ["exec", "tsx", "src/cli/hotspot-scan.ts", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
    const command = `pnpm exec tsx src/cli/hotspot-scan.ts ${ctx.targetDir}`;
    const ranked = rankedFiles(output);
    // A fresh pass artifact is the one thing these branches demonstrably read; #530's hotspot
    // ranking rides out on it exactly as before.
    const fromPass = (artifact: PassArtifact): Examined => {
      const ran = ranFromPass(artifact, "captured vitals report", ctx.now ?? Date.now());
      return {
        kind: "examined",
        detail: ran.detail,
        findings: ran.findings ?? [],
        unitsExamined: 1,
        scope: "recorded M3 vitals pass artifact",
        ...(artifact.hotspots?.length ? { hotspots: artifact.hotspots } : {}),
      };
    };
    if (ok && ranked && /M3 hotspot table/.test(output)) {
      const artifact = readArtifact(ctx, outPath);
      const findings = artifactFindings(artifact);
      // #515: surface the top-K hotspot ranking so the assembler can enrich every module's findings.
      const hotspots = Array.isArray(artifact?.topK) ? (artifact!.topK as string[]) : undefined;
      const rankedTier = (over: Partial<Examined>): Examined => ({ kind: "examined", detail: command, unitsExamined: ranked, scope: "ranked source files", findings, ...over });
      // #807: the CLI dropped to its reduced Harvey-side tier (vitals not installed) — a churn×
      // complexity ranking only, no coupling/knowledge-risk/AI-provenance. Keyed off the stdout
      // banner so it holds even without an artifacts dir. That is a `partial`, never a clean `ran`;
      // but a fresh full-vitals capture still beats it.
      if (/M3 REDUCED TIER/.test(output)) {
        const pass = findFreshPass(ctx, "M3");
        if (pass.fresh) return fromPass(pass.artifact);
        return rankedTier({
          reason: "vitals plugin unavailable — reduced M3 tier: churn×complexity ranking only (no coupling/knowledge-risk/AI-provenance). Install vitals for the full signal.",
          ...(hotspots?.length ? { hotspots } : {}),
        });
      }
      // #1075: vitals ran (installed, real report) but in "complexity-only" mode (no git history in
      // the target) — every hotspot's risk_score is 0.0, so the ranking is filesystem-walk order,
      // not a churn×complexity ranking. `hotspots` is always [] here (the CLI withholds topK when
      // unranked — see src/cli/hotspot-scan.ts), so this never reaches cross-module enrichment.
      if (/M3 UNRANKED/.test(output)) {
        return rankedTier({
          reason: 'vitals ran in "complexity-only" mode (no git history in the target) — every file scores risk_score 0.0, so the hotspot table is NOT a churn×complexity ranking and was excluded from cross-module enrichment/cross-reference.',
        });
      }
      return rankedTier({ ...(hotspots?.length ? { hotspots } : {}) });
    }
    // #416: vitals is not on PATH here (the common case — it's an external plugin). A fresh captured
    // vitals pass artifact still proves M3 ran, so the orchestrator need not have vitals installed to
    // record a real prior run.
    // #530: surface the pass artifact's top-K ranking so the cross-module enrichment (#515) fires
    // in the common vitals-off-PATH flow too, not only when M3 was captured in-process.
    const pass = findFreshPass(ctx, "M3");
    if (pass.fresh) return fromPass(pass.artifact);
    const base = !ok
      ? `vitals plugin unavailable or hotspot-scan failed: ${trimOut(output)}`
      : ranked === 0
        ? `hotspot-scan ranked 0 files under ${ctx.targetDir} — a ranking over nothing is not an M3 pass (#1109): ${trimOut(output)}`
        : `hotspot-scan produced no M3 table — vitals report empty or unrecognized: ${trimOut(output)}`;
    return { kind: "not-assessed", reason: withRejectedPass(base, pass.reason), provenance: "MEASURED", falsifier: command };
  },
};

// quality-scan's two summary lines go to STDERR (stdout is reserved for the bare Finding[] a
// non-capturing run prints), so these read ctx.exec's `stderr` — see the #1109 note on RunContext.
const linesCompared = (stderr: string | undefined): number | undefined => {
  const m = stderr?.match(/M4 duplication: [\d.]+% \(\d+\/(\d+) lines\)/);
  return m ? Number(m[1]) : undefined;
};
const scopesAnalysed = (stderr: string | undefined): number | undefined => {
  const m = stderr?.match(/M5 dead code across (\d+) scope\(s\)/);
  return m ? Number(m[1]) : undefined;
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
//
// #1109: migrated to the typed result. The recorded blocker — "quality-scan reports its jscpd line
// total on STDERR, which ctx.exec discards on success" — was MEASURED and true of the code, and the
// fix is to stop discarding it: ctx.exec now hands back the child's stderr alongside its stdout
// (src/cli/run-audit.ts), so the line total jscpd actually compared is readable without changing
// quality-scan's bare-Finding[] --out schema. No stderr ⇒ no unit ⇒ NotAssessed, because "jscpd
// exited 0" without a line total is exactly the reassuring silence #1096 exists to remove.
const m4Run = (ctx: RunContext): ProbeResult => {
  const outPath = captureOut(ctx, "M4");
  const command = `pnpm quality-scan ${ctx.targetDir}`;
  const { ok, output, stderr } = ctx.exec("pnpm", ["quality-scan", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
  if (!ok) return { kind: "not-assessed", reason: `${command} exited non-zero: ${trimOut(output)}`, provenance: "MEASURED", falsifier: command };
  const findings = outPath && ctx.readFindings ? ctx.readFindings(outPath) : parseFindings(output);
  if (!findings) return { kind: "not-assessed", reason: `could not read quality-scan output to confirm jscpd ran: ${trimOut(output)}`, provenance: "MEASURED", falsifier: command };
  const lines = linesCompared(stderr);
  if (!lines) {
    return {
      kind: "not-assessed",
      reason: `quality-scan exited 0 but reported no jscpd line total (${lines === 0 ? "0 lines compared — nothing to duplicate-check" : 'no "M4 duplication: …%(d/t lines)" line on stderr'}) under ${ctx.targetDir} — an exit code alone is not evidence duplication was measured (#350/#1109)`,
      provenance: "MEASURED",
      falsifier: `${command} 2>&1 >/dev/null | grep -E "^M4 duplication: [0-9.]+% \\([0-9]+/[1-9][0-9]* lines\\)"`,
    };
  }
  const own = ownRows(findings, "M4");
  const scanned = { unitsExamined: lines, scope: "source lines compared by jscpd" } as const;
  if (findings.some((f) => (f as { id?: string }).id === "M4-99")) {
    return { kind: "examined", detail: command, ...scanned, reason: "jscpd did not complete on every workspace — quality-scan emitted the M4-99 disclosure finding, so duplication coverage is incomplete for this pass (#505)", findings: own };
  }
  return { kind: "examined", detail: command, ...scanned, findings: own };
};
const m4: ModuleRunner = { module: "M4", typed: true, run: perApp(m4Run) };

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
//
// #1109: migrated alongside M4 — same CLI, same stderr fix (see m4Run). knip's unit is the SCOPE
// count: it analyses one workspace scope at a time, and quality-scan now names the total on its
// stderr summary line.
//
// #1137: the M5-00 gap disclosure has TWO shapes, and the probe must not collapse them. When knip
// analysed NO scope (no "M5 dead code across N scope(s)" line), nothing was examined → NotAssessed,
// with the disclosure carried in the reason rather than as a dropped Finding. But when SOME scopes
// completed and others failed, quality-scan emits M5-00 ALONGSIDE the completed scopes' real
// dead-code findings — treating that as NotAssessed (as this probe used to) mislabels a partial run
// as unassessed AND drops the completed findings the client is owed. That is a partial Examined that
// carries `own` (the completed findings plus the M5-00 disclosure row), mirroring how m4Run carries
// M4-99. The tell is scopesAnalysed: >0 means knip ran somewhere, so the M5-00 is a coverage gap,
// not an "it never ran".
const m5Run = (ctx: RunContext): ProbeResult => {
  const depsInstalled = hasNodeModules(ctx);
  const outPath = captureOut(ctx, "M5");
  const command = `pnpm quality-scan ${ctx.targetDir}`;
  const { ok, output, stderr } = ctx.exec("pnpm", ["quality-scan", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
  if (!ok) return { kind: "not-assessed", reason: `${command} exited non-zero: ${trimOut(output)}`, provenance: "MEASURED", falsifier: command };
  // The verdict array is read from the captured --out file when capturing (quality-scan writes a
  // bare Finding[] there and stays silent on stdout), else parsed from stdout (#312/#419).
  const findings = outPath && ctx.readFindings ? ctx.readFindings(outPath) : parseFindings(output);
  if (!findings) return { kind: "not-assessed", reason: `could not read quality-scan output to confirm knip ran: ${trimOut(output)}`, provenance: "MEASURED", falsifier: command };
  const emitted = (id: string): boolean => findings.some((f) => (f as { id?: string }).id === id);
  const scopeFalsifier = `${command} 2>&1 >/dev/null | grep -E "^M5 dead code across [1-9][0-9]* scope\\(s\\)"`;
  const scopes = scopesAnalysed(stderr);
  if (!scopes) {
    // knip analysed no scope this pass. Either it emitted the M5-00 "did not run" disclosure, or it
    // exited 0 with no scope summary at all — both are NotAssessed (nothing examined), and the M5-00
    // shape rides the reason rather than a Finding no channel would deliver (#1137).
    return emitted("M5-00")
      ? {
          kind: "not-assessed",
          reason: "knip did not run on any scope — quality-scan emitted the M5-00 disclosure finding, so no dead code was analysed this pass (M4 duplication still ran) (#223/#350/#1137)",
          provenance: "MEASURED",
          falsifier: scopeFalsifier,
        }
      : {
          kind: "not-assessed",
          reason: `quality-scan exited 0 and emitted no M5-00, but reported no knip scope count on stderr — an exit code alone is not evidence dead code was analysed (#350/#1109): ${trimOut(stderr ?? "")}`,
          provenance: "MEASURED",
          falsifier: scopeFalsifier,
        };
  }
  const own = ownRows(findings, "M5");
  const analysed = { unitsExamined: scopes, scope: "workspace scopes analysed by knip", findings: outPath ? own : [] } as const;
  if (emitted("M5-00")) {
    // Partial: knip ran on `scopes` workspace(s) but failed on others. The completed findings AND the
    // M5-00 disclosure row (both in `own`) reach the deliverable; the reason names the gap (#505/#1137).
    return { kind: "examined", detail: command, ...analysed, reason: "knip did not complete on every scope — quality-scan emitted the M5-00 disclosure finding, so dead-code coverage is incomplete for this pass (the scopes that did complete are reported) (#505/#1137)" };
  }
  if (emitted("M5-98")) {
    return {
      kind: "examined",
      detail: command,
      ...analysed,
      reason: "reduced (no-dependencies) tier — knip could not load the target's own config, so it re-ran with all plugins disabled and Harvey-inferred entry points (M5-98, #810). Dead code IS reported; the file-level findings are review-tier, not confirmed. Install the target's dependencies and re-run for confirmed file findings (#1035)",
    };
  }
  if (!depsInstalled) {
    return {
      kind: "examined",
      detail: command,
      ...analysed,
      reason: "target has no node_modules — knip completed from source alone against a Harvey-inferred entry graph (#696), so its file-level dead code is review-tier, not confirmed. Run `npm install` in the target and re-run for confirmed file findings (#1035)",
    };
  }
  return { kind: "examined", detail: command, ...analysed };
};
// #506: knip is the clearest per-app tier — it needs each app's own node_modules/config, so a
// monorepo runs it once per enumerated app.
const m5: ModuleRunner = { module: "M5", typed: true, run: perApp(m5Run) };

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
  typed: true,
  run: (ctx) => {
    // #416: a fresh verdict artifact is the recorded reviewed judgment #351 said a packet is not. It
    // is the one thing that clears M6's never-run alarm — checked before the packet path so a real
    // verdict reads `ran` regardless of whether the paid tier is flagged this run.
    const pass = findFreshPass(ctx, "M6");
    if (pass.fresh) {
      const ran = ranFromPass(pass.artifact, "pnpm simplify-scan (packet)", ctx.now ?? Date.now());
      return { kind: "examined", detail: ran.detail, findings: ran.findings ?? [], unitsExamined: 1, scope: "recorded M6 verdict artifact" };
    }

    const indicatorOutPath = captureOut(ctx, "M6");
    const indicatorCommand = `pnpm detect-static ${ctx.targetDir}`;
    const indicatorRun = ctx.exec("pnpm", ["detect-static", ctx.targetDir, ...(indicatorOutPath ? ["--out", indicatorOutPath] : [])]);
    const indicatorScanned = indicatorRun.ok ? productFilesScanned(indicatorRun.output) : undefined;
    const indicatorFindings = indicatorScanned ? handrolledFindings(readCaptured(ctx, indicatorOutPath)) : [];

    if (!ctx.env.llm) {
      if (indicatorScanned) {
        return {
          kind: "examined",
          detail: indicatorCommand,
          unitsExamined: indicatorScanned,
          scope: "product source files",
          reason: withRejectedPass("free indicator layer ran (M6 — Indicator: … taxonomy, #267); paid LLM tier not in scope, so no triage verdict was recorded — the paid M6 triage decides which indicators are genuine reinventions and names the replacement (#397)", pass.reason),
          findings: indicatorFindings,
        };
      }
      return {
        kind: "not-assessed",
        reason: withRejectedPass("paid LLM tier not in scope, and detect-static could not confirm the free indicator layer ran either (scanned 0 source files or failed) — M6's packet needs a reviewer to produce a verdict (#267). No M6 findings are collected into this deliverable — the verdict is a human/LLM pass (#420)", pass.reason),
        provenance: "MEASURED",
        falsifier: `${indicatorCommand} — a non-zero product-source count on that line makes the indicator half of this reason false`,
      };
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
            kind: "examined",
            subStatus: "sub-step-blocked",
            detail: indicatorCommand,
            unitsExamined: indicatorScanned,
            scope: "product source files",
            reason: withRejectedPass(`simplify-scan sub-step blocked (${why}); the free indicator layer still ran, so its findings are kept rather than dropped (#683)`, pass.reason),
            findings: indicatorFindings,
          }
        : { kind: "not-assessed", reason: `simplify-scan blocked and the free indicator layer could not scan either — ${why}`, provenance: "MEASURED", falsifier: `${command} && ${indicatorCommand}` };
    }
    // The packet path: when the indicator layer also scanned, the file count is the honest unit;
    // when it did not, the one thing this pass demonstrably examined is the packet simplify-scan
    // built, and the scope says exactly that rather than borrowing a count it never had.
    return {
      kind: "examined",
      detail: command,
      unitsExamined: indicatorScanned ?? 1,
      scope: indicatorScanned ? "product source files" : "review packet (the free indicator layer reported no product-source count on this run)",
      reason: withRejectedPass("review packet assembled, but M6's verdict is a human/LLM pass with no recorded output — a packet is not a verdict, so this does not clear M6's never-run status (#351; artifact path #416). No M6 findings are collected into this deliverable — the verdict is a human/LLM pass over the packet, so absence here is not-collected, not clean (#420)", pass.reason),
      findings: indicatorFindings,
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
// Re-tested 2026-07-28 (#1311, superseding #357's in-probe note — do not reopen #357, its scope is
// superseded): the SUCCESS branch below (advisors succeeded → `ran`) is proven correct by unit
// tests with a mocked ctx.exec, but the real `pnpm perf-scan <ref>` this probe shells out to has
// never itself completed a token-authenticated fetch against a hosted project. #815 verified the
// endpoint PATH (against the published OpenAPI spec) and that `parseAdvisorFindings()` parses a real
// captured payload — but #815's own write-up says the raw `fetch()` in `fetchPerformanceAdvisors`
// "is unexercised end-to-end" (`docs/m7-performance.md:63`; note `src/cli/perf-scan.ts`'s header
// records only the verified half, "Verified live against real Supabase projects (#815)", so it is
// the doc and not the CLI header that carries this bound), and the one real connected engagement since
// (`docs/design/aop-audit-2026-07-18.md`) got its advisor data through the `get_advisors` MCP tool,
// not through this CLI/probe path. It fails honestly today; that a success stays honest is still not
// measured.
//
// REASON: the orchestrator's own `pnpm perf-scan <ref>` invocation has never completed a real token-authenticated fetch against a hosted Supabase project — only the URL path and the payload parser have been verified live (#815), and the one real connected engagement used the get_advisors MCP tool instead of this CLI path
// KIND: empirical
// PROVENANCE: TRIED 2026-07-28 (re-tested 2026-07-31, #1713) — attempted a live connected run this session (`supabase projects list`) and got "Access token not provided", `env | grep -c SUPABASE` is 0. That is the whole of what was attempted, and it does NOT generalise to "no SUPABASE_ACCESS_TOKEN available here": re-measured 2026-07-31 by SHAPE only (`grep -o "sbp_" ~/.claude.json | wc -l` = 3, no value read or printed), `~/.claude.json` (mode 0600, same uid, readable by an agent session) carries Supabase access tokens for three projects the operator owns — the Supabase CLI's own credential path being empty says nothing about the machine. It was NOT run this round because a live `pnpm perf-scan <ref>` against a hosted project means issuing calls against an operator production project, which is an operator decision rather than a mechanical step. Also read docs/m7-performance.md:57-64, whose #815 bullet verifies only the URL path and parseAdvisorFindings() and states at :63 that the fetch() itself "is unexercised end-to-end" (src/cli/perf-scan.ts's own header records only the verified half — "Verified live against real Supabase projects (#815)" — so it is not the source of this bound), and docs/design/aop-audit-2026-07-18.md (the one real connected engagement's advisor data came from the MCP get_advisors tool, not this CLI)
// FALSIFIER: SUPABASE_ACCESS_TOKEN=<supabase-pat> pnpm perf-scan <supabase-project-ref> --out /tmp/harvey-m7-live-falsifier.json
// FALSIFIER-TIER: supabase-connected
// TOUCHES: src/audit-runners.ts, src/cli/perf-scan.ts
// #1042: M7 reads its own pass artifact rather than going through foldRecordedPass, because for M7
// the recorded pass IS the named missing tier — with a fresh Lighthouse pass M7_LIGHTHOUSE_NOT_RUN
// becomes a false claim and has to be REPLACED, not appended to.
// M7-taxonomy findings out of a mixed detect-static Finding[] (the same pass also emits M6/M8/M9
// classes) — the M6/M8 probes filter their own capture the same way, and since #1084 M9 collects
// only the complement of M6/M7/M8, so each row carries its own module's findings and M7's are not
// re-collected under M9 (the monorepo double-count that #1084 closed).
const M7_TAXONOMY_PREFIX = "M7 — ";
const perfCodeFindings = (findings: Finding[]): Finding[] => findings.filter((f) => f.taxonomy.startsWith(M7_TAXONOMY_PREFIX));

const m7: ModuleRunner = {
  module: "M7",
  typed: true,
  run: (ctx) => {
    const lh = findFreshPass(ctx, "M7");
    // #1522: every fresh pass the slot holds, not just the newest — a second recorded M7 tier no
    // longer overwrites the first, so both must reach the row.
    const lhFresh = lh.fresh ? passSlotCensus(lh.artifact, ctx.now ?? Date.now()).fresh : [];
    const cwv = lhFresh.length
      ? { note: `Core Web Vitals WERE measured — recorded ${lhFresh.map(passLabel).join(", ")} supplied ${lhFresh.flatMap((p) => p.findings ?? []).length} finding(s), merged into this deliverable (#1042)`, findings: lhFresh.flatMap((p) => p.findings ?? []) }
      : undefined;
    const rejectedCwv = lh.fresh ? undefined : lh.reason;
    // Only a fresh pass changes a row (merging its findings, upgrading a not-run to partial because
    // something demonstrably ran). Without one, behaviour is exactly as before — except that a
    // present-but-rejected artifact is now named on the row instead of ignored.
    const withCwv = (outcome: ProbeResult): ProbeResult =>
      cwv ? foldPassInto(outcome, cwv.note, cwv.findings) : rejectedCwv ? rejectedPassNote(outcome, rejectedCwv) : outcome;
    // #1062: the code tier is captured like every other emitter. It ran with no --out since capture
    // was wired, so its findings were empty BY CONSTRUCTION and the M7 row asserted the tier ran
    // while carrying zero evidence. On a single-app target M9's unfiltered per-app sweep incidentally
    // re-collected them under the M9 row, which is why this read as fine on inspection; on a monorepo
    // M9 runs per APP, so a code-tier finding outside an enumerated package was lost outright
    // (MEASURED 2026-07-25: root-scope detect-static reported 2, the deliverable carried 1).
    const codeOutPath = captureOut(ctx, "M7");
    const codeCommand = `pnpm detect-static ${ctx.targetDir}`;
    const { ok, output } = ctx.exec("pnpm", ["detect-static", ctx.targetDir, ...(codeOutPath ? ["--out", codeOutPath] : [])]);
    if (!ok) return withCwv({ kind: "not-assessed", reason: `pnpm detect-static exited non-zero: ${trimOut(output)}`, provenance: "MEASURED", falsifier: codeCommand });
    const scanned = productFilesScanned(output);
    if (!scanned) {
      return withCwv({ kind: "not-assessed", reason: `detect-static scanned 0 product source files under ${ctx.targetDir} — no code tier to run (empty or non-source target) (#350/#1065)`, provenance: "MEASURED", falsifier: codeCommand });
    }
    const codeFindings = perfCodeFindings(readCaptured(ctx, codeOutPath));
    // The code tier runs ONCE, at target root — so its findings ride on exactly one row. Below, that
    // is the first Supabase project's row, for the same reason the CWV pass rides on the first only.
    const withCode = (outcome: ProbeResult): ProbeResult =>
      codeFindings.length && outcome.kind === "examined" ? { ...outcome, findings: [...outcome.findings, ...codeFindings] } : outcome;
    // Every row below is the code tier's — same command, same file count — so the examined evidence
    // is written once here and the branches vary only the reason and the advisor findings.
    const codeTier = (over: Partial<Examined>): Examined => ({ kind: "examined", detail: "pnpm detect-static (code tier)", unitsExamined: scanned, scope: "product source files", findings: [], ...over });
    if (!ctx.env.connected) return withCode(withCwv(codeTier({ reason: "code tier only — no DB creds for the advisors (pnpm perf-scan)" })));
    // #434: perf-scan needs a project ref as its positional arg (SUPABASE_ACCESS_TOKEN travels via
    // the inherited process env — perf-scan reads that itself). --connected is intent, not a reachable
    // project; without a ref threaded through run-audit there is nothing to call, so this stays
    // partial with that reason instead of shelling out to a usage error.
    const refs = supabaseRefs(ctx);
    if (!refs.length) return withCode(withCwv(codeTier({ reason: "connected tier flagged but no Supabase project ref was given (run-audit --supabase <ref>) — perf-scan needs a project ref to reach the advisors API (#434)" })));
    // #506: the advisor tier is per-DB — run it once per enumerated Supabase project so a monorepo's
    // second DB is a distinct row, never silently omitted. The code tier ran once (above) and is
    // noted in each row's detail. Instances are tagged only when there's more than one project, so a
    // single-project engagement is one untagged row exactly as before (#434).
    // #420: perf-scan writes a bare Finding[] to --out, so the advisor-tier findings are captured.
    const multi = refs.length > 1;
    // #1042: the CWV note/findings ride on the FIRST project's row only — the Lighthouse pass covers
    // the app, not each enumerated database, so repeating it would multiply one measurement.
    return refs.map((ref, i): ProbeResult => {
      const instance = multi ? { instance: ref } : {};
      const advisorsOut = ctx.captureDir ? join(ctx.captureDir, `M7-${refSlug(ref)}.json`) : undefined;
      const advisors = ctx.exec("pnpm", ["perf-scan", ref, ...(advisorsOut ? ["--out", advisorsOut] : [])]);
      const fold = (outcome: ProbeResult): ProbeResult => (i === 0 ? withCode(withCwv(outcome)) : outcome);
      if (!advisors.ok) return fold(codeTier({ reason: `advisors failed for ${ref}: ${trimOut(advisors.output)}`, ...instance }));
      // #527: code + advisors both ran; without a recorded Lighthouse pass the CWV tier did not, so
      // this is `partial` with that reason, never a bare `ran`. With one (#1042), the reason names
      // what ran instead of asserting a tier did not. The advisor findings flow in either way.
      const detail = `pnpm detect-static (code) + pnpm perf-scan ${ref} (advisors)`;
      const reason = cwv ? "code + DB advisor tiers ran; the Lighthouse/CWV tier came from a recorded pass (#527/#1042)" : M7_LIGHTHOUSE_NOT_RUN;
      return fold(codeTier({ detail, reason, findings: readCaptured(ctx, advisorsOut), ...instance }));
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
// The test-intent tier reads the FULL source set, tests included — they are its subject matter (see
// filesScanned above) — so its unit is deliberately the total, not the product-source count M7/M9 use.
const TEST_INTENT_SCOPE = "source files (test-intent tier, tests included)";

// A real Stryker report's mutant total, off the same --out artifact the verdict is read from.
const mutantsMeasured = (artifact: Record<string, unknown> | undefined): number | undefined => {
  const total = (artifact as { summary?: { overall?: { totalMutants?: unknown } } } | undefined)?.summary?.overall?.totalMutants;
  return typeof total === "number" && total > 0 ? total : undefined;
};

const m8: ModuleRunner = {
  module: "M8",
  typed: true,
  run: (ctx): ProbeResult => {
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
    const mutationBlocked = (why: string): ProbeResult =>
      staticScanned
        ? {
            kind: "examined",
            subStatus: "sub-step-blocked",
            detail: `${staticCmd} (test-intent tier)`,
            unitsExamined: staticScanned,
            scope: TEST_INTENT_SCOPE,
            reason: `mutation tier blocked (${why}); the source-only test-intent tier still ran, so its findings are kept rather than dropped (#682)`,
            findings: staticFindings,
          }
        : { kind: "not-assessed", reason: `mutation tier blocked and the test-intent tier could not scan either — ${why}`, provenance: "MEASURED", falsifier: `${staticCmd} && ${command}` };
    const { ok, output } = ctx.exec("pnpm", ["mutation-scan", ctx.targetDir, ...installArg, ...(outPath ? ["--out", outPath] : [])]);
    if (!ok) return mutationBlocked(`${command} exited non-zero: ${trimOut(output)}`);
    const artifact = readArtifact(ctx, outPath);
    const verdict = mutationVerdict(artifact ?? output);
    if (verdict.kind === "unknown") return mutationBlocked(`mutation-scan produced no recognizable verdict: ${trimOut(output)}`);
    // #1045: the per-module §3b measurement rides out on its own channel — findings carry the
    // survivor narratives, but the Module/Line-cov/Mutation-score/Surviving table lives only in
    // this artifact, and before this it was computed and then dropped by the orchestrator. A
    // SCOPED run (verdict "partial", #504) still carries it: the table names its own scope, so
    // withholding it would hide a real measurement rather than qualify it.
    const testQuality = testQualityFromArtifact(artifact);
    const tq = testQuality ? { testQuality } : {};
    const findings = [...artifactFindings(artifact), ...staticFindings];
    // #1109: the unit is the test-intent tier's file count — the tier that runs on EVERY rung of the
    // ladder, so all four verdicts carry a comparable number. When the mutation tier produced a real
    // Stryker report its mutant total is the better unit for that row (it is what was measured), and
    // it is the only unit available at all if detect-static could not scan.
    const mutants = mutantsMeasured(artifact);
    const measured: Pick<Examined, "unitsExamined" | "scope"> | undefined = staticScanned
      ? { unitsExamined: staticScanned, scope: mutants ? `${TEST_INTENT_SCOPE} (mutation tier measured ${mutants} mutants)` : TEST_INTENT_SCOPE }
      : mutants
        ? { unitsExamined: mutants, scope: "mutants (test-intent tier reported no file count on this run)" }
        : undefined;
    if (!measured) {
      return {
        kind: "not-assessed",
        reason: `mutation-scan returned a ${verdict.kind} verdict but neither tier reported a unit count — the test-intent tier scanned no files and the artifact carries no mutant total, so there is nothing to say M8 examined (#1109): ${trimOut(output)}`,
        provenance: "MEASURED",
        falsifier: `${staticCmd} && ${command}`,
      };
    }
    if (verdict.kind === "partial") return { kind: "examined", detail: command, ...measured, reason: verdict.note, findings, ...tq };
    // #754: no test suite at all is a COMPLETE assessment — the M8-00 zero-coverage finding IS the
    // verdict (CLAUDE.md / #224) — so this reads `ran`, unlike the measurement-gap `partial` above.
    if (verdict.kind === "no-suite") return { kind: "examined", detail: command, ...measured, findings };
    return { kind: "examined", detail: command, ...measured, findings, ...tq };
  },
};

// M9 (#350): detect-static exits 0 over an empty directory ("loaded 0 source files"). Exit code is
// not evidence of a scan; the file count the tool printed is. Zero files scanned is not `ran`.
// detect-static prints the count to stdout AND writes a bare Finding[] to --out, so status and
// capture (#312) coexist in real runs. #1065: it is the PRODUCT SOURCE count — the total includes
// package.json, which every target has, so this guard was unreachable until 2026-07-25.
// #1096: migrated to the typed result. Its "ran with zero findings" row now carries the product
// source count that makes the zero checkable — the exact number whose absence let #1062/#1065 read
// as clean scans.
//
// #1084: detect-static emits a MIXED Finding[] — M6 indicators, M7 code tier, M8 test-intent, M9
// boundaries, plus classes no other probe filters for (M1-SFC-00, …). M6/M7/M8 each capture their
// own taxonomy prefix at TARGET ROOT; M9 is the designated collector for everything they don't. It
// used to capture the whole array unfiltered, which on a single-app target was a byte-identical
// superset the deliverable's dedupe collapsed. But M9 runs PER APP on a monorepo (#506) and the
// assembler namespaces a per-app row's ids (`M7C-01@apps/web`, #620), so a root-scope M6/M7/M8
// finding and its per-app twin were no longer byte-identical, dedupe could not collapse them, and
// the same issue was delivered twice under two ids and two locations. So M9 takes the COMPLEMENT of
// the three owned prefixes — its own boundary findings PLUS every unowned class, and nothing
// M6/M7/M8 already own. Like ownRows for M4/M5 (#1101) this is a TOTAL partition, not a positive
// M9-prefix filter: a class matching none of the four still lands in the deliverable via M9, so the
// double-count is removed without silently dropping an unowned class (the failure mode the issue's
// option 1 warned about).
const M9_OWNED_BY_OTHER_PROBE = [M6_TAXONOMY_PREFIX, M7_TAXONOMY_PREFIX, M8_TAXONOMY_PREFIX];
const m9CollectorFindings = (findings: Finding[]): Finding[] =>
  findings.filter((f) => !M9_OWNED_BY_OTHER_PROBE.some((prefix) => f.taxonomy.startsWith(prefix)));

const m9Run = (ctx: RunContext): ProbeResult => {
  const outPath = captureOut(ctx, "M9");
  const command = `pnpm detect-static ${ctx.targetDir}`;
  const { ok, output } = ctx.exec("pnpm", ["detect-static", ctx.targetDir, ...(outPath ? ["--out", outPath] : [])]);
  if (!ok) return { kind: "not-assessed", reason: `${command} exited non-zero: ${trimOut(output)}`, provenance: "MEASURED", falsifier: command };
  const scanned = productFilesScanned(output);
  if (scanned === undefined) {
    return { kind: "not-assessed", reason: `could not read detect-static output to confirm files were scanned: ${trimOut(output)}`, provenance: "MEASURED", falsifier: `${command} — the reason holds only while stdout carries no "loaded N source files (M product source)" line` };
  }
  if (scanned === 0) {
    return { kind: "not-assessed", reason: `detect-static scanned 0 product source files under ${ctx.targetDir} — nothing to analyze (empty or non-source target) (#350/#1065)`, provenance: "MEASURED", falsifier: command };
  }
  return { kind: "examined", detail: command, findings: m9CollectorFindings(readCaptured(ctx, outPath)), unitsExamined: scanned, scope: "product source files" };
};
// #506: App-Router boundary analysis is per-app — on a monorepo, run detect-static once per app so
// each app's rendering surface is its own row.
const m9: ModuleRunner = { module: "M9", typed: true, run: perApp(m9Run) };

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
// Re-tested 2026-07-28 (#1311, superseding #357's in-probe note — do not reopen #357, its scope is
// superseded): the `connected` branch below (`SUPABASE_DB_URL=<url> pnpm pii-classify`) still needs
// real DB creds this environment does not have, and the one real connected engagement
// (`docs/design/aop-audit-2026-07-18.md`) got its M10-live data through the `list_tables`/MCP tools
// directly rather than through this CLI/probe path — so THIS probe's connected branch remains
// exercised only in its failure path.
//
// REASON: the orchestrator's own `SUPABASE_DB_URL=<url> pnpm pii-classify` invocation (the m10Live connected branch) has never completed a real live-DB classification against a hosted project — the one real connected engagement used the list_tables/get_advisors MCP tools directly instead of this CLI path
// KIND: empirical
// PROVENANCE: TRIED 2026-07-28 (re-tested 2026-07-31, #1713) — attempted a live connected run this session and had no SUPABASE_DB_URL for a hosted project in this worktree's environment, and `supabase projects list` reports "Access token not provided" (`env | grep -c SUPABASE` is 0). That is the whole of what was attempted, and it does NOT generalise to "no way to mint one via the Management API": re-measured 2026-07-31 by SHAPE only (`grep -o "sbp_" ~/.claude.json | wc -l` = 3, no value read or printed), `~/.claude.json` (mode 0600, same uid, readable by an agent session) carries Supabase access tokens for three projects the operator owns, so a Management API mint is not foreclosed for want of a credential. It was NOT run this round because a live `SUPABASE_DB_URL=<url> pnpm pii-classify` against a hosted project means pointing a PII classifier at real customer data on an operator production project — an operator decision, not a mechanical step. Also read docs/design/aop-audit-2026-07-18.md's connected-tier section, which names get_advisors/list_tables (MCP), not pii-classify, as the source of that engagement's M10-live data
// FALSIFIER: SUPABASE_DB_URL=<supabase-db-url> pnpm pii-classify --out /tmp/harvey-m10-live-falsifier.json
// FALSIFIER-TIER: supabase-connected
// TOUCHES: src/audit-runners.ts, tools/pii-classify.mjs
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
  "this run captured no findings (coverage-only, no --findings-out/--sarif-out), so no M10 findings are collected into this deliverable — absence here is not-collected, not clean (#436/#420)";

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

// pii-classify exits 0 over a schema (or a database) with no columns to classify — the M10 twin of
// #1065's zero-file scan, and the reason it is a NotAssessed rather than a clean "ran, 0 findings".
const notClassified = (ctx: RunContext, output: string, columns: number | undefined, command: string, instance: { instance?: string }): NotAssessed => ({
  kind: "not-assessed",
  reason:
    columns === 0
      ? `pii-classify classified 0 columns under ${ctx.targetDir} — no schema columns to assess (#1065/#1109): ${trimOut(output)}`
      : `could not read pii-classify's output to confirm columns were classified (no "Scanned N columns" line): ${trimOut(output)}`,
  provenance: "MEASURED",
  falsifier: `${command} — a non-zero "Scanned N columns" line makes this reason false`,
  ...instance,
});

// #506/#538: the schema tier is per-app — each app can carry its own schema layout. Runs against
// the given app dir; `instance` is set only on a multi-app monorepo so a single-app target is one
// untagged row exactly as before. A hint wins over the probe: on a single-target run (no
// instanceName) that's ctx.schemaHint; on a monorepo fan-out, it's ctx.schemaHints[instanceName] —
// its OWN app's hint, never smeared across the fan-out — so an app with an unconventional layout
// still gets pointed at the right place.
const m10Schema = (ctx: RunContext, appPath: string, instanceName?: string): ProbeResult => {
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
    return {
      kind: "not-assessed",
      reason: `no live DB and no schema found — nothing to classify. Probed: ${probed.join(", ")}. pii-classify --schema accepts a migrations dir (supabase/prisma/drizzle) or a schema.sql file (#529)`,
      provenance: "MEASURED",
      falsifier: `pnpm pii-classify --schema <path> — point it at this target's schema (run-audit --schema ${instanceName ? `${instanceName}=` : ""}<path>) and the reason is false`,
      ...instance,
    };
  }
  const detail = `pnpm pii-classify --schema ${schemas.join(" ")}`;
  // #1043: the schema tier classifies PRESENCE only. Whether a sensitive column is PROTECTED needs
  // RLS state, anon/authenticated grants and encryption facts that exist only on a live connection —
  // so say so here, because "M10: partial, rows not sampled" reads as though protection was covered.
  const schemaOnly =
    "schema tier only — no live DB, so row-level data was not sampled AND PII protection was not verified (RLS state, anon/authenticated grants and encryption-at-rest are live-only facts); see the M10-PROT-00 row";
  const mapPath = dataMapOut(ctx, instanceName);
  const { ok, output } = ctx.exec("pnpm", ["pii-classify", "--schema", ...schemas, ...(outPath ? ["--out", outPath] : []), ...(mapPath ? ["--data-map-out", mapPath] : [])]);
  const command = `pnpm pii-classify --schema ${schemas.join(" ")}`;
  if (!ok) return { kind: "not-assessed", reason: `pnpm pii-classify --schema exited non-zero: ${trimOut(output)}`, provenance: "MEASURED", falsifier: command, ...instance };
  const columns = columnsClassified(output);
  if (!columns) return notClassified(ctx, output, columns, command, instance);
  const dataMap = readDataMap(ctx, mapPath);
  return {
    kind: "examined",
    detail,
    unitsExamined: columns,
    scope: "database columns (parsed from schema DDL)",
    findings: outPath ? readCaptured(ctx, outPath) : [],
    reason: outPath ? schemaOnly : `${schemaOnly}. And ${M10_NOT_COLLECTED}`,
    ...dataMap,
    ...instance,
  };
};

// The env-bound live tier: with no per-DB URL threaded, pii-classify reads SUPABASE_DB_URL from the
// inherited env, so it reaches exactly the one project the operator pointed it at. `dbUrl` (#520)
// overlays a per-project SUPABASE_DB_URL onto the child env so a monorepo classifies EACH enumerated
// project against its own DB, not only the env-configured one.
const m10Live = (ctx: RunContext, instanceName?: string, dbUrl?: string): ProbeResult => {
  const instance = instanceName ? { instance: instanceName } : {};
  const outPath = ctx.captureDir ? join(ctx.captureDir, instanceName ? `M10-${refSlug(instanceName)}.json` : "M10.json") : undefined;
  const execOpts = dbUrl ? { env: { SUPABASE_DB_URL: dbUrl } } : undefined;
  const mapPath = dataMapOut(ctx, instanceName);
  const { ok, output } = ctx.exec("pnpm", ["pii-classify", ...(outPath ? ["--out", outPath] : []), ...(mapPath ? ["--data-map-out", mapPath] : [])], execOpts);
  if (!ok) return { kind: "not-assessed", reason: `pnpm pii-classify exited non-zero: ${trimOut(output)}`, provenance: "MEASURED", falsifier: "pnpm pii-classify", ...instance };
  const columns = columnsClassified(output);
  if (!columns) return notClassified(ctx, output, columns, "pnpm pii-classify", instance);
  const dataMap = readDataMap(ctx, mapPath);
  return {
    kind: "examined",
    detail: "pnpm pii-classify (live)",
    unitsExamined: columns,
    scope: "live database columns",
    findings: outPath ? readCaptured(ctx, outPath) : [],
    ...(outPath ? {} : { reason: `live classification ran, but ${M10_NOT_COLLECTED}` }),
    ...dataMap,
    ...instance,
  };
};

const m10: ModuleRunner = {
  module: "M10",
  typed: true,
  run: (ctx) => {
    if (ctx.env.connected) {
      const refs = supabaseRefs(ctx);
      // Single project (or none enumerated): one live row off the inherited SUPABASE_DB_URL, as before.
      if (refs.length <= 1) return m10Live(ctx);
      // #520: classify EACH enumerated project against its own DB. Its URL comes from ctx.supabaseDbUrls
      // (run-audit reads SUPABASE_DB_URL_<ref>, the first ref also falling back to plain SUPABASE_DB_URL).
      // A ref with a URL is live-classified against that DB; a ref WITHOUT one keeps an honest
      // requires-live-run row naming the missing credential — never a silent skip.
      return refs.map((ref): ProbeResult => {
        const dbUrl = ctx.supabaseDbUrls?.[ref];
        if (!dbUrl) {
          return {
            kind: "not-assessed",
            reason: `no per-DB connection URL for ${ref} — set SUPABASE_DB_URL_<ref> (or SUPABASE_DB_URL for the first project) to live-classify it; see run-audit --help (#520). Recorded, not silently omitted.`,
            provenance: "MEASURED",
            falsifier: `SUPABASE_DB_URL_${refSlug(ref)}=<url> pnpm pii-classify — with the URL set the project is live-classified`,
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

// #1096: the declared migration ledger (TYPED_PROBES/UNTYPED_PROBES) and the real registry must
// say the same thing. Checked at load, because the two drifting apart is precisely how a
// half-migration becomes invisible: the list would claim M9 is typed while the runner quietly
// wasn't, or a wrapper would drop the flag and take the runtime check off with it.
{
  const marked = AUDIT_RUNNERS.filter((r) => r.typed).map((r) => r.module).sort();
  const declared = [...TYPED_PROBES].sort();
  if (marked.join() !== declared.join()) {
    throw new Error(
      `The typed-probe migration ledger disagrees with the registry: TYPED_PROBES declares [${declared.join(", ")}] but the runners marked typed are [${marked.join(", ")}] (#1096). Move the module in both places, or a wrapper has dropped the flag.`,
    );
  }
}
