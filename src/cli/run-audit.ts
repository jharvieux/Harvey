// The full-audit runner (#229) — runs all ten modules against a target and DERIVES the coverage
// ledger from what actually executed.
//
//   pnpm exec tsx src/cli/run-audit.ts <target-dir> [--connected] [--dynamic] [--llm]
//       [--out coverage.json] [--findings-out engagement.json] [--meta meta.json]
//       [--artifacts-dir dir] [--supabase <project-ref>]
//
// --supabase (#434): the connected project ref for M7's DB advisor tier (`pnpm perf-scan <ref>`).
// Only meaningful alongside --connected; SUPABASE_ACCESS_TOKEN still comes from the environment
// (perf-scan reads it itself, and it travels through the inherited child-process env unchanged).
// Without it, --connected is recorded intent but M7's advisor call has no project to reach, so M7
// stays partial on the code tier.
//
// --artifacts-dir (#416): where the out-of-orchestrator passes leave their dated results artifact
// (<module>.pass.json — see docs/design/audit-pass-artifacts.md). When a fresh, target-matching
// artifact is present, the M1/M2/M3/M6 probes DERIVE `ran` from it instead of reporting partial/
// requires-live-run. Omit it and those passes stay honestly not-run under the orchestrator.
//
// (No `pnpm run-audit` alias yet — adding one edits package.json, which is operator-owned.)
//
// --findings-out (#312): assemble ONE engagement findings.json — each emitting module's captured
// findings plus the derived coverage ledger — in the shape report-template/ and `pnpm
// validate:findings` consume. Removes the manual "collect every module's output by hand" step.
// --meta points at the engagement metadata (client, health, headline); omit it and the file carries
// a placeholder meta with a loud warning to fill it before the report ships.
//
// --baseline (#457): a prior engagement findings.json for the SAME client. When given (with
// --findings-out), each current finding is classified resolved/persistent/new by stable finding
// identity (src/audit-diff.ts) and the deliverable leads with a progress view. Omit it and behaviour
// is unchanged.
//
// The tier flags declare which environments the engagement HAS, not which modules to run: every
// module is always attempted, and a module whose environment is absent is recorded
// requires-live-run with that reason. There is no flag that skips a module — that is the point.
//
// Contrast with `pnpm audit-coverage --coverage <file>`, which gates a ledger a human wrote by
// hand: it enforces bookkeeping discipline, but cannot detect that you skipped M5. This command
// needs no such trust — every row is a probe's return value.
//
// Exit 1 on any coverage gap, never-run module, or crashed runner.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { assembleEngagementDocument } from "../audit-report.js";
import { buildExecutionPlan, formatExecutionPlan } from "../audit-plan.js";
import { assertAuditComplete, AUDIT_MODULES, buildAuditCoverage, type EngagementEnv, formatAuditCoverage } from "../audit-coverage.js";
import { applyBaseline } from "../audit-diff.js";
import { EXECUTION_LOG_PATH, readExecutionLog, recordExecutions } from "../audit-execution-log.js";
import { formatFailures, runAudit, type RunContext } from "../audit-runner.js";
import { AUDIT_RUNNERS } from "../audit-runners.js";
import { discoverTargets } from "../pentest/targets.js";
import { type Finding, type FindingsDocument, type ReportMeta, validateFindings } from "../findings.js";

// A valid-but-empty meta for the --findings-out scaffold when no engagement --meta was supplied.
// Deliberately blank (not invented): the coverage ledger and findings are derived; client, health,
// and headline are human judgements the operator fills before the report ships.
const placeholderMeta = (target: string): ReportMeta => ({
  client: "", subtitle: "", date: new Date().toISOString().slice(0, 10), commit: "", auditor: "",
  confidential: true, overallHealth: 0, tenantIsolation: "", authModel: "", headline: "",
  scope: target, methodology: "", outOfScope: "",
});

const args = process.argv.slice(2);
const targetArg = args.find((a) => !a.startsWith("--"));
const flagValue = (flag: string): string | undefined => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};
const flagValues = (flag: string): string[] => args.flatMap((a, i) => (a === flag && args[i + 1] ? [args[i + 1]!] : []));
const outPath = flagValue("--out");
const findingsOut = flagValue("--findings-out");
const metaPath = flagValue("--meta");
const artifactsDir = flagValue("--artifacts-dir");
// #506: --supabase is repeatable — one project ref per Supabase project on a monorepo. M7's advisor
// tier fans out over all of them. supabaseRef keeps the single-ref field for back-compat.
const supabaseRefsArg = flagValues("--supabase");
const supabaseRef = supabaseRefsArg[0];
// #457: a prior engagement's findings.json to diff this run against (resolved/persistent/new).
const baselinePath = flagValue("--baseline");

if (!targetArg) {
  console.error("usage: pnpm exec tsx src/cli/run-audit.ts <target-dir> [--connected] [--dynamic] [--llm] [--out coverage.json] [--findings-out engagement.json] [--meta meta.json] [--artifacts-dir dir] [--supabase <project-ref>] [--baseline prior-findings.json]");
  process.exit(2);
}

// The baseline diff is written INTO the engagement findings.json, so it only means something with
// --findings-out. Fail loud rather than silently ignoring a --baseline the operator asked for.
if (baselinePath && !findingsOut) {
  console.error("--baseline requires --findings-out: the resolved/persistent/new diff is written into the engagement findings document.");
  process.exit(2);
}

const targetDir = resolve(targetArg);

// #506: enumerate the monorepo's apps (pnpm-workspace packages with a package.json) so the per-app
// tiers (M4/M5/M9, M10 schema) run once per app and record one ledger row each. A single-app repo
// enumerates one app and the tiers behave exactly as before (no per-instance rows).
const appList = discoverTargets(targetDir).apps.map((a) => ({ name: a.name, path: a.path }));

const env: EngagementEnv = {
  connected: args.includes("--connected"),
  dynamic: args.includes("--dynamic"),
  llm: args.includes("--llm"),
};

// Capture is only wired when an engagement document is requested — a coverage-only run keeps its
// prior behaviour and never asks the module CLIs for their --out artifacts.
const captureDir = findingsOut ? mkdtempSync(join(tmpdir(), "harvey-audit-")) : undefined;

const ctx: RunContext = {
  targetDir,
  env,
  exec: (command, argv) => {
    try {
      const output = execFileSync(command, argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      return { ok: true, output };
    } catch (err) {
      // A tool that exits non-zero or is not installed is a real outcome the probe must judge, not
      // an orchestrator crash — hand it back and let the module's probe describe it.
      const e = err as { stdout?: string; stderr?: string; message?: string };
      return { ok: false, output: e.stderr || e.stdout || e.message || "" };
    }
  },
  exists: existsSync,
  captureDir,
  readFindings: (p) => {
    if (!existsSync(p)) return [];
    const parsed = JSON.parse(readFileSync(p, "utf8"));
    if (!Array.isArray(parsed)) throw new Error(`captured findings at ${p} is not a Finding[] array`);
    return parsed as Finding[];
  },
  // #420: the object-artifact reader — no array assertion, so M3/M8's { ... } --out shapes parse
  // instead of throwing. Missing file → undefined (the CLI declined to write one).
  readArtifact: (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : undefined),
  // #416: where the out-of-orchestrator passes leave <module>.pass.json, and the clock the probes
  // judge freshness against. Undefined artifactsDir ⇒ those probes stay honestly not-run.
  artifactsDir: artifactsDir ? resolve(artifactsDir) : undefined,
  now: Date.now(),
  supabaseRef,
  supabaseRefs: supabaseRefsArg,
  apps: appList,
};

console.log(`\nFull audit — ${targetDir}`);
console.log(`Tiers in scope: source${env.connected ? " + connected" : ""}${env.dynamic ? " + dynamic" : ""}${env.llm ? " + llm" : ""}`);
if (appList.length > 1) console.log(`Monorepo apps enumerated (per-app tiers fan out): ${appList.map((a) => a.name).join(", ")}`);
if (supabaseRefsArg.length > 1) console.log(`Supabase projects enumerated (M7 advisors fan out): ${supabaseRefsArg.join(", ")}`);
console.log("");

const { recorded, failures, findings, hotspots } = runAudit(AUDIT_RUNNERS, ctx);
const report = buildAuditCoverage(recorded, env);

console.log(formatAuditCoverage(report));

// #502: the flagship passes run OUTSIDE this process; print their correct dependency order so the
// M3 → scan-focus → M1-semantic → triage chain is not left to tribal knowledge (it was violated on
// the ATC engagement, silently un-prioritizing the semantic review).
console.log(`\n${formatExecutionPlan(buildExecutionPlan(env))}`);
if (outPath) {
  writeFileSync(outPath, JSON.stringify(recorded, null, 2));
  console.log(`\nDerived coverage ledger → ${outPath}`);
}

// #312: assemble the single engagement findings.json — the captured findings plus the derived
// coverage ledger, so a never-run module is visible in the deliverable rather than reading as
// "no findings". Meta is engagement metadata run-audit cannot derive: take it from --meta, else
// scaffold a placeholder and say loudly that it must be filled before the report ships.
if (findingsOut) {
  const meta: ReportMeta = metaPath ? (JSON.parse(readFileSync(metaPath, "utf8")) as ReportMeta) : placeholderMeta(targetDir);
  let doc = assembleEngagementDocument(recorded, env, findings, meta, hotspots);

  // #457: diff against a prior engagement so the deliverable leads with progress. The baseline is a
  // full findings.json from a previous audit of the SAME client; we diff by finding identity
  // (src/audit-diff.ts) and tag each current finding resolved/persistent/new.
  if (baselinePath) {
    const prior = JSON.parse(readFileSync(baselinePath, "utf8")) as FindingsDocument;
    if (!Array.isArray(prior.findings)) {
      console.error(`--baseline ${baselinePath} is not a findings document (no findings[] array).`);
      process.exit(1);
    }
    const priorLabel = [prior.meta?.date, prior.meta?.commit].filter(Boolean).join(" @ ") || undefined;
    doc = applyBaseline(doc, prior.findings, priorLabel);
    console.log(`\nBaseline diff vs ${baselinePath}: ${doc.baseline?.counts.resolved} resolved, ${doc.baseline?.counts.persistent} persistent, ${doc.baseline?.counts.new} new`);
  }

  const { ok, errors } = validateFindings(doc);
  if (!ok) {
    console.error(`\nAssembled findings document is invalid — refusing to write ${findingsOut}:`);
    for (const e of errors) console.error(`  ✗ ${e}`);
    process.exit(1);
  }
  writeFileSync(findingsOut, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`\nEngagement findings (${doc.findings.length} finding(s) + coverage ledger) → ${findingsOut}`);
  if (!metaPath) console.error("⚠ no --meta given: the deliverable carries a PLACEHOLDER meta — fill client/health/headline/scope before rendering the report.");
}

// #284: the never-run ledger is the complement of this log, so a module that genuinely ran here
// clears its never-run alarm by BANKING THE EVIDENCE — no one edits a Set by hand. Only a full
// `ran` counts: a partial produced real output but not the module's whole scope, and the claim the
// ledger makes is that the module has proven itself end to end at least once.
//
// Written with --record so a dry run can't quietly retire an alarm; the diff is reviewed like any
// other claim about what happened.
if (args.includes("--record")) {
  const ranModules = AUDIT_MODULES.filter((m) => recorded.some((r) => r.module === m && r.status === "ran"));
  const updated = recordExecutions(AUDIT_MODULES, readExecutionLog(), ranModules, targetDir, new Date().toISOString().slice(0, 10), `pnpm exec tsx src/cli/run-audit.ts ${targetDir}`);
  writeFileSync(EXECUTION_LOG_PATH, `${JSON.stringify(updated, null, 2)}\n`);
  console.log(`\nExecution log updated → ${EXECUTION_LOG_PATH} (commit it: it is the evidence behind MODULES_NEVER_EXECUTED)`);
}

if (failures.length) {
  console.error(`\n${formatFailures(failures)}`);
  process.exit(1);
}

try {
  assertAuditComplete(recorded, env);
} catch (err) {
  console.error(`\n${(err as Error).message}`);
  process.exit(1);
}
console.log("\nCOVERAGE PASS — all ten modules accounted for, derived from actual execution.");
