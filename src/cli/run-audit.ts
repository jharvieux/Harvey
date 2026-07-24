// The full-audit runner (#229) — runs all ten modules against a target and DERIVES the coverage
// ledger from what actually executed.
//
//   pnpm exec tsx src/cli/run-audit.ts <target-dir> [--connected] [--dynamic] [--llm]
//       [--out coverage.json] [--findings-out engagement.json] [--sarif-out findings.sarif]
//       [--sbom-out sbom.json] [--meta meta.json]
//       [--artifacts-dir dir] [--supabase <project-ref>]... [--allow-target-install]
//       [--schema <path>]... | [--schema <app-name>=<path>]...
//
// --schema (#529, per-app form #538): an explicit schema location for M10's schema tier (a
// migrations dir or a single .sql file), tried ahead of the conventional-location probe. For a
// target whose schema is not at supabase/migrations, prisma/migrations, drizzle/, db/, or
// schema.sql. REPEATABLE, two forms:
//   --schema <path>              a single-target hint (applies when the target enumerates ≤1 app —
//                                 back-compat with #529's original single-value behavior).
//   --schema <app-name>=<path>   a per-app hint on a monorepo, keyed by the app name run-audit
//                                 discovers (printed at startup when apps are enumerated — see
//                                 "Monorepo apps enumerated" below). One pair per app whose layout
//                                 the conventional-location probe would not find; other apps still
//                                 fall back to that probe.
// Both forms may appear in the same invocation (bare paths and app=path pairs are independent), but
// mixing them for the SAME app is not meaningful — the bare path never applies once >1 app is
// enumerated.
//
// #770: when neither a hint nor the conventional-location probe finds anything, the schema tier
// falls back to discovering schema DDL itself — a bounded, CREATE-TABLE-filtered search for a
// schema.sql living somewhere unconventional (a project root under an unrelated name, or nested
// under a directory the probe doesn't know to look in). No flag needed; this only ever narrows the
// "nothing to classify" gap, never overrides a hint or a conventional match.
//
// Per-DB M10 live classification (#520): on a multi-project connected run, each --supabase project's
// live DB is classified against its own connection URL, read from `SUPABASE_DB_URL_<REF>` (the ref
// uppercased, non-alphanumerics → `_`; the first ref also falls back to plain SUPABASE_DB_URL). A
// project with no URL supplied keeps an honest requires-live-run row rather than being skipped.
//
// --supabase (#434): the connected project ref for M7's DB advisor tier (`pnpm perf-scan <ref>`).
// Only meaningful alongside --connected; SUPABASE_ACCESS_TOKEN still comes from the environment
// (perf-scan reads it itself, and it travels through the inherited child-process env unchanged).
// Without it, --connected is recorded intent but M7's advisor call has no project to reach, so M7
// stays partial on the code tier. REPEATABLE (#506): pass it once per Supabase project on a
// monorepo — M7's advisor tier fans out over all of them, one ledger row each.
//
// --allow-target-install (#523): consent for M8's mutation tier to provision missing Stryker
// packages into the target via `npm install --no-save` (which runs the target's npm lifecycle
// scripts). Default off — a real trust-boundary decision, so it must be explicit; without it a cold
// client target degrades to the loud "re-run with --install" partial instead of installing silently.
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
// --sarif-out (#867): the same findings AND the derived coverage ledger as SARIF 2.1.0, for
// GitHub code scanning / an ASPM the client already runs. The ledger rides as warning-level
// toolExecutionNotifications so a module that did not run cannot vanish into "no results" — see
// the decision recorded at the top of src/sarif.ts.
//
// --sbom-out (#887): a CycloneDX 1.5 SBOM of the target's dependencies, for the buyer's
// procurement/questionnaire process. It is an inventory, not an assessment — its completeness is
// stated in the document itself and printed here when the tree could not be fully resolved.
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
import { basename, join, resolve } from "node:path";
import { assembleEngagementDocument, coverageLedger } from "../audit-report.js";
import { buildExecutionPlan, formatExecutionPlan } from "../audit-plan.js";
import { assertAuditComplete, AUDIT_MODULES, buildAuditCoverage, type EngagementEnv, formatAuditCoverage } from "../audit-coverage.js";
import { applyBaseline } from "../audit-diff.js";
import { EXECUTION_LOG_PATH, readExecutionLog, recordExecutions } from "../audit-execution-log.js";
import { formatFailures, runAudit, type RunContext } from "../audit-runner.js";
import { AUDIT_RUNNERS } from "../audit-runners.js";
import { discoverSchemaFiles } from "../dynamic-validate.js";
import { discoverTargets } from "../pentest/targets.js";
import { isGitRepoRoot } from "../scan/secrets.js";
import { toSarif } from "../sarif.js";
import { buildSbom } from "../sbom.js";
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
const sarifOut = flagValue("--sarif-out");
const sbomOut = flagValue("--sbom-out");
const artifactsDir = flagValue("--artifacts-dir");
// #506: --supabase is repeatable — one project ref per Supabase project on a monorepo. M7's advisor
// tier fans out over all of them. supabaseRef keeps the single-ref field for back-compat.
const supabaseRefsArg = flagValues("--supabase");
const supabaseRef = supabaseRefsArg[0];
// #457: a prior engagement's findings.json to diff this run against (resolved/persistent/new).
const baselinePath = flagValue("--baseline");
// #529 (per-app form #538): an explicit schema location for M10's schema tier, tried ahead of the
// conventional-location probe (supabase/migrations, prisma/migrations, drizzle, db/, schema.sql).
// --schema is repeatable: a bare path (no "=") is the single-target hint — back-compat with #529's
// original single-value behavior, last bare value wins if more than one is given; an
// "<app-name>=<path>" pair targets one specific app's schema tier on a monorepo, keyed by the app
// name run-audit discovers below (appList).
const schemaArgs = flagValues("--schema");
let schemaHint: string | undefined;
const schemaHints: Record<string, string> = {};
for (const schemaArg of schemaArgs) {
  const eq = schemaArg.indexOf("=");
  if (eq > 0) schemaHints[schemaArg.slice(0, eq)] = schemaArg.slice(eq + 1);
  else schemaHint = schemaArg;
}

// #520: per-Supabase-project DB connection URLs for M10's live tier. Convention: one env var per
// project ref, `SUPABASE_DB_URL_<REF>` where <REF> is the ref uppercased with every non-alphanumeric
// char turned into `_` (e.g. ref `proj-rag` → `SUPABASE_DB_URL_PROJ_RAG`). The first `--supabase`
// ref also falls back to the plain `SUPABASE_DB_URL`, so a single-project engagement needs no new
// var. A ref with no URL keeps its honest requires-live-run row rather than being silently skipped.
const dbUrlEnvKey = (ref: string): string => `SUPABASE_DB_URL_${ref.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
const supabaseDbUrls: Record<string, string> = {};
supabaseRefsArg.forEach((ref, i) => {
  const url = process.env[dbUrlEnvKey(ref)] ?? (i === 0 ? process.env.SUPABASE_DB_URL : undefined);
  if (url) supabaseDbUrls[ref] = url;
});

if (!targetArg) {
  console.error("usage: pnpm exec tsx src/cli/run-audit.ts <target-dir> [--connected] [--dynamic] [--llm] [--out coverage.json] [--findings-out engagement.json] [--sarif-out findings.sarif] [--sbom-out sbom.json] [--meta meta.json] [--artifacts-dir dir] [--supabase <project-ref>] [--schema <path> | --schema <app-name>=<path>] [--allow-target-install] [--baseline prior-findings.json]");
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
  exec: (command, argv, opts) => {
    try {
      const output = execFileSync(command, argv, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        // #520: overlay a per-child env (e.g. a per-project SUPABASE_DB_URL for M10's live tier) onto
        // the inherited environment; absent ⇒ inherit unchanged.
        ...(opts?.env ? { env: { ...process.env, ...opts.env } } : {}),
      });
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
  allowTargetInstall: args.includes("--allow-target-install"),
  schemaHint,
  schemaHints,
  discoverSchemaFiles,
  supabaseDbUrls,
  isGitRepoRoot,
};

console.log(`\nFull audit — ${targetDir}`);
console.log(`Tiers in scope: source${env.connected ? " + connected" : ""}${env.dynamic ? " + dynamic" : ""}${env.llm ? " + llm" : ""}`);
if (appList.length > 1) console.log(`Monorepo apps enumerated (per-app tiers fan out): ${appList.map((a) => a.name).join(", ")}`);
if (supabaseRefsArg.length > 1) console.log(`Supabase projects enumerated (M7 advisors fan out): ${supabaseRefsArg.join(", ")}`);
if (Object.keys(schemaHints).length) console.log(`Per-app schema hints (M10, #538): ${Object.entries(schemaHints).map(([app, path]) => `${app}=${path}`).join(", ")}`);
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
// The findings the SARIF export ships: the assembled document's when one was built (so the
// baseline diff's tags ride along), else the raw captured set.
let exportFindings: Finding[] = findings;

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
  exportFindings = doc.findings;
}

// #867: SARIF 2.1.0 for the client's own security tooling. The coverage ledger travels with it as
// toolExecutionNotifications — an export that dropped it would read as a clean bill of health for
// every module that never ran.
if (sarifOut) {
  // coverageLedger, not the raw `recorded` rows: it is the same derived ledger the findings
  // document carries (module names filled in, and a module that was never accounted for at all
  // still gets a row), so the two exports of one run cannot disagree about what ran.
  const ledger = coverageLedger(recorded, env);
  const sarif = toSarif(exportFindings, { coverage: ledger }, { baseUri: targetDir });
  writeFileSync(sarifOut, `${JSON.stringify(sarif, null, 2)}\n`);
  const gaps = ledger.filter((r) => r.status !== "ran").length;
  console.log(`\nSARIF 2.1.0 (${exportFindings.length} result(s), ${gaps} coverage notification(s)) → ${sarifOut}`);
}

// #887: the CycloneDX inventory. Separate from the findings entirely — an SBOM asserts what is
// installed, not what is wrong with it.
if (sbomOut) {
  const { bom, warning } = buildSbom(targetDir, { targetName: basename(targetDir) });
  writeFileSync(sbomOut, `${JSON.stringify(bom, null, 2)}\n`);
  console.log(`\nCycloneDX SBOM (${(bom as { components: unknown[] }).components.length} component(s)) → ${sbomOut}`);
  if (warning) console.error(`⚠ SBOM is not a complete inventory: ${warning}`);
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
