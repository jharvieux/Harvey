// harvey quick-scan — the free freemium tier. Runs the mechanical scan layer locally
// (src/scan/mechanical.ts) against a target directory and prints the free-tier DIAGNOSIS:
// grade, counts, located findings + a plain-English risk line each, and ONE fully-revealed
// sample finding with its fix. The remediation for every other finding, the deep scan,
// the re-scan diff, and the exportable report are gated behind the paid unlock.
//
//   pnpm quick-scan --dir <path> [--bundle <path>] [--tenant-key <column>]
//                    [--tenant-mode per-tenant|per-user] [--json] [--out <file>]
//                    [--findings-out <file>] [--sarif-out <file>] [--sbom-out <file>]
//
// --sbom-out (#887): a CycloneDX 1.5 SBOM of the target's dependencies — the procurement artifact
// buyers ask for contractually. Built from the target's lockfile (src/sbom.ts); when the tree
// cannot be resolved the document says so in its own compositions/properties AND the CLI prints
// the reason, so an incomplete inventory is never handed over looking complete.
//
// --sarif-out (#867): the raw mechanical Finding[] as SARIF 2.1.0, for GitHub code scanning or an
// ASPM the client already runs. quick-scan has NO coverage ledger to export — it is one tier of one
// module — so the SARIF carries an explicit "no ledger, and here is the scope this actually covers"
// notification rather than presenting a mechanical scan as a completed audit.
//
// --findings-out (#528): write the RAW mechanical Finding[] (the input to the free report, before
// the free/paid gating) as a JSON array — the machine-readable feed the orchestrator's M1 probe
// reads to detect coverage-disclosure findings (e.g. SEC-TH-GH-00, git-history tier unassessed).
// Distinct from --out, which writes the gated free diagnosis.
//
// Privacy: the scan runs locally and NO SOURCE CODE leaves the machine. Two mechanical
// checks make network calls that send non-source data only — TruffleHog (--only-verified)
// sends secret hashes to verify liveness, OSV sends dependency coordinates to match CVEs.
// Neither uploads your code. The DEEP scan (paid) is the only tier that needs code egress.
//
// --tenant-key / --tenant-mode (#280): the same declaration detect-deeper.ts (connected tier)
// accepts, so the static RLS-tenancy review (SB-RLS-TENANCY-MODEL) can be told the app's tenancy
// convention instead of only inferring it from a fixed candidate-column list.

import "./sync-stdio.js";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { arg, assertKnownFlags, targetDir } from "./args.js";
import { classifyMigrationSql, classifyPrismaSchema } from "../../tools/pii-classify.mjs";
import { loadSources } from "../detectors/load-sources.js";
import { readRecursiveSafe } from "../fs-walk.js";
import { measureCodebaseSize } from "../scan/codebase-size.js";
import { runJscpd } from "../scan/duplication.js";
import { detectOrm, detectTargetFramework, nonNextWorkspaces } from "../scan/framework-detect.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import { relativizeScanScope } from "../scan/scan-scope.js";
import { CI_PIPELINE_CATEGORY } from "../scan/semgrep.js";
import { buildSbom } from "../sbom.js";
import { buildHealthScorecard, type HealthDimension, type HealthScorecard, type PiiTableBand, type ScorecardInput } from "../health-scorecard.js";
import { duplicationSummary, jscpdToFindings } from "../quality-scan.js";
import { buildQuickScanReport, selectGradedFindings, HANDROLLED_FILES_SHOWN, HANDROLLED_SECTION_BLURB, HANDROLLED_SECTION_TITLE, type QuickScanReport } from "../quick-scan.js";
import { toSarif } from "../sarif.js";

// What a quick-scan SARIF export does and does not cover. Stated in the export itself because a
// SARIF file outlives the terminal session that produced it: an importer who sees only results has
// no way to know which modules were attempted.
//
// #1305: DERIVED from the scorecard, never written out by hand. The hardcoded version said "the
// other nine audit modules … were NOT run", which stopped being true the moment the free scan
// started grading M4/M5/M7/M9 and inventorying M6/M10. A stale scope string is the same defect as a
// missing one — worse, because it reads as deliberate — so it is computed from what actually ran.
//
// The upgrade path this text points at was BROKEN when written: until #1061, `run-audit --sarif-out`
// without --findings-out captured no findings at all, so this string sent a reader from an honest
// partial export to a near-empty one. It captures on --sarif-out alone now, so the sentence is true.
// Falsifier: `run-audit targets/calibration --sarif-out a.sarif` and check the printed result count
// against the same run with --findings-out (src/cli/run-audit.test.ts asserts they match).
function quickScanSarifScope(scorecard: HealthScorecard): string {
  return (
    "This is a free quick-scan, not a Harvey audit, and THIS EXPORT carries the M1 mechanical " +
    "results only (dependency, secret and dangerous-config hygiene plus static indicators). " +
    `The free scan also graded ${scorecard.gradedModules.filter((m) => m !== "M1").join(", ")} and produced indicators for ` +
    `${scorecard.dimensions.filter((d) => d.status === "indicator-only").map((d) => d.module).join(", ")}` +
    // The risk band is a rating, not an indicator: naming it separately keeps the export's own scope
    // note from under-reporting what the scan actually established about the target's data surface.
    `${scorecard.dimensions
      .filter((d) => d.status === "risk-band")
      .map((d) => `, plus a ${d.band} data-exposure rating for ${d.module}`)
      .join("")}; ` +
    "those results are in the report (`--json` / terminal output), NOT in this SARIF file. " +
    `${scorecard.unassessedModules.join(", ")} were not run at all. ` +
    "Absence of a result here is not evidence of absence of a problem. " +
    "Run `run-audit <target> --sarif-out <file>` for an export carrying a real per-module ledger."
  );
}

const FLAGS = [
  "--bundle",
  "--dir",
  "--target",
  "--findings-out",
  "--json",
  "--out",
  "--sarif-out",
  "--sbom-out",
  "--tenant-key",
  "--tenant-mode",
] as const;

function tenantMode(raw: string | undefined): "per-tenant" | "per-user" | undefined {
  if (raw === undefined || raw === "per-tenant" || raw === "per-user") return raw;
  console.error(`--tenant-mode must be "per-tenant" or "per-user", got "${raw}"`);
  process.exit(2);
}

// #1305: the free scan's duplication pass gets a hard ceiling of 60s.
//
// CORRECTED 2026-07-30 (sweep/jscpd-ceiling): this comment used to say "#505 measured jscpd hanging
// indefinitely on a multi-app repo." That misattributes #505's own hang: its body names the culprit
// as "the knip workspace-resolution stage," and #544 (src/cli/quality-scan.ts:9-29) measured jscpd
// completing the SAME monorepo in 1.9s — jscpd has no workspace-resolution stage to get stuck in.
// jscpd has never been measured to hang on a real target, including the pinned corpus's largest
// (carbon: 39.4s per #897 at 4,110 files, 20.3s re-measured below at 4,157). So this cap is a
// defensive ceiling against a hypothetical pathological tree, not a response to an observed jscpd
// hang — a free scan that never returns is still worse than one that discloses "could not measure
// duplication," so the timeout stays regardless, and a trip becomes a disclosed not-assessed row.
//
// MEASURED 2026-07-30: cloned every src/scan/external-corpus.ts EXTERNAL_CORPUS pin fresh (git fetch
// --depth 1 at the pinned commit, via src/scan/corpus-clone.ts's cloneAtPin) and timed
// src/scan/duplication.ts's runJscpd() directly against each, with a 300s ceiling so a slow run would
// still show its real time instead of being truncated at 60s. Result: 0/14 pinned targets hit the
// 60s cap. Wall-clock: carbon (4,157 files) 20.3s, inbox-zero (2,345 files) 8.3s, documenso (2,074
// files) 6.3s, tanstack-com (808 files) 3.9s, ghostfolio (810 files) 2.7s, rallly (787 files) 2.5s,
// proposit (285 files) 1.2s, every remaining target (saas-lite, boxyhq, mvp-boilerplate, launch-mvp,
// multi-tenant-starter, subscription-payments, supabase-security-labs) under 0.7s. The cap is
// UNTRIGGERED on this corpus (population zero, per CLAUDE.md's "a limit with a population of zero is
// not a limit, it is a guess") — 60s stays unchanged: nothing measured here supports raising OR
// lowering it, and the largest real target still clears it with ~3x headroom. Re-run by repeating the
// recipe above; do not move this number without first watching a real target approach it.
const JSCPD_TIMEOUT_MS = 60_000;

// A recursive read, matching src/cli/dry-run.ts's: a Prisma migration lives one directory deeper
// than Supabase's flat layout, so a non-recursive readdir silently reads as "no schema".
// Through readRecursiveSafe, not a raw readdirSync (#1451): a client repo with a committed dangling
// symlink under supabase/migrations would otherwise throw HERE — at the very end of a free scan,
// discarding a completed pass, which is the crash shape that guard exists to stop.
function readSchemaSql(dir: string): string {
  const migrations = join(dir, "supabase", "migrations");
  if (!existsSync(migrations)) return "";
  return readRecursiveSafe(migrations)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => readFileSync(join(migrations, f), "utf8"))
    .join("\n\n");
}

// M10's source-side inventory: which tables hold classified PII/PHI/PCI. SQL migrations first, then
// a schema.prisma — a Prisma app has no supabase/migrations at all, and reading only the first would
// report "no schema" on a target whose schema is right there (the #757 detection-gating rule).
type PiiDataMap = Record<string, { severity: string; categories: string[]; columns: unknown[] }>;

// The classifier's own per-table verdict, reshaped for the scorecard's risk band. Reused rather than
// recomputed: tools/pii-classify.mjs already derives Low/Medium/High/Critical per table from the
// source classification, and a second sensitivity scale here could disagree with M10's own findings.
function tableBands(dataMap: PiiDataMap): PiiTableBand[] {
  return Object.entries(dataMap).map(([table, e]) => ({ table, severity: e.severity, categories: e.categories, columns: e.columns.length }));
}

function classifySchema(dir: string): { tables: number; columns: number; tableBands: PiiTableBand[] } | { gap: string } {
  const sql = readSchemaSql(dir);
  if (sql.trim()) {
    const { dataMap, columns } = classifyMigrationSql(sql);
    return { tables: Object.keys(dataMap).length, columns: columns.length, tableBands: tableBands(dataMap as PiiDataMap) };
  }
  const prismaSchema = join(dir, "prisma", "schema.prisma");
  if (existsSync(prismaSchema)) {
    const { dataMap, columns } = classifyPrismaSchema(readFileSync(prismaSchema, "utf8"));
    return { tables: Object.keys(dataMap).length, columns: columns.length, tableBands: tableBands(dataMap as PiiDataMap) };
  }
  return { gap: "No SQL migrations under supabase/migrations and no prisma/schema.prisma were found, so there was no schema to classify." };
}

// M8: does the target declare a way to run tests at all? A `test` script that runs nothing is a
// louder finding than no script, so the scorecard is told which of the two it is. A malformed
// package.json answers "no" rather than throwing — a free scan must not die on a client's bad JSON.
function declaresTestScript(dir: string): boolean {
  try {
    const scripts = (JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { scripts?: Record<string, string> }).scripts ?? {};
    return Object.keys(scripts).some((name) => /^(test|tests|vitest|jest|spec)(:|$)/.test(name));
  } catch {
    return false;
  }
}

function measureDuplication(dir: string, sourceFileCount: number): Pick<ScorecardInput, "duplication" | "duplicationGap" | "duplicationFindings"> {
  try {
    const report = runJscpd(dir, { timeoutMs: JSCPD_TIMEOUT_MS, sourceFileCount: () => sourceFileCount });
    const { percentage, duplicatedLines, totalLines } = duplicationSummary(report);
    return { duplication: { percentage, duplicatedLines, totalLines }, duplicationFindings: jscpdToFindings(report) };
  } catch (err) {
    // Same three shapes src/cli/quality-scan.ts distinguishes: our own SIGKILL, a missing binary,
    // and anything else. Every one becomes a stated reason on the row — never a silent clean 0%.
    const e = err as { code?: string; stderr?: Buffer | string; message?: string };
    const reason =
      e.code === "ETIMEDOUT"
        ? `the duplication pass did not complete within ${JSCPD_TIMEOUT_MS / 1000}s and was stopped`
        : e.code === "ENOENT"
          ? "the jscpd duplication engine is not installed on the machine that ran this scan"
          : ((e.stderr ? e.stderr.toString() : undefined) || e.message || String(err)).trim().slice(0, 300);
    return { duplicationGap: reason };
  }
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Perf", "Info", "Watch"] as const;

function wrap(text: string, indent: string): string[] {
  const words = text.split(" ");
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if (line && `${line} ${w}`.length > 78) {
      lines.push(indent + line);
      line = w;
    } else line = line ? `${line} ${w}` : w;
  }
  if (line) lines.push(indent + line);
  return lines;
}

// #1305: the per-dimension scorecard, rendered as the headline. This section is the operator's
// 2026-07-12 correction made visible — every module M1–M10 gets a row, so the fact that most of them
// were not run is stated in the artifact a prospect actually reads, not only inside --sarif-out.
// buildHealthScorecard guarantees the ten rows; this function must never filter them.
// The DISCLOSED ROLLUP (operator ruling 2026-07-28 on #1305): at most five examples per dimension,
// duplicates collapsed to one row plus a count. Every number a reader could mistake for a total is
// printed as a ratio — "showing 3 of 12 distinct shapes (41 findings in total)" — because a capped
// list that reads as complete is the silent-omission shape CLAUDE.md ranks worse than a wrong status.
// The grade is computed upstream on the full set; nothing here feeds back into it.
function renderEvidence(d: HealthDimension): string[] {
  const e = d.evidence;
  if (!e) return [];
  const unit = d.status === "risk-band" ? "table" : "shape";
  if (e.totalFindings === 0) return [`         Examples: none — this dimension produced no findings.`];
  const header = e.capped
    ? `Examples — showing ${e.examples.length} of ${e.totalShapes} distinct ${unit}s (${e.totalFindings} in total):`
    : `Examples — all ${e.totalShapes} ${unit}${e.totalShapes === 1 ? "" : "s"} found (${e.totalFindings} in total):`;
  const lines = [`         ${header}`];
  for (const ex of e.examples) {
    // Always print the count, including "1 time": a collapsed row with no count reads as singular,
    // leaving "one occurrence" and "one shown of twenty-three" indistinguishable to a reader.
    lines.push(`           • ${ex.shape} — ${ex.location}  (appears ${ex.occurrences} time${ex.occurrences === 1 ? "" : "s"})`);
  }
  if (e.capped) {
    lines.push(
      ...wrap(
        `… and ${e.hiddenShapes} further ${unit}${e.hiddenShapes === 1 ? "" : "s"} (${e.hiddenFindings} more) are NOT listed here — every one of them, with all its locations, is in the paid report.`,
        "           ",
      ),
    );
  }
  return lines;
}

function renderScorecard(s: HealthScorecard): string[] {
  const lines: string[] = [];
  lines.push(`  Harvey Quick Scan — Codebase Health ${s.grade}  (${s.score}/100)`);
  lines.push("  Ran 100% locally. No source code left your machine.");
  lines.push("");
  lines.push(...wrap(s.scopeSentence, "  "));
  lines.push("");
  lines.push("  ── The scorecard, dimension by dimension ─────────────");
  for (const d of s.dimensions) {
    const head =
      d.status === "graded"
        ? `${d.grade} (${d.score}/100)`
        : d.status === "risk-band"
          ? `${d.band} data-exposure risk (not a letter grade)`
          : d.status === "indicator-only"
            ? "indicators only — not graded"
            : "NOT ASSESSED by this scan";
    lines.push(`    ${d.module.padEnd(4)} ${d.label} — ${head}`);
    if (d.measure) lines.push(`         ${d.measure}`);
    if (d.bandDerivation) lines.push(...wrap(`How this band was set: ${d.bandDerivation}`, "         "));
    if (d.reason) lines.push(...wrap(`Why: ${d.reason}`, "         "));
    if (d.needs) lines.push(`         Answered by: ${d.needs}`);
    if (d.notAssessedRows) lines.push(`         (${d.notAssessedRows} coverage row(s) inside this dimension state what it could not read — see --json)`);
    lines.push(...wrap(d.scope, "         "));
    if (d.bandCaveat) lines.push(...wrap(d.bandCaveat, "         "));
    if (d.evidence) lines.push(...renderEvidence(d));
    lines.push("");
  }
  lines.push(...wrap(`How the grade was composed: ${s.composition}`, "  "));
  lines.push("");
  return lines;
}

function render(r: QuickScanReport, scorecard?: HealthScorecard): string {
  const lines: string[] = [];
  lines.push("");
  if (scorecard) lines.push(...renderScorecard(scorecard));
  // Two-part headline (#227): the grade never appears without its scope, and the risk
  // disclosure sits directly under it — a hygiene grade read as a security verdict is the
  // failure mode this tier exists to avoid. Under #1305 this is M1's own dimension rather than the
  // whole report's headline, so it is labelled as such.
  lines.push(`  ── M1 security & multi-tenant isolation — Hygiene Grade ${r.grade}  (${r.score}/100) ─────────────`);
  lines.push(`  Scope: ${r.gradeScope}`);
  lines.push("");
  lines.push(...wrap(r.riskDisclosure, "  "));
  lines.push("");

  // #1044: the size and its band, printed with the definition that produced them. The pricing page
  // calls this an "instant, transparent quote" — a band with no stated method is neither.
  if (r.size) {
    lines.push("  ── Codebase size (your paid-tier quote band) ────────────");
    lines.push(`  ${r.size.loc.toLocaleString("en-US")} lines of application code across ${r.size.files.toLocaleString("en-US")} file(s)`);
    lines.push(`  Band: ${r.size.bandLabel}`);
    if (r.size.excludedFiles > 0) lines.push(`  ${r.size.excludedFiles.toLocaleString("en-US")} generated/vendored/build file(s) excluded — you are not quoted on them.`);
    lines.push(...wrap(`How this is measured: ${r.size.definition}`, "  "));
    lines.push("");
  }

  if (r.total === 0) {
    lines.push("  No hygiene issues found — nothing mechanically verifiable to fix.");
  } else {
    const counts = SEVERITY_ORDER.filter((s) => r.countsBySeverity[s] > 0)
      .map((s) => `${r.countsBySeverity[s]} ${s}`)
      .join(", ");
    lines.push(`  ${r.total} verified hygiene issue${r.total === 1 ? "" : "s"}: ${counts}`);
    lines.push(`  By category: ${r.categories.map((c) => `${c.count}× ${c.category}`).join(", ")}`);
    lines.push("");

    lines.push("  What's wrong and where:");
    for (const f of r.findings) {
      lines.push(`    [${f.severity}] ${f.title}`);
      lines.push(`      ${f.location}`);
      lines.push(`      Why it matters: ${f.risk}`);
      lines.push("");
    }
  }

  if (r.indicators.length > 0) {
    lines.push("  ── Potential issues — confirmed or cleared in the deep scan ─────────────");
    lines.push("  Spotted in your source. NOT counted in the grade: these need a live database");
    lines.push("  to confirm, and we don't guess.");
    lines.push("");
    for (const f of r.indicators) {
      lines.push(`    [${f.severity}?] ${f.title}`);
      lines.push(`      ${f.location}`);
      lines.push(`      Why it matters if real: ${f.risk}`);
      lines.push("");
    }
  }

  // #996: workflow-file findings are real and fully reported — but they grade the CI pipeline,
  // not the app, and exploitability depends on repo/trigger settings the scan can't see, so they
  // get their own clearly-labeled non-grading section (never folded into "not assessed" — these
  // files WERE assessed). Severity labels are kept: the section's framing carries the "not
  // graded", and a shell-injection finding softened to [Info] would undersell a real CI risk.
  const ciFindings = r.informational.filter((f) => f.category === CI_PIPELINE_CATEGORY);
  const informational = r.informational.filter((f) => f.category !== CI_PIPELINE_CATEGORY);

  if (ciFindings.length > 0) {
    lines.push("  ── CI/CD pipeline hygiene — reported, not graded ─────────────");
    lines.push("  Findings in your GitHub Actions workflows. Real, and worth fixing — but they");
    lines.push("  grade your build pipeline, not your application code, and whether they are");
    lines.push("  exploitable depends on repository settings (who can open PRs, which events");
    lines.push("  trigger the workflow) that a source scan cannot see. Not counted in the grade.");
    lines.push("");
    for (const f of ciFindings) {
      lines.push(`    [${f.severity}] ${f.title}`);
      lines.push(`      ${f.location}`);
      lines.push(...wrap(`Why it matters: ${f.risk}`, "      "));
      lines.push("");
    }
  }

  if (informational.length > 0) {
    lines.push("  ── Informational — not graded ─────────────");
    lines.push("  Facts we verified but won't grade you on: dependency versions matching a");
    lines.push("  published CVE range (a version match is not proof of exploitability),");
    lines.push("  credential-shaped strings in docs/example deployment files (near-certainly");
    lines.push("  placeholders), and confirm-intent configuration — wildcard CORS with no");
    lines.push("  credentials signal (correct for public endpoints) or a wildcard postMessage");
    lines.push("  (a leak only if the data is sensitive). Reason stated per finding. The deep");
    lines.push("  scan triages each one.");
    // #874: the list is ordered by whether your code actually imports the package. Say so, or the
    // ordering looks arbitrary — and say what it is NOT, or "not imported" reads as "safe".
    lines.push("  CVE rows are ordered by reachability: packages your code imports first.");
    lines.push("");
    // Deliberately labeled [Info] rather than each row's underlying severity: an ungraded row
    // printed "[Critical]" would talk over the section's own "not graded" framing (#213).
    for (const f of informational) {
      lines.push(`    [Info] ${f.title}`);
      lines.push(`      ${f.location}`);
      if (f.reachability) lines.push(...wrap(`Reachability (${f.reachability.status}): ${f.reachability.justification}`, "      "));
      lines.push("");
    }
  }

  if (r.handrolled.length > 0) {
    lines.push(`  ── ${HANDROLLED_SECTION_TITLE} ─────────────`);
    lines.push(...wrap(HANDROLLED_SECTION_BLURB, "  "));
    lines.push("");
    for (const c of r.handrolled) {
      const fileCount = c.files.length;
      lines.push(`    ${c.shape} — ${c.total} place${c.total === 1 ? "" : "s"} in ${fileCount} file${fileCount === 1 ? "" : "s"}`);
      for (const f of c.files.slice(0, HANDROLLED_FILES_SHOWN)) {
        lines.push(`      ${f.locations[0]}${f.locations.length > 1 ? ` (${f.locations.length} places in this file)` : ""}`);
      }
      // The volume cap never truncates silently: what isn't printed is counted out loud,
      // and every location is in the --json report.
      const hidden = c.files.slice(HANDROLLED_FILES_SHOWN);
      if (hidden.length > 0) {
        const hiddenPlaces = hidden.reduce((sum, f) => sum + f.locations.length, 0);
        lines.push(`      … and ${hidden.length} more file${hidden.length === 1 ? "" : "s"} (${hiddenPlaces} more place${hiddenPlaces === 1 ? "" : "s"}) — every location is in the --json output`);
      }
      lines.push("");
    }
  }

  if (r.total === 0 && r.indicators.length === 0 && r.informational.length === 0 && r.handrolled.length === 0) {
    lines.push("  Re-scan after your next release and we'll diff it against this run.");
    lines.push("");
  }

  if (r.sample) {
    lines.push("  ── Sample fix (one finding, fully revealed) ─────────────");
    lines.push(`  [${r.sample.severity}] ${r.sample.title}`);
    lines.push(`    ${r.sample.location}`);
    lines.push(`    Fix: ${r.sample.fix}`);
    lines.push("  This is what the unlock delivers — for every finding above.");
    lines.push("");
  }

  lines.push("  Unlock to get:");
  for (const g of r.gated) lines.push(`    • ${g}`);
  if (r.reviewTierExcluded > 0) {
    lines.push("");
    lines.push(
      `  (${r.reviewTierExcluded} lower-confidence signal${r.reviewTierExcluded === 1 ? "" : "s"} were found and ` +
        "deliberately left out of your grade — triaged in the deep scan, never counted here.)",
    );
  }
  lines.push("");
  return lines.join("\n");
}

async function main(): Promise<void> {
  assertKnownFlags(FLAGS);
  const dir = targetDir();
  const bundle = arg("--bundle");
  const tenantKey = arg("--tenant-key");
  const mode = tenantMode(arg("--tenant-mode"));
  const tenancyOverride = tenantKey || mode ? { tenantKey, mode } : undefined;
  // #933: runMechanicalScan walks a scratch copy of the target (src/scan/scan-scope.ts, #101),
  // so every raw location carries that run's mkdtemp `harvey-scan-scope-*` prefix. Relativized
  // HERE, before any consumer below (the free report, --findings-out, the handrolled grouping,
  // SARIF) — quick-scan is the client-facing free report; a per-run/per-machine scratch path in
  // front of every finding location is unreadable and looks like a leaked internal path.
  const rawFindings = (await runMechanicalScan({ dir, bundleDir: bundle, tenancyOverride, handrolledIndicators: true })).map((f) => ({
    ...f,
    location: relativizeScanScope(f.location),
  }));
  const absDir = resolve(dir);
  const size = measureCodebaseSize(absDir);
  const report = buildQuickScanReport(rawFindings, { size });

  // #1305 — the per-dimension health scorecard. Deliberately built from its OWN detector runs rather
  // than from `rawFindings`: that array is the M1 mechanical feed the orchestrator's probe reads
  // (--findings-out), and widening it here would change what M1 reports it examined. The scorecard
  // reads the same tree, separately, and composes a health grade across all ten dimensions.
  // The FULL set, tests included: buildHealthScorecard splits it (product code for M5/M7/M9, test
  // files for M8's census), so the split lives in one place rather than at each call site.
  const sources = loadSources(absDir);
  const pii = classifySchema(absDir);
  const scorecard = buildHealthScorecard({
    m1: { grade: report.grade, score: report.score, gradedCount: report.total, indicatorCount: report.indicators.length, findings: selectGradedFindings(rawFindings) },
    sources,
    kloc: size.loc / 1000,
    framework: detectTargetFramework(absDir),
    nonNextWorkspaces: nonNextWorkspaces(absDir),
    orm: detectOrm(absDir),
    ...measureDuplication(absDir, size.files),
    handrolledClasses: report.handrolled.length,
    handrolledTotal: report.handrolled.reduce((sum, c) => sum + c.total, 0),
    testRunnerDeclared: declaresTestScript(absDir),
    ...("gap" in pii ? { piiGap: pii.gap } : { pii }),
  });

  const findingsOut = arg("--findings-out");
  if (findingsOut) writeFileSync(findingsOut, `${JSON.stringify(rawFindings, null, 2)}\n`);

  const sarifOut = arg("--sarif-out");
  if (sarifOut) {
    const sarif = toSarif(rawFindings, { coverageAbsent: quickScanSarifScope(scorecard) }, { baseUri: dir });
    writeFileSync(sarifOut, `${JSON.stringify(sarif, null, 2)}\n`);
    console.error(`SARIF 2.1.0 (${rawFindings.length} result(s)) → ${sarifOut}`);
  }

  const sbomOut = arg("--sbom-out");
  if (sbomOut) {
    const { bom, warning } = buildSbom(dir, { targetName: basename(resolve(dir)) });
    writeFileSync(sbomOut, `${JSON.stringify(bom, null, 2)}\n`);
    console.error(`CycloneDX SBOM (${(bom as { components: unknown[] }).components.length} component(s)) → ${sbomOut}`);
    if (warning) console.error(`⚠ SBOM is not a complete inventory: ${warning}`);
  }

  const out = arg("--out");
  const body = process.argv.includes("--json") ? JSON.stringify({ ...report, scorecard }, null, 2) : render(report, scorecard);
  if (out) writeFileSync(out, body);
  else console.log(body);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
