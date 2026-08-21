// Schema-drift contracts for the CAPTURED external-tool fixtures beyond osv-scanner (the #1130
// remainder: lighthouse, vitals, trufflehog, jscpd, knip, Stryker). Companion to
// src/scan/osv-fixture-contract.ts — same idea, one contract per tool.
//
// Each captured fixture (see src/scan/__fixtures__/FIXTURE-INVENTORY.md) is a frozen capture of a
// real tool run. A frozen capture protects the parser from the #1063 regression (a fixture encoding
// a field the real tool never emits leaves a detector silently dead against every real target) — but
// only until the tool's OWN output schema drifts underneath it. The periodic drift check
// (src/cli/fixture-drift.ts) re-runs the pinned tool against a reproducible seed and asserts the
// FRESH output still satisfies the contract below: the fields the parser reads exist with the right
// SHAPE. Most tools stop there because their content legitimately churns run-to-run. Semgrep is the
// exception: its purpose-built corpus is deterministic after the narrow canonicalization below, so
// it also gets an exact semantic comparison that protects findings, diagnostics, and scanned scope.
//
// These are PURE (no I/O), so the negative controls run under `pnpm verify`
// (src/scan/fixture-drift-contracts.test.ts). The binary-running CLI is not, like osv-fixture-drift.

import type { JscpdReport, KnipReport } from "../quality-scan.js";
import type { TruffleHogResult } from "./secrets.js";
import type { VitalsReport } from "../hotspot-scan.js";
import type { StrykerReport } from "../mutation-scan.js";
import type { LighthouseResult } from "../lighthouse.js";

// The tool versions each committed fixture was captured from (its PROVENANCE.md) and each parser's
// field-reads were verified against. A drift check run against a different version cannot vouch for
// the fixture — it must fail loud and prompt a re-verification, not silently pass.
export const JSCPD_PINNED_VERSION = "4.2.5";
export const KNIP_PINNED_VERSION = "5.88.1";
export const TRUFFLEHOG_PINNED_VERSION = "3.97.0";
export const VITALS_PINNED_VERSION = "0.2.0";
export const STRYKER_PINNED_VERSION = "9.6.1";
export const LIGHTHOUSE_PINNED_VERSION = "13.4.0";
export const SEMGREP_PINNED_VERSION = "1.173.0";
export const GITLEAKS_PINNED_VERSION = "8.30.1";

function isNum(v: unknown): boolean {
  return typeof v === "number" && Number.isFinite(v);
}
function isStr(v: unknown): boolean {
  return typeof v === "string";
}

// jscpd 4.2.5 `--reporters json` → jscpdToFindings / duplicationSummary (src/quality-scan.ts).
// Reads: statistics.total.{lines,duplicatedLines,percentage}; each duplicate's
// format/lines/tokens/fragment and firstFile/secondFile {name,start,end}.
export function checkJscpdContract(report: JscpdReport): string[] {
  const v: string[] = [];
  const total = report.statistics?.total;
  if (!total || !isNum(total.lines) || !isNum(total.duplicatedLines) || !isNum(total.percentage)) {
    v.push("statistics.total.{lines,duplicatedLines,percentage} are not all finite numbers — duplicationSummary reads them directly");
  }
  if (!Array.isArray(report.duplicates) || report.duplicates.length === 0) {
    v.push("duplicates is empty or not an array — the seed corpus should produce clones; a clean run cannot verify the per-duplicate shape (corpus or jscpd drift?)");
    return v;
  }
  for (const [i, d] of report.duplicates.entries()) {
    const where = `duplicates[${i}]`;
    if (!isStr(d.format)) v.push(`${where}.format is not a string`);
    if (!isNum(d.lines)) v.push(`${where}.lines is ${JSON.stringify(d.lines)}, not a number — jscpdToFindings sorts/severity-bands on it`);
    if (!isNum(d.tokens)) v.push(`${where}.tokens is ${JSON.stringify(d.tokens)}, not a number`);
    if (!isStr(d.fragment)) v.push(`${where}.fragment is not a string — the evidence preview reads it`);
    for (const side of ["firstFile", "secondFile"] as const) {
      const f = d[side];
      if (!f || !isStr(f.name) || !isNum(f.start) || !isNum(f.end)) {
        v.push(`${where}.${side} is missing name(string)/start(number)/end(number) — the location string reads all three`);
      }
    }
  }
  return v;
}

// knip 5.88.1 `--reporter json` → knipToFindings (src/quality-scan.ts). Reads: files (dead files) and
// issues[].{file, exports[], types[], ...}, each export/type record {name, line}. The seed project
// plants one dead file and one file with an unused value export + an unused type export.
export function checkKnipContract(report: KnipReport): string[] {
  const v: string[] = [];
  if (!Array.isArray(report.files) || report.files.length === 0 || !report.files.every(isStr)) {
    v.push("files is not a non-empty array of strings — the seed plants one dead file (src/dead.ts); knipToFindings lists these as unused files");
  }
  if (!Array.isArray(report.issues) || report.issues.length === 0) {
    v.push("issues is empty or not an array — the seed plants one file with an unused export + type; a clean run cannot verify the issue-record shape");
    return v;
  }
  let sawExportRecord = false;
  for (const [i, issue] of report.issues.entries()) {
    if (!isStr(issue.file)) v.push(`issues[${i}].file is not a string`);
    for (const key of ["exports", "types"] as const) {
      const recs = issue[key];
      if (recs === undefined) continue;
      if (!Array.isArray(recs)) {
        v.push(`issues[${i}].${key} is not an array`);
        continue;
      }
      for (const r of recs) {
        sawExportRecord = true;
        if (!isStr(r.name) || !isNum(r.line)) {
          v.push(`issues[${i}].${key}[] is ${JSON.stringify(r)}, not a {name:string, line:number} record — knipToFindings reads .name (and #1101 keys ids off .line)`);
        }
      }
    }
  }
  if (!sawExportRecord) {
    v.push("no issue carried any exports/types export record — the unused-export shape knipToFindings depends on is gone from the output");
  }
  return v;
}

// TruffleHog 3.96.0 `git --no-verification --results=unverified --json` → parseTruffleHogFindings
// (src/scan/secrets.ts) AND scoreGitHistoryResults (src/scan/git-history-secret-gate.ts). Covers
// FIXTURE-INVENTORY rows 8 (unverified) and 10 (git-history) — same tool, same command, same-shaped
// throwaway repo. Reads: DetectorName, DecoderName, Verified, Redacted (the #1099 ""-fallback key),
// ExtraData.rotation_guide (#1078), SourceMetadata.Data.Git {file,line,commit,email,timestamp}.
export function checkTruffleHogContract(results: TruffleHogResult[]): string[] {
  const v: string[] = [];
  if (!Array.isArray(results) || results.length === 0) {
    v.push("no TruffleHog records — the planted PAT recovered from git history should produce at least one (detector/fixture drift?)");
    return v;
  }
  const positive = results.filter((r) => r.SourceMetadata?.Data?.Git?.file === "lib/leaked-token.js");
  if (positive.length === 0) {
    v.push("no record located at SourceMetadata.Data.Git.file === 'lib/leaked-token.js' — scoreGitHistoryResults joins on this exact path (git metadata shape drift?)");
    return v;
  }
  for (const [i, r] of positive.entries()) {
    const where = `positive[${i}]`;
    if (typeof r.Verified !== "boolean") v.push(`${where}.Verified is not a boolean — parseTruffleHogFindings filters on it`);
    if (!isStr(r.Redacted)) v.push(`${where}.Redacted is not a string (real trufflehog emits "" for most detectors — the #1099 fallback keys on it)`);
    if (!isStr(r.DetectorName)) v.push(`${where}.DetectorName is not a string — the finding title reads it`);
    if (!isStr(r.DecoderName)) v.push(`${where}.DecoderName is not a string — the provenance line reads it`);
    if (!r.ExtraData || !isStr(r.ExtraData.rotation_guide)) {
      v.push(`${where}.ExtraData.rotation_guide is not a string — the #1078 rotation procedure the fix reads is gone`);
    }
    const git = r.SourceMetadata?.Data?.Git;
    if (!git || !isStr(git.file) || !isNum(git.line) || !isStr(git.commit) || !isStr(git.email) || !isStr(git.timestamp)) {
      v.push(`${where}.SourceMetadata.Data.Git is missing file/line/commit/email/timestamp — the location + #1078 provenance read all of these`);
    }
  }
  return v;
}

// vitals 0.2.0 `report --json` → src/hotspot-scan.ts. Reads: hotspots/coupling/knowledge_risk arrays
// (the parseReport #94 invariant); each hotspot's file_path/risk_score/churn_label/health/changes and
// churn_data.author_count; knowledge_risk truck_factor/author_count; provenance.has_data + ai_files.
// The seed plants a ranked hotspot table, one truck-factor-1 row, one coupling edge, AI provenance.
export function checkVitalsContract(report: VitalsReport & { _gitScopeSanity?: GitScopeSanity }): string[] {
  const v: string[] = [];
  for (const key of ["hotspots", "coupling", "knowledge_risk"] as const) {
    if (!Array.isArray(report[key])) v.push(`${key} is not an array — the #94-verified vitals shape parseReport requires`);
  }
  if (v.length > 0) return v;

  if (report.hotspots.length === 0) {
    v.push(churnOnlySwallowDiagnosis(report) ?? "hotspots is empty — the seed corpus should produce a ranked table (vitals scoring or seed drift?)");
  }
  for (const [i, h] of report.hotspots.entries()) {
    const where = `hotspots[${i}]`;
    if (!isStr(h.file_path)) v.push(`${where}.file_path is not a string`);
    if (!isNum(h.risk_score)) v.push(`${where}.risk_score is ${JSON.stringify(h.risk_score)}, not a number — it is the sort key`);
    if (!isStr(h.churn_label)) v.push(`${where}.churn_label is ${JSON.stringify(h.churn_label)}, not a string`);
    if (!isNum(h.health)) v.push(`${where}.health is not a number`);
    if (!isNum(h.changes)) v.push(`${where}.changes is not a number`);
    if (!h.churn_data || !isNum(h.churn_data.author_count)) v.push(`${where}.churn_data.author_count is not a number`);
  }
  for (const [i, k] of report.knowledge_risk.entries()) {
    const where = `knowledge_risk[${i}]`;
    if (!isStr(k.file_path)) v.push(`${where}.file_path is not a string`);
    if (!isNum(k.truck_factor)) v.push(`${where}.truck_factor is ${JSON.stringify(k.truck_factor)}, not a number`);
    if (!isNum(k.author_count)) v.push(`${where}.author_count is not a number`);
  }
  for (const [i, c] of report.coupling.entries()) {
    const where = `coupling[${i}]`;
    if (!isStr(c.file_a) || !isStr(c.file_b)) v.push(`${where}.file_a/file_b is not a string`);
    if (!isNum(c.coupling_strength)) v.push(`${where}.coupling_strength is not a number`);
  }
  const prov = report.provenance;
  if (!prov || typeof prov.has_data !== "boolean") {
    v.push("provenance.has_data is not a boolean — the AI-provenance sub-signal reads it");
  } else if (prov.has_data) {
    if (!Array.isArray(prov.ai_files)) {
      v.push("provenance.ai_files is not an array despite has_data — the AI-authored file signal reads it");
    } else {
      for (const [i, a] of prov.ai_files.entries()) {
        if (!isStr(a.file_path) || !isNum(a.total_events)) v.push(`provenance.ai_files[${i}] is missing file_path(string)/total_events(number)`);
      }
    }
  }
  return v;
}

// #1206: read directly from the pinned plugin's own source
// (~/.claude/plugins/cache/vitals/vitals/0.2.0/scripts/git_analysis.py, `_run_git`) — vitals 0.2.0
// discards stderr and collapses ANY non-zero exit or timeout on its internal `git log --since=...ago`
// calls to an empty result, indistinguishable in the JSON output from "genuinely no history in this
// window." seed.py independently re-runs `git log --since=90.days.ago` (stderr NOT suppressed) right
// after building the seeded repo and records the result as `_gitScopeSanity`. When vitals' three
// git-derived sections come back simultaneously empty despite that independent check finding commits
// with no git error, the failure is CONSISTENT WITH that known swallow class rather than with a
// schema/behavior drift in vitals' output — so the drift CLI reports NOT RUN with this reason instead
// of a generic contract-violation FAIL. This does NOT name why git itself failed in a given CI
// occurrence (no stderr was preserved from the one observed case, 2026-07-27, run 30273745542) — only
// that vitals' own error-swallowing is a confirmed mechanism by which such a failure would look
// exactly like this. It used to assert it IS that class, which the evidence does not support: seed.py's
// own header documents a scope/toplevel mismatch producing the identical signature with git working,
// and absorbing THAT as a disclosed flake would let a real regression in seed.py's realpath() pass as
// NOT RUN. `scopeMatchesToplevel` is what separates the two, so the claim is now bounded by a check
// rather than by wording (raised by PR #1398's acceptance verifier, #1206).
export interface GitScopeSanity {
  commits: number;
  returncode: number;
  stderr: string | null;
  // Whether the path seed.py handed vitals is ALREADY the resolved `git rev-parse --show-toplevel`.
  // The competing cause of the identical all-empty signature: vitals resolves symlinks to find the
  // repo root but scopes against the handed path, so a mismatch empties the file scope with git
  // working perfectly. Absent on a capture taken before this field existed.
  scopeMatchesToplevel?: boolean;
}

/**
 * The CHURN-ONLY sub-shape (#1618): `hotspots` empty while `coupling` and/or `knowledge_risk` are
 * POPULATED. Distinct from the all-three-empty shape `classifyVitalsGitScopeFailure` handles, and it
 * has to stay distinct, because the two have different causes and only one of them is excusable.
 *
 * This is a DIAGNOSIS, not an excuse, and it is deliberately NOT wired into `notRunIf`. Excusing it
 * would hide the two live causes below behind a NOT RUN, which is the "unstated limitation reads as
 * a clean bill of health" failure the drift checks exist to prevent. It replaces the generic
 * `hotspots is empty` violation text with a named one and the run still FAILS.
 *
 * Why the populated siblings are the signature. Of the three sections, only `hotspots` needs the
 * per-file CHURN table, which vitals 0.2.0 builds from `git log --numstat` — the one git invocation
 * that reads blob CONTENT. `coupling` (`log --name-only`) and `knowledge_risk` (`log --format=%aN`)
 * do not. So sibling sections that populated are positive evidence that git ran, the repo was in
 * scope, and only the content-reading call failed — which `git_analysis._run_git` swallows into an
 * empty churn table and therefore an empty `code_files`, and therefore no hotspots.
 *
 * Observed live in run 30379062498 (2026-07-28) and run 30635897491; root-caused by #1705 to git
 * >= 2.54 detaching `maintenance run --auto` per commit and repacking the seed corpus out from
 * under the reads. `seed.py` disables auto maintenance and `assert_no_background_gc` fails loud if
 * a future git finds another route to it — this row is what makes a recurrence say so in the drift
 * output instead of pointing at "vitals scoring or seed drift".
 */
export function churnOnlySwallowDiagnosis(report: VitalsReport & { _gitScopeSanity?: GitScopeSanity }): string | undefined {
  if (report.hotspots.length > 0) return undefined;
  const populated = [
    ...(report.coupling.length > 0 ? [`coupling (${report.coupling.length})`] : []),
    ...(report.knowledge_risk.length > 0 ? [`knowledge_risk (${report.knowledge_risk.length})`] : []),
  ];
  if (populated.length === 0) return undefined;
  const sanity = report._gitScopeSanity;
  const corroboration =
    sanity && sanity.returncode === 0 && sanity.commits > 0
      ? ` An independent \`git log --since=90.days.ago\` in the same seeded repo found ${sanity.commits} commit(s) with no git error.`
      : "";
  return (
    `hotspots is empty while ${populated.join(" and ")} populated — the CHURN-ONLY swallow (#1618/#1705), not the ` +
    `all-empty git-scope shape.${corroboration} Of the three sections only hotspots needs the per-file churn ` +
    `table, which vitals 0.2.0 builds from \`git log --numstat\`, the one call that reads blob CONTENT; ` +
    `git_analysis._run_git discards its stderr and returns [] on a non-zero exit. CONSISTENT WITH a missing ` +
    `loose object in the seeded corpus (#1705: git >= 2.54 detaches \`maintenance run --auto\` per commit and ` +
    `repacks it mid-build) — check seed.py's assert_no_background_gc and \`git --version\` on this runner FIRST. ` +
    `The competing cause is a genuine upstream change to vitals' complexity scoring, which would empty hotspots ` +
    `with the churn table intact; that one is real drift and needs a re-capture.`
  );
}

export function classifyVitalsGitScopeFailure(report: VitalsReport & { _gitScopeSanity?: GitScopeSanity }): string | undefined {
  const allGitSectionsEmpty = report.hotspots.length === 0 && report.coupling.length === 0 && report.knowledge_risk.length === 0;
  if (!allGitSectionsEmpty) return undefined;
  const sanity = report._gitScopeSanity;
  if (!sanity || sanity.returncode !== 0 || sanity.commits === 0) return undefined;
  // A NOT-RUN verdict excuses the run, so it must not be reachable by the one other cause known to
  // produce this exact shape: a scope/toplevel mismatch is a regression in seed.py's own realpath()
  // and has to stay a loud FAIL. `!== true` and not `=== false` on purpose — a capture that leaves
  // the question unanswered does not get the benefit of the doubt either.
  if (sanity.scopeMatchesToplevel !== true) return undefined;
  return (
    `vitals returned empty hotspots/coupling/knowledge_risk while an independent ` +
    `\`git log --since=90.days.ago\` in the same seeded repo found ${sanity.commits} commit(s) with no ` +
    `git error (returncode 0), and the seeded path is the resolved git toplevel so the scope-mismatch ` +
    `cause is ruled out — CONSISTENT WITH the git-scope silent-failure class in vitals 0.2.0's ` +
    `git_analysis._run_git, which discards stderr and returns [] on any non-zero exit or timeout. ` +
    `The mechanism matches; which git invocation failed is not recoverable from this output (#1206).`
  );
}

/**
 * What a fresh tool run means, given the tool's contract and its optional known-non-drift
 * classifier. Lives here rather than inline in `runDrift` because #1416.4 measured that the wiring
 * had NO test at all: deleting the `notRunIf` call from the CLI broke nothing in the suite, so the
 * one thing `classifyVitalsGitScopeFailure` exists to do — pre-empt the contract check — was
 * unguarded while the classifier itself had eight.
 *
 * The ORDER is the whole point. A run in the #1206 shape violates the contract too (three empty
 * arrays), so a contract check that ran first would report a schema drift for a git failure, and
 * `notRunIf` would never be consulted.
 */
type FreshRunVerdict =
  | { kind: "not-run"; reason: string }
  | { kind: "drift"; violations: string[] }
  | { kind: "ok" };

export function classifyFreshRun<T>(o: { contract: (p: T) => string[]; notRunIf?: (p: T) => string | undefined }, parsed: T): FreshRunVerdict {
  const reason = o.notRunIf?.(parsed);
  if (reason !== undefined) return { kind: "not-run", reason };
  const violations = o.contract(parsed);
  return violations.length > 0 ? { kind: "drift", violations } : { kind: "ok" };
}

interface DriftReport {
  message: string;
  stream: "log" | "error";
  exitCode: 0 | 1;
}

/**
 * The verdict → stdout/exit mapping, pulled out of `runDrift` (#1727) so it is a pure function with
 * a test — only the actual `console.*`/`process.exit` calls stay unguarded in the CLI. Deleting the
 * `"not-run"` branch here now breaks `fixture-drift-contracts.test.ts` directly, closing the gap
 * #1416.4 left: the mapping used to live inline in `src/cli/fixture-drift.ts`, which imports and
 * runs its argv dispatch at module load, so nothing there was reachable from a test without a live
 * subprocess.
 */
export function renderDriftVerdict(tool: string, installedVersion: string, verdict: FreshRunVerdict, summary: string): DriftReport {
  if (verdict.kind === "not-run") {
    return { message: `○ ${tool}-fixture-drift: NOT RUN — ${verdict.reason}`, stream: "log", exitCode: 0 };
  }
  if (verdict.kind === "drift") {
    return {
      message:
        `✗ ${tool}-fixture-drift: a fresh ${tool} ${installedVersion} run no longer matches the schema the committed fixture assumes:\n  - ${verdict.violations.join("\n  - ")}\n` +
        `Re-capture the committed fixture (see its PROVENANCE.md) and re-verify the parser against the new shape.`,
      stream: "error",
      exitCode: 1,
    };
  }
  return { message: `✓ ${tool}-fixture-drift: ${summary}, schema contract holds (committed fixture and fresh run both compliant).`, stream: "log", exitCode: 0 };
}

/**
 * Vitals' drift options minus the version/rerun half, which needs the plugin binary. It lives HERE
 * rather than beside `vitalsDrift()` for one reason: `src/cli/fixture-drift.ts` runs its argv
 * dispatch at import and calls `process.exit(2)`, so a test importing it from there kills the
 * runner. Splitting it out is what makes the notRunIf registration reachable at all (#1416.4).
 */
export const VITALS_DRIFT_CONTRACT = {
  fixturePaths: ["src/__fixtures__/vitals-report.json"],
  parse: (raw: string): VitalsReport & { _gitScopeSanity?: GitScopeSanity } => {
    const parsed = JSON.parse(raw) as VitalsReport & { _note?: string; _gitScopeSanity?: GitScopeSanity };
    delete parsed._note;
    return parsed;
  },
  contract: checkVitalsContract,
  notRunIf: classifyVitalsGitScopeFailure,
};

// Stryker 9.6.1 `run` JSON report → summarizeMutationReport / vacuousTestFiles (src/mutation-scan.ts).
// Reads: files{}.mutants[].{id,mutatorName,status,location,coveredBy,killedBy,static}, testFiles (the
// #1100 join), thresholds, schemaVersion. The seed is targets/calibration/test-quality/.
export function checkStrykerContract(report: StrykerReport): string[] {
  const v: string[] = [];
  if (!isStr(report.schemaVersion)) v.push("schemaVersion is not a string");
  if (!report.thresholds || !isNum(report.thresholds.high) || !isNum(report.thresholds.low)) {
    v.push("thresholds.{high,low} are not both numbers");
  }
  if (!report.files || typeof report.files !== "object" || Object.keys(report.files).length === 0) {
    v.push("files is empty or not an object — a real run scores at least one file");
    return v;
  }
  let sawMutant = false;
  for (const [file, fr] of Object.entries(report.files)) {
    if (!Array.isArray(fr.mutants)) {
      v.push(`files["${file}"].mutants is not an array`);
      continue;
    }
    for (const [i, m] of fr.mutants.entries()) {
      sawMutant = true;
      const where = `files["${file}"].mutants[${i}]`;
      if (!isStr(m.id)) v.push(`${where}.id is not a string`);
      if (!isStr(m.mutatorName)) v.push(`${where}.mutatorName is not a string`);
      if (!isStr(m.status)) v.push(`${where}.status is ${JSON.stringify(m.status)}, not a string — every summary counts key off it`);
      const loc = m.location;
      if (!loc || !loc.start || !isNum(loc.start.line) || !loc.end || !isNum(loc.end.line)) {
        v.push(`${where}.location.{start,end}.line are not both numbers`);
      }
      if (m.coveredBy !== undefined && (!Array.isArray(m.coveredBy) || !m.coveredBy.every(isStr))) {
        v.push(`${where}.coveredBy is not a string[] — the #1100 vacuous-test join reads it`);
      }
      if (m.killedBy !== undefined && (!Array.isArray(m.killedBy) || !m.killedBy.every(isStr))) {
        v.push(`${where}.killedBy is not a string[] — the #1100 vacuous-test join reads it`);
      }
      if (m.static !== undefined && typeof m.static !== "boolean") {
        v.push(`${where}.static is not a boolean — the #1100 static-majority downgrade reads it`);
      }
    }
  }
  if (!sawMutant) v.push("no file carried any mutants — nothing to score (Stryker or target drift?)");
  if (report.testFiles !== undefined && typeof report.testFiles !== "object") {
    v.push("testFiles is present but not an object — the #1100 coveredBy/killedBy → test-name join reads it");
  }
  return v;
}

// Lighthouse 13.4.0 (onlyCategories: ["performance"]) → src/lighthouse.ts. Reads:
// categories.performance.score; the tracked metric audits' score/scoreDisplayMode/numericValue;
// runWarnings. The seed serves a real page so all three tracked metrics are measured.
const TRACKED_LIGHTHOUSE_AUDITS = ["first-contentful-paint", "largest-contentful-paint", "total-blocking-time", "cumulative-layout-shift"] as const;

export function checkLighthouseContract(result: LighthouseResult): string[] {
  const v: string[] = [];
  const score = result.categories?.performance?.score;
  if (!isNum(score)) {
    v.push(`categories.performance.score is ${JSON.stringify(score)}, not a number — parseLighthouseFindings bands severity on it`);
  }
  if (!result.audits || typeof result.audits !== "object") {
    v.push("audits is not an object — every metric finding reads audits[id]");
    return v;
  }
  for (const id of TRACKED_LIGHTHOUSE_AUDITS) {
    const a = result.audits[id];
    if (!a) {
      v.push(`audits["${id}"] is missing — a real performance run measures all tracked metrics`);
      continue;
    }
    if (!isStr(a.scoreDisplayMode)) {
      v.push(`audits["${id}"].scoreDisplayMode is not a string — the #1074 error-vs-measured distinction reads it`);
    }
    if (a.scoreDisplayMode === "numeric" && !isNum(a.numericValue)) {
      v.push(`audits["${id}"].numericValue is ${JSON.stringify(a.numericValue)}, not a number despite scoreDisplayMode "numeric" — the metric value the finding reports`);
    }
  }
  if (!Array.isArray(result.runWarnings)) {
    v.push("runWarnings is not an array — modelled non-optional on the real LHR (#1074)");
  }
  return v;
}

// semgrep 1.173.0 (the six registry packs + src/scan/rules/semgrep/) → parseSemgrepFindings
// (src/scan/semgrep.ts). Reads check_id, path, start.line, end.line, extra.message, extra.severity,
// extra.metadata.{confidence, harveySeverity, harveyTaxonomy, cwe, owasp, references, likelihood,
// impact, source} — the last two (cwe/owasp) admit EITHER a string[] or a bare string (#976).
// build-corpus.mjs plants one file per required rule below; PROVENANCE.md's "Fiction this capture
// corrected" is why these five specifically, not a spot check of one.
export interface SemgrepContractResult {
  check_id: string;
  path: string;
  start?: { line?: number };
  end?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: { confidence?: string; cwe?: string[] | string; owasp?: string[] | string; [key: string]: unknown };
    [key: string]: unknown;
  };
  [key: string]: unknown;
}
export interface SemgrepContractOutput {
  version?: string;
  results?: SemgrepContractResult[];
  errors?: unknown[];
  paths?: { scanned?: string[]; skipped?: Array<{ path?: string; reason?: string; [key: string]: unknown }>; [key: string]: unknown };
  skipped_rules?: unknown[];
  engine_requested?: string;
  [key: string]: unknown;
}

/**
 * The committed Semgrep fixture is compared byte-for-byte after this one canonicalization step.
 * It removes only raw run telemetry which the parser/deliverable never reads, normalizes the
 * throwaway root in path-bearing strings, and sorts the three Semgrep populations whose order is
 * not semantic. Finding fields and per-path diagnostics are retained in full: a changed rule
 * message, span, error, or skip therefore remains a loud fixture drift rather than disappearing
 * behind the older shape-only contract.
 *
 * The corpus builder imports this function through tsx, and fixture-drift invokes it again before
 * comparison. Keeping one tracked implementation replaces the untracked `process.py` from the
 * previous capture and makes re-capture deterministic and reproducible.
 */
const SEMGREP_RAW_TELEMETRY_KEYS = new Set(["time", "profiling_results"]);

function stableSemgrepValue(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableSemgrepValue).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableSemgrepValue(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "undefined";
}

const SEMGREP_PATH_VALUE_KEYS = new Set(["file", "path", "scanned"]);

function normalizeSemgrepValue(value: unknown, pathRoot: string | undefined, pathValue = false): unknown {
  if (typeof value === "string") {
    let normalized = pathValue ? value.replaceAll("\\", "/") : value;
    if (!pathRoot) return normalized;

    // Exact throwaway roots can also occur inside diagnostic messages. Remove only that known
    // path prefix; do not rewrite arbitrary backslashes in messages/rule text as if they were path
    // separators, because those strings are semantic fixture evidence.
    const roots = new Set([
      pathRoot.replace(/[\\/]$/, ""),
      pathRoot.replaceAll("\\", "/").replace(/\/$/, ""),
      pathRoot.replaceAll("/", "\\").replace(/\\$/, ""),
    ]);
    for (const root of roots) {
      normalized = normalized
        .replaceAll(`${root}/`, "")
        .replaceAll(`${root}\\`, "")
        .replaceAll(root, ".");
    }
    return normalized;
  }
  if (Array.isArray(value)) return value.map((item) => normalizeSemgrepValue(item, pathRoot, pathValue));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, normalizeSemgrepValue(item, pathRoot, SEMGREP_PATH_VALUE_KEYS.has(key))]),
    );
  }
  return value;
}

function sortSemgrepPopulation<T>(items: readonly T[], identity: (item: T) => unknown[]): T[] {
  return [...items].sort((left, right) => {
    const a = stableSemgrepValue(identity(left));
    const b = stableSemgrepValue(identity(right));
    return a.localeCompare(b);
  });
}

export function canonicalizeSemgrepFixtureOutput(output: SemgrepContractOutput, pathRoot?: string): SemgrepContractOutput {
  if (!output || typeof output !== "object" || Array.isArray(output)) throw new Error("Semgrep fixture output is not an object");
  const normalized = normalizeSemgrepValue(output, pathRoot) as SemgrepContractOutput;
  const retained = { ...normalized };
  for (const key of SEMGREP_RAW_TELEMETRY_KEYS) delete retained[key];

  if (Array.isArray(normalized.results)) {
    retained.results = sortSemgrepPopulation(normalized.results, (result) => [
      result.path,
      result.check_id,
      result.start,
      result.end,
      result,
    ]);
  }
  if (Array.isArray(normalized.errors)) {
    retained.errors = sortSemgrepPopulation(normalized.errors, (error) => {
      const record = error && typeof error === "object" ? (error as Record<string, unknown>) : {};
      return [record.path, record.type, record.message, error];
    });
  }
  if (normalized.paths && typeof normalized.paths === "object") {
    retained.paths = {
      ...normalized.paths,
      ...(Array.isArray(normalized.paths.scanned)
        ? { scanned: [...normalized.paths.scanned].sort((a, b) => a.localeCompare(b)) }
        : {}),
      ...(Array.isArray(normalized.paths.skipped)
        ? {
            skipped: sortSemgrepPopulation(normalized.paths.skipped, (skip) => [
              skip.path,
              skip.reason,
              skip,
            ]),
          }
        : {}),
    };
  }
  return normalizeSemgrepValue(retained, undefined) as SemgrepContractOutput;
}

export function compareSemgrepFixtureOutput(
  committed: SemgrepContractOutput,
  fresh: SemgrepContractOutput,
  freshPathRoot?: string,
): string[] {
  const expected = canonicalizeSemgrepFixtureOutput(committed);
  const actual = canonicalizeSemgrepFixtureOutput(fresh, freshPathRoot);
  const violations: string[] = [];
  if (expected.version !== actual.version) {
    violations.push(`version changed from ${JSON.stringify(expected.version)} to ${JSON.stringify(actual.version)}`);
  }
  if (stableSemgrepValue(expected.results) !== stableSemgrepValue(actual.results)) {
    violations.push("canonical results changed — finding fields, population, or semantic identity drifted");
  }
  if (stableSemgrepValue(expected.errors) !== stableSemgrepValue(actual.errors)) {
    violations.push("canonical errors changed — a client-facing Semgrep diagnostic moved or changed");
  }
  if (stableSemgrepValue(expected.paths) !== stableSemgrepValue(actual.paths)) {
    violations.push("canonical paths changed — scanned or skipped scope/reason drifted");
  }
  const withoutCore = (value: SemgrepContractOutput): Record<string, unknown> => {
    const rest = { ...value };
    delete rest.version;
    delete rest.results;
    delete rest.errors;
    delete rest.paths;
    return rest;
  };
  if (stableSemgrepValue(withoutCore(expected)) !== stableSemgrepValue(withoutCore(actual))) {
    violations.push("canonical envelope changed outside version/results/errors/paths");
  }
  return violations;
}

const REQUIRED_SEMGREP_RULES = [
  "harvey-service-role-in-client", // ERROR+HIGH, non-audit — the free-count (high-tier) case
  "audit.code-string-concat.code-string-concat", // a `.audit.` rule — review tier even at ERROR+HIGH
  "harvey-open-redirect", // WARNING/MEDIUM — the plain review-tier case
  "cors-misconfiguration.cors-misconfiguration", // registry rule, cwe/owasp as string[] arrays
  "bypass-tls-verification", // registry rule, cwe/owasp as BARE STRINGS — the #976 normalization path
];

export function checkSemgrepFixtureContract(output: SemgrepContractOutput): string[] {
  const v: string[] = [];
  if (output.version !== SEMGREP_PINNED_VERSION) {
    v.push(
      `version is ${JSON.stringify(output.version)}, not the pinned fixture authority ${SEMGREP_PINNED_VERSION}`,
    );
  }
  if (!Array.isArray(output.skipped_rules)) {
    v.push("skipped_rules is not an array — omitted-rule scope evidence must remain explicit");
  }
  if (!isStr(output.engine_requested)) {
    v.push("engine_requested is not a string — execution-engine provenance must remain explicit");
  }
  if (!Array.isArray(output.errors)) v.push("errors is not an array — semgrepErrorFinding consumes its per-path diagnostics");
  if (!Array.isArray(output.paths?.scanned) || !Array.isArray(output.paths?.skipped)) {
    v.push("paths.scanned/paths.skipped are not both arrays — scope and skip disclosures consume them");
  }
  if (!Array.isArray(output.results) || output.results.length === 0) {
    v.push("results is empty or not an array — the seed corpus should produce matches (corpus or semgrep drift?)");
    return v;
  }
  const byId = (suffix: string): SemgrepContractResult | undefined => output.results!.find((x) => x.check_id?.endsWith(suffix));
  for (const suffix of REQUIRED_SEMGREP_RULES) {
    const r = byId(suffix);
    if (!r) {
      v.push(`no result with check_id ending "${suffix}" — the seed's planted file for it should still fire this rule (rule renamed/removed, or the registry pack no longer matches?)`);
      continue;
    }
    if (!isStr(r.path)) v.push(`${suffix}: path is not a string`);
    if (!isNum(r.start?.line) || !isNum(r.end?.line)) v.push(`${suffix}: start.line/end.line are not both numbers — the finding location reads both`);
    if (!isStr(r.extra?.message)) v.push(`${suffix}: extra.message is not a string`);
    if (!isStr(r.extra?.severity)) v.push(`${suffix}: extra.severity is not a string — severityFromSemgrep reads it`);
  }
  const arrayRule = byId("cors-misconfiguration.cors-misconfiguration");
  if (arrayRule && (!Array.isArray(arrayRule.extra?.metadata?.cwe) || !Array.isArray(arrayRule.extra?.metadata?.owasp))) {
    v.push("cors-misconfiguration: metadata.cwe/owasp are not both arrays — the #455 list-form threading path is unexercised");
  }
  const bareStringRule = byId("bypass-tls-verification");
  if (bareStringRule && (typeof bareStringRule.extra?.metadata?.cwe !== "string" || typeof bareStringRule.extra?.metadata?.owasp !== "string")) {
    v.push("bypass-tls-verification: metadata.cwe/owasp are not both bare strings — the #976 strList normalization path is unexercised");
  }
  return v;
}

// gitleaks 8.30.1 (--config src/scan/rules/gitleaks-supabase.toml --max-decode-depth 2) →
// parseGitleaksFindings (src/scan/secrets.ts). Reads RuleID, File, StartLine, Match. The
// service-role/demo-key co-location (#210) is load-bearing: a real demo service-role JWT's decoded
// body carries BOTH claims, so both rules must fire on the SAME File:StartLine, which is exactly
// what the suppression logic keys on — build-corpus.mjs's `DEMO_SERVICE_JWT` plants it.
export interface GitleaksContractResult {
  RuleID: string;
  File: string;
  StartLine?: number;
  Match?: string;
}

const REQUIRED_GITLEAKS_RULES = [
  { rule: "supabase-service-role-jwt", file: "lib/admin.ts" }, // real (non-demo) service-role JWT
  { rule: "private-key", file: "certs/key.pem" }, // plain private key, no test-IdP context
];

export function checkGitleaksFixtureContract(results: GitleaksContractResult[]): string[] {
  const v: string[] = [];
  if (!Array.isArray(results) || results.length === 0) {
    v.push("no gitleaks records — the seed corpus should produce matches (corpus or gitleaks drift?)");
    return v;
  }
  for (const { rule, file } of REQUIRED_GITLEAKS_RULES) {
    const r = results.find((x) => x.RuleID === rule && x.File?.endsWith(file));
    if (!r) {
      v.push(`no record with RuleID "${rule}" at a File ending "${file}" — the seed's planted file for it should still fire this rule`);
      continue;
    }
    if (!isNum(r.StartLine)) v.push(`${rule}@${file}: StartLine is not a number — the location reads it`);
    if (!isStr(r.Match)) v.push(`${rule}@${file}: Match is not a string — the evidence quotes it`);
  }
  // .endsWith, not ===: the committed fixture's File is relativized (PROVENANCE.md), but a fresh
  // rerun's is the raw mkdtemp absolute path — both end in the same corpus-relative suffix.
  const demoServiceRole = results.find((x) => x.RuleID === "supabase-service-role-jwt" && x.File?.endsWith("supabase/seed.sql"));
  const demoMarker = results.find((x) => x.RuleID === "supabase-demo-key-marker" && x.File?.endsWith("supabase/seed.sql"));
  if (!demoServiceRole || !demoMarker || demoServiceRole.StartLine !== demoMarker.StartLine) {
    v.push("supabase-service-role-jwt and supabase-demo-key-marker no longer co-locate on supabase/seed.sql's line — the #210 demo-key clearance depends on this exact co-location");
  }
  return v;
}
