// Findings schema for the audit deliverable. report-template/render.mjs consumes
// this shape; validate an engagement's findings.json here before rendering.

import { completenessStatement, deriveCompleteness, headlineClaimsCompletion } from "./audit-completeness.js";

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Perf", "Info", "Watch"] as const;
export const CONFIDENCES = ["Confirmed", "Likely", "Review", "N/A"] as const;
// Trust tier for mechanically-generated findings: "high" = ~100%-precision source (verified
// secret, decoded service-role JWT, exact CVE match, advisor lint, HIGH-confidence ERROR
// Semgrep rule) — safe to count without triage. "review" = heuristic/grep-sourced, needs triage.
export const PRECISION_TIERS = ["high", "review"] as const;

// Per-module coverage ledger carried into the deliverable (#349/#312). Derived by run-audit from
// what each probe reported — never hand-typed. Its presence is what lets the report tell a module
// that ran and found nothing (status "ran", no reason) from one that never ran (a non-"ran" status
// WITH a reason). Without it, both collapse into the same silence, which reads as a clean bill of
// health for a module that was never assessed — the exact inversion the coverage guard exists to
// prevent.
export const COVERAGE_STATUSES = ["ran", "partial", "requires-live-run"] as const;

// #682: a partial row's sub-status. "sub-step-blocked" flags a module marked `partial` because one
// sub-step was BLOCKED (crashed / could not run) while a sibling sub-step COMPLETED and surfaced
// findings — so the reader can tell "we ran part of this and here's what we found" apart from a
// requires-live-run that produced nothing. Set by the probe (M8's test-intent tier survives a
// blocked Stryker run — the #623 silent drop this closes); absent ⇒ an ordinary row.
export const SUB_STATUSES = ["sub-step-blocked"] as const;

// Engagement baseline diff (#457). A finding's standing relative to the prior audit of the same
// client: "persistent" (matched by identity in both), "new" (only this run), "resolved" (only the
// prior run). Set by src/audit-diff.ts, never hand-typed. Absent ⇒ no baseline was supplied.
export const BASELINE_STATUSES = ["new", "persistent", "resolved"] as const;

// #874: how reachable a known-vulnerable dependency is IN THIS CODEBASE, at import granularity.
// Orders the CVE list and justifies each row; deliberately NOT an exploitability claim (see
// src/scan/dep-reachability.ts). "not-assessed" exists so an unmeasured row is never presented as
// the least urgent one.
export const REACHABILITY_STATUSES = ["imported", "declared-not-imported", "transitive-only", "not-assessed"] as const;

// #1910: finding-producing code can emit a client defect, a coverage disclosure, or a typed
// not-assessed row. Effectiveness metrics must keep those populations separate: counting a scope
// row as a detected defect inflates recall, while dropping it erases an assessment gap. This is the
// shared classifier used by the versioned producer inventory; individual mixed producers may
// override a family explicitly when an id/taxonomy pattern carries both shapes (M10-VS is one).
export const FINDING_FAMILY_KINDS = ["finding", "coverage-disclosure", "not-assessed"] as const;

export type Severity = (typeof SEVERITIES)[number];
export type Confidence = (typeof CONFIDENCES)[number];
export type PrecisionTier = (typeof PRECISION_TIERS)[number];
export type CoverageStatus = (typeof COVERAGE_STATUSES)[number];
export type SubStatus = (typeof SUB_STATUSES)[number];
export type BaselineStatus = (typeof BASELINE_STATUSES)[number];
export type ReachabilityStatus = (typeof REACHABILITY_STATUSES)[number];
export type FindingFamilyKind = (typeof FINDING_FAMILY_KINDS)[number];

export function findingFamilyKind(input: { id: string; taxonomy: string }): FindingFamilyKind {
  const text = `${input.id} ${input.taxonomy}`.toLowerCase();
  const taxonomy = input.taxonomy.toLowerCase();
  if (/not[- ]assessed|not applicable|not-applicable|\bn\/a\b/.test(text)) return "not-assessed";
  // "tenant scope" and "authorization scope" are ordinary defect language. Only explicit
  // coverage/scope-row wording denotes a disclosure; a bare occurrence of "scope" must not turn
  // BOLA, cache-key, or background-job findings into coverage rows.
  if (
    /\bcoverage\b|\bscope disclosure\b|(?:^|\s)[—:-]\s*scope(?:\b|$)|\bunavailable\b|did not run|not collected|not-collected/.test(taxonomy)
  ) return "coverage-disclosure";
  return "finding";
}

export interface DependencyReachability {
  status: ReachabilityStatus;
  rank: number; // sort key, lower = look at this first
  files?: string[]; // the importing files, when status is "imported"
  // Shown to the client verbatim. States the limit of the signal as well as the signal — a
  // "not imported" row that did not say "this de-prioritizes, it does not clear" would be read
  // as a clearance we have not earned.
  justification: string;
}

// #1049: why a finding's severity is what it is, when M10's data map moved it. Set at assembly time
// (src/data-class-escalation.ts) on any finding whose location/title names a table M10 classified as
// holding PII/PHI/PCI. `escalatedFrom` is present ONLY when the severity was actually raised — a
// match that did not escalate still carries the classes, so the reader sees the data context either
// way. The join only ever raises: a benign table is never evidence a finding is less serious.
export interface DataClassMatch {
  table: string;
  categories: string[]; // PII / SENSITIVE_PII / PHI / PCI / SECRET
  infotypes: string[]; // EMAIL, DOB, US_SSN, …
  escalatedFrom?: Severity;
  // Shown verbatim in the deliverable — a higher severity the client cannot trace back to a table
  // and a data class is an assertion, not a finding.
  reason: string;
}

export interface CoverageRow {
  module: string; // "M1".."M10"
  name: string;
  status: CoverageStatus;
  // Why the module fell short. Required for anything but a clean "ran": an unexplained gap is
  // indistinguishable from a silent skip.
  reason?: string;
  // What actually executed (command, tier).
  detail?: string;
  // #506: which app/Supabase project this row covers, on a monorepo per-app/per-DB tier. Absent ⇒
  // a whole-target row.
  instance?: string;
  // #682: on a `partial` row, "sub-step-blocked" means a sub-step was blocked while a sibling ran
  // and surfaced findings — the renderer badges it distinctly from a partial that produced nothing.
  subStatus?: SubStatus;
}

// #825: an applicable remediation for a finding — the paid-tier upgrade of the prose `fix` into a
// mergeable unified diff. INERT / for-review: Harvey never auto-applies it (mirrors the security
// /patch skill's human-review posture). Only a mechanically-verified fix is ever attached to a
// ticket (src/trackers/fix-diff.ts verifySuggestedFix) — an unverified proposal is dropped, not
// filed. Populated by a paid-tier pass (the M6 verdict / M7 triage / M8 mutant-kill pass that
// already has an LLM/human in the loop), never by the deterministic scan.
export interface SuggestedFix {
  diff: string; // git-apply-compatible unified diff
  verified: boolean; // applies cleanly (+ effect confirmed where a ground-truth check exists)
  verification?: string; // how it was verified, surfaced in the ticket body
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  taxonomy: string;
  location: string;
  status: string;
  evidence: string;
  impact: string;
  fix: string;
  // #825: paid-tier applicable diff, surfaced under the prose `fix` in a filed ticket. Absent ⇒
  // prose-only (free tier, or no diff was produced/verified).
  suggestedFix?: SuggestedFix;
  // BFTB inputs, each 1–5: business value of fixing, ease of fix, safety of fix.
  value: number;
  ease: number;
  safety: number;
  okWhen?: string;
  notOkWhen?: string;
  note?: string;
  // Set by scan modules (src/scan/**) on findings produced by a deterministic tool pass,
  // as opposed to a human/LLM-authored engagement finding.
  mechanical?: boolean;
  precisionTier?: PrecisionTier;
  // M10 (#459): columns flagged by the OPAQUE_JSON_BLOB review class (#377) — a container column
  // whose name suggests nested PII, not asserted. reviewFlagOnly is true when a table has ONLY
  // review-flagged columns and no asserted classification, so the renderer never shows it as an
  // asserted PII holding; reviewFlagColumns lists the flagged column names (present even on a
  // finding that also has asserted columns, so the renderer can surface those too).
  reviewFlagOnly?: boolean;
  reviewFlagColumns?: string[];
  // A finding's own claim that it is more than a version/pattern match — that exploitability in
  // THIS codebase has actually been confirmed, not just a fact about which CVE range a dependency
  // falls in. Grading logic (src/quick-scan.ts NON_GRADING_CATEGORIES) treats a whole category as
  // "fact-only" by default but defers to this per-finding override, so a future exploitability-
  // verified finding in a non-grading category isn't silently un-graded (#260). Unset/false is the
  // safe default — set it explicitly, per finding, only when exploitability was actually confirmed.
  exploitabilityVerified?: boolean;
  // #874: the npm package a "Dependency CVE" finding is about, set by the emitters so the
  // reachability pass can rank the row without re-parsing the location string. Reachability is an
  // ORDERING signal — it never sets exploitabilityVerified and never moves the grade.
  dependency?: string;
  reachability?: DependencyReachability;
  // Engagement baseline diff (#457), set by src/audit-diff.ts when a --baseline is supplied.
  // baselineStatus classifies this finding against the prior audit; lowConfidenceMatch names the
  // prior finding's id this MIGHT be the same as (same taxonomy + location basename, exact key
  // differed) — surfaced for a human to confirm, NEVER used to auto-merge (fail loud).
  baselineStatus?: BaselineStatus;
  lowConfidenceMatch?: string;
  // CWE / OWASP Top-10 identifiers (#455), for ticket-routing/compliance mapping. Populated from
  // the detector's own declaration, never invented at report time: for a semgrep row from the rule
  // `metadata.cwe`/`metadata.owasp` (the external p/owasp-top-ten pack AND every harvey-* rule, all
  // of which now carry a CWE — #975); for a TS/AST detector row from the taxonomy→CWE registry in
  // src/cwe-map.ts, keyed on the detector's stable `taxonomy` string. Absent only where the taxonomy
  // is a deliberate no-clean-CWE (a quality/perf/coverage signal, recorded with a reason in cwe-map).
  cwe?: string[];
  owasp?: string[];
  // #1077: the rule's own remediation links (semgrep `metadata.references`, plus its `source` rule
  // page where present) — populated from the detector's own declaration, same provenance rule as
  // cwe/owasp above. Absent ⇒ the source declared none (e.g. every one of Harvey's own harvey-*
  // custom rules today) and the fix stays the generic placeholder.
  references?: string[];
  // #515: cross-module hotspot enrichment. Set at assembly time when a finding's location sits on
  // an M3-ranked hotspot (high churn × complexity × coupling). onHotspot up-ranks it in the report's
  // cross-module ordering; hotspotRank is the file's 1-based position in the top-K (1 = hottest).
  // One mechanism, every module benefits — most valuably M6 (a hand-rolled reinvention on a hot file
  // matters far more than the same pattern on a stable leaf). Absent ⇒ not on a ranked hotspot, or no
  // M3 ranking was available this run.
  onHotspot?: boolean;
  hotspotRank?: number;
  // #1049: M10's data-aware severity join. Set at assembly time by escalateFindingsByDataClass;
  // absent ⇒ the finding names no classified table, or no data map was available (in which case the
  // run carries an M10-ESCALATION-00 not-assessed row instead of silence).
  dataClass?: DataClassMatch;
}

// Engagement baseline diff summary (#457), attached to the deliverable when a --baseline is
// supplied. resolved carries the prior findings absent from this run (each tagged baselineStatus
// "resolved"); counts drives the report's progress banner.
export interface BaselineSummary {
  priorLabel?: string;
  resolved: Finding[];
  counts: { resolved: number; persistent: number; new: number };
}

export interface ReportMeta {
  client: string;
  subtitle: string;
  date: string;
  commit: string;
  auditor: string;
  confidential: boolean;
  overallHealth: number;
  tenantIsolation: string;
  authModel: string;
  headline: string;
  scope: string;
  methodology: string;
  outOfScope: string;
}

// M8's §3b Test-quality payload (#1045). One row per module, the shape
// docs/audit-report-skeleton.md §3b specifies — src/mutation-scan.ts's toReportRows plus the
// honesty context (#319 covered scope, #504 scope verdict, #819 line-coverage pull status) the
// score must never be printed without.
export interface TestQualityRow {
  module: string;
  // Absent when the target's own coverage tool could not be run (#819) — the renderer says so on
  // the row rather than printing 0%.
  lineCoverage?: number;
  mutationScore: number;
  survivingCount: number;
  hotspotSurvivingCount: number;
  // The §3b "Action" column. Written by the operator per row; derived from the numbers when absent.
  action?: string;
}

// A surviving mutant the suite never disproved — the "tests that can't fail" evidence.
export interface TestQualitySurvivor {
  file: string;
  line: number;
  mutator: string;
  hotspot: boolean;
}

export interface TestQuality {
  mutationScore: number;
  // #1076: Stryker's OTHER published headline metric — detected/(detected+survived), i.e. the score
  // over only the mutants a test actually reached. Absent ⇒ the run's artifact predates the metric,
  // never invented as 0/equal-to-mutationScore. Recomputed from the committed ATC capture: 58.1%
  // here vs. 27.8% for mutationScore — "your tests are bad" and "your tests are decent but reach
  // half the code" are different findings, and Stryker's own report shows both.
  mutationScoreBasedOnCoveredCode?: number;
  coveredScope: string[];
  // True only when the scope check VERIFIED the run covered the configured mutate globs in full
  // (#504). An unverifiable scope reads false — "unproven" is not "whole repo".
  wholeRepo: boolean;
  scopeNote: string;
  rows: TestQualityRow[];
  lineCoverage: { status: "ran" | "partial"; reason?: string };
  survivors: TestQualitySurvivor[];
  survivorTotal: number;
}

// #1048: the engagement's limitations/liability wording. Absent ⇒ the renderer emits its DRAFT
// text under a pending-legal-review banner; it is never omitted, because a report with no stated
// limitations reads as an unbounded warranty.
export interface LegalTerms {
  text: string;
  // Who approved it (counsel/operator). Recorded on the page so an unattributed block is visible.
  approvedBy?: string;
}

export interface FindingsDocument {
  meta: ReportMeta;
  findings: Finding[];
  // The derived per-module coverage ledger (#349). Optional for back-compat with hand-authored
  // engagement docs; when present the renderer states coverage from it rather than from the
  // free-text meta.outOfScope.
  coverage?: CoverageRow[];
  // The engagement baseline diff (#457). Present only when a re-audit consumed a prior baseline;
  // the renderer leads with a resolved/persistent/new progress view when it is.
  baseline?: BaselineSummary;
  // M8's per-module test-quality table (#1045). Present when the run's mutation tier produced a
  // measurement; absent when it did not — the M8 coverage row carries the reason in that case.
  testQuality?: TestQuality;
  // Operator/counsel-approved limitations & liability wording (#1048).
  legalTerms?: LegalTerms;
}

// Bang-for-the-buck score, 0–100. Mirrors the formula in report-template/render.mjs.
export function bftb(f: Pick<Finding, "value" | "ease" | "safety">): number {
  return Math.round(((f.value * f.ease * f.safety) / 125) * 100);
}

export interface ValidationResult {
  ok: boolean;
  errors: string[];
}

const META_STRING_FIELDS: (keyof ReportMeta)[] = [
  "client", "subtitle", "date", "commit", "auditor", "tenantIsolation",
  "authModel", "headline", "scope", "methodology", "outOfScope",
];

const FINDING_STRING_FIELDS: (keyof Finding)[] = [
  "id", "title", "category", "taxonomy", "location", "status", "evidence", "impact", "fix",
];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function scoreInRange(v: unknown): boolean {
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 5;
}

function validateCoverage(coverage: unknown, errors: string[]): void {
  if (!Array.isArray(coverage)) {
    errors.push("coverage: expected an array of module rows");
    return;
  }
  coverage.forEach((row: unknown, i: number) => {
    const at = `coverage[${i}]`;
    if (!isRecord(row)) {
      errors.push(`${at}: not an object`);
      return;
    }
    if (typeof row.module !== "string" || row.module === "") errors.push(`${at}.module: expected non-empty string`);
    if (typeof row.name !== "string") errors.push(`${at}.name: expected string`);
    if (!COVERAGE_STATUSES.includes(row.status as CoverageStatus)) {
      errors.push(`${at}.status: "${String(row.status)}" not one of ${COVERAGE_STATUSES.join("/")}`);
    }
    if (row.detail !== undefined && typeof row.detail !== "string") errors.push(`${at}.detail: expected string`);
    if (row.instance !== undefined && typeof row.instance !== "string") errors.push(`${at}.instance: expected string`);
    if (row.subStatus !== undefined && !SUB_STATUSES.includes(row.subStatus as SubStatus)) {
      errors.push(`${at}.subStatus: "${String(row.subStatus)}" not one of ${SUB_STATUSES.join("/")}`);
    }
    // A non-"ran" row without a reason is a silent skip wearing a status — the exact failure the
    // ledger exists to surface. Mirrors buildAuditCoverage's gap rule (src/audit-coverage.ts).
    if (row.status !== "ran" && (typeof row.reason !== "string" || row.reason.trim() === "")) {
      errors.push(`${at}.reason: required for status "${String(row.status)}" — a gap without a reason is a silent skip`);
    } else if (row.reason !== undefined && typeof row.reason !== "string") {
      errors.push(`${at}.reason: expected string`);
    }
  });
}

function validateBaseline(baseline: unknown, errors: string[]): void {
  if (!isRecord(baseline)) {
    errors.push("baseline: expected an object");
    return;
  }
  if (!Array.isArray(baseline.resolved)) errors.push("baseline.resolved: expected an array");
  const c = baseline.counts;
  if (!isRecord(c)) {
    errors.push("baseline.counts: expected an object");
    return;
  }
  for (const k of ["resolved", "persistent", "new"] as const) {
    if (typeof c[k] !== "number" || !Number.isInteger(c[k])) errors.push(`baseline.counts.${k}: expected integer`);
  }
  if (baseline.priorLabel !== undefined && typeof baseline.priorLabel !== "string") {
    errors.push("baseline.priorLabel: expected string");
  }
}

// #1045: a malformed testQuality would render a table of "undefined%" — a mutation score is a
// client-facing claim, so a broken one must fail validation rather than reach the page.
function validateTestQuality(tq: unknown, errors: string[]): void {
  if (!isRecord(tq)) {
    errors.push("testQuality: expected an object");
    return;
  }
  if (typeof tq.mutationScore !== "number") errors.push("testQuality.mutationScore: expected number");
  if (tq.mutationScoreBasedOnCoveredCode !== undefined && typeof tq.mutationScoreBasedOnCoveredCode !== "number") {
    errors.push("testQuality.mutationScoreBasedOnCoveredCode: expected number");
  }
  if (typeof tq.wholeRepo !== "boolean") errors.push("testQuality.wholeRepo: expected boolean");
  if (typeof tq.scopeNote !== "string") errors.push("testQuality.scopeNote: expected string");
  if (!Array.isArray(tq.coveredScope)) errors.push("testQuality.coveredScope: expected an array");
  if (typeof tq.survivorTotal !== "number") errors.push("testQuality.survivorTotal: expected number");
  if (!Array.isArray(tq.survivors)) errors.push("testQuality.survivors: expected an array");
  const lc = tq.lineCoverage;
  if (!isRecord(lc) || (lc.status !== "ran" && lc.status !== "partial")) {
    errors.push('testQuality.lineCoverage: expected { status: "ran" | "partial" }');
  } else if (lc.status === "partial" && typeof lc.reason !== "string") {
    // Same rule as the coverage ledger: a gap without a reason is a silent skip.
    errors.push("testQuality.lineCoverage.reason: required when status is \"partial\"");
  }
  if (!Array.isArray(tq.rows)) {
    errors.push("testQuality.rows: expected an array");
    return;
  }
  tq.rows.forEach((row: unknown, i: number) => {
    const at = `testQuality.rows[${i}]`;
    if (!isRecord(row)) {
      errors.push(`${at}: not an object`);
      return;
    }
    if (typeof row.module !== "string" || row.module === "") errors.push(`${at}.module: expected non-empty string`);
    for (const k of ["mutationScore", "survivingCount", "hotspotSurvivingCount"] as const) {
      if (typeof row[k] !== "number") errors.push(`${at}.${k}: expected number`);
    }
    if (row.lineCoverage !== undefined && typeof row.lineCoverage !== "number") errors.push(`${at}.lineCoverage: expected number`);
    if (row.action !== undefined && typeof row.action !== "string") errors.push(`${at}.action: expected string`);
  });
}

export function validateFindings(data: unknown): ValidationResult {
  const errors: string[] = [];

  if (!isRecord(data)) return { ok: false, errors: ["document is not an object"] };

  if (!isRecord(data.meta)) {
    errors.push("meta: missing or not an object");
  } else {
    for (const k of META_STRING_FIELDS) {
      if (typeof data.meta[k] !== "string") errors.push(`meta.${k}: expected string`);
    }
    if (typeof data.meta.confidential !== "boolean") errors.push("meta.confidential: expected boolean");
    const h = data.meta.overallHealth;
    if (typeof h !== "number" || h < 0 || h > 10) errors.push("meta.overallHealth: expected number 0–10");
  }

  if (data.coverage !== undefined) validateCoverage(data.coverage, errors);
  if (data.baseline !== undefined) validateBaseline(data.baseline, errors);
  if (data.testQuality !== undefined) validateTestQuality(data.testQuality, errors);
  if (data.legalTerms !== undefined && (!isRecord(data.legalTerms) || typeof data.legalTerms.text !== "string" || data.legalTerms.text.trim() === "")) {
    errors.push("legalTerms.text: expected non-empty string — an empty terms block would render as approved-but-blank");
  }

  // #509: refuse a "done"/"complete" headline over a ledger that isn't. Only checked when a
  // derived ledger is present — a hand-authored legacy doc with no coverage[] has nothing to
  // check against, same back-compat carve-out as validateCoverage above.
  if (Array.isArray(data.coverage) && isRecord(data.meta) && typeof data.meta.headline === "string") {
    const coverage = data.coverage as CoverageRow[];
    const { complete, ranCount, total, gaps } = deriveCompleteness(coverage);
    if (!complete && headlineClaimsCompletion(data.meta.headline)) {
      const gapList = gaps.map((g) => g.module).join(", ");
      errors.push(`meta.headline: claims completion ("${data.meta.headline}") but only ${ranCount}/${total} modules ran — not fully run: ${gapList}. ${completenessStatement(coverage)}`);
    }
  }

  if (!Array.isArray(data.findings)) {
    errors.push("findings: missing or not an array");
    return { ok: false, errors };
  }

  const seenIds = new Set<string>();
  data.findings.forEach((f: unknown, i: number) => {
    const at = `findings[${i}]`;
    if (!isRecord(f)) {
      errors.push(`${at}: not an object`);
      return;
    }
    for (const k of FINDING_STRING_FIELDS) {
      if (typeof f[k] !== "string") errors.push(`${at}.${k}: expected string`);
    }
    if (!SEVERITIES.includes(f.severity as Severity)) {
      errors.push(`${at}.severity: "${String(f.severity)}" not one of ${SEVERITIES.join("/")}`);
    }
    if (!CONFIDENCES.includes(f.confidence as Confidence)) {
      errors.push(`${at}.confidence: "${String(f.confidence)}" not one of ${CONFIDENCES.join("/")}`);
    }
    for (const k of ["value", "ease", "safety"] as const) {
      if (!scoreInRange(f[k])) errors.push(`${at}.${k}: expected integer 1–5`);
    }
    if (typeof f.id === "string") {
      if (seenIds.has(f.id)) errors.push(`${at}.id: duplicate id "${f.id}"`);
      seenIds.add(f.id);
    }
    if (f.mechanical !== undefined && typeof f.mechanical !== "boolean") {
      errors.push(`${at}.mechanical: expected boolean`);
    }
    if (f.exploitabilityVerified !== undefined && typeof f.exploitabilityVerified !== "boolean") {
      errors.push(`${at}.exploitabilityVerified: expected boolean`);
    }
    if (f.precisionTier !== undefined && !PRECISION_TIERS.includes(f.precisionTier as PrecisionTier)) {
      errors.push(`${at}.precisionTier: "${String(f.precisionTier)}" not one of ${PRECISION_TIERS.join("/")}`);
    }
    if (f.reviewFlagOnly !== undefined && typeof f.reviewFlagOnly !== "boolean") {
      errors.push(`${at}.reviewFlagOnly: expected boolean`);
    }
    if (f.suggestedFix !== undefined) {
      const sf = f.suggestedFix;
      if (!isRecord(sf)) {
        errors.push(`${at}.suggestedFix: expected an object`);
      } else {
        if (typeof sf.diff !== "string" || sf.diff.trim() === "") errors.push(`${at}.suggestedFix.diff: expected a non-empty unified diff string`);
        if (typeof sf.verified !== "boolean") errors.push(`${at}.suggestedFix.verified: expected boolean`);
        if (sf.verification !== undefined && typeof sf.verification !== "string") errors.push(`${at}.suggestedFix.verification: expected string`);
      }
    }
    if (f.reviewFlagColumns !== undefined) {
      if (!Array.isArray(f.reviewFlagColumns) || f.reviewFlagColumns.some((c) => typeof c !== "string")) {
        errors.push(`${at}.reviewFlagColumns: expected an array of strings`);
      }
    }
    // #1083: the renderer places a finding in the report ONLY if it's in the asserted-findings list
    // (confidence !== "N/A" && !reviewFlagOnly), the N/A list (confidence === "N/A"), or the
    // review-flagged section (reviewFlagColumns.length > 0) — report-template/render.mjs. A
    // reviewFlagOnly finding with no reviewFlagColumns and confidence !== "N/A" matches none of the
    // three and renders in no section, while still being present in findings.json.
    if (f.reviewFlagOnly === true && f.confidence !== "N/A" && !(Array.isArray(f.reviewFlagColumns) && f.reviewFlagColumns.length > 0)) {
      errors.push(`${at}.reviewFlagColumns: required (non-empty) when reviewFlagOnly is true and confidence is not "N/A" — otherwise the finding renders in no report section`);
    }
    if (f.baselineStatus !== undefined && !BASELINE_STATUSES.includes(f.baselineStatus as BaselineStatus)) {
      errors.push(`${at}.baselineStatus: "${String(f.baselineStatus)}" not one of ${BASELINE_STATUSES.join("/")}`);
    }
    if (f.lowConfidenceMatch !== undefined && typeof f.lowConfidenceMatch !== "string") {
      errors.push(`${at}.lowConfidenceMatch: expected string`);
    }
    for (const k of ["cwe", "owasp", "references"] as const) {
      const v = f[k];
      if (v !== undefined && (!Array.isArray(v) || v.some((id) => typeof id !== "string"))) {
        errors.push(`${at}.${k}: expected an array of strings`);
      }
    }
    if (f.onHotspot !== undefined && typeof f.onHotspot !== "boolean") {
      errors.push(`${at}.onHotspot: expected boolean`);
    }
    if (f.hotspotRank !== undefined && (typeof f.hotspotRank !== "number" || !Number.isInteger(f.hotspotRank) || f.hotspotRank < 1)) {
      errors.push(`${at}.hotspotRank: expected a positive integer (1-based hotspot rank)`);
    }
    if (f.dataClass !== undefined) {
      const dc = f.dataClass;
      if (!isRecord(dc)) {
        errors.push(`${at}.dataClass: expected an object`);
      } else {
        if (typeof dc.table !== "string" || dc.table === "") errors.push(`${at}.dataClass.table: expected non-empty string`);
        for (const k of ["categories", "infotypes"] as const) {
          if (!Array.isArray(dc[k]) || (dc[k] as unknown[]).some((v) => typeof v !== "string")) errors.push(`${at}.dataClass.${k}: expected an array of strings`);
        }
        // The escalation's justification is the whole point of the field — an escalated severity
        // with no stated reason is the silent re-scoring #1049 exists to prevent.
        if (typeof dc.reason !== "string" || dc.reason.trim() === "") errors.push(`${at}.dataClass.reason: required — an escalation without a stated reason is a silent re-scoring`);
        if (dc.escalatedFrom !== undefined && !SEVERITIES.includes(dc.escalatedFrom as Severity)) {
          errors.push(`${at}.dataClass.escalatedFrom: "${String(dc.escalatedFrom)}" not one of ${SEVERITIES.join("/")}`);
        }
      }
    }
  });

  return { ok: errors.length === 0, errors };
}
