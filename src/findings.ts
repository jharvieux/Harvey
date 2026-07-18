// Findings schema for the audit deliverable. report-template/render.mjs consumes
// this shape; validate an engagement's findings.json here before rendering.

import { deriveCompleteness, headlineClaimsCompletion } from "./audit-completeness.js";

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

// Engagement baseline diff (#457). A finding's standing relative to the prior audit of the same
// client: "persistent" (matched by identity in both), "new" (only this run), "resolved" (only the
// prior run). Set by src/audit-diff.ts, never hand-typed. Absent ⇒ no baseline was supplied.
export const BASELINE_STATUSES = ["new", "persistent", "resolved"] as const;

export type Severity = (typeof SEVERITIES)[number];
export type Confidence = (typeof CONFIDENCES)[number];
export type PrecisionTier = (typeof PRECISION_TIERS)[number];
export type CoverageStatus = (typeof COVERAGE_STATUSES)[number];
export type BaselineStatus = (typeof BASELINE_STATUSES)[number];

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
  // Engagement baseline diff (#457), set by src/audit-diff.ts when a --baseline is supplied.
  // baselineStatus classifies this finding against the prior audit; lowConfidenceMatch names the
  // prior finding's id this MIGHT be the same as (same taxonomy + location basename, exact key
  // differed) — surfaced for a human to confirm, NEVER used to auto-merge (fail loud).
  baselineStatus?: BaselineStatus;
  lowConfidenceMatch?: string;
  // CWE / OWASP Top-10 identifiers (#455), for ticket-routing/compliance mapping. Populated from
  // the scanner's own metadata (semgrep rule `metadata.cwe`/`metadata.owasp` — both the external
  // p/owasp-top-ten pack and, where the mapping is unambiguous, the harvey-* custom rules), never
  // invented at report time. Absent on any finding with no defensible mapping.
  cwe?: string[];
  owasp?: string[];
  // #515: cross-module hotspot enrichment. Set at assembly time when a finding's location sits on
  // an M3-ranked hotspot (high churn × complexity × coupling). onHotspot up-ranks it in the report's
  // cross-module ordering; hotspotRank is the file's 1-based position in the top-K (1 = hottest).
  // One mechanism, every module benefits — most valuably M6 (a hand-rolled reinvention on a hot file
  // matters far more than the same pattern on a stable leaf). Absent ⇒ not on a ranked hotspot, or no
  // M3 ranking was available this run.
  onHotspot?: boolean;
  hotspotRank?: number;
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

  // #509: refuse a "done"/"complete" headline over a ledger that isn't. Only checked when a
  // derived ledger is present — a hand-authored legacy doc with no coverage[] has nothing to
  // check against, same back-compat carve-out as validateCoverage above.
  if (Array.isArray(data.coverage) && isRecord(data.meta) && typeof data.meta.headline === "string") {
    const { complete, ranCount, total, gaps } = deriveCompleteness(data.coverage as CoverageRow[]);
    if (!complete && headlineClaimsCompletion(data.meta.headline)) {
      const gapList = gaps.map((g) => g.module).join(", ");
      errors.push(`meta.headline: claims completion ("${data.meta.headline}") but only ${ranCount}/${total} modules ran — not fully run: ${gapList}`);
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
    if (f.reviewFlagColumns !== undefined) {
      if (!Array.isArray(f.reviewFlagColumns) || f.reviewFlagColumns.some((c) => typeof c !== "string")) {
        errors.push(`${at}.reviewFlagColumns: expected an array of strings`);
      }
    }
    if (f.baselineStatus !== undefined && !BASELINE_STATUSES.includes(f.baselineStatus as BaselineStatus)) {
      errors.push(`${at}.baselineStatus: "${String(f.baselineStatus)}" not one of ${BASELINE_STATUSES.join("/")}`);
    }
    if (f.lowConfidenceMatch !== undefined && typeof f.lowConfidenceMatch !== "string") {
      errors.push(`${at}.lowConfidenceMatch: expected string`);
    }
    for (const k of ["cwe", "owasp"] as const) {
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
  });

  return { ok: errors.length === 0, errors };
}
