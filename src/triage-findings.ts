import type { Confidence, Finding, Severity } from "./findings.js";

const TRIAGE_VERDICTS = ["true_positive", "false_positive", "duplicate"] as const;
const VERIFY_VERDICTS = ["exploitable", "mitigated", "needs_manual_test"] as const;
const TRIAGE_SEVERITIES = ["HIGH", "MEDIUM", "LOW"] as const;

type TriageVerdict = (typeof TRIAGE_VERDICTS)[number];
type VerifyVerdict = (typeof VERIFY_VERDICTS)[number];
type TriageSeverity = (typeof TRIAGE_SEVERITIES)[number];

interface TriageFinding {
  id: string;
  verdict: TriageVerdict;
  title?: string;
  file?: string;
  line?: number;
  category?: string;
  severity?: TriageSeverity | null;
  verify_verdict?: VerifyVerdict | null;
  confidence?: number;
  rationale?: string;
  recommendation?: string;
  impact?: string;
  exploit_scenario?: string;
  duplicate_of?: string | null;
  vote_breakdown?: { true_positive: number; false_positive: number; cannot_verify: number };
  value?: number;
  ease?: number;
  safety?: number;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const nonEmpty = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;

function parseVoteBreakdown(value: unknown, at: string, expectedVotes: number | undefined) {
  if (!isRecord(value)) throw new Error(`${at}.vote_breakdown must be an object`);
  const keys = ["true_positive", "false_positive", "cannot_verify"] as const;
  for (const key of keys) {
    if (!Number.isInteger(value[key]) || (value[key] as number) < 0) {
      throw new Error(`${at}.vote_breakdown.${key} must be a nonnegative integer`);
    }
  }
  const result = {
    true_positive: value.true_positive as number,
    false_positive: value.false_positive as number,
    cannot_verify: value.cannot_verify as number,
  };
  const total = result.true_positive + result.false_positive + result.cannot_verify;
  if (total === 0) throw new Error(`${at}.vote_breakdown records zero votes`);
  if (expectedVotes !== undefined && total !== expectedVotes) {
    throw new Error(`${at}.vote_breakdown totals ${total}, expected ${expectedVotes}`);
  }
  return result;
}

function parseOptionalScore(value: unknown, at: string): number {
  if (value === undefined) return 3;
  if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > 5) {
    throw new Error(`${at} must be an integer from 1 to 5`);
  }
  return value as number;
}

function reportSeverity(value: TriageSeverity): Severity {
  return value === "HIGH" ? "High" : value === "MEDIUM" ? "Medium" : "Low";
}

function reportConfidence(value: number, verifyVerdict: VerifyVerdict): Confidence {
  if (verifyVerdict === "needs_manual_test" || value < 5) return "Review";
  return value >= 8 ? "Confirmed" : "Likely";
}

function optionalText(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function parseTriageFinding(value: unknown, index: number, expectedVotes: number | undefined): TriageFinding {
  const at = `findings[${index}]`;
  if (!isRecord(value)) throw new Error(`${at} must be an object`);
  if (!nonEmpty(value.id)) throw new Error(`${at}.id must be a non-empty string`);
  if (!TRIAGE_VERDICTS.includes(value.verdict as TriageVerdict)) {
    throw new Error(`${at}.verdict must be one of ${TRIAGE_VERDICTS.join(", ")}`);
  }
  const finding: TriageFinding = { ...(value as unknown as TriageFinding), id: value.id, verdict: value.verdict as TriageVerdict };
  if (finding.verdict === "duplicate") {
    if (!nonEmpty(finding.duplicate_of)) throw new Error(`${at}.duplicate_of must name the canonical finding`);
    return finding;
  }
  const votes = parseVoteBreakdown(finding.vote_breakdown, at, expectedVotes);
  if (finding.verdict === "false_positive") {
    if (votes.true_positive > votes.false_positive && votes.true_positive > votes.cannot_verify) {
      throw new Error(`${at}.verdict is false_positive but its vote_breakdown has a true-positive majority`);
    }
    return finding;
  }

  for (const field of ["title", "file", "category", "rationale"] as const) {
    if (!nonEmpty(finding[field])) throw new Error(`${at}.${field} must be a non-empty string for a true positive`);
  }
  if (!Number.isInteger(finding.line) || (finding.line as number) < 1) {
    throw new Error(`${at}.line must be a positive integer for a true positive`);
  }
  if (!TRIAGE_SEVERITIES.includes(finding.severity as TriageSeverity)) {
    throw new Error(`${at}.severity must be one of ${TRIAGE_SEVERITIES.join(", ")} for a true positive`);
  }
  if (!VERIFY_VERDICTS.includes(finding.verify_verdict as VerifyVerdict)) {
    throw new Error(`${at}.verify_verdict must be one of ${VERIFY_VERDICTS.join(", ")} for a true positive`);
  }
  if (typeof finding.confidence !== "number" || !Number.isFinite(finding.confidence) || finding.confidence < 0 || finding.confidence > 10) {
    throw new Error(`${at}.confidence must be a number from 0 to 10 for a true positive`);
  }
  if (votes.true_positive <= votes.false_positive || votes.true_positive <= votes.cannot_verify) {
    throw new Error(`${at}.verdict is true_positive but its vote_breakdown has no true-positive majority`);
  }
  parseOptionalScore(finding.value, `${at}.value`);
  parseOptionalScore(finding.ease, `${at}.ease`);
  parseOptionalScore(finding.safety, `${at}.safety`);
  return finding;
}

function semanticKey(finding: Finding): string {
  return [finding.location, finding.taxonomy, finding.title, finding.evidence]
    .map((part) => part.trim().toLowerCase())
    .join("\u0000");
}

function translateTruePositive(finding: TriageFinding): Finding {
  const severity = finding.severity as TriageSeverity;
  const verifyVerdict = finding.verify_verdict as VerifyVerdict;
  const rationale = finding.rationale as string;
  return {
    id: finding.id,
    title: finding.title as string,
    severity: reportSeverity(severity),
    confidence: reportConfidence(finding.confidence as number, verifyVerdict),
    category: "Security",
    taxonomy: finding.category as string,
    location: `${finding.file}:${finding.line}`,
    status: "Open",
    evidence: rationale,
    impact: optionalText(finding.impact) || optionalText(finding.exploit_scenario),
    fix: optionalText(finding.recommendation),
    value: parseOptionalScore(finding.value, `${finding.id}.value`),
    ease: parseOptionalScore(finding.ease, `${finding.id}.ease`),
    safety: parseOptionalScore(finding.safety, `${finding.id}.safety`),
    note: "Imported from completed TRIAGE.json. Missing BFTB values use the neutral 3/3/3 default.",
  };
}

/**
 * Convert the triage skill's completed object into the report-schema Finding[] consumed by
 * record-pass. False positives and explicit duplicates remain in TRIAGE.json as the audit trail;
 * only independently confirmed true positives enter the scored M1 pass.
 */
export function findingsFromCompletedTriage(raw: unknown): Finding[] {
  if (!isRecord(raw)) throw new Error("completed triage input must be a JSON object");
  if (raw.triage_completed !== true) throw new Error("completed triage input requires triage_completed: true");
  if (!Array.isArray(raw.findings)) throw new Error("completed triage input requires a findings array");

  if (!isRecord(raw.triage_context)) throw new Error("completed triage input requires a triage_context object");
  const votes = raw.triage_context.votes_per_finding;
  if (!Number.isInteger(votes) || (votes as number) < 1) throw new Error("triage_context.votes_per_finding must be a positive integer");
  const expectedVotes = votes as number;

  const parsed = raw.findings.map((value, index) => parseTriageFinding(value, index, expectedVotes));
  const ids = new Set<string>();
  for (const finding of parsed) {
    if (ids.has(finding.id)) throw new Error(`completed triage input has duplicate finding id: ${finding.id}`);
    ids.add(finding.id);
  }
  const byId = new Map(parsed.map((finding) => [finding.id, finding]));
  for (const finding of parsed) {
    if (finding.verdict !== "duplicate") continue;
    const canonical = byId.get(finding.duplicate_of as string);
    if (!canonical) {
      throw new Error(`${finding.id}.duplicate_of names an unknown canonical finding: ${finding.duplicate_of}`);
    }
    if (canonical.verdict === "duplicate") {
      throw new Error(`${finding.id}.duplicate_of must name a non-duplicate canonical finding: ${finding.duplicate_of}`);
    }
  }

  const translated = parsed
    .filter((finding) => finding.verdict === "true_positive")
    .map(translateTruePositive)
    .sort((a, b) => a.id.localeCompare(b.id) || semanticKey(a).localeCompare(semanticKey(b)));
  const seen = new Set<string>();
  return translated.filter((finding) => {
    const key = semanticKey(finding);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Preserve the pre-existing bare Finding[] interface while accepting completed TRIAGE.json. */
export function findingsFromRecordPassInput(raw: unknown): Finding[] {
  return Array.isArray(raw) ? raw as Finding[] : findingsFromCompletedTriage(raw);
}
