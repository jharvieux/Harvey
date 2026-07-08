// Free quick-scan tier — the "free diagnosis, gated remediation" freemium model
// (docs/design/quick-scan-tier.md, variant B′). Turns the mechanical scan's Finding[]
// into the free-tier diagnosis: counts, categories, located findings with a plain-English
// risk line, ONE fully-revealed teaser (with its fix), and an A–F grade.
//
// Two invariants this module enforces as real logic, not labels:
//   1. Trust boundary — only ~100%-precision findings (precisionTier "high") reach the
//      free count/grade/list. A single wrong "critical" is credibility-fatal, so heuristic
//      ("review") findings are excluded here, not merely downranked.
//   2. Free/gated split — the free path withholds the fix/remediation for every finding
//      except the single teaser. Location is NEVER gated (anti-shakedown).

import type { Finding, Severity } from "./findings.js";
import { SEVERITIES } from "./findings.js";

export type Grade = "A" | "B" | "C" | "D" | "F";

// A diagnosis-only view of a finding: type + location + why-it-matters, no remediation.
// `fix` is present only in the unlocked (paid) report and on the single free teaser.
export interface DiagnosisFinding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  taxonomy: string;
  location: string;
  risk: string; // plain-English "why it matters" — the Finding's impact line
  fix?: string;
}

export interface QuickScanReport {
  grade: Grade;
  score: number;
  total: number;
  countsBySeverity: Record<Severity, number>;
  categories: { category: string; count: number }[];
  findings: DiagnosisFinding[];
  sample: DiagnosisFinding | null; // the one teaser, always shown with its fix
  reviewTierExcluded: number; // heuristic findings deliberately kept out of the free grade
  locked: boolean;
  gated: string[]; // what the unlock delivers
}

// Grade penalties per verified finding. Weighted so a single verified Critical (leaked
// service-role key, RSC RCE) alone drops the repo out of a passing grade — matching the
// severity these carry for this audience. Flavor, not core payload (design §2).
const SEVERITY_PENALTY: Record<Severity, number> = {
  Critical: 50,
  High: 20,
  Medium: 8,
  Low: 3,
  Perf: 0,
  Info: 0,
  Watch: 0,
};

const GATED_CAPABILITIES = [
  "The fix / remediation steps for every finding above",
  "The DEEP scan: LLM semantic review + live RLS/auth pen test",
  "Re-scan, monitoring, and PR checks",
  "Exportable report (PDF / SARIF)",
];

// The free tier draws ONLY from the ~100%-precision tier (#25's precisionTier tag).
// Everything else is heuristic and must not enter the free count/grade.
export function selectFreeFindings(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.precisionTier === "high");
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function categorize(findings: Finding[]): { category: string; count: number }[] {
  const byCategory = new Map<string, number>();
  for (const f of findings) byCategory.set(f.category, (byCategory.get(f.category) ?? 0) + 1);
  return [...byCategory.entries()]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
}

export function computeGrade(findings: Finding[]): { grade: Grade; score: number } {
  const penalty = findings.reduce((sum, f) => sum + SEVERITY_PENALTY[f.severity], 0);
  const score = Math.max(0, 100 - penalty);
  const grade: Grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  return { grade, score };
}

const severityRank = (s: Severity): number => SEVERITIES.indexOf(s);

// The teaser: the single finding whose fix is revealed free, chosen as the most severe
// verified finding (deterministic id tiebreak) — the best converter is a complete example
// on the user's own most serious issue.
export function pickSample(findings: Finding[]): Finding | null {
  if (findings.length === 0) return null;
  return [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id))[0]!;
}

function toDiagnosis(f: Finding, includeFix: boolean): DiagnosisFinding {
  const d: DiagnosisFinding = {
    id: f.id,
    title: f.title,
    severity: f.severity,
    category: f.category,
    taxonomy: f.taxonomy,
    location: f.location, // never gated
    risk: f.impact,
  };
  if (includeFix) d.fix = f.fix;
  return d;
}

// Build the quick-scan report. `unlocked` models the paid boundary as a flag: locked (free)
// withholds every fix except the teaser's; unlocked reveals all fixes. The precision filter
// and the always-shown location apply in both modes.
export function buildQuickScanReport(findings: Finding[], opts: { unlocked?: boolean } = {}): QuickScanReport {
  const unlocked = opts.unlocked ?? false;
  const free = selectFreeFindings(findings);
  const { grade, score } = computeGrade(free);
  const sample = pickSample(free);
  return {
    grade,
    score,
    total: free.length,
    countsBySeverity: countBySeverity(free),
    categories: categorize(free),
    findings: free.map((f) => toDiagnosis(f, unlocked)),
    sample: sample ? toDiagnosis(sample, true) : null,
    reviewTierExcluded: findings.length - free.length,
    locked: !unlocked,
    gated: unlocked ? [] : GATED_CAPABILITIES,
  };
}
