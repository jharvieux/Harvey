// Free quick-scan tier — the "free diagnosis, gated remediation" freemium model
// (docs/design/quick-scan-tier.md, variant B′). Turns the mechanical scan's Finding[]
// into the free-tier diagnosis: counts, categories, located findings with a plain-English
// risk line, ONE fully-revealed teaser (with its fix), and an A–F grade.
//
// Three invariants this module enforces as real logic, not labels:
//   1. Trust boundary — only ~100%-precision findings (precisionTier "high") reach the
//      free count/grade/list. A single wrong "critical" is credibility-fatal, so heuristic
//      ("review") findings are excluded here, not merely downranked.
//   2. Free/gated split — the free path withholds the fix/remediation for every finding
//      except the single teaser. Location is NEVER gated (anti-shakedown).
//   3. The grade is a HYGIENE grade, never a security verdict (#227). The mechanical tier can
//      only see what it can mechanically verify — dependency and secret hygiene, dangerous
//      config — which is inversely correlated with what actually matters for this audience
//      (tenant isolation, authz). So the headline is two-part: a scope-annotated grade PLUS an
//      explicit risk disclosure naming what was NOT assessed. Source-tier RLS/authz signals ride
//      alongside as non-grading INDICATORS (#220) — the honest teaser, never a verdict.

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

// One M6 "looks hand-rolled" indicator class, rolled up for presentation (#267 Phase 2).
// The rollup is the volume rule the operator ruling requires: repeats of the same shape are
// grouped per file rather than listed one row per occurrence, so forty debounces can't bury
// the real signal. `files` is COMPLETE (every file, every location) — the presentation layer
// caps how many it prints, but the report itself never silently truncates.
export interface HandrolledIndicatorClass {
  taxonomy: string; // "M6 — Indicator: cookie parsing"
  shape: string; // the class label shown to the reader — the taxonomy's suffix
  title: string; // the hedged per-finding title (locked vocabulary, shared by the class)
  total: number; // occurrences of this shape across the whole target
  files: { file: string; locations: string[] }[]; // every occurrence, grouped by file
}

export interface QuickScanReport {
  grade: Grade;
  score: number;
  gradeScope: string; // the grade annotated with what it does and does not cover (#227)
  riskDisclosure: string; // what this tier could NOT assess — always shown, never softened
  total: number; // GRADED findings only — the count the grade actually reflects
  countsBySeverity: Record<Severity, number>;
  categories: { category: string; count: number }[];
  findings: DiagnosisFinding[];
  informational: DiagnosisFinding[]; // seen, reported, deliberately not graded (#213)
  indicators: DiagnosisFinding[]; // source-tier tenant-isolation/authz signals, not verdicts (#220)
  handrolled: HandrolledIndicatorClass[]; // M6 "looks hand-rolled" indicators, rolled up (#267)
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

// What the unlock actually delivers. This is sales copy on the one surface a prospect reads, so
// the fail-loud doctrine applies to it exactly as it applies to a coverage row: EVERY LINE HERE
// MUST NAME A CAPABILITY THAT EXISTS IN THIS REPO TODAY. #866 found it advertising SARIF export,
// PR checks, and monitoring, none of which existed — a commercial-representation risk, not a
// roadmap entry. Each line below is backed by shipped code: remediation text rides on every
// Finding.fix; the deep scan is the LLM pass + src/pentest; the re-scan diff is
// `run-audit --baseline` (src/audit-diff.ts); the PDF is report-template/render.mjs.
// Adding a line for something unbuilt is a defect.
const GATED_CAPABILITIES = [
  "The fix / remediation steps for every finding above",
  "The DEEP scan: LLM semantic review + live RLS/auth pen test",
  "A re-scan diffed against this one — what you resolved, what's still open, what's new",
  "The written report as a PDF",
];

// Categories that are high-precision about the FACT but not about EXPLOITABILITY, so they are
// reported in full and deliberately excluded from the grade (#213/#227). A dependency whose
// version falls in a CVE range is an exact version match, not a proven vulnerability: whether it
// is reachable depends on deployment context (a Vercel-hosted middleware CVE is auto-patched).
// Grading on it produced F's built entirely on unverified version matches while the real
// vulnerability went unmentioned — worse than silence, because a prospect who bumps the version
// believes they cleared their top risk. Keyed on category as the default because every finding
// this category carries TODAY is a version match (crisp or approximate) — but the category isn't
// the actual test. `exploitabilityVerified` (src/findings.ts) is: a finding that earns that flag
// is claiming confirmed exploitability, not just a version overlap, and grades despite its
// category (#260) — the decision travels with the finding that knows its own evidence quality,
// not a category-wide guess.
// "License compliance" (#456) joins the set for the same reason: a copyleft SPDX match or a
// missing-license disclosure is a legal judgment about redistribution terms, not a security
// verdict — surfaced in full, never auto-failing the grade.
const NON_GRADING_CATEGORIES = new Set(["Dependency CVE", "License compliance"]);

const isNonGrading = (f: Finding): boolean => NON_GRADING_CATEGORIES.has(f.category) && !f.exploitabilityVerified;

// The free tier draws ONLY from the ~100%-precision tier (#25's precisionTier tag).
// Everything else is heuristic and must not enter the free count/grade.
export function selectFreeFindings(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.precisionTier === "high");
}

// Of the free (high-precision) findings, the subset the grade is computed from: the classes that
// are exact at the mechanical layer AND mean what they say (#227). Everything else stays visible
// as informational.
export function selectGradedFindings(findings: Finding[]): Finding[] {
  return selectFreeFindings(findings).filter((f) => !isNonGrading(f));
}

// Source-tier tenant-isolation / authz signals (#220). These are INDICATORS, never verdicts: the
// static tier can see a policy's shape but cannot prove how it behaves against a live database,
// so they are surfaced loudly and never counted in the grade. Deliberately drawn from the review
// tier — this is the one place a review-tier signal is shown in the free output, because staying
// silent about a probable cross-tenant hole to protect a precision claim is the worse failure.
const INDICATOR_CATEGORY = "Multi-tenant security";

export function selectIndicators(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.precisionTier === "review" && f.category === INDICATOR_CATEGORY);
}

// M6 "looks hand-rolled" indicators (#267) — the second non-grading indicators section, same
// #227 framing as the RLS/authz one: descriptive, hedged, never a verdict, never in the grade.
// Keyed on the taxonomy prefix the detectors (src/detectors/handrolled.ts) and their language
// lock already guarantee.
const HANDROLLED_TAXONOMY_PREFIX = "M6 — Indicator: ";

function selectHandrolledIndicators(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.taxonomy.startsWith(HANDROLLED_TAXONOMY_PREFIX));
}

// The volume rule (#267 Phase 2, the operator ruling's risk #2): group per class, then per
// file, ordered most-occurrences-first. Nothing is dropped — `files` carries every location;
// only the text renderer caps how many FILES it prints (HANDROLLED_FILES_SHOWN) and it always
// states what it didn't print. Presentation problem, presentation-layer fix: the underlying
// Finding[] (detect-static output, the --json report) stays one row per occurrence.
export const HANDROLLED_FILES_SHOWN = 3;

export function rollupHandrolled(findings: Finding[]): HandrolledIndicatorClass[] {
  const byTaxonomy = new Map<string, Finding[]>();
  for (const f of selectHandrolledIndicators(findings)) {
    const list = byTaxonomy.get(f.taxonomy) ?? [];
    list.push(f);
    byTaxonomy.set(f.taxonomy, list);
  }
  return [...byTaxonomy.entries()]
    .map(([taxonomy, hits]) => {
      const byFile = new Map<string, string[]>();
      for (const h of hits) {
        const file = h.location.replace(/:\d+$/, "");
        const locs = byFile.get(file) ?? [];
        locs.push(h.location);
        byFile.set(file, locs);
      }
      return {
        taxonomy,
        shape: taxonomy.slice(HANDROLLED_TAXONOMY_PREFIX.length),
        title: hits[0]!.title,
        total: hits.length,
        files: [...byFile.entries()]
          .map(([file, locations]) => ({ file, locations }))
          .sort((a, b) => b.locations.length - a.locations.length || a.file.localeCompare(b.file)),
      };
    })
    .sort((a, b) => b.total - a.total || a.taxonomy.localeCompare(b.taxonomy));
}

// Section copy for the free report, exported so the CLI renders exactly these strings and the
// language-lock test can gate them alongside the detector vocabulary: hedged, no replacement
// named, no defect asserted — drifting to "should be replaced" voids the free/paid split.
export const HANDROLLED_SECTION_TITLE = "Looks hand-rolled — may be worth investigating";
export const HANDROLLED_SECTION_BLURB =
  "Recognisable hand-rolled shapes in your source. NOT counted in the grade, and no defect is " +
  "asserted — each may be a deliberate choice. The deep scan triages every one: genuine " +
  "reinvention, or a reasonable decision worth a WHY comment.";

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

// Grades the HYGIENE classes only — the caller passes selectGradedFindings' output. Passing an
// ungraded class here would silently re-create the #213 inversion.
export function computeGrade(findings: Finding[]): { grade: Grade; score: number } {
  const penalty = findings.reduce((sum, f) => sum + SEVERITY_PENALTY[f.severity], 0);
  const score = Math.max(0, 100 - penalty);
  const grade: Grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  return { grade, score };
}

// The grade never travels without its scope (#227) — "B" alone reads as a security verdict, which
// is exactly the claim this tier cannot make.
const RISK_DISCLOSURE =
  "Tenant isolation and authorization were NOT assessed from source — those need the deep scan " +
  "(LLM semantic review + live RLS/auth pen test). This grade covers mechanically-verifiable " +
  "hygiene only; it is not a statement that the app is secure.";

const INDICATOR_DISCLOSURE =
  " Potential tenant-isolation issues were spotted in your source and are listed below as " +
  "indicators — unconfirmed, and confirmed or cleared only in the deep scan.";

function gradeScopeLine(grade: Grade, indicatorCount: number): string {
  const base = `${grade} — hygiene only; tenant isolation and authz not assessed.`;
  return indicatorCount > 0 ? `${base} ${indicatorCount} potential issue${indicatorCount === 1 ? "" : "s"} flagged for the deep scan — see indicators.` : base;
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
  const graded = free.filter((f) => !isNonGrading(f));
  const informational = free.filter(isNonGrading);
  const indicators = selectIndicators(findings);
  const handrolled = rollupHandrolled(findings);
  const handrolledCount = handrolled.reduce((sum, c) => sum + c.total, 0);
  const { grade, score } = computeGrade(graded);
  const sample = pickSample(graded);
  return {
    grade,
    score,
    gradeScope: gradeScopeLine(grade, indicators.length),
    riskDisclosure: indicators.length > 0 ? RISK_DISCLOSURE + INDICATOR_DISCLOSURE : RISK_DISCLOSURE,
    total: graded.length,
    countsBySeverity: countBySeverity(graded),
    categories: categorize(graded),
    findings: graded.map((f) => toDiagnosis(f, unlocked)),
    informational: informational.map((f) => toDiagnosis(f, unlocked)),
    indicators: indicators.map((f) => toDiagnosis(f, unlocked)),
    handrolled,
    sample: sample ? toDiagnosis(sample, true) : null,
    // Heuristic signals kept out of the grade. Indicators (both kinds) are surfaced rather
    // than merely counted, so they aren't part of this "excluded" tally.
    reviewTierExcluded: findings.length - free.length - indicators.length - handrolledCount,
    locked: !unlocked,
    gated: unlocked ? [] : GATED_CAPABILITIES,
  };
}
