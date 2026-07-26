// M3 (hotspot analysis) — shapes the `vitals` plugin's churn×complexity / coupling / knowledge-
// risk / AI-provenance output into (a) a ranked hotspot table and (b) the deterministic boolean
// sub-signals (truck-factor-1, co-change coupling, AI-authored+high-churn) as Finding[] for the
// shared calibration harness, plus (c) the mechanical cross-reference of other modules' findings
// against the top-K hotspots (#363).
//
// STATUS: schema VERIFIED against a live `vitals 0.2.0 report --json <path>` run (issue #94), and
// re-verified against vitals 0.2.0's own emitter source (scripts/vitals_cli.py:300-312) for #1075.
// CORRECTION (#1075): the ROW types (VitalsHotspotRow / VitalsCouplingEdgeRow / VitalsKnowledgeRiskRow)
// match the real per-row shape exactly, but VitalsReport is NOT the real top-level shape — vitals_cli.py
// serializes 11 top-level keys (mode, repo_info, file_health, hotspots, coupling, knowledge_risk,
// provenance, trends, overall_health, files_analyzed, scope); VitalsReport is a DELIBERATE subset
// modelling only mode/hotspots/coupling/knowledge_risk/provenance/trends/overall_health (7 of 11) —
// repo_info/file_health/files_analyzed/scope are not read. `hotspots` is per-file rows sorted by
// `risk_score`; `coupling`/`knowledge_risk` are separate top-level arrays, not nested per hotspot row.
// The `provenance` shape (#369) is verified against vitals 0.2.0's own source
// (scripts/vitals_cli.py provenance_info + scripts/db.py get_ai_file_stats/get_provenance_summary):
// `{ has_data: false }` when no .vitals provenance DB exists, or has_data: true plus `summary`
// and `ai_files` (30-day window, ordered by total_events desc) when it does.
// `src/__fixtures__/vitals-report.json` is a synthetic report built to this real shape (paths and
// values are synthetic; the field names and nesting are not).
//
// Per the locked product decision (docs/design/spec-72-crossmodule-corpus.md preamble #2) and its
// M3 section: a hotspot RANK is an ordering over a continuous score, not a true/false finding —
// there is no M3 precision number, free-tier M3 output is a descriptive map only, never an
// asserted finding. What IS gateable the same way every other module's positives/negatives are:
// the deterministic boolean sub-signals (truck-factor-1, a coupling edge, AI-authored+high-churn),
// which toFactFindings below emits as Finding[] for buildCoverageMatrix. The rank itself is gated separately as a
// top-K *membership* check (rankHotspots / topKFiles) — see hotspot-scan.test.ts — never scored
// as a percentage.

import type { Finding } from "./findings.js";

interface VitalsChurnData {
  changes: number;
  lines_added: number;
  lines_removed: number;
  author_count: number;
  last_change: string;
}

export interface VitalsHotspotRow {
  file_path: string;
  health: number; // 0–10, lower = worse
  role: string;
  centrality: number;
  churn_data: VitalsChurnData;
  churn_label: string;
  complexity_score: number;
  coupling_strength: number;
  changes: number; // flat duplicate of churn_data.changes
  risk_score: number; // vitals' own churn×complexity-weighted rank score — the sort key
}

export interface VitalsCouplingEdgeRow {
  file_a: string;
  file_b: string;
  co_changes: number;
  coupling_strength: number;
  total_a: number;
  total_b: number;
}

export interface VitalsKnowledgeRiskRow {
  file_path: string;
  truck_factor: number;
  author_count: number;
  authors: Array<[string, number]>;
}

interface VitalsAiFileRow {
  file_path: string;
  edit_count: number;
  write_count: number;
  last_modified: number; // unix epoch seconds (float)
  total_events: number;
}

export interface VitalsProvenance {
  has_data: boolean;
  // Present only when has_data is true — vitals emits a bare { has_data: false } otherwise.
  summary?: {
    total_events: number;
    unique_files: number;
    total_sessions: number;
    first_event: number;
    last_event: number;
  };
  ai_files?: VitalsAiFileRow[];
}

// #1075: one row of vitals' day-over-day file_health trend (vitals_cli.py:269-287) — only ever
// populated in `trends.degrading`/`trends.improving`, never at the top level.
interface VitalsTrendFile {
  file_path: string;
  previous: number;
  current: number;
  delta: number;
}

// #1075: vitals' trend comparison against its own previous `.vitals` snapshot (vitals_cli.py:254-290).
// null on a first-ever run (no prior snapshot to diff against) — that is a legitimate "no history
// yet", not a gap. Previously entirely unread; the single most actionable M3 signal for a repeat
// engagement ("health moved from 6.2 to 5.8, driven by these 7 files").
export interface VitalsTrends {
  previous_overall: number;
  previous_timestamp: number;
  days_since: number;
  overall_delta: number;
  degrading: VitalsTrendFile[];
  improving: VitalsTrendFile[];
}

export interface VitalsReport {
  hotspots: VitalsHotspotRow[];
  coupling: VitalsCouplingEdgeRow[];
  knowledge_risk: VitalsKnowledgeRiskRow[];
  // Optional so a pre-0.2.0 capture without the key still parses; 0.2.0 always includes it.
  provenance?: VitalsProvenance;
  // #1075: "full" (has git — churn/coupling/knowledge all real) or "complexity-only" (no git in the
  // target — vitals_cli.py:301 sets churn=0 for every file, so EVERY hotspot's risk_score is 0.0 and
  // the "ranking" is filesystem-walk order). Optional for back-compat with a pre-#1075 capture;
  // absent ⇒ treat as unknown, not "full" (see isUnranked, which checks risk_score directly and does
  // not depend on this field being present).
  mode?: "full" | "complexity-only";
  // #1075: null on a first-ever run (no prior .vitals snapshot); optional for back-compat.
  trends?: VitalsTrends | null;
  // #1075: vitals' single-number codebase health (0–10, lower = worse), computed from the SAME
  // file_health scores hotspots are ranked by — but over every analysed file, not just the top-K.
  overall_health?: number;
}

// Worst-first by vitals' risk_score. Rank is an ordering, never scored as a percentage — callers
// use this (or topKFiles) for a top-K membership check, not a pass/fail per row.
export function rankHotspots(report: VitalsReport): VitalsHotspotRow[] {
  return [...report.hotspots].sort((a, b) => b.risk_score - a.risk_score);
}

export function topKFiles(report: VitalsReport, k: number): string[] {
  return rankHotspots(report)
    .slice(0, k)
    .map((r) => r.file_path);
}

// #1075: true when the ranking carries no real signal — vitals' own "complexity-only" mode (no git
// history in the target: churn is 0 for every file, so risk_score = (10-health)×churn×… is EXACTLY
// 0.0 across the board) leaves `hotspots` non-empty but its order is filesystem-walk order, not a
// churn×complexity ranking. Checked directly on risk_score (not `mode`) so it also catches a
// pre-#1075 capture that has no `mode` field at all. A genuinely EMPTY hotspots list (nothing
// cleared vitals'/Harvey's own churn gate) is a different, already-disclosed case — topKFiles
// already returns [] for it, so enrichment is already a no-op there — and is deliberately excluded
// here so it isn't double-reported.
export function isUnranked(report: VitalsReport): boolean {
  return report.hotspots.length > 0 && report.hotspots.every((h) => h.risk_score === 0);
}

// Reduced-tier fallback (#807) — the churn×complexity ranking Harvey computes ITSELF from git
// history plus a cheap complexity proxy, for a cold sandbox / fresh client repo where the external
// `vitals` plugin is not installed. This is the REDUCED M3 tier: a ranked hotspot table ONLY. File
// health, co-change coupling, knowledge-risk (truck-factor), and AI-provenance are vitals-only
// sub-signals and are NOT assessed here — so buildFallbackReport emits empty coupling/knowledge_risk
// (toFactFindings therefore yields nothing, no invented sub-signal facts), and the CLI/orchestrator
// disclose the result as `partial` with that reason, never a clean `ran` (fail-loud coverage).

// Cheap cyclomatic-ish proxy: 1 + branch/loop/boolean-operator count. Deliberately NOT vitals' AST
// metric — a stand-in cheap enough to run over every churning file, that still separates gnarly
// files from flat ones so the churn×complexity product ranks meaningfully.
export function complexityProxy(source: string): number {
  const tokens = source.match(/\b(if|for|while|case|catch)\b|&&|\|\|/g);
  return 1 + (tokens?.length ?? 0);
}

// vitals health_score.classify_churn thresholds (verified against vitals 0.2.0 source): ≤2 LOW,
// ≤8 MED, else HIGH — mirrored so the reduced tier's churn_label reads the same as a full report.
export function classifyChurn(changes: number): string {
  if (changes <= 2) return "LOW";
  if (changes <= 8) return "MED";
  return "HIGH";
}

export interface FallbackFile {
  file_path: string;
  changes: number;
  complexity: number;
}

// The same churn/complexity gate buildFallbackReport applies, factored out so the CLI can report
// the PRE-slice qualifying count (#1075 point 4) without duplicating the filter.
function qualifyingFallbackFiles(files: FallbackFile[]): FallbackFile[] {
  return files.filter((f) => f.changes >= 2 && f.complexity > 0);
}

// #1075: buildFallbackReport's own `.slice(0, topN)` happens BEFORE the --out artifact is built, so
// both the printed table and the artifact's `hotspots` array only ever see `topN` rows — the header
// that prints `ranked.length` is printing the post-truncation count, not the qualifying total. This
// gives the CLI the true count so it can print "showing top N of M" instead.
export function fallbackQualifyingCount(files: FallbackFile[]): number {
  return qualifyingFallbackFiles(files).length;
}

// Shapes reduced-tier inputs into a VitalsReport so the rest of the M3 pipeline (rankHotspots /
// topKFiles / --out artifact / cross-reference) is unchanged. Gate mirrors vitals: churn ≥ 2 AND
// nonzero complexity. risk = churn × complexity (the classic churn×complexity hotspot metric); no
// health/role/centrality weighting exists in this tier.
export function buildFallbackReport(files: FallbackFile[], topN = 10): VitalsReport {
  const hotspots: VitalsHotspotRow[] = qualifyingFallbackFiles(files)
    .map((f) => ({
      file_path: f.file_path,
      health: 0,
      role: "core",
      centrality: 0,
      churn_data: { changes: f.changes, lines_added: 0, lines_removed: 0, author_count: 0, last_change: "" },
      churn_label: classifyChurn(f.changes),
      complexity_score: f.complexity,
      coupling_strength: 0,
      changes: f.changes,
      risk_score: Math.round(f.changes * f.complexity * 10) / 10,
    }))
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, topN);
  return { hotspots, coupling: [], knowledge_risk: [] };
}

export function truckFactorOneFiles(report: VitalsReport): string[] {
  return report.knowledge_risk.filter((r) => r.truck_factor === 1).map((r) => r.file_path);
}

// Files the vitals provenance log attributes to AI tooling (Edit/Write hook events, 30-day
// window). The attribution itself is a fact given the log (spec-72 §M3); the FINDING below
// additionally requires vitals' own HIGH churn label, because in an AI-assisted codebase
// "AI-touched" alone flags nearly every file — the remediation-priority signal is the
// conjunction (AI-authored AND under heavy iteration), per #369.
export function aiProvenanceFiles(report: VitalsReport): string[] {
  if (!report.provenance?.has_data) return [];
  return (report.provenance.ai_files ?? []).map((r) => r.file_path);
}

interface CouplingEdge {
  a: string;
  b: string;
}

// Derives coupling edges from the report's top-level coupling array, deduped (a<>b and b<>a
// collapse to one).
function edgeKey(a: string, b: string): string {
  return [a, b].sort().join("::");
}

export function couplingEdges(report: VitalsReport): CouplingEdge[] {
  const seen = new Set<string>();
  const edges: CouplingEdge[] = [];
  for (const row of report.coupling) {
    const key = edgeKey(row.file_a, row.file_b);
    if (seen.has(key)) continue;
    seen.add(key);
    edges.push({ a: row.file_a, b: row.file_b });
  }
  return edges;
}

// Maps the deterministic boolean sub-signals into synthetic Finding[] so they score through the
// shared calibration harness (buildCoverageMatrix) exactly like any other module's true/false
// facts. severity/category/taxonomy mirror F-13's real shape (report-template/findings.atc.json)
// — "Watch" severity, "Maintainability" category — the descriptive-map tier, not an asserted bug.
export function toFactFindings(report: VitalsReport): Finding[] {
  const findings: Finding[] = [];

  for (const file of truckFactorOneFiles(report)) {
    findings.push({
      id: `M3-TRUCKFACTOR-${file}`,
      title: `Truck-factor-1 (sole-author): ${file}`,
      severity: "Watch",
      confidence: "Confirmed",
      category: "Maintainability",
      taxonomy: "Knowledge risk (truck-factor-1)",
      location: file,
      status: "Open",
      evidence: `vitals: ${file} committed only by its sole author.`,
      impact: "Single point of failure for this file's institutional knowledge.",
      fix: "Pair or document before the sole author is unavailable.",
      value: 2,
      ease: 3,
      safety: 5,
      mechanical: true,
      precisionTier: "high",
    });
  }

  for (const edge of couplingEdges(report)) {
    findings.push({
      id: `M3-COUPLING-${edge.a}-${edge.b}`,
      title: `Co-change coupling: ${edge.a} <> ${edge.b}`,
      severity: "Watch",
      confidence: "Confirmed",
      category: "Maintainability",
      taxonomy: "Coupling (co-change)",
      location: `${edge.a} <> ${edge.b}`,
      status: "Open",
      evidence: `vitals: ${edge.a} and ${edge.b} are always committed together.`,
      impact: "Hidden coupling raises the blast radius of a change to either file.",
      fix: "Confirm the coupling is intentional; if not, decouple.",
      value: 2,
      ease: 3,
      safety: 5,
      mechanical: true,
      precisionTier: "high",
    });
  }

  // Third sub-signal (#369): AI-authored (provenance-logged) AND vitals churn label HIGH. Both
  // inputs are deterministic per-file facts from the same report — never the risk-score rank.
  // Note vitals truncates `hotspots` to its top-N, so the churn label is only visible for files
  // hot enough to make that list — exactly the population this conjunction is about.
  const highChurn = new Set(report.hotspots.filter((h) => h.churn_label === "HIGH").map((h) => h.file_path));
  for (const file of aiProvenanceFiles(report)) {
    if (!highChurn.has(file)) continue;
    findings.push({
      id: `M3-AIPROV-${file}`,
      title: `AI-authored high-churn file: ${file}`,
      severity: "Watch",
      confidence: "Confirmed",
      category: "Maintainability",
      taxonomy: "AI provenance (AI-authored, high-churn)",
      location: file,
      status: "Open",
      evidence: `vitals provenance log attributes ${file} to AI tooling (Edit/Write events, 30-day window) and labels its churn HIGH.`,
      impact: "AI-generated code under heavy iteration is the highest-likelihood home for looks-right-isn't bugs — a different remediation priority than human-authored churn.",
      fix: "Human-review this file's recent history; add tests before the next AI-assisted change.",
      value: 2,
      ease: 3,
      safety: 5,
      mechanical: true,
      precisionTier: "high",
    });
  }

  findings.push(...trendFindings(report));

  return findings;
}

// #1075: vitals' day-over-day file_health trend (vitals_cli.py:254-290) against its own previous
// `.vitals` snapshot — the single most actionable M3 signal for a repeat/retainer engagement
// ("health moved from 6.2 to 5.8, driven by these files"), previously never read at all (VitalsReport
// declared 4 of vitals' 11 top-level keys). Absent/null on a first-ever run (no prior snapshot to
// diff against) — that is a legitimate "no history yet", not a gap, so it emits nothing rather than
// a disclosure row. One grouped finding (mirrors metricFinding's shape in src/lighthouse.ts) rather
// than one per file, so a codebase with many degrading files doesn't flood the findings list.
export function trendFindings(report: VitalsReport): Finding[] {
  const t = report.trends;
  if (!t || t.degrading.length === 0) return [];

  const n = t.degrading.length;
  const worst = [...t.degrading].sort((a, b) => a.delta - b.delta)[0]!;
  const currentOverall = Math.round((t.previous_overall + t.overall_delta) * 10) / 10;

  return [
    {
      id: "M3-TREND-00",
      title: `Codebase health trending down: ${n} file${n === 1 ? "" : "s"} degraded over the last ${t.days_since} day${t.days_since === 1 ? "" : "s"} (overall ${t.previous_overall.toFixed(1)} → ${currentOverall.toFixed(1)})`,
      severity: "Watch",
      confidence: "Confirmed",
      category: "Maintainability",
      taxonomy: "Codebase health trend (degrading)",
      location: worst.file_path,
      status: "Open",
      evidence:
        `vitals: over the last ${t.days_since} day(s), ${n} file(s) health score dropped by more than 0.5, worst-first: ` +
        t.degrading
          .slice(0, 8)
          .map((f) => `${f.file_path} (${f.previous}→${f.current})`)
          .join(", ") +
        (n > 8 ? `, +${n - 8} more` : "") +
        `. Overall codebase health moved ${t.overall_delta >= 0 ? "+" : ""}${t.overall_delta} since the prior snapshot.`,
      impact: "A file getting worse over time — not just currently bad — is a leading indicator, distinct from a static hotspot ranking: it names where the codebase is actively eroding.",
      fix: "Review the degrading files above before their health drops further; re-run M3 periodically (retainer/repeat engagements) to keep tracking the trend.",
      value: 2,
      ease: 3,
      safety: 5,
      mechanical: true,
      precisionTier: "high",
    },
  ];
}

// #515: the cross-module hotspot enrichment — the ONE mechanism applied to every module's findings
// at assembly time. A finding whose location sits on a top-K hotspot is tagged onHotspot=true and
// hotspotRank (1-based, hottest first), so the report can up-rank it across all modules — most
// valuably M6 (a reinvention on a churny, complex, sole-author file matters far more than the same
// on a stable leaf), and equally M4/M7/M9. Matching mirrors crossReferenceHotspots: substring
// containment of the hotspot path in the finding's location (covers "path:line", "path (pkg)", and
// "a <> b" formats). This ONLY tags — severity and the BFTB inputs are untouched, so graded counts
// are unchanged; ordering is the report's job. topK is the worst-first list from topKFiles.
export function enrichFindingsWithHotspots(findings: Finding[], topK: string[]): Finding[] {
  return findings.map((f) => {
    const idx = topK.findIndex((hotspot) => f.location.includes(hotspot));
    return idx < 0 ? f : { ...f, onHotspot: true, hotspotRank: idx + 1 };
  });
}

interface HotspotCrossRef {
  findings: Finding[];
  hotspotFindingIds: string[];
}

// Mechanical cross-reference (#363): a finding that also sits on a top-K churn×complexity
// hotspot is top remediation priority — the same rule summarizeMutationReport applies to M8's
// surviving mutants, generalized to any module's Finding[] (M1/M7/M9). Matching is substring
// containment of the hotspot file path in the finding's location, which covers "path:line",
// "path (pkg)", and "a <> b" location formats. Annotates via `note` and moves flagged findings
// to the front; severity and the BFTB inputs are never touched, so graded counts are unchanged.
//
// #1075: when the report isUnranked (vitals' complexity-only mode — every risk_score is 0.0), the
// "top-K" is filesystem-walk order, not a ranking. Stamping "top remediation priority" onto another
// module's finding from that order would MANUFACTURE a signal, not lose one — the one bug in this
// class that invents information rather than dropping it. No-op instead: every finding passes
// through untouched and hotspotFindingIds is empty.
export function crossReferenceHotspots(findings: Finding[], report: VitalsReport, k = 10): HotspotCrossRef {
  if (isUnranked(report)) return { findings, hotspotFindingIds: [] };
  const topK = topKFiles(report, k);
  const annotated = findings.map((f) => {
    const file = topK.find((hotspot) => f.location.includes(hotspot));
    if (!file) return { finding: f, hotspot: false };
    const tag = `Top remediation priority: ${file} is a top-${k} churn×complexity hotspot (M3 cross-reference).`;
    return { finding: { ...f, note: f.note ? `${f.note} ${tag}` : tag }, hotspot: true };
  });
  const flagged = annotated.filter((a) => a.hotspot);
  return {
    findings: [...flagged, ...annotated.filter((a) => !a.hotspot)].map((a) => a.finding),
    hotspotFindingIds: flagged.map((a) => a.finding.id),
  };
}
