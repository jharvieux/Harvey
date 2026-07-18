// M3 (hotspot analysis) — shapes the `vitals` plugin's churn×complexity / coupling / knowledge-
// risk / AI-provenance output into (a) a ranked hotspot table and (b) the deterministic boolean
// sub-signals (truck-factor-1, co-change coupling, AI-authored+high-churn) as Finding[] for the
// shared calibration harness, plus (c) the mechanical cross-reference of other modules' findings
// against the top-K hotspots (#363).
//
// STATUS: schema VERIFIED against a live `vitals 0.2.0 report --json <path>` run (issue #94).
// VitalsReport/VitalsHotspotRow below match the real top-level shape: `hotspots` (per-file rows,
// sorted by `risk_score`), a separate top-level `coupling` array (not nested per-row), and a
// separate top-level `knowledge_risk` array (truck-factor lives there, not on hotspot rows).
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

export interface VitalsReport {
  hotspots: VitalsHotspotRow[];
  coupling: VitalsCouplingEdgeRow[];
  knowledge_risk: VitalsKnowledgeRiskRow[];
  // Optional so a pre-0.2.0 capture without the key still parses; 0.2.0 always includes it.
  provenance?: VitalsProvenance;
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

  return findings;
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
export function crossReferenceHotspots(findings: Finding[], report: VitalsReport, k = 10): HotspotCrossRef {
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
