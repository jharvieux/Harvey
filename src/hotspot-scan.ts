// M3 (hotspot analysis) — shapes the `vitals` plugin's churn×complexity / coupling / knowledge-
// risk output into (a) a ranked hotspot table and (b) the deterministic boolean sub-signals
// (truck-factor-1, co-change coupling) as Finding[] for the shared calibration harness.
//
// STATUS: schema VERIFIED against a live `vitals 0.2.0 report --json <path>` run (issue #94).
// VitalsReport/VitalsHotspotRow below match the real top-level shape: `hotspots` (per-file rows,
// sorted by `risk_score`), a separate top-level `coupling` array (not nested per-row), and a
// separate top-level `knowledge_risk` array (truck-factor lives there, not on hotspot rows).
// `src/__fixtures__/vitals-report.json` is a synthetic report built to this real shape (paths and
// values are synthetic; the field names and nesting are not).
//
// Per the locked product decision (docs/design/spec-72-crossmodule-corpus.md preamble #2) and its
// M3 section: a hotspot RANK is an ordering over a continuous score, not a true/false finding —
// there is no M3 precision number, free-tier M3 output is a descriptive map only, never an
// asserted finding. What IS gateable the same way every other module's positives/negatives are:
// the deterministic boolean sub-signals (truck-factor-1, a coupling edge), which toFactFindings
// below emits as Finding[] for buildCoverageMatrix. The rank itself is gated separately as a
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

export interface VitalsReport {
  hotspots: VitalsHotspotRow[];
  coupling: VitalsCouplingEdgeRow[];
  knowledge_risk: VitalsKnowledgeRiskRow[];
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

  return findings;
}
