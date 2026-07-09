// M3 (hotspot analysis) — shapes the `vitals` plugin's churn×complexity / coupling / knowledge-
// risk output into (a) a ranked hotspot table and (b) the deterministic boolean sub-signals
// (truck-factor-1, co-change coupling) as Finding[] for the shared calibration harness.
//
// STATUS: design + fixture, NOT live-verified. Before writing this file, `vitals` / `vitals_cli.py`
// were confirmed not runnable in this environment (no binary, no importable `vitals` python
// module), and `vitals --json`'s schema is not documented anywhere in this repo — only its
// *concepts* are (docs/audit-modules.md M3): churn×complexity ROI ranking, co-change coupling,
// truck-factor-1/sole-author, AI-provenance. The one piece of real field-shaped evidence is a
// prior engagement's actual output, captured as report-template/findings.atc.json's F-13:
// "vitals: health 2.4, 41 changes/90d, co-changes with 29 files" for app/api/chat/route.ts — a
// 6.3/10 overall-health run with 50 truck-factor-1 files. VitalsHotspotRow below is an ASSUMED
// schema built from that citation's field concepts (health, churn count over a 90-day window,
// complexity, an ROI-style rank score, co-change file list, truck-factor flag) — plausible field
// names, UNVERIFIED shape and nesting. Do not treat it as ground truth; it exists so the mapping
// logic can be written and regression-tested now, and swapped for the real schema in one place
// once a live `vitals_cli.py report --json <path>` capture is available (tracked: issue #94).
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

export interface VitalsHotspotRow {
  file: string;
  health: number; // 0–10, lower = worse (F-13: "health 2.4")
  churn: number; // commit count in vitals' scan window (F-13: "41 changes/90d")
  complexity: number; // cyclomatic complexity
  roi: number; // vitals' own churn×complexity-weighted rank score (core > test, central > leaf per docs/audit-modules.md M3) — ASSUMED field name; the real sort key is unverified
  coChanges?: string[]; // files this one is co-committed with (F-13: "co-changes with 29 files")
  truckFactor1?: boolean; // sole-author flag
  soleAuthor?: string;
}

export interface VitalsReport {
  hotspots: VitalsHotspotRow[];
}

// Worst-first by vitals' ROI score. Rank is an ordering, never scored as a percentage — callers
// use this (or topKFiles) for a top-K membership check, not a pass/fail per row.
export function rankHotspots(report: VitalsReport): VitalsHotspotRow[] {
  return [...report.hotspots].sort((a, b) => b.roi - a.roi);
}

export function topKFiles(report: VitalsReport, k: number): string[] {
  return rankHotspots(report)
    .slice(0, k)
    .map((r) => r.file);
}

export function truckFactorOneFiles(report: VitalsReport): string[] {
  return report.hotspots.filter((r) => r.truckFactor1).map((r) => r.file);
}

interface CouplingEdge {
  a: string;
  b: string;
}

// Derives coupling edges from each row's coChanges list, deduped (a<>b and b<>a collapse to one).
function edgeKey(a: string, b: string): string {
  return [a, b].sort().join("::");
}

export function couplingEdges(report: VitalsReport): CouplingEdge[] {
  const seen = new Set<string>();
  const edges: CouplingEdge[] = [];
  for (const row of report.hotspots) {
    for (const other of row.coChanges ?? []) {
      const key = edgeKey(row.file, other);
      if (seen.has(key)) continue;
      seen.add(key);
      edges.push({ a: row.file, b: other });
    }
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
