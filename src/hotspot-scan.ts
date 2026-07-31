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
// modelling 9 of 11 — mode/hotspots/coupling/knowledge_risk/provenance/trends/overall_health, plus
// file_health/files_analyzed since #1290 (they are the DENOMINATORS of vitals' own caps; see
// vitalsScope). repo_info/scope are not read. `hotspots` is per-file rows sorted by
// `risk_score`; `coupling`/`knowledge_risk` are separate top-level arrays, not nested per hotspot row.
// The `provenance` shape (#369) is verified against vitals 0.2.0's own source
// (scripts/vitals_cli.py provenance_info + scripts/db.py get_ai_file_stats/get_provenance_summary):
// `{ has_data: false }` when no .vitals provenance DB exists, or has_data: true plus `summary`
// and `ai_files` (30-day window, ordered by total_events desc) when it does.
// `src/__fixtures__/vitals-report.json` is a REAL `vitals 0.2.0 report --json` capture (#1146),
// produced by src/__fixtures__/vitals-recapture/seed.py from a purpose-seeded git repo + `.vitals`
// provenance DB — not hand-written; every value comes from the tool.
//
// Per the locked product decision (docs/design/spec-72-crossmodule-corpus.md preamble #2) and its
// M3 section: a hotspot RANK is an ordering over a continuous score, not a true/false finding —
// there is no M3 precision number, free-tier M3 output is a descriptive map only, never an
// asserted finding. What IS gateable the same way every other module's positives/negatives are:
// the deterministic boolean sub-signals (truck-factor-1, a coupling edge, AI-authored+high-churn),
// which toFactFindings below emits as Finding[] for buildCoverageMatrix. The rank itself is gated separately as a
// top-K *membership* check (rankHotspots / topKFiles) — see hotspot-scan.test.ts — never scored
// as a percentage.

import { buildPassArtifact, type PassArtifact } from "./audit-pass-artifact.js";
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
  // #1290: vitals' per-file health map (vitals_cli.py:180-188) — ONE ENTRY PER `code_files` ENTRY,
  // never truncated. This is the population `hotspots` is the top-N slice of and the population the
  // truck-factor cap slices, so its size is the denominator both caps need. Optional: absent from a
  // pre-#1290 hand-built report, in which case the denominator is disclosed as underivable, never
  // guessed.
  file_health?: Record<string, number>;
  // #1290: vitals' count of every TRACKED source file it considered (vitals_cli.py:310 —
  // len(source_files)). A wider set than file_health: it includes files that never churned or carry
  // no structural complexity. It is the truck-factor denominator ONLY in vitals' fallback branch
  // (`code_files[:50] if code_files else source_files[:50]`, vitals_cli.py:132).
  files_analyzed?: number;
}

// #1290 — vitals truncates THREE lists before Harvey ever sees them, and #1075 disclosed two of them
// with no denominator ("capped at the first 50 source files") while both denominators were derivable.
// The caps, from vitals 0.2.0's own emitter:
//   hotspots  = hotspots[:top_n]                       (vitals_cli.py:233; top_n default 10, and
//                                                       Harvey never passes --top, so always 10)
//   coupling  = coupling_data[:5]                      (vitals_cli.py:305)
//   knowledge = (code_files or source_files)[:50]      (vitals_cli.py:132)
//
// The population for the first and third is `code_files`, which the report DOES emit in full as the
// `file_health` map — NOT `files_analyzed`, which is len(source_files), i.e. every tracked source
// file. MEASURED 2026-07-28 with `python3 ~/.claude/plugins/cache/vitals/vitals/0.2.0/scripts/
// vitals_cli.py report --json .` against this repo: file_health 314, files_analyzed 1792,
// hotspots 10. So "the first 50 of 1792 source files" would have been wrong by 5.7× in the other
// direction — the fixture masks this because it happens to have file_health 7 == files_analyzed 7.
// Only the coupling total is genuinely absent from the payload; the CLI derives it by calling the
// plugin's own function (see src/cli/hotspot-scan.ts::deriveCouplingTotal).
const VITALS_HOTSPOT_CAP = 10;
const VITALS_COUPLING_CAP = 5;
const VITALS_KNOWLEDGE_CAP = 50;

interface VitalsScope {
  /** len(code_files) — files vitals actually scored. undefined when the report omits file_health. */
  scored?: number;
  /** len(source_files) — every tracked source file. undefined when the report omits files_analyzed. */
  tracked?: number;
  /** The population vitals' 50-file knowledge slice was taken from, mirroring its own branch. */
  knowledgePopulation?: number;
}

export function vitalsScope(report: VitalsReport): VitalsScope {
  const scored = report.file_health ? Object.keys(report.file_health).length : undefined;
  const tracked = report.files_analyzed;
  // Mirrors `code_files[:50] if code_files else source_files[:50]` exactly: an EMPTY code_files
  // (nothing cleared the churn+complexity gate) falls back to the tracked set, which is the case
  // #1112 measured on a fully backdated repo.
  const knowledgePopulation = scored === undefined ? undefined : scored > 0 ? scored : tracked;
  return { scored, tracked, knowledgePopulation };
}

// One "N of M" line per cap. A cap that did not BIND says so plainly rather than implying a cut —
// "showing all 3 co-change pairs" is a different fact from "showing 5 of 10" and a client reads it
// differently. A denominator left underivable is named as such WITH the reason; it is never
// substituted with the nearest available number.
function scopeLine(label: string, shown: number, cap: number, total: number | undefined, unit: [one: string, many: string], missing: string): string {
  const n = (count: number) => `${count} ${count === 1 ? unit[0] : unit[1]}`;
  if (total === undefined) {
    return shown < cap
      ? `${label}: ${n(shown)} — below vitals' cap of ${cap}, so this is the full set.`
      : `${label}: ${n(shown)}, which is exactly vitals' cap of ${cap} — the true total is NOT derivable here (${missing}), so treat ${shown} as a floor, not a census.`;
  }
  return total > shown
    ? `${label}: showing ${shown} of ${n(total)} — vitals caps this list at ${cap}.`
    : `${label}: all ${n(total)} (vitals' cap of ${cap} did not bind).`;
}

// #1290: the client-facing scope row. Emitted as a Finding, not only a console NOTE, because
// "accounted for is not delivered" — a stdout line reaches nobody who reads the report, and "50
// source files analysed" vs "50 of 314" is the difference between a clean bill of health and a
// disclosed 6× sampling. Info/no precisionTier, matching M3-KNOWLEDGE-00: a scope row is never a
// free-count hit against a calibration negative.
export function capScopeFinding(report: VitalsReport, couplingTotal: number | undefined, couplingUnavailable: string): Finding {
  const { scored, tracked, knowledgePopulation } = vitalsScope(report);
  const noFileHealth = "the report omits vitals' file_health map, so the scored-file population is unknown";
  const lines = [
    scopeLine("Hotspot table", report.hotspots.length, VITALS_HOTSPOT_CAP, scored, ["file vitals scored", "files vitals scored"], noFileHealth),
    scopeLine("Co-change coupling", report.coupling.length, VITALS_COUPLING_CAP, couplingTotal, ["coupled file pair", "coupled file pairs"], couplingUnavailable),
    scopeLine(
      "Truck-factor / knowledge risk",
      Math.min(VITALS_KNOWLEDGE_CAP, knowledgePopulation ?? VITALS_KNOWLEDGE_CAP),
      VITALS_KNOWLEDGE_CAP,
      knowledgePopulation,
      scored !== undefined && scored > 0
        ? ["churning source file with structural complexity", "churning source files with structural complexity"]
        : ["tracked source file", "tracked source files"],
      noFileHealth,
    ),
  ];
  const undisclosed = [scored === undefined, couplingTotal === undefined, knowledgePopulation === undefined].filter(Boolean).length;
  return {
    id: "M3-SCOPE-00",
    title: `M3 inputs are capped by vitals — ${undisclosed === 0 ? "all three caps stated with their true totals" : `${undisclosed} of 3 totals could not be derived`}`,
    severity: "Info",
    confidence: undisclosed === 0 ? "Confirmed" : "N/A",
    category: "Maintainability",
    taxonomy: "M3 — Input scope",
    location: "(repository-wide)",
    status: "Open",
    evidence: `vitals truncates its three list outputs before Harvey ever sees them (vitals_cli.py:233 hotspots[:${VITALS_HOTSPOT_CAP}], :305 coupling[:${VITALS_COUPLING_CAP}], :132 knowledge[:${VITALS_KNOWLEDGE_CAP}]). Measured scope for this run:\n  - ${lines.join("\n  - ")}${tracked === undefined ? "" : `\n  - Tracked source files vitals considered overall: ${tracked}.`}`,
    impact:
      undisclosed === 0
        ? "None to the findings themselves — recorded so a capped list is never read as a full census. Every M3 sub-signal above is drawn from the slices named here, not from the whole repository."
        : "A cap whose denominator is unknown cannot be distinguished from no cap at all: the M3 sub-signals may be drawn from a small sample of this repository and this run cannot say how small.",
    fix:
      undisclosed === 0
        ? "No action — this row is scope disclosure, not a defect."
        : "Re-run M3 live against the target (drop --report) with the vitals plugin installed, so the denominators can be derived from the tool rather than estimated.",
    value: 1,
    ease: 5,
    safety: 5,
    mechanical: true,
  };
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

  findings.push(...knowledgeRiskNotAssessed(report));
  findings.push(...trendFindings(report));

  return findings;
}

// #1112 — an empty truck-factor list has TWO causes and they read identically: the authorship
// analysis ran and found no sole-authored file (a measured clean result), or it had nothing to
// analyse. The second is what a decayed fixture looks like, and the standing instruction on a
// conservation `GONE M3` row is "that is a scanner or pipeline bug, never something to rebaseline"
// — so a reader hitting the second case with that instruction in front of them either burns a
// session or weakens the assertion. This row makes the two distinguishable in one read.
//
// The decay horizon is TWO YEARS, not the 90-day churn window #1112 was filed on. MEASURED
// 2026-07-26 against a throwaway repo whose entire history was backdated: at 200 days (churn window
// fully exhausted, hotspot table 0 rows) both truck-factor-1 rows STILL fire; at 800 days they are
// gone. Two things in vitals 0.2.0 (commit 9c580c8) explain it — `vitals_cli.py:131` falls back to
// `source_files[:50]` when no file cleared the churn gate, so knowledge analysis is never starved by
// churn alone, and `git_analysis.py:260` scopes the authorship log to `--since=2.years.ago`, which
// is the window that actually empties it.
export function knowledgeRiskNotAssessed(report: VitalsReport): Finding[] {
  if (truckFactorOneFiles(report).length > 0) return [];
  // #1448: `knowledge_risk` does not answer this question — vitals_cli.py:238-245 admits only
  // truck_factor<=1 rows, so once the early return above has passed the array is empty on EVERY real
  // capture, clean or not. Its length was never the signal.
  //
  // Nor is any file COUNT that survives an exhausted churn gate. `files_analyzed` is
  // len(source_files), a `git ls-files` census (vitals_cli.py:118-119) wholly independent of the
  // authorship window — a repo whose entire history predates that window still reports thousands of
  // tracked files with zero authorship read, which is exactly the 800-day state MEASURED above. So
  // the split keys off whether authorship analysis DEMONSTRABLY had inputs, which needs BOTH:
  //   (1) vitals had git at all. `get_knowledge_distribution` is only called inside the has_git
  //       branch (vitals_cli.py:99/133); complexity-only mode never invokes it yet still populates
  //       `file_health` (vitals_cli.py:136-139), so a population count alone would read a run that
  //       computed no authorship whatsoever as "measured clean".
  //   (2) the knowledge population was the SCORED set — `code_files`, i.e. file_health's keys — every
  //       member of which cleared a >=2-changes-in-90-days churn gate (vitals_cli.py:106-115) and so
  //       is guaranteed a commit inside the two-year authorship log. When `code_files` is empty
  //       vitals falls back to `source_files[:50]` (vitals_cli.py:132), which carries no recency
  //       guarantee at all, and nothing in the report distinguishes a fallback that read authorship
  //       from one that read none. That case is DISCLOSED, never claimed.
  const scored = vitalsScope(report).scored ?? 0;
  const measured = report.mode === "full" && scored > 0;
  // vitals slices the knowledge population to the first 50 (vitals_cli.py:132), so the row may never
  // name more files than were actually read.
  const analysed = Math.min(VITALS_KNOWLEDGE_CAP, scored);
  return [
    {
      id: "M3-KNOWLEDGE-00",
      title: measured
        ? `No truck-factor-1 file — authorship analysed across ${analysed} file${analysed === 1 ? "" : "s"}`
        : "Knowledge risk (truck-factor) NOT assessed — no authorship history to analyse",
      severity: "Info",
      confidence: measured ? "Confirmed" : "N/A",
      category: "Maintainability",
      taxonomy: "M3 — Knowledge risk coverage",
      location: "(repository-wide)",
      status: "Open",
      evidence: measured
        ? `vitals read authorship for ${analysed} of the ${scored} file(s) it scored${scored > VITALS_KNOWLEDGE_CAP ? ` — its knowledge population is the first ${VITALS_KNOWLEDGE_CAP} scored files (vitals_cli.py:132)` : ""} and returned no truck-factor-1 (sole-author) row among them, so no truck-factor-1 finding was emitted. Every one of those files changed at least twice in the trailing 90 days, so each had commits inside vitals' two-year authorship log. The signal ran; this is a measured result, not a gap.`
        : "This run cannot confirm the authorship analysis had anything to read, so the empty truck-factor list is NOT a measured clean result. Causes, in the order worth checking: (a) no file cleared vitals' 90-day churn+complexity gate, so the knowledge population fell back to tracked source files (vitals_cli.py:132) whose authorship log is scoped to the trailing TWO YEARS (`--since=2.years.ago`, git_analysis.py:260) — that window, NOT the 90-day churn window, is what actually empties this list, and the report does not say whether it returned anything; (b) the target has no git history, so vitals ran complexity-only and computed no authorship at all (vitals_cli.py:134-139); (c) the `vitals` plugin is absent and this is the reduced M3 tier, which computes no knowledge-risk signal at all (#807); (d) the capture predates vitals' file_health map, so the scored population is not derivable from it.",
      impact: measured
        ? "None — recorded so an empty truck-factor list is never read as an unrun signal."
        : "Truck-factor is unassessed for this target: no file is named as a single point of knowledge failure, and that silence is NOT evidence the knowledge is well distributed. A conservation run reading `GONE M3` off this state is looking at an input gap, not a detector regression.",
      fix: measured
        ? "No action."
        : "Confirm which cause applies before treating an absent truck-factor row as a defect: `git -C <target> log --since=2.years.ago --oneline | head` distinguishes (a) from (b), the M3 tier line in the coverage ledger distinguishes (c), and a capture with no `file_health` key is (d).",
      value: 1,
      ease: 5,
      safety: 5,
      mechanical: true,
    },
  ];
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

// #1364: the M3 pass artifact src/cli/hotspot-scan.ts writes with --artifacts-dir — the write side
// of the #416 read (findFreshPass reads M3.pass.json). A pure function so the round trip is tested
// without spawning the CLI (hotspot-scan.test.ts): the CLI just calls this with what it already
// computed, then writePassArtifact. `tier` records which of the three CLI tiers (full vitals,
// reduced #807, unranked #1075) produced the findings, since the pass artifact carries no field for
// it and a bare finding count can't distinguish "0 hotspots, full vitals, clean repo" from "0
// hotspots, vitals unavailable".
export function buildM3PassArtifact(params: {
  targetDir: string;
  findings: Finding[];
  hotspots: string[];
  rankedCount: number;
  tier: "full" | "reduced" | "unranked";
  generatedAt: string;
}): PassArtifact {
  const tierLabel = params.tier === "reduced" ? "reduced tier (vitals unavailable)" : params.tier === "unranked" ? "unranked (complexity-only)" : "full vitals";
  return buildPassArtifact({
    module: "M3",
    target: params.targetDir,
    pass: "vitals",
    generatedAt: params.generatedAt,
    summary: `${params.rankedCount} file(s) ranked, ${tierLabel}, ${params.findings.length} finding(s)`,
    findings: params.findings,
    hotspots: params.hotspots,
  });
}
