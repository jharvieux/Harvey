// Classifies a dry-run's planted-bug ground truth into a coverage tally (issue #34). DETECTION is
// NOT decided here: the caller resolves each bug's verdict from the ONE gated answer key — the
// calibration corpus for a static bug, a committed M2 pen-test record for a dynamic one — and
// hands it in as a BugDetection (#425). This module only classifies (caught / missed /
// requires-live-run) and counts. It holds no matcher of its own, so there is no second answer key
// here that could drift from the corpus.
//
// A bug whose detecting tier did not run this pass arrives with detection === null and is scored
// "requires-live-run", never silently "missed" — this module never guesses that something ran.

import type { PrecisionTier } from "./findings.js";
import type { ProbeScore } from "./pentest/scorecard.js";

type CoverageStatus = "caught" | "missed" | "requires-live-run";

// Resolve a dynamic (M2) bug's coverage status from a committed pen-test scorecard (#347), so the
// dry-run scorecard's `requires-live-run` deferral for the M2 replays (SHADOW-API-VERSION,
// NO-RATE-LIMIT, CACHE-CROSS-USER, ANON-PRIVILEGED-RPC) can point at a real recorded outcome
// instead of a memory. Maps the probe's own status: `caught` proved the bug live; `cleared` means
// the probe ran and the bug was absent (a miss on a target where it was planted);
// `not-applicable`/`not-run` recorded no live verdict, so the row stays requires-live-run.
export function statusFromDynamicProbe(status: ProbeScore["status"]): CoverageStatus {
  switch (status) {
    case "caught":
      return "caught";
    case "cleared":
      return "missed";
    default:
      return "requires-live-run";
  }
}

// A bug's DETECTION verdict, resolved by the caller from the single gated answer key. `caught` is
// the corpus entry's (or M2 replay's) verdict on the evidence; `tier` is the matched finding's
// precision tier (caught only). Distinguishing the tier is load-bearing: "high" means the tier
// ASSERTED a verdict, anything else means it SURFACED a shape a human must still adjudicate, so a
// review-tier catch never launders into an autonomous detection (#342).
export interface BugDetection {
  caught: boolean;
  tier?: PrecisionTier;
  note: string;
}

export interface GroundTruthBug {
  id: string;
  severity: string;
  location: string;
  expectedModule: string;
  // Resolved by the CALLER from the ONE gated answer key (the calibration corpus for a static bug;
  // a committed M2 replay for a dynamic one). null = the detecting tier did not run this pass → the
  // bug is scored requires-live-run, never missed. There is deliberately no matcher on this type:
  // "does a rule catch this?" is answered once, in the corpus, so it cannot drift into a second
  // hand-maintained key here (#425 — replaces the former per-bug `matches`/`classMatch`).
  detection: BugDetection | null;
}

interface ScoredBug {
  id: string;
  severity: string;
  location: string;
  expectedModule: string;
  status: CoverageStatus;
  tier?: PrecisionTier;
  note: string;
}

// A catch is "asserted" only when the matched finding is high-precision. Anything else caught
// (review tier, or an untiered finding whose trust we can't vouch for) is surfaced-for-review — the
// conservative direction: never claim the mechanical tier decided unless it actually did.
function isAsserted(bug: ScoredBug): boolean {
  return bug.status === "caught" && bug.tier === "high";
}

export function scoreCoverage(bugs: GroundTruthBug[]): ScoredBug[] {
  return bugs.map((bug) => {
    const base = { id: bug.id, severity: bug.severity, location: bug.location, expectedModule: bug.expectedModule };
    if (bug.detection === null) {
      return {
        ...base,
        status: "requires-live-run",
        note: `${bug.expectedModule} did not execute in this pass — no caught/missed verdict possible.`,
      };
    }
    if (bug.detection.caught) {
      return { ...base, status: "caught", tier: bug.detection.tier, note: bug.detection.note };
    }
    return { ...base, status: "missed", note: bug.detection.note };
  });
}

// Tier-aware, deliberately NOT keyed on a blended "caught": a review-tier catch is a shape surfaced
// for a human, not a verdict the mechanical tier asserted, so the two are separate counts (#342).
interface CoverageSummary {
  asserted: number;
  "surfaced-for-review": number;
  missed: number;
  "requires-live-run": number;
}

export function summarizeCoverage(scored: ScoredBug[]): CoverageSummary {
  return {
    asserted: scored.filter(isAsserted).length,
    "surfaced-for-review": scored.filter((s) => s.status === "caught" && !isAsserted(s)).length,
    missed: scored.filter((s) => s.status === "missed").length,
    "requires-live-run": scored.filter((s) => s.status === "requires-live-run").length,
  };
}
