// Scores a dry-run's actual findings against a target's known ground truth (issue #34).
// Pure mapping/scoring logic — src/cli/dry-run.ts supplies the ground-truth list (transcribed
// from targets/calibration/GROUND-TRUTH.md) and the Finding[] a real scan run produced.
//
// Every bug's `liveRunRequired` and `moduleRan` fields are set by the CALLER from what actually
// executed in that pass — this module never guesses whether something ran. A bug whose detecting
// module didn't run is scored "requires-live-run", never silently "missed".

import type { PrecisionTier } from "./findings.js";

type CoverageStatus = "caught" | "missed" | "requires-live-run";

export interface GroundTruthBug {
  id: string;
  severity: string;
  location: string;
  expectedModule: string;
  // False when the module that would catch this bug did not execute in this pass (e.g. needs
  // a live DB, a missing skill package, or a binary unavailable in the sandbox).
  moduleRan: boolean;
  // True when this finding is a genuine catch of this bug — supplied by the caller per-bug since
  // the match signal differs by module (mechanical findings carry file:line locations; classifier
  // verdicts carry a function/table name). Receives the WHOLE finding, so a predicate can require
  // both the right file AND the right rule: an earlier taxonomy-OR-location signature could only
  // ever see one field at a time, which scored COUNTER-RACE "caught" off /race/i matching the
  // dependency `braces@2.3.2` in a lockfile (#246).
  matches: (finding: ScorableFinding) => boolean;
  // Location-INDEPENDENT class predicate: true for any finding whose taxonomy targets this bug's
  // CLASS, wherever it fires. `matches` is anchored to the planted address, so it can't catch a
  // rule that proves the bug at a DIFFERENT address (an absence-shaped bug proved at its create
  // site, not its absence site) — the drift the location guard structurally misses (#335). Must be
  // precise (an exact taxonomy/rule-id), never a loose word regex, or it false-matches a
  // same-word rule for an unrelated class. The drift guard uses this to falsify a "no mechanical
  // rule reaches this class" claim against the real findings.
  classMatch?: (finding: ScorableFinding) => boolean;
}

interface ScoredBug {
  id: string;
  severity: string;
  location: string;
  expectedModule: string;
  status: CoverageStatus;
  // The matched finding's precision tier (caught only). "high" = the mechanical tier ASSERTED a
  // verdict; "review" (or any non-high) = it surfaced a shape for a HUMAN to adjudicate. Kept
  // distinct so "caught" never launders a review-tier surfacing into an autonomous detection — two
  // of the calibration Criticals are review-tier catches a person must still rule on (#342).
  tier?: PrecisionTier;
  note: string;
}

export interface ScorableFinding {
  taxonomy: string;
  location: string;
  precisionTier?: PrecisionTier;
}

// A catch is "asserted" only when the matching finding is high-precision. Anything else caught
// (review tier, or an untiered finding whose trust we can't vouch for) is surfaced-for-review — the
// conservative direction: never claim the mechanical tier decided unless it actually did.
function isAsserted(bug: ScoredBug): boolean {
  return bug.status === "caught" && bug.tier === "high";
}

export function scoreCoverage(bugs: GroundTruthBug[], findings: ScorableFinding[]): ScoredBug[] {
  return bugs.map((bug) => {
    const base = { id: bug.id, severity: bug.severity, location: bug.location, expectedModule: bug.expectedModule };
    if (!bug.moduleRan) {
      return {
        ...base,
        status: "requires-live-run",
        note: `${bug.expectedModule} did not execute in this pass — no caught/missed verdict possible.`,
      };
    }
    const hit = findings.find((f) => bug.matches(f));
    if (hit) {
      const asserted = hit.precisionTier === "high";
      return {
        ...base,
        status: "caught",
        tier: hit.precisionTier,
        note: asserted
          ? `Asserted by high-precision rule "${hit.taxonomy}" at ${hit.location}.`
          : `Surfaced for review by "${hit.taxonomy}" at ${hit.location} — ${hit.precisionTier ?? "untiered"} tier, a human must still adjudicate this verdict.`,
      };
    }
    return {
      ...base,
      status: "missed",
      note: `${bug.expectedModule} ran but produced no finding matching this bug.`,
    };
  });
}

// Tier-aware, deliberately NOT keyed on a blended "caught": a review-tier catch is a shape surfaced
// for a human, not a verdict the mechanical tier asserted, so the two are separate counts (#342).
export interface CoverageSummary {
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
