// Scores a dry-run's actual findings against a target's known ground truth (issue #34).
// Pure mapping/scoring logic — src/cli/dry-run.ts supplies the ground-truth list (transcribed
// from targets/calibration/GROUND-TRUTH.md) and the Finding[] a real scan run produced.
//
// Every bug's `liveRunRequired` and `moduleRan` fields are set by the CALLER from what actually
// executed in that pass — this module never guesses whether something ran. A bug whose detecting
// module didn't run is scored "requires-live-run", never silently "missed".

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
