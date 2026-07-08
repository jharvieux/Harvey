// Scores a dry-run's actual findings against a target's known ground truth (issue #34).
// Pure mapping/scoring logic — src/cli/dry-run.ts supplies the ground-truth list (transcribed
// from targets/calibration/GROUND-TRUTH.md) and the Finding[] a real scan run produced.
//
// Every bug's `liveRunRequired` and `moduleRan` fields are set by the CALLER from what actually
// executed in that pass — this module never guesses whether something ran. A bug whose detecting
// module didn't run is scored "requires-live-run", never silently "missed".

type CoverageStatus = "caught" | "missed" | "requires-live-run";

export interface GroundTruthBug {
  id: string;
  severity: string;
  location: string;
  expectedModule: string;
  // False when the module that would catch this bug did not execute in this pass (e.g. needs
  // a live DB, a missing skill package, or a binary unavailable in the sandbox).
  moduleRan: boolean;
  // A finding is a "catch" if its taxonomy or location references this bug's id/location —
  // supplied by the caller per-bug since the match signal differs by module (mechanical
  // findings carry file:line locations; classifier verdicts carry a function/table name).
  matches: (findingTaxonomyOrLocation: string) => boolean;
}

interface ScoredBug {
  id: string;
  severity: string;
  location: string;
  expectedModule: string;
  status: CoverageStatus;
  note: string;
}

export interface ScorableFinding {
  taxonomy: string;
  location: string;
}

export function scoreCoverage(bugs: GroundTruthBug[], findings: ScorableFinding[]): ScoredBug[] {
  return bugs.map((bug) => {
    if (!bug.moduleRan) {
      return {
        id: bug.id,
        severity: bug.severity,
        location: bug.location,
        expectedModule: bug.expectedModule,
        status: "requires-live-run",
        note: `${bug.expectedModule} did not execute in this pass — no caught/missed verdict possible.`,
      };
    }
    const hit = findings.find((f) => bug.matches(f.taxonomy) || bug.matches(f.location));
    if (hit) {
      return {
        id: bug.id,
        severity: bug.severity,
        location: bug.location,
        expectedModule: bug.expectedModule,
        status: "caught",
        note: `Matched by finding "${hit.taxonomy}" at ${hit.location}.`,
      };
    }
    return {
      id: bug.id,
      severity: bug.severity,
      location: bug.location,
      expectedModule: bug.expectedModule,
      status: "missed",
      note: `${bug.expectedModule} ran but produced no finding matching this bug.`,
    };
  });
}

export function summarizeCoverage(scored: ScoredBug[]): Record<CoverageStatus, number> {
  return {
    caught: scored.filter((s) => s.status === "caught").length,
    missed: scored.filter((s) => s.status === "missed").length,
    "requires-live-run": scored.filter((s) => s.status === "requires-live-run").length,
  };
}
