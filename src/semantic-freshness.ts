// The staleness alarm for the M1 SEMANTIC recall gate (#1270, remainder of #870).
//
// `validate-semantic` SCORES a recorded semantic pass, and its input is an interactive LLM pass
// (`/vuln-scan` → `/triage`) with no CLI a job could attach to. Whether a cadence could ever produce
// that input is a RECORDED claim with a falsifier `--revalidate` re-tests, not one restated here —
// see the REASON block in src/scored-gates.ts. So the repo's answer for every other gate ("give it a
// cadence", #1288) does not reach this one, and what a schedule CAN answer is the question one level
// up: **is the recorded semantic number still inside the window that makes it evidence about the
// present?**
//
// `MAX_PASS_AGE_MS` already answers that for every other out-of-orchestrator pass: a pass artifact
// older than 30 days describes a prior state of the target, so it is not evidence that the module
// ran for THIS audit (src/audit-pass-artifact.ts). The semantic corpus's own `recordedOn` dates are claims
// of exactly the same kind, and until this module nothing re-read them — so a semantic tally could
// age out of its own freshness window and the only thing that would change is that a hand-run of
// `validate-semantic` would start printing NOT SCORED, in a session nobody was scheduled to have.
//
// Two sources per target, and WHICH ONE WAS USED IS PART OF THE OUTPUT. A recorded pass artifact is
// direct evidence the pass ran; a corpus `recordedOn` is only the date a measurement doc was
// written. Reporting the second as though it were the first is the "unstated limitation reads as a
// clean bill of health" shape, so the row names its source and the summary counts the fallbacks.

import { MAX_PASS_AGE_MS } from "./audit-pass-artifact.js";
import { SEMANTIC_CORPUS } from "./scan/semantic-corpus.js";

const DAY_MS = 24 * 60 * 60 * 1000;

interface SemanticFreshnessRow {
  slug: string;
  repo: string;
  /** `pass-artifact` = a recorded M1.pass.json; `corpus-record` = only the measurement doc's date. */
  source: "pass-artifact" | "corpus-record";
  /** ISO date the evidence carries. */
  recordedOn: string;
  ageDays: number;
  /** Days until this row falls out of the freshness window; negative once it has. */
  daysLeft: number;
  stale: boolean;
}

interface SemanticFreshness {
  rows: SemanticFreshnessRow[];
  stale: SemanticFreshnessRow[];
  /** Targets with no recorded pass artifact at all — running on the measurement doc's date alone. */
  withoutArtifact: number;
  windowDays: number;
}

/**
 * `artifactDates` maps a corpus slug to the `generatedAt` of its recorded `M1.pass.json`, or
 * undefined when none exists. Passed in rather than read here so the whole assessment stays a pure
 * function of (clock, evidence) and the negative control can move either one.
 */
export function assessSemanticFreshness(
  now: number,
  artifactDates: Record<string, string | undefined>,
  maxAgeMs: number = MAX_PASS_AGE_MS,
): SemanticFreshness {
  const rows = SEMANTIC_CORPUS.map((target): SemanticFreshnessRow => {
    const artifact = artifactDates[target.slug];
    // An unparseable artifact date is treated as absent rather than as NaN days old: falling back
    // to the corpus record is a disclosed, weaker source, while NaN would silently never be stale.
    const artifactAt = artifact ? Date.parse(artifact) : NaN;
    const useArtifact = Number.isFinite(artifactAt);
    const recordedAt = useArtifact ? artifactAt : Date.parse(target.recordedOn);
    const ageMs = now - recordedAt;
    return {
      slug: target.slug,
      repo: target.repo,
      source: useArtifact ? "pass-artifact" : "corpus-record",
      recordedOn: useArtifact ? new Date(artifactAt).toISOString().slice(0, 10) : target.recordedOn,
      ageDays: Math.floor(ageMs / DAY_MS),
      daysLeft: Math.ceil((maxAgeMs - ageMs) / DAY_MS),
      stale: ageMs > maxAgeMs,
    };
  });

  return {
    rows,
    stale: rows.filter((r) => r.stale),
    withoutArtifact: rows.filter((r) => r.source === "corpus-record").length,
    windowDays: Math.round(maxAgeMs / DAY_MS),
  };
}
