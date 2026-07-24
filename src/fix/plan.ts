// Fix planning + eligibility screening. Pure functions: given a validated
// Finding and the engagement's configuration, decide whether it enters the
// automated path, and which model tier it starts at. See docs/design/fix-implementation.md §1.1, §5.

import type { Confidence, Finding, Severity } from "../findings.js";

export type FixMode = "auto" | "manual" | "recommend-only";
export type EscalationTier = "cheap" | "standard" | "flagship";

export interface BlastRadius {
  files: string[]; // concrete paths the fix will modify
  createdFiles: string[]; // new files (tests, helpers) — must also pass the allowlist
  symbols: string[]; // functions/routes/policies touched
  callers: string[]; // grep-discovered importers/callers of changed symbols
  behaviorPreserving: boolean; // false => operator gate is mandatory-with-diff-walkthrough
  estimatedChangedLines: number;
}

export interface FixPlan {
  findingId: string; // Finding.id — the join key for everything downstream
  severity: Severity;
  category: string;
  mode: FixMode;
  detectorId: string; // which scan detector produced the finding (re-run in verify)
  approach: string; // what changes and why it resolves the finding
  blastRadius: BlastRadius;
  verifyCommands: string[]; // discovered client commands this fix must pass
  testPlan: string; // which existing tests cover this; what new test (if any) is added
  tier: EscalationTier; // starting model tier
  risks: string[];
  downgradeReason?: string; // set when mode === "recommend-only" or "manual"
}

export interface ScreenOptions {
  enabledCategories: string[]; // engagement's enabled category set
  sensitivePaths?: string[]; // engagement-configured path prefixes that force escalation
}

export interface Screen {
  mode: FixMode;
  tier: EscalationTier;
  reason?: string; // downgrade / manual reason, for the operator and PR body
}

// Only Confirmed/Likely findings are ever auto-fixed; Review/N/A become recommendations.
const FIXABLE_CONFIDENCE: readonly Confidence[] = ["Confirmed", "Likely"];

// The BFTB inputs that gate the automated path (design §1.1).
const AUTO_EASE_MIN = 4;
const AUTO_SAFETY_MIN = 4;

// Keyword heuristics that mark a fix as touching sensitive machinery (design §5 trigger 2).
const SENSITIVE_KEYWORDS = ["assertpermission", "transition", "payout", "stripe", "webhook"];

// §5 trigger 2: the fix touches state-machine / auth-permission / payment-adjacent code, by either an
// engagement-configured sensitive path prefix or a keyword heuristic. One source of truth for both
// the starting-tier decision (assignTier) and the escalation ladder (src/fix/escalation.ts).
export function touchesSensitive(finding: Finding, sensitivePaths: string[] = []): boolean {
  if (sensitivePaths.some((p) => finding.location.startsWith(p))) return true;
  const haystack = `${finding.location} ${finding.category} ${finding.evidence} ${finding.fix}`.toLowerCase();
  return SENSITIVE_KEYWORDS.some((k) => haystack.includes(k));
}

function assignTier(finding: Finding, opts: ScreenOptions): EscalationTier {
  if (finding.severity === "Critical" || finding.severity === "High") return "standard";
  if (touchesSensitive(finding, opts.sensitivePaths ?? [])) return "standard";
  return "cheap";
}

export function screenFinding(finding: Finding, opts: ScreenOptions): Screen {
  const tier = assignTier(finding, opts);

  if (!FIXABLE_CONFIDENCE.includes(finding.confidence)) {
    return { mode: "recommend-only", tier, reason: `confidence "${finding.confidence}" is not auto-fixable` };
  }
  if (!opts.enabledCategories.includes(finding.category)) {
    return { mode: "recommend-only", tier, reason: `category "${finding.category}" is not enabled for this engagement` };
  }
  if (finding.ease < AUTO_EASE_MIN || finding.safety < AUTO_SAFETY_MIN) {
    return {
      mode: "manual",
      tier,
      reason: `ease/safety ${finding.ease}/${finding.safety} below the ${AUTO_EASE_MIN}/${AUTO_SAFETY_MIN} automated threshold`,
    };
  }
  return { mode: "auto", tier };
}
