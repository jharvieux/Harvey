// The model-tier escalation ladder (design §5). Pure functions: they decide which tier a fix STARTS
// at and how verification failures walk the ladder toward a downgrade. No LLM caller lives here — the router
// (docs/design/model-routing.md) maps these tiers to bulk/standard/flagship; this module only decides
// which tier each attempt runs at and records the trail in FixResult.tiersUsed.

import type { EscalationTier, ScreenOptions } from "./plan.js";
import { touchesSensitive } from "./plan.js";
import type { Finding } from "../findings.js";

type EscalationTrigger =
  | "critical-or-high-severity" // §5 trigger 1
  | "sensitive-path-or-keyword"; // §5 trigger 2

// §5 trigger 3: at most two implementation attempts per tier before escalating.
export const MAX_ATTEMPTS_PER_TIER = 2;

const RANK: Record<EscalationTier, number> = { cheap: 0, standard: 1, flagship: 2 };

function higher(a: EscalationTier, b: EscalationTier): EscalationTier {
  return RANK[a] >= RANK[b] ? a : b;
}

// The planning-time triggers that fired for a finding (§5 triggers 1 and 2).
export function planningTriggers(finding: Finding, opts: ScreenOptions): EscalationTrigger[] {
  const triggers: EscalationTrigger[] = [];
  if (finding.severity === "Critical" || finding.severity === "High") triggers.push("critical-or-high-severity");
  if (touchesSensitive(finding, opts.sensitivePaths ?? [])) triggers.push("sensitive-path-or-keyword");
  return triggers;
}

// The tier implementation STARTS at (§5): any one trigger bumps cheap → standard; two or more bump to
// flagship. Never below the tier the finding was screened at.
export function initialTier(screened: EscalationTier, triggers: EscalationTrigger[]): EscalationTier {
  if (triggers.length >= 2) return higher(screened, "flagship");
  if (triggers.length >= 1) return higher(screened, "standard");
  return screened;
}

// Verification-failure escalation caps at standard (§5 trigger 3: "exhausting standard ⇒ downgrade, no
// flagship implementation retries in Phase 1"). A fix that STARTED at flagship (≥2 triggers) does not
// retry below it — it downgrades. So the only failure-escalation step is cheap → standard.
function failureNextTier(tier: EscalationTier): EscalationTier | undefined {
  return tier === "cheap" ? "standard" : undefined;
}

interface EscalationResult {
  tiersUsed: EscalationTier[]; // distinct tiers attempted, in order — feeds FixResult.tiersUsed
  outcome: "implementable" | "downgrade";
  downgradeReason?: string; // names the trigger that caused the downgrade
}

// Walk the ladder for one finding. `attempt(tier)` runs an implementation+verification at that tier and
// returns whether it verified green; it is called at most MAX_ATTEMPTS_PER_TIER times per tier. When a
// tier is exhausted the fix escalates (cheap → standard) or, if there is nowhere left to go, downgrades
// to recommend-only with the reason naming the verification-failure trigger.
// #1464: `attempt` may be async — the interactive path's attempt IS the whole ingest, which spawns
// the client's own suite. The walk itself stays strictly sequential: a tier's next attempt must not
// start until the previous one has been scored.
export async function runEscalation(
  screened: EscalationTier,
  triggers: EscalationTrigger[],
  attempt: (tier: EscalationTier) => boolean | Promise<boolean>,
): Promise<EscalationResult> {
  let tier = initialTier(screened, triggers);
  const tiersUsed: EscalationTier[] = [];
  for (;;) {
    if (!tiersUsed.includes(tier)) tiersUsed.push(tier);
    let verified = false;
    for (let i = 0; i < MAX_ATTEMPTS_PER_TIER; i++) {
      if (await attempt(tier)) {
        verified = true;
        break;
      }
    }
    if (verified) return { tiersUsed, outcome: "implementable" };
    const next = failureNextTier(tier);
    if (next === undefined) {
      return {
        tiersUsed,
        outcome: "downgrade",
        downgradeReason: `verification-failure: exhausted ${MAX_ATTEMPTS_PER_TIER} attempts at tier "${tier}"`,
      };
    }
    tier = next;
  }
}
