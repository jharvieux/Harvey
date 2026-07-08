// Model-tier selection (design §7). A pure function of observable session state so its decisions
// are testable and reproducible in the action log. Base tier comes from the task; escalation flags
// bump it up. Escalation on the third revision is the empirical "the cheap model isn't getting it"
// point — paying the high tier there beats a fourth failed loop.

import type { EscalationFlag, ModelTask, Tier, TierContext } from "./types.js";

const BASE_TIER: Record<ModelTask, Tier> = {
  clarify: "standard",
  "epic-draft": "standard",
  "story-draft": "standard",
  revise: "standard",
  consistency: "flagship",
  qa: "flagship",
};

const REVISION_ESCALATION_THRESHOLD = 3;

export function selectTier(ctx: TierContext): Tier {
  if (ctx.flags.includes("user-requested")) return "flagship";
  if (ctx.flags.includes("contradiction")) return "flagship";
  if (ctx.flags.includes("sizing-anomaly")) return "flagship";
  if (ctx.flags.includes("revision-loop")) return "flagship";
  return BASE_TIER[ctx.task];
}

// Derive the revision-loop flag from a revision count. Centralised here so the controller and its
// tests agree on when the third-revision escalation fires.
export function revisionFlags(revisionCount: number): EscalationFlag[] {
  return revisionCount >= REVISION_ESCALATION_THRESHOLD ? ["revision-loop"] : [];
}
