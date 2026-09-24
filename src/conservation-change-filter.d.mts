export interface ConservationRule {
  kind: "prefix" | "suffix" | "exact";
  value: string;
}

export interface ConservationPlan {
  relevant: boolean;
  drift: boolean;
  paths: string[];
  relevantPaths: string[];
  driftPaths: string[];
  reason: string;
}

export const CONSERVATION_INPUT_RULES: readonly ConservationRule[];
export function planConservationRun(event: string, changedPaths: string[]): ConservationPlan;
