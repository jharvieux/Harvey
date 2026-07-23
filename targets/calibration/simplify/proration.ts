export interface ProrationInput {
  oldPlanCents: number;
  newPlanCents: number;
  daysUsed: number;
  daysInPeriod: number;
}

export function prorateUpgradeCharge(input: ProrationInput): number {
  const { oldPlanCents, newPlanCents, daysUsed, daysInPeriod } = input;
  const remainingRatio = (daysInPeriod - daysUsed) / daysInPeriod;
  const unusedOldValueCents = Math.round(oldPlanCents * remainingRatio);
  const newChargeCents = Math.round(newPlanCents * remainingRatio);
  return Math.max(0, newChargeCents - unusedOldValueCents);
}

export async function applyPlanChange(subscriptionId: string, input: ProrationInput): Promise<void> {
  const dueCents = prorateUpgradeCharge(input);
  const response = await fetch("https://billing.internal.example.com/charges", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subscriptionId, dueCents }),
  });
  if (!response.ok) throw new Error(`plan change failed: ${response.status}`);
}
