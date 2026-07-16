import { createClient } from "@supabase/supabase-js";

export interface PaymentRow {
  amount_cents: number;
  status: "succeeded" | "refunded" | "failed";
}

export interface ReconciliationTotals {
  collectedCents: number;
  refundedCents: number;
  failedCount: number;
}

export function reconcileTotals(rows: PaymentRow[]): ReconciliationTotals {
  let collectedCents = 0;
  let refundedCents = 0;
  let failedCount = 0;
  for (const row of rows) {
    if (row.status === "succeeded") collectedCents += row.amount_cents;
    else if (row.status === "refunded") refundedCents += row.amount_cents;
    else failedCount += 1;
  }
  return { collectedCents, refundedCents, failedCount };
}

export async function monthlyReconciliation(billingMonth: string): Promise<ReconciliationTotals> {
  const supabase = createClient(process.env.SUPABASE_URL ?? "", process.env.SUPABASE_ANON_KEY ?? "");
  const { data, error } = await supabase
    .from("payments")
    .select("amount_cents,status")
    .eq("billing_month", billingMonth);
  if (error) throw error;
  return reconcileTotals((data ?? []) as PaymentRow[]);
}
