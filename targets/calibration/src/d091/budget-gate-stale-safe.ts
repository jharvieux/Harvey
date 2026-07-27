import { supabase } from "../lib/supabaseAnonClient";
import { runBatch } from "./runner";

// The negatives D-091 item 6's rule has to clear.

// (1) The gate re-reads between consuming operations, so the cap is enforced against the value
// that is true at the moment it is checked.
export async function runMonthlyBatchesFresh(tenantId: string, batches: string[]) {
  for (const batch of batches) {
    const { data: budget } = await supabase
      .from("d091_budgets")
      .select("remaining_cents")
      .eq("tenant_id", tenantId)
      .single();
    if ((budget?.remaining_cents ?? 0) < 100) break;
    await runBatch(batch);
  }
}

// (2) A running total compared against a constant ceiling -- the total is recomputed every
// iteration, so there is no stale read. Flagging this would put the rule on every bounded loop.
export async function runUntilCeiling(batches: string[]) {
  let spentCents = 0;
  for (const batch of batches) {
    if (spentCents > 10_000) break;
    spentCents += await runBatch(batch);
  }
}
