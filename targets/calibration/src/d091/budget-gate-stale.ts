import { supabase } from "../lib/supabaseAnonClient";
import { runBatch } from "./runner";

// D-091 item 6 (#1230) -- TOCTOU / stale read in a budget gate. The remaining budget is read ONCE
// outside the loop and then consumed across every batch without a re-read, so the cap is enforced
// against a value that stopped being true after the first batch. Sequential single-run tests pass;
// catching it needs a multi-batch or concurrent case.

export async function runMonthlyBatches(tenantId: string, batches: string[]) {
  const { data: budget } = await supabase
    .from("d091_budgets")
    .select("remaining_cents")
    .eq("tenant_id", tenantId)
    .single();

  for (const batch of batches) {
    if ((budget?.remaining_cents ?? 0) < 100) break;
    await runBatch(batch);
  }
}
