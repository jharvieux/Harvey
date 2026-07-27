import { supabase } from "../lib/supabaseAnonClient";

// D-091 item 13 (#1230) -- this reader still names `legacy_grade`, which the contract migration
// (20260727000003_d091_column_drift.sql) already dropped off `d091_quotes`. The column name is a
// string inside the query chain, so tsc sees nothing; this 500s the first time it runs in prod.

export async function listQuotes(tenantId: string) {
  const { data } = await supabase
    .from("d091_quotes")
    .select("id, legacy_grade, sort_order")
    .eq("tenant_id", tenantId);
  return data;
}
