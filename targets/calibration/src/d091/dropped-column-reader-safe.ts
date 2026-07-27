import { supabase } from "../lib/supabaseAnonClient";

// The negatives D-091 item 13's rule has to clear to ship.

// (1) Same column name, different table -- `d091_bookings.legacy_grade` is live. A rule that is not
// table-aware reports this too, which would make it unusable on any real schema.
export async function listBookings(tenantId: string) {
  const { data } = await supabase
    .from("d091_bookings")
    .select("id, legacy_grade, sort_order")
    .eq("tenant_id", tenantId);
  return data;
}

// (2) The reader already switched off the dropped column -- the expand-migrate-contract order done
// right.
export async function listQuotesSwitched(tenantId: string) {
  const { data } = await supabase
    .from("d091_quotes")
    .select("id, sort_order")
    .eq("tenant_id", tenantId);
  return data;
}
