// #399: the per-entity store-file copy-paste vein — path says nothing about auth/security, but
// the body scopes a supabase query by a tenant key. Diverges from customer.store.ts on the
// scoping literal ('organisation_id' vs 'org_id') — the exact "patched one copy, missed the
// other" tenant-scoping drift #399's widening targets.
import type { SupabaseClient } from "@supabase/supabase-js";

export async function listOrders(supabase: SupabaseClient, organisationId: string) {
  const { data, error } = await supabase
    .from("orders")
    .select("id, name, email, created_at")
    .eq("org_id", organisationId)
    .order("created_at", { ascending: false });
  if (error) throw new Error("failed to list orders");
  return data;
}
