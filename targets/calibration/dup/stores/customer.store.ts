// #399: the per-entity store-file copy-paste vein — path says nothing about auth/security, but
// the body scopes a supabase query by a tenant key. Widened-scope fixture pair with order.store.ts.
import type { SupabaseClient } from "@supabase/supabase-js";

export async function listCustomers(supabase: SupabaseClient, organisationId: string) {
  const { data, error } = await supabase
    .from("customers")
    .select("id, name, email, created_at")
    .eq("organisation_id", organisationId)
    .order("created_at", { ascending: false });
  if (error) throw new Error("failed to list customers");
  return data;
}
