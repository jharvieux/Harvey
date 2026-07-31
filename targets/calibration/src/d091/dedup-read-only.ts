import { supabase } from "../lib/supabaseAnonClient";

// N-D091-DEDUP-READ-ONLY (NEGATIVE — must NOT be flagged, #1257): a single-row lookup on the same
// unconstrained table, with NO insert after it. `d091_contacts_readonly` deliberately has no unique
// constraint, so this row cannot be cleared by the schema — it can only be cleared by the detector
// requiring the WRITE half. Without that conjunct every `.eq().maybeSingle()` read in a codebase is
// a finding, which is the shape that makes a race rule unshippable.

export async function lookupContact(tenantId: string, externalRef: string) {
  const { data, error } = await supabase
    .from("d091_contacts_readonly")
    .select("id")
    .eq("tenant_id", tenantId)
    .eq("external_ref", externalRef)
    .maybeSingle();
  if (error) throw error;
  return data?.id ?? null;
}
