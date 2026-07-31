import { supabase } from "../lib/supabaseAnonClient";

// N-D091-DEDUP-UPSERT (NEGATIVE — must NOT be flagged, #1257): the remedy the finding recommends,
// on the same unconstrained table as the read-only negative — so, like that one, it cannot be
// cleared by the schema. A rule that still fires here is telling the reader to apply a fix it will
// then keep reporting, which is the #989 lesson (a sanitizer that flags its own remedy) restated on
// a race rule.

export async function upsertContact(tenantId: string, externalRef: string) {
  const { data, error } = await supabase
    .from("d091_contacts_readonly")
    .upsert({ tenant_id: tenantId, external_ref: externalRef }, { onConflict: "tenant_id,external_ref" })
    .select("id")
    .single();
  if (error) throw error;
  return data.id;
}
