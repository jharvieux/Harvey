import { supabase } from "../lib/supabaseAnonClient";

// N-D091-DEDUP-WITH-UNIQUE (NEGATIVE — must NOT be flagged, #1257): byte-for-byte the dedup in
// dedup-without-unique.ts, against `d091_contacts_unique`, whose migration declares
// `unique (tenant_id, external_ref)`. The app code is identical, so this row tests exactly one
// thing: that the detector read the schema. A rule that fires here has become "any
// SELECT-then-INSERT", which is most dedup code in most codebases.

export async function findOrCreateContactUnique(tenantId: string, externalRef: string) {
  const { data: existing, error: readError } = await supabase
    .from("d091_contacts_unique")
    .select("id")
    .eq("tenant_id", tenantId)
    .eq("external_ref", externalRef)
    .maybeSingle();
  if (readError) throw readError;
  if (existing) return existing.id;

  const { data: created, error: writeError } = await supabase
    .from("d091_contacts_unique")
    .insert({ tenant_id: tenantId, external_ref: externalRef })
    .select("id")
    .single();
  if (writeError) throw writeError;
  return created.id;
}
