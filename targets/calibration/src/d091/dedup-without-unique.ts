import { supabase } from "../lib/supabaseAnonClient";

// D-091 item 25 (#1230) -- SELECT-then-INSERT dedup with no UNIQUE constraint behind it.
// `d091_contacts` (20260727000003_d091_column_drift.sql) has no unique index on
// (tenant_id, external_ref), so two concurrent callers both read "absent" and both insert. The
// duplicate then breaks every later `.maybeSingle()` on the same predicate.
//
// Planted as a currently-UNCAUGHT class -- outstanding work, not a boundary. The detector needs the
// app-side dedup predicate cross-referenced against the schema's constraints, which is the same
// migration-plus-app-code fold migration-column-drift.ts already does; the fixture carries both
// halves so whoever ships it has a complete answer key.

export async function findOrCreateContact(tenantId: string, externalRef: string) {
  const { data: existing, error: readError } = await supabase
    .from("d091_contacts")
    .select("id")
    .eq("tenant_id", tenantId)
    .eq("external_ref", externalRef)
    .maybeSingle();
  if (readError) throw readError;
  if (existing) return existing.id;

  const { data: created, error: writeError } = await supabase
    .from("d091_contacts")
    .insert({ tenant_id: tenantId, external_ref: externalRef })
    .select("id")
    .single();
  if (writeError) throw writeError;
  return created.id;
}
