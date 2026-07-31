import { admin } from "./supabaseAdmin";

// #1267 — the REPOSITORY half of the cross-file BOLA chain. Nothing here is wrong on its own: a
// data-access function that takes a tenant id and filters on it is the normal shape. The defect is
// that the only caller (pages/api/cross-file-orders.ts) supplies that id from the request while
// having authenticated the caller, and neither function ever compares the two. bola-owner.ts cannot
// see this: it requires the `.eq()` to be in the handler file.
export async function listOrdersForTenant(tenantId: string) {
  const { data, error } = await admin.from("orders").select("id, total_cents").eq("tenant_id", tenantId);
  if (error) throw error;
  return data;
}

// N-BOLA-CROSS-FILE-CHECKED's half: same query, but the repository itself compares the requested
// tenant against the one the server derived, which IS the authorization check.
export async function listOrdersChecked(tenantId: string, session: { tenantId: string }) {
  if (tenantId !== session.tenantId) throw new Error("forbidden");
  const { data, error } = await admin.from("orders").select("id, total_cents").eq("tenant_id", tenantId);
  if (error) throw error;
  return data;
}
