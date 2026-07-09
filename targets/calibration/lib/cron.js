import "server-only";
import { admin } from "./supabaseAdmin";

// N-SERVICE-ROLE-SERVER (NEGATIVE — must NOT be flagged): a legitimate server-only job using
// the service-role client for a trusted internal query. The "server-only" import guarantees a
// build error if this is ever imported from client code, so the key never reaches the browser.
// Service-role use is not a finding by itself (docs/fp-rules.txt) — only in client-reachable
// code (see components/AdminPanel.jsx) or when the key is exposed to the client/edge/a URL.
export async function nightlyRollup() {
  const { data } = await admin.from("audit_logs").select("tenant_id, action");
  return data;
}
