"use client";

import { supabaseAdmin } from "../lib/sbAdmin";

// PLANTED BUG (P-AUTH-ADMIN-CLIENT): a Client Component ("use client") calls auth.admin.* — the
// GoTrue admin API, which requires the service-role key. Any admin surface reachable from the
// browser means the privileged client (and its key) ships to the bundle. harvey-auth-admin-in-client.
export default function AdminUsersClient() {
  async function load() {
    const { data } = await supabaseAdmin.auth.admin.listUsers();
    return data;
  }
  return load;
}
