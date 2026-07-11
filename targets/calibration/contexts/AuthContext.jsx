"use client";

import { supabase } from "../utils/supabase";

// NEGATIVE (N-AUTH-ADMIN-ANON-CLIENT, #164): auth.admin.* is called on the ANON client (utils/
// supabase.js), not a service-role client. This is a broken/no-op call at runtime — the anon key
// can't authorize the GoTrue admin API — a correctness bug, not a service-role-key exposure.
// harvey-auth-admin-in-client now requires the client identifier to read as admin/service-role
// ($C matches /admin|service/i); "supabase" doesn't, so this clears the high-tier gate.
export function deleteAccount(userId) {
  return supabase.auth.admin.deleteUser(userId);
}
