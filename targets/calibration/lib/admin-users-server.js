import "server-only";
import { supabaseAdmin } from "./sbAdmin";

// NEGATIVE (N-AUTH-ADMIN-SERVER): the same auth.admin.* call in a server-only module (no
// "use client"). harvey-auth-admin-in-client fires only inside a Client Component — cleared.
export async function listUsers() {
  const { data } = await supabaseAdmin.auth.admin.listUsers();
  return data;
}
