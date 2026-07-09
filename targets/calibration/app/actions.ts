"use server";

// PLANTED BUG (P-CSRF-MISSING): a cookie-authed mutation with no Origin/CSRF check anywhere in
// the function. The browser attaches the session cookie automatically on a cross-site request
// too, so a malicious page can POST-trigger this deletion as the logged-in user.
export async function deleteAccount(id: string) {
  await supabase.from("accounts").delete().eq("id", id);
}

// TRUE NEGATIVE (N-CSRF-ORIGIN-CHECKED): same mutation shape, but guarded by an Origin check
// before it runs. harvey-csrf-missing's pattern-not-inside excludes any function containing a
// headers().get("origin") call.
import { headers } from "next/headers";

export async function updateAccountName(id: string, name: string) {
  const origin = headers().get("origin");
  if (origin !== process.env.APP_ORIGIN) throw new Error("Cross-origin request rejected");
  await supabase.from("accounts").update({ name }).eq("id", id);
}
