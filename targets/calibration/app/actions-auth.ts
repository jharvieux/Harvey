"use server";

import { headers } from "next/headers";

// PLANTED BUG (P-SERVER-ACTION-NOAUTH): mutates data with no authority/permission check. This
// fixture DOES check the request Origin (so it does NOT trip harvey-csrf-missing, see
// app/actions.ts) — the missing check here is AUTHORIZATION (assertPermission), not origin
// validation: any same-site caller, authorized or not, can archive any document.
export async function archiveDocument(id: string) {
  const origin = headers().get("origin");
  if (origin !== process.env.APP_ORIGIN) throw new Error("Cross-origin request rejected");
  await supabase.from("documents").update({ archived: true }).eq("id", id);
}

// TRUE NEGATIVE (N-SERVER-ACTION-GUARDED): same mutation shape, guarded by an explicit
// assertPermission() authority check before it runs. harvey-server-action-noauth's
// pattern-not-inside excludes any function containing that call.
export async function restoreDocument(id: string) {
  await assertPermission("documents:restore");
  await supabase.from("documents").update({ archived: false }).eq("id", id);
}
