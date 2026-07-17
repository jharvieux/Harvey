"use server";

import { createServiceClient } from "../lib/supabase";

// PLANTED BUG (P-SVC-NOAUTH-BARE-ID, #465): NO auth call anywhere, the service-role client
// (RLS bypassed), and the row updated is chosen by bare `.eq("id", userId)` with the CLIENT's
// userId — anyone can rename any user. The #465-widened bare-id shape of the #221 class,
// modelled on proposit's user-actions.ts updateUserProfileAction. Its RLS-client near-miss is
// actions-rls-bareid.ts (same syntax, policies still gate the write). Detected by
// detectClientSuppliedOwnerId (review tier); the generic missing-auth finding is SUBSUMED by
// the more specific one here — one code defect, one finding.
export async function updateUserProfile(userId: string, displayName: string) {
  const supabaseService = createServiceClient();

  await supabaseService.from("users").update({ display_name: displayName }).eq("id", userId);
}
