"use server";

import { createServiceClient } from "../lib/supabase";

// PLANTED BUG (P-SVC-NOAUTH-INSERT-OWNER, #465): NO auth call, service-role client, and the
// new row's OWNER comes from the client (`user_id: userId`) — the caller says who the
// membership belongs to and nothing checks it. The #465-widened INSERT-value shape of the #221
// class, modelled on proposit's acceptInvitationAction / createOrganisationAction. Its
// near-miss is actions-svc-insert-session.ts (owner id read off the session). Detected by
// detectClientSuppliedOwnerId (review tier); subsumes the generic missing-auth finding.
export async function addMember(organisationId: string, userId: string) {
  const supabaseService = createServiceClient();

  await supabaseService.from("organisation_users").insert({
    organisation_id: organisationId,
    user_id: userId,
    role: "member",
  });
}
