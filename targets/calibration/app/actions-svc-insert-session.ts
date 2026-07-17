"use server";

import { createServiceClient } from "../lib/supabase";
import { getCurrentUser } from "../lib/auth";

// TRUE NEGATIVE (N-SVC-INSERT-SESSION-OWNER, #465): identical service-role insert shape as
// actions-svc-insert.ts, but the owner id reads off the SESSION (`user.id`), not the
// arguments — the caller can only ever add itself. The client-chosen `organisation_id` is NOT
// an owner-identity column for the INSERT-value shape ("which org am I acting in" is a
// legitimate client choice on an insert — see INSERT_OWNER_COLUMN in
// src/detectors/owner-id.ts) — pins that boundary as well as the value-origin one.
export async function joinOrganisation(organisationId: string) {
  const user = await getCurrentUser();
  const supabaseService = createServiceClient();

  await supabaseService.from("organisation_users").insert({
    organisation_id: organisationId,
    user_id: user.id,
    role: "member",
  });
}
