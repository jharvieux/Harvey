"use server";

import { z } from "zod";
import { getCurrentUser } from "../lib/auth";
import { admin } from "../lib/supabaseAdmin";

const UpdateProfileSchema = z.object({ displayName: z.string().min(1) });

// TRUE NEGATIVE (N-AUTHN-SESSION-OWNER, #221): identical imports, auth call, schema parse and
// `.eq("user_id", …)` mutation shape as app/actions-owner.ts's planted bug — the near-miss that
// pins detectClientSuppliedOwnerId to the VALUE's origin rather than the statement's shape. The
// owner id reads off currentUser.id, so a caller can only ever edit its own row.
export async function updateOwnProfileName(input: unknown) {
  const currentUser = await getCurrentUser();
  const { displayName } = UpdateProfileSchema.parse(input);

  await admin.from("profiles").update({ display_name: displayName }).eq("user_id", currentUser.id);
}
