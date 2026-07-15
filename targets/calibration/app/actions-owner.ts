"use server";

import { z } from "zod";
import { getCurrentUser } from "../lib/auth";
import { admin } from "../lib/supabaseAdmin";

const UpdateProfileSchema = z.object({
  userId: z.string().uuid(),
  displayName: z.string().min(1),
});

// PLANTED BUG (P-AUTHN-CLIENT-OWNER, #221): the caller IS authenticated AND the input IS
// schema-validated — so neither harvey-server-action-noauth nor the M9 missing-validation
// check fires — yet the row updated is chosen by the CLIENT-supplied userId rather than by
// currentUser.id. Any signed-in user can rename any other user's profile by sending a
// different (well-formed) uuid: authentication without authorization.
// Modelled on proposit's user-actions.ts. Contrast pages/api/billing/invoice.js
// (P-BOLA-BODY-OWNER), the Pages-Router/read-side shape of the same class.
// The two benign lookalikes live in their own files (actions-owner-session.ts,
// actions-owner-compared.ts) so each corpus entry pins to one location.
export async function updateProfileName(input: unknown) {
  const currentUser = await getCurrentUser();
  const { userId, displayName } = UpdateProfileSchema.parse(input);

  await admin.from("profiles").update({ display_name: displayName }).eq("user_id", userId);
}
