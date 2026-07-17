"use server";

import { z } from "zod";
import { getCurrentUser } from "../lib/auth";
import { admin } from "../lib/supabaseAdmin";

const DeleteAccountSchema = z.object({ accountId: z.string().uuid() });

// PLANTED BUG (P-AUTHN-CLIENT-OWNER-DELETE, #221/#427): a SECOND real instance of the class,
// exercising the DELETE verb and the account_id ownership column — app/actions-owner.ts is an
// .update() on user_id. It is actions-owner-compared.ts with its `currentUser.id !== accountId`
// guard removed: the caller IS authenticated and the input IS schema-validated, yet the row
// deleted is chosen by the CLIENT-supplied accountId with no comparison against the session, so
// any signed-in user can delete any account. Its exact boundary near-miss is
// actions-owner-compared.ts (this shape WITH the guard).
export async function deleteAccount(input: unknown) {
  const currentUser = await getCurrentUser();
  const { accountId } = DeleteAccountSchema.parse(input);

  await admin.from("accounts").delete().eq("account_id", accountId);
}
