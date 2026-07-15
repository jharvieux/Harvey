"use server";

import { z } from "zod";
import { getCurrentUser } from "../lib/auth";
import { admin } from "../lib/supabaseAdmin";

const CloseAccountSchema = z.object({ accountId: z.string().uuid() });

// TRUE NEGATIVE (N-AUTHN-OWNER-COMPARED, #221): the `.eq("account_id", accountId)` DOES read a
// client-supplied value — the literal shape detectClientSuppliedOwnerId keys on — but the action
// compares it against the session's id and throws first, and that comparison IS the authorization
// check. Pins the FP behaviour a shape-only rule would get wrong.
export async function closeOwnAccount(input: unknown) {
  const currentUser = await getCurrentUser();
  const { accountId } = CloseAccountSchema.parse(input);
  if (!currentUser || currentUser.id !== accountId) {
    throw new Error("Not authorized");
  }

  await admin.from("accounts").update({ closed: true }).eq("account_id", accountId);
}
