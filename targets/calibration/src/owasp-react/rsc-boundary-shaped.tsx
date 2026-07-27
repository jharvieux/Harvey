// TRUE NEGATIVE for the boundary rule (N-OWASP-REACT-SHAPED-BOUNDARY) — the sheet's own remedy.
// The same query, the same Client Component, but only the two fields it renders cross the boundary,
// so nothing else reaches the RSC payload. Kept in its own file rather than beside the positive
// because a negative sharing a location with a firing positive can only be scored trivially.

import { db } from "../db/client";
import { ClientProfile } from "./client-profile";

export async function UserProfileShaped({ userId }: { userId: string }) {
  const user = await db.getUser(userId);
  return <ClientProfile name={user.name} avatarUrl={user.avatarUrl} />;
}
