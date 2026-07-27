// OWASP React Security CS (draft), SSR Security: "Shape Data Explicitly at the Server/Client
// Boundary". Every prop a Server Component hands a Client Component is serialized into the RSC
// payload the browser receives, so a full database row crosses the network whether or not it is
// rendered — the passwordHash and stripeCustomerId below are readable in the flight payload.
// The safe projection lives in rsc-boundary-shaped.tsx, in its own file so it is scoreable as a
// negative independently of the finding this file must produce.

import { db } from "../db/client";
import { ClientProfile } from "./client-profile";

export async function UserProfile({ userId }: { userId: string }) {
  const user = await db.getUser(userId);
  return <ClientProfile user={user} />;
}
