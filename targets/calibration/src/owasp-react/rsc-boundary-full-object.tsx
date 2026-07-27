// OWASP React Security CS (draft), SSR Security: "Shape Data Explicitly at the Server/Client
// Boundary". Every prop a Server Component hands a Client Component is serialized into the RSC
// payload the browser receives, so a full database row crosses the network whether or not it is
// rendered — the passwordHash and stripeCustomerId below are readable in the flight payload.

import { db } from "../db/client";
import { ClientProfile } from "./client-profile";

export async function UserProfile({ userId }: { userId: string }) {
  const user = await db.getUser(userId);
  return <ClientProfile user={user} />;
}

export async function UserProfileShaped({ userId }: { userId: string }) {
  const user = await db.getUser(userId);
  return <ClientProfile name={user.name} avatarUrl={user.avatarUrl} />;
}
