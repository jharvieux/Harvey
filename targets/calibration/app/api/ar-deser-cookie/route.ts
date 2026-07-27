import { cookies } from "next/headers";
import { unserialize } from "node-serialize";

// PLANTED BUG (P-DESER-COOKIE, #1224): a serialized session blob is read from an App Router cookie
// and handed to node-serialize, which executes an embedded function body — RCE. A session cookie is
// the classic vector for this weakness, and the rule's Express-only source list could not see the
// App Router cookies() accessor at all.
export async function GET() {
  const jar = await cookies();
  const state = unserialize(jar.get("session_state")?.value ?? "");
  return Response.json(state);
}
