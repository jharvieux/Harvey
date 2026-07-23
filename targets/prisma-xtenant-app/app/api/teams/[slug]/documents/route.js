// POSITIVE CONTROL (#796): an UNSCOPED team route — the planted cross-tenant BOLA bug. It
// authenticates the caller but NEVER checks team membership, so any authenticated user can read ANY
// team's documents by slug. Team A's session reaching team B's documents returns team B's data, so
// the authenticated cross-tenant BOLA probe MUST prove a leak.
import { db, sessionUserId, teamSlugFromUrl } from "../../_db.js";

export function GET(req) {
  const userId = sessionUserId(req.headers.Cookie);
  if (!userId) return { status: 401, body: { error: "Unauthorized" } };
  const team = db.teams.find((t) => t.slug === teamSlugFromUrl(req.url));
  if (!team) return { status: 404, body: { error: "Team not found" } };
  // PLANTED BUG: no db.teamMembers membership check — returns the requested team's documents to any
  // authenticated caller, member or not.
  return { status: 200, body: db.documents.filter((d) => d.teamId === team.id) };
}
