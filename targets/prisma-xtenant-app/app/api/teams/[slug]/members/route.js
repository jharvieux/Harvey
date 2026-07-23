// NEGATIVE CONTROL (#796): a PROPERLY tenant-scoped team route. It authenticates the caller from the
// session cookie, resolves the team by slug, then enforces membership — a caller who is not a member
// of the requested team gets 403. So team A's session reaching team B's members is DENIED and the
// authenticated cross-tenant BOLA probe must NOT flag it.
//
// Synchronous and speaking the probe's XtRequest/XtResponse wire types — the offline analogue of the
// live curl<->HTTP boundary prisma-standup drives against a booted Next.js app.
import { db, sessionUserId, teamSlugFromUrl } from "../../_db.js";

export function GET(req) {
  const userId = sessionUserId(req.headers.Cookie);
  if (!userId) return { status: 401, body: { error: "Unauthorized" } };
  const team = db.teams.find((t) => t.slug === teamSlugFromUrl(req.url));
  if (!team) return { status: 404, body: { error: "Team not found" } };
  const member = db.teamMembers.find((m) => m.teamId === team.id && m.userId === userId);
  if (!member) return { status: 403, body: { error: "You are not a member of this team" } };
  return { status: 200, body: db.teamMembers.filter((m) => m.teamId === team.id) };
}
