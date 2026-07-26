// The pure tenancy decision shared by the LIVE route handlers (which resolve auth via next-auth and
// data via Prisma) and the OFFLINE control test (which drives the same decisions over the in-memory
// _db.js seed). Auth is already resolved to `userId` before these run — so a regression in the
// membership check fails BOTH gates. #796/#1163.

export function decideMembers({ userId, team, isMember, members }) {
  if (!userId) return { status: 401, body: { error: "Unauthorized" } };
  if (!team) return { status: 404, body: { error: "Team not found" } };
  if (!isMember) return { status: 403, body: { error: "You are not a member of this team" } };
  return { status: 200, body: members };
}

export function decideDocuments({ userId, team, documents }) {
  if (!userId) return { status: 401, body: { error: "Unauthorized" } };
  if (!team) return { status: 404, body: { error: "Team not found" } };
  // PLANTED BUG (#796): no membership check — any authenticated caller reads ANY team's documents by
  // slug, so team A's session reaching team B's documents is a cross-tenant BOLA leak.
  return { status: 200, body: documents };
}
