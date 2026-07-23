// In-memory two-tenant seed for the #796 offline cross-tenant fixture — the offline analogue of the
// live Team/membership seed prisma-standup applies. user-a is a member of team-a only, user-b of
// team-b only, so team A's session reaching team B's routes is a genuine cross-tenant access.
export const db = {
  teams: [
    { id: "team-a", slug: "harvey-seed-a", name: "Team A" },
    { id: "team-b", slug: "harvey-seed-b", name: "Team B" },
  ],
  teamMembers: [
    { id: "tm-a", teamId: "team-a", userId: "user-a", role: "ADMIN" },
    { id: "tm-b", teamId: "team-b", userId: "user-b", role: "MEMBER" },
  ],
  documents: [
    { id: "doc-a1", teamId: "team-a", title: "Team A roadmap" },
    { id: "doc-b1", teamId: "team-b", title: "Team B financials" },
  ],
};

// The minted per-tenant sessions — cookie token -> user id, the offline stand-in for the next-auth
// session-token cookie prisma-standup mints live.
const SESSIONS = { "sess-user-a": "user-a", "sess-user-b": "user-b" };

// Resolve the caller from a Cookie header value (`next-auth.session-token=<token>; ...`).
export function sessionUserId(cookieHeader) {
  if (!cookieHeader) return null;
  const match = /next-auth\.session-token=([^;]+)/.exec(cookieHeader);
  return match ? SESSIONS[match[1]] ?? null : null;
}

// The team slug is the third path segment: /api/teams/<slug>/(members|documents).
export function teamSlugFromUrl(url) {
  const parts = new URL(url).pathname.split("/").filter(Boolean);
  return decodeURIComponent(parts[2] ?? "");
}
