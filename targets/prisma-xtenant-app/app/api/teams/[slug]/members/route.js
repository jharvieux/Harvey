// NEGATIVE CONTROL (#796/#1163): a PROPERLY tenant-scoped team route. It authenticates the caller from
// the next-auth session cookie, resolves the team by slug, then enforces membership — a caller who is
// not a member of the requested team gets 403. So team A's session reaching team B's members is DENIED
// and the authenticated cross-tenant BOLA probe must NOT flag it. The tenancy decision lives in the
// shared pure core (_tenancy.js), which the offline control test drives in-process.
import { prisma } from "../../_prisma.js";
import { sessionUserId } from "../../_session.js";
import { decideMembers } from "../../_tenancy.js";

export async function GET(request, { params }) {
  const userId = await sessionUserId(request.headers.get("cookie"));
  const { slug } = await params;
  const team = await prisma.team.findUnique({ where: { slug } });
  const members = team ? await prisma.teamMember.findMany({ where: { teamId: team.id } }) : [];
  const isMember = Boolean(userId && members.some((m) => m.userId === userId));
  const r = decideMembers({ userId, team, isMember, members });
  return Response.json(r.body, { status: r.status });
}
