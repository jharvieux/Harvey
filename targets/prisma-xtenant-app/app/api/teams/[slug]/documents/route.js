// POSITIVE CONTROL (#796/#1163): an UNSCOPED team route — the planted cross-tenant BOLA bug. It
// authenticates the caller but NEVER checks team membership, so any authenticated user can read ANY
// team's documents by slug. Team A's session reaching team B's documents returns team B's data, so the
// authenticated cross-tenant BOLA probe MUST prove a leak. The (buggy) tenancy decision lives in the
// shared pure core (_tenancy.js), which the offline control test drives in-process.
import { prisma } from "../../_prisma.js";
import { sessionUserId } from "../../_session.js";
import { decideDocuments } from "../../_tenancy.js";

export async function GET(request, { params }) {
  const userId = await sessionUserId(request.headers.get("cookie"));
  const { slug } = await params;
  const team = await prisma.team.findUnique({ where: { slug } });
  const documents = team ? await prisma.document.findMany({ where: { teamId: team.id } }) : [];
  const r = decideDocuments({ userId, team, documents });
  return Response.json(r.body, { status: r.status });
}
