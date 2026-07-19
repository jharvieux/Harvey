// PLANTED BUG (P-SENSITIVE-ROUTE-NOAUTH, #568): the paired positive for the guarded negative next
// door — the SAME admin route shape with NO session read at all. Confirms the #568 AUTH_HINT
// broadening did not over-suppress: a genuinely unauthenticated admin route still fires leftover-auth's
// sensitive-route heuristic. AUTH-sensitive-route -> review. (This comment deliberately avoids naming
// any session-accessor helper, since the heuristic greps the whole file text.)
export async function GET() {
  return Response.json({ revenue: await db.metrics.all() });
}
