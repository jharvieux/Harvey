// PLANTED BUG (DIRECT-SERVICE-CALL): an /internal/* service route meant to be reached only through
// the fronting app, but reachable directly with only the anon key and returning data. The seam probe
// GETs it with anon headers; it answers 200 with a non-empty body -> proven.
export const dynamic = "force-dynamic";

export async function GET() {
  // No caller-identity check at all — the /internal segment is the only "control".
  return Response.json([
    { id: 1, email: "alice@tenant-a.example", role: "owner", ssn_last4: "1111" },
    { id: 2, email: "bob@tenant-b.example", role: "member", ssn_last4: "2222" },
  ]);
}
