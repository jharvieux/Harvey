// PLANTED BUG (MISSING-AUTH-SWEEP must fire, #792): an unauthenticated profile lookup that returns
// real tenant/user data with no caller-identity check at all — proves the negative control isn't
// silent because bodyExposesData is broken.
export const dynamic = "force-dynamic";

export async function GET() {
  return Response.json({ email: "alice@tenant-a.example", tenant_id: "tenant-a", role: "owner" });
}
