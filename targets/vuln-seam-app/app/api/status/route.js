// NEGATIVE CONTROL (MISSING-AUTH-SWEEP must stay silent, #792 — the #791 FP class): a public route
// with no tenant/user data at all, just a static status/version body. Deliberately NOT on the
// PUBLIC_ROUTE_ALLOWLIST (verify.ts) so the sweep actually probes it and the verdict rests on
// bodyExposesData's trivial-body gate, not the allowlist.
export const dynamic = "force-dynamic";

export async function GET() {
  return Response.json({ status: "ok", version: "1.0.0" });
}
