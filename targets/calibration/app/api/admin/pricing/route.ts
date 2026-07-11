import { admin } from "../../../../lib/supabaseAdmin";

// TRUE NEGATIVE (N-ROUTE-NOAUTH-ADMIN-AREA, #171): an App Router admin route gated by
// assertPlatformAdminArea(req, "...") — the "Area"-suffixed variant of the assert-prefixed guard
// helper (ATC's apps/main/src/app/api/admin/pricing/route.ts shape, ~70 review-tier FPs on the
// ATC dogfood). Already covered by harvey-route-noauth's assert-prefix bucket (any call starting
// with assert/require/ensure/authenticate/authorize/guard) — must clear.
export async function POST(req: Request) {
  await assertPlatformAdminArea(req, "pricing");
  const body = await req.json();
  const { data } = await admin.from("pricing_plans").update({ amount_cents: body.amountCents }).eq("id", body.id);
  return Response.json(data);
}
