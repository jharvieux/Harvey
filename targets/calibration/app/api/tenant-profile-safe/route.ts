import { admin } from "../../../lib/supabaseAdmin";

// TRUE NEGATIVE (N-ROUTE-NOAUTH-PUT-GUARDED, #382): same PUT-mutation shape as
// app/api/tenant-profile/route.ts, but gated by a custom-named guard helper — assertPermission()
// — before updating. harvey-route-noauth's #126 guard-name regex (assert/require/ensure/...
// prefix) is verb-agnostic, so it suppresses the widened PUT match the same way it does for POST —
// must clear.
export async function PUT(req: Request) {
  await assertPermission(req, "profiles:update");
  const body = await req.json();
  await admin.from("profiles").update({ display_name: body.displayName }).eq("id", body.id);
  return Response.json({ updated: true });
}
