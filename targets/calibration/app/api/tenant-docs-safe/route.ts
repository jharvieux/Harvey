import { admin } from "../../../lib/supabaseAdmin";
import { createRouteClient } from "../../../lib/supabaseRoute";

// TRUE NEGATIVE (N-ROUTE-NOAUTH-DELETE-GUARDED, #382): same DELETE-mutation shape as
// app/api/tenant-docs/route.ts, but reads supabase.auth.getUser() and 401s before deleting.
// harvey-route-noauth's supabase.auth.getUser() pattern-not-inside is declared over the widened
// verb metavariable, so it suppresses the DELETE match exactly as it always has for POST — must
// clear.
export async function DELETE(req: Request) {
  const supabase = createRouteClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return new Response("unauthorized", { status: 401 });
  const id = new URL(req.url).searchParams.get("id");
  await admin.from("documents").delete().eq("id", id);
  return Response.json({ deleted: true });
}
