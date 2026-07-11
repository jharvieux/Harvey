import { admin } from "../../../../lib/supabaseAdmin";

// TRUE NEGATIVE (N-ROUTE-NOAUTH-CONSTANT-TIME, #171): an App Router admin route gated by a
// constantTimeEqual(...) comparison of a caller-supplied header against a server-held secret
// (ATC's apps/main/src/app/api/admin/tenants/route.ts shape). constantTimeEqual has no
// assert/require/verb prefix and no auth-ish token in its name, so the original guard regex
// couldn't see it — harvey-route-noauth now recognizes constantTimeEqual/timingSafeEqual as
// fixed guard names (the comparison against a secret IS the auth check). Must clear.
export async function POST(req: Request) {
  const secret = req.headers.get("x-admin-secret") ?? "";
  if (!constantTimeEqual(secret, process.env.ADMIN_HEADER_SECRET ?? "")) {
    return new Response("forbidden", { status: 403 });
  }
  const body = await req.json();
  const { data } = await admin.from("tenants").insert({ name: body.name });
  return Response.json(data);
}
