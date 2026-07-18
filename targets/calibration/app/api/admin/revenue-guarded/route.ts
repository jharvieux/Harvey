import { admin } from "../../../../lib/supabaseAdmin";
import { getUser } from "../../../../lib/auth";

// TRUE NEGATIVE (N-AUTHED-ROLE-CHECKED, #561): the same authenticated admin-revenue handler, but it
// reads the caller's role and 403s a non-admin before returning any data. harvey-authed-no-role-check's
// pattern-not-regex clears any handler that references a role/authz gate (the `.role` read, the 403
// response) — must clear. Regression guard: confirms the rule fires on the missing-gate case only,
// not on a properly role-gated privileged route.
export async function GET(req: Request) {
  const user = await getUser(req);
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { data: profile } = await admin.from("profiles").select("role").eq("id", user.id).single();
  if (profile.role !== "admin") return new Response("Forbidden", { status: 403 });
  const { data } = await admin.from("invoices").select("amount_cents, org_id");
  return Response.json({ revenue: data });
}
