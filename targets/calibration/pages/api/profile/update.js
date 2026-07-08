import { admin } from "../../../lib/supabaseAdmin";

// "Update my profile role" — meant to change only the caller's own profile row.
export default async function handler(req, res) {
  const { role } = req.body;

  // PLANTED BUG (unscoped update): the service-role client bypasses RLS and there is
  // no .eq() scoping the write, so this rewrites `role` on EVERY profile in EVERY
  // tenant — a one-request cross-tenant privilege escalation. A correct version would
  // add .eq("id", <authenticated user id>).
  const { data, error } = await admin
    .from("profiles")
    .update({ role })
    .select();

  if (error) return res.status(500).json({ error: error.message });
  res.status(200).json({ updated: data.length });
}
