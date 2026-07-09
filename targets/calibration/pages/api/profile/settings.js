import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-MASS-ASSIGNMENT): the entire request body is spread into the update payload —
// a caller can set ANY column the table exposes (e.g. { role: 'admin' } or { is_verified: true }),
// not just the fields this settings form is meant to edit.
export default async function handler(req, res) {
  const { data } = await admin.from("profiles").update({ ...req.body }).eq("user_id", req.session.userId);
  res.status(200).json({ profile: data });
}
