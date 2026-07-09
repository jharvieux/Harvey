import { admin } from "../../../lib/supabaseAdmin";

// TRUE NEGATIVE (N-MASS-ASSIGN-PICK): only an explicit, destructured allowlist of fields is
// passed to update() — no spread of the raw request body. harvey-mass-assignment's sink pattern
// requires a `{ ...req.body }` spread; a plain object literal of named fields is a different
// (safe) shape and does not match.
export default async function handler(req, res) {
  const { displayName, bio } = req.body;
  const { data } = await admin.from("profiles").update({ displayName, bio }).eq("user_id", req.session.userId);
  res.status(200).json({ profile: data });
}
