import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-NOAUTH-COMMENT-GUARD, #1066): the SAME unguarded delete as delete.js, plus one
// TODO comment naming the guard that is missing. harvey-route-noauth's guard clause is a TEXT match
// over the matched function's source, so before #1066 that comment WAS the guard as far as the rule
// could tell and the finding disappeared — the marker of known-missing auth silencing the detector.
// The #989 soundness lesson applied to the auth rules: this positive must STILL fire.
export default async function handler(req, res) {
  // TODO: requireAdmin() before shipping
  await admin.from("settings").delete().eq("key", req.body.key);
  res.status(200).json({ deleted: true });
}
