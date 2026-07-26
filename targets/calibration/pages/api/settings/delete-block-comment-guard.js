import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-NOAUTH-BLOCK-COMMENT-GUARD, #1093): the SAME unguarded delete as delete.js, but
// the "guard" is named inside a MULTI-LINE block comment whose interior line does not start with
// `*`. #1066's LINE_PREFIX guard clause was blind to comments and strings ON THE MATCHED LINE, but
// has no memory of an unclosed block comment from a PRIOR line, so `requireAdmin()` on this comment's
// middle line still reached the guard-token search and the finding vanished. This positive must fire.
export default async function handler(req, res) {
  /*
  requireAdmin()
  */
  await admin.from("settings").delete().eq("key", req.body.key);
  res.status(200).json({ deleted: true });
}
