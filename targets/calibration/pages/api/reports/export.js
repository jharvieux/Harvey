import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-AUTH-BYPASS-CONST): a hardcoded bypass flag disables the auth check entirely —
// not a stubbed-out TODO, an explicit, permanent gate defeat. Caught by the leftover-auth grep
// (bypassAuth reference).
export default async function handler(req, res) {
  const bypassAuth = true;
  if (!bypassAuth) {
    return res.status(401).json({ error: "unauthorized" });
  }
  const { data } = await admin.from("reports").select("*");
  res.status(200).json(data);
}
