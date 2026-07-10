import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-MW-SOLE-AUTHZ, #133): this handler reads admin-only data with no session/role
// check anywhere in the function — it relies ENTIRELY on middleware.ts to gate the page before
// this route is ever reached. There is no defense in depth: if the middleware matcher has a gap
// (see P-MW-MATCHER-EXCLUDES-API, #132) or is ever removed/misconfigured, this route has zero
// authorization of its own. Contrast dashboard-safe.js (N-MW-DEFENSE-IN-DEPTH), which re-checks
// the session here too.
export default async function handler(req, res) {
  const { data } = await admin.from("admin_metrics").select("*");
  res.status(200).json({ metrics: data });
}
