import { admin } from "../../../lib/supabaseAdmin";

// TRUE NEGATIVE (N-ROUTE-NOAUTH-CUSTOM-GUARD, #126): same mutation shape as
// pages/api/permissions/purge.js, but gated by a NAMED CUSTOM GUARD HELPER —
// assertPermission() — instead of the stock getServerSession()/supabase.auth.getUser() calls
// the rule originally recognized. This is the exact ATC dogfood shape (assertPlatformAdmin/
// assertPermission/authenticateUser, 122 false positives, #126): a well-built multi-tenant app
// enforces auth with a shared helper, not middleware, and the helper's name is project-specific.
// harvey-route-noauth's broadened pattern-not-regex (any call whose name starts with
// assert/require/ensure/authenticate/authorize/guard) excludes it — must clear.
export default async function handler(req, res) {
  await assertPermission(req, "permissions:revoke");
  await admin.from("permissions").delete().eq("tenant_id", req.body.tenantId);
  res.status(200).json({ revoked: true });
}
