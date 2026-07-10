import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-ROUTE-NOAUTH-CUSTOM-VERB): #126 regression guard — the route calls
// scheduleCleanup(), a name that shares the "check/verify/..." guard-VERB shape harvey-route-
// noauth now recognizes (see auth.yml), but "schedule" isn't in the recognized verb set and
// "Cleanup" carries no auth-ish token either way, so this must still be caught: no session read,
// no supabase.auth.getUser(), and no call matching the broadened guard-name regex.
export default async function handler(req, res) {
  await scheduleCleanup(req.body.tenantId);
  await admin.from("permissions").delete().eq("tenant_id", req.body.tenantId);
  res.status(200).json({ purged: true });
}
