import { admin } from "../../../lib/supabaseAdmin";
import { getServerSession } from "next-auth";

// TRUE NEGATIVE (N-ROUTE-AUTH-CHECKED): same mutation shape, guarded by a session read before
// the delete runs. harvey-route-noauth's pattern-not-inside excludes any function containing a
// getServerSession()/supabase.auth.getUser() call.
export default async function handler(req, res) {
  const session = await getServerSession(req);
  if (!session) return res.status(401).json({ error: "unauthorized" });
  await admin.from("settings").delete().eq("key", req.body.key);
  res.status(200).json({ deleted: true });
}
