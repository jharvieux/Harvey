import { admin } from "../../../lib/supabaseAdmin";
import { getServerSession } from "next-auth";

// TRUE NEGATIVE (N-DEBUG-ROUTE-GUARDED): a route under a sensitive /debug path segment, but
// guarded by a session read before it does anything. leftover-auth's sensitive-route heuristic
// (SENSITIVE_ROUTE_SEGMENT + AUTH_HINT) requires the path segment AND the absence of an
// auth-call hint; this file's getServerSession() call clears the AUTH_HINT check.
export default async function handler(req, res) {
  const session = await getServerSession(req);
  if (!session) return res.status(401).json({ error: "unauthorized" });
  const { data } = await admin.from("system_status").select("*");
  res.status(200).json(data);
}
