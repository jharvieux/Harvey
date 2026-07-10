import { admin } from "../../../lib/supabaseAdmin";
import { getServerSession } from "next-auth";

// TRUE NEGATIVE (N-BOLA-SESSION-OWNER, #131): same route shape, but the query is scoped to the
// tenant id on the VERIFIED session, not a client-supplied field — a caller cannot read another
// tenant's invoice no matter what tenantId it puts in the body (it's never read).
export default async function handler(req, res) {
  const session = await getServerSession(req);
  if (!session) return res.status(401).json({ error: "unauthorized" });

  const { data } = await admin.from("invoices").select("*").eq("tenant_id", session.user.tenantId);
  res.status(200).json({ invoice: data });
}
