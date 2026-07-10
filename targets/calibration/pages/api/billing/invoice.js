import { admin } from "../../../lib/supabaseAdmin";
import { getServerSession } from "next-auth";

// PLANTED BUG (P-BOLA-BODY-OWNER, #131): the caller IS authenticated (a session must exist to
// reach the query below), but the query is scoped to req.body.tenantId — a value the CLIENT
// supplies — instead of the tenant id on the verified session. Any authenticated user can read
// another tenant's invoice by sending a different tenantId in the request body: this is an
// object/function-level authorization gap (BOLA/BFLA, OWASP API1/API5), not a missing-auth bug —
// contrast pages/api/order/get.js (P-IDOR-PARAM), which has no session at all.
export default async function handler(req, res) {
  const session = await getServerSession(req);
  if (!session) return res.status(401).json({ error: "unauthorized" });

  const { data } = await admin.from("invoices").select("*").eq("tenant_id", req.body.tenantId);
  res.status(200).json({ invoice: data });
}
