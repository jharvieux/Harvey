import { getServerSession } from "next-auth";
import { listOrdersForTenant } from "../../lib/order-repo";

// N-BOLA-CROSS-FILE-SESSION (NEGATIVE — must NOT be flagged, #1267): the same route, the same
// repository function, the same unscoped-looking `.eq("tenant_id", …)` at the far end. The ONLY
// difference is where the id comes from — the verified session rather than the request body. The
// repository is identical in both, which is the point: what makes the positive a bug is the ORIGIN
// of the value, and a rule that fired here would be reporting every data-access layer in existence.
export default async function handler(req, res) {
  const session = await getServerSession(req);
  if (!session) return res.status(401).json({ error: "unauthorized" });

  const orders = await listOrdersForTenant(session.user.tenantId);
  res.status(200).json({ orders });
}
