import { getServerSession } from "next-auth";
import { listOrdersForTenant } from "../../lib/order-repo";

// PLANTED BUG (P-BOLA-CROSS-FILE, #1267): the same class as P-BOLA-BODY-OWNER with ONE thing moved
// — the query lives in a repository module instead of in this file. Nothing else changed: the
// caller is authenticated, the scoping id comes from the request body, and no comparison against
// the session ever happens. bola-owner.ts requires the `.eq()` to be in the handler file, so before
// #1267 this whole shape was dark, and it is the shape any codebase with a data-access layer has.
export default async function handler(req, res) {
  const session = await getServerSession(req);
  if (!session) return res.status(401).json({ error: "unauthorized" });

  const orders = await listOrdersForTenant(req.body.tenantId);
  res.status(200).json({ orders });
}
