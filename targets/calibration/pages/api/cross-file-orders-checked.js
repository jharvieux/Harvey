import { getServerSession } from "next-auth";
import { listOrdersChecked } from "../../lib/order-repo";

// N-BOLA-CROSS-FILE-CHECKED (NEGATIVE — must NOT be flagged, #1267): the request-supplied tenant id
// DOES reach the repository — the syntactic half of the rule is fully satisfied — but the
// repository compares it against the session's before querying, which IS the authorization check.
// The comparison is in the CALLEE, not in this file, so clearing this row requires the detector to
// read the far end of the chain rather than only the near end.
export default async function handler(req, res) {
  const session = await getServerSession(req);
  if (!session) return res.status(401).json({ error: "unauthorized" });

  const orders = await listOrdersChecked(req.body.tenantId, session.user);
  res.status(200).json({ orders });
}
