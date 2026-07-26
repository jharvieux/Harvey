import { admin } from "../../lib/supabaseAdmin";

async function writeReceiptAudit(orderId) {
  const { error } = await admin.from("audit").insert({ kind: "receipt", order_id: orderId });
  if (error) throw error;
}

// PLANTED BUG (P-VOID-ASYNC, D-091 #8): the audit write is fired and forgotten in a serverless
// handler. The function host can freeze or terminate the process as soon as the response is sent,
// so the write may never happen — and nothing observes the failure either way.
export default async function handler(req, res) {
  void writeReceiptAudit(req.body.orderId);

  return res.status(202).json({ queued: true });
}
