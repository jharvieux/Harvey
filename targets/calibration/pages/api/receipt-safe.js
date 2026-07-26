import { admin } from "../../lib/supabaseAdmin";

async function writeReceiptAudit(orderId) {
  const { error } = await admin.from("audit").insert({ kind: "receipt", order_id: orderId });
  if (error) throw error;
}

// The same audit write, awaited — the handler does not return until the work is durable, so the
// host cannot kill the process mid-write.
export default async function handler(req, res) {
  await writeReceiptAudit(req.body.orderId);

  return res.status(202).json({ queued: true });
}
