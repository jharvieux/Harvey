import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-WEBHOOK-NO-SIG): an inbound provider webhook that performs a privileged write
// with no signature verification of any kind — anyone who finds the URL can forge events.
export default async function handler(req, res) {
  const event = req.body;
  await admin
    .from("subscriptions")
    .update({ status: event.status })
    .eq("customer_id", event.customerId);
  res.status(200).json({ received: true });
}
