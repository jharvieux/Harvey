import { supabaseAdmin } from "../../../lib/sbAdmin";

// NEGATIVE (N-CRON-SECRET): the same cron endpoint, gated by a bearer CRON_SECRET check before any
// privileged work. harvey-cron-no-secret excludes a handler that checks CRON_SECRET — cleared.
export default async function handler(req, res) {
  if (req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).end();
  }
  const { data } = await supabaseAdmin.from("invoices").select("amount_cents");
  res.json({ total: data.length });
}
