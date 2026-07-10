import { supabaseAdmin } from "../../../lib/sbAdmin";

// PLANTED BUG (P-CRON-NO-SECRET): a service-role cron endpoint with no caller-secret check. Listed
// in vercel.json crons, but any anonymous request can trigger the privileged rollup. harvey-cron-no-secret.
export default async function handler(req, res) {
  const { data } = await supabaseAdmin.from("invoices").select("amount_cents");
  res.json({ total: data.length });
}
