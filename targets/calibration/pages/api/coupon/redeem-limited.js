import { admin } from "../../../lib/supabaseAdmin";

// NO-RATE-LIMIT negative: rejects a code that has already been redeemed (single-use).
export default async function handler(req, res) {
  const { code } = req.body || {};
  const { data: existing } = await admin
    .from("coupon_redemptions")
    .select("code")
    .eq("code", code);
  if (existing && existing.length > 0) {
    return res.status(429).json({ error: "coupon already redeemed" });
  }
  await admin.from("coupon_redemptions").insert({ code });
  res.status(200).json({ redeemed: true });
}
