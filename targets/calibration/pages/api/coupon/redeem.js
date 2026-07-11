import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (NO-RATE-LIMIT): a high-value flow (coupon redemption) with no anti-automation
// cap — no rate limit and no per-code single-use check — so the same code can be redeemed in an
// unbounded loop. The redeem-limited sibling shows the fix.
export default async function handler(req, res) {
  const { code } = req.body || {};
  await admin.from("coupon_redemptions").insert({ code });
  res.status(200).json({ redeemed: true });
}
