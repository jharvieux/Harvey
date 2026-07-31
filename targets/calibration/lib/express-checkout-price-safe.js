// NEGATIVE (N-SERVER-DERIVED-PRICE, #1373): the same two fields, re-read server-side from the plan
// record the request names. The request supplies only an opaque id, which is the correct shape.
// harvey-client-trusted-price gates on the FIELD NAME being read off the request, so a plan-derived
// price never matches — cleared.
export async function createSubscription(req, res) {
  const plan = await db.plans.findById(req.body.planId);
  await stripe.subscriptions.create({
    customer: req.body.customerId,
    trial_period_days: plan.trial_period_days,
    items: [{ price_data: { unit_amount: plan.unit_amount, currency: "usd" } }],
  });
  res.json({ ok: true });
}
