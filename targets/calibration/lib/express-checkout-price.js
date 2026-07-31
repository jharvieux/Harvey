// PLANTED BUG (P-CLIENT-TRUSTED-PRICE, #1373): a checkout handler takes the unit price and the
// trial length straight from the request body and hands them to the payment provider. Any caller
// can buy at their own price or grant themselves an unlimited trial by editing the JSON body.
// harvey-client-trusted-price → review (re-read the price/trial from the plan record the request
// names, never from the request itself).
export async function createSubscription(req, res) {
  const unitAmount = req.body.unit_amount;
  const trialDays = req.body.trial_period_days;
  await stripe.subscriptions.create({
    customer: req.body.customerId,
    trial_period_days: trialDays,
    items: [{ price_data: { unit_amount: unitAmount, currency: "usd" } }],
  });
  res.json({ ok: true });
}
