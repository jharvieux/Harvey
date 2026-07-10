import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// PLANTED BUG (P-CLIENT-PAYMENT-AMOUNT): the charge amount is taken straight from the request
// body, so a client can pay one cent (or nothing) for anything.
export default async function handler(req, res) {
  const intent = await stripe.paymentIntents.create({
    amount: req.body.amount,
    currency: "usd",
    metadata: { orderId: req.body.orderId },
  });
  res.status(200).json({ clientSecret: intent.client_secret });
}
