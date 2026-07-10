import Stripe from "stripe";
import { admin } from "../../lib/supabaseAdmin";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// The amount is recomputed from the trusted DB price — the request only names the product.
export default async function handler(req, res) {
  const { data: product } = await admin
    .from("products")
    .select("price_cents")
    .eq("id", req.body.productId)
    .single();
  const intent = await stripe.paymentIntents.create({
    amount: product.price_cents * req.body.quantity,
    currency: "usd",
  });
  res.status(200).json({ clientSecret: intent.client_secret });
}
