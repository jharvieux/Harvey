import Stripe from "stripe";
import { admin } from "../../../lib/supabaseAdmin";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// The event is verified with the provider signature (constructEvent) before any write.
export default async function handler(req, res) {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET,
    );
  } catch {
    return res.status(400).json({ error: "invalid signature" });
  }
  await admin
    .from("subscriptions")
    .update({ status: event.data.object.status })
    .eq("customer_id", event.data.object.customer);
  res.status(200).json({ received: true });
}
