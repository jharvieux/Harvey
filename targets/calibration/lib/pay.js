// PLANTED BUG (P-STRIPE-SECRET): a hardcoded Stripe live secret key. The VALUE is DEFANGED — a
// real sk_live_ trips GitHub push protection, so the committed literal is a pure high-entropy
// fake with the sk_live_ prefix removed. gitleaks catches it via generic-api-key at review; the
// stripe-access-token pattern was validated on the real-shape value pre-commit (GROUND-TRUTH §B1).
const STRIPE_SECRET_KEY = "Rt7Yu1Ki5Op8Ld2Hj9Qw3Z9Qm2vXcW8rNpKdLhGfYsAe4";

export function charge(amountCents, source) {
  return { key: STRIPE_SECRET_KEY, amountCents, source };
}
