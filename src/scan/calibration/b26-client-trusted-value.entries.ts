// #1373 — the PRICE / DISCOUNT / TRIAL-LENGTH members of the client-trusted-value class, whose ROLE
// member has shipped since #614 (P-CLIENT-TRUSTED-ROLE, base.entries.ts). Kept in their own file
// rather than appended to base.entries.ts so the two halves of one taxonomy class stay individually
// legible, and because #1301's rule-corpus pairing gate requires a NEW harvey-* rule to arrive with
// both a positive it catches and a benign twin it stays silent on — these are that pair.
//
// MEASURED 2026-07-31 (semgrep 1.164.0): before harvey-client-trusted-price, a probe handler reading
// req.body.trial_period_days / req.body.unit_amount / req.body.discount_percent produced NOTHING
// while req.body.role on the line above it produced harvey-client-trusted-role. The gap was recorded
// in two places as "business context no AST pattern can distinguish"; it was a missing rule.

import type { CorpusEntry } from "./types.js";

export const b26ClientTrustedValueEntries: CorpusEntry[] = [
  {
    id: "P-CLIENT-TRUSTED-PRICE",
    kind: "positive",
    cls: "client-supplied price and trial length reach a payment call",
    location: "express-checkout-price.js",
    match: ["client-trusted-price"],
    expectedTier: "review",
    note: "#1373: lib/express-checkout-price.js reads req.body.unit_amount and req.body.trial_period_days and passes both to the payment provider — the caller names its own price and its own trial length. Review tier for the same reason harvey-client-trusted-role is: a handler that reads the field only to compare or reject it is a benign shape a single-file rule does not separate, so it is surfaced for triage rather than free-counted.",
  },
  {
    id: "N-SERVER-DERIVED-PRICE",
    kind: "negative",
    cls: "price and trial re-read server-side from the plan record",
    location: "express-checkout-price-safe",
    note: "#1373: lib/express-checkout-price-safe.js takes the same two fields off the plan row it loads by id, so the request supplies only an opaque planId. harvey-client-trusted-price gates on the named field being read off the REQUEST, so a plan-derived price never matches — cleared. This is the exact negative shape #1373's acceptance names ('the same fields re-read server-side from the price ID').",
    reviewTierHits: ["src.scan.rules.semgrep.harvey-route-noauth"],
  },
];
