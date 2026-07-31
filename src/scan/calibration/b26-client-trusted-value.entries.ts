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
  // #1682 — the APP ROUTER body spelling of the ROLE member. `harvey-client-trusted-price` above
  // shipped with the `await req.json()` arm and `harvey-client-trusted-role` did not, so ONE
  // taxonomy class was covered unevenly by spelling — the same gap #1221 closed for 17 of 21 other
  // rules and #1240 for the RSC destructured-prop spelling. MEASURED 2026-07-31 (semgrep 1.164.0,
  // three identical runs, `--jobs 1 --timeout 0`, zero errors) on two handlers differing only in
  // how the body is read: `req.body.role` fired, `const body = await req.json(); body.role` was
  // silent. Filed here rather than in base.entries.ts because it is the same class as the price
  // rows above and shares their App Router arm verbatim.
  {
    id: "P-CLIENT-TRUSTED-ROLE-AR",
    kind: "positive",
    cls: "client-supplied role read off an App Router awaited body",
    location: "ar-client-role/route",
    match: ["client-trusted-role"],
    expectedTier: "review",
    note: "#1682: app/api/ar-client-role/route.ts does `const body = await req.json()` then writes `{ role: body.role }`. Review tier for the same reason the Express spelling is — the read usually IS the bug, but a read-then-reject shape is not separable single-file.",
  },
  {
    id: "P-CLIENT-TRUSTED-ROLE-AR-LET",
    kind: "positive",
    cls: "client-supplied privilege flag read off a `let`-bound App Router body",
    location: "ar-client-role-let/route",
    match: ["client-trusted-role"],
    expectedTier: "review",
    note: "#1682: the `let` twin. Registered separately because the arm matches the DECLARATION keyword, so `const` and `let` are two patterns and shipping only one would be a silent half-fix — the acceptance names both.",
  },
  {
    id: "N-AR-BENIGN-BODY-FIELD",
    kind: "negative",
    cls: "ordinary non-privilege field read off an App Router awaited body",
    location: "ar-client-role-benign/route",
    match: ["client-trusted-role"],
    note: "#1682: the FP control for the new arm. app/api/ar-client-role-benign/route.ts reads `body.title` off the same `await req.json()` shape. The arm inherits the privilege-flag vocabulary gate, so widening the rule to App Router bodies must not make every body read a finding — cleared.",
  },
];
