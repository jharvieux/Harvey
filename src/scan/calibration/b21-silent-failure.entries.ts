// Batch B21 (#1021) — the three D-091 "silent side-effect failure" classes the fix pipeline's §8
// acceptance list names but nothing in src/ detected: a compare-and-swap update with no `.select()`
// (D-091 #7), an awaited Supabase mutation whose `{ error }` is discarded (D-091 #3), and
// `void`-prefixed fire-and-forget async in a serverless handler (D-091 #8). All three land in
// src/scan/rules/semgrep/silent-failure.yml as WARNING + MEDIUM rules, so all three positives score
// at REVIEW — these are reliability heuristics whose shape ("this chain is missing a call") cannot
// separate an oversight from a deliberate choice without reading intent, and that belongs nowhere
// near the free count.
//
// Why the fixtures exist BEFORE any fix fixture: #1009's remainder recorded these classes as
// unplanted fixtures; the re-measurement in #1021 found the blocker was upstream — no detector at
// all — so a planted before/after would have produced `notRun` rows, not scored ones. Detector →
// corpus → fix fixture is the order, and src/fix/calibration-acceptance.test.ts now takes all three
// through the full §8 gate on these same files.
//
// Adjacency (kept from double-firing): harvey-unchecked-mutation subtracts the CAS shape by an
// explicit pattern-not, so pages/api/payout-claim.js draws harvey-zero-row-update ONLY.
//
// See GROUND-TRUTH.md §B21.

import type { CorpusEntry } from "./types.js";

export const b21SilentFailureEntries: CorpusEntry[] = [
  // --- POSITIVES (must be caught) ---
  {
    id: "P-ZERO-ROW-UPDATE",
    kind: "positive",
    cls: "compare-and-swap update with no .select() — a lost race is indistinguishable from success",
    location: "pages/api/payout-claim.js",
    match: ["zero-row-update"],
    expectedTier: "review",
    note: "pages/api/payout-claim.js claims a payout with .update({status:'sending'}).eq('id', req.body.payoutId).eq('status','pending') and no .select() on the chain. Supabase JS returns { error: null } for 'matched 0 rows' exactly as for a successful write, so two workers both report the transfer claimed. Semgrep harvey-zero-row-update (2 .eq() filters, at least one against a STRING LITERAL state name, no .select() anywhere on the chain) → review. D-091 #7.",
  },
  {
    id: "P-UNCHECKED-MUTATION",
    kind: "positive",
    cls: "awaited Supabase mutation whose { error } tuple is discarded",
    location: "pages/api/subscribe.js",
    match: ["unchecked-mutation"],
    expectedTier: "review",
    note: "pages/api/subscribe.js awaits admin.from('subscribers').insert({…}) in statement position and returns 200 regardless. Supabase JS v2 does not throw on a database error, so a failed write is silent. Semgrep harvey-unchecked-mutation (awaited insert/update/upsert/delete NOT destructured, assigned or returned) → review. D-091 #3.",
  },
  {
    id: "P-VOID-ASYNC",
    kind: "positive",
    cls: "void-prefixed fire-and-forget async in a serverless handler",
    location: "pages/api/receipt.js",
    match: ["void-async"],
    expectedTier: "review",
    note: "pages/api/receipt.js does `void writeReceiptAudit(req.body.orderId)` then returns 202. The function host can freeze or terminate the process as soon as the response is sent, so the audit write may never land. Semgrep harvey-void-async, scoped by `paths:` to api/inngest/worker directories → review. D-091 #8.",
  },

  // --- NEGATIVES (must NOT be flagged in the free count) ---
  {
    id: "N-ZERO-ROW-SELECTED",
    kind: "negative",
    cls: "compare-and-swap update that chains .select() and asserts the row count",
    location: "pages/api/payout-claim-safe.js",
    match: ["zero-row-update"],
    note: "pages/api/payout-claim-safe.js is the same CAS chained with .select('id') and asserting data.length === 1 before treating the claim as won. harvey-zero-row-update's pattern-not-inside $Z.select(...) clears it — the fixed shape of P-ZERO-ROW-UPDATE, and the exact edit the fix pipeline's §8 gate applies.",
  },
  {
    id: "N-ZERO-ROW-TENANT-SCOPE",
    kind: "negative",
    cls: "two-filter update with no .select() that is tenant scoping, not a compare-and-swap",
    location: "pages/api/rename-workspace.js",
    match: ["zero-row-update"],
    note: "pages/api/rename-workspace.js has D-091's literal sketch shape — update(...) followed by two .eq() calls and no .select() — but both filters compare against VARIABLES (tenant id, workspace id). There is no guarded state and so no lost-race outcome to distinguish. The rule requires one filter against a string literal, so it stays silent; this fixture is what stops the rule from flagging routine tenant scoping. Its { error } is checked, so harvey-unchecked-mutation is clear too.",
  },
  {
    id: "N-CHECKED-MUTATION",
    kind: "negative",
    cls: "Supabase mutation whose { error } is destructured and acted on",
    location: "pages/api/subscribe-safe.js",
    match: ["unchecked-mutation"],
    note: "pages/api/subscribe-safe.js destructures { error } from the same insert and returns 500 when it is truthy. harvey-unchecked-mutation's pattern-not-inside $A = $B clears any destructured/assigned result — cleared.",
  },
  {
    id: "N-AWAITED-ASYNC",
    kind: "negative",
    cls: "the same background work awaited instead of voided",
    location: "pages/api/receipt-safe.js",
    match: ["void-async"],
    note: "pages/api/receipt-safe.js awaits writeReceiptAudit(...) so the handler does not return until the write is durable. harvey-void-async matches only the `void` operator applied to a call — cleared.",
  },
];
