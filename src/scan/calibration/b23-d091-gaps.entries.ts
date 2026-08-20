// B23 — the D-091 catalog items #1197's coverage audit found with NO Harvey detector at all
// (#1230). Six of the nine ship a mechanical detector; the entries below are their answer key.
//
// PROVENANCE, and why this corpus is weaker evidence than the OWASP ones: `briefs/anti-patterns.md`
// is a catalog WE wrote, so these fixtures measure internal consistency, not independent coverage —
// exactly the limitation CLAUDE.md names. What they do measure honestly is the FP side: every
// positive here ships with the benign lookalike its rule has to clear, and those lookalikes are the
// shapes that made #1230 read as un-mechanical in the first place (a live column of the same name
// on another table, a running total compared against a ceiling, a claim done in the right order).
//
// Every `match` is scoped to its detector's own taxonomy phrase. These fixtures sit in a shared
// directory and several attract findings from OTHER rules — an unscoped keyword would record a
// gap as covered off someone else's finding, which is the #1062 masking shape.

import type { CorpusEntry } from "./types.js";

export const b23D091GapEntries: CorpusEntry[] = [
  {
    id: "P-D091-SIG-ENCODING",
    kind: "positive",
    cls: "Webhook signature decoded as hex when the provider sends base64",
    location: "src/d091/webhook-sig-encoding.ts",
    match: ["Webhook signature decoded with the wrong encoding"],
    expectedTier: "high",
    expectedSeverity: "High",
    note: "D-091 item 12. `svix-signature` (Svix/Resend, base64) verified through `Buffer.from(sig, \"hex\")` — every genuine delivery fails and the handler is silently inoperative. #1230 recorded this as blocked on 'a per-provider expected-encoding table Harvey doesn't have'; re-checked and shipped, because the signature HEADER NAME carries the provider and the table is five documented rows. High tier: the mismatch is a fact about two string literals, not a judgement.",
  },
  {
    id: "N-D091-SIG-ENCODING-CORRECT",
    kind: "negative",
    cls: "Signatures decoded with each provider's documented encoding, plus an SDK-owned verification",
    location: "src/d091/webhook-sig-encoding-safe.ts",
    reviewTierHits: ["src.scan.rules.semgrep.harvey-missing-server-only"], note: "Four shapes, all silent: GitHub/hex, Shopify/base64, Svix/base64, and `stripe.webhooks.constructEvent`, which has no encoding literal at all because the SDK owns the decode. The last one is the reason the rule requires BOTH a known provider header and an encoding literal in the same function — without it, every SDK-delegating handler is a false positive.",
  },
  {
    id: "P-D091-DROPPED-COLUMN",
    kind: "positive",
    cls: "App code reads a column the contract migration already dropped",
    location: "src/d091/dropped-column-reader.ts",
    match: ["App code reads a column the migrations dropped"],
    expectedTier: "high",
    expectedSeverity: "High",
    note: "D-091 item 13 (ATC #137). `legacy_grade` is dropped off `d091_quotes` by 20260727000003_d091_column_drift.sql and still named in a `.from(\"d091_quotes\").select(…)` chain. #1230 recorded this as needing 'migration history + app-code cross-reference OVER TIME'; re-checked — the migration files ARE the history and are checked in, so it folds to a single-snapshot pass with no VCS archaeology.",
  },
  {
    id: "N-D091-DROPPED-COLUMN-CLEAR",
    kind: "negative",
    cls: "Same column name on a live table, and a reader already switched off the dropped one",
    location: "src/d091/dropped-column-reader-safe.ts",
    note: "`d091_bookings.legacy_grade` is live, so a rule that is not TABLE-AWARE reports this reader too — which would make it unusable on any real schema, where common column names repeat across tables. The second function is the post-switchover reader. Both silent.",
  },
  {
    id: "P-D091-STAMP-AFTER-SEND",
    kind: "positive",
    cls: "Batch job sends first and stamps the row afterwards",
    location: "src/d091/batch-send-claim.ts",
    match: ["Batch send stamped after dispatch instead of claimed before"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "D-091 item 22. `sendReminder(...)` inside the loop, then `.update({ sent_at })` — a retry or a second overlapping run re-sends every row whose stamp had not landed. Review tier: the ordering is an AST fact, but whether a retry actually happens is not.",
  },
  {
    id: "N-D091-CLAIM-BEFORE-SEND",
    kind: "negative",
    cls: "CAS-claim taken before the send, with the zero-rows-claimed skip",
    location: "src/d091/batch-send-claim-safe.ts",
    note: "`.update({ sent_at }).is('sent_at', null).select('id')` ahead of the send, with the rowcount check. This is the fix the finding recommends, so a rule that fired here would be recommending its own false positive.",
  },
  {
    id: "P-D091-DEDUP-BEFORE-DISPATCH",
    kind: "positive",
    cls: "Idempotency row inserted before the handler it guards",
    location: "src/d091/webhook-dedup-order.ts",
    match: ["Idempotency row written before the dispatched handler"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "D-091 item 10. Insert into `d091_webhook_events` precedes `handleSubscriptionEvent(event)`, so a crash in between makes the provider's genuine retry look like a duplicate and the work never completes. The fixture's event deliberately also carries `created`, which the insert records: this is the ordering detector's negative near-miss, because recording an ordering field in a receipt INSERT is not the state-applying UPDATE/UPSERT that `webhookOrdering` requires.",
  },
  {
    id: "N-D091-DISPATCH-BEFORE-DEDUP",
    kind: "negative",
    cls: "Idempotency row written after the handler returns, and a bare receipt record",
    location: "src/d091/webhook-dedup-order-safe.ts",
    reviewTierHits: ["src.scan.rules.semgrep.harvey-unchecked-mutation"], note: "Two shapes, both silent: the correct order (handler first, row after), and a dedup insert with nothing dispatched after it — recording receipt is not this bug. The second is why the rule is scoped to the enclosing FUNCTION body: file-wide, an insert in one function and an unrelated handler call further down would read as the defect.",
  },
  {
    id: "P-D091-NO-IDEMPOTENCY-KEY",
    kind: "positive",
    cls: "External send from a retryable job with no idempotency key",
    location: "src/inngest/external-send-idempotency.ts",
    match: ["External send without a deterministic idempotency key"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "D-091 item 24, both shapes in one fixture: `stripe.paymentIntents.create(...)` with no request options, and a `fetch` to api.resend.com with no `Idempotency-Key` header, from an Inngest path where the PLATFORM decides to run the code again. Scoped to retryable paths and to APIs whose idempotency contract we can name — an unrecognised host stays silent rather than guessed at.",
  },
  {
    id: "N-D091-IDEMPOTENCY-KEY-PRESENT",
    kind: "negative",
    cls: "Deterministic idempotency keys on both the SDK and the REST form",
    location: "src/inngest/external-send-idempotency-safe.ts",
    note: "The Stripe SDK's `idempotencyKey` request option and an `Idempotency-Key` header on the REST call, both derived from an immutable identifier. Silent.",
  },
  {
    id: "P-D091-STALE-QUOTA",
    kind: "positive",
    cls: "Budget read once outside the loop, consumed across every batch without a re-read",
    location: "src/d091/budget-gate-stale.ts",
    match: ["Quota gate consumed across a loop without re-reading"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "D-091 item 6, the TOCTOU shape distinct from item 18's single select-then-update pair (counter-race.ts) — nothing is written back here; the read is simply stale by the second iteration. #1230 recorded it as un-mechanical cross-statement dataflow; the hop is one binding deep, and requiring the guard value to come off a `.from(…).select(…)` chain is what clears the FP class.",
  },
  {
    id: "N-D091-QUOTA-REREAD",
    kind: "negative",
    cls: "Allowance re-read inside the loop, and a running total against a constant ceiling",
    location: "src/d091/budget-gate-stale-safe.ts",
    note: "Two shapes, both silent, and the second is the load-bearing one: `spentCents > 10_000` is recomputed every iteration, so it is NOT a stale read. A rule keyed on 'a limit-ish name compared inside a loop' fires on every bounded loop in every codebase — requiring the value to be bound from a DB read is the narrowing that makes this shippable.",
  },

  // -----------------------------------------------------------------------------------------------
  // The three of #1230's nine that did NOT ship a mechanical rule. They are planted here rather than
  // left in prose so the gate holds them: each is scored as an intended gap, and if a rule ever
  // fires on one the gate FAILS LOUD instead of letting the gap quietly graduate into a claimed
  // catch. `gapKind` is the honest part — two are boundaries, one is outstanding work, and calling
  // the third "by design" would misreport it.
  // -----------------------------------------------------------------------------------------------
  {
    id: "P-D091-ATOMIC-MULTI-WRITE",
    kind: "positive",
    cls: "Two dependent writes with no single atomic commit",
    location: "src/d091/atomic-multi-write.ts",
    match: ["collectively-atomic", "atomic multi-write", "dependent writes"],
    expectedTier: "none",
    gapKind: "by-design",
    note: "D-091 item 23. MEASURED 2026-07-27: zero findings for this class. BOUNDARY, not a backlog item — two inserts in one function is not a defect, and whether they form ONE invariant is a judgement about what the rows mean. A rule keyed on 'two writes, no RPC wrapper' fires on every multi-entity create handler in every codebase, which is the same unshippability that keeps item 20 (WEBHOOK-REPLAY) at LLM tier. Belongs to the M1 semantic pass. Both writes in the fixture check their error, so the only thing left in it is the atomicity class.",
  },
  {
    id: "P-D091-DEDUP-NO-UNIQUE",
    kind: "positive",
    cls: "SELECT-then-INSERT dedup with no UNIQUE constraint behind it",
    location: "src/d091/dedup-without-unique.ts",
    match: ["select-then-insert dedup"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "D-091 item 25. CLOSED by #1257 (src/scan/dedup-unique.ts); MEASURED 2026-07-31, caught at review tier, and the last of #1230's nine gaps to be settled. The 2026-07-27 label was `measured-gap` rather than `by-design` and that turned out to be the right call: #1230's blanket 'cross-time dataflow' reason was false here — the dedup predicate is in the app code, the constraint set is in the migrations, and folding those two is the same shape migration-column-drift.ts already ships for item 13. Three negatives guard it, each isolating one conjunct: N-D091-DEDUP-WITH-UNIQUE (identical app code, constrained table — tests that the schema was read at all), N-D091-DEDUP-READ-ONLY and N-D091-DEDUP-UPSERT (both on an UNCONSTRAINED table, so neither can be cleared by the schema and each must be cleared by an app-side conjunct). The `match` key was narrowed from ['unique constraint', 'select-then-insert'] to the single taxonomy phrase.",
  },
  {
    id: "N-D091-DEDUP-WITH-UNIQUE",
    kind: "negative",
    cls: "The same SELECT-then-INSERT dedup, on a table whose migration declares the pair UNIQUE",
    location: "src/d091/dedup-with-unique.ts",
    note: "#1257: byte-for-byte the positive's dedup against `d091_contacts_unique`, which carries `unique (tenant_id, external_ref)`. The app code is identical, so this row tests exactly one thing — that the detector read the schema. A rule that fires here has become 'any SELECT-then-INSERT', which is most dedup code in most codebases.",
  },
  {
    id: "N-D091-DEDUP-READ-ONLY",
    kind: "negative",
    cls: "Single-row lookup on an unconstrained table with no insert after it",
    location: "src/d091/dedup-read-only.ts",
    note: "#1257: the WRITE-half conjunct. Deliberately on `d091_contacts_readonly`, which has NO unique constraint, so the schema cannot clear this row — only requiring the insert can. Without that conjunct every `.eq().maybeSingle()` read in a codebase is a finding.",
  },
  {
    id: "N-D091-DEDUP-UPSERT",
    kind: "negative",
    cls: "The remedy the finding recommends — upsert with onConflict on the same predicate",
    location: "src/d091/dedup-upsert.ts",
    note: "#1257: also on the unconstrained table, for the same reason. A rule that fires here reports the fix it just recommended — the #989 lesson (a guard that flags its own remedy) restated on a race rule.",
  },
  {
    id: "P-D091-WEBHOOK-ORDERING",
    kind: "positive",
    cls: "Webhook state applied with no ordering guard, only replay dedup",
    location: "src/d091/webhook-ordering.ts",
    match: ["ordering guard"],
    expectedTier: "review",
    note: "D-091 item 27, SHIPPED by #1352 (src/scan/idempotency.ts, `webhookOrdering`). The production predicate has NO webhook-path prefilter: over every shipping TS/JS source admitted by `detectIdempotencyFindings`, it finds a function whose first identifier parameter declares or reads an ordering field, whose event-derived argument reaches a Supabase/Prisma `.update`, `.updateMany`, or `.upsert`, and whose function body contains no relational comparison. The fixture now includes replay dedup around the state write because two different event IDs can still arrive out of order; dedup is not an ordering guard. MEASURED 2026-08-15 with the production registry command `pnpm corpus-drift --install --shard N/3 --json corpus-drift-shardN.json --baseline-findings prior-drift/corpus-drift.json` for N=1,2,3 in Actions run 31873008063: the `idempotency` detector ledger reports 17 pinned targets, 13,104 `unitsExamined` source units, and 0 findings. The merged `corpus-drift.json` has SHA-256 `5eaeb965920aacf2e83c1f78def674691b2f214935990d8ffb85b3d7f73311ff`. This is the shipped detector, not the earlier webhook-path funnel; the unexplained loadable-file count is dropped. Zero firings means field precision remains unmeasured and the FP rate is undefined, not zero, so the client-legible finding keeps its function-body scope and zero-population limitation.",
  },
];
