// Batch B17 (#353) — two of the three never-covered dry-run planted bugs graduate to a mechanical
// rule at REVIEW tier: UPDATE-UNSCOPED (a raw UPDATE/DELETE string with no WHERE, leftover-auth
// grep) and COUNTER-RACE (a select→arithmetic→update read-modify-write on one table, the AST
// dataflow detector in src/scan/counter-race.ts). Both fire in runMechanicalScan, so they are
// scored by validate-calibration here; both stay review (a grep can't prove a whole-table write is
// unintended, and the AST can't see a DB-side lock/transaction), never free-count. The third bug
// WEBHOOK-REPLAY does NOT graduate — proving the absence of a replay guard needs whole-handler +
// callee reasoning a mechanical rule can't do FP-safely; its verdict is recorded on the dry-run
// scorecard (src/cli/dry-run-scorecard.ts), not here. See #353 and GROUND-TRUTH.md.

import type { CorpusEntry } from "./types.js";

export const b17RaceUnscopedEntries: CorpusEntry[] = [
  { id: "P-UPDATE-UNSCOPED", kind: "positive", cls: "raw service-role UPDATE/DELETE with no WHERE clause (rewrites every tenant's rows)", location: "pages/api/profile/update.js", match: ["unscoped-write"], expectedTier: "review", note: "#353: pages/api/profile/update.js runs pool.query(\"UPDATE public.profiles SET role = $1\", [role]) on the raw service connection with no WHERE — one request rewrites role on every profile in every tenant. leftover-auth's unscoped-write grep (a raw-SQL UPDATE/DELETE string literal with no WHERE, passed to a .query()/.execute() sink in a route file) → review. Discriminator: the missing WHERE, a textual fact like USING(true) (#333). FP shape: a deliberate admin reset/backfill — why it's review, not free-count. The negative adds WHERE id = $2 and is cleared." },
  { id: "N-UPDATE-SCOPED", kind: "negative", cls: "same raw-pool UPDATE, scoped with WHERE id = $2", location: "pages/api/profile/update-safe.js", match: ["unscoped-write"], note: "#353: pages/api/profile/update-safe.js runs UPDATE public.profiles SET role = $1 WHERE id = $2 on the same pool — the WHERE clause scopes the write to the caller's own row. leftover-auth's unscoped-write re-checks the matched DML for a WHERE token and skips it — no finding. Cleared." },

  { id: "P-COUNTER-RACE", kind: "positive", cls: "non-atomic read-modify-write on a counter (lost-update race)", location: "pages/api/counter/increment.js", match: ["read-modify-write"], expectedTier: "review", note: "#353: pages/api/counter/increment.js selects counters.value into `current`, computes `next = (current?.value ?? 0) + 1`, then updates counters with `value: next` — two concurrent requests both read the old value and one increment is lost. detectCounterRaceFindings (src/scan/counter-race.ts) proves the dataflow (a .select() of a table whose value is written back via .update() after a +/- derivation on the same table) → review. Discriminator: the read→arithmetic→write dataflow, not mere table co-occurrence. FP shape (read-then-write of an UNRELATED fresh value) is cleared by the arithmetic-derived-from-read gate. Stays review: can't see a DB-side lock/transaction." },
  { id: "N-COUNTER-ATOMIC", kind: "negative", cls: "atomic increment via a server-side RPC (value = value + 1 in one statement)", location: "pages/api/counter/increment-safe.js", match: ["read-modify-write"], note: "#353: pages/api/counter/increment-safe.js calls admin.rpc(\"increment_counter\", …) — one server-side statement, no select-then-update read-modify-write pair for the detector to flag. Cleared (no select+update on the same table). Recorded to complete the corpus pair." },
];
