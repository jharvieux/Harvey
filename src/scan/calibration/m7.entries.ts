// M7 batch (#72, spec §M7) — Supabase performance-advisor corpus. Connected tier: Splinter's
// performance lints (unindexed_foreign_keys, auth_rls_initplan, unused_index) only fire against
// a LIVE schema (+ pg_stat_user_indexes usage history for unused_index), so — exactly like
// P-RLS-DISABLED in the base corpus — the three positives below are `expectedTier: "local"`:
// N/A in a static run, validated in a live run. #1499 re-tiered them when #1428 split the live
// venues; a Postgres connection to a `supabase start` stack answers every advisor lint here, and
// this header still said "connected" until #1827 derived the tier from the rows. Fixtures:
// targets/calibration/supabase/migrations/20260708000004_perf_calibration.sql.
//
// parseAdvisorFindings (src/perf-scan.ts) already emits Finding[] with precisionTier: "high" for
// every advisor lint (schema-truth, ~100% precise once connected — see that file's comment), so
// these entries score through buildCoverageMatrix unchanged once a live advisor pull is scored
// against them; module: "M7" keeps them out of validate-calibration.ts's `module === undefined`
// filter regardless, so they can't spuriously break the M1 live gate. `match` keywords pin each
// entry to its own advisor rule name (present verbatim in parseAdvisorFindings' evidence field)
// so a shared-table location (e.g. perf_orders carries both the RLS-initplan and unused-index
// fixtures) can't cross-attribute a finding between entries.
//
// Live validation (Layer 2) is a deferred supervisor pass — needs Docker + `supabase start`; see
// SESSION.md "Owed: connected-tier live confirmation pass". Layer 1 (this batch's `pnpm verify`
// gate) is src/perf-scan.test.ts's "M7 calibration corpus" block, scoring parseAdvisorFindings
// against a RECORDED advisor JSON shaped from what a live pull over this schema should return.
//
// M7-P-UNUSED-INDEX and M7-N-USED-INDEX share a table (perf_orders) AND a rule name
// (unused_index) — locationFor() groups by table, not by index, so a rule-name keyword can't
// tell them apart. Both instead match on the specific INDEX NAME, which only ever appears in a
// Finding's evidence when that index is genuinely unused (the used index never generates a lint
// at all, so its keyword can never collide with a real finding).

import type { CorpusEntry } from "./types.js";

export const m7Entries: CorpusEntry[] = [
  // --- POSITIVES (connected tier — must be caught once a live advisor pull is scored) ---
  {
    module: "M7",
    id: "M7-P-UNINDEXED-FK",
    kind: "positive",
    cls: "Unindexed foreign key",
    location: "perf_line_items",
    match: ["unindexed_foreign_keys"],
    expectedTier: "local",
    note: "perf_line_items.order_id references perf_orders(id) with no covering index. Splinter's unindexed_foreign_keys lint; LINT_PROFILES.unindexed_foreign_keys -> Perf. Live validation deferred (needs a Supabase branch).",
  },
  {
    module: "M7",
    id: "M7-P-RLS-INITPLAN",
    kind: "positive",
    cls: "RLS policy re-evaluates auth.* per row",
    location: "perf_orders",
    match: ["auth_rls_initplan"],
    expectedTier: "local",
    note: "perf_orders_select_own's USING clause calls bare auth.uid() (not wrapped in (select ...)). Splinter's auth_rls_initplan lint; LINT_PROFILES.auth_rls_initplan -> Perf. Live validation deferred.",
  },
  {
    module: "M7",
    id: "M7-P-UNUSED-INDEX",
    kind: "positive",
    cls: "Unused index",
    location: "perf_orders",
    match: ["idx_perf_orders_legacy_region"],
    expectedTier: "local",
    note: "idx_perf_orders_legacy_region backs no seeded/hot query. Splinter's unused_index lint (pg_stat_user_indexes idx_scan = 0); LINT_PROFILES.unused_index -> Low. Live validation deferred — requires exercising the sibling used-index query first so the usage-stats window is meaningful.",
  },

  // --- NEGATIVES (must NOT be flagged once a live advisor pull is scored) ---
  {
    module: "M7",
    id: "M7-N-INDEXED-FK",
    kind: "negative",
    cls: "FK with its covering index",
    location: "perf_shipments",
    match: ["unindexed_foreign_keys"],
    note: "perf_shipments.order_id references perf_orders(id) and idx_perf_shipments_order_id covers it. Splinter's unindexed_foreign_keys lint must not raise it.",
  },
  {
    module: "M7",
    id: "M7-N-WRAPPED-RLS",
    kind: "negative",
    cls: "RLS policy correctly wraps auth.uid()",
    location: "perf_events",
    match: ["auth_rls_initplan"],
    note: "perf_events_select_own's USING clause wraps the call as (select auth.uid()), hoisting it to a once-per-query initplan. Splinter's auth_rls_initplan lint must not raise it.",
  },
  {
    module: "M7",
    id: "M7-N-USED-INDEX",
    kind: "negative",
    cls: "Index backing a hot query",
    location: "perf_orders",
    match: ["idx_perf_orders_customer_email"],
    note: "idx_perf_orders_customer_email backs the seeded customer-email lookup. Once that query is exercised live, Splinter's unused_index lint (idx_scan > 0) must not raise it — removing it would be a false 'unused' call. A genuinely-used index never generates a lint, so this entry's keyword (the index's own name) can never collide with a real finding.",
  },
];
