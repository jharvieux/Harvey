// Static auth_rls_initplan (#374) — the source-tier mirror of m7.entries.ts's connected-tier
// M7-P-RLS-INITPLAN / M7-N-WRAPPED-RLS pair, scored against the SAME committed SQL fixtures
// (targets/calibration/supabase/migrations/20260708000004_perf_calibration.sql — no new plant
// needed: the policy text the live advisor lints is already sitting in that migration).
//
// `module` is deliberately OMITTED: checkMigrationRlsInitplanStatic runs inside
// runMechanicalScan, so these entries must flow through validate-calibration.ts's
// `module === undefined` filter — the pipeline the check actually runs in. The module-tagged
// M7 entries are excluded from that pass by design (they score via perf-scan.test.ts against
// recorded advisor output) and are unaffected.
//
// expectedTier is "review", not "high": the check is syntactically exact (Splinter's own
// distinction) but reads cumulative migration text — it cannot see a later `drop policy`/
// re-create, and a perf lint must never inflate the security free count. See the check's
// header in src/scan/supabase-static.ts.

import type { CorpusEntry } from "./types.js";

export const m7InitplanStaticEntries: CorpusEntry[] = [
  {
    id: "M7-P-RLS-INITPLAN-STATIC",
    kind: "positive",
    cls: "RLS policy re-evaluates auth.* per row (read statically from migrations)",
    location: "20260708000004_perf_calibration.sql",
    match: ["perf_orders_select_own"],
    expectedTier: "review",
    note: "perf_orders_select_own's USING clause calls bare auth.uid() (not wrapped in (select …)) — the same plant M7-P-RLS-INITPLAN scores at connected tier, now also reachable on a source-only engagement via checkMigrationRlsInitplanStatic. Matched on the policy name, not the advisor rule name, so it can never cross-attribute with the connected entry's advisor-output keyword.",
  },
  {
    id: "M7-N-WRAPPED-RLS-STATIC",
    kind: "negative",
    cls: "RLS policy correctly wraps auth.uid() (static)",
    location: "20260708000004_perf_calibration.sql",
    match: ["perf_events_select_own"],
    note: "perf_events_select_own's USING clause wraps the call as (select auth.uid()), hoisting it to a once-per-query initplan — byte-for-byte the fix the positive's finding recommends. checkMigrationRlsInitplanStatic must stay silent on it: flagging the corrected shape would tell a client who applied the fix that it changed nothing.",
  },
];
