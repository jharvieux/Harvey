// Batch B24 (#1299, finishing #140/#141/#142) — the three connected-tier Supabase classes that
// shipped in PR #150 with detectors, unit tests and a live ATC run, and then had NO corpus row at
// all: PostgREST schema exposure (#141), pg_graphql introspection (#142) and Realtime authorization
// (#140). `grep -rl 'EXPOSED-SCHEMA\|REALTIME\|GRAPHQL' src/scan/calibration/` returned nothing
// until this file.
//
// WHAT THESE ROWS DO AND DO NOT LOCK — read this before trusting a green gate.
// Every row here is `expectedTier: "connected"`, which scoreEntry() scores N/A and never fails
// (src/scan/calibration.ts). So they do NOT assert that the detectors fire; what they lock is the
// ANSWER KEY (class, fixture, expected id/severity, and the state a seeded stack must be in), the
// per-module parity census, and the fixture pairing a live connected run scores against. The
// wiring seam — that scanHosted actually calls checkExposedSchemas/checkGraphqlIntrospection and
// that checkRealtimeAuthorization runs in BOTH modes — is separately locked by
// src/scan/supabase.test.ts ("runs the connected-tier checks (realtime, exposed schema,
// pg_graphql) on a hosted scan", plus the SB-SCOPE-00 pair added by #1330), and the check bodies by
// supabase-config.test.ts. The one thing still unlocked is a scored LIVE run, which is blocked on
// the calibration target's migration chain (see the note on P-REALTIME-NO-AUTHZ).
//
// THE FIXTURES ARE REAL AND WERE MEASURED, NOT INFERRED (2026-07-28, Supabase CLI 2.102.0, stock
// `supabase start`). psql transcript in docs/runbooks/dry-run-calibration.md §11:
//   - realtime.messages exists with relrowsecurity = TRUE, owned by supabase_realtime_admin; the
//     `postgres` role IS a member of that role, so `alter table realtime.messages disable row level
//     security` returns ALTER TABLE and leaves relrowsecurity = FALSE. The positive is plantable.
//   - pg_graphql is AVAILABLE (default_version 1.5.11) but NOT installed — pg_extension has no row.
//     `create extension pg_graphql` succeeds and lands version 1.5.11 in schema `graphql`, which is
//     what hasPgGraphql() requires; `graphql_public` is already in the default `[api] schemas`.
//   - `create schema internal_ops` succeeds.
//
// SCOPE CONTROL (CLAUDE.md rule 3 — an unread fixture reports zero exactly like a missed one).
// The new migration produces ZERO static findings, so readership was proven rather than assumed:
// a temporary `create policy tmp_probe_using_true on public.notes for select using (true)` was
// appended to it, `dry-run.ts` was re-run, and it emitted
// SB-RLS-POLICY-public.notes.tmp_probe_using_true at
// supabase/migrations/20260728000001_connected_postgrest_realtime.sql:65 — the file is read. The
// probe was then removed. MEASURED 2026-07-28.
//
// A GAP THE SAME PROBE FOUND, tracked separately: the second probe line,
// `alter table public.notes disable row level security`, produced NOTHING. `src/scan/
// supabase-static.ts` has no `disable row level security` pattern at all, and
// checkMigrationRlsStatic aggregates ENABLE across every migration — so a migration that revokes
// RLS from a table an earlier migration protected is invisible statically AND still scores that
// table clean. Not this batch's class; filed as #1425.

import type { CorpusEntry } from "./types.js";

export const b24ConnectedPostgrestRealtimeEntries: CorpusEntry[] = [
  // --- POSITIVES (connected tier — N/A on a static run, never a free-count claim) ---
  {
    id: "P-API-SCHEMA-WIDE",
    kind: "positive",
    cls: "PostgREST exposes a schema beyond the public/graphql_public default",
    location: "internal_ops",
    match: ["schema exposure"],
    expectedTier: "connected",
    expectedSeverity: "Medium",
    note: "#141. Two-part fixture: supabase/config.toml `[api] schemas = [\"public\", \"graphql_public\", \"internal_ops\"]` is the half PostgREST turns into its `db-schema` setting (the ONLY thing checkExposedSchemas reads — it is not queryable from Postgres, which is why local mode discloses SB-SCOPE-00 instead of answering), and migration 20260728000001 creates internal_ops.job_queue behind the name so the exposure is a real reachable surface rather than an empty allow-list entry. Expect SB-API-SCHEMA-internal_ops, review tier, Medium, location \"exposed schema: internal_ops\". Matched on \"schema exposure\" (from the taxonomy) rather than the schema name, which is the entry's own location and would be vacuous under #1355.",
  },
  {
    id: "P-GRAPHQL-INTROSPECTION",
    kind: "positive",
    cls: "pg_graphql installed AND graphql_public exposed — introspection reachable",
    location: "graphql_public",
    match: ["introspection"],
    expectedTier: "connected",
    expectedSeverity: "Medium",
    note: "#142. Needs BOTH preconditions, and only one of them is a stock default: graphql_public is already in `[api] schemas`, but pg_graphql is NOT installed by a stock `supabase start` (MEASURED — pg_available_extensions shows default_version 1.5.11 with a null installed_version). Migration 20260728000001's `create extension if not exists pg_graphql` supplies the missing half. That same absence is why the 2026-07-10 ATC live run recorded this class as a clean NEGATIVE — it was the extension that was missing there too, not the schema, which is the discrimination hasPgGraphql() exists to make and is unit-tested for in supabase.test.ts. Expect SB-GRAPHQL-INTROSPECTION, review tier, Medium.",
  },
  {
    id: "P-REALTIME-NO-AUTHZ",
    kind: "positive",
    cls: "Realtime channel/broadcast lacks authorization (realtime.messages RLS disabled)",
    location: "realtime.messages",
    match: ["channel lacks authorization"],
    expectedTier: "connected",
    expectedSeverity: "High",
    note: "#140, the id the issue itself named. Unlike the other two this check runs in BOTH hosted and local mode (supabase.ts:198/:303), so it is the one of the three a local stack can actually score. Plantable, which was not obvious: realtime.messages ships with RLS ENABLED and is owned by supabase_realtime_admin, but `postgres` is a member of that role, so migration 20260728000001's `alter table realtime.messages disable row level security` succeeds (MEASURED 2026-07-28 — ALTER TABLE, relrowsecurity flips to false). Expect SB-REALTIME-NO-AUTHZ, review tier, High. NOT YET SCORED LIVE against this target: `supabase start` on targets/calibration currently aborts at migration 20260719000002_plpgsql_injection_definer.sql (`type \"public.nocode_tickets\" does not exist`), so no migration from that point on — including this one — has ever been applied to a stack. Pre-existing, unrelated to this batch, filed as #1424; the psql work above was done on a bare stack for exactly that reason.",
  },

  // --- NEGATIVE (boundary — scored statically, deliberately NOT tiered "connected") ---
  {
    id: "N-API-SCHEMA-INTERNAL",
    kind: "negative",
    cls: "Schema present in the database and deliberately absent from the API allow-list",
    location: "analytics_private",
    note: "#141 boundary. Migration 20260728000001 creates analytics_private.rollup_daily alongside internal_ops.job_queue, identically shaped, RLS-enabled and tenant-scoped — the ONLY difference is that analytics_private is not in config.toml's `[api] schemas`. checkExposedSchemas reads the allow-list, not pg_namespace, so it must stay silent; that is the whole claim the check makes and this row is what would fail if the check ever started deriving exposure from the database instead. Left untiered ON PURPOSE, unlike its connected siblings: an untiered negative is really scored by the static gate (no free-count finding, and since #1344 no unrecorded review-tier taxonomy, may land here), so it is the one row in this batch that can actually fail today. MEASURED 2026-07-28: it draws zero findings of either tier, on a file the scope-control probe proved is read.",
  },
];
