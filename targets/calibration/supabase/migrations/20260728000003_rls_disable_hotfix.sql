-- #1425 — the hotfix migration, and the realistic incident shape: an on-call change turns row
-- security off on two tables so a backfill job running as a non-owner role can see every row.
-- One of them is put back (20260728000004). The other is not, and ships to production exposed.

-- PLANTED BUG (P-RLS-DISABLE-NOT-REVERTED, #1425): public.billing_exports was created WITH row
-- security and a correct tenant-scoped policy in 20260728000002, and this is the last row-security
-- statement it ever gets. The table is auto-exposed via PostgREST and its policy is inert — Postgres
-- does not consult policies while row security is disabled, so the schema still READS as protected.
--
-- Before #1425 this scored CLEAN and nothing in the product could say otherwise:
-- checkMigrationRlsStatic tracked only `enable row level security`, aggregated across the whole
-- migration set, so the enable in 20260728000002 cleared the table permanently — and
-- src/scan/supabase-static.ts contained no `disable row level security` pattern at all. MEASURED
-- 2026-07-28 by appending this exact statement to a migration whose readership was proven by a
-- control finding in the same file: exactly zero findings came back for it.
-- checkMigrationRlsStatic → SB-RLS-DISABLED-STATIC-billing_exports, high (Critical).
alter table public.billing_exports disable row level security;

-- TRUE NEGATIVE, first half (N-RLS-DISABLE-REVERTED, #1425): the same statement against
-- public.import_staging. On its own this is indistinguishable from the plant above — same verb,
-- same file, same table shape — which is exactly why it is here. 20260728000004 re-enables it, so
-- the discriminator is the FINAL row-security state of the table across the file set, never the
-- presence of a disable statement. A rule that flagged every `disable row level security` would
-- fire here and fail the gate.
alter table public.import_staging disable row level security;
