-- #1060 — the corpus had no end-to-end control for M10's data-aware severity ESCALATION. The join
-- (src/data-class-escalation.ts, #1049) matched 7 findings on the committed dry-run artifacts and
-- raised none of them, because every table a planted M1 finding named scores Low in the data map,
-- while the tables that score High/Critical (pii_calibration_fixture, support_tickets,
-- legacy_accounts) were named by no finding at all. Unit tests passed; the product's headline path
-- — a tenant-isolation gap on a table holding regulated data is priced higher than the same gap on
-- a preferences table — had never fired against real scanner output.
--
-- This is that control. public.patient_billing carries member_ssn (US_SSN/SENSITIVE_PII, 4 pts) and
-- card_number (CARD/PCI, 6 pts) = 10 → Critical on tools/pii-classify.mjs's ladder, and declares
-- tenant_id, so a SELECT policy of `using (true)` is the same read-side leak as the
-- documents_select_all plant (P-RLS-USING-TRUE-STATIC): usingTrueReview fires at High. The join
-- then raises High → Critical and records dataClass.escalatedFrom.
--
-- Column names are deliberately NOT customer_ssn/card_last4: those are the M10 per-infotype answer
-- key's own locations (src/scan/calibration/m10.entries.ts), and this table must not become the
-- fixture those entries score against.
create table public.patient_billing (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  member_ssn text not null,
  card_number text not null,
  amount_cents integer not null default 0,
  created_at timestamptz not null default now()
);

alter table public.patient_billing enable row level security;

-- BUG (PLANTED) — P-RLS-USING-TRUE-REGULATED. Every tenant's billing rows are readable by anyone
-- holding the anon key, on a table the schema itself declares tenant-scoped.
create policy patient_billing_select_all on public.patient_billing
  for select
  using (true);
