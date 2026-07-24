-- #937/#938 drop-policy lifecycle fixture — the FIX half.
--
-- Drops the leaky `using (true)` policy created in 20260724000001 and replaces it with a
-- tenant-scoped one — exactly the shape a correctly-fixed client schema takes. After #937 the
-- static RLS review judges the FINAL live state, so the dropped audit_events_select_all is not
-- reported and only this scoped policy remains (which the reviewer clears). This is the
-- N-RLS-DROP-POLICY-FIXED negative: the fixed variant must not resurface the policy it replaced.
drop policy audit_events_select_all on public.audit_events;
create policy audit_events_select_scoped on public.audit_events
  for select using (tenant_id = public.current_tenant_id());
