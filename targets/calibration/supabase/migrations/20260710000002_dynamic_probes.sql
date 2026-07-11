-- Dynamic-tier pen-test fixtures (M2 verify probes #145-#148; GROUND-TRUTH rows 9-12).
-- Support table for the coupon-redemption flow (NO-RATE-LIMIT).
create table if not exists public.coupon_redemptions (
  id uuid primary key default gen_random_uuid(),
  code text not null,
  redeemed_at timestamptz not null default now()
);

-- PLANTED BUG (ANON-PRIVILEGED-RPC): a privileged refund function marked SECURITY DEFINER with
-- EXECUTE granted to anon and no auth.uid()/ownership check in its body. Anyone holding the anon
-- key can call POST /rest/v1/rpc/issue_refund and move money — the frontend simply not rendering
-- the button is the only "control".
create or replace function public.issue_refund(order_id text, amount numeric)
returns json
language sql
security definer
set search_path = public
as $$
  insert into public.audit_logs (tenant_id, action, detail)
  values (null, 'refund', order_id)
  returning json_build_object('refunded', true, 'amount', amount);
$$;
grant execute on function public.issue_refund(text, numeric) to anon;

-- ANON-PRIVILEGED-RPC negative: a sibling privileged function with EXECUTE revoked from anon,
-- so the anon key cannot call it (403 permission denied).
create or replace function public.promote_admin(target uuid)
returns void
language sql
security definer
set search_path = public
as $$
  update public.profiles set role = 'admin' where id = target;
$$;
revoke execute on function public.promote_admin(uuid) from anon;
