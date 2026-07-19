-- #602 (cipherx CX-11/CX-12) — migration-SQL static passes for two Critical function classes the
-- semantic tier had to catch: plpgsql dynamic-SQL injection (EXECUTE with `||` concat of a parameter)
-- and SECURITY DEFINER data-dumping functions explicitly granted to the anon (unauthenticated) role.

-- PLANTED BUG (P-PLPGSQL-SQLI-CONCAT, #602 CX-12): search_tickets_unsafe builds its dynamic query by
-- CONCATENATING the p_query parameter into the EXECUTE string — classic CWE-89. It is SECURITY DEFINER,
-- so the injected query runs as the owner, bypassing RLS. checkMigrationDynamicSqlInjection → review.
create or replace function public.search_tickets_unsafe(p_query text)
returns table (id uuid, subject text)
language plpgsql
security definer
as $$
begin
  return query execute
    'select id, subject from public.nocode_tickets where subject ilike ' || p_query;
end;
$$;

-- TRUE NEGATIVE (N-PLPGSQL-SQLI-PARAMETERIZED, #602): the same search, done safely — the query string
-- uses a bound placeholder ($1) and the value is passed via USING. The `|| p_query ||` builds the
-- USING VALUE (after `using`), not the SQL text, so the query-string-scoped check does not flag it.
create or replace function public.search_tickets_safe(p_query text)
returns table (id uuid, subject text)
language plpgsql
security definer
as $$
begin
  return query execute
    'select id, subject from public.nocode_tickets where subject ilike $1'
    using '%' || p_query || '%';
end;
$$;

-- TRUE NEGATIVE (N-PLPGSQL-SQLI-QUOTED, #602): dynamic SQL built with quote_literal() around the
-- parameter — the escaped/quoted form is safe, so the concat-of-param check clears it.
create or replace function public.search_tickets_quoted(p_query text)
returns table (id uuid, subject text)
language plpgsql
security definer
as $$
begin
  return query execute
    'select id, subject from public.nocode_tickets where subject = ' || quote_literal(p_query);
end;
$$;

-- PLANTED BUG (P-DEFINER-ANON-DUMP, #602 CX-11): get_user_by_email is SECURITY DEFINER, returns data,
-- has no caller auth check, and is EXPLICITLY granted execute to anon — an unauthenticated caller can
-- dump any user row. checkMigrationDefinerAuthz only flags privileged WRITES, so this data-dumping
-- reader fell through; checkMigrationDefinerAnonGrant surfaces the explicit-anon-grant signal → review.
create or replace function public.get_user_by_email(p_email text)
returns setof public.nocode_tickets
language plpgsql
security definer
as $$
begin
  return query select * from public.nocode_tickets where requester_email = p_email;
end;
$$;
grant execute on function public.get_user_by_email(text) to anon;

-- TRUE NEGATIVE (N-DEFINER-ANON-CALLER-CHECK, #602): a definer reader granted to anon that DOES check
-- its caller (auth.uid()) before returning rows — legitimately anon-callable and self-scoping, so it
-- is cleared. Proves the anon-grant rule keys on the MISSING caller check, not on the anon grant alone.
create or replace function public.get_my_tickets()
returns setof public.nocode_tickets
language plpgsql
security definer
as $$
begin
  return query select * from public.nocode_tickets where requester_email = auth.jwt() ->> 'email' and auth.uid() is not null;
end;
$$;
grant execute on function public.get_my_tickets() to anon;

-- TRUE NEGATIVE (N-DEFINER-AUTHENTICATED-GRANT, #602): a definer reader granted only to AUTHENTICATED
-- (not anon/public). A user-facing RPC granted to signed-in users is normal, so the anon-grant rule
-- must stay silent — it is scoped to anon/public.
create or replace function public.list_my_org_tickets()
returns setof public.nocode_tickets
language plpgsql
security definer
as $$
begin
  return query select * from public.nocode_tickets;
end;
$$;
grant execute on function public.list_my_org_tickets() to authenticated;
