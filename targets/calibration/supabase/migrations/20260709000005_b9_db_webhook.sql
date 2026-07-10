-- B9 (#71) — outbound DB-webhook secret hygiene, read statically from committed SQL.

-- PLANTED BUG (P-DB-WEBHOOK-SECRET-SQL): a database trigger that calls net.http_post with the
-- outbound Authorization Bearer token hardcoded as a SQL literal. The token ships in the
-- committed migration and is readable by anyone with repo access. Value is FAKE. gitleaks
-- harvey-http-authorization-bearer matches the literal Bearer token → high.
create or replace function public.notify_order_created() returns trigger
language plpgsql security definer as $$
begin
  perform net.http_post(
    url := 'https://hooks.internal.example.com/orders',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'Authorization', 'Bearer whsec_9f3Kd2mQ7pRs1TvWx8Yz0AbCd4Ef6GhJk'
    ),
    body := jsonb_build_object('id', new.id)
  );
  return new;
end;
$$;

-- NEGATIVE (N-DB-WEBHOOK-SECRET-SETTING): the same webhook building its Authorization header from
-- a runtime DB setting (current_setting) instead of a committed literal — no secret in source.
-- The rule requires a 24-char literal after Bearer, which is absent here. Cleared.
create or replace function public.notify_order_shipped() returns trigger
language plpgsql security definer as $$
begin
  perform net.http_post(
    url := 'https://hooks.internal.example.com/orders',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'Authorization', 'Bearer ' || current_setting('app.webhook_secret')
    ),
    body := jsonb_build_object('id', new.id)
  );
  return new;
end;
$$;
