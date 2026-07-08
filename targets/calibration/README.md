# Calibration target

> **INTENTIONALLY VULNERABLE — do not deploy, host, or expose this app.**
> It exists only as controlled ground truth for the Harvey audit scanner. Run it on a
> local, throwaway Supabase stack and nothing else. See `GROUND-TRUTH.md` for the
> complete list of planted bugs.

A tiny two-tenant Next.js + Supabase app with a known set of deliberately-planted
security bugs — one per severity tier and then some — so the scanner's precision/recall
can be measured against a fixed answer key.

## Layout

```
targets/calibration/
  supabase/
    config.toml          # local stack config (from `supabase init`)
    migrations/
      20260708000001_schema.sql   # tables + current_tenant_id() helper
      20260708000002_rls.sql      # RLS policies (contains planted bugs)
    seed.sql             # 2 tenants, 2 users, per-tenant data
  pages/                 # Next.js pages-router routes (contain planted bugs)
    api/...
  lib/                   # supabase service client + pg pool
  GROUND-TRUTH.md        # the answer key
```

## Stand it up locally

Requires Docker and the Supabase CLI.

```bash
cd targets/calibration

# 1. Start the local Supabase stack (Postgres, Auth, PostgREST, Studio).
supabase start

# 2. Apply migrations + run seed.sql from scratch.
supabase db reset
```

`supabase start` prints the local API URL, anon key, and service-role key. Studio is at
http://localhost:54323.

### Run the Next.js app (optional — needed to exercise the API-route bugs)

```bash
npm install

# Point the app at the local stack (values from `supabase start` output):
export SUPABASE_URL=http://127.0.0.1:54321
export SUPABASE_SERVICE_ROLE_KEY=<service_role key from `supabase start`>
export DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:54322/postgres
export WEBHOOK_SECRET=dev-secret

npm run dev   # http://localhost:3100
```

The RLS bugs (#1–#3) are exercised directly against PostgREST / the DB and need no app;
the API-route bugs (#4–#8) need the app running.

## Seeded logins (local only)

| User | Email | Password | Tenant |
|------|-------|----------|--------|
| Alice | `alice@tenant-a.test` | `password123` | A |
| Bob | `bob@tenant-b.test` | `password123` | B |

## Out of scope (follow-ups)

- Running the scanner / `/vuln-scan` against this target and recording precision/recall —
  depends on tooling from sibling issues.
- Any secondary external sanity-check target.
