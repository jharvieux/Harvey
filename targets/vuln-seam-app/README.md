# vuln-seam-app — Harvey M2 seam fixture

**INTENTIONALLY VULNERABLE. Never deploy. Never expose to a public network.**

A tiny, self-contained Supabase/Next.js app that deliberately ships the four insecure inter-service
"seam" surfaces the M2 pen-test probes need in order to exercise their **proven** (finding-producing)
branches live. Every real corpus app we test is hardened, so those branches never fired; this fixture
is the permanent, versioned regression target that drives each to a proven verdict (#718, unblocking
#717 and #159).

## The four planted seams (each with a negative control)

| Probe | Vulnerable route | Negative control |
|-------|------------------|------------------|
| `CROSS-SERVICE-WEBHOOK` | `POST /api/webhooks/stripe` — reads the signature header, never verifies it, processes the event | `POST /api/webhooks/stripe-verified` — HMAC-verifies, empty 200 on failure |
| `DIRECT-SERVICE-CALL` | `GET /api/internal/users` — `/internal` route answering a direct anon call with data | `GET /api/internal/reports` — requires the fronting app's internal secret |
| `SERVICE-JWT-UNVERIFIED` | `GET /api/ingest/events` — decodes the bearer service JWT instead of verifying it (accepts `alg:none`) | `GET /api/ingest/events-verified` — RS256-verifies against a public key |
| `NO-RATE-LIMIT` | `POST /api/coupon/redeem` — replayable with no throttle/one-time-use | `POST /api/checkout` — per-process token bucket → 429 |

The full planted-finding enumeration and scoring key is in
[`ANSWER-KEY.md`](./ANSWER-KEY.md).

## Running the live proof

```
pnpm dynamic-validate targets/vuln-seam-app --execute
```

stands up its own disposable local Supabase (from `supabase/migrations/`), seeds two tenants + two
auth users, boots this app with `next build && next start`, and runs the seam suite + the
NO-RATE-LIMIT loop. Expected: the four vulnerable routes reach **proven**, the four controls stay
**not-vulnerable**. Requires Docker + the Supabase CLI; it never touches a shared/remote database.

## Layout

- `app/api/**/route.js` — the eight seam routes (four vulnerable, four controls).
- `supabase/migrations/0001_schema.sql` — a minimal two-tenant, RLS-scoped schema for the stand-up's
  two-tenant seed and the Tier-1 PostgREST matrix (no planted RLS bug — the bugs are the seam routes).
- `.env.example` — placeholder cred names the stand-up overwrites with the local stack's real creds.
