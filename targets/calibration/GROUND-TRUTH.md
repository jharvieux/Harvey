# GROUND-TRUTH — calibration target answer key

This app is **deliberately vulnerable**. Every bug below is planted on purpose so the
Harvey scanner can be measured for precision/recall against known answers. Line numbers
are the source of truth; if you edit the files, update this table.

Tenants: **A** = `aaaaaaaa-…`, **B** = `bbbbbbbb-…`. Users: `alice@tenant-a.test` (A),
`bob@tenant-b.test` (B). "anon" = a request carrying only the anon key (no user token).

## Planted bugs

| # | ID | Severity | Location (file:line) | Bug | Exploit |
|---|----|----------|----------------------|-----|---------|
| 1 | RLS-USING-TRUE | Critical | `supabase/migrations/20260708000002_rls.sql:31-32` | `documents` SELECT policy is `USING (true)` | Anon or any user reads every tenant's documents: `GET /rest/v1/documents` returns A's and B's rows. |
| 2 | RLS-AUTH-ROLE | Critical | `supabase/migrations/20260708000002_rls.sql:38-39` | `invoices` SELECT policy is `USING (auth.role() = 'authenticated')` — checks *logged-in*, not *which tenant* | Alice (Tenant A) reads Tenant B's invoices: `GET /rest/v1/invoices` returns both tenants' financial rows. |
| 3 | RLS-DISABLED | High | `supabase/migrations/20260708000002_rls.sql:41-43` (absence — `audit_logs` never gets `enable row level security`) | RLS is never enabled on `audit_logs` | Anyone with the anon key reads all tenants' audit trails via PostgREST. |
| 4 | SQLI-SERVICE | Critical | `pages/api/search.js:9` | Untrusted `q` concatenated into raw SQL run on the service DB connection | `GET /api/search?q=' UNION SELECT id, email, encrypted_password FROM auth.users --` exfiltrates password hashes. |
| 5 | WEBHOOK-REPLAY | Medium | `pages/api/webhook.js:20-24` | HMAC signature verified, but no timestamp/nonce check | Capture one valid signed request and POST it repeatedly; each replay re-inserts the side-effect (audit row) forever. |
| 6 | COUNTER-RACE | Medium | `pages/api/counter/increment.js:11-31` | Non-atomic read-modify-write on `counters.value` | Fire N concurrent `POST /api/counter/increment`; final value is < N because increments interleave and are lost. |
| 7 | UPDATE-UNSCOPED | High | `pages/api/profile/update.js:11-14` | `.update({ role })` with no `.eq()` scoping, via service role | `POST /api/profile/update {"role":"admin"}` sets `role=admin` on every profile in every tenant. |
| 8 | OPEN-REDIRECT | Low | `pages/api/redirect.js:9` | `z.string().url()` validates URL shape but not host (no allowlist) | `GET /api/redirect?url=https://evil.example/phish` issues a 302 to the attacker's host. |

## Severity coverage

- **Critical:** #1, #2, #4
- **High:** #3, #7
- **Medium:** #5, #6
- **Low:** #8

## Intended true-negatives (should NOT be flagged)

- `notes` — correctly tenant-scoped RLS (`rls.sql:15-19`).
- `counters` RLS policy — correctly tenant-scoped; the counter bug is in the API route, not the policy (`rls.sql:22-26`).
- `profiles` / `tenants` — self/own-tenant read policies (`rls.sql:5-13`).
- Webhook HMAC check — the signature comparison is correct and constant-time; only replay protection is missing.
