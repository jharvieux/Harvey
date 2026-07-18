# Harvey recall measurement — vandyand/saas-security-teardown

**Date:** 2026-07-18
**Target:** `vandyand/saas-security-teardown` ("Practice Portal"), a deliberately-vulnerable
multi-tenant Supabase/Next.js SaaS. Cloned to `/private/tmp` (ephemeral, deleted after).
**Answer key:** the repo's `README.md` documents exactly **8 planted findings**, and the
`fixed` branch's `git diff main..fixed` is the authoritative fix-for-fix key
(`supabase/migrations/0002_fix_rls.sql` + app/lib route edits + deletion of
`lib/supabase/admin-browser.ts`).

This is a MEASUREMENT — every caught/missed below is grounded in a Harvey run's actual
output observed on this date, not recall. No Harvey source was changed.

## How Harvey was run

- **M1 static (mechanical):** `pnpm quick-scan --dir <target> --findings-out <f>` — 25 raw findings.
- **M1 static (schema/RLS):** the migration-RLS pass inside quick-scan + `pnpm detect-static`.
- **M2 dynamic (autonomous):** `pnpm dynamic-validate <target> --execute --out <dir>` — stood up a
  local Supabase (`supabase start`), applied the client migrations, created two auth users + a
  generic two-tenant seed, ran the live PostgREST cross-tenant matrix (Tier 1), then
  `next build && next start` + the app-route/seam probes (Tier 2). Reported **full coverage, 5
  proven findings**. Stack was torn down (`supabase stop`) after.
- **M10:** `pnpm pii-classify --schema <target>/supabase/migrations` — corroborates the
  sensitivity behind #8.

## The answer key (8 planted findings)

| # | Finding | Class | Location |
|---|---------|-------|----------|
| 1 | RLS never enabled on `orgs` | RLS-off table (anon enumerates tenants) | `supabase/migrations/0001_init.sql` |
| 2 | `line_items` has no policy | RLS-off child table (side-door leak) | `supabase/migrations/0001_init.sql` |
| 3 | `profiles` policy is `using (true)` | Broken RLS → cross-tenant read | `supabase/migrations/0001_init.sql` |
| 4 | service-role key shipped to browser | Secret exposure / full RLS bypass | `.env.example`, `lib/supabase/admin-browser.ts`, `components/StatsWidget.tsx`, `app/security/page.tsx` |
| 5 | admin API has no server-side role check | Broken function-level authz (missing role check) | `app/api/admin/revenue/route.ts` |
| 6 | server trusts client input (mass assignment) | Mass-assignment / privilege escalation | `app/api/profile/route.ts` |
| 7 | storage bucket is public | Public bucket / broken object authz | `scripts/seed.mjs` (`createBucket(..., {public:true})`) |
| 8 | PII over-exposure via `select('*')` | Excessive data exposure | `app/api/team/route.ts` |

## Score — 6 caught / 8, +1 partial, 1 missed

| # | Status | By module | Evidence |
|---|--------|-----------|----------|
| 1 | **CAUGHT** | M1 static | `Migration table without RLS (static): public.orgs is created but never gets RLS enabled` — Critical, `0001_init.sql:9`. (M2 did not probe `orgs` — it's the tenant-parent table, outside the scoped-probe set.) |
| 2 | **CAUGHT** | M1 static | `Migration table without RLS (static): public.line_items is created but never gets RLS enabled` — Critical, `0001_init.sql:38`. (M2 structurally cannot reach it — no tenant column, so it is not in the seeded/probed surface; see gap note.) |
| 3 | **CAUGHT** | M1 static (indicator) + **M2 dynamic (PROVEN)** | M1: `M1 — Multi-tenant security: RLS policy public.profiles.Profiles are viewable by authenticated users — semantic tenancy review` (High?, indicator). M2 proved it live: 4 findings — anon + Tenant A + Tenant B + Admin each read cross-tenant `profiles` rows (`anon read 2 row(s)... RLS off or USING(true)`). |
| 4 | **CAUGHT** | M1 static | `harvey-service-role-in-client` (Critical) fired twice — `app/security/page.tsx:12` and `lib/supabase/admin-browser.ts:19` — plus two `harvey-missing-server-only` (Low) on `lib/supabase/admin.ts`, `scripts/seed.mjs`. |
| 5 | **PARTIAL** | M1 static (heuristic only) | `Unauthenticated debug/admin route: app/api/admin/revenue/route.ts looks like a debug/seed/admin/dev route with no auth-call hint` (High) — flags the exact vulnerable file, but by a filename+missing-recognized-auth-call heuristic, not by modeling the real bug (route authenticates via `getUser` but never checks `role`). M2's app-route probes ran but none models "admin endpoint reachable by a member," so #5 was not proven live. Right file, wrong mechanism → partial. |
| 6 | **CAUGHT** | **M2 dynamic (PROVEN)** | `M2-APP-MASS-ASSIGNMENT` (Critical): `PATCH /api/profile {"role":"HARVEY_MASS_ASSIGN_ROLE"}` → `write accepted; profiles now carries role="HARVEY_MASS_ASSIGN_ROLE"`. (M1's `harvey-route-noauth` also fired on `app/api/profile/route.ts:19`, but with a false premise — the route does call `getUser` — so it does not itself model the mass-assignment; the real catch is M2.) |
| 7 | **MISSED** | — | No detector fired for the public bucket. Harvey HAS `checkPublicBucketsWithNoPolicies`, but it is the **connected/live-storage** tier (reads `storage.buckets`); it is never fed here because (a) statically, `createBucket(..., {public:true})` in `scripts/seed.mjs` is not modeled, and (b) the M2 autonomous stand-up neutralizes the client's own seed and never runs `scripts/seed.mjs`, so the public bucket is never created in the local stack. The adjacent `Upload to storage with no size/MIME limit` (seed.mjs) is a different class. |
| 8 | **CAUGHT** | M1 static (+ M10 corroboration) | `harvey-select-star-pii` (Medium) on `app/api/team/route.ts:32`: `A select("*") result is returned directly in an API response`. M10 `pii-classify` corroborates: `profiles → High (5.6): EMAIL, NAME, US_SSN`. |

**Tally: 6 caught / 8 total (75%)**, plus 1 partial (#5, right file/heuristic flag) and 1 clean
miss (#7). If the partial is credited as "flagged in some form," 7/8 surfaced and only #7 was
wholly invisible.

By tier:
- **M1 static** solidly caught: #1, #2, #4, #8 (4); flagged #3 as an indicator; heuristically
  flagged #5 (partial).
- **M2 dynamic** proved: #3, #6 (2).
- **#3** is the both-tiers case: a static indicator later confirmed live.
- **M10** corroborated the sensitivity behind #8.

## Harvey findings NOT in the answer key

All appear to be legitimate (no false positives against the app's real behavior), just outside the
planted-8 set:
- 6× known-vulnerable dependency (esbuild, postcss, vite×3, vitest) — real CVEs, dev-tier deps.
- Missing CSP / security headers.
- `Sensitive value logged to console` (`scripts/seed.mjs` prints the seed password).
- `Upload to storage with no size/MIME limit` (`scripts/seed.mjs`) — adjacent to #7, different class.
- Unpinned dependency ranges; M6 hand-rolled-currency indicators ×4; M5/M7/M9 quality/perf findings from `detect-static`.

One finding is a **wrong-premise-but-lands-on-a-real-bug** case worth noting: `harvey-route-noauth`
on `app/api/profile/route.ts` claims "no auth-check call anywhere in the function," but the route
does call `getUser(req)` (a custom wrapper the rule doesn't recognize). It happens to point at the
genuinely-vulnerable #6 file, but its stated reason is false — a near-false-positive.

## Gaps to fix (filed as follow-ups)

Filed: **jharvieux/Harvey#560** (public-bucket gap) and **jharvieux/Harvey#561** (broken
function-level authz gap).

1. **#7 miss — public storage bucket is invisible on the source + autonomous-dynamic paths.** (#560)
   Static: no rule models `storage.createBucket(..., {public:true})` in app/seed code. Dynamic:
   the M2 stand-up deliberately neutralizes the client seed (correct, so a broken client seed
   can't block stand-up) but therefore never creates buckets the seed would — so the live
   `checkPublicBucketsWithNoPolicies` never sees them either. A public-bucket vuln created by app
   seed code slips through every non-connected tier.
2. **#5 partial — "authenticated but no role check" (broken function-level authz) is only
   heuristically flagged.** (#561) Harvey flags admin-ish routes by filename, and the app-route probes
   don't include an "admin endpoint reachable by a lower-privilege member" check, so a missing
   server-side `role` gate is never modeled/proven.

## Notes on M2 scope (verified, not recalled)

The M2 generic two-tenant seed (`src/pentest/two-tenant-seed.ts`) seeds only tables with a
recognized tenant column (`org_id`/`tenant_id`/...). In this schema that is `profiles`, `invoices`,
`documents`. `line_items` (keyed by `invoice_id`, no org column) and `orgs` (the tenant parent) are
outside the probe surface — so M2 structurally cannot reach #1 or #2 (both caught by M1 static
instead). `invoices` and `documents` WERE probed and correctly did NOT leak (true negatives — their
0001 policies are correct), a good precision signal.
