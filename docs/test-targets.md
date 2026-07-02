# Test targets — public repos to dry-run the audit against (#1502)

> **Authorized-testing guardrail.** Static review of public code is fine. **Dynamic (M2) testing runs ONLY
> against your own self-hosted clone** (your Supabase project, seeded data) — never a maintainer's live
> deployment or a live anon-key endpoint without written authorization. Clone → self-host → audit your instance.
> Star counts verified via `gh` on 2026-06-27; **none of these have been audited yet — listed as test
> *surface*, not as known-vulnerable** (except where noted).

## Bucket A — Realistic starter kits (best M1–M7 surface; popular = marketing value)

| Repo | ★ | Stack | Why |
|---|---|---|---|
| `vercel/nextjs-subscription-payments` | 7.7k | Next + Supabase + Stripe | Canonical subscription starter. Huge reach → a real finding here is high-impact (and a responsible-disclosure writeup). Likely well-hardened; webhook/idempotency/RLS surface still real. |
| `ShenSeanChen/launch-mvp-stripe-nextjs-supabase` | 1.0k | Next + Supabase + Stripe | **Top pick for the first dry run** — active, real auth + payments + RLS + webhook surface, big enough to be credible, small enough to fully audit. |
| `devtodollars/mvp-boilerplate` | 987 | Next + Supabase | Active boilerplate; good full-module target. |
| `makerkit/nextjs-saas-starter-kit-lite` | 441 | Next + Supabase | Free Makerkit lite; known brand; multi-tenant patterns. |
| `boxyhq/saas-starter-kit` | 4.8k | Next (NOT Supabase) | Enterprise multi-tenant + SSO/SAML. Partial fit — great for M3–M7 + generic security, but not the Supabase-specific M1. |

## Bucket B — Multi-tenant-specific (smaller, exactly the niche)

| Repo | ★ | Notes |
|---|---|---|
| `JakeLeoDev/proposit` | 4 | Open-source self-hosted multi-tenant Next + Supabase. Small but real tenant model. |
| `Wallens11/supabase-multi-tenant-starter` | 0 | "multi-tenant RLS, RBAC, auth middleware" — low-star/likely AI-generated → statistically high odds of the exact bugs you hunt (good calibration). |
| `AppBrewers/supabase-multi-tenant-starter`, `mrdave001/supabase-multi-tenant` | 0 | Same class: "Supabase multi-tenant SaaS starter with RLS." Cheap, find-something-likely targets. |

> Why the low-star ones matter: research found ~98% of vibe-coded apps had ≥1 security flaw. They're not
> marketing-worthy, but they're high-probability **calibration** that the scanner finds real issues.

## Bucket C — Calibration / ground truth

- **No DVWA-style intentionally-vulnerable Supabase repo exists** (confirmed — a gap; could be a content asset to *build*).
- **Build your own deliberately-broken target** (recommended): a tiny Next + Supabase app with seeded
  two-tenant data and planted bugs (`USING (true)`, `auth.role() = 'authenticated'`, a service-role route
  reachable from user input, an unguarded webhook). Gives **controlled ground truth** to calibrate the
  scanner's precision/recall — AND doubles as the **M2 seeded pen-test target** (#1505). Best ROI.
- Jorge Jarne's Medium demo — a live intentionally-vulnerable form app, for manual calibration.

## Tooling spotted (for M2, not targets)

- **SupaSec** — offensive RLS tester with a "Safe Exploit Mode": sends a malicious PATCH/DELETE with the
  `Prefer: tx=rollback,return=representation` header → the API evaluates RLS, returns the result, then rolls
  back in ms (zero production impact). Genuinely useful primitive for the M2 probe kit.
- `hand-dot/supabase-rls-checker` (119★) — defensive RLS presence checker (reference, not a target).

## Recommended first run (#1502)

1. **Primary:** `ShenSeanChen/launch-mvp-stripe-nextjs-supabase` — full M1–M7 dry run end-to-end.
2. **Calibration:** one self-built deliberately-broken target (ground truth) + one 0-star
   `supabase-multi-tenant-starter` (will-find-something).
3. **Stretch / marketing:** `vercel/nextjs-subscription-payments` — if a real, non-intentional finding turns
   up, responsible-disclose it and turn it into a teardown (credibility engine).

> Caution: starters often ship a permissive policy *intentionally* "for the demo." Confirm intent before
> calling it a vuln — don't cry wolf, especially on a Vercel-official repo.

## Sources
- https://vibeappscanner.com/supabase-security · https://vibeappscanner.com/supabase-row-level-security
- https://www.precursorsecurity.com/blog/row-level-recklessness-testing-supabase-security
- https://medium.com/@jorge.jarne/how-to-harden-your-lovable-supabase-setup-a-guide-to-row-level-security-cf290a61c0cf
- https://dev.to/fabio_a26a4e58d4163919a53/supabase-security-the-hidden-dangers-of-rls-and-how-to-audit-your-api-29e9
- https://github.com/hand-dot/supabase-rls-checker
