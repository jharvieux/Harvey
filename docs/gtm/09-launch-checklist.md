# Launch checklist — sequenced setup

Part of the Harvey GTM strategy (see `00-overview.md`). This turns the strategy into an
ordered task list, grouped by what blocks what. Nothing here needs paid tools; the only
hard blockers are operator decisions and account creation.

## Gate 0 — Decisions only the operator can make (blocks everything downstream)

- [x] **Name / brand decision — DONE (2026-07-22).** Brand: **Harvey**. Primary domain:
      **`harvey-qa.com`** (chosen after `harvey.review` was taken at purchase). Defensive:
      consider the no-hyphen `harveyqa.com`. All public assets use "Harvey" as the entity
      name; never compete for the bare "Harvey" query (harvey.ai owns it). See
      `02-positioning-messaging.md`.
- [ ] **Confirm the size-banded pricing grid** (LOC-banded: small $500/$1,500 →
      enterprise custom, `03-pricing-packaging.md`) — or approve treating the first ~5
      engagements per band as price discovery. (Supersedes the old flat $2k/$5k anchors.)
- [ ] **Confirm ICP/scope** is Supabase+Next.js indie/small-SaaS (vs. broadening).

## Gate 1 — Accounts to create (all free; operator, one-time)

- [ ] Register `harvey-qa.com` (primary) + optionally `harveyqa.com` (no-hyphen defensive
      redirect), via Vercel plugin once authenticated, or any registrar.
- [ ] Vercel account (site hosting; plugin installed, needs first-time auth).
- [ ] Resend account (scan-report delivery + newsletter; plugin installed, needs auth).
- [ ] GitHub org (the entity + a home for any open-source detector/tool).
- [ ] LinkedIn company page.
- [ ] X account.
- [ ] Crunchbase profile (AEO entity — `06-seo-aeo.md`).
- [ ] Google Search Console + Bing Webmaster Tools (free; verify site ownership; Bing
      feeds ChatGPT search, so it matters for AEO).
- [ ] Stripe account (payments — only needed at Rung 2, defer if closing by call first).

## Gate 2 — Build (I can do all of this; small effort, copy-quality is the constraint)

- [ ] Website: the 7 launch pages (`05-website-plan.md`) — Next.js on Vercel, static-
      first, green Core Web Vitals (dogfood `pnpm lighthouse-scan` on it).
- [ ] SEO/AEO plumbing: schema.org markup, `llms.txt` + `llms-full.txt`, sitemap,
      per-page meta, OG images (`06-seo-aeo.md`).
- [ ] Sample report (anonymized) as web page + gated PDF — highest-converting asset.
- [ ] Free-scan intake form (manual backend at launch: form → run `run-audit` locally →
      email report within 24h). Do NOT block launch on scan automation.
- [ ] The first-priority content pieces (`06-seo-aeo.md`): service page, the Supabase
      security checklist, the multi-tenant leak pillar guide.
- [ ] Consistent entity description across site/GitHub/LinkedIn/Crunchbase.

## Gate 3 — First distribution (organic, ongoing)

- [ ] Apply to the Supabase partner program, both tracks (`08-partnerships.md`) — do
      early, review takes time.
- [ ] Census supabase.com/partners/catalog to validate/kill the "first security-audit
      partner" claim before using it.
- [ ] Start the daily community-answering habit (`04-marketing-engine.md`): Supabase
      Discord + r/Supabase first, then r/vibecoding, r/lovable, r/nextjs.
- [ ] Start build-in-public on X + Indie Hackers.
- [ ] Begin the flagship original-research audit-of-N-apps (`04-marketing-engine.md`) —
      the single highest-leverage asset; it feeds press, AEO, and the sample report.

## Gate 4 — The launch spike (when the free scan works end-to-end)

- [ ] Show HN of the runnable free scan (`04-marketing-engine.md`) — must be try-able,
      no sign-up wall, author present to discuss.
- [ ] Publish + seed the flagship research to curated newsletters (Next.js Weekly,
      Bytes, TLDR Dev, Hungry Minds) and every community simultaneously.
- [ ] Pitch Indie Bites (easiest podcast yes), then the founder-podcast ladder.

## Gate 5 — Direct outreach in parallel (highest-quality channel)

Carried forward from prior research and re-validated — see `10-old-docs-crosscheck.md`:

- [ ] **Trigger-based outreach** on the strongest paid trigger: the **enterprise vendor
      security questionnaire** (a stalled deal becomes a deadline-driven revenue unlock).
      Signals: hiring first enterprise AE, "SOC 2 in progress," "we just landed {BigCo},"
      fundraise announcements.
- [ ] **Free-audit-for-case-study asks** to 3–5 raising/enterprise-chasing founders (the
      finding is the pitch; testimonial + anonymized-writeup permission in exchange).
- [ ] **Partner outreach** to SOC 2 / compliance shops and fractional CTO/CISO firms —
      SOC 2 explicitly excludes auth/tenant-isolation code review, so Harvey is a clean,
      non-competing referral. (This complements the Supabase/agency partnerships in
      `08-partnerships.md`.)
- Note: single-touch cold email has collapsed (~0.3% reply rates in 2026) — layer
  email + LinkedIn, lead with the trigger/partnership, keep it a light 2-touch sequence.

## The paid ladder (ONLY when the organic funnel proves out — not a launch item)

In rough spend order, cheapest/highest-ICP-fit first:
1. Next.js Weekly sponsorship (cheap, exact ICP).
2. Syntax.fm episode sponsorship (documented 10x-ROI case in the niche).
3. TLDR Dev (470k) / TLDR Founders (380k) custom proposals.
4. Bytes (~105k) via sponsor@fireship.dev.
5. Search ads on the weak-competition commercial queries (`06-seo-aeo.md`).
Master newsletter directory: github.com/jackbridger/developer-newsletters.

## The three metrics that ARE the dashboard

Track from day one (`05-website-plan.md`): free-scan conversion rate, scan→call rate,
call→engagement rate. Everything else is an input to these.

## What I can do vs. what needs the operator

**I can:** build the entire site, write all content, draft all posts/outreach, run the
flagship research (Harvey scanning public apps), prepare the partner applications,
maintain the content queue and metrics. **Operator must:** make the Gate 0 decisions,
create the accounts (Gate 1, under their identity), authenticate the Vercel/Resend/Stripe
plugins when we reach them, approve/post social content, and hold the sales calls.
