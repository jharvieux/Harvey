# Website plan

Part of the Harvey GTM strategy (see `00-overview.md`). The site is the hub every
channel points into; its one job is to convert attention into free scans, and free
scans into audit conversations.

## Conversion architecture

One primary call to action everywhere: **"Run the free scan."** Secondary CTA for
high-intent visitors: **"Book an audit call."** Everything else on the site exists to
make those two credible.

Funnel: content/community/AEO → landing page → free scan (email + repo access or
upload) → scan report delivered → follow-up sequence → audit call → engagement.
The free scan is the lead magnet; the report it produces is the sales letter.

## Pages (launch set, in build order)

1. **Home** — positioning statement, the three pillars (`02-positioning-messaging.md`),
   a real (anonymized) finding as the hero proof, the ten-module grid, free-scan CTA.
   Must pass the "worried founder at 11pm" test: within 10 seconds they know this is
   for Supabase apps, it's a real audit not another scanner, and there's a free way in.
2. **Free scan page** — what the mechanical tier actually checks (honest scope: what
   free does vs. what the paid audit adds — the coverage-honesty brand applied to our
   own pricing page), how repo access works, what the report looks like (show a
   sample), privacy/handling commitments.
3. **The audit (methodology) page** — the ten modules explained in founder language,
   the coverage ledger explained ("we show you what we didn't check and why"), the
   dynamic pen-test explained (two seeded tenants, live cross-tenant probing), sample
   report download (gated on email).
4. **Pricing page** — per `03-pricing-packaging.md`. Publish prices (the boutique
   competitors' unpublished pricing is a friction point we exploit; verified:
   VibeAudits publishes none).
5. **Sample report** — a full anonymized report as a web page + PDF. This is the
   single highest-converting asset a productized service has; nobody in the surveyed
   competitive set shows one.
6. **About/trust page** — who's behind it, methodology provenance, responsible-
   disclosure policy, data-handling (what we do with repo access, retention, deletion).
7. **Blog/research** — the content engine (`04-marketing-engine.md`, `06-seo-aeo.md`).
   Lives at /blog with the flagship checklist/research pieces as standalone URLs.

Later (post-launch): case studies, re-audit/diff offering page (repeat-customer
`--baseline` feature is already built), agency/partner page.

## Technical decisions

- **Stack: Next.js on Vercel.** Non-negotiable irony: the site for a Next.js audit
  service must itself be a clean, fast Next.js app. It will be dogfooded — Harvey's
  own audit runs against it, and `pnpm lighthouse-scan` gates its Core Web Vitals.
  Publishing a "Harvey audited its own website" page is both QA and marketing.
- **Static-first, App Router, no client-side bloat.** Target green Core Web Vitals
  and a Lighthouse performance score ≥95; the site is itself a proof point.
- **Email capture: Resend** (already integrated in our tooling) — scan-report
  delivery, follow-up sequence, and later a newsletter list. Double opt-in for the
  newsletter; transactional for scan reports.
- **Payments (later): Stripe** — deposit/checkout for audit bookings once pricing is
  validated; not needed at launch (calls close the first engagements).
- **Analytics: Vercel Analytics** at launch (zero-config, privacy-friendly); add GA4
  only if attribution needs outgrow it.
- **Free-scan intake at launch = manual behind the scenes.** A form (repo URL or
  GitHub app install → we run `run-audit` locally → report emailed within 24h) ships
  weeks before any self-serve automation. Do not block launch on building a scan
  pipeline; the productized-service phase runs it by hand. Automation is the
  scale-phase investment.

## SEO/AEO plumbing (built-in from day one — details in `06-seo-aeo.md`)

- Schema.org markup: `Organization`, `Service`, `FAQPage` on methodology/pricing,
  `Article` on posts.
- `llms.txt` at the root describing what Harvey is, for answer engines.
- Clean semantic HTML, per-page meta, OpenGraph images, sitemap, fast TTFB.
- Blog URLs designed around target queries, not clever titles.

## Domain

Blocked on the naming decision (`02-positioning-messaging.md` — "Harvey" collides
with harvey.ai for search). Once decided, purchase via Vercel or any registrar;
`09-launch-checklist.md` tracks it. Until then, everything above can be built and
previewed on a vercel.app URL.

## Build & measurement

Build effort is small by design: shadcn/ui + Tailwind, ~7 pages, one form. The
constraint is copy quality, not engineering. Measure from day one: free-scan
conversion rate (target: learn, then optimize), scan→call rate, call→engagement rate.
Those three numbers ARE the GTM dashboard.
