# The marketing engine (organic, $0)

Part of the Harvey GTM strategy (see `00-overview.md`). This is the operating system:
what gets made, where it goes, and the weekly cadence. Every channel below was verified
in a 2026-07-21 research pass (sizes/growth from GummySearch stat pages and fetched
community pages; items that couldn't be fetch-verified are flagged in `08-partnerships.md`
and the channel appendix at the end).

## The core loop

**Reputation → free scan → audit.** The engine has one job: make Harvey the recognizable
"Supabase code-quality person" — the go-to for *whether your codebase is actually ready*,
of which security is one part — and route the attention that earns into free scans that
convert to audits. (Security questions are the most common on-ramp and a fine place to be
helpful — just don't let the reputation collapse to "the security person"; the brand is
the QA leader, per `02-positioning-messaging.md`.) Four inputs feed the loop, in priority
order:

1. **Community answering** (reputation, evergreen SEO) — daily, low effort.
2. **Original research** (press, backlinks, AEO, notability) — the flagship, one big
   piece to start.
3. **Content that owns queries** (`06-seo-aeo.md`) — weekly, compounding.
4. **Build-in-public** (distribution, trust) — continuous, near-zero effort.

## Input 1 — Community answering (the daily habit)

Be genuinely useful in the rooms where the ICP already asks "is my app secure?"
Verified highest-leverage rooms:

- **r/vibecoding** (318k, +748% YoY) — the single best audience; self-promo tolerated,
  every member is the ICP with Harvey's exact fear.
- **Supabase Discord + r/Supabase** (43k sub; Discord large) — small but pure ICP;
  answering RLS/auth questions here builds the reputation everything else compounds on.
  The Supabase team notices consistent contributors.
- **Lovable Discord + r/lovable** (~160k Discord; 53k sub +288% YoY) — non-technical
  builders on Supabase who *know* they can't self-assess.
- **Cursor Forum** (forum.cursor.com, ~103k) and **Vercel Community v0 category** —
  Discourse forums; answers are Google-indexed, so participation IS evergreen SEO.
- **r/nextjs** (171k) — answer App Router auth/RLS questions (maps to Harvey's M9/M1);
  technical sub, naked promo is removed, so answer first and link only when asked.

Rule: value first, link only when it directly answers the question. The reputation is
the asset; the clicks are a byproduct.

## Input 2 — Original research (the flagship)

**This is the highest-leverage single action in the entire GTM.** Harvey is a scanner —
point it at a corpus of public vibe-coded Supabase apps (GitHub, Lovable/Bolt showcases)
and publish the aggregate findings:

> "We audited N public Supabase apps built with AI tools. X% had cross-tenant data
> exposure. Here's the breakdown."

Why it's the flagship:
- **Press & backlinks.** The existing incident coverage (The Register, TNW, XDA — see
  `01-market-competitive-analysis.md`) proves journalists cover this beat. Original data
  is what they cite. Every citation is a backlink (SEO) and a mention LLMs ingest (AEO).
- **Notability path.** This is the credible route to eventual Wikipedia-worthiness and
  to being the named authority answer engines quote (`06-seo-aeo.md`).
- **Proof of the product.** The research IS the product running. It doubles as the
  sample-report proof and the "here's what we find" sales artifact.
- **Distribution-ready.** Seed the writeup to curated newsletters (Input 3) and every
  community (Input 1) simultaneously.

Ethics guardrail: report aggregate/anonymized findings and follow responsible
disclosure for any specific live app (notify before publishing specifics; never publish
an exploitable detail against an identifiable app). This discipline is itself brand-
positive and keeps the research defensible. Do **not** cite the refuted "70% RLS
disabled" stat; generate Harvey's own number instead.

Cadence: one flagship to launch, then a lighter recurring version (quarterly "state of
vibe-coded security" update) as the funnel matures.

## Input 3 — Content that owns queries (weekly, compounding)

Detailed keyword/topic map and priority list live in `06-seo-aeo.md`. The engine here:
publish one substantial piece per week or two targeting a specific query where the
current results are weak. Formats that win in this niche (observed): **free checklist
tools** (SupaExplorer ranks ~#3 for "Supabase security checklist" with exactly this),
**how-to guides**, and **the flagship research**. The free-scan tool itself is the
ultimate "checklist that ranks."

Seed each substantial piece to curated newsletters that link good content for free:
**Next.js Weekly** (7k, exact ICP, submit links), **Bytes** (~105k, sponsor@fireship.dev
also curates), **TLDR Dev/Founders** (470k/380k, curated links), **Hungry Minds** (50k).
Master directory for later paid sponsorship: github.com/jackbridger/developer-newsletters.

## Input 4 — Build-in-public (continuous, ~0 effort)

Post the journey on X (#buildinpublic) and Indie Hackers: real anonymized findings
("found a cross-tenant read in 20 minutes"), the story of building a productized audit
service with AI agents, revenue milestones. Verified norms: Indie Hackers journey posts
with revenue numbers get featured in its newsletter for free; X vibe-coding security
fails go viral regularly — **be the expert voice every time the news cycle hits.**
See `07-social-presence.md` for the specifics.

## The launch moment: Show HN

When the free scan is runnable, **Show HN** is the single highest-leverage launch act.
Verified rules fit Harvey perfectly: it must be something people can *try* (the free
scan qualifies; a brochure page does not), no sign-up wall, author present to discuss.
One good Show HN outranks months of posting elsewhere. Time it for when the free scan
works end-to-end and the site can handle traffic.

## Weekly cadence (the actual routine)

| Cadence | Action | Time |
|---|---|---|
| Daily (15–30 min) | Answer 2–3 questions in Supabase/vibecoding/lovable/nextjs rooms | Low |
| Daily (5 min) | One build-in-public post or expert reply on X | Low |
| Weekly | Publish one query-targeting content piece; seed to newsletters | Medium |
| Weekly | One Indie Hackers / Reddit journey or war-story post | Low |
| One-time → quarterly | Flagship original research, then recurring updates | High once |
| On trigger | Expert take whenever a vibe-coding breach hits the news | Low |
| When ready | Show HN launch of the free scan | Medium |

## What we deliberately are NOT doing at $0

Paid ads, newsletter sponsorships, podcast sponsorships, conference booths, cold email
at scale. All are documented as "when the funnel proves out" upgrades (see the paid
ladder in `09-launch-checklist.md`), not launch activities. The one paid exception worth
considering early if any budget appears: a Next.js Weekly sponsorship (cheap, exact ICP).

## Podcasts (earned, not paid — pitch when there's a revenue story)

Verified pitchable shows, easiest first: **Indie Bites** (explicitly interviews small
bootstrapped founders — the easiest "yes"), then **Indie Hackers Podcast** and
**Startups for the Rest of Us** (pitch once Harvey has traction). **Syntax.fm** Potluck
episodes answer listener questions — submit "how do I secure my Supabase app." Theo
(t3.gg) and Fireship have no guest route but cover security-fail news eagerly — the
flagship research is how you get covered there.

## Channel appendix — verification status

Fetched/confirmed: r/vibecoding, r/lovable, r/cursor, r/nextjs, r/Supabase, r/SaaS,
r/SideProject, r/indiehackers sizes (GummySearch); Cursor Forum, Vercel v0 community,
Show HN rules, jackbridger newsletter directory, TLDR/Bytes/Next.js Weekly advertise
pages. Unverified (search-only, treat sizes as approximate): Supabase/Next.js/Lovable/
Bolt Discord member counts, Supabase/MicroConf YouTube sizes, Indie Hackers membership,
Theo/Fireship subscriber counts, X #buildinpublic community size. None of the unverified
items is load-bearing — they affect prioritization nuance, not the strategy.
