# SEO / AEO strategy (and the Wikipedia question)

Part of the Harvey GTM strategy (see `00-overview.md`). Grounded in a 2026-07-21 pass
that ran 19 live searches and fetched competitor pages. Observations marked **[observed]**
come from actual search-result/page inspection; **[inferred]** is judgment on top.

## The landscape in one paragraph [observed]

A cluster of small purpose-built "vibe security" sites has already colonized this niche —
**vibeappscanner.com** (appeared in 8 of 19 searches), **vibe-eval.com**, **checkvibe.dev**,
**supaexplorer.com**, **ubserve.com**, **zeriflow.com** — all running the same playbook:
free tool → checklist pages → per-platform guides → question pages → llms.txt. Supabase's
own docs own the "how do I secure it myself" queries. Enterprise vendors (Wiz, Snyk,
Checkmarx, Veracode) own the generic head terms. **The conspicuous gap: almost nobody
ranks with a productized *audit service* page, and the "what does it cost" query is a total
content vacuum.** The niche is saturated with free scanners and starved of "pay an expert
to audit it for you" — which is exactly what Harvey sells.

## Strategic principle

**Copy the proven traffic playbook (tool + checklists + per-platform + question pages),
and own the uncontested commercial layer (service pages + transparent pricing) that no
scanner site can credibly write.** Avoid the head terms owned by enterprise vendors and
Supabase docs; win the founder-intent long tail and the buyer-intent service queries.

## Brand framing vs. SEO depth (2026-07-22)

The homepage now brands broadly — **"Codebase QA for AI-Generated Apps"** — to match the
buyer's own identity and catch the wide "AI-generated apps / vibe-coded app" framing. But
the **SEO depth stays stack-specific**: the content lanes below (Supabase, Next.js, Vite,
RLS) are where demand is verified and competition is thin, and that's where ranking is
won. The broad terms are the homepage/brand layer; the stack queries are the content
layer.

**Keep "code" discoverable even though the title says "apps."** Title uses "apps"
(operator choice), so "AI-generated **code**" is carried by the meta description, the
`keywords` (`AI generated code audit`, `AI code security audit`), the `llms.txt`
(explicit synonyms), and body copy ("the code your AI wrote/generated"). Both phrasings
must stay present so answer engines match either. Verify periodically that "code" queries
still surface Harvey.

## Query map — where to fight

**Weak competition, high commercial intent — attack first [observed]:**
- "supabase security audit" — Supabase's own results are about *its* audits, not
  auditing *your* app; a LinkedIn post and a GitHub markdown file currently rank. Prime.
- "supabase pentest" / "supabase penetration testing service price" — GitHub tools and a
  total pricing vacuum. Harvey's M2 live pen-test is a real differentiator here.
- "multi-tenant security supabase" — no authoritative treatment exists; Harvey's exact
  specialty. High strategic value, lower volume.
- "AI code audit service for non-technical founders" — SERP is rescue agencies and a
  Gumroad listing. This query is Harvey's buyer described verbatim.
- "supabase RLS audit" — forum posts and Chrome extensions; no strong domain.

**Medium competition, winnable with a better artifact [observed]:**
- "supabase security checklist" (crowded — 7 small sites; SupaExplorer ~#3 confirmed),
  "lovable app security audit," "bolt.new app security check," "next.js security audit"
  (Arcjet is the only strong brand; the Next.js+Supabase *combination* is unclaimed),
  "security audit before fundraise," "before launch security checklist saas."

**Strong competition — avoid head-on, take the long tail:**
- "vibe coding security," "AI generated code security audit," "supabase row level
  security best practices" (Supabase docs + Makerkit entrenched), "supabase production
  readiness checklist" (official docs own it).

## First 10 content pieces (priority order)

Format for each is chosen to match what demonstrably ranks for that query [observed]:

1. **Service page — "Supabase Security Audit: a real audit, not a scanner."** The
   uncontested commercial query. Include a scanner-vs-audit comparison table, the
   ten-module methodology as differentiating content, and explicit pricing (fills the
   pricing vacuum). Targets "supabase security audit," "supabase pentest," "hire a
   supabase security expert."
2. **Free tool — web-based Supabase/RLS security checker (URL in → findings out).** The
   single highest-leverage build: it's both the top-of-funnel SEO magnet (every
   successful competitor leads with a free tool that earns the GitHub/HN/forum links
   powering the whole domain) AND the lead-gen mechanism. Expose a thin anon-key-probe
   slice of Harvey's existing detection logic.
3. **"The Supabase Security Checklist" — the definitive version.** Interactive checklist
   (the locked-in winning format) with a "can a scanner catch this, or does it need a
   live test?" column no competitor has. Targets the crowded-but-central checklist query.
4. **Pillar guide — "Multi-tenant security in Supabase: how tenant data actually leaks."**
   Weakest SERP, strongest Harvey fit. Harvey's core IP written down; earns topical
   authority for the whole cluster.
5. **Per-platform audit pages — Lovable, then Bolt, then Cursor/Replit/v0.** "[Platform]
   security: what it generates wrong + how to check yours." VAS and VibeEval prove the
   template; Lovable first.
6. **Service-page variant — "AI-built app security audit for non-technical founders."**
   Plain-English, sample-finding excerpt. The positioning (founder never reads a diff)
   IS the page.
7. **Original-research report — "We audited N vibe-coded Supabase apps; here's what we
   found."** Also the marketing-engine flagship (`04-marketing-engine.md`). The single
   strongest AEO play (see below).
8. **"Next.js + Supabase security: the full-stack audit guide."** Owns the unclaimed
   combination.
9. **"Pre-fundraise security audit: what investors' technical DD will find."** Validated
   angle (DevBrows ranks for it); Harvey's report is literally the DD artifact.
10. **Issue-response Q&A pages — "exposed anon key — is it bad?", "service_role key in
    frontend — what now," "RLS disabled — impact."** The 2am-panic long tail; the pages
    AI assistants quote when a founder pastes an error or a Supabase warning email.

## AEO (answer-engine optimization) — verified tactics

Answer engines (ChatGPT, Claude, Perplexity, Google AI overviews) are how this audience
increasingly discovers answers. What the pass verified [observed]:

1. **Quotable statistics are the currency of AI answers.** The AI answer layer repeatedly
   reproduced the same handful of stats verbatim ("83% of exposures trace to RLS
   misconfiguration," "63% of 62 Lovable apps had critical findings," CVE-2025-48757),
   each traceable to one small site's original research. **Harvey's original-research
   report (#7) is the highest-ROI AEO investment** — publish one memorable, precisely-
   worded, Harvey-generated stat at a stable URL. (Do not reuse the refuted "70% RLS
   disabled" number — generate our own.)
2. **Ship `llms.txt` and `llms-full.txt` at launch.** checkvibe.dev publishes a thorough
   `llms-full.txt` and holds the #1 checklist spot; half the niche hasn't done it. Cost
   is near zero. Curated index + full content dump.
3. **Question-format pages with answer-first intros.** Every AI answer summary led with a
   1–2 sentence definitive claim. Every Harvey page opens with the direct answer in the
   first 50 words, then depth. Use H2-as-question headings.
4. **Add the JSON-LD the competitors skip.** The inspected competitor page had FAQ
   content but no `FAQPage`/`HowTo`/`Article` JSON-LD. Harvey ships proper structured
   data — a cheap structural edge — plus `Organization` and `Service` schema.
5. **Anchor to CVEs and named incidents.** LLMs latch onto stable entities (CVE-2025-48757,
   the Tea app breach, Moltbook). Reference them; consider a maintained "Supabase/vibe-app
   security incident timeline" as a citable reference asset.

## The Wikipedia question — answered

**Do not attempt a Wikipedia article now. It would fail and leave a lasting scar.**

- **Notability (WP:NCORP)** requires significant coverage in multiple independent,
  reliable sources — journalists/analysts writing about Harvey unprompted. A pre-press
  venture has none; the article gets declined at review or speedy-deleted.
- **Conflict of interest**: a founder (or an agent acting for them) creating their own
  company's page is exactly what WP:COI targets — must be disclosed, goes to a review
  queue, and reviewer instinct on founder-written startup pages is deletion.
- **The scar**: a deletion leaves a public log tied to the name, and recreation attempts
  get extra scrutiny. Trying early makes it *harder* later.

**What to do instead — the AEO-equivalent authority stack (do these now):**
- **Crunchbase** profile (free; feeds LLMs and Google knowledge panels).
- **LinkedIn company page** + **GitHub org profile** (both feed answer engines and rank
  for the brand name).
- **Schema.org `Organization` markup** on the site so Google/LLMs parse the entity.
- **A consistent "about" entity** repeated identically across Crunchbase/LinkedIn/GitHub/
  site — this is what builds a machine-readable identity, which is 90% of what a
  Wikipedia page would have done for discovery anyway.
- **Get mentioned in the sources LLMs ingest** — the original research earning newsletter
  and press coverage (`04-marketing-engine.md`) is the same motion that builds real
  Wikipedia notability over time.

**The real path to Wikipedia (12–24 months out):** publish original research → earn
independent press citations → *those citations* become both lead gen now and the
reliable-source notability basis later. When multiple independent outlets have covered
Harvey on their own initiative, an editor (ideally not us) can create the article and it
will survive. Revisit then, not now.

## Measurement

Track: brand-name SERP (do we own our own name — remembering "Harvey" bare is
unwinnable, see naming note in `02-positioning-messaging.md`), rankings for the top-5
priority queries above, free-tool referral traffic, and whether AI assistants cite
Harvey when asked "how do I audit my Supabase app's security" (test quarterly by asking
them). The last one is the AEO scoreboard.
