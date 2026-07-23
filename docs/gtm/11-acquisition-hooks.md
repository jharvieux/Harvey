# Acquisition hooks

Part of the Harvey GTM strategy (see `00-overview.md`). A hook is a specific felt pain or
trigger moment a founder is *already* searching, worrying, or getting triggered by — the
door we enter through. The brand ("QA leader in a box," `02-positioning-messaging.md`) is
the house. This doc catalogs the doors.

## The rule that keeps multiple hooks from fragmenting the brand

**Every hook is a separate door; the house is always the same.** Each hook gets its own
targeted content/landing page (its own SEO lane, its own outreach trigger), but all of
them funnel to the *one* free scan and the *one* whole-codebase readiness verdict. The
homepage stays the clean brand hub — hooks do not clutter it. Never build a "performance
product" or a "compliance product"; build performance-flavored *content* that lands on
the QA-leader brand. Using many doors is on-brand *because* Harvey is whole-codebase — a
single-issue competitor structurally cannot do this, and it hedges against any one
dimension's urgency fading.

## Two kinds of hook

- **Moment hooks** — a time-boxed event creates urgency and a nearby budget. Highest
  conversion; ideal for outreach and for landing pages that ride a deadline.
- **Felt-pain / search hooks** — an ongoing ache the founder googles. Ideal for SEO/AEO
  content lanes that compound over time.

---

## Moment hooks (deadline-driven — highest urgency)

### M-1 · Scalability / load-readiness — "can it survive the spike?"
**Modules:** M7 performance + M3 hotspots + M2 (load paths).
**The moment:** about to go live, launch a paid ad campaign, hit a Product Hunt / HN
front page, or a seasonal surge (Black Friday, back-to-school). A date and often a
spend are already committed.
**Door language:** "You're about to spend $8k driving traffic. Will the app survive it?"
· "Before launch day, know what breaks at 10×." · "Is your Supabase app ready for the
spike?"
**Why it's strong:** converts the vague "my app feels slow" ache into a deadline with a
dollar sign. A ~$1.5k readiness check is cheap insurance on a $10k campaign — the math
sells itself.
**Content/format:** "Load-readiness check" landing page; pre-launch/pre-campaign checklist.
**Companion felt-pain lane (keep both):** "my app feels slow" is itself a common, ongoing
user complaint founders actively search ("supabase slow query," "next.js app slow," "why
is my app laggy") — a compounding SEO lane distinct from the scalability *moment*. Same
M7 depth, different intent: the moment hook rides a deadline; the felt-pain hook rides a
recurring frustration. Run both — a "why your Supabase app feels slow" content piece
feeds the same free scan and readiness verdict. (Operator, 2026-07-21: keep "app feels
slow" alongside scalability — it's a common complaint and likely searched.)

### M-2 · Launch-readiness — "is it production-ready?"
**Modules:** all ten (the umbrella).
**The moment:** first public launch. **Door language:** "Is your app actually ready to
launch?" This is the QA-leader brand expressed as a search term; every other hook nests
under it.

### M-3 · Fundraise / acquisition due diligence — "investor-ready"
**Modules:** all ten, packaged as the diligence verdict (the "investor-ready summary,"
`03-pricing-packaging.md`). **The moment:** raising or being acquired. High willingness
to pay. **Door language:** "What a technical DD will find in your AI-built codebase."

### M-4 · Enterprise deal / security questionnaire — "unblock the deal"
**Modules:** M1/M2/M10 lead, full audit delivers. **The moment:** a vendor security
questionnaire gates a first big contract (the strongest paid trigger from the prior
research — `10-old-docs-crosscheck.md`). Reframes audit spend as a revenue unlock with a
deadline. **Door language:** "Unblock the {BigCo} security review."

---

## Felt-pain / search hooks (compounding content lanes)

### F-1 · Security — "is my Supabase app secure?"
**Modules:** M1 + M2 + M10. The verified-demand acquisition hook (`06-seo-aeo.md`):
highest existing search volume and news-cycle attention. The most common on-ramp — but a
*door*, never the frame. Content: the security service page, per-platform pages,
issue-response Q&A pages.

### F-2 · "AI slop" — "how much junk did the AI leave in your codebase?"
**Modules:** M5 dead code + M6 maintainability + M4 duplication.
**Framing guardrail (important):** point "slop" at the **AI, not the founder**. "The AI
left slop behind — we find it and clean it up." The founder is the hero doing the
responsible thing; "your code is slop" shames the buyer and breaks the empathy pillar.
**Door language:** "How much AI slop is in your codebase?" · "Find the AI slop before
your users do." · "The dead weight your AI assistant left behind."
**Why it's strong:** a term the ICP already uses about themselves; punchy, searchable,
shared-enemy framing.
**Content/format:** "AI slop check" content piece; original-research angle ("we measured
the AI slop in N public apps").

### F-3 · The re-fixing trap — "why do you keep fixing the same three files?"
**Modules:** M3 hotspots + M4 duplication + M6 maintainability + M8 test quality — the
felt version of the entire *code-health half* of the suite in one pain.
**The pain:** "Every change to this part breaks something." · "I fixed this bug last
month and it's back." · "One area eats all my time."
**How the modules explain it:** hotspots = the complex, high-churn files where bugs
recur; duplication = you fixed one copy, the others still have it; maintainability =
fragile hand-rolled code; test quality = nothing catches the regression, so it returns.
**Door language:** "The 3 files causing 60% of your bugs." · "You fixed it once — here's
the copy you missed." · "Stop re-fixing the same modules."
**Why it's strong:** a purely felt pain (nobody searches "churn × complexity") that opens
the whole non-security half of the product. On-brand for a *quality* leader.

### F-4 · Compliance / sensitive data — "where's my PII / am I compliant?"
**Modules:** M10 data classification (+ M1). **The pain/trigger:** GDPR anxiety, handling
health/payment data, a customer questionnaire. Overlaps M-4 but is a distinct search
behavior. **Door language:** "Where is your users' PII actually sitting?" · "Find every
unprotected sensitive column." Prioritize if early customers handle regulated data.

### F-5 · Test quality — "my AI-built app has no real tests."
**Modules:** M8. Moderate search intent, but premium **content/AEO fuel** — the "41% of
your tests can't actually catch a bug" framing is striking and shareable, and testing is
QA's home turf (maximally on-brand). Best expressed as an original-research stat.

---

## Priority at $0 budget

Don't work all nine at once. Sequence:

1. **F-1 Security** — already has verified demand; the launch on-ramp.
2. **M-1 Scalability/load-readiness** — highest-urgency moment hook, distinct lane, real
   M7 depth.
3. **F-3 The re-fixing trap** *or* **F-2 AI slop** — pick one to open the code-health
   half; both are on-brand and emotionally resonant. (F-3 is broader; F-2 is punchier.)
4. **M-2 Launch-readiness** — the umbrella; cheap to stand up since it's the brand itself.

Add **F-4 compliance** and **M-3 diligence** as the customer base reveals regulated-data
and fundraising segments. **F-5 test quality** rides along as content/research, not a
standalone lane.

## Demand-validation status

**Verified (2026-07-21 SEO pass):** the F-1 security query cluster only. **NOT yet
measured:** search demand and current rankers for scalability/load-readiness, AI-slop,
re-fixing/maintainability, compliance, and test-quality queries. Per repo discipline
("measure, don't recall"), validate the top new lanes (M-1, F-2/F-3) with a search pass
before committing content effort — don't assume volume.

## How hooks connect to the rest of the strategy

- **SEO/AEO (`06-seo-aeo.md`):** each felt-pain hook is a content lane / cluster of pages.
- **Marketing engine (`04-marketing-engine.md`):** moment hooks drive outreach timing;
  original research can be run per hook (AI-slop stat, hollow-tests stat).
- **Positioning (`02-positioning-messaging.md`):** every hook page's copy ladders back to
  the three QA-leader pillars and routes to the free scan.
- **Pricing (`03-pricing-packaging.md`):** moment hooks (scalability, launch, diligence)
  justify the paid tiers against a nearby budget.
