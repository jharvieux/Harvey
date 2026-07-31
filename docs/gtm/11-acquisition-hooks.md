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
   M7 depth. **Shipped 2026-07-30** (`/supabase-load-readiness`, refs #728).
3. **F-3 The re-fixing trap** — chosen over F-2 AI slop (operator ruling 2026-07-30,
   #1537: F-2's positioning is contested by several vendors; F-3's founder-facing framing
   is an open door). **Shipped 2026-07-30** (`/re-fixing-the-same-files`, refs #1537).
4. **M-2 Launch-readiness** — the umbrella; cheap to stand up since it's the brand itself.

Add **F-4 compliance** and **M-3 diligence** as the customer base reveals regulated-data
and fundraising segments. **F-5 test quality** rides along as content/research, not a
standalone lane.

## Demand-validation status

**Verified (2026-07-21 SEO pass):** the F-1 security query cluster (19 live searches,
competitor pages fetched — `06-seo-aeo.md`).

**Verified (2026-07-30 pass, #728):** a second live-search pass (14 searches, results
read, no keyword-volume tool available — so this is competitor/content-density evidence,
the same proxy the 2026-07-21 pass used, not raw search-volume numbers) covering the six
lanes the 2026-07-21 pass left unmeasured. Findings, marked **[observed]**:

- **M-1 scalability/load-readiness — real, and thinner competition than F-1.**
  "next.js app slow" and "supabase slow query / laggy" each return a deep bench of
  dedicated posts (LogRocket, multiple Medium pieces, official Supabase docs) — genuine,
  recurring founder pain, confirming the doc's "companion felt-pain lane" call. The
  launch-moment framing itself ("is my supabase app ready for a traffic spike," "load
  testing before launch") returns Supabase's own production checklist plus scattered SaaS
  launch-checklist content, but **no competitor packaging this as a paid pre-launch
  readiness check the way this hook proposes** — the "lane no competitor owns" claim
  holds. **Shipped this pass:** `/supabase-load-readiness`, routed to the free scan.
- **F-2 AI slop — real pain, but the exact "audit your AI slop" framing is now
  contested.** Multiple direct competitors already sell close to this exact positioning:
  vibeaudits.com, varyence.com ("Vibe Coding Security Assessment"), vallettasoftware.com
  ("Vibe Coding Audit — Investor-Ready Code from $199"), digitalapplied.com, plus several
  blog-first entrants (aquilax.ai, codewithseb.com, kunalganglani.com). The underlying
  pain is confirmed (an arXiv paper on "AI slop," dead-code-from-AI content, a widely
  quoted "$400M–$4B in AI-codebase cleanup" figure) but the door is no longer empty —
  this is a **downgrade from the doc's "punchier, uncontested" framing**, not a
  disqualifier.
- **F-3 re-fixing the same modules — pain confirmed, framing still open.** "Code churn /
  complexity hotspot" returns an established but developer-tool-facing content set
  (swimm.io, opsera.ai, codepulsehq.com, an arXiv hotspots paper) — real methodology,
  aimed at engineers, not founders. "Why do I keep fixing the same bug" returns generic
  debugging-psychology content, not hotspot-specific competitor pages — nobody is
  running the founder-facing "the 3 files causing 60% of your bugs" framing this hook
  proposes. Confirms the doc's own read: a felt pain with an open door, not a searched
  phrase.
- **F-4 compliance/PII — real demand, wrong buyer size.** "GDPR compliance audit
  startup" and "find PII in your database" both return dense, mature content (Vanta,
  Drata, Scrut, SecurityMetrics, AWS/Google DLP docs) — but the whole ecosystem is
  built for compliance teams and mid-market tooling budgets, not a solo founder running
  a small Supabase app. Real lane, low near-term priority given ICP size — matches the
  doc's own sequencing (add F-4 "as the customer base reveals regulated-data segments").
- **M-2 launch-readiness — the umbrella is genuinely crowded** (opslevel.com, getdx.com,
  cortex.io, port.io, kuberstar.com all publish production-readiness checklists), all
  ops/SRE-facing rather than whole-codebase-QA-facing. Confirms the doc's framing: this
  lane wins on brand ("Is your app actually ready to launch?" as Harvey's own umbrella
  question), not on an open SERP.
- **Adjacent finding, unprompted by the six lanes above but too material to omit:** a
  direct "vibe-coding audit service" competitor set already exists (the F-2 names
  above) selling audits of AI-built apps generally, and a separate competitor
  (OutSight AI) is already running mutation-testing-over-coverage as its core pitch —
  the same framing as F-5's "coverage lies" angle. Both are worth a status re-check
  before those specific lanes get content investment.

**Proposed re-sequencing (operator call, not applied here):** the search pass raises a
question the priority list did not have data for: F-2 (AI slop) and F-3 (re-fixing) traded
places on evidence — F-3 now looks like the more open door of the two code-health lanes,
where the "Priority at $0 budget" list above still names F-2 as the punchier option.
Whether to build F-3 next, still build F-2, or hedge with a thinner version of both is
an operator sequencing decision; this pass supplies the evidence, not the call.

## How hooks connect to the rest of the strategy

- **SEO/AEO (`06-seo-aeo.md`):** each felt-pain hook is a content lane / cluster of pages.
- **Marketing engine (`04-marketing-engine.md`):** moment hooks drive outreach timing;
  original research can be run per hook (AI-slop stat, hollow-tests stat).
- **Positioning (`02-positioning-messaging.md`):** every hook page's copy ladders back to
  the three QA-leader pillars and routes to the free scan.
- **Pricing (`03-pricing-packaging.md`):** moment hooks (scalability, launch, diligence)
  justify the paid tiers against a nearby budget.
