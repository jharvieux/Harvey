# Outreach templates

> Channel guidance from research: **referrals/partnerships are the highest-quality, lowest-cost channel**;
> cold-email reply rates have collapsed (~0.3% in 2026), so layer outbound (email + LinkedIn) and lead with
> partnerships + trigger-based targeting + visible community presence. Personalize every send — these are
> skeletons, not spray templates.

---

## 1. Free-audit ask (weeks 1–2 — validate conversion)

**Target:** Supabase/Next.js founders who are *raising* or *chasing a first enterprise customer*.
**Channel:** warm intro > founder community DM > LinkedIn. Goal is 3 yeses, not volume.

> Subject: free tenant-isolation audit for {Company}?
>
> Hi {Name} — I do security audits specialized in multi-tenant Supabase/Next.js SaaS. The most common
> way these apps leak is a Row-Level-Security policy that *looks* right but lets any logged-in user read
> other tenants' rows — generic tools and even RLS-as-documented miss it.
>
> I'm taking on **3 free audits** to build case studies. I'll read your auth + tenant-isolation logic and
> send a findings report ranked by blast radius — yours to keep. In exchange: a short testimonial if it's
> useful, and permission to anonymize one finding for a writeup.
>
> Worth 20 minutes to scope? — {You}

---

## 2. Trigger-based outreach (the strongest paid trigger)

**Target:** companies that just hit an **enterprise vendor security questionnaire** or are prepping a raise.
Signals: hiring first AE/enterprise sales, "SOC 2 in progress" posts, "we just landed {BigCo}" announcements,
fundraise announcements.
**Why it works:** turns a stalled deal into a deadline-driven revenue unlock.

> Subject: unblock the {BigCo} security review?
>
> Hi {Name} — saw {Company} is {moving upmarket / closing enterprise / raising}. When procurement runs their
> security review, the thing that delays SaaS deals most is cross-tenant data isolation — and on Supabase the
> classic gap is an RLS policy that passes review but leaks across tenants.
>
> I run a **fixed-fee, ~1-week multi-tenant security audit** for Supabase/Next.js stacks — I read the actual
> RLS/auth logic (not a checklist scan) and hand you a report you can show the buyer, ranked by severity with
> fixes. Fixed price, no surprises.
>
> Want the one-page scope + sample report? — {You}

---

## 3. Partnership outreach (highest-quality channel — build this early)

**Target partners** (they sit at the questionnaire moment but don't do code-level review):
SOC 2 / compliance shops (Vanta/Drata-adjacent consultants), fractional CTO/CISO firms, Next.js/Supabase dev
agencies, and AI-app platforms (cf. Lovable×Aikido — platforms are becoming a distribution channel for security
services to their builders).

> Subject: code-level security partner for your {SOC 2 / vCISO / agency} clients?
>
> Hi {Name} — {their firm} gets clients audit-ready, but SOC 2 explicitly excludes auth/tenant-isolation
> *code* review, and black-box pentests rarely read the RLS logic. That's exactly the gap I fill: fixed-fee
> multi-tenant security audits for Supabase/Next.js SaaS.
>
> When your client's pentest or questionnaire flags "no app-layer security testing," I'm a clean referral —
> productized, fast, and I don't compete with what you do. Happy to do a free audit for one of your clients so
> you can see the deliverable. Referral fee or white-label, your call.
>
> 15 minutes this week? — {You}

---

## 4. Content-led inbound (the long game — weeks 4–8 onward)

Not a message — a distribution engine. Publish 2–3 teardowns; each doubles as a sales asset and links to a
"book an audit" CTA.

- "Your Supabase RLS is probably wrong: the `auth.role() = 'authenticated'` cross-tenant leak."
- "How a `service_role` path leaks every tenant's data — and why your AI reviewer won't catch it." (cite arXiv 2509.13650)
- "What an AI PR reviewer misses: a field guide to multi-tenant SaaS security bugs." (the D-091 taxonomy, generalized)

Seed them in: Supabase Discord, r/Supabase, indie-hacker/devtools communities, X/Bluesky devtools circles, and
the Supabase/Vercel partner directories. Be the person who answers RLS-security questions publicly; the audit
sells itself from there.

---

## Cadence note

Per research, single-touch cold email underperforms. For trigger/partner outreach use a light sequence:
email → LinkedIn connect w/ a one-line ref → one follow-up after ~4 business days → stop. Quality of trigger
beats volume every time.
