# Multi-tenant security audit service — Go/No-Go

> Personal venture analysis. Built from the harness in this repo but a **separate business** —
> these docs can be lifted into a dedicated repo anytime. Sole-owner IP; no work-product conflict.
> Last updated 2026-06-27.

## Verdict: GO — a productized, fixed-fee codebase audit, **marketed on** multi-tenant security depth

**Market on the wedge; deliver the breadth.** Lead every pitch with the thing nobody else does well —
multi-tenant security / cross-tenant isolation for Supabase + Next.js (what's underserved and gets the
meeting). But the **deliverable is a full codebase-health audit** across 7 modules (see `audit-modules.md`):

1. **Multi-tenant security** (M1 — the lead/differentiator)
2. **Local penetration test** (M2 — dynamic, *proves* the security findings)
3. **Hotspot analysis** (M3 — churn × complexity)
4. **Duplication** (M4)
5. **Slop / dead-code cleanup** (M5)
6. **Simplification / reuse / maintainability** (M6 — "don't reinvent the wheel," lower support cost)
7. **Performance tuning** (M7 — N+1/unindexed queries, RLS initplan, bundle, Web Vitals)
8. **Test quality & intent** (M8 — StrykerJS mutation testing: which tests can't actually fail)
9. **Next.js App Router** (M9 — server→client data leaks, Server Action auth/validation, cache cost, hydration)

Breadth makes each engagement worth more, stickier (maintainability + perf are recurring needs), and widens
the buyer pool (M6/M7 land even with clients who don't think they have a security problem). Package as a
**Security audit** (M1+M2, the wedge) with a **Full codebase audit** (M1–M9) upsell.

The **positioning** stays narrow and sharp; only the **deliverable** is broad. Do **not** market as "generic
AI code review / code quality" — that lane (per-seat SaaS, SonarQube/Code Climate) is crowded and commoditized.
The D-091 taxonomy + the module briefs are the deliverable's table of contents.

## Why (evidence)

Confidence tags: **[V]** = source-verified this research (3/3 adversarial votes or corroborated across sources); **[J]** = my judgment.

**The incumbents are structurally weak at security — peer-reviewed [V]:**
- GitHub Copilot Code Review, run against 7 benchmark datasets with hundreds of documented vulns,
  produced <20 comments total and caught **zero** critical vulns (SQLi/XSS) — mostly style/spelling.
  It lacks interprocedural data-flow analysis (can't trace input→sink). _(arXiv 2509.13650)_
- ~30% of AI-generated code snippets carry security weaknesses; an LLM remediation pass fixes only
  ~55%, leaving ~45%. _(ACM 10.1145/3716848)_
- Study's own conclusion: a gap between perceived and actual AI-review security capability — "dedicated
  security tools and manual audits remain necessary."

**Your Supabase anti-patterns map to a real, severe, documented class [V]:**
- `service_role` (used by IDE/AI assistants and server code) **bypasses all RLS by design** — "RLS as
  documented does not protect against this class." _(generalanalysis.com)_
- RLS is **opt-in, not default**; without it the embedded `anon` key is "a master key to your entire DB."
- The canonical AI-generated footgun: `USING (auth.role() = 'authenticated')` — looks correct, lets any
  logged-in user read **every tenant's** rows. Only a human reading the code catches it. _(multiple)_

**Demand is real and paid [V]:**
- Seed/Series-A SaaS pay **$5K–$35K** for one-time app pentests/security engagements.
- **Strongest trigger: the enterprise vendor security questionnaire that gates the first big deal** —
  it reframes the spend as a revenue unlock with a hard deadline (what loosens budget). Second trigger:
  fundraising/M&A technical due diligence (~70% of investors now require it). _(Blaze Infosec; Astra; SecureLeap)_

**The gap is real [V]:**
- SOC 2 explicitly treats code review as a **separate control** — the compliance path does **not** deliver
  auth/tenant-isolation code review. _(LinfordCo)_
- Boutique white-box shops (Cure53, Doyensec, Latacora) exist but are custom-quoted and not productized
  for seed budgets. Framework-specific Supabase/Next.js multi-tenant review is **unserved**.
- Existing "scanners" check whether RLS *exists*, not whether it's *correct* — a false-sense-of-security gap.

## The wedge (one sentence)

> "Multi-tenant security audit for Supabase + Next.js SaaS — we find the cross-tenant data leaks and
> service-role exposures that CodeRabbit, Copilot, and even RLS-as-documented miss."

## Pricing strategy

Call it a **security audit** and price against the **pentest band ($5K–$35K)** — not "code review."
- White-box *code review* is sometimes quoted cheap ($500–$2K/asset) **[V]**; do **not** anchor there.
  You're selling avoidance of a catastrophic cross-tenant breach, so price on **value/blast radius**, not lines read.
- **Intro:** $3–5K fixed-fee (first ~5 clients, to build proof + testimonials).
- **Standard:** $8–15K once you have references and a repeatable report.
- **Recurring upsell:** re-audit per release, or the PR-review bot for the niche — sold to audit clients (land-and-expand).

## Competitive / pricing landscape (verified)

| Tool | Price | Security model |
|---|---|---|
| CodeRabbit | $24 / $48 seat/mo | Generic linters + SAST + governance — not multi-tenant-specific |
| Greptile | $30 seat/mo ($1/extra review) | Generic AI review |
| Copilot review | bundled | Documented to miss critical vulns |
| SOC 2 audit (anchor) | $10K–$50K startup; Type 1 $5K–$20K | Compliance — excludes code-level auth review |

## Realistic revenue (my estimate [J] — not a sourced figure)

Solo, fixed-fee audits; **the bottleneck is lead-gen, not delivery.** First 5 sales are the hard part.
Ramped to **2–4 audits/month at $4–8K ≈ $100K–250K/yr.** Adding recurring re-audits compounds after a base exists.

## Top risks

1. **Conversion unproven [J].** Demand for *security audits* is verified; that founders will buy *your specific
   framing* at your price is not. → Validate with free audits first (90-day plan).
2. **Transferability.** ~70% of the harness is Supabase-specific — the niche is the moat *and* the ceiling.
3. **Liability / false-negatives.** A missed leak is reputational/legal exposure. → LLC + capped-fee, point-in-time
   engagement terms (already accepted).
4. **Commoditization.** GitHub/incumbents could add depth — but the arXiv evidence shows they're far from it on
   security today, and the Supabase-specific layer is unlikely to be their priority [J].
5. **Rule rot.** The taxonomy needs maintenance as frameworks evolve (already seen vite/vitest churn).

## Contested in research (don't lean on)

- The specific "CVE-2025-48757 / 170 Lovable apps / 13,000 users" stat: one research pass **refuted** it, another
  corroborated it. The *pattern* (AI apps shipping broken RLS) is well-attested; the exact figure is not — cite the
  pattern, not the number.
- Vibe-coded-app scan stats (98% had flaws, etc.) are vendor-published — directional, not audited.

## First 90 days

1. **Weeks 1–2 — prove conversion before building anything.** Approach ~20 Supabase-stack founders who are
   *raising* or *chasing a first enterprise deal*. Offer **3 free audits** for a testimonial + permission to
   anonymize findings. Can't give away 3? The market signal is cheap and fast.
2. **Weeks 2–5 — deliver the 3, productize the report** (template ranked by blast radius; see `audit-report-skeleton.md`).
3. **Weeks 4–8 — publish 2 teardowns** ("How a Supabase `service_role` path leaks every tenant's data") citing the
   arXiv + General Analysis findings. Distribution engine + proof-of-work.
4. **Weeks 6–12 — start charging** (~$3–5K intro). Build the **partnership channel** (highest-quality per research):
   SOC 2 / compliance shops, fractional CTOs, dev agencies, and the AI-app-platform ecosystems (cf. Lovable×Aikido)
   — they sit at the questionnaire moment. Cold email reply rates have collapsed (~0.3%); lead with partnerships +
   trigger-based outreach + visible presence in the Supabase Discord / r/Supabase, not spray-and-pray.

See `outreach-template.md` (partnership + trigger-based + free-audit scripts) and `audit-report-skeleton.md` (the deliverable).
