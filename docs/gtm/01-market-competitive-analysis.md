# Market & competitive analysis

Part of the Harvey GTM strategy (see `00-overview.md`). Written fresh 2026-07-21 from a
verified deep-research pass (106 agents, 24 sources fetched, 25 claims adversarially
verified 3-vote each; 19 confirmed, 6 refuted). Confidence labels below come from that
verification. Prior GTM docs were deliberately not used as input.

## The one-paragraph read

The niche Harvey targets — audits for AI-assisted/"vibe-coded" SaaS apps on the
Supabase + Next.js stack — **already exists as a market category and has no direct
equivalent to Harvey in it**. Manual boutique auditors (VibeAudits and a tail of
smaller entrants) prove founders will book audits for exactly this stack, but none has
Supabase/RLS-specific tooling, an automated free tier, or dynamic pen-testing.
Automated scanners (Aikido, Snyk, CodeRabbit, SupaExplorer) are cheap and continuous
but structurally cannot cover authorization boundaries, multi-tenant logic, or code
health — the exact ground Harvey's ten modules hold. Demand evidence is unusually
concrete and citable: publicized incidents where vibe-coded apps leaked user data at
scale, with root causes that map one-to-one onto Harvey's M1/M2 modules.

## Demand evidence (high confidence — use these in marketing)

These survived 3-0 adversarial verification and are safe to cite publicly, with the
noted qualifiers:

1. **~10% of showcased Lovable apps leaked user data.** 170 of 1,645 apps tested had
   unauthorized-access issues; assigned CVE-2025-48757 (missing Supabase row-level
   security, CVSS 9.3). Qualifiers to respect when citing: the CVE is formally
   "disputed by supplier," and the original scan was run by a Replit employee (a
   Lovable competitor) though independently corroborated. Sources: XDA, The Next Web,
   NVD record.
2. **One vibe-coded EdTech app exposed 18,697 user records** (Feb 2026): 16
   vulnerabilities, 6 critical, including 4,538 UC Berkeley/UC Davis student accounts.
   Source: The Register (2026-02-27), corroborated by SC Media.
3. **A BOLA flaw in Lovable itself sat exploitable for 48 days** (reported 2026-03-03):
   any free account could extract other users' profiles, source code, and database
   credentials in as few as five API calls. Qualifier: a partial patch covered
   post-Nov-2025 projects during that window.
4. **The recurring vulnerability classes in vibe-coded apps are Harvey's home turf:**
   missing Supabase RLS, frontend-only authorization, over-fetched API responses,
   unauthenticated endpoints, IDOR. Documented statistically (the Lovable scans) and
   anecdotally (a technical editor repeatedly stumbling into leaks in ordinary use).

**Do NOT cite** (refuted 0-3 in verification): the claim that "70% of Lovable apps had
RLS disabled." It circulates widely but failed verification. Using it would hand a
critic an easy debunk.

## Competitive landscape

Four distinct competitor groups, none occupying Harvey's full position:

### 1. Boutique "vibe-code audit" services (closest in kind)

| Provider | Offering | Pricing | Notes |
|---|---|---|---|
| **VibeAudits** (vibeaudits.com) | Manual code audit for AI-built apps; scope explicitly includes multi-tenant boundaries, OWASP, secrets, performance (N+1s, missing indexes), architecture | Not published; Calendly booking | Verified live and bookable 2026-07-21. Targets essentially Harvey's exact stack ("Next.js/React… Postgres or Supabase, Stripe… with a layer of AI") |
| Tail entrants | damiangalarza.com/vibe-code-audit, vibecode-audit.com, sherlockforensics.com, beesoul.co, Valletta Software | Some publish fixed fees (see `03-pricing-packaging.md`) | Category confirmation — multiple independent entrants |

**What this proves:** the category is real, founders book these, and the framing
("you shipped fast with AI, now get it checked") works. **What none of them have:**
Supabase/RLS-specific automated tooling, a free automated scan as the front door,
dynamic pen-testing against a live stack, or a repeatable ten-module methodology with
a coverage guarantee. They are people selling hours; Harvey is a system.

### 2. Automated code-security platforms (cheap, continuous, structurally shallow)

| Provider | Pricing (verified 2026-07-21) | Position vs Harvey |
|---|---|---|
| **Aikido Security** | Free tier; Basic $300/mo (10 users, 100 repos); Pro $600/mo (annual rates; ~$350/$700 monthly) | Closest platform competitor; already a Supabase partner — but listed under DevTools, and its Supabase-facing product only scans the *external perimeter* for misconfigured instances. No source-level RLS-policy or code-health audit. |
| **Snyk** | Free tier; Team ~$25/dev/mo | Strong on known CVEs in dependencies; documented weaknesses: high false-positive noise, weaker on custom-code logic flaws, silently skips files >1 MB (own docs). |
| **CodeRabbit** | Free tier; Pro $24/user/mo; Pro Plus $48/user/mo (annual) | AI PR review, continuous per-seat. Sets the price anchor for *automated review* — a 10-person team pays ~$5,760/yr, at or below the floor of a single small pentest. |
| **Semgrep/OpenGrep-based tools** | Semgrep Team ~$30/contributor/mo per product | Pattern-matching SAST; interfile dataflow analysis remains a commercial Semgrep Pro feature (never in the OpenGrep fork). Misses framework-dependent, multi-file, and business-logic vulnerabilities. |

**The structural gap (medium confidence — factual anchors traced to primary docs, but
framing sources are competitor blogs):** grep-style SAST cannot see vulnerabilities
that depend on framework behavior, authorization boundaries, multi-file context, or
business logic. That is precisely the class of failure the demand evidence documents
(RLS, IDOR, frontend-only authz), and precisely what Harvey's semantic tier + live
pen-test cover. This is the load-bearing differentiation claim, and it is defensible.

### 3. Supabase-specific self-serve scanners (free-tier competitors, not audit competitors)

| Provider | Offering | Pricing |
|---|---|---|
| **SupaExplorer** (Torito) | Free security checklist (ranks ~#3 for "Supabase security checklist"); automated AI scan of a connected project (RLS gaps, public tables, leaked keys); Chrome extension | $9/mo, $90/yr, $249 lifetime |
| Adjacent free checkers | checkvibe.dev, vibeappscanner.com, cyber-checker.com | Free |

These compete with Harvey's **free tier only** — browser-visible/config-level checks,
nothing at source depth, nothing on code health. They matter for two reasons: they
validate that a free Supabase-security scan works as self-serve lead gen, and they
currently own the SEO territory Harvey's free tier needs (see `06-seo-aeo.md`).

### 4. Traditional pentest firms

Generic pentest pricing for small SaaS clusters around $4k–$15k per engagement
(directional — see `03-pricing-packaging.md` for verification status). They sell
security only (no code health), are stack-agnostic (no Supabase depth), and their
price point is above what a pre-revenue indie founder pays. Harvey undercuts them on
price and beats them on stack specificity; they win where a compliance checkbox
(SOC 2-adjacent formal pentest letter) is the actual requirement.

## Where Harvey is genuinely differentiated

Verified against the field above; each point is something *no surveyed competitor* has:

1. **Both halves of the audit.** Security AND code health (duplication, dead code,
   maintainability, test quality, performance) in one engagement. Scanners do neither
   deeply; boutiques do security-ish review without a repeatable quality methodology.
2. **Stack-native depth.** RLS-policy review, live two-tenant cross-tenant probing,
   Supabase config audit, App Router boundary analysis — purpose-built, not generic.
3. **A real dynamic tier.** Harvey stands up the target's own stack locally and
   attacks it (M2, autonomous stand-up). No boutique or scanner in the survey does
   dynamic testing at all in this segment.
4. **The free automated scan as front door.** Boutiques have no self-serve entry;
   self-serve scanners have no audit behind them. Harvey has the full ladder.
5. **Coverage honesty as a product feature.** The ten-module ledger with explicit
   "not run + reason" rows is a trust artifact no competitor shows.

## Threats and honest weaknesses

- **Aikido expands downward.** It has the Supabase partnership, a free tier, $60M
  Series B (Jan 2026, ~$1B valuation), and 100k+ team claims (vendor marketing). If it
  adds source-level RLS auditing, the moat narrows. Speed to category ownership matters.
- **Price-anchor compression.** Founders comparing Harvey to $9/mo SupaExplorer or
  $24/seat CodeRabbit will need the "scan vs. audit" distinction made for them,
  repeatedly. Positioning must do this work (see `02-positioning-messaging.md`).
- **The platforms fix the root cause.** Lovable/Bolt/v0 are under public pressure to
  ship secure defaults. If generated apps stop leaking, the incident-driven urgency
  fades — though code health, performance, and test quality remain (and are why
  Harvey's full-suite scope is the hedge).
- **Solo-operator capacity.** High-touch audits don't scale past a pipeline; the
  free-tier → productized ladder is the answer, but sequencing matters.

## Open questions carried forward

From the verification pass (things we could NOT confirm — do not treat as known):

1. **Is Harvey first-in-category in the Supabase partner catalog?** The claim that the
   catalog holds only one Security-tagged partner was refuted on its counts. A fresh
   manual census of supabase.com/partners/catalog would settle whether a
   security-audit service would be first of its kind there. (Cheap to do; worth doing
   before writing "first Supabase security-audit partner" anywhere.)
2. **Where does Corgea actually sit?** Both analyst-sourced claims about it failed
   verification. Unknown, not dismissed.
3. **High-touch audit pricing in this niche** — being verified in a follow-up pass;
   see `03-pricing-packaging.md`.

## Source notes

Primary sources fetched live 2026-07-21: vibeaudits.com, aikido.dev/pricing,
coderabbit.ai/pricing, supaexplorer.com, supabase.com/partners, forms.supabase.com/partner,
nvd.nist.gov (CVE-2025-48757). Secondary: The Register, The Next Web, XDA Developers.
Adversarial-framing sources (used only for anchors traced to primary docs): Aikido and
Corgea comparison blogs. All pricing is a 2026-07-21 snapshot and changes frequently —
re-verify before quoting in sales material.
