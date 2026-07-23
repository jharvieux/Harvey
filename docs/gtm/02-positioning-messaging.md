# Positioning & messaging

Part of the Harvey GTM strategy (see `00-overview.md`). Grounded in the verified
competitive analysis (`01-market-competitive-analysis.md`) and the product as it
actually exists in this repo (ten-module audit, free mechanical tier, live pen-test).

## The brand — "QA leader in a box"

**Harvey is the senior QA / quality leader your startup can't afford to hire, delivered
as a repeatable audit.** That is the brand, the homepage, and the pitch — not "a
security scanner." Harvey reviews the *whole* codebase the way a senior quality lead
would (does it work, is it tested, is it secure, is it maintainable, is it fast, is the
data safe) and returns one **readiness verdict**. Security is **one of ten modules,
equal weight** — a subsection of the product, never the product. (Operator direction,
2026-07-21: "our brand is QA leader in a box… we can have the security stuff in a
subsection but shouldn't market the entire product that way." This is also the repo's
own doctrine — CLAUDE.md: all ten modules carry equal weight, none is the lead.)

### The security-as-acquisition nuance (deliberate, not a contradiction)
Acquisition demand and search volume genuinely skew security (founders Google "supabase
security audit," not "codebase QA" — see `06-seo-aeo.md`). So security is the **entry
hook** in SEO and news-driven content — the door — while the **brand and pitch are the
QA-leader breadth** — the house. A worried founder arrives via a security query and
discovers Harvey is their entire QA function, of which security is one part. Market on
the acute pain; deliver and brand the breadth. Never let the door become the house.

## Who we serve (ICP)

**Primary: the post-traction founder with no QA function.**
A solo founder or 2–5 person team running an **AI-generated app** — built fast with
Cursor/Claude/Lovable/Bolt/v0, most often on **Supabase + Next.js (or Vite)** — now
holding real users and real revenue, with no QA team and no senior lead reviewing every
merge. They can't see the true state of what they shipped (which tests are hollow, what's
exposed, what won't scale), can't afford a full-time quality hire, and wouldn't know what
to do with a raw scanner dump. Trigger moments: first paying customers, a customer's
security questionnaire, an investor's diligence request, prepping to scale, launching
publicly.

**Secondary: the acquirer/investor doing diligence** on such an app (the
"investor-ready" readiness verdict), and **agencies** that built an app for a client and
want a third-party quality check before handoff.

Explicitly NOT the ICP (for now): mid-market companies with in-house QA/security teams,
enterprises, and stacks outside the AI-generated-app world we go deep on.

## Category and positioning statement

Own a category the field has left empty — outsourced codebase QA for AI-generated apps,
not "another scanner":

> **Harvey is codebase QA for AI-generated apps — a senior quality leader in a box.**
> For founders who shipped fast and have no QA team, Harvey audits the whole codebase
> across ten dimensions — tests, performance, maintainability, data, and security — and
> hands you one readiness verdict you can act on. It goes deepest on the stacks AI tools
> generate most: Supabase, Next.js, and Vite. Start free: an automated scan of your repo
> in minutes.

The words doing the work: **"QA leader"** (a senior, whole-picture quality read with a
verdict — not a single-issue scan), **"AI-generated apps"** (the broad brand and the
buyer's own identity — the homepage casts here), and **"Supabase / Next.js / Vite"**
(stack-native depth no generalist has; the deepest coverage and the SEO wedge). Brand
casts wide on "AI-generated apps/code"; the differentiation and SEO depth are
stack-specific — see the door-vs-house nuance above and `06-seo-aeo.md`.

## The three messaging pillars

Every piece of content, outreach, and web copy should ladder up to one of these:

### 1. "The QA leader you can't afford to hire" — the value pillar
The buyer has no quality function and can't justify a senior QA/eng-quality hire. Harvey
is that hire, as an audit: the whole-picture read a senior leader gives before you
scale, for a fraction of a salary. Never shame how they built it — shipping fast with AI
was the right call; getting a quality read before scaling is what a professional does
next. This is the lead pillar.

### 2. "Ten tools, or one leader" — the differentiation pillar
A founder could buy a security scanner, a coverage tool, a perf monitor, and a linter —
and still not know if they're ready, because tools emit noise across one dimension each
and none gives a verdict. Harvey is the senior read that runs across all ten, ranks by
what matters for *this* app, and says whether it's ready. Judgment, not alerts. Where it
counts, Harvey doesn't just flag — it **proves it live** (e.g. stands up your stack and
demonstrates a cross-tenant read, rather than warning that one "might" exist). This
pillar also answers the price-anchor problem ($9–48/mo tools): different product,
different job.

### 3. "The whole codebase, one verdict" — the completeness pillar
Ten modules, equal weight — tests, performance, maintainability, duplication, dead code,
data classification, App Router boundaries, hotspots, and security. The deliverable is
"the true state of your codebase" and whether it's ready, not a single-issue list. This
is the pillar no competitor can copy cheaply (boutiques lack the tooling; scanners lack
the scope) and the durable one: it holds even as any single dimension's urgency rises or
fades. Sub-message for the diligence audience: this readiness verdict is what
"investor-ready" actually means.

## Proof points (all product-true today)

- Ten modules, equal weight, with a **coverage ledger**: anything not run is listed
  with the reason. No silent gaps. (Turn the repo's fail-loud doctrine into the trust
  feature: "other reports hide what they didn't check; ours shows it.")
- Live dynamic pen-test: Harvey stands up your stack locally, seeds two tenants, and
  probes cross-tenant access, auth attacks, and service seams.
- A real finding record: a genuine Critical found on a real booted target during
  validation (tell this story with client permission or anonymized).
- Free tier is genuinely useful, not a teaser: mechanical checks across security,
  duplication, dead code, performance indicators, test-intent, PII schema mapping.

## Objection handling

| Objection | Response |
|---|---|
| "I already use Snyk/Aikido/CodeRabbit" | Keep them — they're continuous hygiene, one dimension each. Harvey is the senior read across all ten: which tests are hollow, what won't scale, where the data's exposed, whether one tenant can read another — with a verdict, not a wall of alerts. |
| "It's too expensive vs a $9 tool" | The $9 tool checks one thing from the outside. Harvey is a quality leader's read of the whole codebase. Run our free scan first — if it finds nothing worth a deeper look, don't buy. |
| "My AI tool says the code is fine" | The AI that wrote it is the wrong judge of it — same reason auditors don't audit their own books. Independent review is the whole point. |
| "I'll do it after launch" | The stuff a quality review catches (hollow tests, exposed data, what breaks at scale) is exactly what gets expensive after launch. A readiness check before scaling is cheaper than finding out live. |
| "Why not a QA hire / a pentest firm?" | A senior QA hire is a salary you can't justify yet; a pentest firm covers security only and is stack-agnostic. Harvey is the whole-codebase read on your exact stack, as a fixed-fee audit — and if you need a formal compliance letter, we'll tell you to use a pentest firm for that. |

## Voice and tone

Plain English, technically precise, zero fear-mongering, zero enterprise-speak
("synergy," "posture management"). Write like a senior quality leader explaining to a
smart founder — calm, whole-picture, specific. Show real findings and real methodology;
trust is earned with specifics, not badges. Admit limits openly (the coverage ledger IS
the brand). Security appears as one dimension among ten, never as the frame.

**Copy rule — Harvey is the doer** (operator, 2026-07-21): make Harvey the grammatical
subject that *does* the work — "Harvey checks your whole app," "Harvey proves it live,"
"Harvey tells you what it didn't check." Do **not** describe what a QA leader does in the
abstract and leave the reader to connect it ("the way a senior lead would…", "everything
a QA lead checks"). The brand is that Harvey *is* the QA leader, so Harvey acts. Keep
"QA leader in a box" as the identity/tagline; everywhere else, Harvey is the actor.

**Copy rule — never gate the purchase on free-scan issue count** (operator, 2026-07-21):
do not imply "buy the paid audit only if the free scan finds a lot." The free scan is
source-only and reports what the code *indicates*; the paid tiers do what a scan can't
(prove findings live, mutation-test the tests, review the live DB). Sell the paid tiers
on unique depth and capability, not on how alarming the free result looked. See
`03-pricing-packaging.md` → "Free vs. paid."

## Naming — DECIDED

**Brand: Harvey. Primary domain: `harvey-qa.com`** (operator decision, 2026-07-22 —
switched here after `harvey.review` was taken at purchase). It puts "Harvey QA" directly
in the domain, reinforcing the QA-leader brand; it's a `.com` (the default TLD, so no
type-in leakage); and it sidesteps the harvey.ai (legal-AI) collision. **Defensive
registration worth considering:** also grab the no-hyphen **`harveyqa.com`**, since
hyphenated domains lose type-in traffic to the un-hyphenated version.

SEO/AEO discipline that follows from this: we never compete for the bare query "Harvey"
(harvey.ai owns it) — all organic ranking comes from content and service pages targeting
the category queries (`06-seo-aeo.md`), not the brand token. Use "Harvey" consistently
as the entity name across site/GitHub/LinkedIn/Crunchbase.
