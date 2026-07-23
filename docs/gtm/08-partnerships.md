# Partnerships

Part of the Harvey GTM strategy (see `00-overview.md`). Partnership facts verified
2026-07-21 where noted; the Supabase partner program was fetched live.

## Priority 1 — Supabase partner program (the ecosystem on-ramp)

**Verified [live fetch 2026-07-21]:** Supabase runs an open, self-serve, apparently
zero-cost partner program with two tracks, application via forms.supabase.com/partner:

- **Integrations track** — a technology/marketplace catalog listing. Harvey's free scan
  or the connected-audit integration could be listed here. (Only Aikido currently
  occupies adjacent security ground, and only for external-perimeter scanning.)
- **Experts track** — consulting/agency partners (existing examples: CALDA, Morrow,
  Voypost) who build/support Supabase projects. A Harvey audit-service listing fits here.

Recommendation: **apply to both tracks.** The Experts listing positions Harvey as a
Supabase-vetted service (trust + referral flow); the Integrations listing puts the free
tool in the marketplace. Self-serve to apply; acceptance is subject to Supabase review.

**Before claiming "first Supabase security-audit partner" anywhere:** do a fresh manual
census of supabase.com/partners/catalog. The research pass's claim that only one
Security-tagged partner exists was *refuted on its counts* (not confirmed, not disproven)
— so verify first. If true, "first security-audit service in the Supabase ecosystem" is a
powerful, defensible line.

Secondary Supabase plays: contribute to Supabase's community content (they amplify good
community posts and run Launch Week hackathons); an open-source RLS/security tool has a
real chance of being featured by the Supabase team — earned coverage worth more than a
listing.

## Priority 2 — Dev agencies building on Supabase/Next.js

Agencies ship client apps fast and want a third-party health check they can hand the
client (or use internally before delivery). Two models:
- **White-label / referral**: Harvey audits the agency's client work; agency resells or
  refers. Harvey's re-audit `--baseline` diff feature supports an ongoing relationship.
- **Pre-delivery QA**: agencies run Harvey before handing off, as a quality signal.

Sources for the target list: the Supabase Experts directory itself (peers, not just
competitors — many do build work but not security auditing), and agencies visible in the
Next.js/Supabase communities. Approach: lead with a free audit of one of their shipped
apps — the finding IS the pitch.

## Priority 3 — AI app builders (the highest-need user base, hardest partnership)

Lovable, Bolt/StackBlitz, v0, Cursor, Replit — their users ship the insecure apps the
demand evidence documents. Two realities:
- **Their users are Harvey's best audience** — reachable now via the communities
  (`04-marketing-engine.md`) without any partnership.
- **A formal partnership is aspirational** — these platforms are under public pressure
  about security and may not want to co-market a service that highlights their apps'
  flaws. But that same pressure is the opening: a "recommended security audit partner"
  or a security-checklist co-publication helps *them* answer the criticism. Approach
  from "we make your platform look responsible," not "your apps are broken."

Realistic near-term version: get Harvey's free checker mentioned in their community/docs
as a helpful third-party tool, rather than a signed partnership. Start there.

## Priority 4 — Accelerators / incubators

Startups going through YC, Techstars, and smaller accelerators face investor technical
diligence — Harvey's "pre-fundraise / investor-ready audit" (`03-pricing-packaging.md`)
maps exactly. Play: offer accelerator cohorts a free scan + discounted audit as a perk.
Longer sales cycle; pursue after the core funnel is proven and there's a case study to
show. The diligence-audience content (`06-seo-aeo.md` #9) warms this channel.

## Priority 5 — Complementary (non-competing) tools

Tools in the Supabase/Next.js stack that touch quality/security but don't audit:
Resend, Clerk, Vercel-adjacent tools, testing platforms. Cross-content (guest posts,
co-published checklists) and mutual referrals. Low priority; opportunistic.

## What to avoid

- Don't partner-chase before the product's funnel works — a partnership sends traffic to
  a funnel that must already convert.
- Don't position against the AI builders publicly while seeking their partnership — the
  news-jacking (`07-social-presence.md`) and the platform partnerships are in tension;
  keep public commentary about the *category problem*, not any single platform's failures.

## Sequence

1. Apply to the Supabase partner program (both tracks) — do this early; it's free and
   the review takes time.
2. Census the partner catalog to validate the "first-in-category" claim.
3. Begin agency outreach with free-audit-as-pitch once the free scan works.
4. Seed the free checker into AI-builder communities.
5. Accelerator and formal-platform partnerships after the first case studies exist.
