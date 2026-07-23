# Cross-check against the prior GTM docs

Part of the Harvey GTM strategy (see `00-overview.md`). Per the operator's instruction,
the new `docs/gtm/` strategy was written **from scratch** — the old docs were not used as
input. This doc is the promised post-hoc pass over them purely to catch anything real the
new strategy missed. Reviewed 2026-07-21: `docs/go-no-go.md`, `docs/outreach-template.md`,
`docs/free-tier-scope.md`.

**Caveat on the old docs:** they're dated (go-no-go last updated 2026-06-27; references a
7/9-module scope, now ten) and CLAUDE.md marks them human-owned IP not to be edited. Treat
their numbers as unverified-until-retested (repo doctrine). Where they conflict with the
2026-07-21 verified research, the new docs win.

## Real items worth carrying forward — now folded into the new strategy

1. **The enterprise-security-questionnaire trigger** (old: "strongest paid trigger").
   This is a genuinely strong insight the fresh research didn't surface, because it's a
   sales-motion insight, not a market fact. A stalled enterprise deal blocked on a
   security questionnaire reframes the audit spend as a deadline-driven *revenue unlock* —
   the thing that actually loosens budget. **Folded into** `09-launch-checklist.md`
   Gate 5. Worth elevating in messaging too.

2. **The SOC 2 gap** (old, tagged verified): SOC 2 explicitly treats code review as a
   separate control and does NOT deliver auth/tenant-isolation code review; black-box
   pentests rarely read RLS logic. This makes Harvey a *clean, non-competing referral*
   for compliance/vCISO shops. **Folded into** `08-partnerships.md` (compliance-shop
   partners) and `09-launch-checklist.md` Gate 5. Re-verify the SOC 2 claim before
   putting it in client material.

3. **Cold-email reply-rate collapse** (~0.3% in 2026): argues for layered
   email+LinkedIn, partnership-led, trigger-based outreach over volume cold email.
   **Folded into** `09-launch-checklist.md` Gate 5 note. Directionally consistent with
   the organic-first strategy; the specific 0.3% number is unverified — treat as
   directional.

4. **Fundraising / M&A technical due diligence as a trigger** ("~70% of investors now
   require it" — unverified number). The *angle* is already independently validated by
   the fresh SEO research (DevBrows ranks for "pre-fundraise security audit"; it's
   content piece #9 in `06-seo-aeo.md` and a pricing tier in `03-pricing-packaging.md`).
   The old doc's specific 70% stat is unverified — do not cite it; the angle stands on
   the verified SEO evidence.

5. **The free-tier scope table** (`free-tier-scope.md`): a genuinely useful,
   product-accurate breakdown of what each module delivers source-only vs. what's
   reserved for connected/dynamic tiers, plus the "indicators, not verdicts" report-
   framing discipline that protects the brand and creates the upsell bridge. This is
   more operational than GTM, but the **"indicators not verdicts / static indicates,
   live confirms" framing is a real messaging asset** — consistent with the "a scan is
   not an audit" pillar (`02-positioning-messaging.md`) and the coverage-honesty brand.
   The new free-scan positioning in `05-website-plan.md` and `03-pricing-packaging.md`
   is consistent with it; no change needed, but the detailed table is worth keeping as
   the operational spec behind the free tier.

6. **The arXiv/ACM evidence** (old, tagged verified): Copilot Code Review caught zero
   critical vulns across 7 benchmark datasets (arXiv 2509.13650); ~30% of AI-generated
   code carries security weaknesses, LLM remediation fixes only ~55% (ACM 10.1145/3716848);
   `service_role` bypasses all RLS by design (generalanalysis.com). These are strong,
   citable "why automated review isn't enough" proof points for the differentiation
   pillar. **Recommendation:** re-verify each (they're a year old) and, if they hold,
   add to the "a scan is not an audit" content. Not yet folded in pending re-verification
   — flagged here so they aren't lost.

## Where the new strategy diverges from the old (deliberately)

- **Positioning breadth.** Old doc: "market on the multi-tenant security wedge, deliver
  the breadth." New doc: leads with "the codebase audit for Supabase apps" and gives the
  full-suite scope equal billing. Rationale: the verified 2026 market shows the
  vibe-coding/AI-built framing is where the demand, the incidents, and the search volume
  actually are — a broader, more current wedge than multi-tenant-security alone, which
  becomes one (strong) pillar rather than the sole hook. Both agree the deliverable is
  the full audit.
- **Primary ICP.** Old doc centers the enterprise-questionnaire/fundraise buyer. New doc
  centers the post-traction vibe-coding founder, with the questionnaire/fundraise buyer
  as a high-value secondary. Rationale: the free-scan-led, community-driven, organic-only
  motion the operator chose reaches the founder segment first and cheaply; the enterprise
  trigger is a direct-outreach overlay (Gate 5), not the core funnel.
- **Module count / scope.** Old doc references 7–9 modules; the product is now ten
  (M1–M10, incl. PII/PHI/PCI classification). New docs use ten throughout.

## Nothing-missed check — other old GTM material

Scanned the rest of `docs/` for GTM-relevant content: `audit-modules.md` (product spec,
not GTM), `tier1-runbook.md` and the module design docs (delivery/ops, not GTM),
`scan-extras.txt`/`quality-extras.txt`/`fp-rules.txt` (audit briefs). None contains GTM
strategy the new set omits. The three docs reviewed above are the substantive prior GTM
work, and their reusable insights are now folded in or flagged.

## Net

The old docs contributed **four concrete additions** to the new strategy (the
questionnaire trigger, the SOC 2 referral angle, the cold-email-collapse tactic, and the
AI-review-is-weak evidence set — the last pending re-verification), plus confirmation
that the fundraise-diligence angle and free-tier framing were already independently
covered. No load-bearing gap was found. The deliberate divergences (broader vibe-coding
wedge, founder-first ICP, ten modules) are choices, not omissions, and reflect the newer
verified market picture and the operator's chosen organic, product-led motion.
