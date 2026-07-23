# Social media presence

Part of the Harvey GTM strategy (see `00-overview.md`). Channel data verified 2026-07-21
(sizes from GummySearch/fetched pages; Discord/YouTube counts search-only, treated as
approximate). Social is a distribution and trust layer, not a standalone strategy — it
amplifies the marketing engine (`04-marketing-engine.md`).

## Where to be, and why (ranked)

### Tier 1 — the core two (be here daily)

**X / Twitter — the build-in-public and news-jacking channel.**
The indie-founder and vibe-coding conversation lives here, and vibe-coding security
fails go viral on X regularly. Two motions:
- *Build in public* (#buildinpublic): real anonymized findings ("found a cross-tenant
  read in 20 minutes on a live app"), the story of building a productized audit service
  with AI agents, revenue milestones. Verified norm: this format compounds trust at $0.
- *Expert reply / news-jacking*: **be the expert voice every time a vibe-coding breach
  hits the news.** This is Harvey's recurring free-marketing moment. Reply substantively
  in the orbit of @supabase, @IndieHackers, @leerob, @levelsio, @t3dotgg.

**Reddit — the highest-intent audience (participate, don't broadcast).**
Not "social" in the posting-schedule sense, but the single best-fit audience. Covered
operationally in `04-marketing-engine.md`; the reputation built in r/vibecoding,
r/Supabase, r/lovable, r/nextjs, r/SaaS is the foundation everything else rests on.

### Tier 2 — the professional/founder layer (weekly)

**LinkedIn — the company-page and diligence-audience channel.**
Where the "pre-fundraise / investor-ready audit" buyer and agency partners are reachable
in a professional frame. Post the original research, case studies (anonymized), and
methodology explainers. Also the home for the company entity (feeds AEO/Google knowledge
panel — see `06-seo-aeo.md`). Lower volume than X, higher-value audience.

**Indie Hackers — the journey-post channel.**
Verified: journey posts with revenue numbers get featured in the ~165k-subscriber
newsletter for free. Post build-in-public milestones and "what auditing N apps taught
me" war stories in the value-first format the community rewards.

### Tier 3 — presence, not priority

- **YouTube** — high production cost; defer. If any video, make it the original-research
  walkthrough or a "watch me find a cross-tenant leak in a real app" screencast (that
  format would travel). Not a launch commitment.
- **Discord (own server)** — do NOT start one at launch; an empty server is negative
  signal. Be a guest in Supabase/Lovable/Bolt/Cursor servers instead. Revisit a Harvey
  community only once there's a customer base to fill it.
- **TikTok / Instagram** — wrong audience for a B2B developer audit. Skip.

## What to post (the content-to-social mapping)

Every marketing-engine output has a social distribution:

| Source asset | X | LinkedIn | Indie Hackers | Reddit |
|---|---|---|---|---|
| Original research report | Thread with the headline stat | Post + PDF | Journey/findings post | r/vibecoding, r/SaaS |
| A query-targeting blog post | Link + key takeaway | Article share | When relevant | When it answers a question |
| A real (anonymized) finding | "Found X in 20 min" thread | Case-study framing | War-story post | When it answers a thread |
| Revenue/milestone | #buildinpublic | Milestone post | Journey update | — |
| Breach in the news | Expert take, fast | Measured explainer | — | Expert comment |

## Cadence

- **X**: 1 post/day minimum (a finding, a take, or a build update) + reactive expert
  replies whenever security news breaks. ~10 min/day.
- **LinkedIn**: 1–2 substantive posts/week (research, case study, explainer).
- **Indie Hackers**: 1 journey/war-story post per week or two.
- **Reddit**: daily answering (operational, per `04-marketing-engine.md`), not scheduled
  posting.

## Guardrails

- **Never fear-monger or shame.** Same rule as positioning (`02-positioning-messaging.md`)
  — the buyer is proud of what they shipped.
- **Responsible disclosure on every public finding.** Anonymize; never post an
  exploitable detail against an identifiable live app. This discipline is brand-positive.
- **Posting stays manual.** LinkedIn/X automation APIs are restricted/costly; the
  strategy assumes hand-posting. A scheduler (Buffer/Typefully) is a "when it's a chore"
  upgrade, not a launch need. I can draft every post; the operator posts.
- **One identity everywhere.** Same name, same handle, same one-line description across
  X / LinkedIn / GitHub / Crunchbase (the AEO entity-consistency point from
  `06-seo-aeo.md`). Decide the name first (`02-positioning-messaging.md` naming note).

## The operator/agent split

I can: draft every post, thread, and reply; monitor for breach-news moments to react to;
turn each research/blog asset into its platform-specific versions; maintain a content
queue. The operator: creates the accounts (under their own identity), approves/posts,
and handles any real-time DM conversations. Account creation is the only blocker and it's
a one-time ~30-minute task per platform.
