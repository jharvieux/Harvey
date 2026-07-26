# Pricing & packaging

Part of the Harvey GTM strategy (see `00-overview.md`). Price bands below are grounded
in a verified benchmark pass (2026-07-21) — each competitor number was confirmed against
its primary source. All figures are USD and a snapshot; re-verify before publishing.

## The verified pricing landscape

The market clusters in three bands (all confirmed against primary sources):

**Band 1 — cheap automated scans: $0–$2,000/yr.** Fiverr gigs ($100–$300),
scan products (Astra scanner $1,999/yr). Three independent guides (SecureLeap,
DeepStrike, Software Secured) agree on a credibility floor: anything under
~$3,000–$4,000 sold as a "pentest" is presumed to be a rebranded automated scan.

**Band 2 — fixed-fee productized "vibe-code" audits: ~$1,500–$5,000, 3–10 business
days.** This is the dense, directly-comparable segment and it's crowded:

| Provider | Price | Turnaround | Verified against |
|---|---|---|---|
| Valletta Software | $199 / $799 / $1,499 (LOC-tiered) | 3 / 5 / 7 days | own site |
| Beesoul | from $1,500 (own site; roundup says $2,500) | 3–5 days | own site wins |
| Vibe App Rescue | $2,000 (migration) / $3,000 (full) | ~5 days | roundup |
| Varyence | from $2,500 | ~5 days | roundup only |
| Pragmatic Coders | from $3,000 | ~10 days | roundup |
| Intertec / ISHIR | from $5,000 | ~14 days | roundup |
| VibeCheck London | from $7,500 | ~5 days | roundup |
| **VibeAudits** | **no published price** (quote after free call) | n/a | own /pricing page |

Critically: **none of this segment advertises dynamic pen-testing, live-DB review,
mutation testing, or data classification.** They are source-review only. That is the
opening.

**Band 3 — traditional pentests: $4,000–$12,000** for a small-SaaS web app (three
guides independently agree), $8,000–$35,000 for Series A–B web+API, $50k+ only for red
team / enterprise. Human-led, 1–4 weeks, and what SOC 2 / diligence buyers actually pay.

## Harvey's ladder — size-banded, not flat

The strategy: **occupy the empty space between Band 2 and Band 3** — deeper than any
fixed-fee vibe-audit (we have a real dynamic pen-test, live RLS review, mutation
testing, PII classification, and code health), cheaper and faster than a manual pentest
firm. But a **flat price is the wrong shape** (operator, 2026-07-21): $2k/$5k is
prohibitive for a weekend-project vibe coder and far too cheap for an enterprise
monorepo. So price on **two axes**: depth tier × codebase size band.

**Why lines of code as the size proxy.** It's the simplest fair proxy for audit effort,
it's proven in this exact niche (Valletta tiers by LOC: $199 <5k / $799 5k–25k / $1,499
any size), and — decisively — **Harvey can auto-measure it from the repo during the free
scan and quote from it**, turning the free scan into an instant, transparent quote
generator. Alternatives considered and rejected as the primary axis: table/route counts
(capture only part of the effort), funding stage or team size (value-based, not
effort-based — reserve as a sanity check). Bands (not per-line pricing) absorb LOC's
fuzziness; generated and vendored code is excluded (Harvey's M4/M5 already detect it); an
unusually complex small app can be bumped a band.

### Depth tiers — ordered by ACTUAL WORK, not access (operator correction, 2026-07-21)

The prior structure was backwards: it priced the local-stack pen-test tier *below* the
DB-connection tier, and called the middle tier "Full" when it wasn't. The corrected
principle: **standing up a local stack and running the dynamic pen-test is the expensive,
high-value work; reading a read-only DB to run advisors is comparatively cheap.** So the
DB tier is the cheaper paid rung and the pen-test tier is the premium — and "Full" now
genuinely means everything. Each rung is a clean superset of the one before.

- **Rung 0 — Free automated scan ($0, any size).** The mechanical/source tier across all
  ten modules: what the code *indicates*, in plain English. No access beyond the repo.
  The market treats standalone scan value as ~$0, so giving it away costs no perceived
  value and buys the entire funnel. **The GTM's central asset**, and the auto-quote
  mechanism (measures LOC → quotes the paid tiers).
- **Rung 1 — Connected audit (cheaper paid).** The complete *review*: all ten modules
  with real verdicts (semantic triage, cleared false positives, named fixes) **plus a
  read of your live database** (M1 live RLS, M7 Supabase advisors, M10
  PII-protection-in-prod). No environment stand-up. Low incremental labor over
  the source review — hence the modest price.
- **Rung 2 — Full audit (premium — everything).** Everything in Connected **plus** Harvey
  stands up a copy of your stack and runs the dynamic work: the live pen-test (M2 — proven
  cross-tenant access, auth/endpoint/service-seam attacks) and full mutation testing (M8).
  This is the labor-intensive tier and the only one that *proves* a flaw instead of
  flagging it. "Full" = all bands run.

Access ladder rises with price: Free needs only the repo; both paid tiers read your live
DB; Full additionally stands up your stack. If a paid client declines DB access, the
DB-dependent modules record `not run — no access` in the coverage ledger (on-brand), and
the rest still runs.

### The price grid (launch anchors — LOC = app code, generated/vendored excluded)

| Codebase size | Free scan | Connected audit | Full audit |
|---|---|---|---|
| **Small** · <10k LOC (most vibe-coded MVPs) | $0 | $500 | $1,000 |
| **Medium** · 10k–50k | $0 | $1,500 | $3,000 |
| **Large** · 50k–150k | $0 | $3,500 | $7,000 |
| **Enterprise** · 150k+ / monorepo / regulated | $0 | Custom | Custom |

This fixes both ends: a small app enters at $500 (in line with Valletta's $199–$1,499
vibe-audit band), while enterprise is uncapped custom. Full ≈ 2× Connected, and the
premium is backed by the real extra work (stand-up + dynamic pen-test + mutation run) —
not, as before, a big jump for a modest DB read. Large Full ($7,000) sits inside the
small-SaaS pentest band, where a proven live pen-test belongs.

### Rung 3 (later) — Re-audit / continuous: subscription
The repeat-customer `--baseline` diff feature is already built (resolved/persistent/new
finding classification). Package as an annual re-audit or quarterly cadence once there
are customers to renew — the path from service revenue to recurring revenue.

## Guardrails (from the benchmark data, reconciled with banding)

- **The "$4k floor" concern applies to the mid+ bands of the Full (pen-test) tier, not
  the small entry.** The benchmark heuristic ("under ~$4k sold as a *pentest* reads as
  just a scan") is about real-app perception. A genuinely small MVP is understood as
  scoped-small; its comparable set is the $199–$1,499 vibe-audit cluster, not the general
  pentest market. Keep the *language* honest — small tiers are "an audit of a small app,"
  not "a full pentest."
- **Only the Full tier carries pen-test language.** Connected (no stand-up) must not be
  described as a pen-test — it's a review plus a live-DB check. The "prove it live"
  promise is Full's, and it's the tier that justifies the premium.
- **Publish the grid.** VibeAudits and most of Band 2 hide pricing behind a call.
  Transparent, size-based pricing is a differentiator, a friction-remover for a
  self-serve-leaning buyer, and on-brand with Harvey's coverage-honesty identity.
- **Offer a re-audit credit** (Valletta does): re-verify critical findings once at no extra
  charge after the client ships fixes, if requested within 30 days of the original audit;
  **additional re-audits within that window are a paid add-on at 50% of the original audit
  price** (one included, extra rescans charged — operator decision 2026-07-24, price/window
  set 2026-07-26, #1013). Cheap to deliver (the diff feature automates it), high trust.

## Free vs. paid — the honest distinction (do not undersell the paid tiers)

The reason to buy is **not** "the free scan found a lot" (operator correction,
2026-07-21). The free scan is source-only and reports what the code *indicates*. The paid
tiers do things a source scan **structurally cannot**, and the two paid tiers split along
what they access: **Connected** adds semantic verdicts (triage, named fixes) and a read of
your live database (live RLS, advisors, PII-in-prod); **Full** additionally stands
up your stack to *prove* findings live (M2 pen-test) and runs mutation testing (M8). Market
each on **unique capability**, never on free-scan issue volume. Copy Valletta's proven
**"investor-ready / diligence" packaging** as a Full-tier add-on.

The page also carries a **tier × capability matrix** (grouped: reads-your-source →
reads-your-database → stands-up-&-attacks) so the escalation is legible at a glance and
the Full-only "stands up & attacks" band does the upsell.

## Packaging presentation

Three depth cards in ascending order (**Free Scan** / **Connected Audit** / **Full
Audit**, Full featured "Everything included") with "from · by size" pricing, the
size-band grid beneath, and the "investor-ready summary" as a Full-tier add-on. Each card
lists what runs at that tier and — per the coverage-honesty brand — what it does *not*
cover.

## Open pricing questions

- Exact price points need live-market testing — start at the grid anchors, then move by
  band based on close rates. The first ~5 engagements per band are price discovery.
- Band boundaries (10k/50k/150k) are a first guess — validate against real target LOC
  distributions once the free scan is measuring them.
- Whether to charge a scoping deposit. Recommendation: fixed published grid price, optional
  free scoping call for Connected/Enterprise — lower friction than competitors' mandatory-call
  model.
