# Flagship original research — methodology: auditing N public Supabase apps for a citable stat

Status: methodology + tooling ready · Substantive execution operator-gated · Issue: #726 (this doc + the
aggregation harness) → remainder issue for the operator-run corpus/audit/disclosure/publish steps.

This is the methodology and the aggregation tooling for the GTM's flagship original-research report —
"the highest-leverage single action in the entire GTM" (`docs/gtm/04-marketing-engine.md` Input 2), and
"the highest-ROI AEO investment" (`docs/gtm/06-seo-aeo.md`). The deliverable is one memorable,
precisely-worded, Harvey-generated statistic published at a stable URL, in the form:

> "We audited N public Supabase apps built with AI tools. X% had cross-tenant data exposure. Here's the
> breakdown."

**What is built and mergeable now (this PR):** this methodology, the corpus-selection criteria, the
anonymization + denominator rules, the responsible-disclosure and publish gate, and the aggregation
harness (`src/corpus-aggregate.ts` + `pnpm exec tsx src/cli/corpus-aggregate.ts`) with tests over
synthetic inputs.

**What is deliberately NOT done here (operator-gated — see the remainder issue):** choosing and approving
the actual corpus of public apps, running the ten-module audit against them, coordinating responsible
disclosure with any identifiable live app, and approving publication of the number. None of that is done
autonomously; this document is the plan the operator executes, not a claim that any app was audited.

---

## 1. The statistic to compute

The harness computes several defensible corpus-level numbers; the operator picks the ONE headline to
publish. All are computed by `aggregateCorpus()` and printed by the CLI.

1. **Headline severity stat (always computable):** "X% of N public Supabase apps had at least one
   Critical or High severity finding." Pure severity roll-up — needs no live tier, no module attribution,
   and is the most defensible fallback if the corpus's live-tier coverage is thin.
2. **Cross-tenant exposure stat (the memorable GTM framing):** "X% of N public Supabase apps (where
   multi-tenant analysis ran) had a cross-tenant data-exposure finding." A tenant-isolation finding is
   recognized by a fixed keyword predicate over each finding's taxonomy + category + title
   (`CROSS_TENANT_KEYWORDS` in `src/corpus-aggregate.ts`): rls / cross-tenant / isolation / idor / bola /
   auto-exposed public-schema table / authz. **This predicate must be fixed BEFORE the corpus is run** —
   never re-tuned after seeing which wording maximizes the number. That discipline is what keeps the stat
   defensible against a "you p-hacked it" rebuttal.
3. **Supporting breakdown:** severity totals across the corpus, median findings per app, the most
   prevalent finding classes (by number of apps affected), and per-module coverage (how many apps each of
   the ten tiers actually ran on).

**Do NOT reuse the refuted "70% RLS disabled" stat** (`docs/gtm/01-market-competitive-analysis.md`) — the
whole point is a number that is Harvey's own and stands up to scrutiny.

### The honest-denominator rule (non-negotiable)

The cross-tenant stat is gated by the M1 tier having actually run. An app whose engagement findings.json
does not show M1 as `status: "ran"` is **not evidence of a clean app** — it is excluded from that stat's
denominator and reported in a caveat. This is the audit's coverage-guard doctrine ("a module that cannot
run is recorded WITH THE REASON, never silently omitted") applied to a corpus: silently folding
un-assessed apps into the denominator would deflate the percentage and is exactly the kind of number that
gets refuted. The harness enforces this — the published number's denominator is "apps where the gating
tier ran", stated explicitly alongside the percentage.

---

## 2. Corpus-selection criteria (the operator approves the list)

An app qualifies for the corpus only if ALL of these hold:

1. **Public source.** The repository is public (GitHub, or a public export from Lovable / Bolt / v0 /
   Replit / Cursor showcases). Sourcing lanes: GitHub search for `supabase` + framework markers in vibe-
   coded starters; the official showcase galleries of the AI builders; "built with Supabase" community
   directories.
2. **Supabase backend present.** Contains `supabase/` migrations or a Supabase client configuration — the
   audit's target shape. Apps with no Supabase surface are out of scope for this specific research.
3. **AI-generated / vibe-coded provenance is plausible.** Framed as built with an AI tool, or bearing the
   generator's fingerprints. The headline claim is specifically about AI-generated apps.
4. **Licensed for the analysis we perform.** We audit source we are permitted to read; we do NOT run the
   dynamic pen-test (M2) against anyone's hosted/production deployment. M2, where in scope, runs only
   against a LOCAL stack we stand up from the app's own migrations (`pnpm dynamic-validate --execute`) —
   never against a third party's live database or URL.
5. **Corpus size N chosen for defensibility, not drama.** N large enough that the percentage is not
   noise (target N ≥ 20 to launch; the prior-art numbers in the niche cite corpora like "62 Lovable apps"
   — `docs/gtm/06-seo-aeo.md`), and every app in N documented so the corpus is reproducible.

The operator reviews and approves the candidate list before any audit runs. The proposed sourcing lanes
above are a starting point for that approval, not a pre-approved list.

---

## 3. How the ten modules feed the stat

Each app is audited with the standard orchestrator and its per-app findings written out:

```
pnpm exec tsx src/cli/run-audit.ts <app> --findings-out corpus/<app-anon>.json [--llm --dynamic --artifacts-dir …]
```

Every engagement runs all ten modules (the coverage guard applies per app: a tier not in scope records
`requires-live-run`/`partial` WITH a reason, never a skip). The headline cross-tenant number draws on M1
(multi-tenant security) and, where a local stack is stood up, M2 (dynamic pen-test). The supporting
breakdown draws on all ten — the research doubles as proof that Harvey is a full ten-module codebase
audit, not a security-only scanner (`harvey-full-quality-suite-not-security-only` memory).

The per-app findings.json documents are then aggregated:

```
pnpm exec tsx src/cli/corpus-aggregate.ts corpus/*.json --out corpus-summary.json --summary-out corpus-summary.md
```

---

## 4. Anonymization + aggregation

- The aggregation harness **drops `meta.client`** on the way in; each app becomes an opaque ordinal
  (`app-01`, `app-02`, …). The corpus summary and its rendered text carry **no app identity** — this is
  asserted by a test.
- Only aggregate counts and percentages are published. No per-app finding, evidence snippet, location, or
  identifying detail appears in the aggregate report.
- The per-app findings.json files (which DO name the app) are working artifacts, kept out of the published
  material and out of the repo (they are engagement/client data — the `report-template/findings.*.json`
  sensitive-path rule applies in spirit).

---

## 5. Responsible-disclosure + publish gate (operator must clear before anything ships)

This gate is mandatory and precedes publication. It is an operator responsibility; the tooling does not
and must not perform it.

1. **Aggregate is safe to publish; specifics are not.** The anonymized percentage and breakdown may be
   published. A finding tied to an identifiable live app may **not** be published as an exploitable detail.
2. **Notify before publishing specifics.** For any identifiable app whose finding would be recognizable,
   the maintainer is notified first and given reasonable time to remediate, before anything specific to
   that app is published. Never publish an exploitable detail against an identifiable app.
3. **No exploitation, no live third-party testing.** We read source and stand up our OWN local stack. We
   do not attack, log into, or run the dynamic pen-test against anyone's hosted deployment.
4. **Publish approval.** The operator signs off on (a) the exact wording of the headline stat, (b) the
   corpus list's disclosure status, and (c) the publication venue/URL, before release. Publishing is not
   an automated step.
5. **Ethics-as-brand.** This discipline is itself brand-positive and keeps the research defensible
   (`docs/gtm/04-marketing-engine.md` ethics guardrail).

---

## 6. Publication + distribution (operator, post-gate)

Per `docs/gtm/04-marketing-engine.md` and `06-seo-aeo.md`: publish at a stable URL with answer-engine
optimizations (a precisely-worded quotable stat in the first 50 words; `FAQPage`/`Article` JSON-LD;
`llms.txt` entry); seed simultaneously to the curated newsletters (Next.js Weekly, Bytes, TLDR) and the
communities (r/vibecoding, Supabase/Lovable Discords). The report doubles as the sample-report proof and
the "here's what we find" sales artifact. Cadence: one flagship to launch, then a lighter quarterly
"state of vibe-coded security" refresh — re-run the same harness over a fresh corpus.

---

## 7. What the harness is / is not

- **Is:** a deterministic aggregator over already-produced per-app findings.json documents. It computes
  the corpus statistic, enforces the anonymization + honest-denominator rules, and renders a shareable
  summary. Tested over synthetic inputs; it invents no results.
- **Is not:** the audit runner (that is `run-audit`), a corpus fetcher, or a publisher. It does not reach
  the network, does not name apps, and does not decide what is safe to publish.
