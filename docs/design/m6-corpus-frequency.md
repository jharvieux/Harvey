# M6 hand-rolled-shape frequency on the external corpus (#406 item 1)

Measured **2026-07-16** by `pnpm handrolled-frequency` (src/cli/handrolled-frequency.ts). This
replaces the judgment rankings in `docs/design/m6-handrolled-catalogue.md` with measurement for
the 5 SHIPPED, 25 YES, and 34 MAYBE entries, so detector batch 2 can be ordered by measured
frequency. **Regenerate with exactly that command** — per the repo's measure-don't-recall
doctrine, no number below may be quoted without rerunning it.

## What these numbers are — and are not

These are **shape-presence counts by stated signature** on six pinned repos:

- The 5 SHIPPED classes are counted by running `detectHandrolledFindings` itself — the real
  detector is the measurement (package.json files stay in the input, so the class-merge dep-gate
  behaves exactly as in production).
- Every other measured shape is counted by an explicit signature recorded next to its catalogue
  entry number in `src/scan/handrolled-frequency.ts`, each gated by a test
  (`handrolled-frequency.test.ts`) that the signature matches its own canonical example — a
  signature that can't match its own example would report an honest-looking junk zero.
- They are **NOT detector-precision claims and NOT recall claims**, and per #265's constraint
  **no precision number of any kind is claimed for any tier of M6**. A count says "this shape
  appears N times by this signature on this corpus", nothing more. The two dep-gated entries
  (28, 81) are counted **ungated** — raw shape presence, since the question is how common the
  shape is, not whether a detector would fire.

Scope caveats (all inherited from the product loader so counts match what the detectors would
see): at measurement time `loadSources` read `.ts/.tsx/.jsx/.mjs` only, so plain `.js` was NOT
loaded — **that is no longer true of the loader**. #1065 widened it to the whole JS/TS family
(`.ts/.tsx/.jsx/.js/.mjs/.cjs/.mts/.cts`, `SOURCE_FILE` in `src/detectors/load-sources.ts`),
because omitting `.js` meant a plain-JavaScript app was read as effectively empty. The counts below
were measured under the OLD filter and have not been re-measured since; a re-run would see more
files on any corpus entry containing `.js` sources, so treat them as a dated floor, not a current
figure. Test/story/
fixture files are excluded via `NON_PRODUCT`; vendored subtrees (e.g. mvp-boilerplate's
`monero/`) are **not** excluded, unlike M4's #232 denominator fix.

## The corpus (pinned commits)

| Slug | Repo | Commit |
|---|---|---|
| proposit | JakeLeoDev/proposit | 82838cef3606a176c4bca0af0587c5ea6b08d3a0 |
| subscription-payments | vercel/nextjs-subscription-payments | bdd0813206e47e6b218d42f15a7976c8a0d3c3eb |
| boxyhq | boxyhq/saas-starter-kit | abc9b686823cbfb4973c79bc36fea37a3244be6c |
| multi-tenant-starter | Wallens11/supabase-multi-tenant-starter | dcc147c0f945737f69df79e8aa544dc09e84ccbb |
| mvp-boilerplate | devtodollars/mvp-boilerplate | 2aac5c2fcb45c35aa4a5f5eb9eb66645f0f84e70 |
| saas-lite | makerkit/nextjs-saas-starter-kit-lite | 37def9c20b01a3514cf69b5b3383bef3e5ffbcb9 |

## Counts (2026-07-16 run)

Unit "matches" = signature occurrences; "files" = files where the signature holds;
"findings" = the shipped detector's emitted findings.

| # | Verdict | Shape | Unit | proposit | subscription-payments | boxyhq | multi-tenant-starter | mvp-boilerplate | saas-lite | Total |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| 2 | SHIPPED | JSON deep-equal | findings | 2 | 0 | 0 | 0 | 0 | 0 | 2 |
| 3 | YES | unique via filter + indexOf self-compare | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 4 | YES | flatten via reduce + concat with [] seed | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 5 | MAYBE | group-by via reduce pushing into acc[key] | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 6 | MAYBE | chunk/window via slice(i, i + n) | matches | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| 11 | YES | shuffle via sort(() => Math.random() - 0.5) | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 12 | MAYBE | min/max via reduce comparison | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 13 | YES | zero-padding via ("0" + n).slice(-2) | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 15 | MAYBE | case-converter regex chains | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 16 | YES | path-get via split(".").reduce(…) | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 18 | MAYBE | HTML-entity escaping replace chain | matches | 4 | 0 | 0 | 0 | 0 | 0 | 4 |
| 21 | SHIPPED | Math.random().toString(radix>10) id | findings | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 22 | MAYBE | char-loop id builder (random index into charset) | matches | 0 | 0 | 1 | 0 | 0 | 0 | 1 |
| 23 | YES | UUID-v4 template-string snippet | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 24 | YES | composite Date.now() + Math.random() ids | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 27 | YES | non-crypto string-hash loop (djb2/FNV/java-31) | files | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 28 | YES | date math on raw ms constants | matches | 1 | 1 | 6 | 1 | 2 | 0 | 11 |
| 29 | YES | formatDate via getFullYear/getMonth/getDate concat | files | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| 30 | YES | month/day-name literal arrays | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 31 | MAYBE | relative "time ago" if-ladder | files | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 34 | MAYBE | duration formatting via /3600 and %60 | files | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 35 | MAYBE | leap-year modulo chain | matches | 0 | 0 | 0 | 0 | 1 | 0 | 1 |
| 36 | SHIPPED | query-string parsing via splits | findings | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 37 | YES | query-string building via .join("&") | matches | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| 39 | MAYBE | path joining slash-de-dup replace | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 40 | MAYBE | slugify one-liner | matches | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| 41 | YES | MIME-type lookup table | files | 3 | 0 | 0 | 1 | 1 | 0 | 5 |
| 42 | YES | base64url conversion replace chain | matches | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| 43 | MAYBE | hex encode/decode loop | files | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| 44 | YES | fetch timeout via Promise.race | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 47 | MAYBE | polling via setInterval + fetch | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 51 | SHIPPED | cookie parsing by hand | findings | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| 52 | YES | cookie serialization by hand | files | 0 | 0 | 1 | 0 | 0 | 0 | 1 |
| 53 | YES | JWT payload decode by hand | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 57 | SHIPPED | class-string merge (dep-gated) | findings | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 58 | MAYBE | hand-rolled useDebounce hook | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 59 | MAYBE | utility-hook family definitions | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 61 | YES | hand-rolled ErrorBoundary class | files | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 65 | MAYBE | manual <title>/<meta> JSX in app/ files | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 66 | MAYBE | window.location.href = navigation | matches | 1 | 0 | 1 | 0 | 0 | 0 | 2 |
| 67 | MAYBE | middleware pathname.startsWith ladder | files | 0 | 0 | 0 | 1 | 0 | 0 | 1 |
| 68 | YES | JSON.parse(process.env.X) | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 69 | MAYBE | hand-rolled sitemap/robots string building | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 72 | MAYBE | Pages Router idioms inside app/ | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 76 | YES | Supabase storage public-URL concat | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 81 | YES | email-shape validation regex | matches | 1 | 1 | 0 | 0 | 0 | 0 | 2 |
| 83 | MAYBE | URL-shape validation regex | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 88 | YES | currency via symbol + toFixed concat | matches | 3 | 0 | 0 | 0 | 0 | 0 | 3 |
| 89 | YES | thousands-separator lookahead regex | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 90 | MAYBE | byte-size KB/MB/GB ladder | files | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 95 | YES | clipboard via document.execCommand('copy') | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 98 | YES | markdown→HTML via regex replaces | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 99 | MAYBE | CSV assembly via join(,) + join(\n) | files | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 100 | MAYBE | regex-based HTML/XML tag stripping/parsing | matches | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 101 | MAYBE | hand-rolled semver/version compare | matches | 0 | 0 | 0 | 0 | 0 | 2 | 2 |

**Coverage of the catalogue: 55 of 64 shapes measured (5 SHIPPED + 25 of 25 YES + 25 of 34
MAYBE); 9 MAYBE shapes unmeasured, listed below with reasons.** Every YES entry was measurable.

## Unmeasured shapes (9 — a reasoned gap, never a junk count)

| # | Verdict | Shape | Why no honest signature exists |
|---|---|---|---|
| 19 | MAYBE | hand-rolled event emitter | on/off/emit method-set recognition is class-shape AST work; any regex matches nothing or every pub/sub-ish class |
| 32 | MAYBE | manual ISO-date parsing | the catalogue's own blocker stands for measurement too: the crisp subset needs definition first |
| 73 | SHIPPED (#814) | Supabase pagination reinvention | cross-statement by definition (#395's deferral): query chain PLUS nearby offset math — the correlation is now coded (`detectManualPaginationOffset`), graduated on the precision-gate (paired fixtures), not on a corpus signature, so it stays listed here as an unmeasured-but-shipped shape |
| 74 | MAYBE | fetch-all then .data.length count | the countable token is ubiquitous; the shape is the ABSENCE of count options on a distant query |
| 75 | MAYBE | select-then-branch upsert | cross-statement correlation (select + branch + two writes) |
| 82 | MAYBE | phone-number regex | phone regexes too diverse for one stated signature (catalogue's own reason) |
| 92 | MAYBE | list joining "a, b and c" | weak signature per the catalogue; a regex would count ordinary joins |
| 96 | MAYBE | smooth-scroll rAF steppers | rAF + scroll co-occurrence indistinguishable from legitimate animation without loop-shape AST |
| 102 | MAYBE | module-level TTL Map cache | regex cannot scope module level; Map-in-closure alone is every legitimate cache |

## The headline finding: this corpus barely contains the catalogue

**36 of the 55 measured shapes have zero presence across all six repos — including 17 of the 25
YES entries and 3 of the 5 SHIPPED classes.** The grand total across every measured shape is 42
(mixed units — matches/files/findings — so read it as an order of magnitude, not arithmetic), of
which 11 are one shape, #28. The corpus is recorded as ~128k lines in external-corpus.ts's M4
denominators (recorded, not re-measured here). Individual zeros worth naming
because the catalogue's judgment expected otherwise:

- **53 (JWT decode by hand)** — the catalogue called it "rampant in AI Supabase glue (judgment,
  unmeasured)". Measured: **0** on this corpus.
- **76 (Supabase storage public-URL concat)** — "directly on-brand for the wedge". Measured: **0**.
- **23 (UUID-v4 template)** — "the most copy-pasted id snippet on the internet". Measured: **0**.

The honest reading: these six repos are curated, mostly human-maintained starter kits — they are
**not** the AI-generated-code population the catalogue's frequency judgments were about. A zero
here does not mean the shape is rare in AI-written client code; it means this corpus cannot
currently rank it. That is itself the measured result, and it says the corpus needs an
AI-generated tier before "common in AI code" claims can ever be grounded (follow-up below).

## Recommended batch-2 build order (YES entries, measured counts ONLY)

> **Executed 2026-07-16 (#406 item 2):** all eight entries below SHIPPED as detectors, in this
> order — see the catalogue's SHIPPED rows. Detector dogfood on the same pins found the counts
> below are signature counts, not detector counts: the 41 "hits" are repeated `Content-Type`
> header objects (signature over-count, no real lookup table in the corpus), 29 and 37 exist
> only in cross-statement forms the detectors deliberately don't match, and the dep gates
> (28, 81) close most repos. The measurement record below is unchanged.

Non-zero measured YES entries, in measured order (ties broken by entry number, stated):

1. **28** — date math on raw ms constants (11, and the only shape present on 5 of 6 repos)
2. **41** — MIME-type lookup tables (5)
3. **88** — currency via symbol + toFixed concat (3)
4. **81** — email-shape validation regex (2)
5. **29** — formatDate getter concat (1)
6. **37** — query-string building via .join("&") (1)
7. **42** — base64url replace chain (1)
8. **52** — cookie serialization (1)

Measured-zero group — **order unknown, no corpus evidence to rank by; do not interleave by
guess** (17 entries): 3, 4, 11, 13, 16, 23, 24, 27, 30, 44, 53, 61, 68, 76, 89, 95, 98.
Building any of these is speculative until a corpus that contains them exists; they still owe
the same paired-fixture discipline (#61) if built.

No YES entry was unmeasured, so the "unmeasured YES" group is empty. The 9 unmeasured shapes are
all MAYBE and were already deferred on their own blockers; the non-zero MAYBE counts (18: 4,
66: 2, 101: 2, and six at 1) are recorded above for whenever those blockers resolve.

## Follow-up this measurement creates

1. The six-repo corpus under-represents the population M6 targets (AI-generated app code). An
   AI-generated corpus tier — even a handful of representative vibe-coded repos, pinned the same
   way — is what would make these frequencies decision-grade. Until then, batch-2 ordering rests
   on 42 total observations.
2. The catalogue's "Honesty note on ranking" and follow-up item 1 are now satisfied/stale — the
   catalogue should point here (done in the same PR, `docs/design/*.md` is agent-editable).

---

# Per-provenance-tier frequency: AI-generated vs professional (#413)

Measured **2026-07-18** by `pnpm handrolled-frequency` (same command, now extended). Follow-up
item 1 above — "the corpus needs an AI-generated tier before 'common in AI code' claims can be
grounded" — is what this section answers. **Rerun the command to regenerate; per measure-don't-
recall no number here may be quoted without a fresh run.**

## What changed

Every corpus repo now carries an evidence-based `provenance` tag in `src/scan/external-corpus.ts`
(professional / ai-assisted / ai-generated / unclear), and four AI-authored repos were added as a
frequency-only list (`AI_FREQUENCY_CORPUS` in `src/scan/handrolled-frequency.ts`) — **clone-and-
count only, NOT full corpus-drift entries** (establishing honest M4/M5/M7/M8/M9/M10 baselines for
them is a separate, heavier follow-up; fabricating them would be the junk number the repo forbids).
Source is never vendored, so the AGPL/no-license repos are scan-only.

### The provenance-tagged corpus (10 repos, pinned)

| Slug | Repo | Provenance | Evidence |
|---|---|---|---|
| proposit | JakeLeoDev/proposit | ai-assisted | Claude trailers + CLAUDE.md, but real 2-dev team, CI, no slop |
| subscription-payments | vercel/nextjs-subscription-payments | professional | Vercel official template, 31 contributors, no AI files |
| boxyhq | boxyhq/saas-starter-kit | professional | org product, 39 contributors, versioned releases |
| multi-tenant-starter | Wallens11/supabase-multi-tenant-starter | unclear | single-dump commit (mild AI tell) but cleanest code, no fingerprints |
| mvp-boilerplate | devtodollars/mvp-boilerplate | ai-generated | Co-Authored-By: Claude Opus 4.6, CLAUDE.md + agent-skills |
| saas-lite | makerkit/nextjs-saas-starter-kit-lite | professional | commercial Makerkit free tier, renovate/syncpack |
| cravab | stoimera/Cravab | ai-generated (NEW) | `.cursor/rules` mandating tenant_id, AI-slop README — AGPL |
| flori-web | flori-ai-kr/web | ai-generated (NEW) | Co-Authored-By: Claude on ~40 commits + CLAUDE.md — no license |
| effective | joshcoolman/effective | ai-assisted (NEW) | CLAUDE.md + Claude co-author, higher-skill Effect TS — MIT |
| teardown | vandyand/saas-security-teardown | ai-generated, **curated** (NEW) | 'vibe-coded' README; intentionally-vulnerable — bucketed separately |

ATC (jharvieux/atc), operator-confirmed all-AI-generated, is a PRIVATE repo and was NOT cloned;
excluded here rather than guessed (no already-measured M6 frequency numbers exist for it in-repo).

## WITHDRAWN 2026-07-30 (#1600): the AI-vs-professional density ratio

This section used to publish a headline: *"Organic ai-generated code shows ~3.4x the hand-rolled-
primitive density of professional code (1.10 vs 0.32 per KLOC)."* **That claim is withdrawn.** It is
not being refreshed with a newer number, because the number's age was never the defect.

**Why.** The ratio is computed across the per-repo `provenance` tiers in
`src/scan/external-corpus.ts`, and every one of those tiers was assigned **by us, by inspection** — a
`CLAUDE.md` here, a `Co-Authored-By` trailer there, the tone of a README. Nothing verifies them, and
nothing ever did. A ratio computed across labels we assigned reports the labelling, on exactly the
reasoning `CLAUDE.md` already applies to answer keys: an answer key we wrote measures our internal
consistency rather than our coverage. Two further problems ride along: 18 repos chosen for scanner-calibration
purposes is a convenience sample, so it supports a claim about itself rather than about AI code *in
general*, which is how a bolded "~3.4x" reads; and the tiers compare **different repos**, so team, era, domain and language
mix all vary alongside the label.

**Treat every tier-based number below as bookkeeping.** The `provenance` field stays: it is
genuinely useful for describing what the corpus contains and for choosing what to add next. What it
may not do is carry a published comparison. The disclosure this issue requires — that the tiers are
assigned by inspection and checked by nothing — is recorded as a re-testable claim rather than as
prose, so that the day someone builds the verifier, this paragraph fails loud instead of quietly
becoming false:

```
REASON: the per-repo `provenance` tiers in src/scan/external-corpus.ts are assigned by our own inspection and no tool, test or gate checks one against evidence, so no comparison computed across those tiers is published
KIND: empirical
PROVENANCE: MEASURED 2026-07-30 — the field is set as a literal on each corpus entry and read only for grouping and reporting (src/cli/handrolled-frequency.ts, src/cli/genai-admission-census.ts); the repo has no provenance verifier. Exercised in both directions the same day: as committed it exits 1, and with a `src/cli/validate-provenance.ts` present it exits 0.
FALSIFIER: test -d src/cli || exit 127; ls src/cli/validate-provenance.ts >/dev/null 2>&1 && exit 0 || exit 1
TOUCHES: src/scan/external-corpus.ts docs/design/m6-corpus-frequency.md
```

**What the tiers measure today.** Re-measured 2026-07-30 with `pnpm handrolled-frequency` over the
18-repo pinned corpus (branch base `d41ba3a`). Mixed-unit indicator sum — matches/files/findings —
normalised per KLOC of the product code the loader sees, so read as an order of magnitude:

| Tier | Repos | Indicators | Product LOC | Indicators / KLOC |
|---|---:|---:|---:|---:|
| professional | 5 | 90 | 321,744 | 0.28 |
| ai-assisted | 6 | 587 | 1,941,955 | 0.30 |
| ai-generated | 4 | 155 | 137,082 | 1.13 |
| unclear | 2 | 12 | 7,919 | 1.52 |
| curated (bucketed separately) | 1 | 7 | 1,409 | 4.97 |

**The strongest single reason not to publish any ratio from this table is inside the table.** That
one run supports either of these sentences, both arithmetically correct:

- "AI code carries the catalogue at **4.0x** professional density" — ai-generated 1.13 vs professional 0.28.
- "AI code carries the catalogue at **1.3x** professional density" — all organic AI (ai-generated + ai-assisted) 0.36 vs professional 0.28.

They differ threefold, and the only thing that moved between them is which of our own guessed tiers
were grouped together. A figure that swings 3x on a labelling choice is reporting the labelling.

One correction for the record, because the drift is easy to misread in the opposite direction: the
withdrawn 3.4x was the **ai-generated-tier** comparison (1.10 vs 0.32), and that same quantity
measures **4.04x** today — it went up, not down. The 1.3x figure quoted while #1600 was being triaged
is the *blend*, a different quantity. The claim is withdrawn for having no verified ground truth
underneath it, which is true at any value; had it been withdrawn only for being stale, a re-measure
would have "confirmed" it.

Two observations that survive as observations about **these 18 repos**, under the label disclosure
recorded above, and that are not comparisons:

- **The `ai-assisted` tier is not elevated** (0.30/KLOC, level with professional's 0.28). Its two
  largest members, carbon (1.03M LOC) and effective (390k), are high-skill codebases. Whatever the
  tier names, it does not behave like the vibe-coded end of the corpus.
- **`curated` (teardown) is highest at 4.97/KLOC and is not an AI signal at all** — its shapes are
  authored to demonstrate bugs. It is bucketed separately for that reason.

## What replaced it (#1600 step 2): a within-repo, self-declared comparison — and its NEGATIVE result

The operator ruling on #1600 was option (b): **re-found the claim on a methodology whose ground
truth does not come from us guessing.** That was done, and the answer is that **the difference does
not reproduce.**

### The method, and why it is not the old one

`pnpm genai-admission-census --density` (`src/cli/genai-admission-census.ts`). The label is
**commit-level self-admission**: a commit whose own author declared GenAI involvement, either by a
`Co-authored-by:` trailer naming an assistant or by naming one in the message. Three properties the
per-tier ratio never had:

1. **The label is declared, not inferred.** It is written by the commit's author or their tool, not
   assigned by us from a README's tone.
2. **The comparison is WITHIN one repo.** Same team, same language, same era, same domain, same
   reviewers. The per-tier version compared different repos and attributed the difference to the
   label; every one of those confounds is held constant here.
3. **Attribution is per line.** `git blame` maps every product line at the pinned commit to the
   commit that last wrote it; each arm's findings are normalised by that arm's own attributed lines,
   so the larger arm does not dominate the smaller.

### The population, stated before the result

Measured 2026-07-30 over the 18-repo pinned corpus, at each repo's pinned commit, merges excluded:

- **30,330** commits in corpus history; **21,123** touch product source.
- **1,112** of those are self-admitted; **20,011** are not.
- By signal: **1,289** admissions carry a trailer (high precision), **171** are prose-only (low
  precision — reported separately, never blended).
- **12 of 18** repos contain at least one self-admission.
- **3 of 18** supply BOTH arms at ≥30 product-touching commits: **rallly, inbox-zero, carbon**. The
  other 15 are effectively single-armed — flori-web is 119 admitted against 8 not, boxyhq 0 against
  342 — and pooling them across repos would rebuild the per-repo confound this design exists to
  remove, so they are excluded rather than pooled.

That population is the reason the answer is three repos and not eighteen. It is a real limit, and it
is measured rather than assumed.

### The result

| Repo | AI-declared lines | findings | /KLOC | Not-declared lines | findings | /KLOC | rate ratio | 95% CI |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| rallly | 37,603 | 14 | 0.37 | 35,357 | 10 | 0.28 | **1.32x** | [0.54, 3.31] |
| inbox-zero | 76,270 | 15 | 0.20 | 164,990 | 36 | 0.22 | **0.90x** | [0.46, 1.69] |
| carbon | 207,034 | 8 | 0.04 | 822,446 | 40 | 0.05 | **0.79x** | [0.32, 1.72] |

Intervals are exact Poisson rate-ratio intervals (conditional-binomial / Clopper-Pearson). Pooled
across the three repos as strata (Mantel-Haenszel): **0.95**. Totals: 37 findings in the declared-AI
arm, 86 in the not-declared arm.

**Every interval includes 1, and two of the three point estimates are BELOW 1** — that is, in
inbox-zero and carbon the self-declared-AI code carried *fewer* hand-rolled primitives per KLOC than
the rest of the same repo. **On the only ground truth here that we did not assign ourselves, there is
no detectable difference in hand-rolled-primitive density between declared-AI code and the rest.**

This is recorded as the finding. It is not a smaller version of the old claim and it is not a
starting point for tuning: the withdrawn number said 3.4x, the same tiers say 4.0x today, and the
re-founded method says 0.95x with intervals that span 1. Nothing here licenses restating a
difference at any magnitude.

### What this result does NOT establish

- **It is not evidence that AI code is the same as human code in general.** Three repos are not a
  sample of anything, all three sit in the `ai-assisted` tier under the label disclosure recorded
  above, and the M6
  hand-rolled catalogue measures one narrow property.
- **The arms are not clean.** Self-admission is a **biased sample**: the not-declared arm certainly
  contains AI-written code whose author did not say so, which biases any real difference *toward*
  the null. A null result under that bias is weaker evidence of no effect than it looks.
- **Declaration practice is tool-driven.** An assistant that writes a trailer by default produces
  admissions; one that does not produces none, independent of how much code it wrote.
- **Blame is last-writer, not author-of-the-logic.** An admitted commit that reformats or moves a
  file inherits every line it touched.
- **The counts are small** (8–36 findings per arm). The intervals say so.

### External research — read in full vs. skimmed

Recorded because #1600 requires it, and because quoting an unread number is the defect this section
exists to correct.

**Read in full (end to end, including appendices):**

- **Xiao et al., "Self-Admitted GenAI Usage in Open-Source Software"** ([arXiv:2507.10422](https://arxiv.org/pdf/2507.10422), 9pp).
  Source of the method above. Load-bearing details that came from reading it rather than from a
  summary: their funnel is 207,062 repositories → 14,785 engineered projects → 3,004 raw mentions →
  **1,292 true-positive self-admissions across 156 repos**; **1,003 of the 1,292 target COMMIT
  MESSAGES**, only ~176 target source files, and 1,000 of the 1,009 "PR description" instances come
  from a single repository. Their prose retrieval kept 1,292 of 3,004 (~43%) after manual review —
  the reason our prose bucket is reported separately from the trailer bucket. Their Table 7
  catalogues projects whose policies **prohibit** GenAI contributions, which is the concrete
  mechanism behind "self-admission is a biased sample". Two departures from them, deliberate: they
  searched prose for `ChatGPT`/`Copilot` only and did **not** use `Co-authored-by:` trailers, which
  is the signal that carries almost all of this corpus's admissions (1,289 of 1,460).
  **Their own RQ3 is the closest published analogue to our question — an RDD on code churn across
  151 repos at each project's first GenAI mention — and it found NO general increase in churn,
  explicitly contradicting the GitClear narrative.** Our null is consistent with theirs.
- **Cotroneo, Improta, Liguori, "Human-Written vs. AI-Generated Code"** ([arXiv:2508.21634](https://arxiv.org/abs/2508.21634), 8pp).
  Read to decide whether their design transfers. **It does not**, for two reasons only visible in the
  paper: the corpus is **Python and Java** exclusively (Table II: 285,249 Python / 221,795 Java
  samples), and the unit is an isolated function **regenerated from its own docstring**. The M6
  catalogue is about reinventing *ecosystem* primitives in a JS/TS project with a dependency tree —
  a docstring-scoped function regeneration has no dependency tree to reinvent against. Worth noting
  in the other direction: they report human-written code carrying *more* maintainability issues and
  greater structural complexity, which cuts against the direction of the withdrawn claim.

- **GitClear, "AI Copilot Code Quality" (v2025.2.5, February 2025)**, 34pp,
  [PDF](https://gitclear-public.s3.us-west-2.amazonaws.com/GitClear-AI-Copilot-Code-Quality-2025.pdf).
  Read end to end including all appendices, because its *design* is the alternative this issue asked
  us to weigh, and four things are visible only from the appendices:
  - **It carries no AI label at all.** The whole design is a calendar-year trend, 2020–2024. It never
    identifies which code an assistant wrote; AI is inferred from the year. So it trades our
    labelling problem for an uncontrolled one — everything else about software also changed over
    those five years. That is a genuine cost, not a free lunch, and it is why the temporal design was
    not simply adopted here.
  - **Its headline duplicate-block figure compares two different sampling procedures.** Appendix A8:
    2020–2023 were backfilled by analysing only "the largest (by Diff Delta) 1,000 commits made to
    each repo", while 2024 was measured directly — commits scanned goes 19,805 (2020) → 56,495
    (2024). The report argues the bias runs against its own conclusion; either way the "~10x" is not
    a like-for-like year comparison.
  - **The population is a customer base**, not a sample: Appendix A2 puts it at roughly two-thirds
    private corporations that opted into anonymised data sharing, one third open source, and notes
    that under half of what a conventional git stats aggregator counts as "lines changed" qualifies.
  - **The 2025 row in its tables is a projection**, produced by fitting a quadratic in ChatGPT's code
    interpreter (final appendix), printed in the same tables as the measured years.
  Figures verified first-hand against Appendix A1, since the circulating summaries are what this
  issue warns about: Moved lines 24.17% (2020) → 9.47% (2024); Copy/pasted 8.86% → 12.32%; churn
  3.05% → 5.67%. The directional summaries in #1600's body are accurate to the source. **None of
  these numbers is used as evidence for anything in this repo** — they are recorded so the next
  reader does not have to re-derive whether the report supports what it is cited for.

**Read in part:**

- **Suh et al., "An Empirical Study on Automatically Detecting AI-Generated Source Code"**
  ([arXiv:2411.04299](https://arxiv.org/abs/2411.04299)). The retrieved PDF was 3 pages and appears
  to be a partial rendering of the paper; those 3 pages were read in full, the rest was not. Only its
  abstract-level finding is used, read directly rather than via a summary: existing AI-code detectors
  *"all perform poorly and lack sufficient generalizability to be practically deployed"*, and their
  own best fine-tuned model reaches F1 82.55. That is the reason no detector-based labelling was
  attempted here — the declared label was chosen instead.

**Not read:**

- GitClear's separate "Maintainability Gap" page, "Impact of GenAI on Code Expertise Models"
  (arXiv:2507.08160), and the devclass summary piece. Nothing is cited from any of them.

**One tension worth recording**, now that both have been read rather than summarised: GitClear reads
a rise in churn off the calendar, with no per-project AI label; Xiao et al. §RQ3 puts an adoption
boundary *inside each project* (RDD at the first GenAI mention, 151 repos) and finds **no general
increase in churn**. The two most credible external designs disagree, and the one with the tighter
identification is the one that finds nothing. Our own null belongs in that context rather than being
read as anomalous.

### Cadence

`pnpm genai-admission-census` runs on no schedule, and neither does `pnpm handrolled-frequency` —
which is exactly why the withdrawn figure survived a 3x growth of the corpus. A scheduled re-measure
needs a `.github/workflows/` change, a supervised path, so the operator question is recorded on
#1600 with the proposed wording rather than made here. **Until it is answered, every figure in this
section is point-in-time**: quote it with its date (2026-07-30) and its corpus base (`d41ba3a`), or
re-run the tool.

## #413's core question: which of the 17 measured-zero YES entries now fire?

Of the 17 YES entries that measured zero across all six original (mostly-professional) repos,
**9 fire on the AI/non-professional tier** — 8 of them on organic AI code, 1 only on the curated
repo. Measured 2026-07-18:

| Entry | Shape | Count | Repos (all AI-authored) |
|---|---|---:|---|
| 24 | composite Date.now() + Math.random() ids | 5 matches | cravab=5 |
| 98 | markdown→HTML via regex replaces | 5 matches | cravab=5 |
| 30 | month/day-name literal arrays | 5 matches | cravab=1, effective=4 |
| 27 | non-crypto string-hash loop (djb2/FNV/java-31) | 2 files | effective=2 |
| 61 | hand-rolled ErrorBoundary class | 2 files | cravab=1, effective=1 |
| 3 | unique via filter + indexOf self-compare | 1 match | cravab=1 |
| 53 | JWT payload decode by hand | 1 match | flori-web=1 |
| 89 | thousands-separator lookahead regex | 1 match | flori-web=1 |
| 76 | Supabase storage public-URL concat | 3 matches | **teardown=3 (CURATED ONLY)** |

Two catalogue-judgment calls the six-repo run had recorded as measured-zero are now vindicated on
AI code: **53 (JWT decode by hand)** — the catalogue's "rampant in AI Supabase glue" — fires on
flori-web; **76 (Supabase storage public-URL concat)** — "directly on-brand for the wedge" — fires,
but ONLY on the curated teardown repo, so it stays unproven on *organic* AI code (an honest
half-answer, not a graduation trigger). **23 (UUID-v4 template)** stayed zero everywhere.

**Still zero on every non-professional repo (8):** 4, 11, 13, 16, 23, 44, 68, 95. These remain
unrankable — a bigger or differently-sourced AI corpus would be needed to see them, if they occur
at all.

## Graduation candidates — SHIPPED 2026-07-18 (#542)

Per #395's discipline, graduating an entry to a shipped detector requires the detector **plus**
paired positive/negative fixtures. All 8 organic-AI-tier entries below graduated in #542 as
mechanical M6 indicator classes (`src/detectors/handrolled.ts`, fixture-gated in
`handrolled.test.ts`, vocabulary-lock extended), each confirmed to fire on a real positive and NOT
on its paired negative:

1. **24** — composite Date.now()+Math.random() ids (5, cravab) — `M6 — Indicator: composite timestamp-random id`.
2. **98** — markdown→HTML via regex replaces (5, cravab) — `M6 — Indicator: markdown-to-HTML by regex`.
3. **30** — month/day-name literal arrays (5: cravab+effective) — `M6 — Indicator: month/day-name array`.
4. **61** — hand-rolled ErrorBoundary class (2: cravab+effective) — `M6 — Indicator: hand-rolled ErrorBoundary`.
5. **27** — non-crypto string-hash loop (2, effective) — `M6 — Indicator: non-crypto string hash`.
6. **3 / 53 / 89** — one organic-AI hit each — `array-unique via filter` / `JWT decode by hand` / `thousands-separator regex`.

**Entry 76 is explicitly NOT graduated** — its only evidence is the curated teardown repo, not
organic AI code, so it stays a YES-not-yet-graduated candidate in the catalogue.

## Follow-ups this measurement creates

1. **Full corpus-drift baselines for the 4 new AI repos.** They are frequency-only today (no
   M4/M5/M7/M8/M9/M10 baselines). Promoting any to a full `ExternalTarget` needs a measured scan +
   triage per module — the heavier follow-up #413 deferred.
2. **Graduation of the 8 candidates above** — DONE 2026-07-18 (#542): all 8 organic-AI-tier YES
   entries shipped as mechanical M6 indicators under the #395 fixture discipline. Entry 76 stays a
   YES candidate (curated-only evidence).
3. **A wider organic-AI sample — for COVERAGE, not for the ratio.** ATC is private (excluded here);
   the ai-generated tier is 4 repos as of 2026-07-30. More repos on this exact stack would give the
   still-zero entries a chance to appear, which is a genuine reason to add them. It would **not**
   rehabilitate the withdrawn density ratio: adding repos does not verify the labels, and the ratio
   was withdrawn for the labels, not the sample size (see the withdrawal section above).
