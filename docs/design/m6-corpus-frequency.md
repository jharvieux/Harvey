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
see): `loadSources` reads `.ts/.tsx/.jsx/.mjs` only (plain `.js` is not loaded); test/story/
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
| 73 | MAYBE | Supabase pagination reinvention | cross-statement by definition (#395's deferral): query chain PLUS nearby offset math |
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

## The headline: AI-generated code carries the catalogue at ~3x professional density

Per-provenance-tier indicator density (mixed-unit sum — matches/files/findings — so read as an
order of magnitude, normalised per KLOC of product code the loader sees). Measured 2026-07-18:

| Tier | Repos | Indicators | Product LOC | Indicators / KLOC |
|---|---|---:|---:|---:|
| **professional** | subscription-payments, boxyhq, saas-lite | 13 | 41,222 | **0.32** |
| **ai-assisted** | proposit, effective | 86 | 426,843 | **0.20** |
| **ai-generated** (organic) | mvp-boilerplate, cravab, flori-web | 151 | 137,661 | **1.10** |
| unclear | multi-tenant-starter | 3 | 1,526 | 1.97 |
| curated (weighted separately) | teardown | 7 | 1,409 | 4.97 |

**Organic ai-generated code shows ~3.4x the hand-rolled-primitive density of professional code
(1.10 vs 0.32 per KLOC).** That is the measured signal #413 asked for, and it is in the expected
direction: the vibe-coded MVP tier reinvents standard primitives markedly more than maintained
professional starter kits do.

Two honesty caveats, both measured:
- **ai-assisted is NOT elevated** (0.20/KLOC, actually below professional). effective (390k of the
  426k ai-assisted LOC) is higher-skill Effect TS and dilutes the tier — consistent with
  "capable-dev-with-AI" being a genuinely different population from vibe-coding, which is exactly
  why the classification keeps them apart. The blended "all organic AI" figure (0.42/KLOC over
  564k LOC) is therefore an underread, dragged down by effective's size; the ai-*generated* tier is
  the honest AI-vibe-coding number.
- **curated (teardown) is highest (4.97/KLOC) but must not be read as an AI-frequency signal** —
  its shapes are authored to demonstrate bugs, not organic. It is reported and bucketed separately.

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
3. **ATC and a wider organic-AI sample.** ATC is private (excluded here); the ai-generated tier is
   3 repos. More organic vibe-coded repos on this exact stack (the AI code-gen platforms emit
   Vite/React without committed Supabase migrations, so the pool is Cursor/Claude-assisted) would
   tighten the 1.10/KLOC figure and give the 8 still-zero entries a chance to appear.
