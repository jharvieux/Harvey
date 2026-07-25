# Large-Supabase-schema scale measurement — `crbnos/carbon` (#897)

**What this answers:** every Supabase target in `src/scan/external-corpus.ts` before this was a starter
kit — single- to low-double-digit migration counts — so M10's schema classification, M4's duplication
pass and M7's code tier had *only ever been measured at small scale*. Scale-dependent failures
(timeouts, quadratic analysis, output that becomes unreadable at volume) were structurally invisible.
#897 asked the question the right way round: **the first question is whether anything times out or
degrades, not what it finds.**

Everything below was executed on **2026-07-24** on this machine. Numbers are from runs, not recall.

- Target: `crbnos/carbon` @ `92e19c04417e7023a38264315d7846449fd5c4a1` (open-source manufacturing
  ERP/MES/QMS). Licence NOASSERTION → pinned-clone manifest only, no vendoring, no public teardown.
- Measured surface at that pin: **859** `supabase/migrations` (4,954,187 bytes of SQL), 39 edge
  functions, **4,194 source files loaded** (4,116 product-code), 36 workspaces, React Router 7.
- Machine: node v24.15.0, darwin arm64. Wall clock, not CPU time, except where noted.

## Headline: nothing timed out, nothing degraded quadratically

| Stage | Wall clock | Note |
|---|---|---|
| clone at pin (`--depth 1`) | 3.6 s | |
| `detect-static` (M5-slop, M6-indicator, M7 code, M8-intent, M9) | **19.8 s** | 4,194 files |
| `quality-scan` (M4 jscpd whole-repo + M5 knip × 36 workspaces) | **39.4 s** | |
| `mutation-scan --detect-only` (M8 suite detection) | 0.8 s | |
| M10 read 859 migration files | 0.1 s | 4.95 MB concatenated |
| M10 `classifyMigrationSql` over that 4.95 MB | **0.1 s** | 154 tables classified |
| `quick-scan` — the whole free tier incl. the mechanical M1 binaries | **76 s** | 268 s user / 382 % CPU |

**M10 is linear and fast.** The module #897 most suspected of scale failure — classification over the
largest public Supabase policy surface found — parsed 4.95 MB of DDL and classified 154 tables in
**0.1 s**. There is no quadratic behaviour to find here.

**The AST/duplication tier grows super-linearly but nowhere near quadratically.** Across the five
targets measured in the same sweep (all with their deps installed, same machine, same day):

| Target | Source files loaded | `detect-static` | `quality-scan` |
|---|---|---|---|
| ghostfolio | 809 | 2.7 s | 6.0 s |
| rallly | 815 | 1.0 s | 10.6 s |
| documenso | 2,098 | 6.2 s | 9.4 s |
| inbox-zero | 2,364 | 6.7 s | 17.3 s |
| **carbon** | **4,194** | **19.8 s** | **39.4 s** |

2.0× the files (2,098 → 4,194) costs 3.2× the `detect-static` time. Super-linear, but a quadratic
pass would have cost 4× and a 5× file-count range would have blown the budget outright; it did not.
**No module hit the `quality-scan` timeout, none hung, none needed scoping down.**

## What DID fail at scale — three product findings

### 1. Output volume is the real failure mode, and it is severe

The free source tier produced **8,027 counted findings** on this one target:

| Module | Counted | Total |
|---|---|---|
| M4 duplication | 3,251 | 4,526 |
| M5-knip dead code | 2,773 | 2,775 |
| M5-slop | 1,125 | 1,263 |
| M7 performance | 673 | 841 |
| M10 data classification | 154 | 154 |
| M6-indicator | 48 | 48 |
| M8-intent | 3 | 3 |
| M4-diverged / M9 | 0 | 0 / 1 |

> Two rows in that table have since moved and are kept as the original reading: **M10** is 214, not
> 154 (#936 camelCase tokenization, see §3), and **M9** is 241, not 0 (#916–#918 React Router 7
> support, see "What could NOT be measured"). The volume finding gets worse, not better.

`quality-scan` alone wrote a 7,301-finding JSON. That is not a report a client can act on, and it is
not something the renderer was designed against — the corpus's previous maximum was proposit's 105.
**The scanners scale; the deliverable does not.** Filed as its own issue rather than treated as a
reason to drop the target, per #897's own instruction.

### 2. The free tier cried wolf at scale — grade **F (0/100)** on placeholder credentials (FIXED, #934 + #996)

> **Update 2026-07-24 (#934):** the placeholder-credential class is reclassified — gitleaks
> high-precision hits in doc/example-deployment paths (`docs/**`, `contrib/**`, `*.md`/`*.mdx`,
> example/sample files, `*.dev.yml` composes) now report at Low in the non-grading informational
> section with the reason stated; TruffleHog live-VERIFIED secrets are exempt. Re-measured on this
> pin: all 14 former Criticals report informational, 0 graded. carbon is now in
> `FREE_TIER_EXPECTATIONS` (weekly-scored `mustNotGradeDocContextCreds` invariant).
>
> **Update 2026-07-24 (#996) — the F is gone; this section is a historical record.** The remaining
> 11 graded Highs were re-tiered: 7 bare-wildcard CORS headers with no credentials signal (the
> correct shape for a deliberately-public endpoint) route to `harvey-permissive-cors-bare`, 3
> GitHub-Actions workflow findings move to a non-grading "CI/CD pipeline hygiene" report section,
> and 1 `postMessage(data, "*")` becomes non-grading informational — data sensitivity is a paid-LLM
> judgment. `computeGrade` also now penalizes distinct problem CLASSES rather than copies (full
> penalty for a class's most severe instance, +3 per repeat). MEASURED 2026-07-24 post-change:
> **grade A (97/100)**, graded set 1 Low (unpinned deps), 27 findings before AND after — all 11
> former Highs still fully reported. carbon's `mustNotScoreF` is now `true` in
> `FREE_TIER_EXPECTATIONS`. Falsify with `pnpm corpus-drift --target carbon`.

`quick-scan` graded carbon **F (0/100)** on 26 verified hygiene issues: 14 Critical, 11 High, 1 Low.
Every one of the 14 Criticals inspected is a **placeholder credential in documentation or an example
deployment file** — `contrib/deploying/simple-docker-caddy/docker-compose.prod.yml`,
`packages/dev/docker/docker-compose.dev.yml`, `docs/content/docs/platform/self-hosting/*.mdx`, and one
in a vendored agent-skill reference doc. Not one is an application secret.

This is #227's don't-cry-wolf invariant failing on a real, professionally-maintained product, and it
only shows up at scale because a large repo ships a large self-hosting/docs surface. A starter kit has
one docker-compose; an ERP has nine. **This is a finding about Harvey, not about carbon** — no
disclosure is warranted and none was filed.

### 3. M10's severity model did not separate an ERP from a starter kit — half of it was a tokenizer bug (#936)

154 PII-bearing tables were classified across a schema carrying **employee, supplier, customer,
contact and address records**, and the highest severity produced anywhere in those 154 tables was
**Medium** — at or below what `subscription-payments`, a 5-table billing demo, tops out at. That
read as a severity-model problem.

> **Update 2026-07-24 (#936/#968):** a large part of it was not the severity model but the
> **tokenizer** — M10 split column names on `_` only, so every camelCase column was invisible and
> **60 PII-bearing tables were silently classified NONE**. With camelCase tokenization the same pin
> MEASURED **214 PII-bearing tables** (4,951 columns scanned, 177 PII-bearing) at 4 High / 14
> Medium / 196 Low, and the severity ceiling moved Medium → **High**: `company` 6.3
> (taxId+address+phone+fax+email), `oauthClient`/`printerRoute` 6.3 (name+apiKey), `oauthToken` 6
> (authToken). **This supersedes the "154 tables / Medium ceiling" figures above**, which are kept
> only as the record of what the bug looked like. The residual complaint — that 214 undifferentiated
> rows give an operator little to triage by — stands. Falsify with
> `pnpm corpus-drift --target carbon`.

## What could NOT be measured, and why

Recorded as reasons, never omitted (the coverage guard):

- **M8 mutation scoring.** `npm install` fails outright on this target — `EUNSUPPORTEDPROTOCOL:
  Unsupported URL Type "catalog:"` (a pnpm catalog dependency). `corpus-drift`'s `installTargetDeps`
  swallows exactly this, so no runner and no Stryker can be provisioned by `corpus-m8.yml` as built.
  A suite IS detected, so #224's zero-coverage finding correctly does not fire. Recorded not-run with
  that reason in the manifest.
- **M5-knip runs in reduced tier.** Same install failure → knip runs in #810's no-dependencies mode
  across all 36 workspaces and discloses it as the M5-98 row. The 2,773 is a **drift** baseline, not a
  dead-code claim. This reproduces in CI (the job's install fails the same way), which is why the
  baseline is recorded from a no-deps run rather than a locally-privileged one.
- **M9 was not applicable *at the time of this measurement*.** carbon is React Router 7 (framework
  mode), not Next.js App Router. #903's guard emitted `M9 not assessed — React Router 7 (framework
  mode) (framework not supported)` as an Info row instead of a silent zero, and the guard behaved
  correctly on the corpus's largest target.

  > **Update 2026-07-24 (#916–#918, #964):** M9 is no longer Next-only — the framework-agnostic
  > boundary model routes React Router 7 to an adapter, so carbon **is** analysed now. MEASURED on
  > the same pin: **241 counted / 248 total** (7 Info not-assessed rows), after #964's precision fix
  > removed 106 reproduced FPs from an initial 347. The residual 241 were individually confirmed:
  > 116 Low SSR-only API misuse, 66 High route-action missing input validation, 56 Medium
  > data-fetching waterfall, 3 High server→client leak. The `M9 0 / 1` row in the volume table above
  > is therefore the pre-#916 reading. Falsify with `pnpm corpus-drift --target carbon`.
- **M1 semantic, M2 dynamic, M3, M6 verdict, M7 advisors, M10 live.** Out of scope for #897, which is
  a source-tier scale measurement. No live stack was stood up and no client DB exists for this target.

## What is now pinned

`carbon` is a `CorpusTarget` in `src/scan/external-corpus.ts` with per-module baselines measured as
above. `pnpm corpus-drift --target carbon --install` scores **9/9 green** against them (verified
2026-07-24 on a fresh clone, which is a different absolute path from the one used for the timings —
so the numbers reproduce across environments, not just in place).

The cost to the weekly job is roughly one extra minute of scanning plus a failed install; the 30-minute
timeout in `corpus-drift.yml` still holds with all five 2026-07-24 additions.
