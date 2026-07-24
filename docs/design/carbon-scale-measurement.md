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

`quality-scan` alone wrote a 7,301-finding JSON. That is not a report a client can act on, and it is
not something the renderer was designed against — the corpus's previous maximum was proposit's 105.
**The scanners scale; the deliverable does not.** Filed as its own issue rather than treated as a
reason to drop the target, per #897's own instruction.

### 2. The free tier cries wolf at scale — grade **F (0/100)** on placeholder credentials

> **Update 2026-07-24 (#934):** the placeholder-credential class is reclassified — gitleaks
> high-precision hits in doc/example-deployment paths (`docs/**`, `contrib/**`, `*.md`/`*.mdx`,
> example/sample files, `*.dev.yml` composes) now report at Low in the non-grading informational
> section with the reason stated; TruffleHog live-VERIFIED secrets are exempt. Re-measured on this
> pin: all 14 former Criticals report informational, 0 graded. carbon is now in
> `FREE_TIER_EXPECTATIONS` (weekly-scored `mustNotGradeDocContextCreds` invariant). The grade
> remains F (0/100) on 11 graded Highs; their precision/severity decisions and the
> `mustNotScoreF: true` flip are tracked in #996.

`quick-scan` graded carbon **F (0/100)** on 26 verified hygiene issues: 14 Critical, 11 High, 1 Low.
Every one of the 14 Criticals inspected is a **placeholder credential in documentation or an example
deployment file** — `contrib/deploying/simple-docker-caddy/docker-compose.prod.yml`,
`packages/dev/docker/docker-compose.dev.yml`, `docs/content/docs/platform/self-hosting/*.mdx`, and one
in a vendored agent-skill reference doc. Not one is an application secret.

This is #227's don't-cry-wolf invariant failing on a real, professionally-maintained product, and it
only shows up at scale because a large repo ships a large self-hosting/docs surface. A starter kit has
one docker-compose; an ERP has nine. **This is a finding about Harvey, not about carbon** — no
disclosure is warranted and none was filed.

### 3. M10's severity model does not separate an ERP from a starter kit

154 PII-bearing tables were classified across a schema carrying **employee, supplier, customer,
contact and address records**. The highest severity produced anywhere in those 154 tables is
**Medium**. `subscription-payments` — a billing demo with 5 classified tables — also tops out at High.
A model that ranks a manufacturing ERP's HR and supplier data at or below a Stripe template's is not
discriminating, and volume alone (154 rows) gives an operator nothing to triage by.

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
- **M9 is not applicable.** carbon is React Router 7 (framework mode), not Next.js App Router. #903's
  guard emits `M9 not assessed — React Router 7 (framework mode) (framework not supported)` as an Info
  row instead of a silent zero. This is the largest target in the corpus and the guard behaved
  correctly on it.
- **M1 semantic, M2 dynamic, M3, M6 verdict, M7 advisors, M10 live.** Out of scope for #897, which is
  a source-tier scale measurement. No live stack was stood up and no client DB exists for this target.

## What is now pinned

`carbon` is a `CorpusTarget` in `src/scan/external-corpus.ts` with per-module baselines measured as
above. `pnpm corpus-drift --target carbon --install` scores **9/9 green** against them (verified
2026-07-24 on a fresh clone, which is a different absolute path from the one used for the timings —
so the numbers reproduce across environments, not just in place).

The cost to the weekly job is roughly one extra minute of scanning plus a failed install; the 30-minute
timeout in `corpus-drift.yml` still holds with all five 2026-07-24 additions.
