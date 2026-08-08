# Harvey — the ten modules, what each one finds, and how it runs

A single-page reference for the complete **M1–M10 security & codebase-health audit**.

**Scope authority is `briefs/audit-modules.md`** — this file summarises it and adds the measured
detector counts and run commands. Where the two disagree, the brief wins.

> **All ten modules carry equal weight.** None is "the lead," none is secondary. Running a
> security-only (or any ad-hoc) subset is a defect, not a scan. Security is the *wedge* that gets
> the meeting; the breadth is what makes the engagement worth buying.

---

## At a glance

Detector counts below are **MEASURED 2026-08-01** via `pnpm detector-census`. They count
**detectors capable of firing**, which is *not* recall. **Re-run the census rather than quoting this
table** — it moves with every detector that lands.

| # | Module | Detectors | Tier | What it answers for the client |
|---|--------|----------:|------|--------------------------------|
| **M1** | Multi-tenant security | **238** | free → connected → paid-LLM | *Can one customer reach another's data?* |
| **M2** | Local penetration test | **39** | dynamic (live stack) | *Is that exposure actually reachable — show me the row.* |
| **M3** | Hotspot analysis | **6** | external plugin | *Where should remediation budget go?* |
| **M4** | Duplication | **1** | source-only | *Where will one fix miss three copies?* |
| **M5** | Slop / dead code | **16** | source-only | *How much of this codebase is dead weight?* |
| **M6** | Simplification / maintainability | **33** | free indicators → paid triage | *What was hand-rolled that a library already does?* |
| **M7** | Performance | **32** | source + connected + local-run | *What's slow, and what does it cost?* |
| **M8** | Test quality & intent | **11** | source + target test suite | *Is the coverage number lying to me?* |
| **M9** | Server→client boundary | **21** | source-only | *Is privileged data being shipped to the browser?* |
| **M10** | Data classification | **42** | connected or schema | *Which data is exposed — not just "data".* |
| | **Total distinct detectors** | **439** | | |

M4's count of 1 and M3's of 6 are honest, not gaps: both modules are mostly **wrappers around
external engines** (jscpd, the `vitals` plugin), so the detector count measures Harvey's own code,
not the module's power. M8 is the same shape — 11 static test-intent detectors plus StrykerJS,
which is external and uncounted.

**Stack coverage.** Every module is written against Supabase Postgres + RLS, but **Prisma/Postgres
is a first-class supported shape** (epic #756), and since #869/#901 `detectOrm` also resolves
Drizzle, Kysely, TypeORM, Sequelize, Knex, Mongoose and bare raw-SQL drivers. A non-Supabase target
does not silently lose the RLS detectors — they record **N/A-by-architecture** with an
`M1-ARCH-<LAYER>` row naming the layer.

---

## M1 — Multi-tenant security

**Finds:** cross-tenant data exposure (permissive or missing RLS), service-role bypass,
single-layer isolation, per-route auth gaps, webhook replay, fail-open enforcement, unchecked
mutations, read-modify-write counter races, idempotency ordering, in-memory rate limits,
SSRF-via-URL, state-machine boundary violations, error disclosure.

**Three tiers, and they are different products:**

| Tier | Command | What it proves |
|---|---|---|
| Mechanical (free) | `pnpm quick-scan --dir <t>` | pattern-level defects, scored against a calibration corpus |
| Config (connected) | `pnpm exec tsx src/cli/scan.ts --supabase <ref\|local>` | live RLS/policy state |
| Semantic (paid-LLM) | invoke the `vuln-scan` skill with `briefs/scan-extras.txt`, then the `triage` skill with `briefs/fp-rules.txt` | reasoning a pattern match cannot reach |
| Live policy review | `pnpm detect-deeper` | policy *quality*, not just presence |

**Prisma:** a Prisma app has **no database-level tenant enforcement at all** — there is no RLS to
audit — so every bit of isolation lives in application code, which is exactly where M1's
ORM-agnostic detectors already operate. `src/scan/prisma-tenant-scope.ts` flags the Prisma BOLA
equivalent: `prisma.<model>.update/delete/findFirst` filtered by `id` alone with no tenant column
anywhere in the `where`. Measured **zero RLS-detector false positives** against boxyhq, a real
Prisma app.

**What it cannot see:** M1's rules are JS/TS-only. Every other language present in the target gets
an `M1-LANG-00` not-assessed row naming it. Files the source loader cannot read
(`.svelte`/`.vue`/`.astro`) get a counted row too.

---

## M2 — Local penetration test (dynamic)

**Finds:** what static review can't *prove* — actually reachable cross-tenant access, IDOR on API
routes, missing-auth endpoints, auth/role escalation, rate-limit bypass across instances, injection
that lands. **A proven finding is worth 10× a theoretical one.**

**Method:** stand up the target locally with a **seeded two-tenant dataset**, then run probes as
(a) anon key, (b) tenant-A user, (c) tenant-B user — and assert nobody crosses tenants.

**Run:** `pnpm exec tsx src/cli/pentest.ts` against a local `supabase start` stack.

**Probe families:**

- PostgREST + `pg_graphql` cross-tenant matrices
- Session-lifecycle and auth-attack probes
- Invitation-state revoked-BOLA
- Soft-delete / restore / tenant-teardown data residue
- Share-link identity-class probes
- Supabase Storage object authorization
- API-token / service-account credential-store readability
- **Guest / cross-org-collaborator** — seeds a *third* auth user with a schema-resolved third role
  and proves whether a partially-privileged session reaches another tenant
- **Realtime** — subscribe-and-assert, opt-in behind `HARVEY_PROBE_REALTIME`, with Broadcast and
  Presence cross-identity reach; wire shape proven live against realtime v2.100.0

**Every probed run emits an `M2-SCOPE-RECONSTRUCTION` disclosure**: what was stood up, from which
schema, at which commit, and that **production config was NOT observed**. An unexercised access
path is a `not probed` row *with its reason* — never an absent row.

**Prisma:** no PostgREST and no DB-level RLS, so the Supabase matrix is recorded explicitly
**not-applicable** and isolation is tested through the app's own HTTP routes — including an
authenticated cross-tenant BOLA probe using a two-tenant Team/membership seed with minted sessions.

---

## M3 — Hotspot analysis

**Finds:** the files that are **both** frequently changed **and** complex — where bugs and
maintenance cost concentrate.

**Run:** `pnpm exec tsx src/cli/hotspot-scan.ts <t>` (wraps the `vitals` plugin).

Delivers churn × complexity ranked by **ROI** (core > test, central > leaf), **co-change coupling**,
**knowledge risk** (truck-factor-1 / sole-author files), **AI-provenance** tracking, and health
trends across scans.

**The cross-reference is the value:** a hotspot that is *also* an M1 or M7 finding is the top
remediation priority. M3's `--hotspots-out` feeds M8's mutation targeting and M6's review packet, so
the hottest files get the deepest review.

**Fails loud, two ways:** the installed vitals version is asserted against a pinned expectation, so
upstream drift is caught rather than absorbed. If vitals is unavailable entirely, a Harvey-side
git-only churn×complexity **reduced tier** runs and is disclosed `partial`. An empty truck-factor
list emits `M3-KNOWLEDGE-00` stating whether it was *measured clean* or *never had authorship
history to read* — those are different facts.

---

## M4 — Duplication

**Finds:** copy-paste clones — a bug multiplier and a maintenance tax.

**Run:** `pnpm check:duplication` or `pnpm quality-scan <t>`.

Two passes, and the second is the interesting one:

1. **jscpd** across the source tree — % duplication and the worst clusters.
2. **Diverged-clone near-miss pass**, scoped to security-relevant files: function-level Type-3
   comparison that catches copy-pasted auth/tenant checks **that were then edited**. That is exactly
   the "patched one copy, missed the other" population jscpd's exact-token match *structurally
   cannot see*. Review tier, never a mechanical verdict.

---

## M5 — Slop / dead code

**Finds:** AI-generated cruft and dead weight — narrating comments, single-use helpers, try/catch
that just re-throws, orphan TODOs, unused exports, unreachable branches, stub-shaped code.

**Two engines, and running only one is half the module:**

| Engine | Command | Needs |
|---|---|---|
| Dead code (knip) | `pnpm quality-scan <t>` | target deps installed for confirmed findings |
| Slop AST detectors | `pnpm detect-static <t>` | source only |

If the target's deps aren't installed and knip can't load its config, the run retries with all
plugins disabled and reports **review-tier** dead code, disclosed as an `M5-98` row — never a
silent downgrade.

Every slop class is gated by a **positive + negative fixture pair**, so a class that stops firing
fails the suite.

---

## M6 — Simplification / reuse / maintainability

**Finds:** the supportability tax — hand-rolled implementations of things a stdlib primitive or a
well-known library already does; over-abstraction; inconsistent patterns that raise the bus factor.

**The free/paid split is load-bearing:**

- **Free** lists mechanically-recognisable hand-rolled shapes as **non-grading indicators** —
  *"this looks hand-rolled; may be worth investigating"* — and never names a replacement.
- **Paid** triages each and **names the replacement**. Naming the replacement *is* the asserted
  judgment, which is why the hedged free wording matters.

**Run:** `pnpm quick-scan --dir <t>` (indicators) + `pnpm detect-static <t>` + `pnpm simplify-scan <t>`
(assembles the brief + source into a review packet).

> **`simplify-scan` produces a review PACKET, not a verdict.** Printing source is not running M6.

**Two independent reviewers, mechanically compared.** Measured reviewer variance made single passes
*datapoints, not verdicts*. Two reviewers read the identical packet in fresh independent contexts;
`pnpm exec tsx src/cli/m6-agreement.ts <a.json> <b.json>` computes agreement — never eyeballed.
Unanimous flags go to human triage, unanimous spares are spared, **a split goes to a human
adjudicator with both arguments and never straight into a report**, and a file reviewed by only one
pass is surfaced loudly as uncompared rather than defaulted to spare.

---

## M7 — Performance

**Finds:** N+1 and unindexed foreign-key queries, missing or unused indexes, RLS policies
re-evaluated per row (bare `auth.*` not wrapped in a subquery), over-fetching, missing pagination,
missing caching, oversized client bundles, poor Core Web Vitals, inefficient hot-loop algorithms.

**Three layers:**

| Layer | Command | Tier |
|---|---|---|
| Code | `pnpm detect-static <t>` + `pnpm quick-scan --dir <t>` | source |
| Database advisors | `pnpm perf-scan` | connected |
| Core Web Vitals | `pnpm lighthouse-scan` | local build + serve + browser |

**Prisma:** no Supabase performance advisor exists, so `src/scan/prisma-schema-perf.ts` statically
reviews `schema.prisma` for scalar FK columns with no covering index. Postgres does **not**
implicitly index a relation's FK column the way Prisma's MySQL connector does, so an uncovered FK
forces a sequential scan on every JOIN through that relation and every cascade UPDATE/DELETE on the
parent. Runs from source alone, no live DB.

---

## M8 — Test quality & intent

**Finds:** tests that **cannot fail when the logic changes** — the false-confidence layer.
Tautological and snapshot-only tests, tests that assert WHAT not WHY, high *line* coverage masking
low *mutation* coverage, and the precise code paths with no effective test.

**Two facets:**

1. **Mutation scan** — StrykerJS injects faults (flip `>` to `>=`, negate conditionals, swap
   returns, delete statements) and reports the **mutation score** = % of mutants the suite kills.
   Surviving mutants are the blind spots, located precisely.
2. **Tests-for-intent review** — read the high-value tests (auth, tenant isolation, payments, state
   machines) and flag the ones that would still pass if the behaviour they "cover" were broken.

**Run:** `pnpm detect-static <t>` (test-intent) + `pnpm mutation-scan <t> --stub-check` (pre-Stryker
deletion survival) + `pnpm mutation-scan <t>` (full Stryker).

**Run it over the whole repo.** With `coverageAnalysis: "perTest"`, `--concurrency` and
`--incremental`, a full-repo scan is a one-time batch job, not a reason to cut scope.

**No tests is a finding, not a skip** — it emits a zero-coverage finding. A scoped run records
`partial` with its scope; a failed dry run surfaces as a distinct env-fragile-suite verdict rather
than a clean zero.

**The pitch:** *your coverage number is lying to you, and here is exactly where.*

---

## M9 — Server→client boundary & rendering

**Finds:** framework boundary footguns that cross the security/perf line and that generic tools
miss — server→client data leaks (a full DB row passed to a `'use client'` prop is serialized to the
browser), Server Actions with missing auth or input validation (they are public POST endpoints),
missing or over-broad cache config (cost, or cross-user cache bleed), unbounded and self-calling
routes, SSR-only-API and hydration misuse.

**Run:** `pnpm detect-static <t>`.

**No longer Next-only.** A framework-agnostic boundary model routes **Remix, React Router 7 and
TanStack Start** to adapters. Astro, SvelteKit and Nuxt stay **disclosed not-assessed** pending the
SFC parse layer — and a target the model doesn't cover gets a not-assessed row **naming the
framework**, never a silent run on a false Next.js premise.

---

## M10 — Data classification (PII / PHI / PCI) — *detect, don't ask*

**Finds:** which tables and columns hold personal data, by matching **column names and types**
against standard taxonomies — Google Cloud DLP infoTypes, Microsoft Presidio, GDPR special
categories, HIPAA PHI, PCI cardholder data.

**Names only, never values** → no real PII is handled. Privacy-safe, and runs on the read-only
connection we already have.

**Why it isn't a client questionnaire:** data sensitivity is derivable from the schema, so we detect
it. Reserve the questionnaire for facts genuinely outside the repo.

**Run:** `pnpm pii-classify` with `SUPABASE_DB_URL=…` (live) or `--schema <path>` over a migrations
dir, a `.sql` file, discovered DDL, or a `schema.prisma`.

### What it unlocks — this is the differentiator

**Data-aware severity.** A cross-tenant gap on a table holding `email + date_of_birth +
passport_number` auto-escalates to Critical; a table with only a display name stays Low. Generic
tools say *"data exposed"* — Harvey says **which data**. The escalation records
`dataClass {table, categories, infotypes, escalatedFrom, reason}` on the finding, so it is legible
rather than a silently higher number. It only ever raises, never lowers.

**Compliance applicability** falls out of the same map: detected PHI → HIPAA checks apply;
cardholder data → PCI.

**Protection verdict (connected tier):** gathers per-table RLS state, anon/authenticated SELECT
grants and pgsodium masking rules, and emits a per-column verdict. Every run carries `M10-PROT-00`
saying whether protection was verified **and what the check cannot see** (application-layer
encryption, RLS *policy quality*, non-`public` schemas). On the schema tier it states plainly that
protection was **not** assessed.

**Known false-positive class, disclosed rather than hidden:** `email_category` is not an email,
`awaiting_dob_reprompt` is a boolean, "health" matches `vendor_health`. Hits carry a **confidence**
label and ambiguous names default to low/review.

---

## How the modules compose into one engagement

1. **Threat-model** — focus areas
2. **M10 data classification** — the data map runs *first*, because it weights every exposure
   finding's severity — plus **M1** static security
3. **M3 + M4 + M5 + M6 + M7 + M8 + M9** in parallel (full-repo Stryker with perTest + concurrency)
4. **M2 local pen test** to *prove* the high-severity M1/M9 findings
5. **Assemble** into the ranked report, cross-referencing hotspots and surviving mutants against
   findings
6. **Remediation plan** + retest offer

### Running it — one orchestrator, three modes

`pnpm run-audit <target>` drives all ten modules and **derives** the coverage ledger from what each
probe actually reported. There is no parameter through which a caller can assert that a module ran.

| Mode | Command | Environment it assumes |
|---|---|---|
| **Free** | `run-audit <t>` | source only, mechanical |
| **Validation** | `run-audit <t> --llm --dynamic --artifacts-dir <dir>` | source + LLM passes + our own local stack, no client DB |
| **Paid** | add `--connected` | a live read-only client DB |

**The flags declare which environments the engagement HAS — not which modules to run.** Every mode
runs all ten; a tier not in scope records `requires-live-run` or `partial` *with a reason*.

**Also available:**

- **Re-audit diff** — `--baseline <prior findings.json>` classifies each finding
  resolved / persistent / new against a prior engagement, for repeat customers.
- **SARIF export** — `--sarif-out <file>` for GitHub code-scanning / ASPM ingestion. The per-module
  coverage ledger travels with it as `toolExecutionNotifications`, so **a module that did not run
  cannot vanish into "no results."**
- **SBOM export** — `--sbom-out <file>` emits CycloneDX 1.5.

---

## The principle that runs through all ten

**A module that cannot run is recorded as `partial` / `requires-live-run` WITH THE REASON — never
silently omitted. Fail loud.**

Silent omission is worse than a wrong status: a wrong status shows up in the tally, an absent row
does not. An unstated limitation reads as a clean bill of health.

This is why every module above has a "what it cannot see" clause, and why the disclosure-row family
(`M1-LANG-00`, `M1-EXT-00`, `M3-KNOWLEDGE-00`, `M10-PROT-00`, `INFRA-SCOPE-00`, `SUP-SCOPE-00`, …)
keeps growing. **Adding a new row is the normal response to finding something Harvey cannot
assess.** The defect is a silent gap, never a missing row id.

Two mechanisms enforce it beyond good intentions:

- **The conservation gate** — a planted finding per module, asserted both *produced by that module's
  own probe* and *present in the assembled deliverable*. Accounted-for is not delivered.
- **Typed probes** — a probe returns `Examined { findings, unitsExamined, scope }` or
  `NotAssessed { reason, provenance, falsifier }`. The silent-empty version **does not compile**.

---

## Packaging

| Offer | Modules | Position |
|---|---|---|
| **Security audit** | M1 + M2 + the M9 security items | the wedge — lower price, faster, gets the meeting |
| **Full codebase audit** | M1–M10 | the upsell — the reason the engagement is worth it |

Lead the pitch with the security depth; show the full report as the reason to buy the bigger
package. Do **not** market as generic code quality — that is the commoditized lane.

---

*Detector counts measured 2026-08-01 with `pnpm detector-census`. Re-run it rather than quoting
this file — the numbers move with every detector that lands, and a stored number becomes an
argument's premise long after it stops being true.*
