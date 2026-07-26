# Audit modules — the full deliverable

> **Positioning vs. deliverable.** Market on the **wedge** (multi-tenant security depth — what's
> underserved and gets the meeting). Deliver the **breadth** below (a complete codebase-health audit —
> what makes the engagement worth $X, sticky, and expands who'll buy). Do **not** market as "generic code
> quality" — that's the commoditized lane (SonarQube/Code Climate). Security leads; the rest is the value.

A full audit is ten modules (M1–M10). Each lists what it finds, the method, the tool/skill that powers it, whether it's
**net-new build** or **existing tooling to wire in**, and what it contributes to the report.

| # | Module | Powered by | Status |
|---|--------|-----------|--------|
| M1 | Multi-tenant security (lead) | `scan-extras.txt` + `/vuln-scan` + `/triage` | exists (Tier-1 briefs done) |
| M2 | Local penetration test (dynamic) | local stack + probe scripts; later the Tier-2 pipeline | **net-new** (#1503 dynamic half) |
| M3 | Hotspot analysis | **`vitals` plugin** (`/vitals:scan`) | exists — run, don't build |
| M4 | Duplication | jscpd | exists (`pnpm check:duplication`) |
| M5 | Slop / dead code | `pnpm quality-scan` (knip dead code) + `pnpm detect-static` (slop AST detectors, `src/detectors/slop.ts`) | exists — both engines wired |
| M6 | Simplification / reuse / maintainability | `pnpm simplify-scan` (brief + source → review packet) + two-reviewer verdict protocol (#813, `src/cli/m6-agreement.ts`) | runner exists (#266); first real-target verdict recorded 2026-07-18 (#283) |
| M7 | Performance tuning | Supabase perf advisors + profiling + bundle/Web-Vitals tools | **net-new** to assemble |
| M8 | Test quality & intent | StrykerJS mutation testing + tests-for-intent review | **net-new** |
| M9 | Next.js App Router boundary & rendering | `scan-extras.txt` (M9 section) + static review | **net-new** |
| M10 | Data classification (PII / PHI / PCI) | schema → PII dictionary (`tools/pii-classify.mjs`) | **prototype built** |

> **Stack coverage.** Every module above is written against the primary target shape (Supabase
> Postgres + RLS). As of 2026-07-23 (epic #756), a Prisma/Postgres target — no Supabase, no
> database-level RLS — is a first-class supported shape too, detection-gated so the two never
> collide: `detectOrm` (`src/scan/framework-detect.ts`, #757) reads the target's own signals
> (`@prisma/client`/`prisma` dep or a `schema.prisma` file vs. `@supabase/supabase-js` or a
> `supabase/` project dir), with Supabase winning when both appear so a real RLS surface is never
> suppressed. The framing that matters: **a Prisma app has no database-level tenant
> enforcement at all** — there is no RLS to audit — so every bit of tenant isolation lives in
> application code, which is exactly where M1's ORM-agnostic detectors (and the new Prisma-idiom
> one) already operate. Each affected module section below (M1, M2, M7, M10) calls out its
> Prisma-specific behavior. Proven live end-to-end against a real target,
> [boxyhq/saas-starter-kit](https://github.com/boxyhq/saas-starter-kit).

---

## M1 — Multi-tenant security (the differentiator)
- **Finds:** cross-tenant data exposure (permissive/missing RLS), service-role bypass, single-layer isolation,
  per-route auth gaps, webhook replay, fail-open enforcement, unchecked mutations, RMW counter races,
  idempotency ordering, in-memory rate limits, SSRF-via-URL, state-machine boundary, error disclosure.
- **Method:** static review (the brief) + outcome-based confirmation for the Critical class.
- **Powered by:** `scan-extras.txt` + `fp-rules.txt` via `/vuln-scan --extra` / `/triage --fp-rules`.
- **Report:** §3 Findings, ranked by blast radius. This is the headline.
- **Prisma/Postgres apps (#757/#760, landed 2026-07-23):** `detectOrm` routes a detected Prisma
  target to the app-layer tier — the Supabase-specific migration/RLS/PostgREST/edge-config
  detectors (`supabase-static.ts`, `supabase-config.ts`, `supabase-splinter.ts`,
  `supabase-advisors.ts`) record their tier **N/A-by-architecture** rather than silently
  reporting nothing. What fills that gap: the ORM-agnostic detectors that already ran on
  pg/Express apps (`pg-idor.ts`, `bola-owner.ts`, …), plus a Prisma-idiom detector added for
  this (`src/scan/prisma-tenant-scope.ts`, #760) that flags the Prisma equivalent of the same
  BOLA class — `prisma.<model>.update/delete/findFirst/…` filtered by `id` alone, with no
  tenant/owner column (`organizationId`/`tenantId`/`teamId`/`userId`/a named relation) anywhere
  in the `where` clause. Review tier (the AST proves the where-clause has no visible tenant
  scope, not that no ownership check exists in a wrapper it can't see). Measured **zero
  RLS-detector false positives** against boxyhq, a real Prisma app.

## M2 — Local penetration test (dynamic)
- **Finds:** what static review can't *prove* — actually reachable cross-tenant access, IDOR on API routes,
  missing-auth endpoints, auth/role escalation, rate-limit bypass across instances, injection that lands.
- **Method:** stand up the target locally (or a throwaway staging) with a **seeded two-tenant dataset**;
  run probes as (a) anon key, (b) tenant-A user, (c) tenant-B user — assert nobody crosses tenants; hit
  every API route with missing/forged auth; attempt the limiter bypass. Turns a static "looks exploitable"
  into a demonstrated "here's the row from the other tenant."
- **Status:** **net-new.** A guided/semi-automated dynamic pass now; later automated by the Tier-2
  outcome-based detector (#1503). Tracked separately (see issues).
- **Report:** dynamic confirmations attached to M1 findings (a proven finding is worth 10× a theoretical one),
  plus any dynamic-only findings.
- **Prisma/Postgres apps (#759, #787, landed 2026-07-23):** a Prisma app has no PostgREST and no
  DB-level RLS, so the Supabase cross-tenant PostgREST/RLS matrix **does not apply** — tenant
  isolation is entirely app-layer and testable only through the app's own HTTP routes.
  `src/prisma-dynamic.ts` + `src/pentest/prisma-standup.ts` stand up a **plain Postgres**
  (no Supabase stack), apply the schema (`prisma migrate deploy` when versioned migrations are
  committed, else `prisma db push`), seed two tenants, boot the app, and drive the existing
  app-route probe tier — with the PostgREST/RLS matrix recorded explicitly
  **not-applicable**, never a silent skip. Proven live against
  [boxyhq/saas-starter-kit](https://github.com/boxyhq/saas-starter-kit): the schema applied, the
  app booted, and the unauthenticated probe tier reached a real Critical (a missing-auth
  endpoint). #787 closed the *authenticated* half: it seeds a two-tenant **Team/organization
  membership join** (`Team`/`TeamMember(teamId, userId, role)`, detected directly from the
  schema), mints per-tenant sessions, and drives an authenticated cross-tenant BOLA/IDOR probe —
  tenant A's session against tenant B's team-scoped route. #791 gates the missing-auth sweep on
  the response **actually exposing data** (not just an unexpected 200), closing a false positive
  the boxyhq run surfaced on a no-op demo endpoint. **Open:** a dedicated offline
  fixture-level regression control for the cross-tenant probe itself (#796) — today it's
  unit-tested directly, not yet driven end-to-end against an in-repo Prisma fixture the way the
  Supabase seam probes are.

## M3 — Hotspot analysis
- **Finds:** the files that are **both** frequently changed **and** complex — where bugs and maintenance cost
  concentrate. Tells the client *where to spend remediation budget*.
- **Method:** the **`vitals` plugin** (`/vitals:scan` / `vitals_cli.py report --json <path>`) — already installed.
  It does churn × complexity ranked by **ROI** (core > test, central > leaf), plus **co-change coupling**,
  **knowledge risk** (truck-factor 1 / sole-author files), **AI-provenance** tracking, and health trends across
  scans. Strictly better than a hand-rolled churn×complexity script. Cross-reference its hotspots against M1/M7/M9
  findings (a hotspot that's also a security/perf finding is the top remediation priority).
- **Status:** **exists — run, don't build.** Scope to a subdir on a monorepo (`report --json apps/main/src`).
- **Report:** the vitals hotspot table (health · churn · complexity · centrality) + coupling + knowledge-risk,
  with the "fix these first" callout driven by ROI and overlap with findings.
- **Validated on ATC:** overall health 6.3/10; #1 hotspot `app/api/chat/route.ts` (health 2.4, 41 changes, cx 68,
  co-changes with 29 files); 50 truck-factor-1 files; 2,857 AI-provenance events tracked.

## M4 — Duplication
- **Finds:** copy-paste clones — a bug-multiplier and maintenance tax (fix once, miss the other three copies).
- **Method:** jscpd across the source tree; report % duplication and the worst clusters. Plus a scoped
  diverged-clone near-miss pass (#360) over security-relevant files only: function-level Type-3 comparison that
  catches copy-pasted auth/tenant checks that were then EDITED — exactly the "patched one copy, missed the other"
  population jscpd's exact-token match structurally cannot see. Review tier, never a mechanical verdict.
- **Powered by:** existing `pnpm check:duplication` (jscpd) — point it at the client repo.
- **Report:** duplication summary + top clone clusters with consolidation suggestions.

## M5 — Slop / dead code
- **Finds:** AI-generated cruft and dead weight — narrating comments, single-use helpers, try/catch that just
  re-throws, orphan TODOs, unused exports, unreachable branches, stub-shaped code (params that don't affect output).
- **Method:** two engines, and running only one is half the module (#811). (1) **Dead code:**
  knip over the target — unused exports, unused files, unused dependencies — via
  `pnpm quality-scan <target>`; if the target's deps aren't installed and knip can't load its
  config, the run retries with all knip plugins disabled and reports review-tier dead code,
  disclosed as an M5-98 row (#810) — install the target's deps for confirmed (non-review)
  file findings. (2) **Slop:** the mechanical AST detector suite `src/detectors/slop.ts` (the D-091
  classes ported from ATC's slop-check diff scanner, generalized to a whole-repo pass, then
  fanned out — narrating comments, orphan TODOs, try/catch-rethrow, single-call wrappers,
  single-use helpers, placeholder stubs, elision/AI-phrasing comments, redundant booleans,
  else-after-return, redundant JSDoc, unused params/imports, unreachable branches) via
  `pnpm detect-static <target>`; source-only, no install needed.
- **Powered by:** `pnpm quality-scan` (knip) + `pnpm detect-static` (`src/detectors/slop.ts`,
  every class gated by a positive+negative fixture pair in `slop.test.ts`).
- **Report:** a cleanup list (delete/inline/simplify), grouped, with rough line-count reduction.

## M6 — Simplification / reuse / maintainability ("don't reinvent the wheel")
- **Finds:** the supportability tax — hand-rolled implementations of things a stdlib/framework primitive or a
  well-known library already does; over-abstraction (abstractions for single use); inconsistent patterns that
  raise the bus-factor; complexity a senior engineer would call overcomplicated.
- **Method:** `pnpm simplify-scan <target>` assembles the `quality-extras.txt` M6 brief (its SIMPLIFICATION +
  FALSE POSITIVES sections) plus the target's source into a review packet; a reviewer reads the packet and
  writes up what to replace, applying the pre-pr-reviewer "surgical-changes / reuse / would-a-senior-call-this-
  overcomplicated" doctrine. The runner assembles and does not judge — M6's verdict is a reviewer's opinion, so
  the writeup goes through human triage before it reaches a client (`docs/design/m6-simplification-eval.md` §5).
- **Powered by:** `pnpm simplify-scan` + `quality-extras.txt`.
- **Verdict protocol — two independent reviewers (#813, 2026-07-23):** the paid M6 verdict is never asserted
  from a single reviewer pass — measured reviewer variance (two fresh contexts split on the same file under
  the same rubric, `docs/design/m6-simplification-eval.md` §3.4) made single passes datapoints, not verdicts.
  Two reviewers each review the *identical* packet in fresh, independent contexts (same-model
  self-consistency is fine; independence of context is the load-bearing property) and end their writeups
  with the packet's machine-readable verdict block, one `flag`/`spare` row per packet file.
  `pnpm exec tsx src/cli/m6-agreement.ts <a.json> <b.json>` computes agreement mechanically — never
  eyeballed. Unanimous flags go to the human triage below; unanimous spares are spared; a **split goes to a
  human adjudicator with both reviewers' arguments and never straight into a report**; a file reviewed by
  only one pass is surfaced loudly as uncompared, never defaulted to spare. The labeled corpus
  (`targets/calibration/simplify/`, twelve files) and the recorded agreement baseline live in
  `docs/design/m6-simplification-eval.md` §3.5/§4 and `docs/design/m6-eval-runs/`.
- **Status (2026-07-15, #266):** M6 has produced **no output in any engagement** since it was defined
  (2026-07-09, #72) — it had no runner until now, and the coverage guard recorded its absence as a routine `na`
  every time. `src/audit-coverage.ts` (`MODULES_NEVER_EXECUTED`) now fails loud on this until M6 runs
  against a real target. `MODULES_NEVER_EXECUTED` is itself **derived**, not hand-kept (#284): it's the
  complement of `audit-execution-log.json`, the record the full-audit runner
  (`pnpm run-audit <target>`, #229/#310) writes from what actually executed. **Superseded 2026-07-18
  (#283):** M6 has now run against a real target (stoimera/Cravab) with a reviewed verdict recorded via the
  M6 pass artifact + `run-audit --record`, clearing the never-run alarm — see
  `docs/design/m6-first-real-target-verdict.md`.
- **Report:** maintainability recommendations — each "reinvented wheel" with the suggested
  library/primitive to replace it, and the over-abstractions to collapse. This is the "lower your ongoing
  maintenance + onboarding cost" pitch, which lands even with clients who don't think they have a security problem.
- **Tier (operator ruling 2026-07-15, #267):** free lists mechanically-recognisable hand-rolled shapes as
  **non-grading indicators** — "this looks hand-rolled; may be worth investigating," never naming a replacement.
  **Paid triages each and names the replacement** (the report line above). The hedged free wording is
  load-bearing: naming the replacement IS the asserted judgment. Same free/paid form as the M1 source-tier
  RLS/authz indicators. The free tier does not ship until the #267 detectors exist.

## M7 — Performance tuning
- **Finds:** the slow paths and the cost they impose — N+1 / unindexed foreign-key queries, missing or unused
  indexes, RLS policies re-evaluated per row (bare `auth.*` not wrapped in a subquery), over-fetching / missing
  pagination, missing caching, oversized client bundles, poor Core Web Vitals, inefficient hot-loop algorithms.
- **Method:** static (query-pattern review, missing-index detection, bundle analysis) + dynamic (slow-query
  logs, profiling, Lighthouse/Web-Vitals on the running app). For Supabase specifically, the **performance
  advisor** (`get_advisors` performance) surfaces unindexed FKs, unused indexes, and `auth_rls_initplan`
  directly — then verify fixes against a test DB before recommending.
- **Status:** **net-new** to assemble (advisor pull + bundle/Web-Vitals tooling + a profiling pass). Tooling
  mostly exists; the build is the harness around it.
- **Report:** §3b Performance table (finding · layer · impact · fix · effort), ranked by user-facing impact.
- **Proof point:** this very dimension is demonstrated in the source repo — unindexed FKs → covering indexes,
  and `auth.uid()` → `(select auth.uid())` RLS initplan fixes, both advisor-surfaced and test-DB-verified.
- **Prisma equivalent (#761, landed 2026-07-23; deferrable):** a Prisma target has no Supabase
  performance advisor to call, so `src/scan/prisma-schema-perf.ts` statically reviews
  `schema.prisma` for scalar foreign-key columns with no covering index (no `@id`/`@unique` on
  the field, no `@@id`/`@@unique`/`@@index` naming it) — the schema-derived equivalent of
  Supabase's `unindexed_foreign_keys` advisor lint. Postgres does not implicitly index a
  relation's FK column the way Prisma's MySQL connector does, so an uncovered FK forces a
  sequential scan on every JOIN through that relation and every cascade UPDATE/DELETE on the
  parent. Needs no live DB or connected tier — it runs on every Prisma engagement from source
  alone. Deliberately schema-only: cross-referencing app code for N+1 loop patterns and
  unindexed filter columns (a field read in a `where` elsewhere in the codebase) is split into
  #793 (open, deferred for precision — it needs cross-referencing app source against the schema,
  a materially noisier heuristic than parsing the schema alone).

## M8 — Test quality & intent
- **Finds:** tests that **can't fail when the logic changes** — the false-confidence layer. Tautological/snapshot-only
  tests, tests that assert WHAT not WHY, high *line coverage* masking low *mutation* coverage, and the specific code
  paths with no effective test (surviving mutants). Directly operationalizes the house rule "a test that can't fail
  when business logic changes is wrong."
- **Method:** two facets. (1) **Mutation scan** — run **StrykerJS** (or the stack's mutation tester): it injects
  faults (flip `>` to `>=`, negate conditionals, swap return values, delete statements) and reports the **mutation
  score** = % of mutants the suite kills. Surviving mutants are the blind spots, located precisely. (2)
  **Tests-for-intent review** — read the high-value tests (auth, tenant isolation, payments, state machines) and flag
  the ones that would still pass if the behavior they "cover" were broken.
- **Status:** **net-new.** Stryker needs a working test runner. **Run it over the WHOLE repo** — with
  `coverageAnalysis: "perTest"` (only runs the tests that cover each mutant), `--concurrency` (parallel workers),
  and `--incremental` (fast re-runs), a full-repo scan is a one-time batch job, not a reason to cut scope. Whole-repo
  is also the better deliverable: a complete surviving-mutant map cross-referenced against every finding/hotspot.
  Pair the score with the qualitative read for the report.
- **Report:** mutation score overall + per module (whole repo); a "tests covering X can't actually fail" list (the
  dangerous ones — e.g. a tenant-isolation test that passes even with RLS removed); and which surviving mutants sit
  on a security/perf hotspot (cross-reference M1/M3). The pitch: *your coverage number is lying to you, here's where.*

---

## M9 — Next.js App Router boundary & rendering
- **Finds:** App-Router-specific footguns that cross the security/perf line and that generic tools miss —
  server→client data leaks (a full DB row passed to a `'use client'` prop is serialized to the browser),
  Server Actions with missing auth or missing input validation (they're public POST endpoints), missing/over-
  broad cache config (Vercel+DB cost, or cross-user cache bleed), unbounded/self-calling routes & edge fns,
  and SSR-only-API/hydration misuse. The current guard suite is thin here — this is the App-Router blind spot.
- **Method:** static review with the `scan-extras.txt` **M9 section** as the brief; the security items (leak,
  Server Action auth/validation) report into §3 Findings, the cost items (caching, unbounded routes) into §3b
  Performance.
- **Status:** **net-new.** This is the gap analysis turned into a module (none of the existing `check:*` guards
  cover the App-Router-specific surface; the DB/RLS/index side is well covered).
- **Report:** App-Router findings folded into §3 (security) and §3b (performance) by severity, tagged `M9`.

## M10 — Data classification (PII / PHI / PCI) — *detect, don't ask*
- **Finds:** which tables/columns hold personal data, by **matching column names + types against standard
  taxonomies** — Google Cloud DLP infoTypes, Microsoft Presidio, GDPR special categories, HIPAA PHI, PCI
  cardholder data. **Names only, never values** → no real PII handled, privacy-safe, runs on the read-only
  connection we already have.
- **Why it's not a question:** data sensitivity is derivable from the schema, so we don't ask the client — we
  detect it. This is the "detect > ask" principle: reserve the questionnaire for facts genuinely outside the repo.
- **What it unlocks (the differentiator):** **data-aware severity** — a cross-tenant gap on a table holding
  `email + date_of_birth + passport_number` auto-escalates to Critical, while a table with only a display name
  stays Low. Generic tools say "data exposed"; we say *which* data. Also drives **compliance applicability**
  (detected PHI → HIPAA checks apply; cardholder data → PCI).
- **Status:** **prototype built** (`tools/pii-classify.mjs`, name-based dictionary + self-test). Validated on ATC:
  **94 PII-bearing columns across 40 tables** (email, DOB, passport, contacts). It also surfaced its own FP class
  (`email_category` ≠ email; `awaiting_dob_reprompt` is a boolean; "health" matched `vendor_health` infra) — so
  hits carry a **confidence** label and ambiguous names ("name") default to low/review. The opt-in LLM semantic
  pass (catches obfuscated fields) landed in #855; the severity-weighting wiring landed in #1049.
- **Report:** a data map (table → categories) in context; feeds the severity of every exposure finding.
- **Data-aware severity, landed #1049:** `pnpm pii-classify --data-map-out <path>` writes the table→data-class
  map; the orchestrator's M10 probe hands it to the assembler, which raises any finding whose location or title
  names a classified table to that table's data severity (never lowers it) and records `dataClass`
  {table, categories, infotypes, escalatedFrom, reason} on the finding so the escalation is legible rather than
  a silently higher number. No map captured ⇒ an `M10-ESCALATION-00` not-assessed row, never silence.
- **Protection verdict (connected tier), landed #1043:** the live tier gathers per-table RLS state,
  anon/authenticated SELECT grants and pgsodium masking rules, and emits a per-column protection verdict
  (`M10-PII-nn`). Every run carries `M10-PROT-00` saying whether protection was verified and what the check
  cannot see (application-layer encryption, RLS *policy* quality, non-`public` schemas, review-flagged columns);
  on the schema tier it states plainly that protection was NOT assessed.
- **Prisma support (#758, landed 2026-07-23):** a target whose schema lives in `schema.prisma`
  (not `supabase/migrations/*.sql`) now classifies too —
  `pnpm pii-classify --schema <schema.prisma path>` (repo root or `prisma/schema.prisma`, both
  conventional locations). It first tries the target's own locally-installed Prisma CLI
  (`prisma migrate diff --from-empty --to-schema-datamodel schema.prisma --script`) to emit the
  equivalent SQL and reuses the existing migration-SQL column parser unchanged; when no local
  Prisma CLI is resolvable it falls back to a lightweight `schema.prisma` model/field parser
  (`src/prisma-schema-parse.ts`) that reads `model` blocks directly — respecting `@map`/`@@map`
  column/table renames, skipping relation fields (backed by a scalar FK elsewhere, not a column
  of their own) and enum-typed fields it has no visibility into — into the same
  `{table_name, column_name, data_type}` shape the SQL path produces, so the identical downstream
  classifier (`buildDataMap`) runs regardless of which path produced the columns.

## How the modules compose into one engagement
1. Threat-model (focus areas) → 2. M10 data classification (the data map — it weights every exposure finding's
severity, so it runs before the security pass) + M1 static security scan → 3. M3 hotspots + M4 dup + M5 slop + M6 maintainability
+ M7 performance + M8 test quality + M9 App Router (can run in parallel; full-repo Stryker, perTest + concurrency)
→ 4. M2 local pen test to **prove** the high-severity M1/M9 findings → 5. assemble into the ranked report
(`audit-report-skeleton.md`), cross-referencing hotspots and surviving mutants against findings → 6. remediation plan + retest offer.

**Running it:** one orchestrator, `pnpm run-audit <target>` (#229/#310), drives all ten
modules per the run-mode/env-flag table in `CLAUDE.md` and derives the coverage ledger from what each probe
actually reported, rather than trusting a caller-supplied record. `src/audit-coverage.ts` (`pnpm audit-coverage`)
remains for engagements whose modules run outside the orchestrator.

**Packaging:** offer a **Security audit** (M1+M2+the M9 security items, the wedge, lower price/faster) and a
**Full codebase audit** (M1–M10, higher price, the upsell). Lead the pitch with the security depth; show the full report as the reason to buy the bigger package.
