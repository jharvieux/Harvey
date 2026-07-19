# ATC engagement — full ten-module audit (2026-07-18)

**Target:** local ATC monorepo at `/Users/johnharvieux/ClaudeCodeProjects/atc` (operator's own app, fully
authorized; not yet live). Findings repo: `jharvieux/ATC`.
**Engagement type:** validated retry of the earlier ATC dry run (Harvey #511), run against the fixed
pipeline per `docs/runbooks/full-engagement-run.md`. Environment had Docker + Supabase CLI + psql + node
and the read-only `supabase-main` / `supabase-rag` MCP servers.
**Operator/scanner tools present:** semgrep, trufflehog, gitleaks, osv-scanner, docker, supabase, psql, vitals plugin.

This is a COMPLETE audit: all ten modules were accounted for against every app and every Supabase backend.
Modules that could not fully run are recorded `partial` / `requires-live-run` **with the reason** — never a
silent skip (CLAUDE.md coverage doctrine).

> **Addendum — 2026-07-19 (M2 re-run after Harvey #622).** With the #622 seed fix landed, M2 was re-run live
> against `apps/main` on an isolated stack (project `harvey-dv-7264109781`, non-default ports api=55181/db=55182;
> stood up + all 185 apps/main migrations applied cleanly + torn down clean — 0 Harvey containers/volumes left,
> no foreign volumes touched, #604 verified). **#622 is confirmed fixed against ATC's real schema:** the seed no
> longer fails on `tenants_onboarding_stage_check` — `onboarding_stage` now seeds a legal value derived from the
> ALTER-added `IS NULL OR IN (...)` constraint. However the two-tenant seed still could not fully apply: the first
> `tenants` INSERT now aborts on `tenants_tier_id_fkey` — the seed fills the nullable generic FK `tenants.tier_id`
> (→ `tier_definitions`) with a dangling `gen_random_uuid()` instead of NULL/a seeded parent (**Harvey #630**, a
> distinct seed gap). So the live cross-tenant PostgREST matrix **still did not run, and ATC's runtime tenant-isolation
> proof remains pending** — now blocked by #630, not #622. This re-run was scoped to `apps/main` only; per-project
> stand-up (apps/rag) stays open as #610. No genuine ATC M2 finding resulted (the blocker is a Harvey harness gap,
> not an ATC vulnerability).

> **Addendum 2 — 2026-07-19 (M2 seed switched to LIVE-SCHEMA INTROSPECTION, Harvey #646).** The M2
> `--execute` seed is now built by **introspecting the live post-migration database** (`information_schema`
> / `pg_catalog` — columns, types, nullability, defaults, PK/UNIQUE, the FK graph, and CHECK/enum/domain
> definitions) instead of parsing migration text. This kills the entire unrecognized-type + schema-evolution
> class at the source: the daterange blocker (`tenant_usage_metrics.billing_period`, #646) that stopped the
> #622 re-run is **GONE** — a NOT NULL `daterange` now seeds a valid range literal from the real applied type.
> M2 was re-run live against `apps/main` on an isolated stack (project `harvey-dv-25105cd717`, non-default
> ports api=58161/db=58162; **185 migrations applied cleanly + torn down clean** — 0 Harvey containers/volumes
> left, no foreign volumes touched, #604 verified). The introspection seed advanced **far past** every prior
> blocker: the first `tenants` row (nullable FK `tier_id`, #630) ✓, and the `bookings`/`commissions` multi-column
> *belt-and-suspenders* consistency CHECKs ✓ (a new null-branch heuristic: null the nullable referenced columns,
> pin the NOT NULL discriminator to its first allowed value) — reaching `tasks` at `seed.sql:85`, deep in the
> 92-table scoped set. **New, distinct blocker there:** `tasks`' table-level CHECK
> `(contact_id IS NOT NULL)::int + (quote_id …)::int + (booking_id …)::int + (conversation_id …)::int = 1`,
> an **exactly-one-of / polymorphic-parent** invariant requiring exactly ONE of four nullable FKs to be non-null
> — the opposite of the null-branch shape, so the generic heuristic can't satisfy it. This is a **bespoke
> multi-column CHECK-invariant class (Harvey #649)**, NOT a type/schema-evolution issue. So the live cross-tenant
> PostgREST matrix **still did not run, and ATC's runtime tenant-isolation proof remains PENDING** — now blocked
> by #649 (bespoke cross-column CHECKs), not by #646 (types, closed) or #630/#622. Recommended next step (in
> #649): apply the seed per-table under SAVEPOINTs so a table with an unsatisfiable bespoke CHECK is
> skipped+disclosed while the rest seed, letting the matrix run on the bulk of the surface for a *partial* runtime
> proof. No genuine ATC M2 finding resulted (the blocker is a Harvey harness gap, not an ATC vuln).

---

## 1. Target enumeration

**Apps (workspaces):**
| app | kind | notes |
|-----|------|-------|
| `apps/main` | Next.js App Router (`@atc/main`) | 269 API `route.ts`, Inngest jobs, Stripe, chat/AI. Backend: **main** |
| `apps/rag` | Next.js App Router (`@atc/rag`) | 24 API `route.ts`, pgvector RAG. Backend: **rag** |
| `apps/extension` | browser extension (plain JS) | `manifest.json` + background/popup/submit JS. **Not a pnpm workspace** → Harvey's per-app tiers (M4/M5/M9/M10-schema) do NOT enumerate it; covered by the M1 semantic pass only |
| `packages/config`, `packages/contracts`, `packages/eslint-plugin-atc`, `packages/shared-types` | internal libs | enumerated by run-audit; no own DB schema |

`'use server'` server actions: **0 confirmed** (the entire Server-Action vuln class is N/A for ATC — the scan-extras brief's assumption verified correct).

**Supabase backends (two distinct projects):**
| backend | project ref | url | tables | migrations |
|---------|-------------|-----|--------|------------|
| main (production) | `mfaknjyqiwcjojukcnea` | https://mfaknjyqiwcjojukcnea.supabase.co | ~140 (all RLS-enabled) | 185 (`apps/main/supabase/migrations`) |
| rag | `jjznkprbotkqqnuvcost` | https://jjznkprbotkqqnuvcost.supabase.co | 11 (all RLS-enabled) | 35 (`apps/rag/supabase/migrations`) |

Connected tier was **read-only** throughout: `list_tables` / `list_migrations` / `get_advisors` on both MCP
servers, plus read-only `execute_sql` sampling on the rag project only. **No write** was issued to any live
database. `supabase-main` MCP intentionally exposes no `execute_sql` (engagement scope).

---

## 2. Derived coverage ledger (module × app/DB)

Legend: **ran** = all in-scope classes executed · **partial** = some classes ran, reason given ·
**requires-live-run** = a prereq environment was absent, reason given.

| Module | Instance | Tier | Status | Reason (if not full) |
|--------|----------|------|--------|----------------------|
| **M1** Multi-tenant security | apps/main | mechanical (quick-scan) | ran | secret/config mechanical tier ran |
| M1 | apps/main+rag+extension | semantic (LLM /vuln-scan→/triage) | ran | 3 focused review passes over RLS/DDL, routes, rag/inngest/seam/extension (guided by scan-extras, triaged by fp-rules) — banked M1 evidence below |
| M1 | git-history secrets (TruffleHog) | mechanical | ran (clean) | **orchestrator falsely skipped it (Harvey #619)**; run manually: 26,311 chunks / 49MB, **0 verified, 0 unverified secrets** |
| M1 | main DB | connected (live RLS/advisors) | ran | read-only `get_advisors(security)` + DDL review |
| M1 | rag DB | connected (live RLS/advisors) | ran | read-only `get_advisors(security)` + DDL review |
| **M2** Local pen-test (dynamic) | apps/main / main DB | dynamic | **partial** | isolated stack stood up + migrations applied + torn down cleanly (#604), but the two-tenant **seed failed** on ATC's `tenants_onboarding_stage_check` constraint → cross-tenant/IDOR/BFLA probes did not run; 0 findings, no artifact, exit 1 (Harvey #622) |
| M2 | apps/rag / rag DB | dynamic | requires-live-run | second backend not stood up — the runner applies only `migrationDirs[0]` (Harvey #610); would need a per-DB stand-up |
| **M3** Hotspot analysis | monorepo | vitals | ran | orchestrator failed (abs-path CWD bug, Harvey #624); re-run via `--report` capture → 56 findings (50 truck-factor-1, 5 co-change, 1 AI-authored high-churn); top-10 hotspots feed M1/M6/M8 |
| **M4** Duplication | apps/main | jscpd | **partial** | jscpd did not complete on the workspace (M4-99 disclosure, Harvey #505) |
| M4 | apps/rag + 4 packages | jscpd | ran | |
| **M5** Slop / dead code | apps/main, apps/rag, config, contracts, eslint-plugin-atc | knip | ran | target `node_modules` present |
| M5 | packages/shared-types | knip | requires-live-run | that package has no local `node_modules` — knip can't resolve config imports |
| **M6** Simplification | monorepo (hotspot set) | free indicators | ran | non-grading "hand-rolled" indicators emitted |
| M6 | hotspot set | paid verdict | ran | reviewed 9 hotspot files vs quality-extras — verdict recorded + banked (packet tool bug worked around, Harvey #621) |
| **M7** Performance | monorepo | static code tier | ran | detect-static |
| M7 | main DB | connected advisors | ran | 214 unused_index + 5 unindexed FK (email_retry_content), all INFO; no initplan/permissive/duplicate |
| M7 | rag DB | connected advisors | ran | 1 RLS initplan (WARN, rag_media_assets), 4 unindexed FK, many unused_index |
| M7 | apps/main, apps/rag | Lighthouse (CWV) | requires-live-run | needs a local `next build`+`next start` against ATC's production `.env.local` (live secrets) — not built, to avoid a multi-minute build touching live services |
| **M8** Test quality | apps/main | stub-check + Stryker | **partial** | ATC's tests live in a **root-level vitest workspace**; per-app `apps/main/package.json` has no `scripts.test` → stub-check reports "no test suite"; orchestrator root Stryker dry-run fails env. ATC IS well-tested — Harvey's M8 could not run it (Harvey #623). Not a "no tests" finding against ATC |
| M8 | apps/rag | stub-check + Stryker | requires-live-run | same root-workspace shape; not separately run |
| **M9** App Router boundary | apps/main, apps/rag | AST | ran | Next apps fully analyzed |
| M9 | packages/config, contracts, eslint-plugin-atc, shared-types | AST | ran | non-App-Router → N/A rows recorded |
| M9 | apps/extension | AST | requires-live-run | not a workspace + not App Router → N/A (covered by M1 semantic) |
| **M10** Data classification | apps/main (schema) | schema | ran | 50 schema findings + 12 JSONB nested-PII containers flagged |
| M10 | apps/rag (schema) | schema | ran | 2 findings (minimal PII surface) |
| M10 | main DB | live (row sampling) | requires-live-run | `supabase-main` MCP exposes no `execute_sql` by engagement scope — row-level PII not sampled; schema tier + `list_tables` columns used instead |
| M10 | rag DB | live (row sampling) | ran (partial data) | read-only `execute_sql` sampled column inventory of non-empty tables (tenant_registry_shadow=9 rows, rag_media_assets=12); confirmed low PII surface |
| M10 | packages/* | schema | requires-live-run | no schema in those packages (nothing to classify) |

**Every one of the ten modules was accounted for against every app and both backends.** The only fully-blocked
tier is M2's dynamic pen-test (seed constraint failure + single-backend stand-up) and M7 Lighthouse (deliberate
env-safety decision) — both recorded with reasons, neither silently skipped.

---

## 3. Findings filed against `jharvieux/ATC`

13 real, triaged findings filed (label `harvey-audit`). The app-code and DB-isolation layers are **exceptionally
hardened** — visible D-091 remediation, a fail-closed `tenantClient` proxy, correct Stripe/webhook replay defense,
RS256 service JWTs. No cross-tenant data-exposure path was found in the reviewed surface. Findings are the residue.

| # | Sev | Module | Issue | Title |
|---|-----|--------|-------|-------|
| 1 | Medium | M1 | [#2012](https://github.com/jharvieux/ATC/issues/2012) | Unvalidated `hero_image_url` stored & rendered to group invitees |
| 2 | Medium | M1 | [#2000](https://github.com/jharvieux/ATC/issues/2000) | Browser extension `host_permissions: https://*/*` + cookies exposes session tokens on every site |
| 3 | Medium | M1 | [#2001](https://github.com/jharvieux/ATC/issues/2001) | RAG approve-with-edits bypasses the zero-tolerance PII gate (approve/tenant + approve/global) |
| 4 | Medium | M1 | [#2002](https://github.com/jharvieux/ATC/issues/2002) | `MAIN_APP_ADMIN_API_KEY` static non-rotating seam bearer, absent from the env schema |
| 5 | Low | M1 | [#2003](https://github.com/jharvieux/ATC/issues/2003) | import-pipeline service-role read of `gmail_inbound_messages` lacks a tenant predicate |
| 6 | Low | M1 | [#2004](https://github.com/jharvieux/ATC/issues/2004) | `RAG_WEBHOOK_SECRET` has no rotation pair (hardening) |
| 7 | Low | M1 | [#2005](https://github.com/jharvieux/ATC/issues/2005) | `rag_retrieval_log_daily` RLS policy is `USING(TRUE)` — isolation rests on the grant layer only |
| 8 | Low | M1 | [#2006](https://github.com/jharvieux/ATC/issues/2006) | `tenant_is_active()` SECURITY DEFINER RPC is a parameter-only tenant-status oracle (documented/accepted) |
| 9 | Medium | M1-live | [#2007](https://github.com/jharvieux/ATC/issues/2007) | Supabase Auth leaked-password protection disabled (main production DB) |
| 10 | Low | M7 | [#2008](https://github.com/jharvieux/ATC/issues/2008) | RAG Supabase DB advisor hardening: RLS init-plan + extensions-in-public + unindexed FKs |
| 11 | Medium | M6 | [#2009](https://github.com/jharvieux/ATC/issues/2009) | `precruise-generate-and-send` hand-rolls LLM JSON parsing → use provider structured output |
| 12 | Low | M6 | [#2010](https://github.com/jharvieux/ATC/issues/2010) | Standardize route-body validation on zod; hand-rolled cookie parse → `next/headers` |
| 13 | Info | M10 | [#2011](https://github.com/jharvieux/ATC/issues/2011) | PII data-map: 12 JSONB container columns need nested-PII review (main DB) |

### Notable false positives triaged OUT (high-signal deliverable)
- **Stripe webhook replay** — `constructEvent` (5-min tolerance) + atomic idempotency insert + DB-level CAS staleness guard. Belt and braces.
- **GitHub / Gmail-PubSub / Resend-inbound webhooks** — all verify authenticity (HMAC / Google-JWT / Svix) and dedup; fail-closed.
- **admin GET service endpoints** (`/api/admin/tenants`, `/platform-settings`) — constant-time bearer compare, documented.
- **Mass-assignment candidates** — each spread is a strict Zod whitelist with no privilege fields.
- **`invitations` BFLA action-switch** — all actions require the same coordinator authority.
- **RLS-enabled-no-policy tables** (main ×12, rag ×9) — service-role-only / no client grants = deny-all by design (safe per fp-rules); `personal_access_tokens`, `supervisor_review_queue`, `stripe_price_map` all verified GRANT-to-service_role-only.
- **`auth_user_in_tenant` / `auth_user_can_access_conversation`** SECURITY DEFINER funcs — caller-scoped via `auth.uid()` (OK); only `tenant_is_active` (param-only) flagged.
- **`tenantClient` single-layer isolation** — the proxy injects `.eq("tenant_id",…)` and throws fail-closed on unregistered tables; documented accepted service-role filter.
- **SSRF via stored `*_url`** in rag — all persisted URL fields pass through `safeUrl` (scheme allowlist + metadata-host denylist).

---

## 4. Semantic→mechanical + harness issues filed against `jharvieux/Harvey`

| Issue | Type | Title |
|-------|------|-------|
| [#619](https://github.com/jharvieux/Harvey/issues/619) | harness (high) | `isGitRepoRoot` false-negative on case-insensitive FS silently skips git-history secret scan (SEC-TH-GH-00) |
| [#620](https://github.com/jharvieux/Harvey/issues/620) | harness (high) | Monorepo per-app fan-out reuses finding IDs → `--findings-out` fails schema validation, deliverable findings.json not written |
| [#621](https://github.com/jharvieux/Harvey/issues/621) | harness | M6 `simplify-scan` ignores `--hotspots` scope on a monorepo (105MB / 21,386-file packet) |
| [#622](https://github.com/jharvieux/Harvey/issues/622) | harness | M2 two-tenant seed fails on ATC `tenants_onboarding_stage_check` (hard-coded onboarding_stage value) |
| [#623](https://github.com/jharvieux/Harvey/issues/623) | harness | M8 monorepo root-level test workspace is dark — per-app reports "no test suite", orchestrator Stryker dry-run fails env |
| [#624](https://github.com/jharvieux/Harvey/issues/624) | harness | M3 hotspot-scan invokes vitals with target as path arg but vitals reads `./.vitals/store.db` from CWD → false "plugin unavailable" |
| [#625](https://github.com/jharvieux/Harvey/issues/625) | semantic→mechanical | Over-broad WebExtension `manifest.json` host_permissions + cookies is mechanically dark (ATC `apps/extension`) |

---

## 5. Modules that could not fully run, and why (fail-loud summary)

- **M2 dynamic pen-test — partial/blocked.** The isolated stack stood up and tore down cleanly (no foreign
  Docker volumes touched, #604 verified), but Harvey's two-tenant seed inserts an `onboarding_stage` value ATC's
  current CHECK constraint rejects, so no cross-tenant probe executed. Second backend (rag) not stood up (#610).
  → Harvey #622, #610. **This is the one module with no findings coverage this engagement.** _Update 2026-07-19:
  #622 fixed and verified (see the addendum at the top); the seed now advances past the CHECK but is blocked on the
  next column by a dangling generic FK (`tenants.tier_id`) → Harvey #630. Runtime isolation proof still pending._
- **M7 Lighthouse — requires-live-run (deliberate).** A CWV run needs a full `next build`+`next start` against
  ATC's production `.env.local`; not built to avoid a long build touching live services. Static code tier + DB
  advisors ran.
- **M8 mutation — partial.** ATC's root-level vitest workspace is not runnable through Harvey's per-app or
  orchestrator M8 invocation → no mutation score. ATC is well-tested; this is a Harvey limitation (#623), not a
  client gap.
- **M10 live (main) — requires-live-run.** `supabase-main` MCP has no `execute_sql` by engagement scope; row-level
  PII not sampled. Schema tier + column inventory covered it.
- **M4 (apps/main), M5 (shared-types) — partial/requires-live-run** with reasons above.

## 6. CLAUDE.md reconciliation note (for the supervisor)

Nothing in CLAUDE.md was falsified by this run. Two brief-level observations for the operator (human-owned IP —
not edited by me):
- `docs/scan-extras.txt` pre-states ATC advisor conclusions ("2 of 3 [DEFINER] cleared", "11 of 13
  [no-policy] confirmed locked"). Re-measured live this run: the counts still hold (3 DEFINER flagged, 2
  caller-scoped cleared + `tenant_is_active` residual; no-policy tables all service-role-only). The pre-stated
  numbers are currently accurate but are recall — the brief could note "verify live, do not quote."
- The runbook step-7 assembly (`--findings-out`) is currently unusable on a monorepo (Harvey #620); the report
  ledger here was assembled from the derived `coverage.json` + the individual pass artifacts instead.
