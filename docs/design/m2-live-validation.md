# M2 autonomous live stand-up — validation record

**What this proves:** Harvey's M2 dynamic pen-test provisions its OWN local Supabase for an
arbitrary Supabase/Next.js target and runs the tenant-isolation matrix against it, with **no
operator step**. Everything below was executed for real (Docker 29.5, Supabase CLI 2.102, psql 18,
node 24) on 2026-07-18 — this is a "measure, don't recall" record, not a description of intent.

Command under test:

```
pnpm dynamic-validate <target> --execute --out <artifacts-dir>
```

The autonomous pipeline (`src/pentest/live-standup.ts` `createLiveStandUp`, driven by the pure
orchestrator in `src/dynamic-validate.ts`):

1. `supabase start` a fresh local stack (client `supabase/seed.sql` neutralized so a broken client
   seed can't block the stand-up; restored on teardown).
2. `supabase db reset --no-seed` — applies the client's migrations. A set that won't apply to a
   fresh stack is recorded as an M2 finding (`M2-PROVISION-MIGRATE`), never a silent skip.
3. Captures the local `anon` / `service_role` keys + API URL from `supabase status -o env`.
4. Creates **two real auth users** (one per tenant) via the local GoTrue admin API, applies the
   Harvey generic two-tenant seed (`src/pentest/two-tenant-seed.ts`) wired to those users' ids, and
   signs both users in for per-persona JWTs.
5. Runs the live PostgREST cross-tenant read/write matrix (`pentest.ts --mode=explore` →
   `engine.ts runExplore`) against `127.0.0.1`, and writes `<artifacts-dir>/M2.pass.json`.
6. Always `supabase stop` in a `finally`.

`run-audit --artifacts-dir <dir>` then derives M2 `ran` from that artifact and folds its findings
into the deliverable — verified below.

---

## Target 1 — `targets/calibration` (deliberately-vulnerable, known answer key)

Run against a disposable copy in `/private/tmp`. The calibration app has planted RLS bugs
(`documents` `USING (true)`, `audit_logs` RLS-off, `invoices` `auth.role()='authenticated'`) plus
correctly-scoped true-negatives (`notes`, `counters`, `profiles`, `tenants`, …).

| Stage | Result |
|---|---|
| `supabase start` | ✅ stack up (all core services) |
| Migrations apply | ⚠️ **First run FAILED for real** — `relation "reports" already exists`: `reports` is declared in **two** committed calibration migrations (`20260709000004_b8_connected_advisors.sql` and `20260715000001_rls_using_true_negatives.sql`). The committed migration set has never stood up on a fresh live DB. Recorded, not hidden. (See follow-up below.) Also the committed `supabase/seed.sql` references `public.legacy_accounts`, which does not exist. |
| (disposable-copy workaround) | Made the duplicate `create table` idempotent and neutralized the client seed **in the /private/tmp copy only** to exercise the probe path against the real planted RLS bugs. |
| Two auth users + seed | ✅ created; generic seed applied (12 scoped tables, deduped) |
| App boot (Tier 2) | ❌ honest degrade — `npm install` fails on the calibration app's deliberately-broken dep `expres@1.0.0`; recorded as a limitation, Tier-1 still ran |
| Cross-tenant REST matrix | ✅ **11 findings, all correct, zero false positives** |
| `M2.pass.json` emitted | ✅ |

Findings vs. ground truth (exact match):

- `documents` — read leak to **anon + Tenant A + Tenant B + Admin** (4) — `USING (true)` ✅
- `audit_logs` — read leak to **anon + Tenant A + Tenant B + Admin** (4) — RLS off ✅
- `invoices` — read leak to **Tenant A + Tenant B + Admin** but **NOT anon** (3) — `auth.role()='authenticated'` ✅
- `notes`, `counters`, `profiles`, `tenants`, `pii_calibration_fixture`, `reports` — **no finding** (correctly scoped) ✅

The authenticated-persona scoping is real: `current_tenant_id()` reads `profiles.tenant_id where id
= auth.uid()`, and because the seed writes each auth user's real id into `profiles`, Tenant A sees
exactly its own `notes`/`counters` row and no other. Manually confirmed at the DB/REST layer too.

Evidence-path check:

```
pnpm exec tsx src/cli/run-audit.ts /private/tmp/m2-calibration --artifacts-dir /private/tmp/m2-artifacts-calibration
  → RAN  M2  Local pen-test (dynamic)  — … + dynamic pass (…: dynamic validation (postgrest-only coverage); 11 finding(s))
```

## Target 2 — `Wallens11/supabase-multi-tenant-starter` (real external multi-tenant app)

Cloned to `/private/tmp` at pinned commit `dcc147c…`. A genuine multi-tenant SaaS starter: tenant
membership lives in a `user_tenants(user_id, tenant_id, role)` junction table, and RLS scopes via
`get_user_tenant_ids(auth.uid())` — the **membership-table** pattern, not the profiles pattern.

| Stage | First run | After seed-robustness fix |
|---|---|---|
| `supabase start` + migrations | ✅ | ✅ |
| Two auth users | ✅ | ✅ |
| Generic seed applies | ❌ **`tenants_plan_check` CHECK violated** by the placeholder `'harvey-seed'` on the `plan` enum column → recorded as an `M2-PROVISION-MIGRATE` finding (fail-loud, not skipped) | ✅ seed applies cleanly (see fix) |
| App boot (Tier 2) | ❌ honest degrade — the target's `next build` fails (a real build error in `getTenantMembers`) | ❌ same, recorded |
| Cross-tenant matrix | — | ✅ **0 findings** |

The **0 findings is a real true-negative, not vacuous**: manually confirmed the seed populated 2
rows in each of `tenants` / `user_tenants` / `tenant_invitations` (service-role oracle), Tenant A's
JWT reads exactly **1** `user_tenants` row (its own tenant only), and anon reads **0** from both
scoped tables. mtstarter's RLS correctly isolates tenants, and Harvey correctly reports clean.

This target drove two general seed-robustness fixes that only surfaced by running for real:

- **Omit columns that carry a `DEFAULT`** (like serials): the default is a legal value by
  construction, so the seed survives `CHECK (plan IN (…))`, a `UNIQUE … DEFAULT gen_random_bytes()`
  token, etc., where a generic placeholder would not.
- **Per-row-distinct text placeholders** (`harvey-seed-a` / `-b`): a `UNIQUE` text column (a `slug`,
  a `name`) no longer collides across the two seeded rows.
- Plus **auth.users FK handling** (fill such columns with the real created-user id, so the FK holds
  and the membership/profile row maps the JWT to its tenant) and **table/column de-duplication** (a
  table declared in two migrations no longer double-seeds or names a column twice) — both first
  observed against calibration.

## Precision fix the live run forced (write probes)

The very first calibration run produced **59** findings: 11 correct reads + **48 false-positive
write "criticals"**. Cause: PostgREST returns a 2xx (204) for an unfiltered `PATCH`/`DELETE` that
RLS scoped to **zero rows**, and the old `diffWrite` treated any 2xx as a leak — so a persona's
authorized no-op write, and even an anon write that touched nothing, read as a breach. Fixed by
requesting `Prefer: return=representation` on every write and making `diffWrite` tenant-aware like
`diffRead` (a write leaks only if it actually **affected** rows the persona had no business
changing: an anon write that took effect, or an authenticated write that touched a foreign tenant).
Result: calibration drops to the correct **11 / 0-FP**. The calibration fixture was also updated to
model the real 200-with-own/empty-rows write response, so this class can't regress silently.

## Teardown / hygiene

Every run tears the stack down (`supabase stop --no-backup`) and restores the client seed file in a
`finally`. Verified no orphaned `supabase_*` containers remained after the runs. External targets
were cloned only under `/private/tmp`; `targets/calibration` in the repo was never modified.

## Follow-ups (filed as issues)

- **Calibration migrations don't stand up on a fresh live DB** (#546, fixed) — duplicate `create
  table public.reports` across two migrations, and a `seed.sql` referencing a non-existent
  `legacy_accounts`. The static tooling never applied them live, so this stayed latent. Fixed by
  renaming the benign tenant-scoped-read fixture's table to `tenant_reports` (the connected-tier
  `P-RLS-ENABLED-NO-POLICY` plant keeps the literal name `reports`) and adding the missing
  `legacy_accounts` table (RLS enabled, zero policies, same deny-all shape as `service_state`).
  Also found and fixed in the same pass: the `#301` widgets migration
  (`20260718000001_fk_tenant_scope.sql`, landed after this doc was written) called a
  nonexistent `current_tenant()` instead of `public.current_tenant_id()`, which also blocked a
  fresh `supabase db reset`. Verified live: `supabase db reset` applies the full migration set +
  seed with zero errors.
- **Generic seed can't satisfy a `CHECK` on a *non-defaulted* enum column** (#547) — the
  `DEFAULT`-omission fix covers the common case (defaulted enums); a `CHECK (col IN (…))` with no
  default still fails the INSERT (recorded as an `M2-PROVISION-MIGRATE` finding). Parsing simple `IN
  (…)` allow-lists to pick a legal value would close the gap.
- **App-route probes (Tier 2)** ran only as a build/boot attempt here; neither target booted
  (calibration's broken dep; mtstarter's build error), so the NO-RATE-LIMIT loop (#159) and seam
  probes (#161) were not exercised end-to-end against a live app. The PostgREST matrix (Tier 1) does
  not need the app and ran fully on both.
