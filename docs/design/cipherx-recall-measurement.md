# Harvey recall measurement — thecipherxpro/cipherx-vulnerability-lab

**Date:** 2026-07-18
**Target:** `thecipherxpro/cipherx-vulnerability-lab` ("CipherX Vulnerability Lab"), a deliberately-
vulnerable **Next.js 16 App Router + Supabase** (Auth / PostgreSQL / RLS / RPC / Storage, role-based)
internship training lab. Cloned to `/private/tmp` (ephemeral, deleted after).
**Answer key:** `docs/design/cipherx-answer-key.md` — 21 grounded findings (CX-01..CX-21) reconstructed
from source (the repo ships no scored report), each with an expected tier. CX-21 (fake outdated deps)
and README module 12 (report writing) are **advertised-but-not-real** and score N/A.

## Reproducible semantic re-score identity (#1947)

The semantic re-score is pinned to repository commit
`b6f0d9d7fa1e956ef91903f11d7dddcc628ba869` at the repository root. Generate the effective policy
with `pnpm exec tsx src/cli/semantic-corpus-triage-policy.ts --measurement semantic-recall --slug
cipherx --repo <clone-root> --out <policy-file>`, then invoke the `vuln-scan` skill with
`briefs/scan-extras.txt` and the `triage` skill with three fresh votes.
The policy waives only the blanket intended-demo exclusion for this exact corpus identity. Mock CVE
data, public anon keys, placeholder credentials, missing hardening, unreachable code, and every other
technical precision rule remain active. Preserve the completed `TRIAGE.json` unchanged and feed it
directly to `record-pass`; do not force findings to meet the historical 20-positive floor.

### #1947 audited reconciliation — 2026-09-03

The pinned scan produced 32 candidates. Fresh triage conserved all 93 independent ballots across
31 deduplicated candidates and classified 15 true positives, 16 false positives, and 1 duplicate.
A row-level source/grant audit freezes **16 positives** and retains CX-21/CX-22 as the two precision
negatives. CX-01/02/04/10/12/15/16/17/18 remain with narrower mechanisms. Retired compound CX-11
becomes CX-23/24/25 for the three independently proven anon definer RPCs; retired app-route CX-13
becomes CX-26/27 for the two explicitly granted definer invoice IDORs. CX-28 records the signup
role-metadata escalation and CX-29 the authenticated secret-dump RPC. CX-03, CX-05..09, CX-14,
CX-19, and CX-20 are retired because the pin shows decoys, absent grants/exposure, no reset consumer,
or hardening-only impact. No retired ID was silently reused, and the pin is unchanged.
The completed attempt is retained as `semantic-corpus-passes/cipherx.2026-09-03.triage.json`
(SHA-256 `032bc8927bc61d57ef556a448c1346881a758795cbbe101998ee610d35ade7cd`); its generated but
unaccepted M1 receipt has SHA-256 `804e1a91400705d63d9dedbef0b42af84e075e8f761c9fff832d9a8cf62193cd`.
The failed dated receipt remains evidence, not an accepted pass. A complete exact-pin scan,
three-vote triage, `record-pass`, and both semantic validators must pass before the live artifact is
replaced.

This is a MEASUREMENT — every caught/missed below is grounded in a Harvey run's actual output observed
on this date, across **all three tiers** (mechanical, semantic-LLM, dynamic). No Harvey source was
changed. Isolated Docker (autonomous M2 self-provisions a fresh local Supabase in its own temp workdir;
app port pinned `HARVEY_APP_PORT=65367`); stack torn down (`docker ps -aq` = 0) after. The committed
cloud `.env` (CX-02) was **never** used — the dynamic tier stood up a local stack from the target's own
`supabase/migrations/`.

---

## Historical tally: 20 caught / 20 pre-audit claims (CX-21 = N/A) — 20/21

A finding = caught if **any** tier caught it. Every real finding (CX-01..CX-20) was caught; CX-21 is
not a real vulnerability and was correctly **not** flagged (osv-scanner found nothing planted — the
"outdated deps" endpoint returns a hard-coded mock CVE list; real `package.json` deps are current).

| Tier | Real findings it caught | Notes |
|------|-------------------------|-------|
| **Mechanical** (`quick-scan` + static RLS/config + `detect-static` + `pii-classify --schema`) | **7 outright** — CX-02, CX-03, CX-04, CX-05, CX-06, CX-09, CX-16. Plus **7 partial/disclosed** — CX-01, CX-07, CX-11, CX-15, CX-18, CX-19, CX-20. | The static permissive-`USING(true)` RLS pass caught CX-05/06/09; `harvey-ssrf-fetch` fired live (CX-16). |
| **Semantic (LLM)** (rigorous `vuln-scan` skill review of source, triaged vs `fp-rules.txt`) | **20** — every real finding CX-01..CX-20, incl. all 8 the mechanical tier missed or only partially caught. | Carries CX-08, CX-10, CX-12, CX-13, CX-14, CX-17 outright, and completes CX-01/07/11/15/18/19/20. |
| **Dynamic (M2)** (`dynamic-validate --execute`, autonomous stand-up) | **0 CX findings proven live** + **1 real M2 provisioning finding** (`M2-PROVISION-MIGRATE`). | Recognized the org-tenant model and Supabase Auth (further than SuperRedHat), but the two-tenant seed collided with the target's `handle_new_user` profile trigger before the live matrix — recorded loud, not skipped (#598). |
| **Union** | **20 / 20 real (20/21)** | Semantic is the tier that clears the board. |

**Tier split of the aggregate:** mechanical is the strongest it has been on any App-Router target
measured (7 outright, driven by the new permissive-RLS pass and a live SSRF hit); semantic is decisive
(20/20); dynamic contributed 0 CX findings this run because of a stand-up seed collision, not a
detection gap — it is the same #598 limitation, hit here for a different reason than SuperRedHat.

---

## The permissive-RLS verdict (the answer key's headline prediction) — CONFIRMED, with nuance

The answer key predicted: RLS is **enabled** with permissive `USING(true)` policies (not disabled), so
the "table without RLS" detector will **not** fire on CX-05/06/08/09 — verify whether a permissive-policy
static pass and/or the dynamic tier catches them. Measured result:

- **The "table without RLS" detector did NOT fire** (correct — RLS is on for every table). But a
  **newer static permissive-`USING(true)` RLS-policy pass DID catch the ones that carry a recognized
  tenant key.** For CX-05 (`invoices`), CX-06 (`support_tickets`), CX-09 (`employee_records`) it emitted
  `[High] SB-RLS-POLICY-…` with the exact reason:
  > *"USING is 'true' — the policy puts every row of a table that declares the tenant key 'company_id'
  > in scope, so every caller … reads every tenant's rows. Live clauses — SELECT USING: true."*
  These three are caught **mechanically**.
- **CX-07** (`fake_secrets` / `fake_files` `TO anon USING(true)`) was **not** flagged as a finding but
  was **disclosed loud**: `[Info] SB-RLS-USING-TRUE-UNASSESSED` names `fake_secrets` and `fake_files`
  explicitly as `USING(true)` policies "left unassessed — no recognised tenant key to judge them
  against … named so the sparing can be checked rather than read as clean from the absence of a
  finding." This is the fail-loud contract working: an anon-readable table isn't silently passed, it is
  surfaced for review. Semantic confirms it as a real leak; the M1-connected live-RLS tier
  (`checkPublicBucketsWithNoPolicies` / `detect-deeper`) would prove it, but no client DB was in scope.
- **CX-08** (`profiles_select_weak_hints … USING (is_active = true)`) was the one the static pass
  **missed**: `USING (is_active = true)` is not literally `true`, and `profiles` is per-user (not
  `company_id`-keyed), so neither the permissive-`USING(true)` rule nor the tenant-key rule matched.
  Caught by the **semantic** tier.

So: the permissive-`USING(true)` static pass catches the tenant-keyed permissive policies mechanically
(CX-05/06/09), discloses the anon ones (CX-07), and misses the non-literal-`true` predicate (CX-08).
The dynamic tier could not add live proof for any of them because the stand-up seed collided (below).

---

## How Harvey was run

- **M1 static (mechanical):** `pnpm quick-scan --dir <t> --findings-out <f>` — 63 findings (semgrep
  `harvey-*` + gitleaks/trufflehog + osv-scanner + the static Supabase RLS/DEFINER/config passes).
- **M6/M7/M9 static:** `pnpm detect-static <t>` — 49 findings (quality/perf/App-Router AST; no new
  security CX catch — the App-Router authz taint stayed dark, see #601).
- **M10:** `pnpm pii-classify --schema <t>/supabase/migrations` — `employee_records → High (5.6): NAME,
  EMAIL, US_SSN`; `internal_credentials → High: STORED_PASSWORD`; `profiles → Medium: EMAIL, NAME,
  PHOTO`. Corroborates the PII sensitivity behind CX-08/CX-09.
- **Semantic (LLM):** manual `vuln-scan` skill review of every `src/app/api/**/route.ts`, the RLS/RPC
  migrations, storage/bucket config, role-gating (`src/lib/roles.ts`, `admin.ts`), and the seed scripts;
  each finding grounded in a re-read file:line; triaged against `briefs/fp-rules.txt` (which is what keeps
  CX-21 out — a mock CVE list is not a dependency finding).
- **Dynamic (M2, autonomous):** `HARVEY_APP_PORT=65367 pnpm dynamic-validate <t> --execute --out <dir>`
  — self-provisioned a fresh local Supabase, applied the migrations, attempted the two-tenant + auth-user
  seed, then (would have) run the live PostgREST cross-tenant matrix + app-route probes. Torn down in a
  `finally` (`docker ps -aq` = 0 after).

## Per-finding score (2026-07-18)

| id | Status | Tier(s) | Evidence (from this date's runs) |
|----|--------|---------|-----------------------------------|
| CX-01 | **CAUGHT** (mech partial) | semantic; mechanical(partial) | Mechanical: `[High] AUTH-sensitive-console-log … scripts/seed-auth-users.ts` (a password is written to console). Semantic reads the plaintext weak creds `Admin123 / Manager2024 / client123 / support1` at `seed-auth-users.ts:30,38,46,55`. |
| CX-02 | **CAUGHT** | mechanical; semantic | `[Critical] Supabase service_role JWT (decoded role claim)` (`supabase-service-role-jwt`) at git-tracked `.env:13`, plus `jwt` hits at `.env:13,18`. |
| CX-03 | **CAUGHT** | mechanical; semantic | `[High] detected-aws-secret-access-key` at `public/.env.backup:11` + `[High] Sensitive file served from public/: public/.env.backup`. |
| CX-04 | **CAUGHT** | mechanical; semantic | 4× `[High] Sensitive file served from public/`: `.env.backup`, `backup/database_backup_2024.sql.bak`, `backups/db-backup-demo.sql`, `configs/.env.demo`. |
| CX-05 | **CAUGHT** | mechanical (permissive-RLS pass); semantic | `[High] SB-RLS-POLICY-public.invoices.invoices_select_all_auth` — "USING is 'true' … tenant key 'company_id' … reads every tenant's rows" (`…0001_vulnerable_rls.sql`). |
| CX-06 | **CAUGHT** | mechanical (permissive-RLS pass); semantic | `[High] SB-RLS-POLICY-public.support_tickets.support_tickets_select_all_auth` (same mechanism). |
| CX-07 | **CAUGHT** (mech disclosed) | semantic; mechanical(disclosed) | `[Info] SB-RLS-USING-TRUE-UNASSESSED` names `fake_secrets` + `fake_files` (anon `USING(true)`) as unassessed — fail-loud, not a High finding (no recognized tenant key). Semantic confirms the anon read. |
| CX-08 | **CAUGHT** | semantic | `profiles_select_weak_hints … USING (is_active = true)` at `…0007_portal_rls.sql:33-34` exposes `weak_password_hint` to any authed user. Mechanical MISS (`is_active=true` ≠ literal `true`; profiles not `company_id`-keyed). |
| CX-09 | **CAUGHT** | mechanical (permissive-RLS pass); M10; semantic | `[High] SB-RLS-POLICY-public.employee_records.employee_records_select_auth` + `pii-classify`: `employee_records → High: NAME, EMAIL, US_SSN`. |
| CX-10 | **CAUGHT** | semantic | Public read buckets `lab-public`/`lab-backups`/… (`INSERT INTO storage.buckets (…, public, …) … true` + `FOR SELECT TO public`, `…0003_storage_buckets.sql:4,10-12`). Mechanical MISS (no `storage.buckets` static pass); M1-**connected** `checkPublicBucketsWithNoPolicies` would catch but no live DB in scope (requires-live-run). |
| CX-11 | **CAUGHT** (mech partial) | semantic; mechanical(partial) | `get_user_by_email`/`search_lab_data`/`export_demo_secrets` are `SECURITY DEFINER` + `GRANT EXECUTE … TO anon` (`…0002_vulnerable_rpc.sql:20,38,48`). The DEFINER-review pass fired only on `seed_portal_profile`, missing the anon-grant dump RPCs → **#602**. |
| CX-12 | **CAUGHT** | semantic | plpgsql SQLi: `search_tickets_unsafe` builds `EXECUTE '… ILIKE ''%'' \|\| p_query \|\| ''%'''` (`…0005_spec_buckets_and_rpc.sql:114-118`). Mechanical MISS (JS-only SQLi taint; no migration-body scan) → **#602**. |
| CX-13 | **CAUGHT** | semantic | IDOR at `src/app/api/invoices/[id]/route.ts:23` (`.eq("id", id).single()`, no `company_id` check). Mechanical MISS — `harvey-idor-param` source is `params.$K`; this uses `const { id } = await params` (Next 16 async) → **#601**. Dynamic not proven (seed collision). |
| CX-14 | **CAUGHT** | semantic | Mass assignment at `src/app/api/profile/route.ts:29` (`.update(body)` from `await request.json()`, no whitelist). Mechanical MISS — `harvey-mass-assignment` requires a spread `{...$BODY}`; this passes a bare `body` → **#601**. |
| CX-15 | **CAUGHT** (mech partial) | semantic; mechanical(partial) | `src/app/api/internal/users/route.ts:9` trusts `x-user-role` header → `createAdminClient()` dumps `fake_secrets` + `system_config`. Mechanical: only `[Medium] harvey-select-star-pii` at `:20` (right file, wrong mechanism). No header-role-spoof detector → noted in **#601**. |
| CX-16 | **CAUGHT** | mechanical; semantic | `[Medium] harvey-ssrf-fetch` at `src/app/api/webhook/route.ts:25` (`fetch(url)`, url from `searchParams`). **Fired live** — the answer key predicted this as manual-only (#570 dark); that prediction is now falsified for App-Router SSRF. |
| CX-17 | **CAUGHT** | semantic | Reflected XSS (`q` + row fields interpolated into an HTML string, `tickets/search/route.ts:57,63`) + reflected CORS (`Access-Control-Allow-Origin: origin` + `Credentials:true`, `:11-17`). Mechanical MISS — `harvey-cors-reflected-origin` matches only imperative `res.setHeader`, not object-literal headers; no reflected-XSS-into-HTML-string detector → **#601**. |
| CX-18 | **CAUGHT** (mech partial) | semantic; mechanical(partial) | Mechanical caught the conn-string leak: `[Critical] harvey-db-uri-credentials` + `detected-username-and-password-in-uri` at `src/app/api/debug/route.ts:10`. Broader verbose-error facets (`error.stack`, `process.cwd()`, env dump at `:16-22`) are semantic-only. |
| CX-19 | **CAUGHT** (mech partial) | semantic; mechanical(partial) | Mechanical: `[Medium] harvey-route-noauth` at `password-reset/route.ts:10` (right file, "unauthenticated mutation" premise). Semantic gets the actual bug: reset `debug_token`/`reset_url` returned in the JSON response + written to `support_tickets.internal_notes` + GET echo + no rate limit (`:17-52`). Rate-limit facet tracked by #159. |
| CX-20 | **CAUGHT** (mech partial) | semantic; mechanical(partial) | Mechanical: `[Medium] No Content-Security-Policy configured` (`next.config.ts`). Semantic adds the `.htaccess` `Header unset X-Frame-Options` / `Header unset Content-Security-Policy` / `Header set Access-Control-Allow-Origin "*"` (`.htaccess:29-32`). |
| CX-21 | **N/A** (correctly not flagged) | — | `src/app/api/dependencies/route.ts` returns a hard-coded fake CVE list; osv-scanner over real `package.json` planted nothing (only genuine, unrelated `postcss@8.4.31`). `fp-rules.txt` (mock data ≠ dependency finding) keeps it out. Not a real vulnerability. |

## Dynamic (M2) — what the autonomous stand-up reached, and where it stopped

The M2 pipeline got **further on shape** than on SuperRedHat: it read this app as **org-tenant** and
recognized four scoped tables —
`HARVEY_TABLES=profiles:company_id,invoices:company_id,support_tickets:company_id,employee_records:company_id`
— and correctly detected **Supabase Auth** (`supabase.auth.getUser` / `@supabase/ssr`), so the seeded
Supabase sessions would have applied to the authenticated app-route probes. The verdict was `GO (full)`.

It then **stopped at the seed**, loud:

> `client migrations failed to apply (recorded as an M2 finding, not skipped): … seed.sql:3: ERROR:
> duplicate key value violates unique constraint "profiles_pkey" … Key (id)=(127d6569-…) already exists.`

Root cause (verified): the target defines `handle_new_user()` `AFTER INSERT ON auth.users` that inserts
a `public.profiles` row (`…0000_initial_schema.sql:134-150`). Harvey's two-tenant seed creates two auth
users (which fire the trigger → profiles rows) and then its generated `seed.sql` **explicitly inserts
those same profile ids** → `profiles_pkey` collision, aborting the seed transaction. No cross-tenant
rows landed, so the live PostgREST matrix and the Tier-2 app-route probes (IDOR-OBJECT / MASS-ASSIGN /
BFLA / CSRF) never ran. The tool wrote **`M2-PROVISION-MIGRATE` (Medium, Confirmed)** rather than a
silent clean pass, and (a labeling nit) reported it as a *migration* failure when it was the *seed*.

**This exact limitation is already tracked as jharvieux/Harvey#598** ("two-tenant seed collides with
`handle_new_user` profile trigger + mislabels seed failure as migration failure"). It is the reason the
dynamic tier proved 0 CX findings here — a stand-up gap, not a detection gap: CX-05/06/09 (cross-tenant),
CX-13 (IDOR-object), CX-14 (mass-assign), CX-15 (BFLA), CX-19 (rate-limit) are all shapes M2 *would*
have probed on a clean seed. Not filed anew; #598 is precise. The dynamic tier is the one to re-run
against this target once #598 lands (seed with `ON CONFLICT DO NOTHING` around trigger-created profiles).

## Where each tier changed the result

- **Mechanical vs the answer key's prediction — better than predicted twice.** The answer key expected
  CX-16 (SSRF) to be manual-only (`harvey-ssrf-fetch` dark, #570) — it **fired**. It expected the
  permissive-RLS policies to *maybe* be caught — they **were**, for the `company_id`-keyed tables
  (CX-05/06/09), with CX-07 disclosed. Measure, don't recall: #570 landing changed the SSRF result.
- **Semantic is decisive: 20/20.** It carries the 8 findings mechanical missed or half-caught, most of
  which are **structurally mechanizable** — filed as **#601** (App-Router taint: async await-params IDOR
  source, bare-var mass-assign sink, object-literal reflected-origin CORS, + the header-role-spoof note)
  and **#602** (migration SQL: plpgsql `EXECUTE`-concat SQLi, DEFINER-granted-to-anon dump RPCs).
- **Dynamic proved 0 this run**, blocked before the matrix by the #598 seed collision — reported loud,
  not skipped.

## Semantic → mechanical flags filed

| CX | Class | Harvey issue |
|----|-------|--------------|
| CX-13, CX-14, CX-15, CX-17 | App-Router taint/authz/CORS request-shape precision | **jharvieux/Harvey#601** |
| CX-11, CX-12 | Migration-SQL static: plpgsql `EXECUTE`-concat SQLi + DEFINER-granted-to-anon | **jharvieux/Harvey#602** |

Not separately filed (noted for a future coverage pass): CX-18's broader verbose-error facets
(`error.stack` / `process.cwd()` / env dumped into a response — mechanizable but lower-value) and CX-19's
rate-limit facet (already #159). CX-01/CX-20 are caught mechanically in part and fully by semantic; no
new detector warranted.

## Harvey findings NOT in the answer key

All appear legitimate against the app's actual behavior, outside the planted-21 set:
- `[Critical] harvey-db-uri-credentials` ×several on the seed/backup SQL (`supabase/seed.sql`,
  `storage-seed/lab-backups/…`, `public/backup/…`) — real inline DB-password URIs.
- `[Low] SB-OPEN-SIGNUP` + `[Medium] SB-EMAIL-CONFIRM-OFF` (`supabase/config.toml`) — open signup, email
  confirmation off.
- `[High] SB-DEFINER-AUTHZ seed_portal_profile` — a `SECURITY DEFINER` function flagged for caller-authz
  review (a *different* function than CX-11's anon RPCs).
- 8× RLS-initplan Perf findings (`auth.*` re-evaluated per row) and the M6/M7/M9 quality signals from
  `detect-static` (unbounded `select('*')`, no-cache data routes, single-use helpers).
- `[Medium] postcss@8.4.31` OSV hit — a genuine (unplanted) transitive dependency advisory.

## Comparison to prior measurements

`docs/design/vandyand-recall-measurement.md` (org-tenant + Supabase-Auth) and
`docs/design/superredhat-recall-measurement.md` (per-user + custom-auth, re-scored 12/12 across three
tiers). CipherX is **org-tenant + Supabase-Auth + pure App Router** and scores **20/21 (20/20 real)** on
the union — the highest raw count of the three, carried by the semantic tier. The distinguishing facts
here: (1) the new permissive-`USING(true)` RLS pass makes CX-05/06/09 **mechanical**, and `harvey-ssrf-fetch`
now fires on App-Router SSRF (CX-16) — mechanical is materially stronger than the SuperRedHat baseline;
(2) the remaining App-Router taint gaps are narrower and more precise than "#570 systematic" — they are
the async-`await params`, bare-`update(body)`, and object-literal-CORS shapes in #601; (3) the dynamic
tier, which cleared 4 findings on SuperRedHat, cleared 0 here purely because of the #598 seed collision,
not a modeling gap — this target is the best M2-shaped of the three and should re-score well once #598 lands.

## Provenance

Every row grounded in a run observed 2026-07-18 on the cloned source (deleted after). Artifacts:
`quick-scan` findings (63), `detect-static` (49), `pii-classify --schema` (14 PII columns / 8 tables),
and the M2 run log + `M2.pass.json` (1 finding: `M2-PROVISION-MIGRATE`). Docker torn down
(`docker ps -aq` = 0). No Harvey source changed; the committed cloud `.env` was never used.
