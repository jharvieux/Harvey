# Harvey answer key — thecipherxpro/cipherx-vulnerability-lab

**Date:** 2026-07-18
**Target:** `thecipherxpro/cipherx-vulnerability-lab` ("CipherX Vulnerability Lab"), a deliberately-
vulnerable Next.js 16 App Router + Supabase (Auth / PostgreSQL / RLS / RPC / Storage, role-based)
internship training lab. Cloned to `/private/tmp` (ephemeral, deleted after this run).

**This is an ANSWER KEY, not a measurement.** The repo ships **no scored report** — only a fake
placeholder (`public/reports/pentest-draft-demo.md`) whose "findings" are lorem-ipsum for a
file-discovery exercise. The ground truth below was **reconstructed from source**: every entry cites
a real file:line read on this date (a migration, a route handler, an RPC, a storage/bucket config, an
exposed file). It is the **denominator** a future `run-audit` / `dynamic-validate` pass will be scored
against — no Harvey was run here, and no Harvey source was changed. Mirrors the structure of
`docs/design/vandyand-recall-measurement.md` and `docs/design/superredhat-recall-measurement.md`.

The README advertises **"12 vulnerability training modules"** and a "Vulnerable Endpoints" table.
Each was verified against code below; two of the twelve (M11 fake deps, M12 report writing) are
**advertised but are not real code vulnerabilities**, and the real attack surface is **wider than 12**
— the header-role-spoof, SSRF, reflected-XSS/CORS, password-reset-token-leak, SQL-injection, and
committed-secret findings are genuine and are enumerated as their own entries.

## Target shape (predicts what Harvey will catch)

Per the SuperRedHat/vandyand measurements, recall on a Supabase/Next.js target is largely a function
of how closely its shape matches the org-tenant / Supabase-Auth / (Express-vs-App-Router) assumptions
Harvey's rules were written against. This target's shape:

- **Tenancy: org-tenant via `company_id`**, with a per-user overlay. `invoices`, `support_tickets`,
  `employee_records` carry `company_id UUID … REFERENCES client_companies(id)`
  (`supabase/migrations/20260101000000_initial_schema.sql:34,45` + `20260101000006_portal_roles.sql:10`).
  `profiles`/`findings` are per-user (`id = auth.uid()`, `user_id`). **`company_id` IS one of the scope
  columns M2's two-tenant seed recognizes** (unlike SuperRedHat's `owner_id`) — so M2 should seed a
  second tenant and probe the invoices/tickets/employee tables live. Closer to vandyand (6/8) than to
  SuperRedHat (6/12) in M2-reachability.
- **Auth: Supabase Auth (email/password)**, `@supabase/ssr` cookie sessions, `supabase.auth.getUser()`
  (`src/lib/supabase/server.ts`, `src/lib/auth.ts`, `src/lib/supabase/middleware.ts`). App role lives in
  `profiles.role` (enum) and is additionally derived from a hard-coded email→role map
  (`src/lib/roles.ts:17-25`). **Not a custom JWT** — so M2's app-route probes (which mint a Supabase
  session token) should authenticate successfully here, unlike SuperRedHat.
- **Framework: pure Next.js 16 App Router** route handlers (`src/app/api/**/route.ts`). Request input is
  read as `request.nextUrl.searchParams.get(...)`, `await request.json()`, and the `{ params }` promise
  arg — **none of the Express `req.query/req.body/req.params` shapes Harvey's taint rules key on**. So the
  static object-level-authz / mass-assignment / SSRF / template rules are expected to go **dark** here
  (the #570 systematic gap), and those findings fall to M2 dynamic or manual review.

**Prediction:** M1 static should catch the committed/exposed secrets and the permissive-RLS migrations;
M2 dynamic should prove cross-tenant RLS reads and possibly mass-assignment; the App-Router-taint
findings (BOLA, SSRF, reflected XSS, CORS, verbose-error) are largely **manual-only** on the current
rule set. One M2 caveat: the `MASS-ASSIGNMENT` probe is hard-wired to `PATCH /api/profile`, but this app
exposes the mutation at **`PUT /api/profile`** (`src/app/api/profile/route.ts:19`) — the probe may miss it.

## The answer key (21 grounded findings across the 12 advertised modules + real extras)

Severity is best-effort CVSS-band judgment. "Expected tier" = the Harvey tier that *should* catch it
(M1 static / M1 connected / M2 dynamic / M10 / manual). "Manual?" flags findings no current Harvey
detector models (scanner-invisible on today's rule set).

| id | Module / name | Class | CWE | Sev | Location (file:line) | Expected tier | Manual? |
|------|---------------|-------|-----|-----|----------------------|---------------|---------|
| CX-01 | M1 Weak Password Accounts | Weak/default credentials | CWE-521 / CWE-1392 | High | `scripts/seed-auth-users.ts:30,38,46,55` (Admin123 / Manager2024 / client123 / support1); echoed in `public/archive/old-admin-notes.txt`, README | M1 static (string scan in seed/notes) + manual | partial |
| CX-02 | M5 Exposed Demo Secrets | Committed real Supabase **service-role + anon JWT** in tracked `.env` | CWE-798 / CWE-312 | Critical | `.env:12` (anon), `.env:13` (service_role — full RLS bypass), `.env:14` (`SUPABASE_DB_PASSWORD`) — `.env` **is git-tracked** | M1 static (gitleaks/trufflehog) | |
| CX-03 | M5 Exposed Demo Secrets | Secrets backup file with AWS/Stripe/JWT/SMTP keys | CWE-538 / CWE-312 / CWE-798 | High | `public/.env.backup:8` (service-role placeholder), `:11` (AWS secret), `:12` (Stripe), `:15` (`JWT_SECRET`) | M1 static (gitleaks over `public/`) | |
| CX-04 | M3 Sensitive File Discovery | Sensitive files served from web root; scanners un-hidden | CWE-538 / CWE-548 | Medium | `public/configs/.env.demo`, `public/backup/database_backup_2024.sql.bak`, `public/git-config/config`, `public/backups/db-backup-demo.sql`, `public/archive/*`; `.htaccess:44-46` grants `.bak/.sql/.env`; advertised via `public/robots.txt`+`sitemap.xml` | M1 static (secret scan) + manual (path enum) | partial |
| CX-05 | M2 Weak RLS | `invoices` readable by **every** authenticated user (cross-tenant) | CWE-285 / CWE-639 | High | `supabase/migrations/20260101000001_vulnerable_rls.sql:40-41` (`USING (true)`) | M2 dynamic (cross-tenant matrix) + M1 static permissive-policy pass | |
| CX-06 | M2 Weak RLS | `support_tickets` readable by every authenticated user | CWE-285 / CWE-639 | High | `20260101000001_vulnerable_rls.sql:44-45` (`USING (true)`) | M2 dynamic + M1 static permissive-policy | |
| CX-07 | M2 Weak RLS | `fake_secrets` / `fake_files` readable by **anon** | CWE-200 / CWE-732 | High | `20260101000001_vulnerable_rls.sql:48-49,55-56` (`TO anon USING (true)`) | M1 connected (live RLS) / M2 (anon PostgREST read) | |
| CX-08 | M2 Weak RLS | Any authenticated user reads all profiles incl. `weak_password_hint` | CWE-200 | Medium | `20260101000007_portal_rls.sql:33-34` (`profiles_select_weak_hints … USING (is_active = true)`) | M2 dynamic + M1 static permissive-policy | |
| CX-09 | M2 Weak RLS (+ PII) | `employee_records` (salary, `ssn_last4`) readable by any authenticated user | CWE-285 / CWE-359 | High | `20260101000007_portal_rls.sql:11-12` (`USING (true)`); table at `20260101000006_portal_roles.sql:8-17` | M2 dynamic + M10 PII + M1 static | |
| CX-10 | M4 Public Storage Bucket Exposure | Public read buckets (`lab-public`, `lab-backups`, `public-assets`, `lab-configs`) | CWE-732 | High | `20260101000003_storage_buckets.sql:4,6` + `20260101000005_spec_buckets_and_rpc.sql:9,10` (`public, …, true`) | M1 connected (`checkPublicBucketsWithNoPolicies`) | partial (static likely dark on `INSERT INTO storage.buckets`) |
| CX-11 | M9 Vulnerable RPC Function | `SECURITY DEFINER` RPCs granted to **anon** that dump/enumerate data | CWE-269 / CWE-862 / CWE-732 | Critical | `20260101000002_vulnerable_rpc.sql:20` (`get_user_by_email` → anon, user enum/PII), `:38` (`search_lab_data` → anon), `:48` (`export_demo_secrets` → anon); spec aliases `debug_fake_secret_dump` `20260101000005:70-87`, `get_invoice_debug` `:47-68` | M1 connected (live RPC review / `detect-deeper`) + manual | partial |
| CX-12 | M10 Unsafe Search Function | **SQL injection** — plpgsql dynamic `EXECUTE` with string concatenation | CWE-89 | Critical | `20260101000005_spec_buckets_and_rpc.sql:114-118` (`search_tickets_unsafe`; `EXECUTE '… ILIKE ''%'' || p_query || ''%'''`) | manual (plpgsql SQLi — JS/semgrep taint blind) | manual |
| CX-13 | M6 Broken Object-Level Authorization | IDOR — any invoice returned by id, no `company_id` ownership check | CWE-639 | High | `src/app/api/invoices/[id]/route.ts:18-22`; RPC twins `get_invoice_debug`/`get_invoice_details` (`…005:47`, `…002:51`) | M2 dynamic (app-route probe) / manual | manual on static (App-Router `{params}` source, #570) |
| CX-14 | M7 Mass Assignment Profile Update | Over-posting: `update(body)` with no field whitelist (role/company_id/is_active) | CWE-915 | High | `src/app/api/profile/route.ts:27-30` (`.update(body).eq("id", user.id)`) | M2 dynamic (but probe targets `PATCH`, app uses `PUT` — may miss) / manual | manual on static (`req.json()` source, #570) |
| CX-15 | (extra) Broken function-level authz / header-role spoof | Server trusts `X-User-Role` header, then uses **service-role** client to dump secrets + `system_config` | CWE-284 / CWE-639 / CWE-807 | Critical | `src/app/api/internal/users/route.ts:9-27` (`x-user-role` → `createAdminClient()` reads `fake_secrets`, `system_config`) | M2 dynamic / manual | manual on static |
| CX-16 | (extra) SSRF webhook fetch | Server fetches arbitrary attacker URL incl. cloud metadata (169.254.169.254) | CWE-918 | High | `src/app/api/webhook/route.ts:25` (`fetch(url)` from `searchParams.get("url")`) | M2 dynamic / manual | manual on static (App-Router source + `harvey-ssrf-fetch` dark, #570) |
| CX-17 | (extra) Reflected XSS + reflected CORS | `q` and row fields interpolated into an HTML response; CORS reflects `Origin` + `credentials:true` | CWE-79 / CWE-942 | High | `src/app/api/tickets/search/route.ts:57,63` (HTML interp), `:11-14` (reflected-origin CORS); also `src/app/api/debug/route.ts:36,59` | manual | manual (sink is an HTML **string**, not `dangerouslySetInnerHTML`; `harvey-permissive-cors` dark on reflected/object-literal) |
| CX-18 | M8 Verbose Error Messages | Info disclosure — DB connection string, stack traces, env, cwd leaked in responses | CWE-209 / CWE-200 | Medium | `src/app/api/debug/route.ts:10-22` (conn string + stack + env + `process.cwd()`); `src/app/api/profile/route.ts:35-40`; `src/app/api/invoices/[id]/route.ts:26-28` | manual / partial static (info-leak heuristic) | partial |
| CX-19 | (extra) Password-reset token leak / user enum / no rate limit | Reset token returned in API response **and** written to `support_tickets.internal_notes`; GET echoes token; no throttle | CWE-640 / CWE-201 / CWE-307 | High | `src/app/api/password-reset/route.ts:17-35` (`debug_token`, `reset_url`, token in ticket notes), `:39-52` (GET echo) | M2 dynamic (NO-RATE-LIMIT, #159) / manual | manual |
| CX-20 | (extra) Weak security headers / wildcard CORS | CSP + X-Frame unset; server-wide `Access-Control-Allow-Origin: *` | CWE-693 / CWE-942 / CWE-1021 | Low | `.htaccess:33-41` (`Header unset Content-Security-Policy`; `Header set Access-Control-Allow-Origin "*"`); no `next.config.ts` headers | M1 static (missing-security-headers) | partial |
| CX-21 | M11 Fake Outdated Dependencies | **Advertised but NOT a real vuln** — endpoint returns a hard-coded fake CVE list; actual `package.json` deps are current (next 16.2.10) | (n/a — mock data) | Info | `src/app/api/dependencies/route.ts:4-61` (static JSON); real deps in `package.json` | manual (osv-scanner on real deps finds nothing planted here) | manual / not-a-real-vuln |

**Module M12 "Final Report Writing"** is a lab deliverable, not a vulnerability:
`src/app/api/report-template/route.ts` serves a blank report template. Counted in the README's "12
modules" but has no attack surface — recorded here so the tally is legible, not as a scored item.

### Coverage of the README's 12 advertised modules

| README module | Real? | Answer-key id(s) |
|---|---|---|
| 1 Weak Password Accounts | yes | CX-01 |
| 2 Weak Supabase RLS | yes | CX-05, CX-06, CX-07, CX-08, CX-09 |
| 3 Sensitive File Discovery | yes | CX-04 |
| 4 Public Storage Bucket Exposure | yes | CX-10 |
| 5 Exposed Demo Secrets | yes | CX-02, CX-03 |
| 6 Broken Object-Level Authorization | yes | CX-13 |
| 7 Mass Assignment Profile Update | yes | CX-14 |
| 8 Verbose Error Messages | yes | CX-18 |
| 9 Vulnerable RPC Function | yes | CX-11 |
| 10 Unsafe Search Function | yes | CX-12 (SQLi) |
| 11 Fake Outdated Dependencies | **no** (mock data) | CX-21 (advertised-not-real) |
| 12 Final Report Writing | **no** (deliverable) | — |
| *(beyond the 12)* header-role spoof | yes | CX-15 |
| *(beyond the 12)* SSRF | yes | CX-16 |
| *(beyond the 12)* reflected XSS + CORS | yes | CX-17 |
| *(beyond the 12)* reset-token leak / no rate limit | yes | CX-19 |
| *(beyond the 12)* weak headers / wildcard CORS | yes | CX-20 |

## Expected tally by tier (a prediction, to be replaced by a measured run)

Grounded in the shape analysis, not a Harvey run. When Harvey is actually scored against this key,
replace this section with observed caught/missed.

- **M1 static (mechanical) — likely CAUGHT:** CX-02, CX-03 (committed/exposed secrets via
  gitleaks/trufflehog), CX-04 (secret strings in `public/`), and the permissive-RLS pass *may* flag
  CX-05/06/08/09 if it models `USING (true)` policies (vs. only "table without RLS"; RLS **is** enabled
  here, so the "table without RLS" detector will NOT fire — verify which pass catches permissive
  policies). CX-20 partial (missing-security-headers).
- **M1 connected — likely CAUGHT:** CX-07 (anon RLS live), CX-10 (public buckets via
  `checkPublicBucketsWithNoPolicies`), CX-11 (live RPC/grant review).
- **M2 dynamic — likely PROVEN (org-tenant + Supabase Auth, M2-reachable):** CX-05, CX-06, CX-09
  (cross-tenant reads on `company_id`-scoped tables). Possibly CX-13/CX-14 via app-route probes — with
  the `PATCH`-vs-`PUT` caveat on CX-14.
- **M10 — corroborates:** `employee_records` (salary, `ssn_last4`) and `profiles` (email, name) PII
  behind CX-08/CX-09.
- **Manual-only (no current detector models these; expect MISS on an automated run):** CX-12 (plpgsql
  SQLi), CX-13 static (BOLA — App-Router source, #570), CX-15 (header-role spoof), CX-16 (SSRF, #570),
  CX-17 (reflected XSS/CORS), CX-18 (verbose errors), CX-19 (reset-token leak / rate limit, #159), and
  CX-01/CX-21 partials. These especially test the dynamic M2 tier and future App-Router taint support.

The App-Router-taint gap (#570) and the M2 per-user/custom-auth gaps (#571) noted for SuperRedHat are
the two axes to watch here — but this target is **more favorable to M2** than SuperRedHat because it is
org-tenant (`company_id`) and uses Supabase Auth.

## Stand-up guide

Prereqs: **Node 20+, Docker (Rancher Desktop), Supabase CLI** (all per the repo README). The lab uses
Supabase local (migrations + seed) plus two seed scripts and demo accounts.

```bash
git clone https://github.com/thecipherxpro/cipherx-vulnerability-lab
cd cipherx-vulnerability-lab
npm install
cp .env.example .env.local           # DO NOT use the committed .env — it points at a real cloud project
npx supabase start                    # brings up local Postgres/Auth/Storage on default ports
# copy the anon + service_role keys printed by `supabase start` into .env.local
npm run supabase:reset                # = supabase db reset (10 migrations + seed.sql) + seed:auth + seed:storage
# or step by step:
#   npm run db:reset        # apply migrations + supabase/seed.sql
#   npm run seed:auth       # create the 6 demo auth users (Admin API, service role)
#   npm run seed:storage    # upload storage-seed/** into the public/backup buckets
npm run dev                           # http://localhost:3000
```

Reset lab data between exercises: `npm run reset:lab`.

**Demo accounts** (from the README; passwords also weak-by-design and discoverable via CX-01/CX-04 recon):

| Email | Password | Role |
|---|---|---|
| admin@cipherxlab.local | Admin123 | admin |
| instructor@cipherxlab.local | Teach123 | instructor |
| student1@cipherxlab.local | password123 | student |
| student2@cipherxlab.local | welcome1 | student |
| client@cipherxlab.local | client123 | client_demo |
| legacy@cipherxlab.local | qwerty123 | student |

(The seed script `scripts/seed-auth-users.ts` additionally provisions portal accounts
`manager@` / `it_support@`; passwords `Manager2024` / `support1`.)

**Safety note for any live Harvey run:** the repo's committed `.env` (CX-02) targets a **real** Supabase
cloud project (`fyzaqjfsvehxxzvygcou.supabase.co`) with a live-looking service-role JWT. Do **not** point
tooling at it — stand up the local stack with `.env.local` only. For Harvey's autonomous M2
(`pnpm dynamic-validate <target> --execute`), the stand-up provisions its **own** local Supabase from
the target's `supabase/migrations/`, independent of the committed `.env`.

## Provenance

Every row above was read on 2026-07-18 from the cloned source:
`supabase/migrations/20260101000000_initial_schema.sql`, `…0001_vulnerable_rls.sql`,
`…0002_vulnerable_rpc.sql`, `…0003_storage_buckets.sql`, `…0005_spec_buckets_and_rpc.sql`,
`…0006_portal_roles.sql`, `…0007_portal_rls.sql`; the App Router handlers under `src/app/api/**`;
`src/lib/supabase/*`, `src/lib/auth.ts`, `src/lib/roles.ts`; `.env`, `.env.example`, `.htaccess`,
`public/.env.backup`, `public/configs/.env.demo`, `public/archive/old-admin-notes.txt`;
`scripts/seed-auth-users.ts`, `scripts/seed-storage.ts`; `package.json`, `README.md`. The temp clone
was deleted after extraction.
