# Harvey answer key — thecipherxpro/cipherx-vulnerability-lab

**Original reconstruction:** 2026-07-18. **Audited semantic reconciliation:** 2026-09-03 (#1947).
**Target:** `thecipherxpro/cipherx-vulnerability-lab` ("CipherX Vulnerability Lab"), a deliberately-
vulnerable Next.js 16 App Router + Supabase (Auth / PostgreSQL / RLS / RPC / Storage, role-based)
internship training lab. Cloned to `/private/tmp` (ephemeral, deleted after this run).

**This is an ANSWER KEY, not a fresh-pass claim.** The repo ships **no scored report** — only a fake
placeholder (`public/reports/pentest-draft-demo.md`) whose "findings" are lorem-ipsum for a
file-discovery exercise. The ground truth below was **reconstructed from source**: every entry cites
a real file:line. The 2026-09-03 audit reconciled those claims against the unchanged pinned source
and three-vote triage; the table below is the **denominator** for the next semantic pass. It does not
promote the retained failed receipt or assert that a fresh pass is green. Mirrors the structure of
`docs/design/vandyand-recall-measurement.md` and `docs/design/superredhat-recall-measurement.md`.

The README advertises **"12 vulnerability training modules"** and a "Vulnerable Endpoints" table.
The audit treats those labels as claims to verify rather than ground truth. M11 fake dependencies
and M12 report writing are not real vulnerabilities; source-proven attack paths outside the module
list are represented independently in the current key.

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

## Audited semantic answer key (16 positives + 2 precision negatives)

The #1947 audit binds this key to
`b6f0d9d7fa1e956ef91903f11d7dddcc628ba869`. Every positive below is supported by the pinned
source and a 3/0/0 triage disposition. The exact pin is unchanged.

| id | Scored mechanism | Source / triage anchor |
|---|---|---|
| CX-01 | Weak seeded credentials disclosed from public static paths | `.htaccess` / `public/**`; f024 ties published pairs to provisioned accounts |
| CX-02 | Tracked service-role credential | `.env:13`; f023 |
| CX-04 | Sensitive files and backup configuration served publicly | `.htaccess` / `public/**`; f024 |
| CX-10 | Public backup and cross-user storage reads | `20260101000003_storage_buckets.sql`; f015 |
| CX-12 | Definer dynamic-SQL injection | `20260101000005_spec_buckets_and_rpc.sql:104`; f018 |
| CX-15 | Caller-controlled role header unlocks a service-role client | `src/app/api/internal/users/route.ts:9`; f002 |
| CX-16 | Public response-bearing SSRF | `src/app/api/webhook/route.ts:9`; f008 |
| CX-17 | Reflected/stored data emitted as executable HTML | `src/app/api/tickets/search/route.ts:52`; f007 |
| CX-18 | Public debug response discloses credentials and server internals | `src/app/api/debug/route.ts:10`; f022 |
| CX-23 | `get_user_by_email` anon definer enumeration | `20260101000002_vulnerable_rpc.sql:4`; f011 |
| CX-24 | `search_lab_data` anon definer search | `20260101000002_vulnerable_rpc.sql:23`; f012 |
| CX-25 | `export_demo_secrets` anon definer export | `20260101000002_vulnerable_rpc.sql:41`; f013 |
| CX-26 | `get_invoice_details` definer IDOR | `20260101000002_vulnerable_rpc.sql:51`; f014 |
| CX-27 | `get_invoice_debug` definer IDOR | `20260101000005_spec_buckets_and_rpc.sql:47`; f016 |
| CX-28 | Signup trigger trusts caller-controlled role metadata | `20260101000000_initial_schema.sql:134`; f026 |
| CX-29 | `debug_fake_secret_dump` exposes every secret to authenticated users | `20260101000005_spec_buckets_and_rpc.sql:70`; f017 |
| CX-21 | **Negative:** mock outdated-dependency endpoint is not a real dependency finding | `src/app/api/dependencies/route.ts` |
| CX-22 | **Negative:** browser anon/publishable key is public by design | `src/lib/supabase/client.ts` |

### Old-to-new disposition

| Former row(s) | Disposition |
|---|---|
| CX-01/02/04/10/12/15/16/17/18 | Retained with narrower, source-proven mechanisms; CX-17 is XSS only and CX-18 is the public debug route only. |
| CX-11 | Retired as a compound row; split into CX-23, CX-24, and CX-25. |
| CX-13 | Retired app-route claim; replaced by explicitly granted RPC rows CX-26 and CX-27. |
| CX-03 | Retired: demo/placeholder decoys do not prove usable secrets. |
| CX-05 through CX-09 | Retired: RLS policy text does not grant table access and the pinned config disables automatic exposure. |
| CX-14 | Retired: the required UPDATE grant is absent. |
| CX-19 | Retired: the disclosed reset token has no reset consumer. |
| CX-20 | Retired: the surviving header claim is hardening-only. |
| — | CX-28 and CX-29 added from independently confirmed source paths. |
| CX-21/CX-22 | Precision negatives preserved unchanged. |

**Module M12 "Final Report Writing"** is a lab deliverable, not a vulnerability:
`src/app/api/report-template/route.ts` serves a blank report template. Counted in the README's "12
modules" but has no attack surface — recorded here so the tally is legible, not as a scored item.

### Relationship to the README modules

The README labels are training prompts rather than a scored security oracle. The audit keeps their
source-proven portions under the rows above, splits independently exploitable RPCs, and rejects
grant-dependent, decoy, no-consumer, and hardening-only claims. M12 remains a deliverable rather
than a vulnerability; CX-21 records the fake dependency list as a precision negative.

## Fresh semantic rerun required

This reconciliation changes the denominator but does not claim a current passing receipt. Run the
exact-pin policy generator, `vuln-scan`, three-vote `triage`, and `record-pass`; then require both
`pnpm validate:semantic --artifacts-dir reports/semantic-recall` and
`pnpm validate:semantic-freshness --artifacts-dir reports/semantic-recall` to pass before replacing
the accepted CipherX artifact. Preserve the dated failed triage and receipt as provenance.

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
