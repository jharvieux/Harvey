# Harvey recall measurement — yagaMI-Reverse/nocode-rescue

**Date:** 2026-07-18
**Target:** `yagaMI-Reverse/nocode-rescue` ("FeedbackHQ"), a representative multi-tenant
Supabase feedback-triage SaaS the way it comes out of a no-code builder (Lovable/Bolt/v0).
Cloned to `/private/tmp` (ephemeral, deleted after).
**Upstream claims:** the repo's `CASE-STUDY.md` documents **8 claimed findings** (3 Critical /
4 High / 1 Medium) with before-file locations. The #1947 source-and-triage audit retains **5** as
the frozen semantic scoring key; the disposition below explains why three claims are not scored.
The `before/` vs `after/` directory diff remains useful evidence (`after/supabase/migrations/0002_rls.sql` = the RLS fixes;
`after/.env.example` = the secret split; `after/app/api/triage/route.ts` = the server-side LLM move).

## Reproducible semantic re-score identity (#1947)

The semantic re-score is pinned to repository commit
`81350ee96e1aa223f0ce55e5ea91b6b1ffde1595` and scope `before/`. Clone that exact commit, generate
the effective policy with `pnpm exec tsx src/cli/semantic-corpus-triage-policy.ts --measurement
semantic-recall --slug nocode-rescue --repo <clone-root> --scope before --out <policy-file>`, then invoke the `vuln-scan`
skill with `briefs/scan-extras.txt` and the `triage` skill with three fresh votes over `<clone-root>/before`. The generated policy
waives only the blanket intended-demo exclusion for this exact corpus identity. It leaves every
technical precision rule active. Preserve the completed `TRIAGE.json` unchanged and pass it directly
to `record-pass`; do not restamp the historical July findings or hand-author the M1 receipt.

### #1947 audited reconciliation — 2026-09-03

The pinned scan produced 10 candidates. Fresh three-vote triage conserved all 30 ballots and
classified 6 true positives and 4 false positives. A row-by-row source audit then froze a **5-row**
key: NR-2 through NR-6. NR-1 is an invalid placeholder (0/3), NR-7 is a nonprivileged user-role
prompt with no privileged sink (0/3), and NR-8 combines non-distinct impacts and has no independent
3/0/0 finding. The pin and scope are unchanged. The failed dated attempt remains evidence; it is not
an accepted current pass.
The completed attempt is retained as `semantic-corpus-passes/nocode-rescue.2026-09-03.triage.json`
(SHA-256 `a64bab2608ec08e6da069c35294c53901c10fdcd550afd2e5370ab38d9d7eca8`); its generated but
unaccepted M1 receipt has SHA-256 `81046e31697b22741906ed708c41c6a6806428ef81f9972e5390f7a2001c601a`.
Re-run `vuln-scan`, three-vote `triage`, `record-pass`, `validate:semantic`, and
`validate:semantic-freshness` at the exact pin before replacing any accepted artifact.

This is a MEASUREMENT — every caught/missed below is grounded in a Harvey run's actual output
observed on this date, not recall. No Harvey source was changed.

## SCOPE — STATIC ONLY (this target cannot exercise the dynamic tier)

The vulnerable (`before/`) side is a **Vite + React SPA export**, not Next.js: a root
`schema.sql` (created by clicking around the Supabase Table Editor, *not* `supabase/migrations/`),
`import.meta.env.VITE_*` secrets, hardcoded key literals, `dangerouslyAllowBrowser`, and a
browser-direct OpenAI call. It is **not** a stand-up-able `supabase migrations` app for Harvey's M2
autonomous pen-test pipeline. So only Harvey's SOURCE/STATIC tiers were run here; the M2 dynamic
lane (Docker/`supabase start`) is out of scope for this measurement. This matters for scoring: some
answer-key classes are inherently dynamic- or semantic-only and are flagged **N/A-tier**, distinct
from genuine static-tier **gaps**.

## How Harvey was run

- **M1 static (mechanical):** `pnpm quick-scan --dir before --findings-out <f>` — semgrep + gitleaks
  + trufflehog + osv-scanner, all four binaries present. **3 raw findings** (1 security, 2 hygiene/
  coverage). trufflehog + gitleaks reported **0 leaks** (the committed keys are redacted
  placeholders, e.g. `...SERVICE_ROLE_FULL_ACCESS.xxx`, so the secret-value scanners have nothing to
  match — the structural `service-role-in-client` semgrep rule is the intended catch here, see #1).
- **M1 static (schema/RLS):** the migration-RLS pass inside quick-scan (`checkMigrationRlsStatic`).
- **M6/M7/M8-intent/M9:** `pnpm detect-static before --out <f>` — **4 findings** (2× M9, 2× M7).
  M9 App-Router detectors do not apply to a Vite SPA — recorded as N/A-tier, see below.
- **M10:** `pnpm pii-classify --schema before/schema.sql` — direct-on-`.sql` data classification.

## Audited semantic answer key (5 positives)

| ID | Sev | Finding | Class | Location (before) |
|---|-----|---------|-------|-------------------|
| NR-2 | 🔴 | OpenAI key via `VITE_OPENAI_API_KEY` + `dangerouslyAllowBrowser` | Client-side secret / browser LLM | `src/lib/ai.ts`, `.env` |
| NR-3 | 🔴 | No RLS on `tickets`/`profiles`/`workspaces` | RLS-off tables (anon read/write all tenants) | `schema.sql` |
| NR-4 | 🟠 | Client-only auth (`if(!user) navigate('/login')`) | Auth enforced in client, data layer open | `src/pages/Dashboard.tsx:20` |
| NR-5 | 🟠 | Client-side authz (`localStorage.role === 'admin'`) | Privilege from the client | `src/pages/Dashboard.tsx:16` |
| NR-6 | 🟠 | Stored XSS (`dangerouslySetInnerHTML={{__html: t.body}}`) | Stored XSS | `src/pages/Dashboard.tsx:61` |

Retired rows: NR-1 (invalid placeholder, 0/3), NR-7 (no privileged sink, 0/3), and NR-8
(compound/non-distinct impacts, 0/3). Historical sections below retain the original eight-claim
measurement for provenance; they are not the current semantic gate denominator.

## Score — 1 caught / 8, +3 partial, 4 missed (3 genuine static gaps + 1 N/A-tier)

| # | Status | By module | Evidence (from the run) |
|---|--------|-----------|--------------------------|
| 1 | **MISSED — genuine gap** | — | No detector fired. `harvey-service-role-in-client` (base.yml) is **Next.js-shaped**: it requires `process.env.SUPABASE_SERVICE_ROLE_KEY` *inside a `"use client"` block*. Here the key is a hardcoded JWT literal assigned to `createClient(URL, SUPABASE_SERVICE_ROLE, …)` and sourced from `import.meta.env.VITE_SUPABASE_SERVICE_ROLE` — no `"use client"` (Vite has no such boundary). trufflehog/gitleaks: 0 leaks (redacted placeholder). |
| 2 | **MISSED — genuine gap** | — | No detector models `dangerouslyAllowBrowser` (grep of `src/` for `dangerouslyAllowBrowser`/`allowBrowser` = 0 hits) nor a `VITE_`/`import.meta.env` secret-shipped-to-browser rule (`harvey-nextconfig-env-secret` keys off a Next.js `next.config`'s `{ env: { …process.env } }`, absent in Vite). 0 leaks from the value scanners (redacted key). |
| 3 | **MISSED — genuine gap** | — | Harvey **has** the RLS-off detector (`checkMigrationRlsStatic`, which caught this exact class on the vandyand teardown), but its file discovery is hardcoded to `<dir>/supabase/migrations/*.sql`. This target's schema is a root-level `before/schema.sql` (the Table-Editor export shape), so `existsSync(migrationsDir)` is false and the pass returns `[]`. quick-scan output: no RLS finding. This class **is** statically catchable — Harvey just didn't look at the file → real miss, not N/A. |
| 4 | **PARTIAL — wrong mechanism** | M9 (N/A-tier) | M9 flagged `` `localStorage` read on the SSR render path `` (Low) at `Dashboard.tsx:14` — the `localStorage.getItem("user")` auth-source line. It lands on the right line but as an SSR-hydration/correctness note, not "auth is enforced only in the client." No security detector models client-only auth; that class is semantic/dynamic. (And on a Vite SPA there is no SSR path, so the M9 flag is itself a false premise.) |
| 5 | **PARTIAL — wrong mechanism** | M9 (N/A-tier) | Same as #4: M9 flagged `Dashboard.tsx:16` (`localStorage.getItem("role")` — the admin-authz line) as SSR misuse (Low). Right line, wrong mechanism (perf/SSR, not authz). No detector models "authorization decided from `localStorage.role`." |
| 6 | **CAUGHT** | M1 static | `harvey-dangerously-set-inner-html` (High) at `src/pages/Dashboard.tsx:61`: "A request-controlled value reaches dangerouslySetInnerHTML unsanitized — reflected/stored XSS." Clean catch, correct mechanism. |
| 7 | **MISSED — N/A-tier** | — | No prompt-injection detector exists (grep `src/scan`,`src/detectors` for prompt-injection/LLM-sink = none). Prompt injection + input-validation-of-LLM-input is an LLM-semantic class (Harvey's paid M1 semantic pass), not modelable on the static mechanical tier. Not a mechanical-tier gap. |
| 8 | **PARTIAL — half caught (M10), half N/A** | M10 | `pii-classify --schema` flagged `workspaces → Medium (3.6): PAYMENT_REF` — the `stripe_customer_id` billing secret, corroborating the "billing secret in a public table" half. The "public-readable" half rides on #3 (RLS, missed on this layout); the "no rate limit on the AI call" half is a browser-direct OpenAI call with no server route to gate — inherently dynamic/server, N/A on a static SPA. |

**Tally: 1 caught / 8 (12.5%)** modeled-as-the-bug, plus **3 partial** (#4, #5 right-line-wrong-
mechanism; #8 billing-secret half via M10) and **4 missed**. Of the 4 missed, **3 are genuine
static-tier gaps** (#1, #2, #3 — classes Harvey's static tier can and should catch, blocked by
Next.js-coupled rule shapes / a too-narrow schema-discovery path) and **1 is N/A-tier** (#7, an
LLM-semantic class with no mechanical detector). If line-level surfacing is credited generously,
the XSS (#6) plus the three partials means **4/8 were touched in some form**; only #6 was modeled
correctly as the security bug it is.

By tier:
- **M1 static mechanical (semgrep):** caught #6. Missed #1, #2, #3 — all three are **Vite/no-code
  shape gaps**, not absence of the capability (the same detectors fire on Next.js + `supabase/
  migrations` targets, e.g. vandyand).
- **M9 AST (N/A-tier):** 2 findings, both false-premise on a Vite SPA (no SSR render path); they
  happen to land on the #4/#5 lines but by a perf/hydration mechanism, not security.
- **M7 code:** unbounded `select("*")` (Perf, near #3's over-fetch line) and a hook-deps note — real
  quality signals, not security.
- **M10 schema:** caught the data-classification behind #8 (`workspaces → PAYMENT_REF`).
- **M2 dynamic / connected:** out of scope (this target is not stand-up-able as a `supabase
  migrations` app; no live client DB). #7 and the enforcement half of #4/#5 would need the
  semantic-LLM or dynamic tiers.

## Why this scores far below the vandyand teardown (6/8 there, 1/8 here)

The gap is **structural, not a regression**. The vandyand teardown is a **Next.js app with a
`supabase/migrations/` tree** — exactly the shape Harvey's static M1 detectors are written against
(`"use client"` boundaries, `process.env.*` secrets, migration-file RLS discovery). nocode-rescue's
`before/` is a **Vite/React SPA export** with a root `schema.sql`, `import.meta.env.VITE_*` env,
hardcoded key literals, and no server boundary. Most of Harvey's static security rules key off
Next.js-specific structure and simply do not match this shape. **This is the single most important
finding of this measurement:** Harvey's static M1 tier is Next.js-coupled and materially
under-detects on Vite/no-code exports — which are a *core* target for the product's "rescue a
no-code export" positioning (the very premise of this test repo).

## Harvey findings NOT in the answer key

All are legitimate (no false positives against the app's real behavior) except the 2× M9 noted:
- `SUP-NO-LOCKFILE` (Medium) — real: `before/` ships no lockfile.
- `SEC-TH-GH-00` (Info) — coverage-disclosure note: the git-history secret scan (TruffleHog
  git mode) did not run on the scoped copy. A coverage disclosure, not a vuln — the fail-loud tier
  working as intended.
- M7 `Unbounded select("*")` (Perf, `Dashboard.tsx:26`) — real perf note on the "pull every ticket"
  line (adjacent to #3's cross-tenant over-fetch, different class).
- M7 missing-hook-deps (Info, `Dashboard.tsx:21`) — real quality note.
- M10 `profiles → Low (1): EMAIL` — real PII, adjacent to the key.
- **2× M9 `localStorage read on the SSR render path` (Low) — FALSE PREMISE on a Vite SPA:** there is
  no SSR render path in a Vite single-page app, so the stated mechanism does not apply. They land on
  the genuinely-vulnerable #4/#5 lines but for the wrong reason. An FP class worth noting for any
  Vite target (the M9 detectors assume Next.js SSR).

## Gaps to fix (filed as a follow-up)

Filed **jharvieux/Harvey#565** — "Static M1 is Next.js-coupled; under-detects Vite/no-code
exports (nocode-rescue: 1/8 static)". Three concrete detector fixes, all proven missed above:

1. **#3 — RLS static pass ignores a root `schema.sql`.** `checkMigrationRlsStatic` (and the
   companion policy/PII schema readers in `src/scan/supabase-static.ts`) only glob
   `<dir>/supabase/migrations/*.sql`. A no-code Table-Editor export commits a single root
   `schema.sql`; broaden discovery to also pick up `schema.sql` / `**/*.sql` at the repo root.
   **Highest value** — the detector already exists, it just isn't pointed at the file.
2. **#1 — `harvey-service-role-in-client` is Next.js-coupled.** It requires
   `process.env.SUPABASE_SERVICE_ROLE_KEY` inside `"use client"`. Add a variant that fires on a
   service-role JWT literal / `import.meta.env.VITE_*SERVICE_ROLE*` passed to `createClient(...)` in
   any browser-reachable module (Vite has no `"use client"` marker — the whole SPA is the client).
3. **#2 — no `dangerouslyAllowBrowser` / browser-LLM-key detector.** Add a rule for
   `new OpenAI({ …, dangerouslyAllowBrowser: true })` and for an LLM/API key sourced from
   `import.meta.env.VITE_*` reaching a client module — the canonical no-code "the AI key is in the
   bundle" footgun (#2 here). No detector references `dangerouslyAllowBrowser` today.

Not filed (correctly out of static scope): #7 (prompt injection — LLM-semantic tier) and the
rate-limit/enforcement halves of #4/#5/#8 (dynamic/server tier), owned by the M1-semantic and M2
lanes respectively.

## Notes on tier scope (verified, not recalled)

- The static RLS pass reads only `<dir>/supabase/migrations/*.sql` — confirmed by reading
  `src/scan/supabase-static.ts` (`migrationsDir = join(dir,"supabase","migrations")`;
  `if (!existsSync(migrationsDir)) return []`). On this target that directory does not exist.
- `pii-classify --schema` accepts a single `.sql` file directly (not only a directory) and parsed
  16 columns from `before/schema.sql`, classifying 2.
- No M2 dynamic or connected-tier run was performed (target not stand-up-able as a migrations app;
  no client DB). That is a scope boundary of this measurement, not a Harvey capability claim.

---

## RE-SCORE — 2026-07-18 (full THREE-TIER, after the Vite/no-code coverage campaign)

**Why:** the 1/8 above was **static-only, pre-Vite-fixes**. Since then the Vite/no-code campaign
merged — root-schema RLS discovery (#565), the Vite service-role + `dangerouslyAllowBrowser`
detectors (#565/#589), the client-trust-boundary authz detector (#576), and autonomous root-schema
M2 stand-up (#574/#590/#609). This re-score runs **all three tiers** (mechanical + semantic + live
dynamic) against the same `before/` code, the way the SuperRedHat/cipherx re-scores validated the
App-Router campaign. Every status below is grounded in a run observed on this date; no Harvey source
was changed. Target re-cloned to `/private/tmp`, deleted after; the M2 stack self-isolated
(project-id `harvey-dv-5cba2f2fe8`, ports 56091/56092) and was torn down (scoped teardown, #604/#609).

### How each tier was run (this re-score)

- **Mechanical:** `pnpm quick-scan --dir before` (semgrep + gitleaks + trufflehog + osv-scanner, all
  four binaries present) + `pnpm detect-static before` (M6/M7/M8/M9) + `pnpm pii-classify --schema
  before/schema.sql` (M10).
- **Semantic (LLM):** rigorous manual security review of the five `before/` source files, guided by
  `briefs/scan-extras.txt`, triaged by `briefs/fp-rules.txt`. All eight planted findings are genuine,
  real, FP-clean bugs — a competent manual pass catches every one.
- **Dynamic (M2):** `pnpm dynamic-validate before --execute`. Verdict **GO (postgrest-only)** — the
  root `schema.sql` is applied directly to a local Supabase (#574), two tenants + auth users are
  seeded, and the live PostgREST cross-tenant matrix runs. The app isn't runnable (no dev/build/start
  script, no server routes), so the app-route/seam probe tier is honestly skipped; the PostgREST RLS
  matrix still runs. **12 live findings.**

### Score — 8 / 8 caught across the three tiers (was 1/8 static-only)

| # | Finding | Mechanical | Semantic | Dynamic | Overall |
|---|---------|-----------|----------|---------|---------|
| 1 | `service_role` key in browser client | **miss** (see gap A) | **CAUGHT** | n/a (SPA, no server tier) | **CAUGHT** |
| 2 | OpenAI key via `VITE_*` + `dangerouslyAllowBrowser` | **CAUGHT** `harvey-dangerously-allow-browser` (High) @ `ai.ts:8` | **CAUGHT** | n/a | **CAUGHT** |
| 3 | No RLS on `tickets`/`profiles`/`workspaces` | **miss** (see gap B) | **CAUGHT** | **CAUGHT** — live | **CAUGHT** |
| 4 | Client-only auth (`if(!user) navigate`) | partial (M9 lands on line 14, wrong mechanism) | **CAUGHT** | corroborated (data layer open, proven live) | **CAUGHT** |
| 5 | Client-side authz (`localStorage.role==='admin'`) | **CAUGHT** `AUTH-client-side-authz` (High, #576) @ `Dashboard.tsx` | **CAUGHT** | corroborated | **CAUGHT** |
| 6 | Stored XSS (`dangerouslySetInnerHTML`) | **CAUGHT** `harvey-dangerously-set-inner-html` (High) @ `Dashboard.tsx:61` | **CAUGHT** | n/a | **CAUGHT** |
| 7 | Prompt injection + no input validation | n/a-tier (no mechanical detector — LLM-semantic class) | **CAUGHT** | n/a | **CAUGHT** |
| 8 | No rate limit on AI call + billing secret in public table | partial — M10 caught the billing half (`workspaces → Medium 3.6 PAYMENT_REF`) | **CAUGHT** | billing-half corroborated (RLS-off proven live); rate-limit half is browser-direct, no server to gate | **CAUGHT** |

**Tally: 8/8 caught (three-tier).** Per tier: **mechanical** caught #2, #5, #6 fully + the M10 half
of #8 (3/8 fully, up from 1/8); **semantic** carried **8/8**; **dynamic** independently proved #3
(and corroborated #4/#5/#8) with 12 live cross-tenant findings.

### vs the prior 1/8 — which #565/#576 gaps closed

The prior measurement named **3 genuine static gaps** (#565) plus the client-authz addition (#576):

- **#565 gap for #2 — `dangerouslyAllowBrowser` / browser-LLM key: CLOSED.** `harvey-dangerously-
  allow-browser` now fires (High) on `ai.ts:8`. Full mechanical catch.
- **#576 — client-side authz: CLOSED.** `AUTH-client-side-authz` fires (High) on `Dashboard.tsx`
  for the `localStorage.getItem("role") === "admin"` gate. #5 goes partial→full mechanically.
- **#565 gap for #1 — Vite service-role: PARTIALLY closed.** `harvey-vite-service-role-in-client`
  landed for the `import.meta.env.VITE_*SERVICE_ROLE*` shape, but **this** target hardcodes the key
  as a JWT **literal** passed to `createClient(URL, SUPABASE_SERVICE_ROLE, …)` (the `.env` holds the
  `VITE_` var; the client module inlines a literal). The literal→`createClient` variant the prior
  doc proposed did **not** land, so #1 still misses mechanically → **residual gap A** below.
- **#565 gap for #3 — root-schema RLS: PARTIALLY closed.** `readRlsSqlSources` now discovers the
  root `schema.sql` (#565), but the `CREATE_TABLE`/`ENABLE_RLS` regexes require a **`public.`-
  qualified** table name, and a no-code Table-Editor export emits **bare** `create table workspaces`
  (public is the default schema, left implicit). So the file is read but zero tables are enumerated
  → still no RLS-off finding → **residual gap B** below. (The dynamic tier now catches this class
  live, and semantic catches it on read — but the cheap mechanical catch is still blocked.)

Net: of the campaign's targeted classes, **#2 and #5 are fully closed mechanically**; **#1 and #3
are closed on the semantic + dynamic tiers** but retain narrower mechanical residuals (A, B) exposed
only by re-running *this exact* target shape.

### Mechanizable residuals filed (semantic/dynamic-caught, cheaply mechanizable)

Filed **jharvieux/Harvey#611** (two concrete detector fixes; dedup-checked vs #565/#576/#578/#601/
#602 — neither is covered: #578 is built-bundle/CORS/headers/open-signup, #601/#602 are cipherx
App-Router/migration-SQLi):

- **Gap A — service-role JWT literal → `createClient`.** Extend the service-role-in-client detection
  to fire on a service-role-named identifier/JWT literal passed as the key argument to
  `createClient(url, <service-role>, …)` in a browser-reachable module, independent of whether the
  value arrives via `import.meta.env`. Proven missed on `before/src/lib/supabaseClient.ts:20`.
- **Gap B — unqualified `create table` in the static RLS pass.** Broaden `CREATE_TABLE` (and
  `ENABLE_RLS`) in `src/scan/supabase-static.ts` to accept an optional `public.` qualifier so the
  bare `create table workspaces` DDL that no-code Table-Editor exports emit is enumerated. The root
  `schema.sql` is already discovered; the regex coupling is the only thing blocking the RLS-off
  catch. Proven missed on `before/schema.sql`.

Not filed (correctly out of mechanical scope): **#7** (prompt injection — LLM-semantic tier, caught
by the semantic pass, no cheap mechanical model) and the rate-limit enforcement half of **#8**
(needs a server route to gate; the SPA calls OpenAI browser-direct).

### Notes (verified this run, not recalled)

- **Dynamic evidence for #3:** the M2 pass emitted 12 findings — cross-tenant/anon **reads** of
  `profiles` and `tickets` for every persona (anon / Tenant A / Tenant B / Admin) and **Critical
  unauthorized POSTs** accepted on `tickets` — a live demonstration that RLS is off and the anon key
  reaches every tenant's rows (`M2.pass.json`).
- **M9 SSR false-premise persists here:** `detect-static` still emits 2× "SSR-only API misuse" (Low)
  on `Dashboard.tsx:14/16`. The Vite/SPA SSR-suppression (#573/#575/#582/#605) keys off a detected
  Vite framework, but this bare `before/` export ships **no `package.json`**, so the framework probe
  returns `other` and the suppression does not engage. Same false-premise as the prior measurement
  (right lines #4/#5, wrong mechanism) — an FP note, not a security catch, and not counted as one.
- **#1's env-declared service role** surfaces only as a coverage note (`SEC-BUNDLE-00`, Info: "run a
  production build so client-inlined secrets can be scanned") — the built-bundle secret pass (#578)
  needs a `dist/` build, absent on this source-only export. The fail-loud coverage tier working as
  intended, not a finding.
