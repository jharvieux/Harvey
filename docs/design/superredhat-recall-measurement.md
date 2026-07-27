# Harvey recall measurement — SuperRedHat/secure-code-review-demo

**Date:** 2026-07-18
**Target:** `SuperRedHat/secure-code-review-demo` ("NoteVault"), a deliberately-vulnerable
multi-tenant Supabase/Next.js (App Router) notes app. Cloned to `/private/tmp` (ephemeral,
deleted after).
**Answer key:** the repo's `report/REMEDIATION-REPORT.md` enumerates **12 findings (F-01..F-12)**
with file:line, OWASP-2021, CWE, and CVSS vectors. The authoritative fix-for-fix key is the
`vulnerable → hardened` branch diff — **one fix commit per finding** (`git log origin/vulnerable..origin/hardened`),
confirmed on this date. The report itself flags **F-03, F-04, F-11** as **manual / scanner-invisible**
access-control findings ("a scanner sees syntactically valid code and cannot know an ownership
predicate is missing") — those especially test Harvey's dynamic M2 tier.

This is a MEASUREMENT — every caught/missed below is grounded in a Harvey run's actual output
observed on this date, not recall. No Harvey source was changed.

---

# 2026-07-18 RE-SCORE — full three tiers incl. the SEMANTIC (LLM) tier

**This section supersedes the 6/12 body below.** The original measurement scored only the mechanical
and dynamic tiers and predated the Vite / App-Router coverage campaign. This re-score runs **all three
tiers** — mechanical, **semantic (the paid M1 LLM review, absent from the prior score)**, and dynamic
— against the `vulnerable` branch after pulling the merged detectors (#571, #578, #590, #592, #593).
Isolated Docker (`project_id srh-rescore`, DB ports 65360-65366, app 65367); stack torn down (Docker
`ps -aq` = 0) after. Grounded in real runs; no Harvey source changed.

## New tally: 12 caught / 12 (100%) — up from 6/12

| Tier | Findings it caught | vs prior |
|------|--------------------|----------|
| **Mechanical** (`quick-scan` + `detect-static` + `pii-classify --schema`) | **11** — F-01,02,03,04,05,06,07,08,09(1 of 3 facets),10,12. Miss: **F-11** (no static CSRF/rate-limit detector). | 6 → 11 |
| **Semantic (LLM)** (manual `/vuln-scan`-style review of source, triaged vs `fp-rules.txt`) | **12** — all findings incl. all 3 facets of F-09; independently confirms the manual F-03/F-04/F-11. | new tier |
| **Dynamic (M2)** (`dynamic-validate --execute`, autonomous stand-up) | **4 proven live** — F-02, F-03, F-04, F-11. | 0 → 4 |
| **Union (a finding = caught if any tier caught it)** | **12 / 12** | 6 → 12 |

**What changed the result vs the old 6/12:**
- **Mechanical 6 → 11.** The App-Router taint detectors that were dark in the prior run all fired on
  the exact planted lines: `harvey-idor-param` ×3 (F-03), `harvey-mass-assignment` ×2 (F-07),
  `harvey-ssrf-fetch` ×2 (F-05), `harvey-template-injection` (F-12 SSTI facet), `harvey-permissive-cors`
  on the object-literal wildcard (F-10), and `harvey-authed-no-role-check` (F-04, now the correct
  mechanism, not the old filename heuristic). The Express-vs-App-Router "systematic gap" the prior
  section blamed for F-03/F-05/F-07/F-10/F-12-SSTI is **closed** for this target.
- **Dynamic 0 → 4.** M2 now models this target's shape: per-user `owner_id` seed (2 scoped tables) and
  **custom HS256 auth — it discovered the signing secret in source and minted an app session** (#571),
  so the authenticated app-route probes reached the real paths. Proven live: 8× cross-tenant/anon
  PostgREST reads on `notes` + `api_tokens` (**F-02**), `M2-APP-IDOR-OBJECT` on `/api/notes/<id>`
  (**F-03**), `M2-APP-BFLA-ADMIN` on `/api/admin/users` (**F-04**), `M2-APP-CSRF` on `/api/notes`
  (**F-11**). (MASS-ASSIGNMENT and NO-RATE-LIMIT probes ran but were not proven live here — F-07 is
  covered mechanically; the rate-limit facet of F-11 is tracked by #159. Reported, not skipped.)
- **Semantic is what carries F-11 and completes F-09.** F-11 has no static detector at all — only the
  semantic review and the M2 CSRF probe catch it. F-09's two mechanically-missed facets (sign-side
  **no `expiresIn`** at `jwt.ts:17`, hardcoded fallback secret `"notevault-dev-secret"` at `jwt.ts:6`)
  are caught **only** by the semantic tier; mechanical got just the unpinned-algorithm facet.

## Per-finding re-score (2026-07-18)

| # | Status | Tier(s) | Evidence (from this date's runs) |
|---|--------|---------|-----------------------------------|
| F-01 | **CAUGHT** | mechanical; semantic | `[Critical] Committed credential` (`supabase-service-role-jwt`, decoded `role:service_role`) + `[High] jwt` at `lib/supabaseAdmin.ts:15`. Semantic also flags the `NEXT_PUBLIC_`-prefixed service-role key as browser-bundled. |
| F-02 | **CAUGHT** | mechanical; **dynamic**; semantic | Mechanical: 4× `[Critical] Migration table without RLS (static)` at `0001_init.sql:4,13,22,28`. Dynamic: 8× `M2-EXPLORE` cross-tenant/**anon** reads of `notes` + `api_tokens` via PostgREST — the RLS-off leak proven live. |
| F-03 | **CAUGHT** | mechanical; **dynamic**; semantic | Mechanical: `harvey-idor-param` at `notes/[id]/route.ts:15,30,42` (GET/PATCH/DELETE by id, no owner predicate). Dynamic: `M2-APP-IDOR-OBJECT` proven at `/api/notes/<uuid>`. **(was MISS)** |
| F-04 | **CAUGHT** | mechanical; **dynamic**; semantic | Mechanical: `[High] harvey-authed-no-role-check` at `admin/users/route.ts:7` + `[High] Client-side authorization decision` at `admin/page.tsx`. Dynamic: `M2-APP-BFLA-ADMIN` proven at `/api/admin/users`. **(was PARTIAL — now correct mechanism)** |
| F-05 | **CAUGHT** | mechanical; semantic | 2× `harvey-ssrf-fetch` at `avatar/route.ts:7` + `import/route.ts:15` (cross-file taint into `fetchRemote` now traced). **(was MISS)** |
| F-06 | **CAUGHT** | mechanical; semantic | `harvey-dangerously-set-inner-html` + `-stored` at `notes/[id]/page.tsx:21`. |
| F-07 | **CAUGHT** | mechanical; semantic | 2× `harvey-mass-assignment` at `notes/route.ts:29` + `notes/[id]/route.ts:29` (`insert/update({ ...body })` from `await req.json()`). **(was MISS)** |
| F-08 | **CAUGHT** | mechanical; semantic | `harvey-insecure-random-token` at `tokens.ts:12` (`Math.random`) + `harvey-weak-hash-security` at `tokens.ts:19` (MD5 of an API token). |
| F-09 | **CAUGHT** (mechanical 1/3 facets; semantic 3/3) | mechanical; **semantic** | Mechanical: `[High] harvey-jwt-verify-noalg` at `jwt.ts:23` (unpinned alg). Semantic adds the two mechanically-dark facets: no `expiresIn` at `jwt.sign` (`jwt.ts:17`) + hardcoded fallback secret `"notevault-dev-secret"` (`jwt.ts:6`). Mechanizable → **#595**. |
| F-10 | **CAUGHT** | mechanical; semantic | `harvey-permissive-cors` at `lib/cors.ts:3` — the object-literal wildcard `Access-Control-Allow-Origin:"*"` now matched. **(was MISS)** |
| F-11 | **CAUGHT** | **dynamic**; **semantic** (mechanical MISS) | Dynamic: `M2-APP-CSRF` proven at `/api/notes` (cross-origin state-changing request accepted). Semantic: no CSRF/same-origin guard + no rate limiting on mutating/auth routes. No static detector fired — mechanical still misses this outright. **(was MISS)** |
| F-12 | **CAUGHT** (both facets) | mechanical; semantic | Dep facet: `[Medium] Known-vulnerable dependency ejs@3.1.6` (2 OSV hits incl. the template-injection advisory). SSTI facet: `[High] harvey-template-injection` at `render/route.ts:8` (`ejs.render(await req.json().template)`). **(SSTI facet was MISS)** |

## Semantic tier — findings it caught that mechanical missed

- **F-11** (CSRF / no rate limiting): no static detector exists; semantic and the M2 CSRF probe are the
  only tiers that catch it. **Not cleanly static-mechanizable** — CSRF here is a Bearer-auth caveat and
  rate-limit is an absence-of-control best proven dynamically (already tracked by #159); left to M2 +
  #159 rather than a noisy static rule.
- **F-09 facets** (no `expiresIn`, hardcoded Node secret fallback): semantic-only, and **both are
  structurally mechanizable** — filed as **#595** (`harvey-jwt-sign-noexpiry` + `harvey-node-secret-fallback`).

## Guard / isolation notes (fail-loud)

Docker was isolated to `project_id srh-rescore` on ports 65360-65367 and fully torn down after the run
(`docker ps -aq` = 0, no residual `srh` volumes). M2 recorded its one limitation in-output (per-user
offline plan → seed applied live with the two real user ids); the MASS-ASSIGNMENT / NO-RATE-LIMIT
probes ran and are reported as *not proven live here* rather than silently dropped.

---

## How Harvey was run

- **M1 static (mechanical):** `pnpm quick-scan --dir <target> --findings-out <f>` — 45 raw findings
  (semgrep `harvey-*` + gitleaks + osv-scanner + the static Supabase/RLS migration pass).
- **M1 static (schema/RLS):** the migration-RLS pass inside quick-scan (4× "Migration table without RLS").
- **M2 dynamic (autonomous):** `pnpm dynamic-validate <target> --execute --out <dir>` — stood up a
  local Supabase (`supabase start`, default ports; no sibling stack present), applied the client
  migration, attempted the two-tenant seed + two auth users, ran the live PostgREST cross-tenant
  matrix (Tier 1), then `npm install && npm run build && npm run start` + the app-route/seam probes
  (Tier 2). Stack torn down (`supabase stop --no-backup`) after. **See the M2 section for what the
  stand-up could and could not reach on this target.**
- **M9/M7:** `pnpm detect-static <target>` — App Router / performance AST detectors.
- **M10:** `pnpm pii-classify --schema <target>/supabase/migrations`.

## The answer key (12 findings)

| # | Finding | Class | Location (vulnerable) | Manual? |
|---|---------|-------|------------------------|---------|
| F-01 | Hardcoded Supabase service-role key in source | Secret exposure / full RLS bypass (CWE-798) | `lib/supabaseAdmin.ts:13-16` | |
| F-02 | RLS disabled on every table | Broken tenant isolation (CWE-285/639) | `supabase/migrations/0001_init.sql:38-41` | |
| F-03 | IDOR — notes read/written by id, no ownership check | Broken object-level authz (CWE-639) | `app/api/notes/[id]/route.ts:15,30,42` | **manual** |
| F-04 | Admin authz enforced in the UI only | Broken function-level authz (CWE-602/285) | `app/api/admin/users/route.ts:13` | **manual** |
| F-05 | SSRF in avatar proxy / URL import | SSRF (CWE-918) | `lib/fetchUrl.ts:7` (via avatar + import routes) | |
| F-06 | Stored XSS via `dangerouslySetInnerHTML` | Injection / XSS (CWE-79) | `app/notes/[id]/page.tsx:21` | |
| F-07 | Mass assignment / over-posting on note writes | Broken access control (CWE-915) | `app/api/notes/route.ts:29`, `app/api/notes/[id]/route.ts:29` | |
| F-08 | Weak randomness (`Math.random`) + MD5 for API tokens | Cryptographic failure (CWE-330/327) | `lib/tokens.ts:12,19` | |
| F-09 | Insecure JWT: no expiry, unpinned alg, hardcoded secret | Auth / crypto (CWE-347/798) | `lib/jwt.ts:6,17` | |
| F-10 | Wildcard CORS on the authenticated API | Security misconfig (CWE-942) | `lib/cors.ts:4` | |
| F-11 | No CSRF protection / no rate limiting | CSRF + brute force (CWE-352/307) | `app/api/notes/*`, `app/api/import/route.ts` | **manual** |
| F-12 | Vulnerable dependency `ejs@3.1.6` + SSTI render endpoint | Vulnerable component + SSTI/RCE (CWE-1395) | `package.json`; `app/api/render/route.ts:8` | |

## Score — 6 caught / 12, +1 partial, 5 missed

| # | Status | By module | Evidence |
|---|--------|-----------|----------|
| F-01 | **CAUGHT** | M1 static (secret scan) | Two gitleaks hits at `lib/supabaseAdmin.ts:15`: `[Critical] Committed credential` (rule `supabase-service-role-jwt`, evidence `"role":"service_role"`) + `[High] Possible committed credential` (rule `jwt`). Exact file/line of the hardcoded key. |
| F-02 | **CAUGHT** | M1 static (RLS migration pass) | 4× `[Critical] Migration table without RLS (static)` on `public.profiles/notes/shares/api_tokens` (`0001_init.sql:4,13,22,28`): "create table … has no matching alter table … enable row level security anywhere in supabase/migrations/." Matches the `disable row level security` block at 38-41. |
| F-03 | **MISS** | — (M2 could not prove) | Static: Harvey HAS `harvey-idor-param` (auth.yml), but it did not fire. Its taint **sources are Express-shaped** (`req.query`/`req.params`); this App Router handler reads the id from the `{ params }` function argument (`params.id`) — an unrecognized source shape. M2 could not prove it either (see M2 section). See "Systematic gap." |
| F-04 | **PARTIAL** | M1 static (filename heuristic, wrong premise) | `[High] Unauthenticated debug/admin route` on `app/api/admin/users/route.ts` — evidence: "Route path matches /debug\|seed\|admin/ and no auth-check call pattern was found in the file." It lands on the exact vulnerable file, **but by a filename heuristic with a FALSE premise**: the route *does* call `getUser(req)` and 401s — the real bug is authenticated-but-no-server-side-**role**-check (broken function-level authz). Right file, wrong mechanism → partial. (Same class as vandyand #5; root cause is #561 + #562: `getUser` not recognized, no function-level-authz model.) |
| F-05 | **MISS** | — | `harvey-ssrf-fetch` (base.yml) exists but did not fire. The sink `fetch($URL)` lives in a **separate helper** (`lib/fetchUrl.ts`), while the request-controlled URL enters in the routes (`new URL(req.url).searchParams.get("url")` in avatar; `await req.json()` in import) — cross-file taint the rule can't span, and neither entry shape is one of its Express-style sources. No M2 SSRF probe in the app-route set. |
| F-06 | **CAUGHT** | M1 static | `[High] harvey-dangerously-set-inner-html` + `[High] harvey-dangerously-set-inner-html-stored`, both `app/notes/[id]/page.tsx:21` — reflected + stored XSS at the exact sink. |
| F-07 | **MISS** | — (M2 could not prove) | Static: Harvey HAS `harvey-mass-assignment` (auth.yml) with sink `insert({ ...$BODY })` / `update({ ...$BODY })` — which structurally matches `insert({ ...body, owner_id })` and `update({ ...body })` here. It did NOT fire because its **taint source is `req.body`** (Express); the body comes from `await req.json()` (App Router), so the source→sink taint never connects. M2's `MASS-ASSIGNMENT` probe did not prove it (see M2 section). See "Systematic gap." (`harvey-route-noauth` fired on `app/api/notes/route.ts:20` but with a false "no auth" premise — the POST does call `getUser`.) |
| F-08 | **CAUGHT** | M1 static | `[Medium] harvey-insecure-random-token` at `lib/tokens.ts:12` (`Math.random()` for a token) + `[High] harvey-weak-hash-security` at `lib/tokens.ts:19` (MD5). Both facets, exact lines. |
| F-09 | **CAUGHT (1 of 3 facets)** | M1 static | `[High] harvey-jwt-verify-noalg` at `lib/jwt.ts:23` catches the **unpinned-algorithm** facet (one of F-09's three named defects). The **no-expiry** facet and the **hardcoded fallback secret** (`"notevault-dev-secret"`, `lib/jwt.ts:6`) were NOT caught — gitleaks did not match the dev-secret string, and no rule models a missing `expiresIn`. Right file, partial facet coverage. |
| F-10 | **MISS** | — | `harvey-permissive-cors` (base.yml) exists but only matches `$RES.setHeader("Access-Control-Allow-Origin","*")` / `$RES.headers.set(...)`. The target declares the wildcard as an **object literal** (`const CORS_HEADERS = { "Access-Control-Allow-Origin": "*", ... }`) passed to `NextResponse.json(..., { headers })` — the App Router idiom the pattern doesn't match. |
| F-11 | **MISS** | — (M2 could not prove) | No static CSRF / rate-limit detector. The app-route probe set includes a `NO-RATE-LIMIT` id, but M2's Tier 2 probes could not exercise this target (see M2 section) — 0 proven. |
| F-12 | **CAUGHT (dep facet); SSTI facet MISS** | M1 static (osv-scanner) | `[Medium] Known-vulnerable dependency` on `ejs@3.1.6` fired twice, incl. the exact SSTI advisory **GHSA-phwq-j96m-2c2q (CVE-2022-29078)** the report cites, plus CVE-2024-33883. The **vulnerable-component facet (F-12's primary A06 classification) is caught.** The **SSTI code path** (`ejs.render(String(template ?? ""), …)`, `app/api/render/route.ts:8`) was NOT: `harvey-template-injection` exists with sink `ejs.render($X, …)` but its sources are `req.query/req.body/req.params/nextUrl.searchParams` — the template comes from `await req.json()`, so no taint. |

**Tally: 6 caught / 12 (50%)**, +1 partial (F-04), 5 missed (F-03, F-05, F-07, F-10, F-11) — tier split below after the M2 section. (Facet note: F-09 is credited on 1 of its 3 named facets — unpinned algorithm; F-12 is credited on its vulnerable-component facet, not the SSTI code path.)

## M2 dynamic — what the autonomous stand-up reached on this target

**Result: M2 produced 0 findings** (grounded in the run's own `run.log`: "dynamic validation ran
(full) … findings: 0", `M2.pass.json` summary "dynamic validation (full coverage); 0 finding(s)").
The stand-up itself succeeded — Supabase started, the migration applied, the app built and booted
at `127.0.0.1:3000` — but two structural mismatches made every probe dark, and the tool recorded
both as loud in-output limitations rather than skipping:

1. **This app is per-USER (`owner_id`), not per-ORG-tenant.** M2's two-tenant seed only recognizes
   org-style scope columns (`tenant_id/org_id/organization_id/workspace_id/account_id/company_id/team_id`).
   The schema keys everything by `owner_id` (a FK to `profiles.id`, i.e. a user), so the seed found
   **0 scoped tables** and created no cross-tenant rows. The Tier-1 live PostgREST cross-tenant matrix
   therefore had nothing to leak (`explore.json` = `[]`), even though RLS is genuinely off (F-02). The
   RLS-off condition that F-02 describes is real and *would* leak, but M2's isolation model is org-tenant
   shaped and never seeded a second principal's rows into any table.
2. **This app uses a custom HS256 JWT, not Supabase Auth.** `lib/session.ts::getUser` verifies the
   app's own token (`lib/jwt.ts`, secret `"notevault-dev-secret"`). M2's app-route probes authenticate
   by minting a **Supabase-issued ES256 session token** (`/auth/v1/token`), which `getUser` rejects →
   every authenticated route 401s. So the Tier-2 `IDOR-OBJECT`, `MASS-ASSIGNMENT`, and `NO-RATE-LIMIT`
   probes (the ones that would target F-03/F-07/F-11) could not reach the vulnerable authenticated
   paths. My run's Tier-2 verify temp dir was created but wrote no `verify.json` (0 proven). Separately,
   the `MASS-ASSIGNMENT` probe is hard-wired to `PATCH /api/profile`, a route this target doesn't have.

Neither mismatch is a bug in the target — both were shapes M2 didn't yet model **on 2026-07-16**.
**This is now false — see the 2026-07-18 re-score at the top of this doc.** After #571 (per-user
`owner_id` seed + custom-auth app-session minting), #590 (root-schema stand-up + BFLA), and #593
(IDOR-object + CSRF probes), M2 stands up on this exact per-user + custom-auth App Router app **and
proves 4 findings live** (8 cross-tenant PostgREST reads + IDOR-OBJECT + BFLA-ADMIN + CSRF). The
original "stands up cleanly and proves nothing" claim below was true only for the 2026-07-16 code and
must not be quoted as current. (Contrast vandyand, an org-tenant Supabase-Auth app, where the same M2
pipeline proved 2 findings live.)

## Tally by tier

- **M1 static** caught **6**: F-01 (secret scan), F-02 (RLS migration pass), F-06 (XSS sink),
  F-08 (crypto primitives), F-09 (unpinned-alg facet), F-12 (vulnerable-dep facet). It **partially**
  flagged F-04 (filename heuristic, false "unauthenticated" premise).
- **M2 dynamic** proved **0** — structurally blind here (per-user data model + custom auth, above).
- **M10** corroborated the PII sensitivity (`profiles → EMAIL/NAME/PHOTO`) behind F-02/F-03/F-04.
- **Missed outright: 5** — F-03 (IDOR), F-05 (SSRF), F-07 (mass assignment), F-10 (wildcard CORS),
  F-11 (CSRF/rate-limit). Four of these five are rules that **exist in Harvey but stayed dark on
  App Router request shapes** (see below); **F-11 is the same story, not the exception this line
  used to claim.** *(Corrected 2026-07-25, #1033 sweep: it read "F-11 has no detector at all",
  which is false — `harvey-csrf-missing` (`src/scan/rules/semgrep/headers.yml`) and the rate-limit
  detectors in `src/scan/leftover-auth.ts` both exist. Neither REACHES F-11's shape: the CSRF rule
  matches only a `'use server'` Server Action, and the rate-limit ones only an auth endpoint, while
  F-11 sits on plain App Router route handlers. Falsify the corrected sentence by re-running the
  recall pass over this target, or `grep -n "pattern-inside" src/scan/rules/semgrep/headers.yml`
  to see the Server-Action scope.)*

The corrected F-11 claim, recorded per #1072 with the live-tier falsifier that would retire it:

> REASON: F-11 (CSRF / no rate limiting) is MISSED by the M1 static tier on superredhat — harvey-csrf-missing (src/scan/rules/semgrep/headers.yml) and the rate-limit detectors (src/scan/leftover-auth.ts) both EXIST, but neither REACHES F-11's shape: the CSRF rule matches only a 'use server' Server Action and the rate-limit ones only an auth endpoint, while F-11 sits on plain App Router route handlers
> KIND: empirical
> PROVENANCE: MEASURED 2026-07-25 (#1033 sweep corrected the earlier "no static detector at all"; the two detectors' scope re-read in headers.yml / leftover-auth.ts and confirmed not to reach a plain App Router route handler)
> FALSIFIER: pnpm quick-scan --dir <superredhat-clone> --findings-out /tmp/srh.json && grep -Eiq "csrf|rate.?limit" /tmp/srh.json
> FALSIFIER-TIER: secbench

**Every mechanical detector that does NOT depend on request-taint fired** (secrets, RLS-off migration,
XSS sink, crypto primitives, vulnerable dependencies). **Every rule that depends on tracing tainted
request input** (IDOR, mass-assignment, SSRF, SSTI) **went dark**, because their sources are written
for Express and this is a pure Next.js App Router app. That split — not detector absence — is the story
of this measurement.

## Systematic gap — Harvey's security taint rules assume Express, not the Next.js App Router

This is the dominant reason for the misses (F-03, F-05, F-07, F-12-SSTI) and the F-04 partial. The
rules exist and their **sinks match**, but their **taint sources are Express-shaped** and the
App Router request-access idioms are unrecognized:

| Rule | Sink (matches target) | Sources it recognizes | What this App Router target actually uses |
|------|-----------------------|-----------------------|-------------------------------------------|
| `harvey-idor-param` | `.select(...).eq("id", $ID)` ✓ | `req.query`, `req.params` | `params.id` from the `{ params }` handler arg |
| `harvey-mass-assignment` | `insert({ ...$BODY })` ✓ | `req.body` | `const body = await req.json()` |
| `harvey-ssrf-fetch` | `fetch($URL)` ✓ (in a helper) | `req.query/body/params`, `nextUrl.searchParams` | `new URL(req.url).searchParams` + cross-file helper |
| `harvey-template-injection` | `ejs.render($X)` ✓ | `req.query/body/params`, `nextUrl.searchParams` | `await req.json()` |
| `harvey-permissive-cors` | `res.setHeader(...,"*")` | (n/a — pattern, not taint) | wildcard in an **object literal** → `NextResponse.json(...,{headers})` |
| `harvey-route-noauth` | (mutation w/o recognized auth call) | — | `getUser(req)` custom wrapper → **false "no auth" premise** (#562) |

Next.js App Router handlers read input as `await req.json()`, `new URL(req.url).searchParams`, and
the `{ params }` function argument — none of the Express `req.body/req.query/req.params` shapes. On a
pure App Router codebase, Harvey's object-level-authz, mass-assignment, SSRF, and SSTI-taint rules are
effectively dark, even though each rule's sink is present and correct. This is broader than #562 (which
is only the `harvey-route-noauth` false premise).

## Harvey findings NOT in the answer key

All appear legitimate (real signals against the app's actual behaviour), just outside the planted-12 set:

- **~15 known-vulnerable-dependency findings** on `next@14.2.35` (a stack of 2025/2026 Next.js CVEs)
  plus `@supabase/auth-js`, `glob`, `minimatch`, `postcss` — real OSV matches, not planted.
- **5× `github-actions-mutable-action-tag`** in `.github/workflows/security-audit.yml` (unpinned action tags).
- **`[Medium] Missing security headers`** (`next.config.mjs`) — no CSP / security headers configured.
- **`harvey-missing-server-only`** (`lib/jwt.ts:6`) — server secret module with no `import 'server-only'` guard.
- **M6 indicator** "random-string id" (`lib/tokens.ts:12`), **M7** unbounded-select ×2 + client-fetch-in-useEffect,
  **M9** unsafe/missing cache config — quality/perf signals from `detect-static`.
- **M10** `pii-classify`: `profiles → Medium (1.9): EMAIL, NAME?, PHOTO` — corroborates the sensitivity
  behind the RLS-off / IDOR / admin-list findings (F-02/F-03/F-04).

Near-false-positives (right location, wrong stated reason): `harvey-route-noauth` on
`app/api/import/route.ts:8` and `app/api/notes/route.ts:20` claim "no auth-check call in the function,"
but both routes call `getUser(req)` — the premise is false (tracked as #562). `notes/route.ts` happens
to be F-07's file, but the flag is about auth, not mass assignment.

## Follow-ups filed

- **jharvieux/Harvey#570** (M1) — security taint rules (`harvey-idor-param`, `harvey-mass-assignment`,
  `harvey-ssrf-fetch`, `harvey-template-injection`) + `harvey-permissive-cors` miss Next.js App Router
  request shapes. Root cause of F-03, F-05, F-07, F-10, and the F-12 SSTI facet. The rules exist and
  their sinks match; only the Express-shaped taint sources / setHeader-only CORS pattern block them.
- **jharvieux/Harvey#571** (M2) — the dynamic tier is blind to per-user (`owner_id`) data models
  (the seed only recognizes org-style scope columns) and to custom (non-Supabase) auth (probes mint a
  Supabase session token this app's `getUser` rejects). Why M2 proved 0 here.
- **#561** (commented) — F-04 reproduces the "authenticated but no server-side role check" partial
  (right file, false "unauthenticated" premise).
- **#562** (commented) — `harvey-route-noauth` false-premise firings on `import/route.ts` and
  `notes/route.ts` (both call the custom `getUser` wrapper).

Not separately filed: F-11 (no CSRF / rate-limit static detector at all) and F-09's uncaught facets
(missing `expiresIn`, hardcoded dev secret) — noted here for a future detector-coverage pass.

## Comparison to the vandyand measurement

`docs/design/vandyand-recall-measurement.md` scored 6/8 (75%) on an **org-tenant + Supabase-Auth**
app; this target scored **6/12 (50%)** on a **per-user + custom-auth pure-App-Router** app. The two
targets isolate Harvey's shape assumptions cleanly: the same mechanical detectors (secrets, RLS-off,
XSS, crypto, vuln-deps) caught in both, but here the request-taint authz/injection rules went dark
(App Router sources, #570) and the whole M2 tier went dark (per-user + custom auth, #571). Recall on
this repo is a function of how closely the target matches the org-tenant/Supabase-Auth/Express shapes
Harvey's rules were written against.

