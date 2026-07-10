# Corpus Roadmap — Round 2 (#71 synthesis of the 5-lens research)

Status: planning artifact (2026-07-09) · Issue #71 · Companion to
`docs/design/spec-71-security-corpus.md` (round 1) and `docs/design/scan-coverage-gaps.md`.
**Research/planning only — no fixtures, rules, gate rows, or scanner code changed here.**

## What this is

Round 1 (`spec-71-security-corpus.md`) defined ~100 security classes in 8 batches; batches
**B1–B8 are all built** into `targets/calibration/GROUND-TRUTH.md` +
`src/scan/calibration/*.entries.ts`. The static security corpus today stands at roughly
**24 high-tier (free-count) positives, ~53 review-tier, and ~16 connected-tier** — the ~100-class
round-1 target is essentially met. (The 7 deferred B2 rows — `P-NEXT-EOL`, `N-NEXT-SUPPORTED`,
`P-REACT-DOM-CVE`, `P-DEP-CVE-CRITICAL`, `P-MISSING-LOCKFILE`, `P-KNOWN-IOC-PKG`,
`N-POSTINSTALL-KNOWN` — are landing in a parallel task and are treated as covered here.)

This doc consumes a **second research round** (`scratchpad/candidates.json`: 5 parallel lenses —
OWASP, Next.js surface, framework CVEs, Semgrep registry, Supabase-specific) and does three things:
dedups it, drops what round 1 already covers, and lays out the next build batches.

**Honesty note on "to 100."** The round-1 corpus already reached ~100 *classes*; the free-count
`high` tier is deliberately capped (`mechanical-toolchain.md` §7: a single wrong "Critical" is
credibility-fatal), so the deliverable of round 2 is **breadth** — a modest, genuinely-precise
`high`-tier bump plus a large, correctly-quarantined `review`/`connected`/`dynamic`/`semantic`
backlog for the paid and connected tiers. "Batches to 100" below therefore means *batches to build
this round-2 backlog*, not a race to 100 free-count claims.

## Detection tiers (unchanged from round 1)

- **`high`** — ~100% precise (exact pattern / config parse / version-range / verified secret). Feeds the free "quick scan" count and the A–F grade.
- **`review`** — mechanically *runnable* but heuristic (taint, absence-of-X, name-gated). Scanned, but only asserted in the **paid** report after LLM triage + human sign-off.
- **`connected`** — needs a live Supabase project (Advisor / Management API). N/A on a static run.
- **`dynamic` / `semantic`** — needs a running app (probe) or whole-program/LLM reasoning. Belongs to the M-series paid modules and the #5 pen-test. **Never promoted into the mechanical count.**

## Dedup method

- **Cross-lens merges (5, mandated by the research notes).** Each collapses two lens entries into one class/fixture:
  `next-image remotePatterns SSRF` (owasp + nextjs) · `localStorage auth-token` (owasp + semgrep) ·
  `signed-URL excessive expiry` (owasp + supabase) · `realtime-broadcast no-authz` (owasp + supabase) ·
  `undici SSRF + header-leak` (framework-cves → one undici dep-CVE cluster fixture with two facts).
- **Already-covered → dropped, not deleted silently** (recorded below with the covering id).
- Raw candidates: **85**. After 5 merges: **80**. After dropping 2 already-covered: **78 net-new**
  (1 negative + 18 excluded-tier + **59 new mechanical**).

---

## 1. Already-covered (drop, do not rebuild)

| candidate slug | lens | covered by | note |
|---|---|---|---|
| `react-server-dom-rsc-dos-cluster` | framework-cves | `P-REACT-DOM-CVE` (deferred B2, landing now) | same React2Shell `react-server-dom-*` version chain |
| `next-image-optimizer-content-injection` | framework-cves | `P-NEXT-CVE-CACHE` (B2) | same May-2026 Next advisory batch / OSV hitset |

## 2. Merged clusters (one class each)

| merged class | merged-from (lens) | tier | note |
|---|---|---|---|
| `P-IMG-REMOTEPATTERNS-WILD` | owasp `next-image-ssrf-…` + nextjs `nextjs-image-remotepatterns-wildcard` | high | config-parse of `images.remotePatterns` hostname `**` |
| `P-TOKEN-IN-WEBSTORAGE` | owasp `auth-token-in-web-storage` + semgrep `jwt-token-in-localstorage` | review | name-gated; `csrfToken` in localStorage is the benign lookalike |
| `P-SIGNED-URL-TTL` | owasp `…-excessive-ttl` + supabase `…-excessive-expiry` | high | numeric-literal arg to `createSignedUrl` |
| `P-REALTIME-NO-AUTHZ` | owasp `…-broadcast-no-rls` + supabase `…-broadcast-no-authorization` | connected/semantic | **excluded** — needs live channel/policy state |
| `P-UNDICI-CVE-CLUSTER` | framework-cves `undici-ssrf` + `undici-header-leak` | high | one undici dep-CVE fixture, two CVEs (SSRF + header-leak) |

---

## 3. Deduped master list — new mechanical classes (the round-2 build target)

`action`: **detect** unless marked *suppress* (benign-negative fixture). `[new-scanner]` = needs a
new check; otherwise extends an existing rule file / scanner. Ranked build order is in §5.

### 3a. Secrets & config-secret breadth (extends `secrets.ts` / gitleaks patterns; no new scanner)

| id | class | tier | pos / neg one-liner | lens |
|---|---|---|---|---|
| P-NEXTCONFIG-ENV-SECRET | Secret bundled to client via `next.config.js` `env:{}` field | high | pos: `env:{SUPABASE_SERVICE_ROLE_KEY}` / neg: `env:{APP_VERSION}` | owasp |
| P-SB-DEFAULT-JWT-SECRET | Self-hosted Supabase default `JWT_SECRET` literal | high | pos: `your-super-secret-jwt-token-…` / neg: rotated random | owasp |
| P-NPM-TOKEN-COMMITTED | npm `_authToken` committed in `.npmrc` | high | pos: `_authToken=npm_…` / neg: `${NPM_TOKEN}` | semgrep |
| P-GCP-SA-JSON | Google service-account JSON committed | high | pos: `type:service_account` key file / neg: `.json.example` | semgrep |
| P-SLACK-WEBHOOK-URL | Slack webhook URL committed | high | pos: `hooks.slack.com/services/T…/B…` / neg: placeholder | semgrep |
| P-URI-CREDS-NONPG | `user:pass@` in ftp/http/smtp URI | high | pos: `smtp://user:P@ss@host` / neg: `smtp://user:${env}@` (complements `P-DB-URL-PASSWORD`) | semgrep |
| P-EDGEFN-SECRET | Hardcoded secret fallback in a Supabase Edge Function | high | pos: `Deno.env.get('RESEND_API_KEY') ?? 're_live_…'` / neg: throws, no literal | supabase |
| P-DB-WEBHOOK-SECRET-SQL | Outbound DB-webhook bearer literal in committed SQL | high | pos: `net.http_post` `Authorization Bearer <literal>` / neg: `current_setting(...)` | supabase |
| P-GCP-API-KEY | Google API key (`AIza…`) committed | review | pos: `const KEY='AIza…'` / neg: from `process.env` (verification-gated like other fake keys) | semgrep |
| P-SECRET-IN-URL | API key passed as a URL query param | review | pos: `fetch('…?api_key=${KEY}')` / neg: `Authorization` header | owasp |
| P-SIGNED-URL-TOKEN-SRC | Storage signed-URL token committed in source/docs | review | pos: `…/sign/…?token=eyJ…` / neg: `<SIGNED_URL_TOKEN>` | supabase |
| N-BCRYPT-HASH-SEED *(suppress)* | bcrypt hash in seed/migration = benign | — | neg: `password_hash '$2b$10$…'` must NOT flag (free-count FP guard) | semgrep |

### 3b. Dependency-CVE / framework-version breadth (extends `dependencies.ts` / `checkNextVersionCVEs` / OSV; no new scanner)

| id | class | tier | pos / neg | lens |
|---|---|---|---|---|
| P-NEXT-CVE-NULLORIGIN | Next 16.0.1–16.1.6 Server Actions null-origin CSRF (5th `checkNextVersionCVEs` row) | high | `next@16.0.5` / `16.1.7+` | framework-cves |
| P-JSONWEBTOKEN-CVE | `jsonwebtoken` <9.0.0 in lockfile | high | `8.5.1` / `9.0.2` | framework-cves |
| P-NEXTAUTH-CSRF-CVE | `next-auth` <4.20.1 OAuth CSRF (CVE-2023-27490) | high | `4.19.0` / `4.24.x` | framework-cves |
| P-NEXTAUTH-EMAIL-CVE | `next-auth` email-signin misdelivery (GHSA-5jpx-9hw9-2fx4) | high | `4.24.5` / `4.24.12+` | framework-cves |
| P-FOLLOW-REDIRECTS-CVE | `follow-redirects` header leak (CVE-2024-28849) | high | `1.15.4` / `1.15.6+` | framework-cves |
| P-AXIOS-SSRF-CVE | `axios` <1.8.2 baseURL SSRF (CVE-2025-27152) | high | `1.7.2` / `1.8.2+` | framework-cves |
| P-UNDICI-CVE-CLUSTER | `undici` SSRF + cross-origin header leak (CVE-2022-35949 / 2024-24758) | high | `5.7.0` / `5.28.3+` | framework-cves |
| P-COOKIE-PKG-CVE | `cookie` <0.7.0 field injection (CVE-2024-47764) | high | `0.5.0` / `0.7.0+` | framework-cves |
| P-WS-REDOS-CVE | `ws` <7.4.6 ReDoS (CVE-2021-32640) | high | `7.4.5` / `7.4.6+` | framework-cves |
| P-SHARP-LIBWEBP-CVE | `sharp` <0.32.6 libwebp overflow (CVE-2023-4863) | high | `0.31.3` / `0.32.6+` | framework-cves |
| P-MINIMIST-PROTO-CVE | `minimist` <1.2.6 prototype pollution | review | `1.2.5` transitive / `1.2.6+` or dev-only (`N-DEV-DEP` guard) | framework-cves |

### 3c. Crypto-API misuse & JWT-verify options (extends `rules/semgrep/crypto.yml`; no new scanner)

| id | class | tier | pos / neg | lens |
|---|---|---|---|---|
| P-CIPHER-NO-IV | `createCipher`/`createDecipher` (implicit IV) | high | `createCipher('aes-256-ctr',secret)` / `createCipheriv(…,key,iv)` | semgrep |
| P-PSEUDORANDOM-BYTES | `crypto.pseudoRandomBytes()` for a token | high | `pseudoRandomBytes(16)` reset token / `randomBytes(16)` | semgrep |
| P-JWT-VERIFY-NOALG | `jwt.verify()` with no `algorithms` restriction (alg confusion) | high | 2-arg `jwt.verify(t,KEY)` / `{algorithms:['RS256']}` | framework-cves |
| P-JWT-IGNORE-EXP | `jwt.verify(...,{ignoreExpiration:true})` | high | option present / default options | owasp |
| P-INSECURE-WS-URL | `ws://` insecure WebSocket URL | high | `new WebSocket('ws://…')` / `wss://` | semgrep |
| P-GCM-NO-TAGLEN | AES-GCM decipher with no `authTagLength` | review | `createDecipheriv` gcm, no authTagLength / `authTagLength:16`+`setAuthTag` | semgrep |
| P-AEAD-NO-FINAL | AEAD decipher without `.final()`/tag check | review | `.update()` only, no `.final()` / `final()` hard-fails | semgrep |
| P-JWT-DECODE-RENDER | Unverified `jwtDecode` claim used in UI/authz (client-render sink) | review | `const{role}=jwtDecode(t)` / role from server session (adjacent `P-JWT-DECODE-NOVERIFY`) | semgrep |
| P-HMAC-HARDCODED-KEY | Hardcoded key literal to `createHmac` | review | `createHmac('sha256','literal')` / `…, process.env.SECRET` (adjacent `P-JWT-SIGNING-SECRET`) | semgrep |

### 3d. Next-config / client-surface misconfig (extends `semgrep.ts` config-parse + `headers.yml`/`xss.yml`)

| id | class | tier | pos / neg | lens |
|---|---|---|---|---|
| P-IMG-REMOTEPATTERNS-WILD | next/image SSRF via wildcard `remotePatterns` | high | `hostname:'**'` / explicit allowlist | owasp+nextjs |
| P-PROD-SOURCEMAPS | `productionBrowserSourceMaps:true` ships readable source | high | key `true` / absent-or-false | owasp |
| P-SERVERACTIONS-ORIGIN-WILD | Server Actions `allowedOrigins:['*']` | high | wildcard / explicit host | nextjs |
| P-PUBLIC-DIR-SENSITIVE | Sensitive/dev files served from `public/` | high | `public/.env.local`,`public/backup.sql` / only favicon+fonts (realizes scan-gaps §1.4) | nextjs |
| P-SIGNED-URL-TTL | `createSignedUrl` excessive expiry | high | `createSignedUrl(p,31536000)` / `…,300` | owasp+supabase |
| P-POSTMESSAGE-WILDCARD | `postMessage(data,'*')` | high | `parent.postMessage(session,'*')` / explicit origin | semgrep |
| P-TOKEN-IN-WEBSTORAGE | App-issued auth token in localStorage | review | `localStorage.setItem('authToken',t)` / `csrfToken` (JS-readable by design) | owasp+semgrep |
| P-MISSING-SRI | Third-party CDN `<script>` without `integrity` | review | `<script src='https://cdn…'>` / same with SRI+crossorigin | owasp |
| P-ISR-REVALIDATE-NOSECRET | ISR `revalidate` route with no secret token | review | `res.revalidate(req.query.path)` / secret compared first | owasp |
| P-CRLF-HEADER-INJ | CRLF header injection via untrusted `res.setHeader` value | review | `setHeader('Content-Disposition',`…${req.query.name}`)` / CRLF-stripped | owasp |
| P-POSTMESSAGE-NO-ORIGIN | `message` listener without origin validation | review | `addEventListener('message',e=>setState(e.data))` / origin checked | semgrep |

### 3e. Supabase static-config / edge + injection-sink breadth (extends `supabase-config.ts`, `injection.yml`; `P-RLS-MISSING-STATIC` needs a new static-migration check)

| id | class | tier | pos / neg | lens |
|---|---|---|---|---|
| P-RLS-MISSING-STATIC `[new-scanner]` | `CREATE TABLE` with no `ENABLE RLS`, read **statically from migrations** | high (opportunity) | pos: `create table public.X` no enable-rls / neg: followed by `ENABLE ROW LEVEL SECURITY`, or service-only table (`N-RLS-DENY-ALL`). **Static path for `P-RLS-DISABLED`, today connected-only** | supabase |
| P-PG-SSL-DISABLED | Direct `pg` `Pool({ssl:false})` to a Supabase pooler host | high | `ssl:false` to `pooler.supabase.com` / `ssl:{rejectUnauthorized:true}` | supabase |
| P-AUTH-ADMIN-CLIENT | `auth.admin.*` reachable from a Client Component | high | `'use client'`+`supabaseAdmin.auth.admin.listUsers()` / server-only guarded (narrower `P-SRV-KEY-CLIENT`) | supabase |
| P-SPAWN-SHELL | `spawn`/`execFile` with `{shell:true}` | high | `spawn('convert',[userFile],{shell:true})` / argv array no shell (extends `harvey-command-injection`) | semgrep |
| P-EDGEFN-VERIFY-JWT-OFF | Edge Function `verify_jwt=false` on a privileged handler | review | `[functions.admin-refund] verify_jwt=false` + service-role work / HMAC-checked webhook | supabase |
| P-SELECT-STAR-PII | `.select('*')` PII spread into an API response | review | `select('*')` from `customers(ssn)`→`res.json` / `select('id,name,email')` | supabase |
| P-CRON-NO-SECRET | Service-role cron endpoint with no caller secret | review | `/api/cron` uses `supabaseAdmin`, in `vercel.json` crons, no `CRON_SECRET` / Bearer checked | supabase |
| P-DYNAMIC-REQUIRE | `require()` with a tainted arg | review | `require(req.query.module)` / `require('./fixed')` | semgrep |
| P-DYNAMIC-DISPATCH | `obj[userInput]()` dynamic method dispatch | review | `actions[req.body.action](p)` no allowlist / checked against allowlist | semgrep |
| P-TEMPLATE-AUTOESCAPE-OFF | Handlebars/Mustache autoescape off | review | `Handlebars.compile(tpl,{noEscape:true})` user data / default escaping | semgrep |
| P-HTML-TEMPLATE-LITERAL | HTML template literal interpolated into `res.send` | review | `res.send(`<h1>${req.query.name}</h1>`)` / plain-text log | semgrep |
| P-INCOMPLETE-SANITIZE | Non-global `.replace()` used as a sanitizer | review | `s.replace('<','').replace('>','')` / `/</g` real sanitizer | semgrep |

### 3f. App-logic heuristics (all `review`; extend `leftover-auth.ts` + new heuristics)

| id | class | tier | pos / neg | lens |
|---|---|---|---|---|
| P-CLIENT-PRIV-HEADER | Authz decision from a client-controlled header/body/query | review | `if(req.headers['x-role']==='admin')` / role from `getUser().app_metadata` | owasp |
| P-CLIENT-PAYMENT-AMOUNT | Server trusts a client-supplied payment amount | review | `paymentIntents.create({amount:req.body.amount})` / recompute from DB price | owasp |
| P-WEBHOOK-NO-SIG | Inbound webhook handler with zero signature verification | review | privileged DB write, no HMAC anywhere / `constructEvent` before write (distinct from replay) | owasp |
| P-SENSITIVE-CONSOLE-LOG | Password/token/secret logged to console | review | `console.log('login',{email,password})` / logs outcome only | owasp |
| P-UPLOAD-NO-LIMIT | Upload endpoint, no size/MIME limit before storage write | review | `storage.upload(name,buf)` no checks / content-length+MIME allowlist (code-side of `supabase-storage-unrestricted-upload-policy`) | owasp |

---

## 4. Excluded-tier backlog (correctly NOT in the mechanical count)

Real, valuable classes routed to the paid/connected/pen-test tiers per the tier rules. Mapped to
their product surface.

### 4a. Semantic (LLM/whole-program — paid M-series)

| class | lens | why not mechanical |
|---|---|---|
| `missing-object-property-level-authz` (BOLA/BFLA, broad) | owasp | object-level authz needs request+identity context |
| `middleware-matcher-excludes-api-routes` | nextjs | matcher regex vs route inventory — whole-program |
| `middleware-sole-authz-layer` | nextjs | defense-in-depth reasoning (scan-gaps §2.1) |
| `draft-mode-enable-missing-secret` | nextjs | control-flow: is the enable path guarded? |
| `host-header-trusted-in-url-construction` | nextjs | taint from `Host` into reset-link URL |
| `server-component-conditional-client-auth-gate` | nextjs | authz-by-client-render, control-flow shape |
| `supabase-storage-rls-ownership-gap` | supabase | policy checks auth not ownership — policy-body semantics |
| `supabase-storage-unrestricted-upload-policy` | supabase | `WITH CHECK(true)` — policy-body semantics (code-side is `P-UPLOAD-NO-LIMIT`) |
| `supabase-secdef-function-privileged-write-noauth` | supabase | SECURITY DEFINER + missing `auth.uid()` — semantics |

### 4b. Connected (live Supabase — Advisor / Management API, connected tier)

| class | lens | detection |
|---|---|---|
| `P-REALTIME-NO-AUTHZ` (merged) | owasp+supabase | live channel `private:true` + `realtime.messages` policy state |
| `supabase-schema-overexposure-config` | supabase | PostgREST `[api] schemas` breadth |
| `supabase-graphql-introspection-enabled` | supabase | `pg_graphql` introspection setting |
| `gotrue-oidc-issuer-verification-bypass` | framework-cves | self-hosted GoTrue <2.185.0 (server version) |
| `gotrue-email-link-poisoning-xff` | framework-cves | self-hosted GoTrue XFF handling (server version + proxy) |

### 4c. Dynamic (needs a running app — #5 pen-test)

| class | lens |
|---|---|
| `shadow-deprecated-api-version-endpoint` (old `/api/v1/*` live) | owasp |
| `unrestricted-business-flow-no-anti-automation` | owasp |
| `personalized-response-cached-cross-user` | nextjs |
| `supabase-anon-rpc-relies-on-frontend-gating` | supabase |

---

## 5. Ranked mechanical build order

Ranked by (prevalence × severity in the Next.js/Supabase stack) × (detection-precision confidence).
`high` rows feed the free count; `review` rows are paid-tier but still worth building for breadth.

**Tier 1 — high-precision, high-value (build first):** P-RLS-MISSING-STATIC · P-EDGEFN-SECRET ·
P-NEXTCONFIG-ENV-SECRET · P-SB-DEFAULT-JWT-SECRET · P-PUBLIC-DIR-SENSITIVE ·
P-IMG-REMOTEPATTERNS-WILD · P-NEXT-CVE-NULLORIGIN · P-UNDICI-CVE-CLUSTER · P-AXIOS-SSRF-CVE ·
P-JSONWEBTOKEN-CVE · P-PG-SSL-DISABLED · P-AUTH-ADMIN-CLIENT.

**Tier 2 — high-precision, medium-value:** P-NEXTAUTH-CSRF-CVE · P-NEXTAUTH-EMAIL-CVE ·
P-FOLLOW-REDIRECTS-CVE · P-COOKIE-PKG-CVE · P-WS-REDOS-CVE · P-SHARP-LIBWEBP-CVE ·
P-CIPHER-NO-IV · P-PSEUDORANDOM-BYTES · P-JWT-VERIFY-NOALG · P-JWT-IGNORE-EXP · P-SPAWN-SHELL ·
P-NPM-TOKEN-COMMITTED · P-GCP-SA-JSON · P-URI-CREDS-NONPG · P-SLACK-WEBHOOK-URL ·
P-DB-WEBHOOK-SECRET-SQL · P-SIGNED-URL-TTL · P-PROD-SOURCEMAPS · P-SERVERACTIONS-ORIGIN-WILD ·
P-POSTMESSAGE-WILDCARD · P-INSECURE-WS-URL.

**Tier 3 — review (paid-tier breadth), build with their high siblings:** all §3 `review` rows
(P-MINIMIST-PROTO-CVE, P-GCM-NO-TAGLEN, P-AEAD-NO-FINAL, P-JWT-DECODE-RENDER, P-HMAC-HARDCODED-KEY,
P-GCP-API-KEY, P-SECRET-IN-URL, P-SIGNED-URL-TOKEN-SRC, P-TOKEN-IN-WEBSTORAGE, P-MISSING-SRI,
P-ISR-REVALIDATE-NOSECRET, P-CRLF-HEADER-INJ, P-POSTMESSAGE-NO-ORIGIN, P-EDGEFN-VERIFY-JWT-OFF,
P-SELECT-STAR-PII, P-CRON-NO-SECRET, P-DYNAMIC-REQUIRE, P-DYNAMIC-DISPATCH, P-TEMPLATE-AUTOESCAPE-OFF,
P-HTML-TEMPLATE-LITERAL, P-INCOMPLETE-SANITIZE, P-CLIENT-PRIV-HEADER, P-CLIENT-PAYMENT-AMOUNT,
P-WEBHOOK-NO-SIG, P-SENSITIVE-CONSOLE-LOG, P-UPLOAD-NO-LIMIT).

> **Honesty flag (P-RLS-MISSING-STATIC).** This is the one genuinely-new *mechanical opportunity*
> to move a previously connected-only class (`P-RLS-DISABLED`) onto the static free path by parsing
> committed migrations for `CREATE TABLE … public.*` with no matching `ENABLE ROW LEVEL SECURITY`.
> It is only `high` if it clears the existing `N-RLS-DENY-ALL` service-only-table lookalike and any
> table whose RLS is enabled in a later migration — verify against those negatives before promoting.
> Everything else in Tier 1/2 is a config-parse, exact-literal, exact-API, or version-range match.

---

## 6. Proposed batches (continuing the round-1 B1–B8 naming; ~15 classes each)

Following the round-1 rule: `GROUND-TRUTH.md` + the `CORPUS` array are a single answer key one
agent owns per PR, each batch self-contained (fixtures + rule/scanner + `CORPUS` rows +
`GROUND-TRUTH` table + green `pnpm validate:calibration`), grouped by subsystem coherence.

| Batch | Theme | Classes (incl. neg) | Shared file(s) touched | New vs extend |
|---|---|---|---|---|
| **B9** | Secrets & config-secret breadth | 12 (11 pos + `N-BCRYPT-HASH-SEED`) | `src/scan/secrets.ts`, gitleaks custom patterns, `supabase-config.ts` (edge/db-webhook) | **extend** existing scanner + patterns |
| **B10** | Dependency-CVE & framework-version breadth | 11 | `src/scan/dependencies.ts`, `checkNextVersionCVEs`, OSV curated ranges, lockfile fixture | **extend** (mostly corpus rows + version tables; no new scanner) |
| **B11** | Crypto-API misuse & JWT-verify options | 9 | `src/scan/rules/semgrep/crypto.yml` | **extend** existing rule file |
| **B12** | Next-config & client-surface misconfig | 11 | `src/scan/semgrep.ts` (config-parse), `rules/semgrep/headers.yml`, `xss.yml` | **extend**; small new config-parse checks (sourcemaps, remotePatterns, allowedOrigins, public/ walk) |
| **B13** | Supabase static-config/edge + injection-sink breadth | 12 | `supabase-config.ts`, `rules/semgrep/injection.yml`; **new** static-migration RLS check for `P-RLS-MISSING-STATIC` | **extend** + **one new scanner** (`checkMigrationRlsStatic`) |
| **B14** | App-logic heuristics (review) | 5 | `src/scan/leftover-auth.ts` + new small heuristics | **extend** |

**Counts:** raw candidates **85** → after dedup **80** → already-covered **2** → **59 new
mechanical** (≈**33 high**, ≈**26 review**) + **18 excluded-tier** + **1 negative**. Six batches
(**B9–B14**) build out the 59 mechanical classes; the 18 excluded-tier classes are backlog for the
connected tier (B8-style) and the M-series/pen-test paid modules, not new mechanical batches.

**"Batches to 100":** the corpus already passed ~100 classes in round 1; this round adds breadth,
not free-count claims. The ~33 new `high` candidates would roughly double the free-count `high`
tier (~24 → ~57), but per the credibility cap several are best asserted with exploitability
caveats (self-hosted-only CVEs, version-match ≠ exploitable) — keep the "a wrong Critical is
credibility-fatal" discipline when promoting.

## Sources

Round-2 candidates: `scratchpad/candidates.json` (5 research lenses, 2026-07-09). Reused repo docs:
`docs/design/spec-71-security-corpus.md`, `docs/design/scan-coverage-gaps.md`,
`docs/design/calibration-corpus-spec.md`, `docs/design/mechanical-toolchain.md`,
`targets/calibration/GROUND-TRUTH.md`, `src/scan/rules/semgrep/*.yml`, `src/scan/calibration/*.entries.ts`.
Per-class CVE/GHSA and OWASP/CWE references are carried inline in `candidates.json`.
