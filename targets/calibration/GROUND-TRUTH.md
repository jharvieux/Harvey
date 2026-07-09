# GROUND-TRUTH — calibration target answer key

This app is **deliberately vulnerable**. Every bug below is planted on purpose so the
Harvey scanner can be measured for precision/recall against known answers. Line numbers
are the source of truth; if you edit the files, update this table.

Tenants: **A** = `aaaaaaaa-…`, **B** = `bbbbbbbb-…`. Users: `alice@tenant-a.test` (A),
`bob@tenant-b.test` (B). "anon" = a request carrying only the anon key (no user token).

## Planted bugs

| # | ID | Severity | Location (file:line) | Bug | Exploit |
|---|----|----------|----------------------|-----|---------|
| 1 | RLS-USING-TRUE | Critical | `supabase/migrations/20260708000002_rls.sql:31-32` | `documents` SELECT policy is `USING (true)` | Anon or any user reads every tenant's documents: `GET /rest/v1/documents` returns A's and B's rows. |
| 2 | RLS-AUTH-ROLE | Critical | `supabase/migrations/20260708000002_rls.sql:38-39` | `invoices` SELECT policy is `USING (auth.role() = 'authenticated')` — checks *logged-in*, not *which tenant* | Alice (Tenant A) reads Tenant B's invoices: `GET /rest/v1/invoices` returns both tenants' financial rows. |
| 3 | RLS-DISABLED | High | `supabase/migrations/20260708000002_rls.sql:41-43` (absence — `audit_logs` never gets `enable row level security`) | RLS is never enabled on `audit_logs` | Anyone with the anon key reads all tenants' audit trails via PostgREST. |
| 4 | SQLI-SERVICE | Critical | `pages/api/search.js:9` | Untrusted `q` concatenated into raw SQL run on the service DB connection | `GET /api/search?q=' UNION SELECT id, email, encrypted_password FROM auth.users --` exfiltrates password hashes. |
| 5 | WEBHOOK-REPLAY | Medium | `pages/api/webhook.js:20-24` | HMAC signature verified, but no timestamp/nonce check | Capture one valid signed request and POST it repeatedly; each replay re-inserts the side-effect (audit row) forever. |
| 6 | COUNTER-RACE | Medium | `pages/api/counter/increment.js:11-31` | Non-atomic read-modify-write on `counters.value` | Fire N concurrent `POST /api/counter/increment`; final value is < N because increments interleave and are lost. |
| 7 | UPDATE-UNSCOPED | High | `pages/api/profile/update.js:11` | `pool.query("UPDATE public.profiles SET role = $1", [role])` with no `WHERE` clause, via the raw pg connection — bypasses both RLS and PostgREST's WHERE-clause guard | `POST /api/profile/update {"role":"admin"}` sets `role=admin` on every profile in every tenant. |
| 8 | OPEN-REDIRECT | Low | `pages/api/redirect.js:9` | `z.string().url()` validates URL shape but not host (no allowlist) | `GET /api/redirect?url=https://evil.example/phish` issues a 302 to the attacker's host. |

## Severity coverage

- **Critical:** #1, #2, #4
- **High:** #3, #7
- **Medium:** #5, #6
- **Low:** #8

## Intended true-negatives (should NOT be flagged)

- `notes` — correctly tenant-scoped RLS (`rls.sql:15-19`).
- `counters` RLS policy — correctly tenant-scoped; the counter bug is in the API route, not the policy (`rls.sql:22-26`).
- `profiles` / `tenants` — self/own-tenant read policies (`rls.sql:5-13`).
- Webhook HMAC check — the signature comparison is correct and constant-time; only replay protection is missing.

---

## Mechanical-scan calibration corpus (issues #61 / #52 / #9)

The mechanical/static layer (`src/scan/mechanical.ts`) is tuned and gated against this corpus.
The 8 planted bugs above stay the semantic/RLS ground truth; the rows below add the fixtures
that measure the mechanical layer's **precision** — every planted static vuln that must be caught,
and every benign lookalike that must NOT be flagged in the free count. Scored by the calibration
harness: `pnpm validate:calibration` (live binaries) / `src/scan/calibration.test.ts` (unit, CI).

**Precision tiers:** `high` = ~100% precise, safe for the free "quick scan" count · `review` =
LLM-triage / paid tier · `connected` = needs a live DB (Supabase Advisor), not a static run.
Every secret value in these fixtures is FAKE (valid-shape only); this app is never deployed.

### Positives — planted vulns (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-SQLI-CONCAT `[=#4]` | `pages/api/search.js:9` | Semgrep `harvey-sql-injection-template` (taint: req → template-literal SQL → `.query`) | high |
| P-OPEN-REDIRECT `[=#8]` | `pages/api/redirect.js:18` | Semgrep `harvey-open-redirect` (taint through zod to `res.redirect`) | review |
| P-RLS-DISABLED `[=#3]` | `supabase/migrations/…_rls.sql` (`audit_logs`, absence) | Supabase Advisor `0013` — **connected tier**, validated in the 2026-07-08 live run (`SB-EXPOSED`), not re-run in this static build | connected (N/A) |
| P-SRV-KEY-CLIENT | `components/AdminPanel.jsx:10` | Semgrep `harvey-service-role-in-client` (SERVICE_ROLE_KEY inside a `"use client"` module) | high |
| P-NEXTPUBLIC-SECRET | `.env.local:12` | gitleaks `stripe-access-token` + `supabase-next-public-secret-leak` | review |
| P-HARDCODED-KEY | `lib/ai.js:4` | gitleaks `anthropic-api-key` (fake, valid-shape; TruffleHog can't verify a dead key → not high) | review |
| P-NEXT-CVE-29927 | `package.json` (`next@^14.2.5`) | `checkNextVersionCVEs` (< 14.2.25, GHSA-f82v-jwr5-mffw) | high |
| P-NEXT-CVE-RSC | `package.json` (`next@^14.2.5`) | `checkNextVersionCVEs` (< 14.2.35, React2Shell RSC RCE) | high |
| P-DEP-CVE | `package.json` (`lodash@4.17.11`) | OSV-Scanner over the committed `package-lock.json` (issue #65) — live run 2026-07-08 matches 7 GHSA advisories against `lodash@4.17.11` (prototype pollution among them) | review (caught) |
| P-XSS-DSIH | `pages/post.js:8` | Semgrep `harvey-dangerously-set-inner-html` (taint: `router.query` → `__html`) | high |
| P-CORS-WILDCARD | `pages/api/data.js:5` | Semgrep `harvey-permissive-cors` | high |
| P-NO-CSP | `next.config.js` | `checkMissingCsp` (no CSP in next.config/middleware/vercel.json) | review |
| P-SSRF-FETCH | `pages/api/fetch-preview.js:5` | Semgrep `harvey-ssrf-fetch` (taint: `req.query` → `fetch`) | review |
| P-SLOPSQUAT | `package.json` (`react-supabase-helpers`) | `checkSlopsquat` npm-registry existence check (issue #66) — live 404 against `registry.npmjs.org/react-supabase-helpers` | high (caught) |
| P-POSTINSTALL | `package.json` (scripts) | `checkInstallScripts` (postinstall lifecycle hook) | review |
| P-DEBUG-ENDPOINT | `pages/api/dev/seed.js`, `pages/api/admin/reset.js` | leftover-auth (sensitive-route + `isAdmin = true` greps) | review |
| P-TODO-AUTH | `pages/api/comments/create.js` | leftover-auth (`// TODO: auth` grep) | review |

### Negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-ANON-KEY | `.env.local:8` | Public anon key (`role:anon`), public by design. gitleaks allowlist `regexTarget=line` on `NEXT_PUBLIC_SUPABASE_ANON_KEY` suppresses every rule on the line. The most credibility-fatal FP. |
| N-ENV-EXAMPLE | `.env.example` | Documented placeholders; path-allowlisted, unverifiable. |
| N-SECRET-NAME | `components/ResetForm.jsx` | Variables named like secrets (`passwordLabel`) holding none — Harvey never flags on name alone. |
| N-PARAM-QUERY | `pages/api/list.js` | Parameterized `pool.query("… $1", [req.x])`; the SQLi rule fires only on interpolation, not bound params. |
| N-DSIH-SANITIZED | `pages/about.js` | `sanitizeHtml(...)` + a constant literal — the custom rule (sanitizer stop) clears both; a registry `.audit` rule flags it at review tier only. |
| N-OBJ-INJECTION | `lib/i18n.js` | `translations[locale]` with `locale` validated against an enum. |
| N-JSX-KEY | `components/List.jsx` | Composite stable key ``key={`${it.id}-${i}`}`` — quality rule, never in the security count. |
| N-WEAK-HASH-CACHE | `lib/cache.js` | md5 as an ETag/cache tag, not auth/integrity. |
| N-REDOS-SAFE | `lib/validate.js` | Linear email regex (negated classes); ReDoS stays out of the count. |
| N-FS-STATIC | `lib/read-config.js` | Static `fs.readFileSync(path.join(__dirname,…))` + an unrelated `widget.open()`. |
| N-DEV-DEP | `package.json` (`webpack@4.42.0`, dev) | Dev-only dep — excluded from the count. Live OSV run (issue #65) over the committed lockfile finds zero CVEs on `webpack@4.42.0` itself; its dev-only transitive deps (`braces`, `elliptic`, `micromatch`, `serialize-javascript`) do carry real CVEs but land at review tier (non-curated), never high. |
| N-SERVICE-ROLE-SERVER | `lib/cron.js` | `import "server-only"` + admin client, no `"use client"` — service-role use is not a finding by itself. |
| N-RLS-DENY-ALL | `supabase/migrations/…` (`service_state`) | RLS on + zero policies = deny-all by design; Advisor `0008` is informational, not a finding (connected tier). |
| N-URL-ENV | `lib/redis.js` | `z.string().url()` on `process.env.REDIS_URL` (`redis://`) — operator/env URLs are exempt. |
| N-INMEM-CACHE | `lib/memo.js` | Module-level `Map` for memoization, not a rate limiter. |

### Live result (2026-07-08, static binaries, no Docker)

`pnpm validate:calibration`: **positives caught 14/16 static (6 at high/free-count), 1
connected-tier N/A; negatives cleared 15/15; zero free-count false positives — GATE PASS.**
The two misses (P-DEP-CVE, P-SLOPSQUAT) are review-tier recall gaps needing a committed lockfile
and an npm-registry existence check respectively — tracked follow-ups, not regressions. This
replaces the pre-tuning baseline of **0 true positives / 1 false positive** (dry-run-calibration
§8.3). The one prior FP (`harvey-service-role-in-client` on `lib/supabaseAdmin.js`, issue #56) is
resolved: the rule now gates on the `"use client"` directive, so the server-only admin client is
correctly silent.

### Follow-up live result (2026-07-08, issues #65/#66 — lockfile + npm-registry existence check)

`pnpm validate:calibration`: **positives caught 16/16 static (7 at high/free-count), 1
connected-tier N/A; negatives cleared 15/15; zero free-count false positives — GATE PASS.**
Both prior review-tier recall gaps are now closed: P-DEP-CVE is caught by OSV-Scanner over a
newly-committed `package-lock.json` (issue #65 — generated with `react-supabase-helpers`
temporarily removed via `npm install --package-lock-only --ignore-scripts`, since it doesn't
exist and would fail a real install; the entry stays package.json-only, exactly as intended for
#66 to catch); P-SLOPSQUAT is caught at **high** tier by `checkSlopsquat`, a live
`registry.npmjs.org` existence check (issue #66) — `react-supabase-helpers` 404s. N-DEV-DEP stays
clear: the live OSV pass finds zero CVEs on `webpack@4.42.0` itself (only its dev-only transitive
deps carry non-curated, review-tier CVEs).

---

## Batch B1 (#71) — secrets & credential-exposure breadth

The first #71 expansion batch (spec `docs/design/spec-71-security-corpus.md` §B1). Adds the
full secret-provider breadth as planted positives + the benign lookalikes secret scanners throw.
All secret values are FAKE (valid-shape only); the app is never deployed. Tiering per the spec's
locked preamble: only ~100%-precision detections are `high` (free count) — the **decoded**
`service_role` claim, and the unambiguous `sb_secret_` / private-key / DB-connection-URI prefixes.
Provider patterns that only live TruffleHog verification would confirm (OpenAI/Stripe/AWS/GitHub/
SendGrid) land at `review`, because a FAKE key can't verify — the same honest outcome already used
for `P-HARDCODED-KEY`.

### B1 positives — planted secrets (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-SRV-ROLE-JWT-SRC | `lib/admin.js:8` | gitleaks `supabase-service-role-jwt` (base64-decodes the JWT body, `--max-decode-depth 2`, matches `"role":"service_role"`) | high |
| P-SB-SECRET-KEY | `lib/edge-config.js:4` | gitleaks custom `supabase-secret-key` (`sb_secret_` prefix — Supabase's secret namespace, never public) | high |
| P-PRIVATE-KEY | `certs/key.pem:1` | gitleaks `private-key` (`-----BEGIN PRIVATE KEY-----` block) | high |
| P-SRV-ROLE-IN-BUNDLE | `prebuilt-bundle/chunk.4f2a.js:7` | gitleaks `supabase-service-role-jwt` on a committed pre-built chunk (models a service-role key leaked into browser-shipped `.next/static`) | high |
| P-DB-URL-PASSWORD | `.env.local:19` | gitleaks custom `harvey-db-uri-credentials` (`postgres://user:password@host`; loopback hosts allowlisted) | high |
| P-OPENAI-KEY | `lib/llm.js:5` | gitleaks `generic-api-key` (value defanged for push protection — see note; `openai-api-key` validated pre-commit) | review |
| P-STRIPE-SECRET | `lib/pay.js:4` | gitleaks `generic-api-key` (value defanged; `stripe-access-token` validated pre-commit) | review |
| P-AWS-KEY | `lib/s3.js:5` | gitleaks `generic-api-key` on the secret (values defanged; `aws-access-token` validated pre-commit) | review |
| P-GH-TOKEN | `scripts/deploy.js:4` | gitleaks `github-pat` (`ghp_`; push protection did not block this fake; unverifiable → review) | review |
| P-SENDGRID-KEY | `lib/email.js:4` | gitleaks `generic-api-key` (value defanged; `sendgrid-api-token` validated pre-commit) | review |
| P-JWT-SIGNING-SECRET | `lib/auth.js:7` | gitleaks `generic-api-key` (high-entropy signing-secret literal to `jwt.sign`; heuristic → review) | review |

**Push-protection defang note.** GitHub push protection blocks committing a real-shape OpenAI /
Stripe / AWS / SendGrid key. For those four, the committed literal is a pure high-entropy fake
with the provider prefix removed, keeping the provider word in its `*_API_KEY` variable name — so
gitleaks catches it via `generic-api-key` at review (the provider word rides along in the match).
The provider-specific patterns (`openai-api-key`, `stripe-access-token`, `aws-access-token`,
`sendgrid-api-token`) were confirmed to fire on the real-shape values during pre-commit validation
(gitleaks 8.30.1). Class and tier (hardcoded provider secret, review) are unchanged; only the
firing rule differs. The `ghp_` GitHub PAT fake and all high-tier prefix/claim-based detections
(service_role, `sb_secret_`, private-key, DB-URI) were not blocked and are committed as-is.

### B1 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-STRIPE-PK-PUBLISHABLE | `.env.local` (`NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_…`) | Stripe publishable keys are public by design (like the anon key). gitleaks allowlist `pk_(live|test)_` (regexTarget=line) suppresses every rule on the line. |
| N-STRIPE-TEST-KEY | `.env.local` (`sk_test_…`) | Test-mode key, no production risk. gitleaks `stripe-access-token` still pattern-matches it → review only (triaged out), never high. |
| N-AWS-EXAMPLE-KEY | `docs/aws-setup.md` (`AKIAIOSFODNN7EXAMPLE`) | AWS-docs placeholder; gitleaks stopword-allowlists the `EXAMPLE` marker — `aws-access-token` stays silent. |
| N-DB-URL-LOCAL | `README.md:53` (`postgres://postgres:postgres@127.0.0.1`) | Standard local Supabase dev string, not a committed credential. `harvey-db-uri-credentials` allowlists loopback hosts (`localhost`/`127.0.0.1`). |

**Deferred to a later batch (spec §B1 rows not built here, tracked follow-ups):**
`P-ENV-COMMITTED` (a committed `.env` with live values — overlaps `P-DB-URL-PASSWORD`, which
already exercises a committed non-anon secret in `.env.local`); `P-SECRET-GIT-HISTORY` (a secret
added+removed across commits — the TruffleHog git-history pass only runs against a repo **root**,
not the `targets/calibration` subdirectory, so it can't be validated by this harness as-is;
needs a dedicated single-repo history fixture).

### B1 live result (2026-07-09, static binaries: gitleaks 8.30.1, trufflehog 3.95.8, no Docker)

`pnpm validate:calibration`: **positives caught 27/27 static (12 at high/free-count), 1
connected-tier N/A; negatives cleared 19/19; zero free-count false positives — GATE PASS.** The 11
new B1 positives all fire (5 at high: the two decoded service_role claims, `sb_secret_`,
private-key, DB-URI; 6 at review: the unverifiable provider patterns). The 4 new negatives clear:
the publishable key and loopback DB URI are gitleaks-allowlisted (silent), the AWS example key is
stopword-allowlisted (silent), and the test-mode Stripe key draws a review hit only (triaged out).
TruffleHog contributes nothing (every planted key is a dead fake, `--only-verified`), exactly as
scored. `pnpm verify` (offline) is green via recorded gitleaks output in `calibration.test.ts`.

---

## Batch B3 (#71) — injection & code-execution family

The injection expansion batch (spec `docs/design/spec-71-security-corpus.md` §"Batch 1 — Injection
& code-execution family"). Custom Semgrep taint rules in `src/scan/rules/semgrep/injection.yml`
(the per-batch rule-file directory established by the Part-1 modularization). Tiering per the
locked preamble: only ~100%-precision sinks are `high` (free count) — a raw-SQL-executor RPC,
`exec`/`execSync` of a request string, and `eval`/`new Function` of request input. The heuristic
sinks stay `review`. SQLi-via-template-literal (`P-SQLI-CONCAT` = planted bug #4) and its safe
lookalike `N-PARAM-QUERY` already ship in the base corpus; the ReDoS-safe / static-fs negatives
(`N-REDOS-SAFE`, `N-FS-STATIC`) too — B3 does not duplicate them.

### B3 positives — planted injections (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-SQLI-RPC | `pages/api/report.js:10` | Semgrep `harvey-sql-injection-rpc` (taint: `req.query` → SQL string → `.rpc('exec_sql', …)`; sink gated on raw-SQL-executor RPC names) | high |
| P-CMD-INJECTION | `pages/api/convert.js:8` | Semgrep `harvey-command-injection` (taint: `req.query` → `exec`/`execSync` string) | high |
| P-EVAL-CODE-INJ | `pages/api/calc.js:6` | Semgrep `harvey-code-injection-eval` (taint: `req.body` → `eval`/`new Function`) | high |
| P-POSTGREST-FILTER-INJ | `pages/api/find.js:12` | Semgrep `harvey-postgrest-filter-injection` (taint: `req.query` → string `.or()`) | review |
| P-PROTO-POLLUTION | `lib/merge.js:8` | Semgrep `harvey-prototype-pollution` (taint: `req.body` → `lodash.merge`/`defaultsDeep`) | review |
| P-INSECURE-DESERIALIZE | `pages/api/import.js:7` | Semgrep `harvey-unsafe-deserialization` (taint: `req.body` → `unserialize()`) | review |
| P-XXE | `pages/api/xml.js:6` | Semgrep `harvey-xxe` (xml2js parse options `noent: true`) | review |
| P-PATH-TRAVERSAL | `pages/api/file.js:11` | Semgrep `harvey-path-traversal` (taint: `req.query` → `path.join` → `fs`; `path.basename` sanitizer) | review |
| P-ZIP-SLIP | `lib/unzip.js:11` | Semgrep `harvey-zip-slip` (`fs.writeFileSync(path.join(dir, entry.entryName), …)`, no containment) | review |
| P-SSTI | `pages/api/render.js:7` | Semgrep `harvey-template-injection` (taint: `req.body` → `ejs.render`) | review |
| P-REDOS | `lib/parse.js:4` | Semgrep `harvey-redos` (`new RegExp` with a nested-quantifier `metavariable-regex`) | review |
| P-LOG-INJECTION | `pages/api/track.js:7` | Semgrep `harvey-log-injection` (taint: `req.query` → `console.log`) | review |

### B3 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-CMD-SAFE | `lib/img.js` | `execFile('convert', [inputPath, …])` — argv array, no shell. `harvey-command-injection` fires only on `exec`/`execSync` of a string. |
| N-EVAL-JSON | `lib/cfg.js` | `JSON.parse(req.body)` parses data, cannot execute. `harvey-code-injection-eval` fires only on `eval`/`new Function`. |
| N-PROTO-SAFE | `lib/opts.js` | `Object.assign({}, DEFAULTS, {theme, pageSize})` — shallow, explicit fields, no recursive merge. |
| N-XXE-SAFE | `lib/xml-safe.js` | xml2js parse with `noent: false` — external entities disabled. `harvey-xxe` fires only on `noent`/`resolveEntities` `true`. (Named `xml-safe.js`, not the spec's `lib/xml.js`, to avoid a basename collision with the `pages/api/xml.js` positive in the corpus location matcher.) |
| N-PATH-BASENAME | `pages/api/dl.js` | `path.basename(req.query.f)` strips directory components before the join; `harvey-path-traversal` registers `path.basename` as a sanitizer. |
| N-RPC-PARAM | `pages/api/rep.js` | `admin.rpc('report_total', { uid })` — a normal RPC with a bound argument (PostgREST parameterizes it); `harvey-sql-injection-rpc` fires only on raw-SQL-executor RPC names. |

### B3 live result (2026-07-09, static binaries: semgrep 1.164.0, gitleaks 8.30.1, trufflehog 3.95.8, osv-scanner 2.3.8, no Docker)

`pnpm validate:calibration`: **positives caught 39/39 static (15 at high/free-count), 1
connected-tier N/A; negatives cleared 25/25; zero free-count false positives — GATE PASS.** The 12
new B3 positives all fire (3 at high: raw-SQL-executor RPC, `exec` command injection, `eval` code
injection; 9 at review: the heuristic sinks). The 6 new negatives clear with no free-count finding
(the argv-array `execFile`, `JSON.parse`, shallow `Object.assign`, hardened `noent: false`,
`path.basename` sanitizer, and parameterized RPC are each correctly ignored). No regression on the
base or B1 batches. `pnpm verify` (offline) is green: the scorecard logic over the expanded CORPUS
is exercised in `calibration.test.ts`; the Semgrep rules themselves are proven by the live gate.
## Batch B4 (#71) — XSS & client-side sink family

The XSS/client-sink expansion batch (spec `docs/design/spec-71-security-corpus.md` §"Batch 2 —
XSS & client-side sink family"). Custom Semgrep taint rules in `src/scan/rules/semgrep/xss.yml`
(the per-batch rule-file directory established by the Part-1 modularization). Tiering per the
locked preamble: only ~100%-precision sinks are `high` (free count) — `.innerHTML`/
`insertAdjacentHTML` and `document.write`, which execute markup/script unconditionally once the
source is tainted, with no benign "just text" reading. The heuristic sinks (href scheme, a direct
`window.location` assignment, `setAttribute`, and a DB-read source reaching
`dangerouslySetInnerHTML`) stay `review`. XSS-via-tainted-`dangerouslySetInnerHTML` (`P-XSS-DSIH`)
and its sanitized/constant lookalike (`N-DSIH-SANITIZED`) already ship in the base corpus — B4
does not duplicate them.

### B4 positives — planted XSS/client sinks (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-DOM-XSS-INNERHTML | `components/Widget.jsx:11` | Semgrep `harvey-dom-innerhtml` (taint: `router.query` → `.innerHTML`/`insertAdjacentHTML`) | high |
| P-DOM-XSS-DOCWRITE | `components/Embed.jsx:9` | Semgrep `harvey-document-write` (taint: `location.hash` → `document.write()`) | high |
| P-XSS-STORED-DSIH | `pages/comment.js:10` | Semgrep `harvey-dangerously-set-inner-html-stored` (taint: Supabase `.from().select()` → `dangerouslySetInnerHTML`) | review |
| P-XSS-HREF-JS | `components/AnchorLink.jsx:9` | Semgrep `harvey-href-js-url` (taint: `router.query` → native `<a href>`) | review |
| P-XSS-DANGEROUS-URL | `components/LocationNav.jsx:10` | Semgrep `harvey-open-url-sink` (taint: `URLSearchParams.get()` → `window.location` assignment) | review |
| P-XSS-SETATTR | `components/ImgAttr.jsx:12` | Semgrep `harvey-set-attribute-xss` (taint: `router.query` → `setAttribute('src', …)`) | review |

### B4 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-INNERHTML-STATIC | `components/WidgetSafe.jsx` | `ref.current.innerHTML = '<strong>Loading…</strong>'` — constant string, no tainted source. `harvey-dom-innerhtml` fires only on `router.query`/`location`/`searchParams`. (Named `WidgetSafe.jsx`, not the spec's `Widget.jsx`, to avoid a basename collision with the `P-DOM-XSS-INNERHTML` positive — the same disambiguation B3 used for `xml-safe.js`.) |
| N-HREF-INTERNAL | `components/NavLink.jsx` | `<Link href="/dashboard">` — `next/link`, constant string, not a native `<a>` and not request-derived. `harvey-href-js-url`'s sink is a native `<a href={...}>` from a tainted source; neither the element nor the source matches. |
| N-SEARCHPARAMS-TEXT | `pages/search-results.js` | `<p>Results for: {router.query.q}</p>` — a React text child (JSX auto-escapes), never an `innerHTML`/`href`/`setAttribute`/`document.write` sink. None of the B4 rules match a plain text expression. |

### B4 live result (2026-07-08, static: semgrep 1.164.0, no Docker)

`pnpm validate:calibration`: **positives caught 45/45 static (17 at high/free-count), 1
connected-tier N/A; negatives cleared 28/28 static; zero free-count false positives — GATE
PASS.** The 6 new B4 positives all fire exactly once each, at their declared tier (2 at high:
`.innerHTML`/`insertAdjacentHTML` and `document.write`; 4 at review: the DB-sourced DSIH variant,
the `<a href>` scheme sink, the `window.location` open-URL sink, and `setAttribute`). The 3 new
negatives clear with no finding at all (not even a review-tier hit): the constant `innerHTML`,
the `next/link` internal route, and the text-rendered search param. No regression on the base,
B1, or B3 batches. One tuning note during development: the fixture for `P-XSS-STORED-DSIH`
originally destructured the DB row's HTML field as `.body` (matching the spec's `pages/comment.js`
sketch), which accidentally also matched the pre-existing `harvey-dangerously-set-inner-html`
rule's `$REQ.body` source pattern (a generic `<expr>.body` member-access match, not scoped to an
actual request object) — the fixture was renamed to `.content` to isolate the new `-stored` rule
and avoid over-crediting a DB-read source as a request-tainted `high` finding. `pnpm verify`
(offline) is green: the scorecard logic over the expanded `CORPUS` is exercised in
`calibration.test.ts`; the Semgrep rules themselves are proven by the live gate above.

---

## Batch M4+M5 (#72) — duplication (jscpd) + dead code (knip)

The M4/M5 slice of the #72 cross-module corpus (spec `docs/design/spec-72-crossmodule-corpus.md`
§M4/§M5). Both are fully-mechanical, static, self-contained — no live DB, no external service.
Scored via `src/scan/calibration/m4-m5.entries.ts` against `Finding[]` produced by
`pnpm quality-scan targets/calibration` (`src/quality-scan.ts::jscpdToFindings` /
`knipToFindings`, `src/cli/quality-scan.ts`). Per the spec's locked precision-tier discipline both
land at **`high`**: jscpd's text-match and knip's dead-export detection are ~100% precise once the
FP class (generated code / framework magic / dynamic reference / public API) is configured — the
negatives below are exactly that configuration.

### M4 — Duplication (jscpd)

**Positives — planted clones (must be caught)**

| id | location | detection | tier |
|---|---|---|---|
| M4-P-CLONE-A | `dup/invoice-total.ts` ↔ `dup/order-total.ts` | genuine 27-line copy-pasted tax/rounding block (299 tokens); jscpd clone cluster; `jscpdToFindings` → Low severity | high |
| M4-P-CLONE-B | `dup/report-a.ts` ↔ `dup/report-b.ts` | genuine 52-line copy-pasted metric-aggregation block (658 tokens); jscpd clone cluster; `severityForClone` → Medium (≥50 lines) | high |

**Negatives — benign lookalikes (must NOT be flagged)**

| id | location | why benign / suppression |
|---|---|---|
| M4-N-GENERATED | `dup/generated/schema.gen.ts` | repeats the `invoice-total.ts` tax block but is a generated file, not hand-maintained duplication. Excluded via the quality-scan CLI's jscpd `--ignore` glob, extended to `**/generated/**` (`src/cli/quality-scan.ts`) — jscpd never sees it. |
| M4-N-BOILERPLATE | `dup/route-a.ts` ↔ `dup/route-b.ts` | shares the Next.js API-route `config` + handler-signature boilerplate — a framework contract, not a defect. Shared span stays under jscpd's 50-token minimum (`.jscpd.json` `minTokens`) — not flagged. |

### M5 — Slop / dead code (knip)

Requires `targets/calibration/knip.json` (`entry`: `dead/consumer.ts`, `dead/dispatch.ts`,
`dead/index.ts`; `project`: `dead/**/*.ts`, `pages/dead-page.js`; `tags`: `["-lintignore"]`) so the
framework-magic and dynamic-reference negatives resolve — scoped narrowly to the M4/M5 fixture
subtree so it doesn't pull the M1 security fixtures (`pages/api/*.js`, `lib/*.js`) into the dead-code
report.

**Positives — planted dead code (must be caught)**

| id | location | detection | tier |
|---|---|---|---|
| M5-P-DEAD-EXPORT | `dead/orphan.ts` | exports `unusedHelper()`, imported nowhere (`dead/consumer.ts` only uses `computeTotal`); knip `issues[].exports` → `knipToFindings` | high |
| M5-P-DEAD-FILE | `dead/never-imported.ts` | no entry point ever imports this file; knip top-level `files[]` → `knipToFindings` (measured 6-line count) | high |

**Negatives — benign lookalikes (knip's FP class: dynamically-referenced / framework / public-API exports — must NOT be flagged)**

| id | location | why benign / suppression |
|---|---|---|
| M5-N-NEXT-MAGIC | `pages/dead-page.js` | default export + `getServerSideProps` are called by Next.js routing/build convention, never by import. knip's built-in Next.js plugin (auto-detected via the target's `next` dependency) treats `pages/**` as entry points. |
| M5-N-DYNAMIC-REF | `dead/registry.ts` | `handlerA` is referenced only via `dead/dispatch.ts`'s `handlers[name]` runtime lookup, invisible to static analysis. Tagged `@lintignore`; `knip.json`'s `tags: ["-lintignore"]` silences it. |
| M5-N-PUBLIC-API | `dead/index.ts` | the package's declared public entry (`package.json` `exports["."]`) for external consumers. Listed under `knip.json`'s `entry`, so the file and its export stay silent instead of a false dead-file/dead-export report. |

### M4+M5 live result (2026-07-08, static: jscpd 4.2.5, knip 5.88.1, no Docker)

`pnpm quality-scan targets/calibration` scored against `src/scan/calibration/m4-m5.entries.ts`:
**positives caught 4/4 (4 at high); negatives cleared 5/5; zero false positives — GATE PASS.**
jscpd reports exactly 2 clone clusters (both planted: 27-line Low + 52-line Medium, 4.63%
duplication overall) and zero clusters touching the two benign-lookalike fixtures. knip reports
exactly 1 unused file + 1 file with unused exports (both planted) and zero issues on the three
benign-lookalike fixtures. `pnpm verify` (offline) is green — `quality-scan.test.ts` covers the new
`precisionTier: "high"` tagging on recorded jscpd/knip fixtures; the live run above is the
Layer-2 gate (issue #61 two-layer pattern). No dedicated `validate:quality-calibration` CLI exists
yet — scoring above was run ad hoc against `buildCoverageMatrix`; adding that CLI (mirroring
`src/cli/validate-calibration.ts`) is a tracked follow-up, not a regression.

---

## M10 (#72) — PII/PHI/PCI data classification corpus

The first #72 cross-module batch (spec `docs/design/spec-72-crossmodule-corpus.md` §M10).
Promotes `tools/pii-classify.mjs`'s own selftest — already a precision measure, with positives
and the exact FP negatives baked in (`email_category`, `awaiting_dob_reprompt`, `vendor_health`)
— into the shared corpus/gate format, backed by a schema fixture: `public.pii_calibration_fixture`
in `supabase/migrations/20260708000003_pii_calibration.sql`. Column names/types only, never
seeded with data anywhere in this repo — privacy-safe by construction. `classifyColumn` is pure
name/type matching; no live DB is needed, so this is a **fully self-contained batch** (spec
"Precision tier: high... Live-env: none").

Answer key: `src/scan/calibration/m10.entries.ts` (`module: "M10"`, spread into `CORPUS` in
`src/scan/calibration.ts`). These entries are **not** scored by `pnpm validate:calibration`
(that gate's `runMechanicalScan` doesn't run the PII classifier) — `src/cli/validate-calibration.ts`
filters `CORPUS` down to `module === undefined` before scoring, so M10 can't spuriously break the
M1 live gate. M10's own live pipeline is `src/cli/dry-run.ts`'s M10 phase (parses migration SQL →
`buildDataMap`); wiring that into a dedicated `pnpm validate:pii-calibration` CLI (spec §M10(e)
Layer 2, marked optional) is a documented follow-up. Layer 1 — the answer key above plus the
extended `tools/pii-classify.test.ts` "M10 calibration corpus" block — is the gate for this batch
and runs in `pnpm verify`.

### M10 positives — planted columns (must be classified, all high confidence)

| id | column | classifier result |
|---|---|---|
| M10-P-EMAIL | `pii_calibration_fixture.email` | EMAIL / PII / high |
| M10-P-DOB | `pii_calibration_fixture.date_of_birth` | DOB / PII / high |
| M10-P-SSN | `pii_calibration_fixture.customer_ssn` | US_SSN / SENSITIVE_PII / high |
| M10-P-PASSPORT | `pii_calibration_fixture.passport_number` | PASSPORT / SENSITIVE_PII / high |
| M10-P-CVV | `pii_calibration_fixture.cvv` | CVV / PCI / high (severity-override → table scores Critical) |
| M10-P-CARD | `pii_calibration_fixture.card_last4` | CARD / PCI / high |

### M10 negatives — benign lookalikes (must NOT be flagged in the free/high count)

| id | column | why benign / suppression |
|---|---|---|
| M10-N-EMAIL-CAT | `pii_calibration_fixture.email_category` | descriptor suffix — categorizes the concept, not the value; excluded, `classifyColumn` returns `null`. |
| M10-N-DOB-FLAG | `pii_calibration_fixture.awaiting_dob_reprompt` (boolean) | boolean-flag naming (and boolean sql type); excluded, returns `null`. |
| M10-N-VENDOR-HEALTH | `pii_calibration_fixture.vendor_health` | infra/system health, not medical health; excluded, returns `null`. |
| M10-N-NAME-AMBIG | `pii_calibration_fixture.product_name` | ambiguous `NAME?` → classified but only at low confidence — never asserted in the free/high count. |

### M10 live result (2026-07-08, static — no DB, no external binary)

`tools/pii-classify.mjs`'s classifier run live against the parsed migration SQL
(`pnpm exec tsx src/cli/dry-run.ts`'s M10 phase, reading
`supabase/migrations/20260708000003_pii_calibration.sql`): **positives classified 6/6 (all at high
confidence — EMAIL, DOB, US_SSN, PASSPORT, CVV, CARD); negatives cleared 4/4** (3 excluded outright
by the exclusion pass, 1 — `product_name` — classified but held at low confidence, never asserted).
`pii_calibration_fixture` aggregates to categories `["PCI","PII","SENSITIVE_PII"]`, severity
**Critical** (driven by the lone CVV column's `INFOTYPE_POINT_OVERRIDES` weight). Zero free-count
false positives. `pnpm verify` (offline) is green via `tools/pii-classify.test.ts`'s "M10
calibration corpus" block (21/21 tests in the file, including the 3 new M10-specific cases) and the
unchanged `calibration.test.ts` suite (11/11, `CORPUS` now includes the 6 M10 positives + 4
negatives with no location collisions against the existing corpus).
