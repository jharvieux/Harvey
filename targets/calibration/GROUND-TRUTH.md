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
| 7 | UPDATE-UNSCOPED | High | `pages/api/profile/update.js:11-14` | `.update({ role })` with no `.eq()` scoping, via service role | `POST /api/profile/update {"role":"admin"}` sets `role=admin` on every profile in every tenant. |
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
