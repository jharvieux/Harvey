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
| 6 | COUNTER-RACE | Medium | `pages/api/counter/increment.js:11-26` | Non-atomic read-modify-write on `counters.value` | Fire N concurrent `POST /api/counter/increment`; final value is < N because increments interleave and are lost. |
| 7 | UPDATE-UNSCOPED | High | `pages/api/profile/update.js:12` | `pool.query("UPDATE public.profiles SET role = $1", [role])` with no `WHERE` clause, via the raw pg connection — bypasses both RLS and PostgREST's WHERE-clause guard | `POST /api/profile/update {"role":"admin"}` sets `role=admin` on every profile in every tenant. |
| 8 | OPEN-REDIRECT | Low | `pages/api/redirect.js:9` | `z.string().url()` validates URL shape but not host (no allowlist) | `GET /api/redirect?url=https://evil.example/phish` issues a 302 to the attacker's host. |

### Dynamic-tier probes (M2 verify replays, #145–#148)

Rows 9–12 are **dynamic-tier** classes: they can only be confirmed by probing the running app,
so they're M2 pen-test `verify` replays (`src/pentest/verify.ts`), not mechanical-scan findings.
Each has a seeded positive route/RPC and a benign sibling the probe clears. They are NOT expected
in the mechanical `validate:calibration` count (the app routes deliberately avoid mechanical
triggers like `select('*')`; the `issue_refund` SECURITY DEFINER grant is review-tier, not free).

| # | ID | Severity | Location | Bug | Exploit |
|---|----|----------|----------|-----|---------|
| 9 | SHADOW-API-VERSION | High | `pages/api/v1/export.js` | Deprecated v1 export route left live and unauthenticated after v2 replaced it | `GET /api/v1/export` returns every tenant's documents to anyone with the anon key; `/api/v2/export` requires a token (negative). |
| 10 | NO-RATE-LIMIT | High | `pages/api/coupon/redeem.js` | High-value flow with no anti-automation cap / single-use check | POST the same coupon N× — all N succeed; `coupon/redeem-limited.js` rejects a re-used code with 429 (negative). |
| 11 | CACHE-CROSS-USER | High | `pages/api/me/summary.js` | Per-user response served `Cache-Control: public` with no `Vary` on the auth token | A shared cache serves Tenant A's personalized summary to a later anon visitor; `pages/api/me/private.js` is `private, no-store` (negative). |
| 12 | ANON-PRIVILEGED-RPC | Critical | `supabase/migrations/20260710000002_dynamic_probes.sql` (`issue_refund`) | `issue_refund` is SECURITY DEFINER, EXECUTE granted to `anon`, no `auth.uid()` check | `POST /rest/v1/rpc/issue_refund` with only the anon key executes a refund; `promote_admin` has EXECUTE revoked from anon (negative). |

## Severity coverage

- **Critical:** #1, #2, #4, #12
- **High:** #3, #7, #9, #10, #11
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
The planted bugs above stay the semantic/RLS ground truth — bugs 1–8 are statically reachable and
scored by `dry-run-scorecard.ts`; bugs 9–12 are M2 dynamic replays scored by `src/pentest/verify.ts`
(see the "Planted bugs" table above for the current count). The rows below add the fixtures
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
| ~~P-NEXT-CVE-RSC~~ | ~~`package.json` (`next@^14.2.5`)~~ | **RETIRED (#212) — it was a false positive.** The RSC-RCE advisory (GHSA-9qr9-h5gf-34mp) opens at `14.3.0-canary.77`, so no released 14.x is affected and the `< 14.2.35` boundary this row asserted was fabricated. Re-registered inverted as B10's `N-NEXT-RSC-14X-UNAFFECTED`. | — |
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
| P-ENV-COMMITTED (#130) | `.env:9,13` | gitleaks `supabase-service-role-jwt` (decoded claim) + `harvey-db-uri-credentials` (MongoDB URI), both on a committed **bare** `.env` (not `.env.local`) carrying multiple live-shaped secrets at once | high |

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
| N-ENV-EXAMPLE `[reused, also covers P-ENV-COMMITTED]` | `.env.example` | Documented placeholders, not secrets — already in the base corpus. Doubles as `P-ENV-COMMITTED`'s negative (a committed placeholder-only env file vs. the committed live-value `.env`) rather than duplicating a fixture; `P-ENV-COMMITTED`'s corpus entry uses the `.env:` location (colon included) specifically so it can't be cross-attributed a finding from `.env.example` or `.env.local`. |

**The former "Deferred to a later batch" row is now resolved:** `P-SECRET-GIT-HISTORY` is
resolved by #129 via a **dedicated validation path outside the CORPUS matrix above**, since
TruffleHog's git-history pass needs a clonable repo root and `targets/calibration` is a
subdirectory — see "Git-history secret gate (#129)" below. (`P-ENV-COMMITTED`, the B1 row's other
former deferral, is now built above as #130.)

### B1 live result (2026-07-09, static binaries: gitleaks 8.30.1, trufflehog 3.95.8, no Docker)

`pnpm validate:calibration`: **positives caught 27/27 static (12 at high/free-count), 1
connected-tier N/A; negatives cleared 19/19; zero free-count false positives — GATE PASS.** The 11
new B1 positives all fire (5 at high: the two decoded service_role claims, `sb_secret_`,
private-key, DB-URI; 6 at review: the unverifiable provider patterns). The 4 new negatives clear:
the publishable key and loopback DB URI are gitleaks-allowlisted (silent), the AWS example key is
stopword-allowlisted (silent), and the test-mode Stripe key draws a review hit only (triaged out).
TruffleHog contributes nothing (every planted key is a dead fake, `--only-verified`), exactly as
scored. `pnpm verify` (offline) is green via recorded gitleaks output in `calibration.test.ts`.

### Git-history secret gate (#129) — P-SECRET-GIT-HISTORY

TruffleHog's git-history pass (`trufflehog git`) only works against a clonable repo **root**;
`targets/calibration` is a subdirectory of this repo, so a fixture planted there is invisible to
that pass the way a real client repo's history would be. Instead of trying to force the class into
the subdirectory corpus, it gets its own validation path: `src/scan/git-history-secret-gate.ts`
builds a throwaway git repo in a temp dir **at runtime** (deterministic, no network —
`--no-verification` skips every live provider call, which a FAKE secret could never pass anyway),
commits a fake GitHub PAT then removes it in the next commit (still recoverable from history), and
commits+removes a benign non-secret value the same way. It's wired into `pnpm validate:calibration`
(runs after the main coverage matrix, folded into the same exit code) rather than duplicated as a
separate npm script — trufflehog is already a required binary for that command. Unit-tested
offline in `src/scan/git-history-secret-gate.test.ts`: the pure scoring function against recorded
TruffleHog output, and the fixture-building git plumbing itself (no trufflehog binary needed for
that half).

Live result (2026-07-10, trufflehog 3.95.9): `pnpm validate:calibration` — **P-SECRET-GIT-HISTORY
caught (1 hit, detector Github, recovered from the "add integration token" commit after the file
was removed at HEAD); N-GIT-HISTORY-BENIGN clear (0 hits on the benign add/remove) — GATE PASS.**

### Scan-scope guard (issue #101) — N-UNTRACKED-ENV

The mechanical scan used to walk the raw target directory, so a scan against a real *working
checkout* (not a clone) would pick up untracked/gitignored local artifacts — most credibility-fatal,
the operator's own `.env.local` — and hand them back as "Critical" findings. Fixed in
`src/scan/scan-scope.ts` / `src/scan/mechanical.ts`: when the target is a git repo, every
filesystem-walking tool (gitleaks, TruffleHog's filesystem pass, Semgrep, the leftover-auth walk,
OSV/lockfile reads) now runs against a scratch copy of the git-**tracked** files only
(`git ls-files`), not the raw directory. Untracked/gitignored files never reach the scratch copy.
The git-history TruffleHog pass is the one exception — it needs the real, clonable `.git`, so it
still points at the original directory (unaffected either way, since it already scans committed
history, not the working tree).

This is why this target's `.env.local` (tracked despite being listed in `.gitignore` — see
`git ls-files -- .env.local`) keeps working as B1's committed-secret positives while a genuinely
untracked `.env.local` would not: git tracking, not the filename, is what the scoping keys off.
**N-UNTRACKED-ENV** encodes that intent as a negative — "an untracked artifact must not be
scanned" — but can't be represented as a fixture *in this committed target* (a file can't be both
committed and untracked at once). It's verified at the logic/test layer instead:
`src/scan/scan-scope.test.ts` builds a throwaway git repo with a tracked file plus an untracked
`.env.local` and asserts the untracked file is excluded from the scoped copy (and, separately,
that a force-added-despite-gitignored fixture — mirroring this target's real `.env.local` — is
kept). The non-git (zip-export) fallback path is covered by the same test file: a hard exclude
list (`node_modules`, `.claude/`, `.next`, `dist`, `build`, `coverage`, worktree dirs) applies, but
`.env*` is deliberately NOT excluded there (no git history to distinguish a legitimately-committed
`.env` from a leaked working-tree one — best-effort only; git-clone access is preferred).

---

## Batch B2 (#71) — framework-CVE + supply-chain manifest hygiene

The framework-CVE / supply-chain expansion batch (spec `docs/design/spec-71-security-corpus.md`
§"Batch 4 — Framework CVEs & dependency version hygiene" + §"Batch 5 — Supply chain / manifest
hygiene"). Answer key: `src/scan/calibration/b2-deps.entries.ts`. Unlike the Semgrep batches (B3–B7),
**most of this batch's detection code already existed** — it was the *corpus* that lagged: the live
mechanical scan already produced these findings, but no gate row verified them. The base-batch dep
rows already ship (`[exists]`, `base.entries.ts`) and are not duplicated: `P-NEXT-CVE-29927`,
`P-DEP-CVE`, `P-SLOPSQUAT`, `P-POSTINSTALL`, `N-DEV-DEP` (plus `P-NEXT-CVE-RSC`, retired by #212 —
see §Base).

Tiering per the locked preamble: only the two deterministic-syntactic checks are `high` (free
count) — the exact CVE version-range match (WS-SSRF) and the unpinned-range check. The OSV-backed
cache-poisoning cluster, the offline edit-distance typosquat, and the non-registry-source check
stay `review` (a version match / edit-distance / git-source presence is not proof of
exploitability). One small new scanner ships with the batch: `checkNonRegistryDependencies`
(`src/scan/supply-chain.ts`), a deterministic manifest parse mirroring `checkUnpinnedDependencies`.

Fixtures added to `targets/calibration/package.json` (never installed — the manifest already can't
`npm install` because of the `react-supabase-helpers` slopsquat fixture): `expres` (a **real**,
published npm package one edit from `express`, so `checkSlopsquat`'s registry HEAD stays silent and
only the offline typosquat check fires) and `left-pad` pinned to a `git+https` URL (also a real npm
name, so slopsquat stays silent while `checkNonRegistryDependencies` fires).

### B2 positives — framework-CVE + manifest bugs (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-NEXT-CVE-WS-SSRF | `package.json` (`next@^14.2.5`) | `checkNextVersionCVEs` — CVE-2026-44578 range (>=13.4.13 <15.5.16, GHSA-c4j6-fc7j-m34r, CVSS 8.6) | high |
| P-UNPINNED-DEP | `package.json` (`^`-ranged deps) | `checkUnpinnedDependencies` — syntactic unpinned-range fact | high |
| P-NEXT-CVE-CACHE | `package-lock.json` (`next@14.2.35`) | OSV-Scanner — May-2026 cache-poisoning advisories (e.g. GHSA-wfc6-r584-vfw7); `parseOsvFindings` tiers every non-curated hit review | review |
| P-TYPOSQUAT | `package.json` (`expres`) | `checkTyposquat` — Levenshtein-1 from `express` (offline corpus match) | review |
| P-NONREGISTRY-DEP | `package.json` (`left-pad@git+https…`) | `checkNonRegistryDependencies` (new) — git/url/file dependency source | review |
| P-NEXT-EOL | `fixtures/legacy-app/package.json` (`next@12.3.5`) | `checkNextVersionCVEs` — EOL major (< 14.x); 12.3.5 sits at/above every curated fix for its major, so EOL is the sole finding | review |
| P-REACT-DOM-CVE | `fixtures/legacy-app/package.json` (`react-dom@16.4.0`) | `checkKnownDependencyCVEs` (new) — CVE-2018-6341 range (>=16.0.0 <16.4.2); approximate range (backported patches inside it) → review | review |
| P-DEP-CVE-CRITICAL | `fixtures/legacy-app/package.json` (`minimist@1.2.5`) | `checkKnownDependencyCVEs` (new) — CVE-2021-44906 (< 1.2.6, CVSS 9.8); crisp single-boundary range → the curated critical-CVE promotion path OSV lacked | high |
| P-MISSING-LOCKFILE | `fixtures/legacy-app` (no lockfile) | `checkLockfilePresence` — standalone project root shipping no lockfile | high |
| P-KNOWN-IOC-PKG | `fixtures/legacy-app/package.json` (`flatmap-stream@0.1.1`) | `checkKnownIoc` (new) — curated IOC-feed name match (2018 event-stream malware); slopsquat not re-run on the fixture | high |

### B2 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-DEP-PINNED | `package.json` (`lodash@4.17.11`) | Exact-pinned, registry-sourced — never appears in the SUP-UNPINNED or SUP-NON-REGISTRY evidence. The pinned-dep FP a naive "any dependency is unpinned" rule throws. Doubles as the registry-source negative for `P-NONREGISTRY-DEP`. Its OSV CVE finding lives at the lockfile location (not `package.json`), so it can't be mis-attributed here. |
| N-SLOPSQUAT-REAL | `package.json` (`@supabase/supabase-js`) | A real, popular, scoped package (exact-match in the typosquat popular set; a 200 from the slopsquat registry HEAD) — the FP a name-shape heuristic throws on a legitimate scoped dep. Draws no slopsquat/typosquat finding. |
| N-NEXT-SUPPORTED | `fixtures/supported-app/package.json` (`next@15.5.16`) | A current, fully-patched Next version — `checkNextVersionCVEs` draws nothing (no EOL, no 29927/RSC/WS-SSRF). The supported-version half of the EOL pair, resolved by living in its own fixture root. |
| N-POSTINSTALL-KNOWN | `fixtures/supported-app/package.json` (`esbuild@0.21.5`) | A hugely-popular package that famously runs a postinstall to fetch its native binary — exactly the trait a "has install scripts = suspicious" heuristic false-positives on. `checkKnownIoc` keys on the curated malware-name feed, not install-script presence, so esbuild clears. |

### B2 manifest-layout decision (the deferred rows' single-manifest conflict, resolved)

The main target has ONE `package.json`, pinned `next@^14.2.5` to drive the CVE positives, and MUST
keep its committed lockfile for `P-DEP-CVE`. Five deferred classes needed a manifest state that
conflicts with that single root: an EOL `next`, a supported `next`, a vulnerable `react-dom`, a
critical dependency CVE, and a project root that ships no lockfile. **Resolution:** two additional
STANDALONE project-root fixtures under `targets/calibration/fixtures/` — `legacy-app/` (vulnerable:
EOL next, vulnerable react-dom, critical minimist, IOC `flatmap-stream`, and NO lockfile) and
`supported-app/` (clean: supported next, patched react-dom, a legit-postinstall package, WITH a
committed lockfile). Each is its own root, not a monorepo sub-package — the main target's lockfile
would otherwise "cover" a sub-package and suppress `P-MISSING-LOCKFILE`.

The product scanner (`runMechanicalScan`) is unchanged: it still reads only the root manifest and
runs `checkLockfilePresence` root-scoped, so no monorepo false-positive risk is introduced. The
calibration runner (`src/cli/validate-calibration.ts`) additionally scans each fixture app-root with
the OFFLINE manifest checks only (`checkNextVersionCVEs`, `checkKnownDependencyCVEs`,
`checkKnownIoc`, `checkLockfilePresence`), each finding located by a stable `fixtures/<app>/…`
label. The network/binary passes (slopsquat, OSV, Semgrep, gitleaks) are deliberately NOT re-run on
the fixtures — those are already gated on the main target, and the classes here are all offline
manifest facts. `flatmap-stream` is declared as DATA ONLY (never installed/fetched); the fixtures
are never `npm install`-ed (no repo script or CI step installs `targets/calibration`).

Two new detections ship as genuine product checks (wired into `runMechanicalScan`'s root pass too,
where they stay silent on the clean root): `checkKnownDependencyCVEs` (curated non-Next CVE ranges,
`src/scan/dependencies.ts`) and `checkKnownIoc` (curated malware-name feed, `src/scan/supply-chain.ts`).

### B2 live result (2026-07-09, static binaries: semgrep 1.164.0, gitleaks 8.30.1, trufflehog 3.95.8, osv-scanner 2.3.8, no Docker)

Original batch — `pnpm validate:calibration`: **positives caught 77/77 static (25 at
high/free-count), 15 connected-tier N/A; negatives cleared 49/49; zero free-count false positives —
GATE PASS.** The 5 original B2 positives all fire (2 at high: the WS-SSRF version-range match and the
unpinned-range check; 3 at review: the OSV cache-poisoning cluster, the edit-distance typosquat, and
the non-registry git source). `pnpm verify` (offline) is green: `supply-chain.test.ts` gained two
unit tests for `checkNonRegistryDependencies`; the scorecard logic over the expanded `CORPUS` is
exercised in `calibration.test.ts` (including its synth-collision guard).

Deferred-rows follow-up (#71, secondary manifest fixtures) — `pnpm validate:calibration`:
**positives caught 82/82 static (28 at high/free-count), 15 connected-tier N/A; negatives cleared
51/51; zero free-count false positives — GATE PASS.** All 7 previously-deferred classes now land:
`P-NEXT-EOL` and `P-REACT-DOM-CVE` at review; `P-DEP-CVE-CRITICAL`, `P-MISSING-LOCKFILE`, and
`P-KNOWN-IOC-PKG` at high; `N-NEXT-SUPPORTED` and `N-POSTINSTALL-KNOWN` clear with no finding at all.
No regression on any prior batch (high-tier count moved 25 → 28). `pnpm verify` (offline) is green:
`dependencies.test.ts` gained tests for `checkKnownDependencyCVEs` (+ the manifest-path label and
the 12.3.5 EOL-only case), `supply-chain.test.ts` for `checkKnownIoc` and the lockfile label, and
`calibration.test.ts` gained a B2-deferred block that reconstructs the fixture findings from the
real detection functions and scores all seven entries.

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

---

## Batch B6 (#71) — JWT / crypto / randomness

The JWT/crypto expansion batch (spec `docs/design/spec-71-security-corpus.md` §"Batch 8 — JWT /
crypto / randomness"). Custom Semgrep rules in `src/scan/rules/semgrep/crypto.yml` (the per-batch
rule-file directory established by the Part-1 modularization). Tiering per the locked preamble:
only ~100%-precision sinks are `high` (free count) — an explicit `algorithms:['none']` JWT verify,
a weak hash (MD5/SHA-1) whose immediate input is named like a password/token/secret/signature (the
sink-gating signal that separates it from a non-security cache-key hash), a named-weak cipher
(DES/3DES/RC4/ECB), and an explicit `rejectUnauthorized: false`/`NODE_TLS_REJECT_UNAUTHORIZED=0`.
The rest (unverified `jwt.decode()`, a hardcoded/static IV, `Math.random()` feeding a
token/secret-named sink, a raw password column with no hash fn) stay `review` — each needs more
context than a static rule can see. `N-WEAK-HASH-CACHE` and `N-REDOS-SAFE` (the classic
MD5-as-cache-key and linear-regex-not-ReDoS lookalikes) already ship in the base corpus — B6 does
not duplicate them, and this batch's `harvey-weak-hash-security` rule is exercised against the
existing `lib/cache.js` fixture as its negative.

### B6 positives — planted JWT/crypto bugs (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-JWT-NONE-ALG | `lib/jwt.js:8` | Semgrep `harvey-jwt-none-alg` (literal `"none"` in the `jwt.verify` `algorithms` allowlist) | high |
| P-WEAK-HASH-SEC | `lib/pw.js:9` | Semgrep `harvey-weak-hash-security` (`crypto.createHash('md5').update($ARG)`, `$ARG` name-gated to password/pwd/secret/token/signature) | high |
| P-WEAK-HASH-SPLIT | `lib/pw-split.js:8` | Semgrep `harvey-weak-hash-security` split-statement form (`const digest = createHash('md5'); digest.update(password)`) — name-gated on the `.update()` arg (#988) | high |
| P-WEAK-CIPHER | `lib/crypto.js:8` | Semgrep `harvey-weak-cipher` (`createCipheriv('des-ede3-cbc', …)` — algorithm-literal regex: DES/3DES/RC2/RC4/Blowfish/*-ECB) | high |
| P-WEAK-CIPHER-ECB | `lib/crypto-ecb.js:8` | Semgrep `harvey-weak-cipher` on `createCipheriv('des-ede3-ecb', …)` — an ECB-mode algorithm outside the old explicit allowlist (#988) | high |
| P-TLS-VERIFY-DISABLED | `lib/http.js:6` | Semgrep `harvey-tls-verify-disabled` (`{ rejectUnauthorized: false }` / `NODE_TLS_REJECT_UNAUTHORIZED=0`) | high |
| P-JWT-DECODE-NOVERIFY | `middleware.ts:10` | Semgrep `harvey-jwt-decode-noverify` (`jwt.decode()` used to feed an authz decision — heuristic: flags every call) | review |
| P-STATIC-IV-SALT | `lib/static-iv.js:8` | Semgrep `harvey-static-iv` (`createCipheriv($ALGO, $KEY, Buffer.from($IV, …))` with `$IV` a string literal) | review |
| P-INSECURE-RANDOM | `lib/token.js:7` | Semgrep `harvey-insecure-random-token` (`Math.random()` inside a function named like token/secret/otp/session/password/reset) | review |
| P-PLAINTEXT-PASSWORD | `pages/api/register.js:7` | Semgrep `harvey-plaintext-password` (`.insert({ …, password: req.body.$K, … })`, no hash call) | review |

### B6 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-JWT-VERIFY-OK | `lib/jwt-safe.js` | `jwt.verify(token, key, { algorithms: ['RS256'] })` — signature checked, `'none'` not in the allowlist. (Named `jwt-safe.js`, not the spec's `lib/auth.js`, to avoid a location collision with `P-JWT-SIGNING-SECRET`'s existing fixture in `lib/auth.js`.) |
| N-RANDOM-NONSEC | `lib/ui.js` | `Math.random() * 100` inside `jitterDelay()` — a UI stagger delay; the function name doesn't match the token/secret/session/otp/password/reset gate. |
| N-SHA256-INTEGRITY | `lib/hash.js` | `crypto.createHash('sha256')` on a file buffer for an integrity checksum; `harvey-weak-hash-security` only matches md5/sha1. |
| N-TLS-VERIFY-ON | `lib/http-safe.js` | `new https.Agent()` with no override — `rejectUnauthorized` defaults to `true`. (Named `http-safe.js`, not the spec's `lib/http.js`, to avoid a location collision with `P-TLS-VERIFY-DISABLED`'s fixture already in `lib/http.js`.) |
| N-WEAK-HASH-CACHE `[reused from base corpus]` | `lib/cache.js` | MD5 as an ETag/cache-tag fingerprint (`.update(JSON.stringify(params))`) — `harvey-weak-hash-security`'s name-gate on the immediate hash input requires password/pwd/secret/token/signature; `params` doesn't match — cleared. |
| N-WEAK-HASH-CACHE-SPLIT | `lib/cache-split.js` | Same cache-key MD5 in SPLIT-statement form (`const h = createHash('md5'); h.update(JSON.stringify(params))`) — the split broadening (#988) is gated on a security-named `.update()` arg OR hash var; neither `h` nor `params` matches — cleared. |

### B6 live result (2026-07-09, static binaries: semgrep 1.164.0, gitleaks 8.30.1, trufflehog 3.95.8, osv-scanner 2.3.8, no Docker)

`pnpm validate:calibration`: **positives caught 47/47 static (19 at high/free-count), 1
connected-tier N/A; negatives cleared 29/29; zero free-count false positives — GATE PASS.** All 8
new B6 positives fire (4 at high: JWT `"none"` alg, name-gated weak-hash-in-security-sink,
named-weak cipher, disabled TLS verification; 4 at review: `jwt.decode()`, static IV, name-gated
insecure-random token, plaintext password). The 4 new negatives clear with no free-count finding,
and — the precision-critical check for this batch — `N-WEAK-HASH-CACHE` (the existing MD5-as-
cache-key fixture in `lib/cache.js`) stays clear too: `harvey-weak-hash-security`'s gate on the
immediate `.update()` argument's name (password/pwd/secret/token/signature) does not match
`JSON.stringify(params)`, confirming the sink-gating holds against the classic MD5-cache-key FP.
No regression on the base, B1, or B3 batches. `pnpm verify` (offline) is green: the scorecard logic
over the expanded CORPUS is exercised in `calibration.test.ts`; the Semgrep rules themselves are
proven by the live gate above.

---

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

## Batch B5 (#71) — headers / CORS / CSRF / transport / error-hygiene

The headers expansion batch (spec `docs/design/spec-71-security-corpus.md` §"Batch 6 — Headers /
CORS / CSRF / transport / error-hygiene"). Custom Semgrep rules in
`src/scan/rules/semgrep/headers.yml` (the per-batch rule-file directory established by the Part-1
modularization). Two rows already ship (`[exists]`) and are not duplicated here: `P-NO-CSP`
(`checkMissingCsp`, `src/scan/semgrep.ts`) and `P-CORS-WILDCARD` (`harvey-permissive-cors`,
`base.yml`); `P-OPEN-REDIRECT` (`[exists]`) is also part of this spec batch conceptually but ships
in the base corpus. Tiering per the locked preamble: only `harvey-cors-reflected-origin` and
`harvey-cookie-insecure` are ~100%-precision (`high`, free count); the rest are heuristic
presence/pattern checks (`review`).

Three of the new rules (`harvey-missing-hsts`/`-frame-options`/`-nosniff`) use the Semgrep
"pattern minus `pattern-not`, both with `...`" idiom to detect a `next.config.js` `headers()`
route object whose `headers:` array lacks a specific key — a genuine per-object-literal Semgrep
match rather than `checkMissingCsp`'s cross-file global-OR presence check, so the positive
(incomplete route) and negative (complete route) can coexist in the same `next.config.js` without
disturbing the existing `P-NO-CSP` fixture (which stays global: no `Content-Security-Policy`
string appears anywhere in `next.config.js`/`middleware.ts`/`vercel.json`). The CSP-unsafe-inline
positive/negative pair lives in `lib/security-headers.js` for the same reason — kept out of the
three files `checkMissingCsp` scans.

### B5 positives — planted header/CORS/CSRF/error bugs (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-CORS-REFLECT-ORIGIN | `middleware.ts:5` | Semgrep `harvey-cors-reflected-origin` (two-statement pattern: `Access-Control-Allow-Origin` set to `req.headers.get('origin')` verbatim, `Access-Control-Allow-Credentials: true` in the same function) | high |
| P-COOKIE-INSECURE | `pages/api/session.js:6` | Semgrep `harvey-cookie-insecure` (`Set-Cookie` value with zero semicolons — no attributes) | high |
| P-COOKIE-EXPRESS-INSECURE | `pages/api/cookie-express.js:7` | Semgrep `harvey-cookie-insecure-express` (`res.cookie(name, val, { maxAge })` — options omit HttpOnly/Secure/SameSite) (#988) | high |
| P-CSP-UNSAFE-INLINE | `lib/security-headers.js:9` | Semgrep `harvey-csp-unsafe-inline` (CSP header object; `metavariable-regex` requires `script-src`+`unsafe-inline`/`unsafe-eval`) | review |
| P-NO-HSTS | `next.config.js:13` | Semgrep `harvey-missing-hsts` (`{source, headers}` route object missing a `Strict-Transport-Security` element) | review |
| P-NO-FRAME-OPTIONS | `next.config.js:13` | Semgrep `harvey-missing-frame-options` (same route object, missing `X-Frame-Options`) | review |
| P-NO-NOSNIFF | `next.config.js:13` | Semgrep `harvey-missing-nosniff` (same route object, missing `X-Content-Type-Options`) | review |
| P-CSRF-MISSING | `app/actions.ts:6` | Semgrep `harvey-csrf-missing` (`'use server'` function calling `.delete()`/`.update()`, `pattern-not-inside` any `headers().get("origin")` call) | review |
| P-VERBOSE-ERROR | `pages/api/verbose.js:8` | Semgrep `harvey-verbose-error` (`err.stack`/`err.message` echoed into a JSON response) | review |
| P-DB-ERROR-DISCLOSURE | `pages/api/orders.js:6` | Semgrep `harvey-db-error-disclosure` (raw `error` identifier, the supabase-js destructure convention, echoed into a JSON response) | review |
| P-NODE-ENV-NOT-PROD | `lib/env.js:4` | Semgrep `harvey-node-env-not-prod` (`process.env.NODE_ENV = "development"` literal assignment) | review |

### B5 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-CORS-ALLOWLIST | `lib/cors-allowlist.js` | `Access-Control-Allow-Origin` is only ever set to a validated `origin` variable checked against an explicit allowlist, never directly to `req.headers.get("origin")` — `harvey-cors-reflected-origin`'s pattern requires that literal expression as the value. |
| N-COOKIE-SECURE | `pages/api/session-secure.js` | `Set-Cookie` value carries `HttpOnly; Secure; SameSite=Strict` (three semicolons) — `harvey-cookie-insecure` requires zero. |
| N-COOKIE-EXPRESS-SECURE | `pages/api/cookie-express-safe.js` | `res.cookie(name, val, { httpOnly: true, secure: true, sameSite: 'strict', … })` — `harvey-cookie-insecure-express`'s `pattern-not` excludes the fully-hardened form — cleared (#988). |
| N-CSP-PRESENT | `lib/security-headers.js` | `script-src 'self'` only, no `unsafe-inline`/`unsafe-eval` — `harvey-csp-unsafe-inline`'s `metavariable-regex` doesn't match. |
| N-HEADERS-VERCEL | `next.config.js` | a second `headers()` route sets HSTS + X-Frame-Options + nosniff together (modeled here rather than `vercel.json` so it's in the same Semgrep-scanned surface as the positives, avoiding a JSON-vs-JS language gap) — none of the three missing-header rules match it. |
| N-CSRF-ORIGIN-CHECKED | `app/actions.ts` | `updateAccountName()` checks `headers().get("origin")` against an allowlisted `APP_ORIGIN` before mutating — `harvey-csrf-missing`'s `pattern-not-inside` excludes it. |
| N-ERROR-GENERIC | `pages/api/orders-safe.js` | `res.status(500).json({ error: "Server error" })` — a literal string, not `.stack`/`.message` access or the raw `error` identifier; clears both `harvey-verbose-error` and `harvey-db-error-disclosure`. |
| N-NODE-ENV-PROD | `lib/env-check.js` | reads `process.env.NODE_ENV` in a conditional, never assigns it — `harvey-node-env-not-prod` only matches a literal assignment. |

Four of the negatives above (`N-CSP-PRESENT`, `N-HEADERS-VERCEL`, `N-CSRF-ORIGIN-CHECKED`, and
partially `N-CORS-ALLOWLIST` via an unrelated registry-pack hit) share a fixture file with a B5
positive; each carries a `match` keyword disjoint from its sibling positive's rule-id keyword
(guarded by `calibration.test.ts`'s "keeps fixtures that share a file apart" collision test) so
they can't be cross-attributed a finding that belongs to the positive.

### B5 live result (2026-07-09, static binaries: semgrep 1.164.0, no Docker)

`pnpm validate:calibration`: **positives caught 49/49 static (17 at high/free-count), 1
connected-tier N/A; negatives cleared 32/32; zero free-count false positives — GATE PASS.** The 10
new B5 positives all fire (2 at high: reflected-origin CORS, bare `Set-Cookie`; 8 at review: the
missing-header/CSRF/error-disclosure/dev-mode heuristics). The 7 new negatives clear with no
free-count finding; one (`N-CORS-ALLOWLIST`) draws an unrelated `p/owasp-top-ten` registry-pack
hit at review tier (a known third-party heuristic FP on any `Access-Control-Allow-Origin` set from
a request-derived variable, regardless of the allowlist check) — correctly triaged out, not a gate
failure. No regression on the base, B1, or B3 batches. `pnpm verify` (offline) is green: the
scorecard logic over the expanded CORPUS is exercised in `calibration.test.ts`, including the
file-sharing collision guard; the Semgrep rules themselves are proven by the live gate above.

---

## Batch B8 (#71) — Supabase connected config

The connected-tier slice of the #71 corpus (spec `docs/design/spec-71-security-corpus.md`
§"Batch 10 — Supabase project config"). Every row here is `expectedTier: "connected"`: it needs a
**live** Supabase project (`get_advisors`, Management API config reads, `list_extensions`) to
confirm. `buildCoverageMatrix` (`src/scan/calibration.ts`) scores every `connected` entry N/A —
pass, regardless of what a static run produces — so this batch can never regress the free-count
gate. **This PR was built and validated OFFLINE only**: fixtures + the calibration answer key +
recorded-advisor-JSON parsing tests (mirroring how `supabase-advisors.test.ts` / `supabase.test.ts`
already mock the Advisor/Management API output). **Live confirmation against a running project —
actually starting the local stack or a hosted project and running `get_advisors` for real — is a
deferred main-session pass with Docker,** not done here.

Detection code for all seven advisor lints named below already existed before this batch:
`parseAdvisorFindings` (`src/scan/supabase-advisors.ts`) maps ANY lint name through
`CURATED_SEVERITY`, which already carried `rls_disabled_in_public`, `rls_enabled_no_policy`,
`auth_users_exposed`, `security_definer_view`, `function_search_path_mutable`,
`rls_references_user_metadata`, and `sensitive_columns_exposed`. Storage/auth-config/extension
checks (`checkPublicBucketsWithNoPolicies`, `checkAuthConfig`, `checkDangerousExtensions` in
`src/scan/supabase-config.ts`) were also already wired. So B8 adds fixtures + calibration rows +
more recorded-JSON test cases, not new detection code — no lint needed extending.

Fixtures: `supabase/migrations/20260709000004_b8_connected_advisors.sql` (schema-level lints) and
`supabase/config.toml` (Auth config + declarative Storage buckets — commented and marked
`BUG (PLANTED, connected/B8)` inline). `P-LEAKED-PW-OFF` (leaked-password/HIBP protection) has no
local-fixture equivalent — it's a hosted-project-only Auth setting with no `config.toml` field, so
it's confirmed purely via a live Management API config read; `checkAuthConfig` already handles it
and is unit-tested against a recorded response.

### B8 positives — planted connected-tier bugs (must be caught on a live advisor run)

| id | location | detection | tier |
|---|---|---|---|
| P-RLS-DISABLED `[exists, =#3]` | `supabase/migrations/…_rls.sql` (`audit_logs`) | Splinter `0013 rls_disabled_in_public` | connected |
| P-RLS-ENABLED-NO-POLICY | `public.reports` | Splinter `rls_enabled_no_policy` — RLS on, zero policies, on a table meant to be tenant-readable (contrast the deny-all-by-design `N-RLS-DENY-ALL` negative) | connected |
| P-AUTH-USERS-EXPOSED | `public.user_directory` | Splinter `auth_users_exposed` — a view selecting from `auth.users`, granted to `anon`/`authenticated` | connected |
| P-SECDEF-VIEW | `public.tenant_totals` | Splinter `security_definer_view` — no `security_invoker = true`, runs as owner, bypasses `invoices` RLS | connected |
| P-FN-SEARCH-PATH | `public.get_invoice_total` | Splinter `function_search_path_mutable` — no `set search_path` | connected |
| P-RLS-USER-META | `public.internal_notes` | Splinter `rls_references_user_metadata` — policy trusts the self-editable `user_metadata` JWT claim | connected |
| P-SENSITIVE-COLS | `public.support_tickets` (`customer_ssn`) | Splinter `sensitive_columns_exposed` — known-sensitive column name exposed via PostgREST | connected |
| P-STORAGE-PUBLIC | `[storage.buckets.avatars]` (`config.toml`) | `checkPublicBucketsWithNoPolicies` — `public=true`, zero `storage.objects` policies scoped to it | connected |
| P-LEAKED-PW-OFF | Auth config (live-only, no local fixture) | `checkAuthConfig` — `password_hibp_enabled=false` | connected |
| P-EMAIL-CONFIRM-OFF | `[auth.email] enable_confirmations` (`config.toml`) | `checkAuthConfig` — email confirmation disabled | connected |
| P-OTP-LONG-EXPIRY | `[auth.email] otp_expiry = 86400` (`config.toml`) | `checkAuthConfig` — OTP expiry past the 3600s baseline | connected |
| P-OAUTH-REDIRECT-WILD | `[auth] additional_redirect_urls` (`config.toml`, `"*"`) | `checkAuthConfig` — wildcard redirect allowlist | connected |
| P-PGNET-SSRF | `public.fetch_webhook_preview` (+ `pg_net` extension) | `checkDangerousExtensions` — `pg_net` enabled and callable via a `SECURITY DEFINER` RPC with a caller-supplied URL | connected |

### B8 negatives — benign lookalikes (must NOT be flagged live)

| id | location | why benign / suppression |
|---|---|---|
| N-RLS-DENY-ALL `[exists]` | `public.service_state` | RLS on + zero policies = deny-all by design on a service-role-only table — reused unchanged as the `P-RLS-ENABLED-NO-POLICY` lookalike. |
| N-DEFINER-SCOPED | `public.current_tenant_id` | `SECURITY DEFINER` + `set search_path = public` + scoped by `auth.uid()` — the correct pattern; contrasts `P-FN-SEARCH-PATH`. |
| N-STORAGE-PRIVATE | `[storage.buckets.invoices-private]` (`config.toml`) | `public=false` — `checkPublicBucketsWithNoPolicies` filters on `public=true` first; contrasts `P-STORAGE-PUBLIC`. |

### B8 offline result (2026-07-08, no Docker — live advisor confirmation deferred)

No binary or live project was run for this batch. What WAS validated offline:
`parseAdvisorFindings` was exercised against recorded advisor JSON fixtures covering all seven
lint names above (`supabase-advisors.test.ts`), confirming the existing `CURATED_SEVERITY` map
produces the expected severity for each; `checkAuthConfig` was exercised against the exact
planted config shape (`otp_expiry: 86400`, a wildcard `uri_allow_list`) and `checkDangerousExtensions`
against `pg_net` (`supabase-config.test.ts`). `pnpm validate:calibration` (static gate, run in this
environment against the real installed binaries — semgrep, gitleaks, trufflehog, osv-scanner; no
Docker/live DB involved): **positives caught 63/63 static (24 at high/free-count), 15
connected-tier N/A; negatives cleared 39/39; zero free-count false positives — GATE PASS.** All 12
new B8 positives and 2 new B8 negatives report **N/A — connected tier, not evaluated statically**,
as designed — zero effect on the static free-count gate (the 63/63 and 39/39 totals and the 24
high-tier count are unchanged from the pre-B8 baseline; only the connected-tier N/A count moved
from 1 to 15). **Live confirmation — actually running `get_advisors` against a started local or
hosted project — is a deferred main-session pass with Docker.**

---

## Batch B9 (#71) — secrets & config-secret breadth

The secrets/config-secret expansion batch (spec `docs/design/corpus-roadmap-to-100.md` §3a). Answer
key: `src/scan/calibration/b9-secrets.entries.ts`. Extends the EXISTING secret scanners — no new
scanner: custom gitleaks rules in `src/scan/rules/gitleaks-supabase.toml`, three structural Semgrep
rules in `src/scan/rules/semgrep/secrets.yml`, and the high-precision rule set in `src/scan/secrets.ts`.
All planted secret values are FAKE (valid-shape, inert). Tiering per the locked preamble: only
~100%-precision detections are `high` (free count) — a dedicated-format prefix, a published constant,
or a structural sink whose match alone is proof. Provider-key patterns that only live verification
would confirm (the fake `AIza` key, the committed storage JWT) stay `review`, as does the
secret-in-URL heuristic.

### B9 positives — planted secrets/config-secrets (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-NEXTCONFIG-ENV-SECRET | `next.config.js` (`env:{SUPABASE_SERVICE_ROLE_KEY}`) | Semgrep `harvey-nextconfig-env-secret` (secret-named key whose value is a `process.env` read, scoped inside an `env` block) | high |
| P-SB-DEFAULT-JWT-SECRET | `supabase/docker.env` (`JWT_SECRET=your-super-secret-jwt-token-…`) | gitleaks custom `supabase-default-jwt-secret` (exact published self-hosted default string) | high |
| P-NPM-TOKEN-COMMITTED | `.npmrc` (`_authToken=npm_…`) | gitleaks default `npm-access-token`, promoted to high in `secrets.ts` (dedicated `npm_`+36 token format) | high |
| P-GCP-SA-JSON | `secrets/gcp-service-account.json` | gitleaks `private-key` (the `-----BEGIN PRIVATE KEY-----` body of the service-account file) | high |
| P-SLACK-WEBHOOK-URL | `lib/notify.js` | gitleaks default `slack-webhook-url`, promoted to high in `secrets.ts` (`hooks.slack.com/workflows/…`; the `/workflows/` path keeps the fixture inert to GitHub push protection's `/services/` incoming-webhook pattern) | high |
| P-URI-CREDS-NONPG | `lib/mailer.js` (`smtp://user:pw@host`) | gitleaks custom `harvey-uri-credentials` (non-DB schemes; loopback + `${env}` excluded) | high |
| P-EDGEFN-SECRET | `supabase/functions/send-email/index.ts` | Semgrep `harvey-edgefn-secret-fallback` (`Deno.env.get(...) ?? "literal"`) | high |
| P-DB-WEBHOOK-SECRET-SQL | `supabase/migrations/20260709000005_b9_db_webhook.sql` | gitleaks custom `harvey-http-authorization-bearer` (24+ char literal after `Bearer`) | high |
| P-GCP-API-KEY | `lib/maps.js` (`AIza…`) | gitleaks custom `harvey-gcp-api-key` (default ruleset ships no working AIza rule this version) | review |
| P-SECRET-IN-URL | `lib/weather.js` (`?api_key=${KEY}`) | Semgrep `harvey-secret-in-url-param` (secret-bearing query param) | review |
| P-SIGNED-URL-TOKEN-SRC | `lib/share.js` (`…/sign/…?token=eyJ…`) | gitleaks default `jwt` (payload decodes to a benign storage claim, not `service_role`) | review |

### B9 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-NEXTCONFIG-ENV-BENIGN | `next.config.js` (`APP_VERSION`) | A non-secret build constant in the same `env` block — the rule's key-name regex doesn't match it. |
| N-SB-JWT-ROTATED | `supabase/docker.env` (`ANON_JWT_SECRET=<random>`) | A rotated random secret is NOT the published default string; `supabase-default-jwt-secret` stays silent (a generic-api-key review hit only, triaged out). |
| N-NPM-TOKEN-ENV | `.npmrc` (`${NPM_TOKEN}`) | Token sourced from the environment — no literal, `npm-access-token` matches nothing. |
| N-GCP-SA-EXAMPLE | `secrets/gcp-service-account.json.example` | `<YOUR_PRIVATE_KEY>` placeholder, no PEM block — `private-key` silent; only a LOW-confidence semgrep review hit (triaged out). |
| N-SLACK-WEBHOOK-PLACEHOLDER | `lib/notify.js` (`<WEBHOOK_TOKEN>`) | Angle-bracketed placeholder; `slack-webhook-url` needs a real 24-char token segment. |
| N-URI-CREDS-ENV | `lib/mailer.js` (`${SMTP_PASSWORD}`) | Env-interpolated password; the rule's char class excludes `${ }`. |
| N-EDGEFN-SECRET-THROWS | `supabase/functions/send-email-safe/index.ts` | Reads env and throws when absent — no string-literal fallback for the rule to match. |
| N-DB-WEBHOOK-SECRET-SETTING | `…/20260709000005_b9_db_webhook.sql` | Header built from `current_setting(...)` — no committed literal after `Bearer`. |
| N-GCP-KEY-ENV | `lib/maps.js` (`process.env.GOOGLE_MAPS_API_KEY`) | No `AIza` literal in source. |
| N-SECRET-IN-HEADER | `lib/weather.js` (Authorization header) | Secret sent in a header, no secret-bearing query param — the URL regex doesn't match. |
| N-SIGNED-URL-PLACEHOLDER | `lib/share.js` (`<SIGNED_URL_TOKEN>`) | Angle-bracketed placeholder, not a JWT. |
| N-BCRYPT-HASH-SEED | `supabase/seed.sql` (`$2b$…`) | A bcrypt digest in seed data is a one-way hash of a throwaway dev password, not a secret — free-count FP guard. semgrep's `detected-bcrypt-hash` fires only at LOW confidence → review, triaged out; never high. |

### B9 detection additions

Custom gitleaks rules (`src/scan/rules/gitleaks-supabase.toml`): `supabase-default-jwt-secret`,
`harvey-uri-credentials` (non-DB URI creds), `harvey-http-authorization-bearer`, `harvey-gcp-api-key`.
Two gitleaks DEFAULT rules were promoted to the high-precision set in `src/scan/secrets.ts`
(`npm-access-token`, `slack-webhook-url`) alongside the three new high custom rules. Structural
Semgrep rules (`src/scan/rules/semgrep/secrets.yml`): `harvey-nextconfig-env-secret` and
`harvey-edgefn-secret-fallback` (both ERROR + HIGH → high), `harvey-secret-in-url-param`
(WARNING + MEDIUM → review). No product scanner module was added; `supabase-config.ts`'s
live-input edge/webhook checks are unchanged (they run on a connected pull, not the static gate) —
the edge-function/DB-webhook classes here are caught statically by the Semgrep/gitleaks passes that
`validate-calibration.ts` actually runs. The Edge Function fixtures are inert source files, never
deployed; the migration/seed SQL is data only, never applied to any database.

### B9 live result (2026-07-09, static binaries: semgrep 1.164.0, gitleaks 8.30.1, trufflehog 3.95.8, osv-scanner 2.3.8, no Docker)

`pnpm validate:calibration`: **positives caught 93/93 static (36 at high/free-count), 15
connected-tier N/A; negatives cleared 63/63; zero free-count false positives — GATE PASS.** All 11
B9 positives fire (8 at high: the next.config env-inlining, the default JWT secret, the npm token,
the GCP service-account private key, the Slack webhook, the SMTP URI creds, the Edge Function
literal fallback, the DB-webhook bearer literal; 3 at review: the fake AIza key, the secret-in-URL
param, the committed storage JWT). All 12 B9 negatives clear (the high-tier count moved 28 → 36; no
regression on any prior batch). `pnpm verify` (offline) is green: `calibration.test.ts` gained a B9
recorded block that feeds recorded gitleaks + semgrep output through the real tier mapping and
scores all B9 entries (8 high / 3 review), plus the whole-CORPUS synth collision guard covers the
new locations.

---

## Batch B10 (#71) — dependency-CVE & framework-version breadth

The dependency-CVE expansion batch (spec `docs/design/corpus-roadmap-to-100.md` §3b). Answer key:
`src/scan/calibration/b10-deps.entries.ts`. **Extends the curated offline CVE ranges — no new
scanner:** one new row inside `checkNextVersionCVEs` (the Next Server Actions null-origin CSRF) and
nine new entries in `CURATED_DEP_CVES` (`src/scan/dependencies.ts`). Every one is a crisp single
`< fixed` boundary (some scoped to a major line via `introduced` where older majors carry their own
fix), so all ten land `high`. Determinism is offline: these fire from the DECLARED manifest range via
`checkNextVersionCVEs` / `checkKnownDependencyCVEs`, independent of OSV's DB — `pnpm verify` stays
green with no network.

Modelled with the B2 secondary-manifest mechanism: three STANDALONE fixture app-roots under
`targets/calibration/fixtures/`, scanned offline by `validate-calibration.ts`'s `scanManifestFixtures`
(the network/binary passes are NOT re-run — these are all offline manifest facts). All versions are
declared as DATA ONLY and never installed.

- `b10-vuln-deps/` — vulnerable pins (WITH an inert lockfile so `checkLockfilePresence` stays silent).
- `b10-nextauth-csrf/` — the OAuth-CSRF `next-auth@4.19.0`, isolated in its own root because it
  can't share `b10-vuln-deps`'s email-misdelivery `next-auth@4.24.5` (one manifest declares
  `next-auth` once).
- `b10-patched-deps/` — patched counterparts; must draw NOTHING.

### B10 positives — vulnerable-version pins (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-NEXT-CVE-NULLORIGIN | `fixtures/b10-vuln-deps/package.json` (`next@16.0.5`) | `checkNextVersionCVEs` — CVE-2026-27978 Server Actions null-origin CSRF (>=16.0.1 <16.1.7, GHSA-mq59-m269-xvcx). 16.0.5 also (correctly) trips the RSC-RCE + WS-SSRF ranges; isolated by the `27978` keyword. Carried a descriptive id until #212's OSV check found the real CVE | high |
| P-JSONWEBTOKEN-CVE | `fixtures/b10-vuln-deps/package.json` (`jsonwebtoken@8.5.1`) | `checkKnownDependencyCVEs` — CVE-2022-23540 (<9.0.0, `jwt.verify` alg-confusion, GHSA-qwph-4952-7xr6) | high |
| P-NEXTAUTH-CSRF-CVE | `fixtures/b10-nextauth-csrf/package.json` (`next-auth@4.19.0`) | `checkKnownDependencyCVEs` — CVE-2023-27490 (4.x line <4.20.1, OAuth CSRF, GHSA-7r7x-4c4q-c4qf). Co-fires the email class; matched by CVE id | high |
| P-NEXTAUTH-EMAIL-CVE | `fixtures/b10-vuln-deps/package.json` (`next-auth@4.24.5`) | `checkKnownDependencyCVEs` — GHSA-5jpx-9hw9-2fx4 (4.x line <4.24.12, email-signin misdelivery). 4.24.5 is above the CSRF fix, so it fires ONLY this class | high |
| P-FOLLOW-REDIRECTS-CVE | `fixtures/b10-vuln-deps/package.json` (`follow-redirects@1.15.4`) | `checkKnownDependencyCVEs` — CVE-2024-28849 (<1.15.6, Proxy-Authorization not cleared on cross-origin redirect) | high |
| P-AXIOS-SSRF-CVE | `fixtures/b10-vuln-deps/package.json` (`axios@1.7.2`) | `checkKnownDependencyCVEs` — CVE-2025-27152 (1.x line <1.8.2, absolute-URL baseURL SSRF, GHSA-jr5f-v2jv-69x6) | high |
| P-UNDICI-CVE-CLUSTER | `fixtures/b10-vuln-deps/package.json` (`undici@5.7.0`) | `checkKnownDependencyCVEs` — TWO CVEs from one pin: CVE-2022-35949 (pathname SSRF, <5.8.2) + CVE-2024-24758 (Proxy-Auth cross-origin leak, <5.28.3) | high |
| P-COOKIE-PKG-CVE | `fixtures/b10-vuln-deps/package.json` (`cookie@0.5.0`) | `checkKnownDependencyCVEs` — CVE-2024-47764 (<0.7.0, out-of-bounds chars → field injection) | high |
| P-WS-REDOS-CVE | `fixtures/b10-vuln-deps/package.json` (`ws@7.4.5`) | `checkKnownDependencyCVEs` — CVE-2021-32640 (7.x line <7.4.6, `Sec-WebSocket-Protocol` ReDoS, GHSA-6fc8-4gx4-v693). Matched by CVE id (not `ws`, a substring of the co-firing next WS-SSRF finding) | high |
| P-SHARP-LIBWEBP-CVE | `fixtures/b10-vuln-deps/package.json` (`sharp@0.31.3`) | `checkKnownDependencyCVEs` — CVE-2023-4863 (<0.32.6, bundled libwebp <1.3.2 heap overflow, GHSA-54xq-cgqr-rpm3) | high |

### B10 negatives — patched-version pins (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-NEXT-NULLORIGIN-PATCHED | `fixtures/b10-patched-deps/package.json` (`next@16.2.5`) | Above the CVE-2026-27978 null-origin fix (16.1.7) AND the overlapping WS-SSRF range (<16.2.5), so `checkNextVersionCVEs` draws nothing — the truly-clean patched next-16. A bare 16.1.7 would still carry a WS-SSRF high, so 16.2.5 is the correct clean negative for the whole next-16 CVE set. |
| N-NEXT-RSC-14X-UNAFFECTED | `fixtures/b10-next14-rsc/package.json` (`next@14.2.35`) | **The #212 regression guard.** GHSA-9qr9-h5gf-34mp's ranges open at `14.3.0-canary.77`, so no RELEASED 14.x is affected by the RSC RCE. This shipped inverted — as base-batch positive `P-NEXT-CVE-RSC` at `high`, against a fabricated `14.2.35` fix — so every `next@14.2.x` target took a Critical FP. Needs its own fixture root: the root target's `next@^14.2.5` shares the bare location `next` with the B10 manifests' genuine RSC findings, which a substring match can't separate. 14.2.35 still (correctly) draws the WS-SSRF high; the `55182` keyword isolates the retired class. |
| N-JSONWEBTOKEN-PATCHED | `…/package.json` (`jsonwebtoken@9.0.2`) | At/above the 9.0.0 fix — outside the CVE-2022-23540 range. |
| N-NEXTAUTH-PATCHED | `…/package.json` (`next-auth@4.24.12`) | At/above both fixes (4.20.1 OAuth-CSRF, 4.24.12 email) — clears both classes with one patched pin. |
| N-FOLLOW-REDIRECTS-PATCHED | `…/package.json` (`follow-redirects@1.15.6`) | At the fix — outside CVE-2024-28849. |
| N-AXIOS-PATCHED | `…/package.json` (`axios@1.8.2`) | At the fix — outside CVE-2025-27152. |
| N-UNDICI-PATCHED | `…/package.json` (`undici@5.28.3`) | At/above both cluster fixes (5.8.2 SSRF, 5.28.3 header-leak) — clears the whole cluster. |
| N-COOKIE-PATCHED | `…/package.json` (`cookie@0.7.0`) | At the fix — outside CVE-2024-47764. |
| N-WS-PATCHED | `…/package.json` (`ws@7.4.6`) | At the fix — outside CVE-2021-32640. |
| N-SHARP-PATCHED | `…/package.json` (`sharp@0.32.6`) | At the fix (bundles libwebp >= 1.3.2) — outside CVE-2023-4863. |

### B10 dropped class — P-MINIMIST-PROTO-CVE (roadmap §3b, review)

Dropped as **already covered**. It is the SAME CVE-2021-44906 / `minimist < 1.2.6` range already
landed at `high` by B2's `P-DEP-CVE-CRITICAL` (`checkKnownDependencyCVEs`). Re-landing it would
duplicate that exact finding; re-tiering minimist to `review` would regress the shipped high
positive; and the dev-only-transitive "clears" half the roadmap notes (`N-DEV-DEP` guard) is already
modelled by the existing `N-DEV-DEP` negative (`webpack@4.42.0`, dev-only, cleared). The curated
check has no dev/prod distinction that would make this a distinct class, so it adds no coverage.

### B10 live result (2026-07-09, static binaries: semgrep 1.164.0, gitleaks 8.30.1, trufflehog 3.95.8, osv-scanner 2.3.8, no Docker)

`pnpm validate:calibration`: **GATE PASS — zero free-count false positives; every high-tier rule
fired on its positive.** All 10 B10 positives land at high (the null-origin CSRF row; the eight
single-CVE curated ranges; the two-CVE undici cluster from one pin) and all 9 B10 negatives clear
(the patched fixture draws nothing at all). No regression on any prior batch. `pnpm verify` (offline)
is green: `dependencies.test.ts` gained the null-origin range tests and a parametrized block over the
nine new curated CVEs (+ the undici two-CVE cluster and the ws 7.x-scoping guard); `calibration.test.ts`
gained a B10 block that reconstructs the fixture findings from the real check functions and scores all
19 entries, and the whole-CORPUS synth-collision guard covers the new fixture locations.

---

## Batch B11 (#71) — crypto-API misuse & JWT-verify options

The crypto-API / JWT-verify-options expansion batch (spec `docs/design/corpus-roadmap-to-100.md`
§3c). Answer key: `src/scan/calibration/b11-crypto.entries.ts`. **Extends the EXISTING per-batch
Semgrep rule file `src/scan/rules/semgrep/crypto.yml` — no new scanner.** Tiering per the locked
preamble: only exact-API / unambiguous-literal sinks are `high` (free count) — the no-IV
`createCipher`/`createDecipher` API, `crypto.pseudoRandomBytes()`, a 2-argument `jwt.verify()` with
no `algorithms` allowlist, an explicit `{ ignoreExpiration: true }`, and a `ws://` WebSocket URL.
The absence-of-X / heuristic sinks (a GCM decipher with no `authTagLength`, an AEAD decipher that
returns `update()` with no `final()`, an unverified client-side `jwtDecode()` render sink, a
hardcoded HMAC key literal) stay `review`. All fixtures are inert source files.

Two adjacencies flagged in the spec were kept from double-firing: `harvey-jwt-decode-render` matches
only the client `jwt-decode` package's `jwtDecode()`/`jwt_decode()` (the server-side `jwt.decode()`
stays with B6's `harvey-jwt-decode-noverify`), and `harvey-hmac-hardcoded-key` fires on the
`createHmac` literal-key SINK (the gitleaks `JWT_SIGNING_SECRET` rule catches the secret's
declaration) — the existing `createHmac(..., process.env.WEBHOOK_SECRET)` in `pages/api/webhook.js`
is env-keyed and stays silent.

### B11 positives — planted crypto/JWT bugs (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-CIPHER-NO-IV | `lib/cipher-noiv.js:9` | Semgrep `harvey-crypto-createcipher` (`crypto.createCipher(...)` / `createDecipher(...)` — the no-IV API) | high |
| P-PSEUDORANDOM-BYTES | `lib/pseudorandom.js:8` | Semgrep `harvey-crypto-pseudorandombytes` (`crypto.pseudoRandomBytes(...)`, a non-CSPRNG alias) | high |
| P-JWT-VERIFY-NOALG | `lib/jwt-verify-noalg.js:8` | Semgrep `harvey-jwt-verify-noalg` (2-arg `jwt.verify($T, $K)` — no algorithms allowlist) | high |
| P-JWT-IGNORE-EXP | `lib/jwt-ignore-exp.js:8` | Semgrep `harvey-jwt-ignore-exp` (literal `ignoreExpiration: true`) | high |
| P-INSECURE-WS-URL | `lib/ws-client.js:6` | Semgrep `harvey-insecure-ws-url` (`new WebSocket($URL)`, `$URL` anchored to `^ws://`) | high |
| P-GCM-NO-TAGLEN | `lib/gcm-notag.js:8` | Semgrep `harvey-gcm-no-authtaglength` (3-arg `createDecipheriv` with a `gcm` algo — no options object) | review |
| P-AEAD-NO-FINAL | `lib/aead-nofinal.js:9` | Semgrep `harvey-aead-decipher-no-final` (returns `$D.update(...)` with no `$D.final()`; AEAD algo) | review |
| P-JWT-DECODE-RENDER | `components/RoleBadge.jsx:11` | Semgrep `harvey-jwt-decode-render` (`jwtDecode()`/`jwt_decode()` — client `jwt-decode` package) | review |
| P-HMAC-HARDCODED-KEY | `lib/sign.js:9` | Semgrep `harvey-hmac-hardcoded-key` (`createHmac($ALGO, $KEY)`, `$KEY` a string literal) | review |

### B11 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-CIPHER-IV-OK | `lib/cipher-iv.js` | `createCipheriv('aes-256-ctr', key, crypto.randomBytes(16))` — the correct IV-taking API; `harvey-crypto-createcipher` matches only `createCipher`/`createDecipher`, and `aes-256-ctr` is not a weak cipher. |
| N-RANDOMBYTES-OK | `lib/randombytes.js` | `crypto.randomBytes(16)` — the CSPRNG; `harvey-crypto-pseudorandombytes` matches only the `pseudoRandomBytes` alias. |
| N-JWT-VERIFY-ALGS | `lib/jwt-verify-checked.js` | `jwt.verify(t, KEY, { algorithms:['HS256'], issuer:'harvey' })` — the safe counterpart for BOTH verify-option classes: `harvey-jwt-verify-noalg` fires only on the 2-arg form, `harvey-jwt-ignore-exp` needs `ignoreExpiration: true` (absent). |
| N-WSS-SECURE | `lib/ws-secure.js` | `new WebSocket('wss://…')` — `harvey-insecure-ws-url` is anchored to `^ws://`; the extra `s` of `wss://` doesn't match. |
| N-GCM-TAGLEN-OK | `lib/gcm-tag.js` | `createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 })` + `setAuthTag` + `.final()` — the safe counterpart for BOTH AEAD classes: the 4-arg options form clears `harvey-gcm-no-authtaglength`, and the `.final()` call clears `harvey-aead-decipher-no-final`. |
| N-JWTDECODE-SERVER | `components/RoleBadgeSafe.jsx` | `session.role` from a signature-verified server session prop — no `jwtDecode()` call for `harvey-jwt-decode-render` to match. |
| N-HMAC-KEY-ENV | `lib/sign-env.js` | `createHmac('sha256', process.env.HMAC_SIGNING_KEY)` — `harvey-hmac-hardcoded-key`'s key regex matches a string literal only, not a `process.env` read. |

### B11 detection additions

Nine new rules in `src/scan/rules/semgrep/crypto.yml`: five ERROR + HIGH → high
(`harvey-crypto-createcipher`, `harvey-crypto-pseudorandombytes`, `harvey-jwt-verify-noalg`,
`harvey-jwt-ignore-exp`, `harvey-insecure-ws-url`) and four WARNING + MEDIUM → review
(`harvey-gcm-no-authtaglength`, `harvey-aead-decipher-no-final`, `harvey-jwt-decode-render`,
`harvey-hmac-hardcoded-key`). No product scanner module was added. No class was dropped — all nine
§3c rows landed (the two flagged adjacencies were disambiguated rather than dropped).

### B11 live result (2026-07-09, static binaries: semgrep 1.164.0, gitleaks 8.30.1, trufflehog 3.95.8, osv-scanner 2.3.8, no Docker)

`pnpm validate:calibration`: **GATE PASS — zero free-count false positives; every high-tier rule
fired on its positive.** All 9 B11 positives fire (5 at high: no-IV `createCipher`,
`pseudoRandomBytes`, 2-arg `jwt.verify`, `ignoreExpiration:true`, `ws://` URL; 4 at review: GCM
no-authTagLength, AEAD no-`final()`, client `jwtDecode()` render sink, hardcoded HMAC key) and all 7
B11 negatives clear with no free-count finding. Whole-corpus totals: **positives caught 112/112
static (51 at high/free-count, up 46 → 51), 15 connected-tier N/A; negatives cleared 79/79; zero
free-count false positives.** No regression
on any prior batch — in particular `harvey-jwt-verify-noalg`'s 2-arg pattern does not fire on the
existing 3-arg `lib/jwt.js`/`lib/jwt-safe.js` verifies, and `harvey-hmac-hardcoded-key` stays silent
on the env-keyed `createHmac` in `pages/api/webhook.js`. `pnpm verify` (offline) is green:
`calibration.test.ts` gained a B11 recorded-semgrep block that feeds the recorded findings through
the real tier mapping and scores all 16 entries (5 high / 4 review positives + 7 negatives), and the
whole-CORPUS synth-collision guard covers the new fixture locations.

---

## Batch B12 (#71) — Next-config & client-surface misconfig

The Next-config / client-surface expansion batch (spec `docs/design/corpus-roadmap-to-100.md` §3d).
Answer key: `src/scan/calibration/b12-nextconfig.entries.ts`. Detection is split three ways: three
exact config-object Semgrep rules plus two review-tier server rules **extend the existing
`src/scan/rules/semgrep/headers.yml`**; four client-surface rules **extend
`src/scan/rules/semgrep/xss.yml`**; and the one class Semgrep can't express — a sensitive file
physically served from `public/` — is a **new filesystem check** (`checkPublicDirSensitive` in
`src/scan/semgrep.ts`, wired into `runMechanicalScan`). Tiering per the locked preamble: only the
exact config-parse / unambiguous-literal / filesystem sinks are `high` (free count); the heuristic /
absence-of-X sinks stay `review`. All fixtures are inert source files.

The three config classes share `config-variants/insecure.config.js` (positives) and
`config-variants/hardened.config.js` (negatives) — a second next-config-shaped surface named off the
`next.config.*` pattern so `checkMissingCsp` (which keys off exact filenames) never picks it up. Each
class is disambiguated by its rule-id `match` keyword, exactly as B5's shared `next.config.js` routes
are. `P-SIGNED-URL-TTL` is the numeric-literal-TTL lens (`createSignedUrl` expiry), distinct from
B9's `P-SIGNED-URL-TOKEN-SRC` (a committed signed-URL token) — different file, different mechanism.

### B12 positives — planted config/client-surface bugs (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-IMG-REMOTEPATTERNS-WILD | `config-variants/insecure.config.js:16` | Semgrep `harvey-img-remotepatterns-wild` (all-asterisks `hostname` inside a `remotePatterns` element) | high |
| P-PROD-SOURCEMAPS | `config-variants/insecure.config.js:13` | Semgrep `harvey-prod-sourcemaps` (literal `productionBrowserSourceMaps: true`) | high |
| P-SERVERACTIONS-ORIGIN-WILD | `config-variants/insecure.config.js:19` | Semgrep `harvey-serveractions-origin-wild` (bare `"*"` in `allowedOrigins`) | high |
| P-PUBLIC-DIR-SENSITIVE | `public/backup.sql`, `public/.env.production` | `checkPublicDirSensitive` (filesystem walk of `public/`) | high |
| P-SIGNED-URL-TTL | `lib/signed-url-ttl.js:11` | Semgrep `harvey-signed-url-ttl` (`createSignedUrl($P, $N)`, `$N > 604800`) | high |
| P-POSTMESSAGE-WILDCARD | `components/PostMessageWild.jsx:6` | Semgrep `harvey-postmessage-wildcard` (literal `"*"` targetOrigin) | high |
| P-TOKEN-IN-WEBSTORAGE | `lib/webstorage-token.js:6` | Semgrep `harvey-token-in-webstorage` (auth-token-named Web Storage key) | review |
| P-MISSING-SRI | `components/CdnScript.jsx:6` | Semgrep `harvey-missing-sri` (external CDN `<script>` with no `integrity`) | review |
| P-ISR-REVALIDATE-NOSECRET | `pages/api/isr-rebuild.js:8` | Semgrep `harvey-isr-revalidate-nosecret` (`res.revalidate` on a request path, no secret gate) | review |
| P-CRLF-HEADER-INJ | `pages/api/download.js:7` | Semgrep `harvey-crlf-header-injection` (taint `req.query` → `res.setHeader` value) | review |
| P-CRLF-MULTIHOP | `pages/api/crlf-multihop.js:9` | Semgrep `harvey-crlf-header-injection` via a multi-hop `req.headers.referer` (dotted) source → `res.setHeader` — a source shape the old rule missed (#988) | review |
| P-POSTMESSAGE-NO-ORIGIN | `components/MessageListener.jsx:9` | Semgrep `harvey-postmessage-no-origin` (`message` listener callback with no `.origin` check) | review |

### B12 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-IMG-REMOTEPATTERNS-OK | `config-variants/hardened.config.js` | `hostname: 'images.example.com'` — an explicit host; the hostname regex (`^['"]?\*+['"]?$`) matches only all-asterisks. |
| N-PROD-SOURCEMAPS-OFF | `config-variants/hardened.config.js` | `productionBrowserSourceMaps: false` (also the absent-key default); the rule matches only the literal `true`. |
| N-SERVERACTIONS-ORIGIN-OK | `config-variants/hardened.config.js` | `allowedOrigins: ['app.example.com','admin.example.com']` — no bare `"*"` element to match. |
| N-PUBLIC-DIR-BENIGN | `public/favicon.ico` | `favicon.ico`, `fonts/inter.woff2`, `robots.txt` are benign assets; none match `checkPublicDirSensitive`'s sensitive-name patterns. |
| N-SIGNED-URL-TTL-OK | `lib/signed-url-ttl-ok.js` | `createSignedUrl(path, 300)` — a 5-min TTL; the `metavariable-comparison` fires only above 7 days. |
| N-POSTMESSAGE-ORIGIN-OK | `components/PostMessageOrigin.jsx` | `postMessage(session, 'https://app.example.com')` — an explicit origin; `harvey-postmessage-wildcard` matches only `"*"`. |
| N-WEBSTORAGE-CSRF | `lib/webstorage-csrf.js` | `localStorage.setItem('csrfToken', …)` — JS-readable by design; the key regex excludes `csrf`-prefixed keys. |
| N-SRI-PRESENT | `components/CdnScriptSri.jsx` | the same CDN `<script>` with `integrity` + `crossOrigin`; `harvey-missing-sri` excludes any `<script>` carrying `integrity`. |
| N-ISR-REVALIDATE-SECRET | `pages/api/isr-rebuild-secret.js` | handler compares `req.query.secret` against a server secret before revalidating; the `pattern-not-inside` excludes it. |
| N-CRLF-SANITIZED | `pages/api/download-safe.js` | `req.query.name.replace(/[\r\n"]/g, "")` before `setHeader` — the CR/LF strip is the taint sanitizer. |
| N-POSTMESSAGE-NO-ORIGIN-OK | `components/MessageListenerOrigin.jsx` | the listener checks `e.origin` before trusting `e.data`; `harvey-postmessage-no-origin` excludes any callback referencing `.origin`. |

### B12 detection additions

Six new rules in `src/scan/rules/semgrep/headers.yml` (`harvey-img-remotepatterns-wild`,
`harvey-prod-sourcemaps`, `harvey-serveractions-origin-wild`, `harvey-signed-url-ttl` — all ERROR +
HIGH → high; `harvey-crlf-header-injection`, `harvey-isr-revalidate-nosecret` — WARNING + MEDIUM →
review) and four in `src/scan/rules/semgrep/xss.yml` (`harvey-postmessage-wildcard` — ERROR + HIGH →
high; `harvey-token-in-webstorage`, `harvey-missing-sri`, `harvey-postmessage-no-origin` — WARNING +
MEDIUM → review). One **new scanner** function, `checkPublicDirSensitive` (`src/scan/semgrep.ts`,
wired into `runMechanicalScan`), covers `P-PUBLIC-DIR-SENSITIVE` — a filesystem-presence fact no
Semgrep AST rule can express — with a focused unit test in `src/scan/semgrep.test.ts`. No class was
dropped — all 11 §3d rows landed (6 high, 5 review).

### B12 live result (2026-07-09, static binaries: semgrep 1.164.0, gitleaks 8.30.1, trufflehog 3.95.8, osv-scanner 2.3.8, no Docker)

`pnpm validate:calibration`: **GATE PASS — zero free-count false positives; every high-tier rule
fired on its positive.** All 11 B12 positives fire (6 at high: wildcard `remotePatterns`,
`productionBrowserSourceMaps`, `'*'` Server-Actions origin, `createSignedUrl` TTL, `'*'` postMessage,
sensitive file in `public/`; 5 at review: auth token in Web Storage, CDN `<script>` no SRI, ISR
revalidate no secret, CRLF header injection, `message` listener no origin) and all 11 B12 negatives
clear with no free-count finding. `pnpm verify` (offline) is green: `calibration.test.ts` gained a
B12 recorded-semgrep + real-`checkPublicDirSensitive` block scoring all 22 entries, and
`semgrep.test.ts` gained focused `checkPublicDirSensitive` unit tests.

---

## Batch B13 (#71) — Supabase static-config/edge + injection-sink breadth

The Supabase static-config/edge + injection-sink expansion batch (roadmap
`docs/design/corpus-roadmap-to-100.md` §3e). Answer key: `src/scan/calibration/b13-supa.entries.ts`.
Detection is split three ways:

1. **One new static scanner** — `checkMigrationRlsStatic` (`src/scan/supabase-static.ts`, wired into
   `runMechanicalScan`). Parses committed `supabase/migrations/*.sql` for a `create table public.X`
   that never gets `alter table public.X enable row level security` anywhere in the migration set.
   This is the **static path for `P-RLS-DISABLED`**, which was connected-tier only (needed a live
   Advisor). The roadmap §5 honesty flag class: it is `high` **only because** it clears the two
   verified negatives — `service_state` (RLS enabled + zero policies, deny-all by design) and any
   table whose RLS is enabled in a **later** migration file (`documents`, created in
   `…0001_schema.sql`, enabled in `…0002_rls.sql`). The enable-check aggregates across all files and
   ignores views, so on the real target it fires on exactly one table: `audit_logs`.
2. **A small static config check** — `checkEdgeFunctionVerifyJwt` (same module): parses
   `supabase/config.toml` for `[functions.X] verify_jwt = false`. `review`. (Semgrep generic-mode on
   TOML was tried first and rejected — it produced garbage line mappings and phantom matches.)
3. **Semgrep rules** extending `src/scan/rules/semgrep/injection.yml` — two ERROR+HIGH structural
   rules, one ERROR+HIGH client-surface rule, and six WARNING+MEDIUM injection-sink heuristics.

### B13 positives — planted bugs (must be caught)

| id | location | detection | tier |
|---|---|---|---|
| P-RLS-MISSING-STATIC | `supabase/migrations/20260708000001_schema.sql:35` (`audit_logs`, absence) | `checkMigrationRlsStatic` (create-table with no enable-RLS anywhere) | high |
| P-PG-SSL-DISABLED | `lib/pg-ssl-disabled.js:7` | Semgrep `harvey-pg-ssl-disabled` (`ssl: false` in a `Pool` literal + a `pooler.supabase.com` host) | high |
| P-AUTH-ADMIN-CLIENT | `components/AdminUsersClient.jsx:10` | Semgrep `harvey-auth-admin-in-client` (`$C.auth.admin.$M(...)` inside a `"use client"` module) | high |
| P-SPAWN-SHELL | `pages/api/thumbnail.js:7` | Semgrep `harvey-spawn-shell-true` (`spawn`/`execFile` with `{ shell: true }`) | high |
| P-EDGEFN-VERIFY-JWT-OFF | `supabase/config.toml` (`[functions.admin-refund]`) | `checkEdgeFunctionVerifyJwt` (`verify_jwt = false` under a `[functions.X]` table) | review |
| P-SELECT-STAR-PII | `pages/api/customers.js:10` | Semgrep `harvey-select-star-pii` (taint `select("*")` → `res.json`) | review |
| P-CRON-NO-SECRET | `pages/api/cron/rollup.js:6` | Semgrep `harvey-cron-no-secret` (`supabaseAdmin` DB call in a handler with no `if` guard) | review |
| P-DYNAMIC-REQUIRE | `pages/api/plugin.js:4` | Semgrep `harvey-dynamic-require` (taint `req.*` → `require`) | review |
| P-DYNAMIC-DISPATCH | `pages/api/dispatch.js:10` | Semgrep `harvey-dynamic-dispatch` (taint `req.*` → `obj[$IDX](...)`) | review |
| P-TEMPLATE-AUTOESCAPE-OFF | `lib/render-template.js:7` | Semgrep `harvey-template-autoescape-off` (`Handlebars.compile(…,{noEscape:true})`) | review |
| P-HTML-TEMPLATE-LITERAL | `pages/api/greet.js:6` | Semgrep `harvey-html-template-literal` (taint `req.*` → `res.send` of a template literal) | review |
| P-INCOMPLETE-SANITIZE | `lib/sanitize-bad.js:5` | Semgrep `harvey-incomplete-sanitize` (string-literal `.replace` needle) | review |

### B13 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-RLS-DENY-ALL-STATIC | `…0001_schema.sql` (`service_state`) | RLS enabled in `…0002_rls.sql` with zero policies — deny-all by design; the check sees the ENABLE and stays silent. |
| N-RLS-ENABLED-LATER | `…0001_schema.sql` (`documents`) | RLS enabled in the LATER `…0002_rls.sql`; the enable-check aggregates across all files — cleared. |
| N-PG-SSL-OK | `lib/pg-ssl-ok.js` | `ssl: { rejectUnauthorized: true }` to the pooler; the rule matches only `ssl: false`. |
| N-AUTH-ADMIN-SERVER | `lib/admin-users-server.js` | the same `auth.admin.*` in a server-only module (no `"use client"`) — the rule fires only inside a Client Component. |
| N-SPAWN-NOSHELL | `pages/api/thumbnail-safe.js` | `execFile` with an argv array and no shell option; the rule requires `shell: true`. |
| N-EDGEFN-VERIFY-JWT-ON | `supabase/config.toml` (`[functions.user-profile]`) | `verify_jwt = true`; the check matches only `= false`. |
| N-SELECT-EXPLICIT | `pages/api/customers-safe.js` | `select("id,name,email")` — an explicit projection; the rule requires a `select("*")` source. |
| N-CRON-SECRET | `pages/api/cron/rollup-secure.js` | a `CRON_SECRET` bearer check (an `if` guard) precedes the admin call; the `pattern-not-inside` excludes it. |
| N-REQUIRE-FIXED | `lib/fixed-require.js` | `require("./helper")` — a fixed string, no request taint. |
| N-DISPATCH-ALLOWLIST | `pages/api/dispatch-safe.js` | the action is checked against an allowlist and a fixed reference dispatched — no tainted key reaches a computed call. |
| N-TEMPLATE-ESCAPED | `lib/render-template-safe.js` | `Handlebars.compile(tpl)` with default escaping — no `noEscape` option. |
| N-HTML-PLAINTEXT | `pages/api/greet-safe.js` | `res.json({ name: req.query.name })` — no `res.send` HTML template literal. |
| N-SANITIZE-GLOBAL | `lib/sanitize-ok.js` | `s.replace(/</g, "")` — a `/g` regex needle, not a string; the `metavariable-regex` requires a quoted string. |

### B13 detection additions

One **new module** `src/scan/supabase-static.ts` (two static checks read from committed files:
`checkMigrationRlsStatic` — high; `checkEdgeFunctionVerifyJwt` — review), both wired into
`runMechanicalScan` with focused unit tests in `src/scan/supabase-static.test.ts`. Nine new rules in
`src/scan/rules/semgrep/injection.yml`: `harvey-spawn-shell-true`, `harvey-pg-ssl-disabled`,
`harvey-auth-admin-in-client` (ERROR + HIGH → high); `harvey-select-star-pii`, `harvey-cron-no-secret`,
`harvey-dynamic-require`, `harvey-dynamic-dispatch`, `harvey-template-autoescape-off`,
`harvey-html-template-literal`, `harvey-incomplete-sanitize` (WARNING + MEDIUM → review). Adjacency:
`P-SPAWN-SHELL` is disjoint from `harvey-command-injection` (exec/execSync); `P-AUTH-ADMIN-CLIENT`
keys off the `auth.admin` call, not the `SERVICE_ROLE_KEY` env literal `harvey-service-role-in-client`
(base.yml) matches; `P-RLS-MISSING-STATIC` is the static counterpart of the connected `P-RLS-DISABLED`
(both coexist). **No class was dropped — all 12 §3e rows landed (4 high, 8 review).**

### B13 live result (2026-07-09, static binaries: semgrep, gitleaks, trufflehog, osv-scanner; no Docker)

`pnpm validate:calibration`: **GATE PASS — zero free-count false positives; every high-tier rule
fired on its positive.** All 12 B13 positives fire (4 at high: static-migration RLS, pg `ssl:false`
to a pooler, `auth.admin` in a Client Component, `spawn` `shell:true`; 8 at review) and all 13 B13
negatives clear. Corpus totals after B13: **135/135 static positives caught (61 at high/free-count,
15 connected N/A); 103/103 static negatives cleared.** `pnpm verify` (offline) is green: 443 tests,
including the B13 recorded-semgrep + real-static-check block in `calibration.test.ts` and the
`supabase-static.test.ts` unit tests.

---

## Batch B14 (#71) — app-logic heuristics

The final #71 corpus batch (roadmap `docs/design/corpus-roadmap-to-100.md` §3f). Answer key:
`src/scan/calibration/b14-applogic.entries.ts`. Five app-logic / client-trust classes, all detected
by five new greps in `src/scan/leftover-auth.ts` (`B14_CHECKS` plus the upload and webhook checks).
Every class is **`review` tier** — these are absence-of-check / client-trust heuristics with the
highest negative-precision risk in the corpus (a grep can only see that a check's shape is absent in
*this* file, never that it isn't enforced in middleware or a wrapper it can't see), so none feed the
free count.

### B14 positives — planted bugs (must be caught, all `review` tier)

| id | location | detection | tier |
|---|---|---|---|
| P-CLIENT-PRIV-HEADER | `pages/api/promote.js:5` | leftover-auth `client-priv-header` (privilege literal compared directly against a `req` header/body/query value) | review |
| P-CLIENT-PAYMENT-AMOUNT | `pages/api/checkout.js:9` | leftover-auth `client-payment-amount` (`amount…: req.(body\|query\|params)`) | review |
| P-WEBHOOK-NO-SIG | `pages/api/webhooks/inbound.js:6` | leftover-auth `webhook-no-sig` (`webhook`-path route + privileged write + no signature hint) | review |
| P-SENSITIVE-CONSOLE-LOG | `lib/audit-login.js:4` | leftover-auth `sensitive-console-log` (`console.*` argument carrying password/secret/token/api_key/…) | review |
| P-UPLOAD-NO-LIMIT | `pages/api/upload.js:7` | leftover-auth `upload-no-limit` (a storage `.upload()` with no content-length/MIME hint in the file) | review |

### B14 negatives — benign lookalikes (must NOT be flagged; here also fully silent)

| id | location | why benign / suppression |
|---|---|---|
| N-PRIV-FROM-SESSION | `pages/api/promote-safe.js` | the role is read from `getUser().app_metadata`, compared against a session value — no `req.*` operand on the comparison, so `client-priv-header` doesn't match. |
| N-PAYMENT-DB-PRICE | `pages/api/checkout-safe.js` | `amount: product.price_cents * req.body.quantity` — `amount:` is followed by the DB price, not `req.*`. |
| N-WEBHOOK-SIGNED | `pages/api/webhooks/inbound-signed.js` | `stripe.webhooks.constructEvent(...)` verifies the signature before the write; the signature-hint regex matches. |
| N-LOG-OUTCOME-ONLY | `lib/audit-login-safe.js` | logs `{ email, success }` — no sensitive identifier in the `console.*` argument. |
| N-UPLOAD-LIMITED | `pages/api/upload-safe.js` | a `content-length` cap and an `ALLOWED_MIME` allowlist precede `.upload()`; the limit-hint regex matches. |

### B14 detection additions

Five new greps in `src/scan/leftover-auth.ts`, all emitting `review`-tier findings with a stable
keyword (`client-priv-header`, `client-payment-amount`, `sensitive-console-log`, `upload-no-limit`,
`webhook-no-sig`) in the finding id/evidence for corpus attribution. Unit tests in
`src/scan/leftover-auth.test.ts`; a recorded-vector block in `calibration.test.ts` runs the real
`classifyLeftoverAuth` over the fixture shapes. **Adjacency:** `P-SENSITIVE-CONSOLE-LOG` sources the
credential from a function parameter (not `req.*`), so the taint rule `harvey-log-injection`
(`injection.yml`) stays silent and only the name-gated grep fires — no double-fire.
`P-WEBHOOK-NO-SIG` is path-gated on `webhook` + absence of any signature hint, so it is disjoint from
the other admin-write route fixtures (register/settings/seed aren't webhooks) and stays silent on the
existing `pages/api/webhook.js`, which HAS an HMAC check (the WEBHOOK-REPLAY shape: signed, but no
anti-replay). `P-UPLOAD-NO-LIMIT` is the code-side of the semantic-tier
`supabase-storage-unrestricted-upload-policy` (roadmap §4a). **No class was dropped — all 5 §3f rows
landed (0 high, 5 review).**

### B14 live result (2026-07-10, static binaries: semgrep, gitleaks, trufflehog, osv-scanner; no Docker)

`pnpm validate:calibration`: **GATE PASS — zero free-count false positives; every high-tier rule
fired on its positive.** All 5 B14 positives fire at review and all 5 B14 negatives are fully silent
(no finding at all). Corpus totals after B14: **140/140 static positives caught (61 at high/free-count,
15 connected N/A); 108/108 static negatives cleared.** `pnpm verify` (offline) is green: 452 tests,
including the B14 real-`classifyLeftoverAuth` recorded-vector block in `calibration.test.ts` and the
new `leftover-auth.test.ts` heuristic unit tests.

---

## Batch B15 (#123, issues #131-#136) — Next.js/Supabase authz-shape classes (semantic tier)

Six classes from the roadmap's §4a excluded-tier backlog (`docs/design/corpus-roadmap-to-100.md`
§4a "Semantic (LLM/whole-program — paid M-series)"): each needs request+identity context, matcher-
vs-route-inventory reasoning, or control-flow reasoning. When B15 landed, none was mechanically
detected and no new scanner was added — the batch seeded the corpus/GROUND-TRUTH answer key so the
paid-tier LLM pass had fixtures to measure against later. **Updated by #354 (see §B17):** the
re-triage found two of the six were mechanically detectable at review tier after all —
`P-MW-MATCHER-EXCLUDES-API` (the matcher's api-lookahead is a textual fact) and
`P-DRAFTMODE-NO-SECRET` (a shallow intra-file "enable with no secret gate" check) — and both
graduated to `leftover-auth` grep rules. **Updated by #433:** `P-BOLA-BODY-OWNER` graduated to the
`bola-owner` AST pass (`src/scan/bola-owner.ts`, runs in `runMechanicalScan`, review tier) —
session-bound handler + service-rooted `.eq(<ownership col>, <request-rooted value>)` + no
session-vs-client comparison is a dataflow fact. The remaining three (`P-MW-SOLE-AUTHZ`,
`P-HOST-HEADER-URL`, `P-CLIENT-RENDER-AUTHZ`) stay LLM/paid-tier as measured. Built incrementally,
one issue per commit. Answer key: `src/scan/calibration/b15-nextjs-authz.entries.ts`.

### B15 positives — planted bugs (semantic tier; NOT expected to be caught by the offline mechanical gate)

| id | location | class | issue |
|---|---|---|---|
| P-BOLA-BODY-OWNER | `pages/api/billing/invoice.js:14` | route scopes the query to `req.body.tenantId` (client-supplied) instead of the session's tenant id — object/function-level authz gap (BOLA/BFLA). **Graduated (#433)**: caught at review by `bola-owner` (`src/scan/bola-owner.ts`) | #131 |
| P-MW-MATCHER-EXCLUDES-API | `middleware.ts` (`config.matcher`) | matcher `/((?!api\|_next/static\|_next/image\|favicon.ico).*)` excludes every `/api/*` path from the middleware entirely | #132 |
| P-MW-SOLE-AUTHZ | `pages/api/admin/dashboard.js:11` | reads `admin_metrics` with no session/role check of its own — relies entirely on `middleware.ts`, no defense in depth | #133 |
| P-DRAFTMODE-NO-SECRET | `pages/api/preview/enable.js:8` | `draftMode().enable()` runs unconditionally, no secret/token check | #134 |
| P-HOST-HEADER-URL | `lib/reset-link.js:11` | password-reset link built from `headers().get("host")` — attacker-controlled, enables reset-link poisoning | #135 |
| P-CLIENT-RENDER-AUTHZ | `app/admin/page.tsx:11` + `components/AdminDashboardClient.jsx:8` | server fetches the full admin dataset unconditionally; the only gate is the client component's `if (!isAdmin) return null` — data already shipped in the RSC payload | #136 |

### B15 negatives — benign lookalikes (must NOT be flagged in the free count; here also fully silent — no existing rule targets these shapes)

| id | location | why benign |
|---|---|---|
| N-BOLA-SESSION-OWNER | `pages/api/billing/invoice-safe.js` | query scoped to `session.user.tenantId`; `req.body.tenantId` is never read. |
| N-MW-MATCHER-INCLUDES-API | `lib/middleware-matcher-safe.ts` | `config.matcher` has no `api` exclusion — `/api/*` still runs through the middleware auth check. |
| N-MW-DEFENSE-IN-DEPTH | `pages/api/admin/dashboard-safe.js` | calls `getServerSession()` and checks the role itself before returning `admin_metrics`, in addition to middleware. |
| N-DRAFTMODE-SECRET-CHECKED | `pages/api/preview/enable-safe.js` | validates `req.query.secret` against `process.env.PREVIEW_SECRET` before `draftMode().enable()` runs. |
| N-HOST-HEADER-FIXED-ORIGIN | `lib/reset-link-safe.js` | builds the link from `process.env.NEXT_PUBLIC_SITE_URL`; `headers()`/Host is never read. |
| N-SERVER-ROLE-CHECK | `app/admin/page-safe.tsx` | checks the role server-side and redirects BEFORE querying `admin_metrics` — the query never runs for a non-admin. |

### B15 adjacency note

`P-CLIENT-RENDER-AUTHZ` shares a theme with the existing `P-SERVER-CLIENT-LEAK`
(`app/documents/detail-page.tsx`) but is a distinct shape: `harvey-server-client-leak` requires an
exact `const { $DATA } = await $C.from($T).select("*").eq($COL, $ID);` + `<$COMP {...$DATA} />`
spread; `app/admin/page.tsx` uses no `.eq()` chain and passes `metrics={data}` as a named prop, not
a spread, so that rule stays silent on this fixture (verified live below). `P-MW-SOLE-AUTHZ` is a
`SELECT`, not an insert/update/delete, so the existing `harvey-route-noauth` mutation rule does not
fire on `pages/api/admin/dashboard.js` — keeps this class isolated from the B7 route-noauth pair.

### B15 live result (2026-07-10, static binaries: semgrep, gitleaks, trufflehog, osv-scanner; no Docker)

`pnpm validate:calibration`: **GATE PASS — zero free-count false positives; every high-tier rule
fired on its positive.** All 6 B15 negatives are fully silent (no finding at all) and all 6 B15
positives are reported as non-fatal review-tier recall gaps (expected — no mechanical rule targets
them, including confirming `harvey-server-client-leak` stays silent on `app/admin/page.tsx`).
Corpus totals after B15: **141/147 static positives caught (61 at high/free-count, 15 connected
N/A); 115/115 static negatives cleared.** `pnpm verify` (offline) is green: 452 tests (no new tests
were needed — `b15-nextjs-authz.entries.ts` is exercised by the existing whole-`CORPUS` tests in
`calibration.test.ts`, which only assert entries are counted correctly, not caught, for entries
with no matching rule).

---

## Batch B16 (#123) — semantic-tier Supabase policy/function-body fixtures (review tier, no mechanical detector)

Three of the nine classes carved out in #123 (`docs/design/corpus-roadmap-to-100.md` §4a — the
semantic/paid-M-series backlog explicitly excluded from the mechanical corpus). Answer key:
`src/scan/calibration/b16-storage-secdef.entries.ts`. All three need policy-body or function-body
reasoning that a structural grep can't do reliably: detection is left to the existing LLM
high-recall pass (`/vuln-scan` + `/triage`), per #123 option (b) — **no new mechanical scanner is
added here.** Every positive is `review` tier and is EXPECTED to miss `pnpm validate:calibration`
(a non-fatal `reviewMisses` line); the gate's job is proving the negatives raise zero free-count
false positives.

### B16 positives — planted bugs (review tier; static miss by design, LLM pass covers detection)

| id | location | class | tier |
|---|---|---|---|
| P-STORAGE-AUTH-NOT-OWNER `[#137]` | `supabase/migrations/20260710000001_b15_storage_secdef_semantic.sql` (`user_files_select_authenticated`) | `storage.objects` SELECT policy `USING (auth.role() = 'authenticated')` — checks login, not ownership | review |
| P-STORAGE-UPLOAD-CHECK-TRUE `[#138]` | same file (`user_files_insert_open`) | `storage.objects` INSERT policy `WITH CHECK (true)` — unrestricted upload to any bucket/path. Code-side is `P-UPLOAD-NO-LIMIT` (B14). | review |
| P-SECDEF-PRIV-WRITE-NOAUTH `[#139]` | same file (`promote_to_admin`) | `security definer` function updates `profiles.role` with no check on the caller's identity — any authenticated caller can promote anyone to admin | review |

### B16 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign |
|---|---|---|
| N-STORAGE-OWNERSHIP-SCOPED | same file (`user_files_select_own`) | `USING (bucket_id = 'user-files' and (storage.foldername(name))[1] = auth.uid()::text)` — the standard one-folder-per-user ownership pattern. No mechanical rule reads `storage.objects` policy bodies at all — trivially silent. |
| N-STORAGE-UPLOAD-OWNERSHIP-MIME | same file (`user_files_insert_own`) | `WITH CHECK (... foldername ownership ... and mimetype = any (allowed list))` — ownership-scoped and mime-restricted, mirroring the bucket's `allowed_mime_types` (`config.toml`). No mechanical rule reads `storage.objects` bodies — trivially silent. |
| N-SECDEF-PRIV-WRITE-AUTHCHECK | same file (`promote_to_admin_checked`) | the identical privileged write, gated by `where id = auth.uid() and role = 'admin'` on the CALLER's own row before the target row is touched. No mechanical rule reads `security definer` function bodies — trivially silent. |

### B16 detection

No new mechanical scanner. All three positives are documented, non-fatal `pnpm validate:calibration`
review-tier misses (`reviewMisses`, `cli/validate-calibration.ts`) — detection is the existing LLM
`/vuln-scan` + `/triage` high-recall pass, per parent tracker #123 option (b). All three negatives
are fully silent (no mechanical rule reads Supabase policy or `security definer` function bodies).
Six of the nine #123 classes (BOLA/BFLA, middleware matcher, middleware-sole-authz, draft-mode
secret, host-header trust, client-render authz) remain out of scope for this fixture sweep.

### B16 live result (2026-07-10, static binaries: semgrep, gitleaks, trufflehog, osv-scanner; no Docker)

`pnpm validate:calibration`: **GATE PASS — zero free-count false positives; every high-tier rule
fired on its positive.** All 3 B16 positives are documented, non-fatal review-tier misses (as
designed — semantic/policy-body detection, no mechanical rule) and all 3 B16 negatives are fully
silent. Corpus totals after B16 (merged with B15 and the #150/#152 landings already on `main`):
**142/151 static positives caught (62 at high/free-count, 15 connected N/A; 9 documented
review-tier misses across B15+B16 — the 6 B15 Next.js/Supabase-authz classes plus
P-STORAGE-AUTH-NOT-OWNER, P-STORAGE-UPLOAD-CHECK-TRUE, P-SECDEF-PRIV-WRITE-NOAUTH), 118/118 static
negatives cleared.** `pnpm verify` (offline) is green (no new detector, so no new test count — the
B16 answer key is scored purely via `buildCoverageMatrix`/`validate-calibration.ts`, no
`calibration.test.ts` recorded-vector block).

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
| M4-P-CLONE-SEC | `dup/auth/session-check-api.ts` ↔ `dup/auth/session-check-action.ts` | genuine 25-line copy-pasted session/tenant validation block (246 tokens) in an auth path; jscpd clone cluster; `touchesSecurityPath` fires (#361) → severity elevated Low→Medium + M1 cross-check note in impact | high |
| M4-P-SMALL-DISCLOSED | `dup/pricing-tier-a.ts` ↔ `dup/pricing-tier-b.ts` | genuine 9-line volume-discount ladder (129 tokens) — real logic under `MIN_SIGNIFICANT_LINES`; must be counted (and named in evidence) by the aggregate `M4-00` sub-threshold disclosure finding (#365) | high |
| M4-P-DIVERGED-TENANT | `dup/auth/require-tenant-api.ts` ↔ `dup/auth/require-tenant-admin.ts` | copy-pasted tenant guard whose copies have DIVERGED (`'tenant_id'` vs `'owner_id'` scoping literal + drifted error strings) — jscpd's exact token match sees only sub-threshold fragments, never the pair; the #360 near-miss pass (`src/diverged-clones.ts`) emits an `M4-DIV-*` review finding (High) naming the drifted literals | review |
| M4-P-DIVERGED-TENANT-WIDENED | `dup/stores/customer.store.ts` ↔ `dup/stores/order.store.ts` | copy-pasted per-entity supabase query whose copies have DIVERGED on the tenant-scoping literal (`'organisation_id'` vs `'org_id'`) — neither path matches `touchesSecurityPath`, so only the #399 content-based widening (`touchesTenantSupabasePath`: a tenant-key literal AND a supabase query in the same file) puts them in front of the #360 near-miss pass at all; emits an `M4-DIV-*` review finding (High) | review |

**Negatives — benign lookalikes (must NOT be flagged)**

| id | location | why benign / suppression |
|---|---|---|
| M4-N-GENERATED | `dup/generated/schema.gen.ts` | repeats the `invoice-total.ts` tax block but is a generated file, not hand-maintained duplication. Excluded via the quality-scan CLI's jscpd `--ignore` glob, extended to `**/generated/**` (`src/cli/quality-scan.ts`) — jscpd never sees it. |
| M4-N-BOILERPLATE | `dup/route-a.ts` ↔ `dup/route-b.ts` | shares the Next.js API-route `config` + handler-signature boilerplate — a framework contract, not a defect. Shared span stays under jscpd's 50-token minimum (`.jscpd.json` `minTokens`) — not flagged. |
| M4-N-SMALL-FLOOR | `dup/pricing-tier-a.ts` ↔ `dup/pricing-tier-b.ts` | the same 9-line ladder must NOT surface as an individual `M4-*` finding — #365 measured that emitting the 5–9-line band individually would triple an AI-authored target's M4 report while the #232 noise classes (import headers) share the band. Disclosed via the `M4-00` aggregate instead. |
| M4-N-DIV-DISTINCT | `dup/auth/api-key-check.ts` | an independently-written guard in the same auth path — same domain, different structure. The #360 pass must not pair it with the require-tenant guards (similarity-floor FP guard). Note the `session-check-*` pair is also a #360 negative by construction: a CONSISTENT rename (Type-2) is faithful duplication jscpd already reports, not drift — asserted in `src/diverged-clones.test.ts`. |

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

---

## M8 (#72) — Test quality (StrykerJS mutation) corpus

The M8 slice of the #72 cross-module corpus (spec `docs/design/spec-72-crossmodule-corpus.md`
§M8). Unlike M4/M5/M10, the calibration target had **no test suite at all** before this batch —
M8 adds one, scoped entirely to `targets/calibration/test-quality/`, a small, deliberately
isolated npm project (its own `package.json`, `vitest.config.ts`, `stryker.config.json`,
`node_modules`). Isolated on purpose: `targets/calibration/package.json`'s own dependency tree
can never `npm install` (`react-supabase-helpers` is a deliberately nonexistent slopsquat
fixture for M1 — see that file's `description`), so a Stryker/vitest install at that level was
never viable. `test-quality/` is a separate project boundary, not linked via npm workspaces, so
it installs cleanly on its own.

**Fixtures:**
- `test-quality/discount.ts` — `applyDiscount(total, isMember)`, covered ONLY by
  `discount.tautological.test.ts`, a single happy-path assertion (`applyDiscount(100, true) ===
  80`) that never exercises the non-member branch, the negative-total guard, or the `<100`
  member boundary. This is the planted weak test (M8-P-TAUTOLOGICAL).
- `test-quality/authz.ts` — `canAccess(role, action)`, covered by `authz.strong.test.ts`, which
  is exhaustive over the 2x2 role/action truth table (admin/member × read/delete), including the
  denial path. This is the planted strong test (M8-N-STRONG).

**Tool + invocation:** `npx stryker run` (Stryker 9.6.1, `@stryker-mutator/vitest-runner` 9.6.1,
`coverageAnalysis: "perTest"`) from `targets/calibration/test-quality/`, or
`pnpm mutation-scan targets/calibration/test-quality` from the repo root once Stryker is
installed there (`src/cli/mutation-scan.ts`).

### M8 positives — planted weak test (must leave a surviving mutant)

| id | fixture | weakness class | expected Stryker result |
|---|---|---|---|
| M8-P-TAUTOLOGICAL | `test-quality/discount.ts` + `discount.tautological.test.ts` | happy-path-only / assertion-light (quality-extras.txt M8 category 5) | ≥1 mutant Survived/NoCoverage on `discount.ts` |

### M8 stub-check pair (#373) — deletion-survival, proven by execution (not Stryker)

The stub-check instrument (`src/stub-check.ts`, `pnpm mutation-scan <t> --stub-check`) answers
the M8 brief's litmus test directly: stub each covered exported function's body to
`return undefined` and re-run the covering tests. Its planted pair (deliberately NOT added to
`stryker.config.json`'s `mutate` list, so the recorded live result above stays reproducible):

| id | fixture | expected stub-check result |
|---|---|---|
| M8-P-DELETION-SURVIVING | `test-quality/audit-log.ts` + `audit-log.deletion-surviving.test.ts` | covering test calls `logAuditEvent` but asserts nothing → still passes with the body stubbed → `M8-01-*` finding |
| (contrast, reuses M8-P-TAUTOLOGICAL) | `test-quality/discount.ts` + `discount.tautological.test.ts` | weak per Stryker, but its one assertion checks a return value → FAILS when `applyDiscount` is stubbed → no finding |

Both verdicts are executed (transpile-and-run), not recorded: `src/stub-check.test.ts`'s
"M8-P-DELETION-SURVIVING calibration pair" block runs the covering tests against the real and
stubbed sources on every `pnpm verify`.

### M8 negatives — planted strong test (must NOT be flagged)

| id | fixture | why genuinely strong | must NOT happen |
|---|---|---|---|
| M8-N-STRONG | `test-quality/authz.ts` + `authz.strong.test.ts` | exhaustive over the 2x2 role/action truth table, denial path included | zero surviving mutants on `authz.ts` — must not land on the false-confidence list |

### M8 live result (2026-07-08, live: Stryker 9.6.1, `@stryker-mutator/vitest-runner` 9.6.1, vitest 3.2.7, no Docker)

`npx stryker run` against `targets/calibration/test-quality/` (`mutate:
["discount.ts","authz.ts"]`, `coverageAnalysis: "perTest"`):

- **`discount.ts` (weak test): 15 mutants — 9 Killed, 4 Survived, 2 NoCoverage → mutation score
  60.0%.** Surviving: two `ConditionalExpression` mutants negating the guard/boundary conditions
  (lines 4 and 5), one `EqualityOperator` mutant loosening the negative-total guard
  (`total < 0` → `total <= 0`, line 4), one `ConditionalExpression` mutant on the `>= 100`
  boundary (line 6). NoCoverage: a `StringLiteral` mutant on the error message (line 4, never
  thrown) and an `ArithmeticOperator` mutant on the non-member discount math (line 7, branch
  never exercised). **M8-P-TAUTOLOGICAL: caught — 6 surviving mutants prove the weak test's false
  confidence.**
- **`authz.ts` (strong test): 10 mutants — 10 Killed, 0 Survived, 0 NoCoverage → mutation score
  100.0%.** Every `ConditionalExpression`, `EqualityOperator`, `BooleanLiteral`, and
  `StringLiteral` mutant flips at least one of the four truth-table outcomes the test asserts.
  **M8-N-STRONG: cleared — zero false positives on the false-confidence list.**
- **Overall: 25 mutants — 19 Killed, 4 Survived, 2 NoCoverage → mutation score 76.0%**, matching
  Stryker's own reported "All files" score-table row exactly (independent confirmation that
  `src/mutation-scan.ts`'s `mutationScore()` formula agrees with Stryker's).

**Gate:** mutant-level recall, per spec §M8(d) — "a survived mutant at a location is
deterministic given the suite," so this is a real measure; it does **not** validate the
qualitative tests-for-intent read (`docs/m8-test-quality.md` §4), which stays a documented manual
method. `pnpm verify` (offline) is green — the real Stryker JSON capture above is recorded
verbatim (trimmed to the `StrykerReport` shape) into `src/mutation-scan.test.ts`'s "M8
calibration corpus — live Stryker capture" block, asserting the per-file mutation scores and
surviving-mutant counts land exactly as this live run produced. This closes the
`docs/m8-test-quality.md` "Deferred: live timed run against a real test suite" gap. Answer key:
`src/scan/calibration/m8.entries.ts` (`module: "M8"`, spread into `CORPUS` in
`src/scan/calibration.ts`) — like M10, these entries are not yet scored by `buildCoverageMatrix`
(`summarizeMutationReport` returns a `MutationSummary`, not a `Finding[]`); a Finding-emitting
adapter (spec §3b.3: `location = file:line`, `precisionTier: "high"` per surviving mutant) and a
dedicated `pnpm validate:mutation-calibration` CLI (spec §M8(e) Layer 2) are documented
follow-ups, not required for this batch's gate.

**Root-suite isolation:** `vitest.config.ts` (repo root, new) excludes `targets/**` from the
default test glob — without it, root `vitest run` picks up
`targets/calibration/test-quality/*.test.ts` as if they were part of this repo's own suite (they
happened to pass, since the weak test is weak in its *assertions*, not broken as a test — but
running the target's own tests through the root suite was never the intent, and a future,
deliberately-failing weak-test fixture would break `pnpm verify` on an unrelated branch).

---

## Batch B7 (#71) — auth / access-control heuristics

The auth expansion batch (spec `docs/design/spec-71-security-corpus.md` §"Batch 7 — Auth /
access-control / left-open"). Custom Semgrep rules in `src/scan/rules/semgrep/auth.yml` (the
per-batch rule-file directory established by the Part-1 modularization), plus one extension to the
existing `leftover-auth` grep (`src/scan/leftover-auth.ts` — a sensitive-auth-route +
no-rate-limiter-hint check, mirroring its existing sensitive-debug-route + no-auth-hint check) and
one reuse of its existing `bypassAuth` grep. Three rows already ship (`[exists]`) and are not
duplicated here: `P-DEBUG-ENDPOINT` and `P-TODO-AUTH` (`leftover-auth` greps, `base.entries.ts`)
and `P-SRV-KEY-CLIENT` (`harvey-service-role-in-client`, `base.yml`).

The spec deliberately schedules this batch **last** in the #71 fan-out because it carries the
**highest negative-precision risk** of the whole corpus: a static tool cannot confirm an
ownership/permission/rate-limit check is *correct*, only that a specific guard shape is *absent*.
Per the locked preamble, every rule in this batch is `WARNING` + `MEDIUM` confidence → **`review`
tier — none feed the free count**, including the two classes that read as unambiguous elsewhere
(`if (true)` bypass, hardcoded hardcoded-flag gate) — the existing `leftover-auth` module is a pure
text grep with no AST, so even a `bypassAuth` hit stays `review` by that module's own design.

**Known, intentional overlap (not a bug):** `harvey-route-noauth`'s "mutation with no auth-check
call" shape also fires, at `review` tier, on several pre-existing fixtures planted for a
*different* named bug — `pages/api/dev/seed.js`, `pages/api/admin/reset.js`,
`pages/api/comments/create.js`, `pages/api/counter/increment.js` (all genuinely lack an
auth-check call too) and `pages/api/register.js`/`pages/api/webhook.js` (registration and an
HMAC-signed webhook are legitimately *not* session-authed by design; the heuristic can't tell HMAC
verification from "no auth" — a known, documented limitation of a `review`-tier heuristic, not a
gate concern). Similarly `harvey-missing-server-only` also fires on the pre-existing
`lib/supabaseAdmin.js` and `pages/api/webhook.js` (both genuinely lack a `server-only` guard).
None of this affects the gate — only `high`-tier findings on registered `negative` entries can
fail it, and every rule in this batch is `review`.

### B7 positives — planted auth/access-control bugs (must be caught, all `review` tier)

| id | location | detection | tier |
|---|---|---|---|
| P-AUTH-BYPASS-CONST | `pages/api/reports/export.js:7` | `leftover-auth`'s existing `bypassAuth` grep (`const bypassAuth = true;` guards a data read) | review |
| P-SERVER-ACTION-NOAUTH | `app/actions-auth.ts:9` | Semgrep `harvey-server-action-noauth` (`'use server'` mutation, Origin checked but no `assertPermission`/`requirePermission`/`requireRole` call) | review |
| P-ROUTE-NOAUTH | `pages/api/settings/delete.js:8` | Semgrep `harvey-route-noauth` (Pages Router handler deletes data, no `getServerSession`/`supabase.auth.getUser()` call) | review |
| P-IDOR-PARAM | `pages/api/order/get.js:7` | Semgrep `harvey-idor-param` (taint: `req.query.id` → exact-shape `.eq('id', $ID)` sink, no owner predicate) | review |
| P-MASS-ASSIGNMENT | `pages/api/profile/settings.js:6` | Semgrep `harvey-mass-assignment` (taint: `req.body` → `{ ...req.body }` spread into `.update()`) | review |
| P-SERVER-CLIENT-LEAK | `app/documents/detail-page.tsx:9` | Semgrep `harvey-server-client-leak` (`select('*')` row spread whole into a `'use client'` component's props) | review |
| P-MISSING-SERVER-ONLY | `lib/secret.js:5` | Semgrep `harvey-missing-server-only` (`process.env.INTERNAL_API_SECRET`, no `import "server-only"`, no `"use client"`) | review |
| P-NO-RATE-LIMIT | `pages/api/auth/login.js:7` | `leftover-auth`'s new sensitive-auth-route + no-rate-limiter-hint check (`src/scan/leftover-auth.ts`) | review |
| P-FAIL-OPEN | `lib/rate-limiter.js:4-11` | Semgrep `harvey-fail-open` (`catch` block returns `true` on a Redis error) | review |
| P-ROUTE-NOAUTH-CUSTOM-VERB | `pages/api/permissions/purge.js:9` | Semgrep `harvey-route-noauth` (#126 regression guard: calls `scheduleCleanup()` — not a recognized guard verb — before deleting, no `getServerSession`/`supabase.auth.getUser()`) | review |

### B7 negatives — benign lookalikes (must NOT be flagged in the free count)

| id | location | why benign / suppression |
|---|---|---|
| N-SERVER-ACTION-GUARDED | `app/actions-auth.ts` | `restoreDocument()` calls `assertPermission('documents:restore')` before mutating — `harvey-server-action-noauth`'s `pattern-not-inside` excludes it. |
| N-ROUTE-AUTH-CHECKED | `pages/api/settings/delete-safe.js` | Reads `getServerSession(req)` and 401s before the delete — `harvey-route-noauth`'s `pattern-not-inside` excludes it. This is the operator-flagged precision case: "a route that DOES check auth before the sensitive call." |
| N-IDOR-SCOPED | `pages/api/order/scoped.js` | Chains `.eq('id', req.query.id).eq('user_id', session.user.id)` — the extra `.eq()` makes the destructured statement's RHS a different (longer) expression tree than `harvey-idor-param`'s exact-shape sink pattern. The operator-flagged case: "an id-param handler that DOES scope by the caller." |
| N-MASS-ASSIGN-PICK | `pages/api/profile/settings-safe.js` | Destructures `{ displayName, bio } = req.body` and updates only those named fields — no `{ ...req.body }` spread. |
| N-DTO-MAPPED | `app/documents/detail-page-safe.tsx` | Passes two named fields (`title`, `updated_at`) to `<DocumentCard>`, not the raw `select('*')` row. |
| N-SERVER-ONLY-PRESENT | `lib/secret-safe.js` | Starts with `import "server-only";` — `harvey-missing-server-only`'s `pattern-not-inside` excludes it. |
| N-RATE-LIMIT-PRESENT | `pages/api/auth/login-limited.js` | Calls `rateLimit(req)` and 429s before signing in — `leftover-auth`'s rate-limiter-hint regex matches the call. |
| N-DEBUG-ROUTE-GUARDED | `pages/api/debug/status.js` | Sits under a `/debug` path segment but reads `getServerSession(req)` and 401s first — clears the *existing* `leftover-auth` sensitive-route heuristic's `AUTH_HINT` check. The operator-flagged case: "a debug route that IS auth-gated" — this is a regression guard on the pre-existing `P-DEBUG-ENDPOINT` heuristic, not a new rule. |
| N-ROUTE-NOAUTH-CUSTOM-GUARD | `pages/api/permissions/revoke.js` | Calls `assertPermission(req, 'permissions:revoke')` before deleting — the exact ATC dogfood shape (`assertPlatformAdmin`/`assertPermission`/`authenticateUser`, 122 FPs, #126) `harvey-route-noauth` previously couldn't see. The broadened `pattern-not-regex` (any call whose name starts with `assert`/`require`/`ensure`/`authenticate`/`authorize`/`guard`, or `check`/`verify` combined with an auth-ish token) excludes it — cleared. |

### B7 live result (2026-07-08, static: semgrep 1.164.0, gitleaks 8.30.1, trufflehog 3.95.8, osv-scanner 2.3.8, no Docker)

`pnpm validate:calibration`: **positives caught 72/72 static (24 at high/free-count), 1
connected-tier N/A; negatives cleared 47/47; zero free-count false positives — GATE PASS.** All 9
new B7 positives fire, every one at exactly `review` tier as tiered (none landed at `high` —
confirms the conservative tiering held). All 8 new B7 negatives clear; `N-MASS-ASSIGN-PICK` draws
one `review`-tier hit (the expected `harvey-route-noauth` overlap — that fixture also has no
`getServerSession` call — correctly triaged out, not a gate failure). The three
operator-flagged precision cases (route-with-auth-check, id-param-scoped-by-caller,
auth-gated-debug-route) all clear cleanly. No regression on the base, B1, B3, B4, B5, or B6
batches. `pnpm verify` (offline) is green: `src/scan/leftover-auth.test.ts` gained three unit
tests for the new rate-limit heuristic; the scorecard logic over the expanded `CORPUS` is
exercised in `calibration.test.ts`; the Semgrep rules themselves (`semgrep --validate` clean, 49
rules across the directory) are proven by the live gate above.

### Follow-up live result (2026-07-10, issue #126 — route-noauth custom guard helpers)

The 2026-07-10 ATC re-scan (expanded #71 corpus) found `harvey-route-noauth` firing on **122**
App Router routes, 0/122 real — every one gated by a NAMED CUSTOM GUARD HELPER
(`assertPlatformAdmin`/`assertPlatformAdminArea`/`assertSuperadmin`, `assertPermission` (408 call
sites), `authenticateUser`) the rule's fixed `getServerSession`/`supabase.auth.getUser`
`pattern-not-inside` couldn't see. Fixed in `src/scan/rules/semgrep/auth.yml` by broadening
`harvey-route-noauth`'s guard recognition to a `pattern-not-regex` over the matched function's
source: any call whose name starts with a guard-specific verb (`assert`/`require`/`ensure`/
`authenticate`/`authorize`/`guard`) or starts with a weaker generic verb (`check`/`verify`)
*and* also carries an auth-ish token (`admin`/`permission`/`auth`/`session`/`tenant`/`role`/
`access`/`user`/`login`) in the same identifier. A `metavariable-regex` constraint on a
`$GUARD(...)` metavariable bound only inside `pattern-not-inside` was tried first and rejected —
verified empirically (ad hoc semgrep run, not committed) that it suppresses ALL matches in the
enclosing function regardless of which call the metavariable binds to, not just the guard call;
`pattern-not-regex` is the mechanism that actually works. This stays a pure Semgrep, single-pass
fix (no two-pass project-aware guard discovery) — still `review` tier, per file-header doctrine.

New calibration pair: `P-ROUTE-NOAUTH-CUSTOM-VERB` (`pages/api/permissions/purge.js` — calls
`scheduleCleanup()`, outside both guard buckets, no session read — must still be caught, proving
the broadened regex doesn't over-suppress) and `N-ROUTE-NOAUTH-CUSTOM-GUARD`
(`pages/api/permissions/revoke.js` — calls `assertPermission(...)` before the delete, the exact
ATC shape — must clear). `pnpm validate:calibration`: **positives caught 141/141 static (61 at
high/free-count, 15 connected-tier N/A); negatives cleared 109/109 — GATE PASS.** Both new B7
entries pass; no regression on any other batch.

Acceptance check against the real ATC corpus (read-only clone, not modified): a mechanical scan
scoped to the ATC checkout, filtered to `harvey-route-noauth`/`route-noauth` findings, went from
**122 before the fix to 0 after**. The residual 5 (all webhook routes verifying an inbound
signature — `verifyGitHubSignature`/`jwtVerify`/`verifyResendSignature` (x2)
/`verifyWebhookSignature`) cleared once the weak-verb bucket's token list was extended with
`signature`/`jwt`/`webhook`/`hmac`/`token` and made order-independent (lookahead, so `jwtVerify`
matches as well as `verifyJwt`) — this is the "genuinely public, signature-verified" category the
issue's acceptance criteria names explicitly, distinct from the named-guard-helper class but
covered by the same regex family. The ATC clone was scanned read-only; not modified.

### #129/#130 close-out — B1 secrets deferred rows resolved

`P-ENV-COMMITTED` (#130, see §B1 above) and `P-SECRET-GIT-HISTORY` (#129, see "Git-history secret
gate" above) are both built, closing out B1's last two deferred rows. `pnpm validate:calibration`
(2026-07-10, gitleaks 8.30.1, trufflehog 3.95.9, semgrep 1.164.0, osv-scanner 2.3.8, no Docker):
**positives caught 142/142 static (62 at high/free-count, 15 connected-tier N/A); negatives
cleared 109/109; zero free-count false positives; git-history secret gate PASS — GATE PASS.** No
regression on any prior batch (high-tier count moved 61 → 62 for `P-ENV-COMMITTED`; the
git-history gate is additive, outside the CORPUS matrix).

---

## M7 (#72) — Performance (Supabase advisors) corpus

The M7 slice of the #72 cross-module corpus (spec `docs/design/spec-72-crossmodule-corpus.md`
§M7). **Connected tier** — like `P-RLS-DISABLED` in the base corpus, Splinter's performance
lints (`unindexed_foreign_keys`, `auth_rls_initplan`, `unused_index`) only fire against a LIVE
schema (`unused_index` additionally needs `pg_stat_user_indexes` usage history), so they can't be
scored by a static run. Fixture: `supabase/migrations/20260708000004_perf_calibration.sql`
(tables `perf_orders`, `perf_line_items`, `perf_shipments`, `perf_events`). Tool + invocation:
`pnpm perf-scan <project-ref>` → `src/perf-scan.ts::parseAdvisorFindings`, already wired with
curated `LINT_PROFILES` for all three rules (no scanner changes needed for this batch beyond
tagging every emitted `Finding` `precisionTier: "high"` — advisor lints are schema-truth, ~100%
precise once connected).

Answer key: `src/scan/calibration/m7.entries.ts` (`module: "M7"`, `expectedTier: "connected"` on
the 3 positives, spread into `CORPUS` in `src/scan/calibration.ts`). Excluded from
`pnpm validate:calibration`'s `runMechanicalScan` gate by the same `module === undefined` filter
as M8/M10 — the performance advisor isn't part of the mechanical/security scan. Bundle/Core Web
Vitals (Lighthouse, `next build` first-load JS) stays documented-plan-only per
`docs/m7-performance.md` §3 — no fixture built for it here, per spec.

### M7 positives — planted advisor lints (connected tier — must be caught once a live pull is scored)

| id | location | detection | tier |
|---|---|---|---|
| M7-P-UNINDEXED-FK | `perf_line_items.order_id` (FK to `perf_orders.id`, no covering index) | Splinter `unindexed_foreign_keys` | connected |
| M7-P-RLS-INITPLAN | `perf_orders_select_own` policy (`created_by = auth.uid()`, bare) | Splinter `auth_rls_initplan` | connected |
| M7-P-UNUSED-INDEX | `idx_perf_orders_legacy_region` (no seeded/hot query touches it) | Splinter `unused_index` | connected |

### M7 negatives — benign lookalikes (must NOT be flagged once a live pull is scored)

| id | location | why benign |
|---|---|---|
| M7-N-INDEXED-FK | `perf_shipments.order_id` (FK to `perf_orders.id`, covered by `idx_perf_shipments_order_id`) | advisor must not raise `unindexed_foreign_keys` |
| M7-N-WRAPPED-RLS | `perf_events_select_own` policy (`actor = (select auth.uid())`, wrapped) | advisor must not raise `auth_rls_initplan` |
| M7-N-USED-INDEX | `idx_perf_orders_customer_email` (backs the seeded customer-email lookup) | advisor must not raise `unused_index` once the query is exercised live — removing it would be a false "unused" call |

`M7-P-UNUSED-INDEX` and `M7-N-USED-INDEX` share a table (`perf_orders`) and rule name
(`unused_index`) — `locationFor()` groups by table, not by index, so both entries match on the
specific *index name* instead of the rule name: a genuinely-used index never generates a lint at
all, so `idx_perf_orders_customer_email` can never collide with a real finding.

### M7 offline result (2026-07-08, static — no live DB, `pnpm verify` only)

`src/perf-scan.test.ts`'s "M7 calibration corpus — modeled advisor pull" block scores
`parseAdvisorFindings` against a **modeled** advisor JSON (NOT a live capture — shaped from what
a live Splinter pull over `20260708000004_perf_calibration.sql` should return) through
`buildCoverageMatrix`: **all 3 planted positives attribute correctly at `high` precision (the
matching logic resolves `location` + rule-name/index-name `match` keywords to the exact intended
finding); all 3 negatives draw zero findings from the modeled report.** Since every
`M7-P-*` entry is `expectedTier: "connected"`, `pnpm validate:calibration`'s live gate reports
them **N/A**, not passing — the precision claim is only earned by the deferred live-branch run
(SESSION.md "Owed: connected-tier live confirmation pass": `colima start` → `supabase start` →
apply this migration on a throwaway branch → `get_advisors(performance)` → confirm the 3
positives fire and the 3 negatives don't, then delete the branch). `pnpm verify` (offline) is
green: `calibration.test.ts`'s generic `buildCoverageMatrix` tests already cover a connected-tier
entry scoring N/A regardless of findings; the new `perf-scan.test.ts` block is this batch's
Layer-1 gate, proving the shaping/matching logic ahead of that live run.

---

## M3 (#72) — Hotspot analysis (vitals) corpus — SCHEMA VERIFIED, OFFLINE GATE ONLY

The M3 slice of the #72 cross-module corpus (spec `docs/design/spec-72-crossmodule-corpus.md`
§M3). **This is deliberately not the same shape as every other module's section below** — read
the discipline note first.

**Why M3 doesn't get a precision number (read first):** a hotspot *rank* is an ordering over a
continuous score, not a true/false finding — "this file is #1 by churn×complexity" isn't
something a tool is right or wrong about the way "this string is a live secret" is. Per the
locked product decision (spec preamble #2) and the spec's M3 section, M3's free-report artifact is
a **descriptive map**, not an asserted finding, and its gate is a **regression/ordering check on
deterministic facts** — never a precision/recall percentage. Nothing in this section or in
`src/scan/calibration/m3.entries.ts` should ever be read as "M3 precision = X%."

**Schema status (issue #94, resolved):** the original batch (#95) shipped against an ASSUMED
schema because `vitals`/`vitals_cli.py` wasn't runnable in that sandbox. An operator has since run
`vitals 0.2.0 report --json <path>` against a real repo and captured the live output shape. The
real top-level report carries `hotspots` (`file_path`, `complexity_score`, `risk_score`,
`churn_data.changes` plus a flat `changes`, `health`, `role`, `centrality`, `churn_label`,
`coupling_strength`), a **separate top-level `coupling` array** (`file_a`/`file_b`/`co_changes`/
`coupling_strength`/`total_a`/`total_b` — not nested per hotspot row), and a **separate top-level
`knowledge_risk` array** (`file_path`/`truck_factor`/`author_count`/`authors` — truck-factor is
not a boolean on hotspot rows), plus `repo_info`, `overall_health`, `file_health`, `provenance`,
`files_analyzed`. `src/hotspot-scan.ts`'s `VitalsReport`/`VitalsHotspotRow` types and the
`rankHotspots`/`topKFiles`/`couplingEdges`/`truckFactorOneFiles` functions were rewritten against
this real shape; the ASSUMED/UNVERIFIED caveats in the file's header no longer apply.

### What was built

- **`src/hotspot-scan.ts`** — the M3 adapter (`rankHotspots`, `topKFiles`, `truckFactorOneFiles`,
  `couplingEdges`, `toFactFindings`), now typed against the REAL, live-captured `vitals` schema
  (`risk_score`-sorted rank, coupling and knowledge-risk read from their own top-level arrays).
- **`src/__fixtures__/vitals-report.json`** — a synthetic `vitals` report (synthetic paths/values,
  real field shape) used by `src/hotspot-scan.test.ts`. Plants every corpus fixture below.
- **`src/hotspot-scan.test.ts`** — the Layer-1 `pnpm verify` gate, scoring the adapter against the
  real-schema fixture above.
- **`src/scan/calibration/m3.entries.ts`** — `module: "M3"` corpus entries for the two
  **deterministic boolean sub-signals only** (truck-factor-1, coupling edge) — never the rank.
  Spread into `CORPUS` in `src/scan/calibration.ts`; excluded from `pnpm validate:calibration`'s
  `runMechanicalScan` gate by the same `module === undefined` filter as M7/M8/M10.
- No `pnpm validate:hotspots` / Layer 2 in this repo: the vitals plugin
  (`~/.claude/plugins/.../vitals_cli.py report --json <path>`) isn't a repo dependency, so it stays
  an operator-run command against a real checkout, not something `pnpm verify` can shell out to.
  `pnpm verify` gates against the committed synthetic fixture instead. The git-history fixture
  problem below is still open.

### M3 fixtures (`src/__fixtures__/vitals-report.json`, not static target files)

Unlike every other #72 module, M3's positives/negatives are **not files under
`targets/calibration/`** — churn, coupling, and knowledge-risk are derived from git commit
history, and `targets/calibration` is a subdirectory of the Harvey repo, not its own git repo, so
there is no history to plant against it statically. The spec (§M3(e)) calls this out as the
expensive fixture and offers two options for the real Layer 2: a build script that scaffolds a
throwaway repo and replays a scripted, date/author-pinned `git commit` sequence
(`targets/calibration-vitals/build-history.sh`), or a committed `git bundle`
(`targets/calibration-vitals/history.bundle`) unpacked at gate time. Neither is built here — the
JSON fixture now matches the real vitals output shape, but no git-history replay backs it. Tracked
as a follow-up.

| id | fixture row (in `src/__fixtures__/vitals-report.json`) | what it must produce | gate type |
|---|---|---|---|
| M3-P-HOTSPOT | `core/checkout.ts` — high churn (38) and high complexity (61) → highest risk_score (92) | ranks in the top-3 of `topKFiles` | rank regression (ordering assertion, not a `CorpusEntry`) |
| M3-N-CHURN-TRIVIAL | `generated/schema.gen.ts` — the highest raw churn in the fixture (55) but trivial complexity (4) → low risk_score (8) | must NOT rank in the top-3 despite the highest churn | rank regression (ordering assertion, not a `CorpusEntry`) |
| M3-P-TRUCK1 | `core/billing.ts` — `knowledge_risk` row with `truck_factor: 1`, sole author `alice` | `truckFactorOneFiles` includes it; `toFactFindings` emits a Knowledge-risk Finding | boolean fact (`CorpusEntry`, `module: "M3"`) |
| M3-P-COUPLING | `core/a.ts` / `core/b.ts` — one row in the top-level `coupling` array | `couplingEdges` returns one deduped edge; `toFactFindings` emits a Coupling Finding | boolean fact (`CorpusEntry`, `module: "M3"`) |
| M3-N-MULTIAUTHOR | `core/reporting.ts` — `knowledge_risk` row with `truck_factor: 3` (3 seeded authors) | must NOT be in `truckFactorOneFiles`; `toFactFindings` emits nothing for it | boolean fact (`CorpusEntry`, `module: "M3"`) |

`lib/stable.ts` (health 8.5, churn 3, complexity 5, risk_score 5) rounds out the fixture as a
boring, uncontested low-risk file — not itself a planted positive or negative.

### M3 result (2026-07-09, real schema, offline synthetic fixture)

`src/hotspot-scan.test.ts` (8 tests, all passing in `pnpm verify`): the top-K ordering block
confirms `core/checkout.ts` ranks in the top-3 and `generated/schema.gen.ts` does not, despite
having the highest raw churn in the fixture (the risk_score-weighted rank sinks it, same
discipline as jscpd/knip's FP classes); the boolean-fact block confirms
`truckFactorOneFiles`/`couplingEdges` resolve `core/billing.ts` and the `core/a.ts <> core/b.ts`
edge from the real schema's separate `knowledge_risk`/`coupling` arrays, and that `toFactFindings`
scores clean through `buildCoverageMatrix` against `m3Entries` — 2/2 positives caught, 1/1
negative cleared, zero free-count false positives. The schema is now **verified** from a live
`vitals 0.2.0 report --json` capture (not an assumption), but the gate itself still runs offline
against a committed synthetic fixture — `pnpm verify` has no vitals binary to shell out to. An
operator can run the live Layer-2 command directly against a real checkout:
`~/.claude/plugins/.../vitals_cli.py report --json <path>` (or `/vitals:scan`). The claim this
batch supports is "regression-gated hotspot signals + reproducible ranking against the real,
verified schema" — still never "M3 precision = X%." The git-history fixture (build script or
`git bundle` for a real Layer-2 `pnpm validate:hotspots` gate) remains open.

---

## M6 (#72) — Simplification / reuse rubric-eval corpus

The M6 slice of the #72 cross-module corpus (spec `docs/design/spec-72-crossmodule-corpus.md`
§M6; full rubric writeup `docs/design/m6-simplification-eval.md`). **Not a gate — M6's verdict
has no mechanical detector.** Unlike every other module in this file, there is no
`Finding[]`-emitting adapter, no `precisionTier`, and no `CorpusEntry` rows in
`src/scan/calibration.ts` for this corpus: M6's output is prose from an LLM review (the
review packet `pnpm simplify-scan` assembles from `docs/quality-extras.txt`'s SIMPLIFICATION
section), not a tool result a scorer can match against a `location`. Folding it into
`CorpusEntry`/`buildCoverageMatrix` — even filtered out of today's gate, the way M8/M10's entries
are — would leave a row shaped exactly like a precision-tier finding, one line away from being
scored as one. (Since #267, M6 also has a mechanical FREE-tier indicator layer —
`src/detectors/handrolled.ts`, hedged Info-only `M6 — Indicator: …` findings — but it is gated by
its own co-located fixture pairs in `handrolled.test.ts`, not by this corpus, and it asserts
shape presence, never a verdict. Per the spec preamble item 2 as revised 2026-07-15: indicators
free and non-grading, verdicts paid.)

Fixtures: `targets/calibration/simplify/` — seven planted items to flag, five benign
lookalikes to spare (expanded 2026-07-23 from 4+3, #813), paired by shape where possible so the
reviewer has to reason about *why* (a `// WHY:` tradeoff comment, a framework contract, a
testability seam) rather than pattern-match on shape alone. The #813 expansion gives the
dep-drop and testability-seam FP classes a second instance each and adds two positive classes
the corpus previously lacked (inconsistent patterns, premature/speculative generality).

### M6 positives — planted reinventions (should be flagged for replacement)

| id | location | the standard replacement a review should name |
|---|---|---|
| M6-P-DEBOUNCE | `simplify/debounce.ts` | a hand-rolled `setTimeout`-based debounce → stdlib/existing-dep debounce (e.g. lodash-es `debounce`) |
| M6-P-GROUPBY | `simplify/group.ts` | a hand-rolled array group-by reduce → `Object.groupBy` / `Map.groupBy` / lodash-es `groupBy` |
| M6-P-UUID | `simplify/id.ts` | a hand-rolled random-id string builder (`Math.random()`-based) → `crypto.randomUUID()` |
| M6-P-OVERABSTRACT | `simplify/manager.ts` | a single-implementation `InvoiceManager` interface + `createInvoiceManager` factory wrapping one concrete class → collapse to the concrete code |
| M6-P-DEEPEQUAL | `simplify/deep-equal.ts` | a hand-rolled recursive deep-equality function → `node:util` `isDeepStrictEqual` / lodash-es `isEqual`. Added 2026-07-23 (#813). |
| M6-P-INCONSISTENT | `simplify/dates.ts` | the same task — format a `Date` as `YYYY-MM-DD` — implemented three different ways in one file (`getFullYear` string-building, `toISOString().slice`, `Intl.DateTimeFormat("en-CA")`); the rubric's "inconsistent patterns" row → converge on one, name which. Added 2026-07-23 (#813). |
| M6-P-SPECGEN | `simplify/pipeline.ts` | a `registerExportTransform`/`runExportPipeline` extension point with exactly one registered transform; the rubric's "premature/speculative generality" row → collapse to a direct call until a second transform exists. Added 2026-07-23 (#813). |

### M6 negatives — benign lookalikes (should NOT be flagged)

| id | location | why benign |
|---|---|---|
| M6-N-DEPDROP | `simplify/depdrop.ts` | a small hand-rolled `throttle`, shaped like `debounce.ts`, but carries a `// WHY:` comment recording a deliberate tradeoff (drop a heavy dep for an 8-line function) — `quality-extras.txt` "FALSE POSITIVES": note the tradeoff, don't flag as a defect. |
| M6-N-FRAMEWORK | `simplify/framework-adapter.ts` | a single-implementation class shaped like `manager.ts`'s over-abstraction, but the shape is imposed by a library contract the code itself demonstrates: `CookieSessionStorage implements SupportedStorage`, the type `@supabase/supabase-js` re-exports from `@supabase/auth-js`, and the instance is passed to `createClient`'s `auth.storage` option — so auth-js really does call `getItem`/`setItem`/`removeItem` on it. The `getItem → string \| null` signature and the `isServer` flag are the library's, not the author's; collapsing the class would break the option's type. `quality-extras.txt` "FALSE POSITIVES": an abstraction mandated by a framework/library contract. **Rebuilt 2026-07-15 (#290)** — see "M6-N-FRAMEWORK rebuild" below. |
| M6-N-SEAM | `simplify/reconcile.ts` | a single-use helper shaped like the over-abstraction class (`reconcileTotals` has exactly one caller, `monthlyReconciliation`), but the helper is the testability seam the brief itself demands: it is the pure money-math half of a function whose other half is Supabase I/O. Inlining it into its one caller would entangle the calculation with the network — the exact "MISSING SEAMS — business logic entangled with I/O so it can't be tested without the DB/network" failure `quality-extras.txt`'s SUPPORTABILITY section names — and it is exported, so a test can exercise the money math with no client at all. `quality-extras.txt` "FALSE POSITIVES": a single-use helper that exists for testability/seam reasons. The contract is in the code (pure exported helper + I/O-entangled sole caller), not asserted in a comment — the #290 bar. **Added 2026-07-16 (#325)**; the same FP class on the M5 mechanical side is handled by `detectSingleUseHelper`'s non-exported-only scope (#370). |
| M6-N-CSVDROP | `simplify/csv.ts` | a hand-rolled CSV field parser, shaped like the classic library reinvention (`papaparse`/`csv-parse` exist) and paired with `deep-equal.ts` by shape, but its `// WHY:` block records the deliberate tradeoff (one bounded, spec-published bank format vs a new install/audit surface) *and* the revisit condition — `quality-extras.txt` "FALSE POSITIVES": the deliberate dep-drop, second instance so a reviewer can't memorize `depdrop.ts` as "the" WHY fixture. Added 2026-07-23 (#813). |
| M6-N-PRORATE | `simplify/proration.ts` | exported pure proration math (`prorateUpgradeCharge`) with exactly one caller (`applyPlanChange`) whose other half is billing-API I/O (`fetch`) — the testability-seam FP class, second instance after `reconcile.ts`. The discriminator is the pure/I-O split in the code, no comment asserting it (the #290 bar): inlining the math into its `fetch`-entangled caller would make the money calculation untestable without the network. Added 2026-07-23 (#813). |

### M6 eval status

**The fixtures are de-labelled as of 2026-07-15 (#265 follow-up).** The verdict headers that named
each file's own expected outcome now live here in this answer key and nowhere else — this section
and the tables above are the labels. The eval scores by file path, so nothing needs an in-file id.
`depdrop.ts`'s `// WHY:` block and `framework-adapter.ts`'s library-contract shape are kept:
they are the fixtures' discriminators (the content the rubric must reason about), not labels.

**Run 1 (2026-07-15, #265) — contaminated, not a usable baseline.** 4/4 positives, 2/2 negatives,
scored while every fixture still announced its own verdict in line 1. A reviewer reading only the
headers scores 6/6, so the run cannot distinguish rubric application from label-reading.

**Run 2 (2026-07-15) — first run against the de-labelled corpus: 4/4 positives, 1/2 negatives.**
The reviewer (a fresh, uncontaminated context) flagged `framework-adapter.ts` (M6-N-FRAMEWORK),
arguing Next.js dispatches `getServerSideProps` as a module-level export and never invokes a class
method — so the shape was not a framework contract and the interface was a genuine
single-implementation over-abstraction. **That argument was correct** (#290): the fixture's benign
status rested on a header comment asserting a contract the code never demonstrated.
`depdrop.ts` was spared on the `// WHY:` comment alone, which is the negative behaving as designed.

**Run 2 stays scored 1/2 against the key it ran against.** It is not retroactively re-scored to 2/2
now that the fixture is fixed: the run happened against the old file, and the reviewer's flag was the
right call on that code. The rebuild below changes what a *future* run faces, not what run 2 measured.

**Run 3 (2026-07-16, #324) — first run against the corrected key: 4/4 positives, 2/2 negatives.**
A fresh-context reviewer (Claude Fable 5 subagent, confirmed it read only its input) reviewed the
packet produced by `pnpm simplify-scan targets/calibration/simplify` — the production M6 runner path.
It spared `framework-adapter.ts` by naming the `SupportedStorage` contract and the
`createClient({ auth: { storage } })` call site as the reason the shape is mandated — the code
evidence alone, no comment present to assert it — and spared `depdrop.ts` on its `// WHY:` block.
This is the datum the #290 rebuild existed to enable: the corpus now has a measured
negative-side baseline. Report it as "reviewer agreed 4/4 positives, 2/2 negatives on this rubric
set" — never as a precision figure. Full procedure and caveats:
`docs/design/m6-simplification-eval.md` §3.3.

**Run 4 (2026-07-16, #325) — first run over the seven-file corpus: 4/4 positives, 2/3 negatives.**
A second fresh-context reviewer, same procedure. The new M6-N-SEAM (`reconcile.ts`) was **spared on
its first exposure, for the designed reason** (the pure/I-O split is a testability seam).
`framework-adapter.ts` was flagged — a miss, but on a NEW argument (duplicates `@supabase/ssr`),
not run 2's: the reviewer explicitly accepted that `SupportedStorage` mandates the class shape,
then guessed at a dependency-tree premise the packet gave it no way to check (`@supabase/ssr` is
not in this target's deps). Scored 2/3 against the key, unrationalized. Runs 3 and 4 splitting on
the same fixture is measured reviewer variance — the reason the paid tier has human sign-off.
Details: `docs/design/m6-simplification-eval.md` §3.4.

### M6-N-FRAMEWORK rebuild (2026-07-15, #290)

**Decision: rebuilt, not relabeled** — a real, code-evident library contract exists, so the negative
survives and the corpus keeps two.

The old fixture declared a `PageDataAdapter` interface with a `getServerSideProps` *method*. Next.js's
actual contract is a module-level `export async function getServerSideProps(ctx)` from a page file —
it has no mechanism to discover or call a class method (`pages/dead-page.js` in this same target uses
the real module-level form). Nothing imported the class; the framework could never reach it. The
"contract" existed only in the stripped header comment, so the row was pinning nothing.

The rebuild uses `SupportedStorage` from `@supabase/auth-js` (re-exported by `@supabase/supabase-js`,
which this target already depends on — verified against the installed 2.108.1 types:
`export type SupportedStorage = PromisifyMethods<Pick<Storage, 'getItem'|'setItem'|'removeItem'>> &
{ isServer?: boolean }`). Why this one is a genuine negative and the old one wasn't:

- **The library really calls it.** The instance is passed to `createClient({ auth: { storage } })`;
  auth-js invokes `getItem`/`setItem`/`removeItem` on it to persist sessions. The old class had no caller.
- **The shape is not the author's choice.** The three method names, the `string | null` return, and
  `isServer` are all fixed by `SupportedStorage`. A reviewer proposing "collapse this to a plain
  object/function" would produce code that no longer type-checks against the `storage` option.
- **The evidence is in the code, not a comment.** `implements SupportedStorage` + the `createClient`
  call site are the discriminator, inferable with no prose asserting anything — the bar #282 set and
  the bar `depdrop.ts` already meets with its `// WHY:` block.

It stays paired 1:1 with `manager.ts` by shape (single-implementation class, one construction site):
the reviewer still must distinguish "single implementation because it's gratuitous" from "single
implementation because a library's type says so."

**Known limitation, deliberate.** `targets/calibration` is never `npm install`ed (its `package.json`
says so — `react-supabase-helpers` is a slopsquat fixture), so the `SupportedStorage` import does not
resolve locally and the contract is not machine-checked here. It is checked by reading, against the
real published types cited above. This is the same footing as every other fixture in this target,
none of which compile; an M6 reviewer reads source, it does not typecheck. If the corpus ever gains a
real install, this fixture should typecheck as-is.

**Two-reviewer protocol + corpus expansion (2026-07-23, #813).** The paid M6 verdict is no
longer asserted from a single reviewer pass: two independent fresh-context passes over the
identical packet, compared mechanically by `pnpm exec tsx src/cli/m6-agreement.ts` — unanimous
flags to human triage, splits to a human adjudicator, uncompared files surfaced loudly. The
recorded agreement baseline is the runs 3 vs 4 pair (agreed 5/6 co-reviewed files, split on
`framework-adapter.ts`), transcribed at `docs/design/m6-eval-runs/`. The corpus expanded from
seven to twelve files in the same batch (rows marked #813 above); **no paired two-reviewer run
over the expanded corpus exists yet** — it needs two genuinely independent contexts and is
tracked as #830 (the #813 remainder). Protocol: `docs/design/m6-simplification-eval.md` §3.5.

Full write-up: `docs/design/m6-simplification-eval.md` §3.1 (run 1), §3.2 (run 2), §3.3 (run 3),
§3.4 (run 4, the first over the seven-file corpus), §3.5 (the two-reviewer protocol, #813).
Whatever a run produces, report it as **"reviewer agreed N/7 positives, M/5 negatives"** (N/4 +
M/2 for runs 1–3 and N/4 + M/3 for run 4, which predate the #813 expansion) — never as an
"M6 precision" percentage.

## Known-public/test-credential recognizer (issues #210, #211, #225)

A live public-repo scan (2026-07-12) surfaced two credibility-fatal secret-scanner FPs: the fixed
Supabase local-dev demo key (`iss:"supabase-demo"`, ships with every `supabase start`) flagged as
Critical (#210), and a SAML integration-test private key committed in a CI workflow alongside
`*.example.com`/`ENTITY_ID` markers, also flagged as Critical (#211, which also had a mismatched
`risk`/impact string copied from the JWT rule). #225 generalized both into one recognizer instead
of two one-offs: two internal gitleaks correlation-marker rules
(`supabase-demo-key-marker`, `harvey-test-idp-marker` — see `src/scan/rules/gitleaks-supabase.toml`)
that are never themselves surfaced as findings, consumed by `parseGitleaksFindings` in
`src/scan/secrets.ts` to clear or down-rank the credential they sit beside. Per-rule impact text
(`HIGH_PRECISION_IMPACT`) replaces the one-size-fits-all JWT sentence, fixing #211's bug at the
same time.

Fixtures: the demo key pair in `supabase/seed.sql` (service_role decodes to a co-located
`supabase-service-role-jwt` hit, cleared) and as a Bearer literal in `scripts/checks.mjs`
(clears `harvey-http-authorization-bearer` — the "anon-key equivalent" FP class); the SAML test
keypair in `.github/workflows/saml-integration-test.yml` (down-ranks `private-key` from Critical
to Review, not cleared — still worth a look). The real, non-demo positives (`P-SRV-ROLE-JWT-SRC`
at `lib/admin.js`, `P-PRIVATE-KEY` at `certs/key.pem`) carry no marker and are unaffected.

### Live result (2026-07-12, gitleaks 8.30.1, trufflehog 3.95.9)

All 4 new negatives clear (`N-SB-DEMO-KEY-SVC`, `N-SB-DEMO-KEY-ANON`, `N-SB-DEMO-KEY-BEARER`
fully cleared; `N-SAML-TEST-PRIVATE-KEY` clears from the free count at review, not silently
dropped), and both regression positives (`P-SRV-ROLE-JWT-SRC`, `P-PRIVATE-KEY`) still fire at
high — no change to the existing high-tier count. `pnpm verify` (offline) is green:
`secrets.test.ts` gained pure-function coverage of the clear/down-rank/impact-text logic and
`calibration.test.ts` scores the new fixtures against recorded gitleaks output with no binary
invoked.

## Batch B17 (#353) — the three never-covered dry-run planted bugs, re-triaged

Operator-directed (#353): build FP-safe mechanical rules for the three "Planted bugs" table rows
(above) that had never been covered — `WEBHOOK-REPLAY`, `COUNTER-RACE`, `UPDATE-UNSCOPED`. Per-bug
MEASURED verdict:

| bug | verdict | rule / reason |
|---|---|---|
| UPDATE-UNSCOPED | **graduated (review)** | `leftover-auth` `unscoped-write` grep: a raw `UPDATE`/`DELETE` string with no `WHERE` handed to a `.query()`/`.execute()` sink in a route file. Discriminator: the missing `WHERE` (a textual fact, like `USING (true)`, #333). FP shape: a deliberate admin reset/backfill — why it's review, not free-count. |
| COUNTER-RACE | **graduated (review)** | `detectCounterRaceFindings` (`src/scan/counter-race.ts`) AST: a `.select()` of a table whose value is written back via `.update()` on the SAME table after a `+`/`-` derivation. Discriminator: the read→arithmetic→write DATAFLOW, not mere table co-occurrence. FP shape (read-then-write of an unrelated fresh value) is cleared by the arithmetic-derived-from-read gate. |
| WEBHOOK-REPLAY | **stays LLM-tier (measured, does not graduate)** | Proving no replay guard exists is proving a negative across the whole handler and its callees. A rule flagging every HMAC-verifying webhook without a recognised nonce/timestamp would FP on correct handlers that dedupe via an idempotency key, provider-side dedupe, or a DB unique constraint — no FP-safe discriminator. Recorded on `src/cli/dry-run-scorecard.ts`. |

### B17 benign siblings (new — the negatives are the deliverable)

| id | location | why benign |
|---|---|---|
| N-UPDATE-SCOPED | `pages/api/profile/update-safe.js` | same raw-`pool` UPDATE, scoped with `WHERE id = $2` on the caller's id — the rule re-checks the matched DML for a `WHERE` and skips it. |
| N-COUNTER-ATOMIC | `pages/api/counter/increment-safe.js` | atomic increment via a server-side RPC (`increment_counter`) — no select-then-update read-modify-write pair for the AST to flag. |

WEBHOOK-REPLAY gets no benign sibling here — no rule ships for it, so there is no rule to FP-pin.

### B17 live result

`pnpm validate:calibration`: **GATE PASS — zero free-count false positives; every high-tier rule
fired on its positive.** Both graduated positives (`P-UPDATE-UNSCOPED`, `P-COUNTER-RACE`) fire at
review and both new negatives are cleared; the two #354 graduations (`P-MW-MATCHER-EXCLUDES-API`,
`P-DRAFTMODE-NO-SECRET`) also fire at review with their negatives cleared. Corpus totals after
B17/#354: **153/157 static positives caught (61 at high/free-count, 15 connected N/A); 137/137
static negatives cleared.** Four review-tier recall gaps remained then, all measured LLM-tier:
`P-BOLA-BODY-OWNER`, `P-MW-SOLE-AUTHZ`, `P-HOST-HEADER-URL`, `P-CLIENT-RENDER-AUTHZ`. The dry-run
scorecard now reads **7 caught / 1 missed (WEBHOOK-REPLAY) / 4 requires-live-run**.

**Updated by #433/#465 (live gate re-run 2026-07-17): GATE PASS — `P-BOLA-BODY-OWNER` graduated**
(caught at review by the `bola-owner` AST pass in `runMechanicalScan`; `N-BOLA-SESSION-OWNER`
stays fully silent), so the review-tier recall gaps are down to THREE (`P-MW-SOLE-AUTHZ`,
`P-HOST-HEADER-URL`, `P-CLIENT-RENDER-AUTHZ`). Corpus totals after #433/#465: **156/159 static
positives caught (61 at high/free-count, 15 connected N/A); 139/139 M1 static negatives cleared;
M9 census 4 positives / 4 negatives** (the #465-widened server-action shapes — see Batch
M9-authz below). The dry-run scorecard is unchanged (the 12 planted bugs are a separate ledger).

## Batch B18 (#684) — service-role query in a background-job path with no tenant predicate

Operator-directed (#684): the #681 JOB-TENANT-SCOPE class graduates into the scored M1 recall
corpus, mirroring how #433 (bola-owner) and #353 (counter-race) each earned a scored positive+
negative. The detector already ships (`src/scan/job-tenant-scope.ts`, registered as
`scanJobTenantScope` in `runMechanicalScan`); this batch only adds its fixtures + answer-key rows so
the class is measured by the live gate, not just its co-located unit test.

| bug | verdict | rule / reason |
|---|---|---|
| JOB-TENANT-SCOPE | **graduated (review)** | `scanJobTenantScope` (`src/scan/job-tenant-scope.ts`) AST: a service-rooted `.from(X).select/update/delete(...)` in a background-job path (`inngest`/`jobs`/`queues`/`workers`/`app/api/cron`) with NO in-chain tenant predicate (`.eq`/`.in`/`.filter`/`.match` on a tenant/owner column). Discriminator: the MISSING predicate itself — a job has no request/session, so the RLS-bypassing client returns/mutates rows across every tenant (ATC finding #2003). Stays review: the AST can't see a wrapper/RPC enforcing scoping out of view (suppress with `// d091-allow:service-role-tenant`). |

### B18 positive + benign sibling

| id | location | class / why |
|---|---|---|
| P-JOB-TENANT-SCOPE | `src/inngest/import-inbound.ts` | `admin.from("gmail_inbound_messages").select("*")` in an Inngest job with no tenant predicate — cross-tenant read. Caught at review by `scanJobTenantScope`. |
| N-JOB-TENANT-SCOPED | `src/inngest/import-inbound-safe.ts` | same service-role read scoped by `.eq("tenant_id", event.data.tenantId)` — the explicit predicate confines the read to one tenant, so nothing fires. Cleared. |

Answer key: `src/scan/calibration/b18-job-tenant-scope.entries.ts`.

## Batch M9-authz (#221/#318, widened by #465) — client-supplied owner id trusted by a server action

#221 catalogued one recurring class three ways; only the first proved mechanically detectable at
acceptable precision (the other two stay semantic/paid-tier — see below). `detectClientSuppliedOwnerId`
(`src/detectors/app-router.ts`) originally fired only when an AUTHENTICATED action's mutating chain
(`insert`/`update`/`upsert`/`delete`/`rpc`) was scoped by an ownership-column `.eq()` whose value
roots in a parameter rather than a session binding, with no session-vs-client comparison in the
body. **Widened by #465 (operator ruling)** to the three shapes proposit's real instances take —
bare `.eq("id", …)`, INSERT-value owner ids (`.insert({ user_id: <argument> })`), and
no-in-body-auth — all gated on the chain rooting in the RLS-bypassing service/admin client (the
measured precision boundary; on the RLS client the generic missing-auth finding owns the defect).
Measured against proposit HEAD (286 files): recall 3/3 on the #221 instances, 0 FP. When a widened
shape fires on a no-auth action, the generic `M1 — Server Action missing authorization check`
finding for that action is SUBSUMED (one code defect, one finding). Entries in
`src/scan/calibration/m9-authz.entries.ts`, tagged `module: "M9"` (runs in `static-detect`, not
`runMechanicalScan`, so it stays out of `validate:calibration`'s M1 gate — its own gate is
`app-router.test.ts`; the pages/api surface of the same class DOES run mechanically — see
`P-BOLA-BODY-OWNER`/#433 in §B15).

| id | location | detection | tier |
|---|---|---|---|
| P-AUTHN-CLIENT-OWNER | `app/actions-owner.ts` | `detectClientSuppliedOwnerId` — `updateProfileName()` authenticates and schema-validates, then `.eq("user_id", userId)` with the client's `userId` instead of the session's | review |
| P-AUTHN-CLIENT-OWNER-DELETE | `app/actions-delete.ts` | same detector, a second real instance exercising the DELETE verb and the `account_id` ownership column (#427 parity — two positives across different mutation-verb/column surfaces) | review |
| P-SVC-NOAUTH-BARE-ID | `app/actions-svc-bareid.ts` | #465 bare-id shape — no auth, service-role client, `.eq("id", userId)` with the client's `userId` (proposit's `updateUserProfileAction`); subsumes the generic missing-auth finding | review |
| P-SVC-NOAUTH-INSERT-OWNER | `app/actions-svc-insert.ts` | #465 INSERT-value shape — no auth, service-role client, `.insert({ user_id: userId })` (proposit's `acceptInvitationAction`); subsumes the generic missing-auth finding | review |
| N-AUTHN-SESSION-OWNER | `app/actions-owner-session.ts` | negative — identical shape, but the `.eq("user_id", …)` value reads off `currentUser.id` (session-bound), so `collectSessionBoundNames` clears it | — |
| N-AUTHN-OWNER-COMPARED | `app/actions-owner-compared.ts` | negative — the client-supplied `accountId` IS used in `.eq()`, but `currentUser.id !== accountId` throws first; `hasOwnershipComparison` clears it | — |
| N-RLS-CLIENT-BARE-ID | `app/actions-rls-bareid.ts` | negative — same no-auth + bare `.eq("id", …)` syntax as P-SVC-NOAUTH-BARE-ID but on the plain RLS client (proposit's `updateOrganisationLogo`); the widened shape stays silent, the generic missing-auth finding fires unsubsumed | — |
| N-SVC-INSERT-SESSION-OWNER | `app/actions-svc-insert-session.ts` | negative — same service-role insert shape but `user_id: user.id` reads off the session; also pins `INSERT_OWNER_COLUMN`'s boundary (the client-chosen `organisation_id` is a container column, not an owner-identity column) | — |

The other two #221 shapes stay semantic (business/whole-program context an AST pass doesn't have)
and were already seeded before #221 in earlier batches, not new here: trusting a client-supplied
security-relevant value is `P-CLIENT-PAYMENT-AMOUNT`/`P-CLIENT-PRIV-HEADER` (Batch B14 above); a
permission check present only in the UI is `P-CLIENT-RENDER-AUTHZ`/`P-MW-SOLE-AUTHZ` (Batch B15
above) — both got a matching LLM-prompt lens added to `docs/scan-extras.txt`'s HIGH section (#328).
