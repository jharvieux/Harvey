> **Product decisions (locked 2026-07-09) — these govern how this spec is built:**
>
> 1. **Free count = high-precision (~100%) findings only.** The `review`-tier (heuristic)
>    and `connected`-tier (live-advisor) classes are still *scanned*, but they are NOT
>    asserted in the free report and do NOT affect the free A–F grade (asserting a heuristic
>    "Critical" to a stranger is the credibility-fatal failure mode). They become **verified
>    candidate findings in the PAID report** — LLM triage → human sign-off → dynamic
>    confirmation for high-severity — before they are asserted. So: free = the high-precision
>    findings + the grade; paid = those plus the verified review/connected findings.
> 2. **Judgment-heavy modules:** M3 hotspots may appear in the free report ONLY as a limited,
>    deterministic **descriptive map** (churn×complexity, top-K) — factual (client's own data),
>    false-positive-safe, not asserted as findings; deeper coupling/knowledge-risk stays paid.
>    **M6 simplification is paid-only** (LLM opinion; no false-positive-safe automated free
>    version). Principle: factual/descriptive & FP-safe can be free; asserted judgments cannot.

# Spec — Issue #71: Expand the mechanical security corpus toward the top ~100 Next.js/Supabase classes

Status: research deliverable (2026-07-08). Author: security-tooling research agent. Scope: **research only** — no repo code, rules, or fixtures were modified. This spec defines exactly what #71 should build; the batches below are the implementation contract for the agents that will own `targets/calibration/GROUND-TRUTH.md` + the `src/scan/calibration.ts` answer key.

> **Housekeeping flag for a human:** GitHub issue #71 currently carries one comment from an untrusted account (`kogokowewo`) containing a phishing-style `.zip` link. It is **not** part of the spec — recommend deleting/reporting it. Do not fetch that link.

---

## 1. Intro — how this extends the existing 17/15 corpus

The existing corpus (`docs/design/calibration-corpus-spec.md`, encoded in `src/scan/calibration.ts` and `targets/calibration/GROUND-TRUTH.md`) is **17 positives + 15 negatives**, gated by #61: a rule ships/counts only if it fires on its planted positive AND stays silent on its benign lookalike. Live result on 2026-07-08: 14/16 static positives caught (6 at free-count `high`), 15/15 negatives cleared, zero free-count FPs.

This spec is a **strict superset**: every existing entry is kept (marked `[exists]`), and ~80 new positive classes + ~35 new negative lookalikes are added to reach **~100 positives / ~50 negatives**. The trust model is unchanged (`mechanical-toolchain.md` §7): only `high`-tier (~100% corpus precision) rules feed the free "quick scan" count; everything heuristic is `review`; anything needing a live DB is `connected` (Advisor tier, N/A for a static run).

**Honesty note on the count.** The task asked for ~100 *mechanically-detectable* classes. I can justify **~100 positive classes total**, but they are NOT all free-count-safe. The realistic split is:

| Tier | Meaning | ~count | Feeds free count? |
|---|---|---|---|
| `high` | ~100% precise (pattern/verification/exact-version) | **~34** | Yes |
| `review` | heuristic — needs LLM/human triage | **~42** | No (paid/triage) |
| `connected` | needs a live Supabase project (Advisor/Mgmt API) | **~18** | No (connected tier) |

So the deliverable is honest about padding: ~34 of the ~100 are credible free-count rules; the rest are real, valuable, mechanically-*runnable* checks that are correctly quarantined to `review`/`connected`. Padding the free count past ~34 would break the "a wrong Critical is credibility-fatal" rule. Sources are cited per row; **every Semgrep registry rule id below is marked `‡` and MUST be confirmed with `semgrep --validate` / `semgrep --config <pack> --dump-ast` before it is wired into the gate** — registry ids drift and I cannot verify them from here.

---

## 2. Positive classes (planted-vuln fixtures) — target ~100

Legend: **Tier** = `high` (free count) / `review` (triage) / `connected` (live DB). `[exists]` = already in the corpus (keep). `‡` = Semgrep registry rule id to verify with `semgrep --validate`. Fixtures live under `targets/calibration/`. All secret values are FAKE (valid-shape only); the app is never deployed.

### Batch 1 — Injection & code-execution family (Semgrep custom + `p/javascript`/`p/owasp-top-ten`)

| id | class | CWE / OWASP | fixture sketch (file + minimal code) | detection mechanism | tier | source |
|---|---|---|---|---|---|---|
| P-SQLI-CONCAT `[exists]` | SQLi via template-literal interpolation | CWE-89 / A03 | `pages/api/search.js` — `` pool.query(`... ilike '%${q}%'`) `` | custom `harvey-sql-injection-template` (taint) | high | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| P-SQLI-RPC | SQLi via `supabase.rpc()`/`.sql` built from input | CWE-89 / A03 | `pages/api/report.js` — `` supabase.rpc('exec', { q: `select ... ${req.query.id}` }) `` | extend `harvey-sql-injection-template` sink set to `.rpc`/`sql\`\`` | high | [Supabase RPC](https://supabase.com/docs/guides/database/functions) |
| P-POSTGREST-FILTER-INJ | PostgREST filter injection via string `.or()`/`.filter()` | CWE-89 / A03 | `pages/api/find.js` — `.or(\`name.eq.${req.query.n}\`)` | custom taint rule (req → `.or`/`.filter`/`.textSearch` string arg) | review | [PostgREST filters](https://postgrest.org/en/stable/references/api/tables_views.html) |
| P-CMD-INJECTION | OS command injection via `exec`/`execSync` template literal | CWE-78 / A03 | `pages/api/convert.js` — `` exec(`convert ${req.query.f}`) `` | custom taint (req → `child_process.exec*`); `‡ javascript.lang.security.audit.dangerous-exec` | high | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| P-EVAL-CODE-INJ | Code injection via `eval`/`new Function(reqInput)` | CWE-95 / A03 | `pages/api/calc.js` — `eval(req.body.expr)` | `‡ javascript.lang.security.audit.eval-detected` + custom taint | high | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| P-PROTO-POLLUTION | Prototype pollution via recursive merge / `lodash.merge(req.body)` | CWE-1321 / A08 | `lib/merge.js` — `merge({}, req.body)` into config | `‡ javascript.lang.security.audit.prototype-pollution*`; custom | review | [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) |
| P-INSECURE-DESERIALIZE | Unsafe deserialization (`node-serialize`, `JSON.parse` reviver exec, `vm`) | CWE-502 / A08 | `pages/api/import.js` — `unserialize(req.body.data)` | `‡ javascript.lang.security.audit.unsafe-deserialization`; dep presence | review | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| P-XXE | XXE via `xml2js`/`libxmljs` with external entities enabled | CWE-611 / A05 | `pages/api/xml.js` — parse with `noent: true` on req body | `‡ javascript.lang.security.audit.xml-external-entity` | review | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) |
| P-PATH-TRAVERSAL | Path traversal — req input joined into `fs`/served file path | CWE-22 / A01 | `pages/api/file.js` — `fs.readFile(path.join(dir, req.query.name))` | custom taint (req → `path.join`→`fs`); `‡ javascript.lang.security.audit.path-traversal` | review | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| P-ZIP-SLIP | Archive extraction path traversal (zip-slip) | CWE-22 | `lib/unzip.js` — extract entry name to disk unchecked | `‡ javascript.lang.security.audit.zip-slip` | review | [Snyk zip-slip](https://security.snyk.io/research/zip-slip-vulnerability) |
| P-SSTI | Server-side template injection (handlebars/ejs from input) | CWE-1336 / A03 | `pages/api/render.js` — `ejs.render(req.body.tpl)` | `‡ javascript.lang.security.audit.template-injection`; custom | review | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) |
| P-REDOS | ReDoS — catastrophic-backtracking regex on user input | CWE-1333 | `lib/parse.js` — `new RegExp('(a+)+$').test(req.query.s)` | Semgrep `‡ ...redos` / linter — needs backtracking analysis | review | [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) |
| P-LOG-INJECTION | Log injection / forging via unsanitized req in log line | CWE-117 | `pages/api/track.js` — `console.log(\`user \${req.query.u}\`)` | `‡ ...log-injection` (heuristic) | review | [CWE-117](https://cwe.mitre.org/data/definitions/117.html) |

### Batch 2 — XSS & client-side sink family (custom + `p/react` + `eslint-plugin-no-unsanitized`)

| id | class | CWE / OWASP | fixture sketch | detection mechanism | tier | source |
|---|---|---|---|---|---|---|
| P-XSS-DSIH `[exists]` | Reflected XSS via tainted `dangerouslySetInnerHTML` | CWE-79 / A03 | `pages/post.js` — `__html: router.query.body` | custom `harvey-dangerously-set-inner-html` (taint+sanitizer stop) | high | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| P-XSS-STORED-DSIH | Stored XSS — DB value → `dangerouslySetInnerHTML` | CWE-79 | `pages/comment.js` — `__html: row.body` from Supabase read | custom rule w/ DB-read source; `review` (stored-source taint) | review | [OWASP XSS](https://owasp.org/www-community/attacks/xss/) |
| P-XSS-HREF-JS | XSS via `javascript:` URL in `href`/`src` from input | CWE-79 | `components/Link.jsx` — `<a href={req-derived}>` | `‡ typescript.react.security.audit.react-href-var` | review | [React href XSS](https://semgrep.dev/p/react) |
| P-DOM-XSS-INNERHTML | DOM XSS via `el.innerHTML =`/`insertAdjacentHTML` from input | CWE-79 | `components/Widget.jsx` — `ref.current.innerHTML = q` | `eslint-plugin-no-unsanitized` `no-unsanitized/property` | high | [no-unsanitized](https://github.com/mozilla/eslint-plugin-no-unsanitized) |
| P-DOM-XSS-DOCWRITE | DOM XSS via `document.write(userInput)` | CWE-79 | `components/Embed.jsx` — `document.write(location.hash)` | `‡ ...document-write`; no-unsanitized/method | high | [no-unsanitized](https://github.com/mozilla/eslint-plugin-no-unsanitized) |
| P-XSS-DANGEROUS-URL | Open-URL sink `window.location = userInput` | CWE-601/79 | `components/Nav.jsx` — `window.location = params.get('to')` | custom taint (req/hash → `location` assign) | review | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) |
| P-XSS-SETATTR | XSS via `setAttribute('href'/'src', userInput)` | CWE-79 | `components/Img.jsx` — dynamic `setAttribute` | `‡ ...set-attribute` | review | [React pack](https://semgrep.dev/p/react) |

### Batch 3 — Secrets & credential exposure (gitleaks + TruffleHog `--only-verified` + custom `NEXT_PUBLIC` regex)

Detection: gitleaks provider patterns / TruffleHog verification / custom regex; `high` **only** for verified secrets or high-specificity provider patterns; unverifiable "valid-shape but dead" keys are `review` (matches how `P-HARDCODED-KEY` is already scored).

| id | class | CWE / OWASP | fixture sketch | detection mechanism | tier | source |
|---|---|---|---|---|---|---|
| P-NEXTPUBLIC-SECRET `[exists]` | Secret mis-prefixed `NEXT_PUBLIC_` | CWE-200 / A05 | `.env.local` — `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_…` | custom `supabase-next-public-secret-leak` regex + gitleaks | review | [Supabase keys](https://supabase.com/docs/guides/getting-started/api-keys) |
| P-HARDCODED-KEY `[exists]` | Hardcoded Anthropic key in source | CWE-798 | `lib/ai.js` — `const key = "sk-ant-api03-…"` | gitleaks `anthropic-api-key` (dead → not verified) | review | [gitleaks](https://github.com/gitleaks/gitleaks) |
| P-SRV-ROLE-JWT-SRC | Hardcoded Supabase `service_role` JWT in source | CWE-798 / A05 | `lib/admin.js` — `createClient(url, "eyJ…role:service_role…")` | gitleaks custom decode `role` claim (`--max-decode-depth 2`) | high | [mechanical-toolchain §3](https://supabase.com/docs/guides/getting-started/api-keys) |
| P-SB-SECRET-KEY | Hardcoded `sb_secret_` API key | CWE-798 | `lib/db.js` — `sb_secret_…` literal | gitleaks custom `sb_secret_` pattern | high | [Supabase keys](https://supabase.com/docs/guides/getting-started/api-keys) |
| P-SRV-ROLE-IN-BUNDLE | `service_role` JWT present in built `.next/static` chunk | CWE-200 | build a chunk embedding the service-role JWT | scan built bundle for decoded `role: service_role` | high | [scan-gaps §1.1](https://blog.ogwilliam.com/post/moltbook-hack-supabase-vibe-coding) |
| P-OPENAI-KEY | Hardcoded OpenAI `sk-`/`sk-proj-` key | CWE-798 | `lib/llm.js` — `sk-proj-…` literal | gitleaks/TruffleHog `openai` (verify) | high (verified) / review | [gitleaks](https://github.com/gitleaks/gitleaks) |
| P-STRIPE-SECRET | Hardcoded Stripe `sk_live_` secret | CWE-798 | `lib/pay.js` — `sk_live_…` | TruffleHog `stripe` (verify) | high (verified) / review | [gitleaks](https://github.com/gitleaks/gitleaks) |
| P-AWS-KEY | Hardcoded AWS `AKIA…` access key + secret | CWE-798 | `lib/s3.js` — `AKIA…` + secret | TruffleHog `aws` (verify against STS) | high (verified) / review | [TruffleHog](https://github.com/trufflesecurity/trufflehog) |
| P-GH-TOKEN | Hardcoded GitHub `ghp_`/`github_pat_` token | CWE-798 | `scripts/deploy.js` — `ghp_…` | TruffleHog `github` (verify) | high (verified) / review | [TruffleHog](https://github.com/trufflesecurity/trufflehog) |
| P-DB-URL-PASSWORD | Connection string w/ inline password committed | CWE-798 | `.env.local` — `postgres://user:pass@host/db` | gitleaks `postgres`/URI-with-cred pattern | high | [gitleaks](https://github.com/gitleaks/gitleaks) |
| P-PRIVATE-KEY | Committed private key (`-----BEGIN … PRIVATE KEY-----`) | CWE-798 | `certs/key.pem` | gitleaks `private-key` | high | [gitleaks](https://github.com/gitleaks/gitleaks) |
| P-JWT-SIGNING-SECRET | Hardcoded JWT/session signing secret | CWE-798/321 | `lib/auth.js` — `jwt.sign(p, "hardcoded-secret")` | custom pattern (literal secret to `jwt.sign`/session) | review | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) |
| P-ENV-COMMITTED | Real `.env`/`.env.local` committed with live values | CWE-200 | committed `.env.local` (not allowlisted) w/ non-anon secret | gitleaks path + verification | high (verified) | [gitleaks #1830](https://github.com/gitleaks/gitleaks/issues/1830) |
| P-SECRET-GIT-HISTORY | Secret removed from HEAD but live in git history | CWE-200 | commit adds+removes a verified key | gitleaks/TruffleHog full-history scan | high (verified) | [scan-gaps §1.3](https://github.com/gitleaks/gitleaks) |
| P-SENDGRID-KEY | Hardcoded SendGrid `SG.…` / Twilio / Slack token | CWE-798 | `lib/email.js` — `SG.…` | TruffleHog provider detectors (verify) | high (verified) / review | [TruffleHog](https://github.com/trufflesecurity/trufflehog) |

### Batch 4 — Framework CVEs & dependency version hygiene (OSV-Scanner + `checkNextVersionCVEs`)

Requires a **committed lockfile** for OSV coverage (the calibration target currently ships none — `P-DEP-CVE` is a documented miss; #71 should add a lockfile fixture so these become live, or keep them `review`/documented-miss).

| id | class | CWE / ref | fixture sketch | detection mechanism | tier | source |
|---|---|---|---|---|---|---|
| P-NEXT-CVE-29927 `[exists]` | Next middleware auth bypass | CVE-2025-29927 / A06 | `package.json` — `next@^14.2.5` (<14.2.25) | `checkNextVersionCVEs` (GHSA-f82v-jwr5-mffw) | high | [JFrog](https://jfrog.com/blog/cve-2025-29927-next-js-authorization-bypass/) |
| P-NEXT-CVE-RSC `[exists]` | React2Shell RSC RCE (CVSS 10, KEV) | CVE-2025-55182/66478 | `next@^14.2.5` (<14.2.35) | `checkNextVersionCVEs` | high | [React blog](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components) |
| P-NEXT-CVE-WS-SSRF | Next WebSocket-upgrade SSRF | CVE-2026-44578 (CVSS 8.6) | `next` in `>=13.4.13 <15.5.16` | `checkNextVersionCVEs` range | high | [GHSA-c4j6-fc7j-m34r](https://github.com/advisories/GHSA-c4j6-fc7j-m34r) |
| P-NEXT-CVE-CACHE | Next cache-poisoning / image-optimizer batch (May 2026) | CVE-2025-49826/57752/59471 | pin an affected `next` minor | `checkNextVersionCVEs` / OSV | high | [Vercel changelog](https://vercel.com/changelog/next-js-may-2026-security-release) |
| P-REACT-DOM-CVE | Vulnerable `react-server-dom-*` version | React2Shell chain | pin `react-server-dom-webpack` < 19.0.1 | OSV / version check | high | [React blog](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components) |
| P-NEXT-EOL | EOL / unsupported Next major (<14) | CWE-1104 | pin `next@13.0.0` | version-check EOL table | review | [scan-gaps §2.5](https://nextjs.org/blog) |
| P-DEP-CVE `[exists]` | Known-vulnerable runtime dep | CWE-1395 / A06 | `lodash@4.17.11` (proto-pollution) | OSV-Scanner exact GHSA (needs lockfile) | review (no lockfile) | [OSV-Scanner](https://google.github.io/osv-scanner/) |
| P-DEP-CVE-CRITICAL | Known-**critical** runtime dep CVE, confirmed range | CWE-1395 / A06 | a runtime dep pinned in a KEV range | OSV exact match on critical GHSA | high | [OSV-Scanner](https://google.github.io/osv-scanner/) |

### Batch 5 — Supply chain / manifest hygiene (custom lockfile+manifest scan)

| id | class | CWE / ref | fixture sketch | detection mechanism | tier | source |
|---|---|---|---|---|---|---|
| P-SLOPSQUAT `[exists]` | Slopsquatted / hallucinated dep | CWE-1357 | `react-supabase-helpers` (nonexistent) | npm-registry existence check (to build) | review (not yet caught) | [Mend](https://www.mend.io/blog/the-hallucinated-package-attack-slopsquatting/) |
| P-POSTINSTALL `[exists]` | Lifecycle-script supply-chain risk | CWE-506 | root `package.json` `postinstall` | `checkInstallScripts` | review | [Unit42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/) |
| P-TYPOSQUAT | Typosquat edit-distance-1 dep name | CWE-1357 | `expresss`/`loadsh` in deps | offline edit-distance vs popular-corpus | review | [scan-gaps §5.4](https://arxiv.org/pdf/2509.22202) |
| P-UNPINNED-DEP | Floating range / `*` / `latest` version | CWE-1104 | `package.json` — `"axios": "*"` | manifest parse (range detection) | review | [scan-gaps §5.2](https://docs.npmjs.com/cli/v10/configuring-npm/package-json) |
| P-MISSING-LOCKFILE | No committed lockfile | CWE-1104 | delete `package-lock.json` | presence check | review | [scan-gaps §5.2](https://docs.npmjs.com/cli/v10/configuring-npm/package-json) |
| P-NONREGISTRY-DEP | Dep installed from git/http URL (not registry) | CWE-829 | `"x": "git+https://…"` / `http://…tgz` | manifest parse (protocol) | review | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) |
| P-KNOWN-IOC-PKG | Installed version on a Shai-Hulud/known-IoC list | CWE-506 | pin a package@version on the IoC list | lockfile cross-check vs IoC feed | high (exact IoC) | [CISA Shai-Hulud](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) |

### Batch 6 — Headers / CORS / CSRF / transport / error-hygiene (config-parse custom)

| id | class | CWE / OWASP | fixture sketch | detection mechanism | tier | source |
|---|---|---|---|---|---|---|
| P-NO-CSP `[exists]` | Missing CSP | CWE-1021 / A05 | `next.config.js` — no `headers()` CSP | `checkMissingCsp` | review | [scan-gaps §4b.1](https://www.ox.security/blog/vibe-coding-security/) |
| P-CORS-WILDCARD `[exists]` | Wildcard CORS + credentials | CWE-942 / A05 | `pages/api/data.js` — `ACAO: '*'` | custom `harvey-permissive-cors` | high | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) |
| P-CORS-REFLECT-ORIGIN | CORS reflects `Origin` header + `Allow-Credentials:true` | CWE-942 | `middleware.ts` — `ACAO = req.headers.origin` + credentials | custom rule (reflected origin + credentials) | high | [PortSwigger CORS](https://portswigger.net/web-security/cors) |
| P-CSP-UNSAFE-INLINE | CSP present but `unsafe-inline`/`unsafe-eval` in `script-src` | CWE-1021 | `next.config.js` — CSP with `'unsafe-inline'` | `checkMissingCsp` extension (parse directive) | review | [CSP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) |
| P-NO-HSTS | Missing HSTS header | CWE-319 | no `Strict-Transport-Security` in headers | header-presence check | review | [scan-gaps §4b.1](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) |
| P-NO-FRAME-OPTIONS | Missing `X-Frame-Options`/`frame-ancestors` (clickjacking) | CWE-1021 | no frame directive | header-presence check | review | [Clickjacking](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html) |
| P-NO-NOSNIFF | Missing `X-Content-Type-Options: nosniff` | CWE-693 | absent header | header-presence check | review | [OWASP headers](https://owasp.org/www-project-secure-headers/) |
| P-CSRF-MISSING | Mutating Server Action / route, cookie auth, no CSRF/origin check | CWE-352 / A01 | `app/actions.ts` — `'use server'` mutation, no origin check | custom heuristic (cookie auth + mutation, no token) | review | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| P-COOKIE-INSECURE | Session cookie without `Secure`/`HttpOnly`/`SameSite` | CWE-614/1004 | `res.setHeader('Set-Cookie','sid=…')` bare | `‡ ...cookie-missing-secure`/custom | high | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) |
| P-OPEN-REDIRECT `[exists]` | Open redirect | CWE-601 / A01 | `pages/api/redirect.js` — req URL → `res.redirect` | custom `harvey-open-redirect` (taint) | review | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) |
| P-VERBOSE-ERROR | Stack trace / raw error echoed to client in prod | CWE-209 | `pages/api/x.js` — `res.json({ stack: err.stack })` | custom pattern (`err.stack`/`.message` in response) | review | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) |
| P-DB-ERROR-DISCLOSURE | Raw Postgres error `.message`/`.details` echoed | CWE-209 | `res.status(500).json(error)` from supabase-js error | custom pattern | review | [scan-extras LOW](https://cwe.mitre.org/data/definitions/209.html) |
| P-NODE-ENV-NOT-PROD | `NODE_ENV` not production / dev-mode markers shipped | CWE-489 | `next.config.js` / code forcing dev | config parse | review | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) |

### Batch 7 — Auth / access-control / left-open (Semgrep custom + `leftover-auth` greps) — mostly `review`

| id | class | CWE / OWASP | fixture sketch | detection mechanism | tier | source |
|---|---|---|---|---|---|---|
| P-DEBUG-ENDPOINT `[exists]` | Debug/seed/admin route, no auth | CWE-489 / A05 | `pages/api/dev/seed.js`; `admin/reset.js` `isAdmin=true` | `leftover-auth` (sensitive-route + `isAdmin=true`) | review | [scan-gaps §4.5](https://www.ox.security/blog/vibe-coding-security/) |
| P-TODO-AUTH `[exists]` | Placeholder/left-open auth | CWE-306 / A01 | `comments/create.js` — `// TODO: auth` | `leftover-auth` grep | review | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) |
| P-AUTH-BYPASS-CONST | Hardcoded `if (true)`/`bypassAuth`/`skipAuth` gate | CWE-489 | route with `const authed = true` | `leftover-auth` const-bypass grep | review | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) |
| P-SERVER-ACTION-NOAUTH | `'use server'` mutation with no authority check | CWE-862 / API5 | `app/actions.ts` — mutate, no `assertPermission` | custom (`'use server'` + mutation, no guard call) | review | [scan-extras M9](https://cwe.mitre.org/data/definitions/862.html) |
| P-ROUTE-NOAUTH | Route handler mutation with no auth guard | CWE-862 / API5 | `app/api/x/route.ts` — `POST` mutate, no session read | custom heuristic | review | [OWASP API5](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) |
| P-IDOR-PARAM | IDOR — `req.params.id` into query with no ownership predicate | CWE-639 / API1 | `pages/api/order/[id].js` — `.eq('id', req.query.id)` only | custom heuristic (id from req, no `auth.uid()`/owner eq) | review | [OWASP API1 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) |
| P-MASS-ASSIGNMENT | Mass assignment — `{...req.body}` spread into insert/update | CWE-915 / API3 | `pages/api/profile.js` — `.update({ ...req.body })` | custom (spread of req.body into `.insert`/`.update`) | review | [OWASP API3](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) |
| P-SERVER-CLIENT-LEAK | Server Component passes full DB row to a Client Component | CWE-200 | `app/page.tsx` — `<Client data={dbRow} />` no DTO | custom heuristic (async RSC → client prop spread) | review | [scan-extras M9](https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns) |
| P-MISSING-SERVER-ONLY | Secret/service-role module missing `import 'server-only'` | CWE-668 | `lib/secret.js` touches `process.env.SECRET`, no `server-only` | custom (secret-env use, no `server-only`, importable) | review | [server-only](https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns#keeping-server-only-code-out-of-the-client-environment) |
| P-SRV-KEY-CLIENT `[exists]` | Service-role key in a Client Component | CWE-522 / A05 | `components/AdminPanel.jsx` — `'use client'` + SERVICE_ROLE | custom `harvey-service-role-in-client` | high | [scan-gaps §1.1](https://blog.ogwilliam.com/post/moltbook-hack-supabase-vibe-coding) |
| P-NO-RATE-LIMIT | No rate limit on `/auth`/login/OTP/LLM endpoint | CWE-770 / API4 | `pages/api/login.js` — no limiter | custom heuristic (sensitive route, no limiter) | review | [OWASP API4](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) |
| P-FAIL-OPEN | Auth/limit check returns allowed on backing-store error | CWE-636 | `catch { return { allowed: true } }` | custom heuristic | review | [scan-extras HIGH](https://cwe.mitre.org/data/definitions/636.html) |

### Batch 8 — JWT / crypto / randomness (Semgrep `p/security-audit` + custom)

| id | class | CWE / OWASP | fixture sketch | detection mechanism | tier | source |
|---|---|---|---|---|---|---|
| P-JWT-NONE-ALG | JWT verified with `algorithms:['none']` / no verify | CWE-347 / API2 | `lib/auth.js` — `jwt.verify(t, k, {algorithms:['none']})` | `‡ ...jwt-none-alg` / custom | high | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) |
| P-JWT-DECODE-NOVERIFY | `jwt.decode()` used for authz (no signature check) | CWE-347 / API2 | `middleware.ts` — `jwt.decode(token)` then trust claims | custom (`jwt.decode` feeding an authz decision) | review | [OWASP API2](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) |
| P-WEAK-HASH-SEC | MD5/SHA-1 in a security sink (password/signature/integrity) | CWE-327 / A02 | `lib/pw.js` — `crypto.createHash('md5').update(pw)` | `‡ ...weak-hash` gated to security sink (not cache) | high | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) |
| P-WEAK-CIPHER | DES/RC4/`aes-…-ecb` cipher | CWE-327 / A02 | `lib/crypto.js` — `createCipheriv('des-ecb',…)` | `‡ ...weak-cipher` | high | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) |
| P-STATIC-IV-SALT | Hardcoded IV / static salt | CWE-329/760 | `createCipheriv(algo,key,Buffer.from('0000…'))` | `‡ ...static-iv` / custom | review | [CWE-329](https://cwe.mitre.org/data/definitions/329.html) |
| P-INSECURE-RANDOM | `Math.random()` for token/id/secret | CWE-338 / A02 | `lib/token.js` — `Math.random().toString(36)` as reset token | `‡ ...math-random-crypto` gated to token/secret sink | review | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) |
| P-PLAINTEXT-PASSWORD | Password stored w/o bcrypt/argon (plaintext or fast hash) | CWE-256/916 | `.insert({ password: req.body.pw })` raw | custom heuristic (password column, no hash fn) | review | [CWE-256](https://cwe.mitre.org/data/definitions/256.html) |
| P-TLS-VERIFY-DISABLED | `rejectUnauthorized:false` / `NODE_TLS_REJECT_UNAUTHORIZED=0` | CWE-295 / A02 | `lib/http.js` — agent `rejectUnauthorized:false` | `‡ ...disabled-cert-validation` / custom | high | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) |

### Batch 9 — SSRF & outbound request (custom taint)

| id | class | CWE / OWASP | fixture sketch | detection mechanism | tier | source |
|---|---|---|---|---|---|---|
| P-SSRF-FETCH `[exists]` | SSRF via server-fetched user URL | CWE-918 / A10 | `pages/api/fetch-preview.js` — `fetch(req.query.url)` | custom `harvey-ssrf-fetch` (taint) | review | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| P-SSRF-STORED-URL | SSRF via persisted `*_url` field fetched server-side | CWE-918 / A10 | `lib/preview.js` — `fetch(row.webhook_url)` | custom (stored url source → `fetch`) | review | [scan-extras SSRF](https://cwe.mitre.org/data/definitions/918.html) |
| P-SSRF-IMG-RENDER | Unvalidated user `*_url` rendered to `<img src>`/`<a href>` | CWE-918/601 | `components/Avatar.jsx` — `<img src={row.avatar_url}>` | custom (persisted url → JSX src) | review | [scan-extras SSRF](https://cwe.mitre.org/data/definitions/918.html) |

### Batch 10 — Supabase project config (`connected` tier — Advisor / Management API; correctly NOT free-count)

These require a live Supabase project (`get_advisors`, `list_extensions`, Storage/Auth config). They are part of the corpus for the **connected tier** and are N/A on a static run — never a free-count claim.

| id | class | Advisor lint / ref | fixture / project-state | detection | tier | source |
|---|---|---|---|---|---|---|
| P-RLS-DISABLED `[exists]` | Public table, RLS off | Splinter `0013 rls_disabled_in_public` | `audit_logs` never `ENABLE RLS` | `get_advisors` | connected | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| P-AUTH-USERS-EXPOSED | `auth.users` exposed to anon/`public` | `0002 auth_users_exposed` | view exposing `auth.users` | `get_advisors` | connected | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| P-SECDEF-VIEW | SECURITY DEFINER view | `0010 security_definer_view` | a `security_definer` view | `get_advisors` | connected | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| P-FN-SEARCH-PATH | Mutable `search_path` on function | `0011 function_search_path_mutable` | function without `set search_path` | `get_advisors` | connected | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| P-RLS-USER-META | RLS policy references `user_metadata` (user-controlled) | `0015 rls_references_user_metadata` | policy using `auth.jwt()->>'user_metadata'` | `get_advisors` | connected | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| P-SENSITIVE-COLS | Sensitive columns exposed via API | `0023 sensitive_columns_exposed` | table exposing `encrypted_password` | `get_advisors` | connected | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| P-STORAGE-PUBLIC | Public Storage bucket / no `storage.objects` policy | Mgmt API | `storage.buckets.public=true`, zero policies | `list` Storage + policy check | connected | [scan-gaps §3.1](https://supabase.com/docs/guides/storage/security/access-control) |
| P-PGREST-EXPOSED | Auto-exposed `public` tables via PostgREST/`pg_graphql` | Data API config | table reachable via REST/GraphQL, Data API on `public` | config check | connected | [scan-gaps §3.2](https://supabase.com/docs/guides/api) |
| P-LEAKED-PW-OFF | Leaked-password protection disabled | `auth_leaked_password_protection` | Auth setting off | `get_advisors` | connected | [scan-gaps §3.3](https://supabase.com/docs/guides/auth/password-security) |
| P-EMAIL-CONFIRM-OFF | Email confirmation off / open anon signups | Auth config | confirmation disabled | Mgmt API | connected | [scan-gaps §3.4](https://supabase.com/docs/guides/auth) |
| P-OTP-LONG-EXPIRY | OTP long expiry / loose auth limits | `auth_otp_long_expiry` | OTP expiry high | `get_advisors` | connected | [scan-gaps §3.5](https://supabase.com/docs/guides/auth) |
| P-OAUTH-REDIRECT-WILD | OAuth redirect allowlist has `*`/`localhost` | Auth config | wildcard redirect URL | Mgmt API | connected | [scan-gaps §3.6](https://supabase.com/docs/guides/auth/redirect-urls) |
| P-PGNET-SSRF | `pg_net`/`http` extension SSRF-from-DB | `list_extensions` | extension enabled + callable RPC | `list_extensions` | connected | [scan-gaps §3.7](https://supabase.com/docs/guides/database/extensions) |
| P-EDGEFN-SECRET | Edge Function hardcoded secret / service-role proxy | static | `supabase/functions/x/index.ts` — literal secret | gitleaks over functions dir | high (static) | [scan-gaps §3.8](https://supabase.com/docs/guides/functions) |
| P-DB-WEBHOOK-SECRET | Outbound DB webhook w/ embedded secret / unsigned | config | webhook config w/ inline secret | Mgmt API | connected | [scan-gaps §3.9](https://supabase.com/docs/guides/database/webhooks) |
| P-RLS-USING-TRUE | RLS policy `USING (true)` — permissive but present | semantic | `documents` `USING (true)` | **policy-body semantics — DEEP, see §5** | connected/deep | [scan-extras CRITICAL](https://supabase.com/docs/guides/database/postgres/row-level-security) |
| P-RLS-AUTH-ROLE | RLS `USING (auth.role()='authenticated')` — no tenant predicate | semantic | `invoices` policy | **policy-body semantics — DEEP, see §5** | connected/deep | [scan-extras CRITICAL](https://supabase.com/docs/guides/database/postgres/row-level-security) |

**Positive total:** ~100 classes (17 existing + ~83 new). Free-count `high`: ~34. `review`: ~42. `connected`: ~18 (Batch 10). The two `RLS-*` policy-body rows are listed for corpus completeness but are **DEEP/semantic**, not mechanical (see §5) — do not count them toward the mechanical total.

---

## 3. Negative benign-lookalikes (must NOT be flagged in the free count) — target ~50

Each new positive rule needs a lookalike that models the FP a competing tool throws. The 15 existing negatives (all `[exists]`) are kept. New ones below.

| id | class (benign) | fixture sketch | which rule it must not trip | source |
|---|---|---|---|---|
| N-ANON-KEY `[exists]` | Public anon key looks like a secret | `.env.local` `NEXT_PUBLIC_SUPABASE_ANON_KEY` (role:anon) | secret scanners | [Supabase keys](https://supabase.com/docs/guides/getting-started/api-keys) |
| N-ENV-EXAMPLE `[exists]` | Placeholder secrets in sample file | `.env.example` `sk_live_your_key_here` | secret scanners | [gitleaks #1830](https://github.com/gitleaks/gitleaks/issues/1830) |
| N-SECRET-NAME `[exists]` | Var named like a secret, holds none | `ResetForm.jsx` `passwordLabel` | Sonar S2068 / name-only | [Sonar S2068](https://community.sonarsource.com/t/false-positive-for-password-detected-in-this-expression-review-this-potentially-hard-coded-credential/32964) |
| N-PARAM-QUERY `[exists]` | Parameterized query looks like SQLi | `list.js` `pool.query('… $1',[x])` | `harvey-sql-injection-template` | [GitLab #471655](https://gitlab.com/gitlab-org/gitlab/-/issues/471655) |
| N-DSIH-SANITIZED `[exists]` | Sanitized/constant `dangerouslySetInnerHTML` | `about.js` `DOMPurify.sanitize` + literal | `harvey-dangerously-set-inner-html` | [semgrep-rules #2168](https://github.com/semgrep/semgrep-rules/issues/2168) |
| N-OBJ-INJECTION `[exists]` | Benign `obj[key]` bracket access | `i18n.js` `translations[locale]` (enum) | eslint detect-object-injection | [docs](https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/detect-object-injection.md) |
| N-JSX-KEY `[exists]` | Composite/stable JSX key | `List.jsx` `key={`${it.id}-${i}`}` | Sonar S6479 | [Sonar S6479](https://community.sonarsource.com/t/typescript-s6479-fails-to-account-for-keys-that-include-other-values-with-an-index/107623) |
| N-WEAK-HASH-CACHE `[exists]` | md5 as cache key/ETag | `cache.js` `md5(JSON.stringify(params))` | P-WEAK-HASH-SEC / Sonar S4790 | [Sonar S4790](https://community.sonarsource.com/t/make-sure-this-weak-hash-algorithm-is-not-used-in-a-sensitive-context-here-false-positive-with-md5/152193) |
| N-REDOS-SAFE `[exists]` | Linear regex looks like ReDoS | `validate.js` `^[^\s@]+@[^\s@]+\.[^\s@]+$` | P-REDOS / Sonar S5852 | [Sonar S5852](https://community.sonarsource.com/t/false-positive-regex-dos-vulnerability/102019) |
| N-FS-STATIC `[exists]` | Static/unrelated `fs`/`.open()` | `read-config.js` `fs.readFileSync(path.join(__dirname,…))` | P-PATH-TRAVERSAL / eslint fs rules | [eslint #26](https://github.com/nodesecurity/eslint-plugin-security/issues/26) |
| N-DEV-DEP `[exists]` | Vulnerable dep in devDependencies | `webpack@4.42.0` (dev) | OSV/`npm audit` | [overreacted](https://overreacted.io/npm-audit-broken-by-design/) |
| N-SERVICE-ROLE-SERVER `[exists]` | Legit server-only service-role use | `cron.js` `import 'server-only'` + admin | `harvey-service-role-in-client` | `docs/fp-rules.txt` |
| N-RLS-DENY-ALL `[exists]` | RLS-enabled-no-policy, service-only table | `service_state` RLS on, 0 policies | Advisor 0008 | `docs/fp-rules.txt` |
| N-URL-ENV `[exists]` | Operator/env config URL | `redis.js` `z.string().url()` on `REDIS_URL` | SSRF/url rules | `docs/fp-rules.txt` |
| N-INMEM-CACHE `[exists]` | `Map` as cache, not limiter | `memo.js` module-level `Map` | rate-limit rule | `docs/fp-rules.txt` |
| N-CMD-SAFE | `execFile`/`spawn` with array args, no shell | `lib/img.js` `execFile('convert',[a,b])` | P-CMD-INJECTION | [Node child_process](https://nodejs.org/api/child_process.html) |
| N-EVAL-JSON | `JSON.parse`, not `eval` | `lib/cfg.js` `JSON.parse(body)` | P-EVAL-CODE-INJ | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| N-PROTO-SAFE | `Object.assign({}, defaults, validated)` | `lib/opts.js` guarded merge (no proto keys) | P-PROTO-POLLUTION | [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) |
| N-XXE-SAFE | XML parse with entities disabled | `lib/xml.js` `noent:false` | P-XXE | [OWASP XXE](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) |
| N-PATH-BASENAME | `path.basename` sanitized file access | `api/dl.js` `path.basename(req.query.f)` | P-PATH-TRAVERSAL | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| N-RPC-PARAM | `supabase.rpc('fn',{arg})` parameterized | `api/rep.js` `.rpc('total',{uid})` | P-SQLI-RPC | [Supabase RPC](https://supabase.com/docs/guides/database/functions) |
| N-INNERHTML-STATIC | `innerHTML = constant` | `Widget.jsx` `el.innerHTML='<b>hi</b>'` | P-DOM-XSS-INNERHTML | [no-unsanitized](https://github.com/mozilla/eslint-plugin-no-unsanitized) |
| N-HREF-INTERNAL | `href` from constant/internal route | `Nav.jsx` `<Link href="/dashboard">` | P-XSS-HREF-JS / open redirect | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) |
| N-SEARCHPARAMS-TEXT | `searchParams` rendered as text | `page.tsx` `<p>{q}</p>` | P-XSS-* | [React escaping](https://react.dev/reference/react-dom/components/common) |
| N-STRIPE-PK-PUBLISHABLE | Stripe publishable `pk_live_` is public | `.env.local` `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_…` | secret scanners | [Stripe keys](https://stripe.com/docs/keys) |
| N-STRIPE-TEST-KEY | `sk_test_`/`pk_test_` test-mode keys | `.env.local` test keys | high-severity secret finding | [Stripe keys](https://stripe.com/docs/keys) |
| N-AWS-EXAMPLE-KEY | AWS documented example key | `docs/x.md` `AKIAIOSFODNN7EXAMPLE` | P-AWS-KEY | [AWS docs example](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html) |
| N-JWT-VERIFY-OK | `jwt.verify` with `algorithms:['RS256']` allowlist | `lib/auth.js` proper verify | P-JWT-NONE-ALG / P-JWT-DECODE | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) |
| N-RANDOM-NONSEC | `Math.random()` for UI jitter, not tokens | `lib/ui.js` random delay | P-INSECURE-RANDOM | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) |
| N-SHA256-INTEGRITY | SHA-256 for a non-password integrity check | `lib/hash.js` `sha256(file)` for checksum | P-WEAK-HASH-SEC | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) |
| N-TLS-VERIFY-ON | `rejectUnauthorized` default/true | `lib/http.js` default agent | P-TLS-VERIFY-DISABLED | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) |
| N-CORS-ALLOWLIST | CORS with explicit origin allowlist | `middleware.ts` `ACAO` from allowlist set | P-CORS-WILDCARD / reflect | [PortSwigger CORS](https://portswigger.net/web-security/cors) |
| N-CSP-PRESENT | Proper CSP configured | `next.config.js` strict CSP | P-NO-CSP / unsafe-inline | [CSP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) |
| N-HEADERS-VERCEL | Security headers set via `vercel.json` | `vercel.json` headers block | header-presence rules | [OWASP headers](https://owasp.org/www-project-secure-headers/) |
| N-COOKIE-SECURE | Cookie with `Secure;HttpOnly;SameSite` | `res` sets hardened cookie | P-COOKIE-INSECURE | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) |
| N-MASS-ASSIGN-PICK | Explicit field projection | `api/p.js` `.update({title,body})` destructured | P-MASS-ASSIGNMENT | [OWASP API3](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) |
| N-IDOR-SCOPED | Query with ownership predicate | `api/o.js` `.eq('user_id', session.user.id)` | P-IDOR-PARAM | [OWASP API1](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) |
| N-SERVER-ACTION-GUARDED | `'use server'` + `assertPermission` | `app/actions.ts` guarded mutation | P-SERVER-ACTION-NOAUTH | [Next server actions](https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations) |
| N-DEP-PINNED | Exact-pinned deps + lockfile | `package.json` exact versions | P-UNPINNED-DEP / missing-lockfile | [npm docs](https://docs.npmjs.com/cli/v10/configuring-npm/package-json) |
| N-SLOPSQUAT-REAL | Real popular pkg w/ similar name | `@supabase/supabase-js` in deps | P-SLOPSQUAT / P-TYPOSQUAT | [Mend](https://www.mend.io/blog/the-hallucinated-package-attack-slopsquatting/) |
| N-POSTINSTALL-KNOWN | Well-known legit lifecycle script | `husky`/`esbuild` postinstall | P-POSTINSTALL (→ informational) | [Unit42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/) |
| N-NEXT-SUPPORTED | Current supported Next version | `next@15.5.x` | P-NEXT-EOL / CVE ranges | [Next blog](https://nextjs.org/blog) |
| N-ERROR-GENERIC | Generic error message, no stack | `res.status(500).json({error:'Server error'})` | P-VERBOSE-ERROR / P-DB-ERROR | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) |
| N-STORAGE-PRIVATE | Private Storage bucket | `public=false` bucket | P-STORAGE-PUBLIC (connected) | [Supabase storage](https://supabase.com/docs/guides/storage/security/access-control) |
| N-DEFINER-SCOPED | SECURITY DEFINER fn with `auth.uid()` check | caller-scoped definer fn | P-SECDEF-VIEW (connected) | `docs/scan-extras.txt` |
| N-SERVER-ONLY-PRESENT | Secret module with `import 'server-only'` | `lib/secret.js` guarded | P-MISSING-SERVER-ONLY | [Next server-only](https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns) |

**Negative total:** ~46 (15 existing + ~31 new). Every new `high`-tier positive has a paired negative; `review`-tier positives get a negative where a common FP exists.

---

## 4. Build-sequencing plan (incremental, not one mega-PR)

`GROUND-TRUTH.md` and the `src/scan/calibration.ts` `CORPUS` array are a single answer key that one agent must own per PR to avoid merge conflicts. Land in **8 coherent batches grouped by detection mechanism**, each self-contained: fixtures + rule/suppression + `CORPUS` rows + a `GROUND-TRUTH.md` table update + green `pnpm validate:calibration` (unit path) in the same PR. Order is by dependency and value.

| Batch | Theme | New positives | New negatives | Detection work | Risk |
|---|---|---|---|---|---|
| **B1** | Secrets breadth (Batch 3) | ~13 | ~6 | gitleaks/TruffleHog custom patterns; decode `role`; bundle scan | Low — high-value, mostly `high` |
| **B2** | Framework CVE + supply chain (Batches 4+5) | ~13 | ~4 | `checkNextVersionCVEs` ranges; OSV lockfile fixture; manifest/lockfile scanners; **build the npm-registry existence check** (closes the `P-SLOPSQUAT` miss) | Med — needs a committed lockfile fixture |
| **B3** | Injection & code-exec (Batch 1) | ~13 | ~5 | custom taint rules + verify `p/javascript` rule ids | Med — taint FP-prone; keep most `review` |
| **B4** | XSS/client sinks (Batch 2) | ~7 | ~4 | extend `harvey-dangerously-set-inner-html`; wire `eslint-plugin-no-unsanitized` | Low — `no-unsanitized` is high-signal |
| **B5** | Headers/CORS/CSRF/errors (Batch 6) | ~13 | ~4 | extend `checkMissingCsp` to a header/cookie/CORS config auditor | Low-Med — presence checks, mostly `review` |
| **B6** | JWT/crypto/randomness (Batch 8) | ~8 | ~4 | `p/security-audit` rule ids + custom sink-gating (weak-hash vs cache) | Med — sink-gating is the precision lever |
| **B7** | Auth/access-control/SSRF (Batches 7+9) | ~15 | ~4 | extend `leftover-auth`; new IDOR/mass-assign/server-action heuristics | High — heuristic, keep `review`; watch negatives |
| **B8** | Supabase connected config (Batch 10) | ~18 | ~2 | `get_advisors`/`list_extensions`/Mgmt API mapping; extend the connected-tier harness | Med — connected tier, N/A statically but must be modeled |

Sequencing rationale: B1–B2 first (highest free-count value, most deterministic, unblock the lockfile fixture). B3–B6 add the SAST/config breadth. B7 (heuristics) late because it carries the most negative-precision risk. B8 last — connected tier is orthogonal to the static gate and can land independently. Each batch is ~15–20 corpus rows including negatives, matching the issue's "batches of ~15-20" instruction.

**Gate discipline per PR:** the PR may only mark a rule `high` if its positive is caught AND all negatives clear at free-count tier in `calibration.test.ts`. Anything that trips a negative is demoted to `review` in the same PR (never merged as `high`). Re-run the whole corpus on every rule/pack version bump.

---

## 5. Out-of-scope — NOT mechanically detectable (stay in dynamic/semantic tiers)

Do **not** pad the mechanical count with these. They belong to the DEEP / dynamic / connected-semantic tiers (the paid M-series modules and the #5 pen-test), and are already the semantic ground truth in `GROUND-TRUTH.md`.

- **Cross-tenant RLS *logic*** — `USING (true)`, `USING (auth.role()='authenticated')` (calibration bugs #1, #2). Enabled, present policies that *look* correct; only reading the policy body + tenant model catches the leak. The Advisor catches RLS *disabled* (#3), not permissive-but-present. **Semantic.**
- **Single-layer tenant isolation** — app-`.eq('tenant_id')` OR RLS but not both. Needs whole-program reasoning about defense layers.
- **Webhook replay** (#5) — needs freshness-control semantics (timestamp window / nonce / dedup) across the handler + provider SDK.
- **Counter/balance race** (#6) — read-modify-write dataflow; concurrency, not a pattern.
- **Unscoped cross-tenant `.update()`** (#7) — needs cross-tenant reasoning about what the missing `.eq()` exposes.
- **Business-logic authorization / broken object-level authz at runtime** — true BOLA/IDOR exploitability (OWASP API1) needs a live request with two tenants; only the *statically-visible* shape (P-IDOR-PARAM) is a `review` heuristic, never `high`.
- **Idempotency-row-before-dispatch, fail-open under store outage, state-machine transition validity** — semantic/dynamic.
- **Prompt injection / LLM instruction-data separation / LLM tool-call authority** (OWASP LLM01) — DEEP; only the mechanical shell (`dangerouslySetInnerHTML` fed by an LLM var) is a pattern.
- **Exploitability narratives** — a version match ≠ exploitable (CVE-2025-29927 only matters self-hosted-with-middleware-auth). The *version finding* is mechanical `high`; the *exploitability claim* is `review`.
- **RSC server→client over-serialization actually leaking a secret field** — the shape (P-SERVER-CLIENT-LEAK) is a `review` heuristic; proving a specific sensitive field crosses the boundary is semantic.

---

## 6. Sources (all URLs)

**Reused repo docs (not re-derived):** `docs/design/calibration-corpus-spec.md`, `docs/design/scan-coverage-gaps.md`, `docs/design/mechanical-toolchain.md`, `docs/scan-extras.txt`, `docs/fp-rules.txt`, `src/scan/rules/semgrep-nextjs-supabase.yml`, `src/scan/calibration.ts`, `targets/calibration/GROUND-TRUTH.md`.

**OWASP frameworks (breadth source):**
- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/ (API1 BOLA, API2 Broken Auth, API3 BOPLA/mass-assignment, API4 Unrestricted Resource Consumption, API5 Broken Function Level Authz, API7 SSRF, API8 Security Misconfiguration)
- OWASP LLM Top 10: https://genai.owasp.org/llm-top-10/
- OWASP Cheat Sheets: XSS https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html · CSP https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html · XXE https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html · Clickjacking https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html · Secure Headers https://owasp.org/www-project-secure-headers/

**CWE (per-class refs):** CWE-22, 78, 79, 89, 95, 117, 200, 209, 256, 295, 306, 319, 327, 329, 338, 347, 352, 489, 502, 522, 601, 611, 614, 636, 639, 668, 693, 770, 798, 829, 915, 916, 1021, 1104, 1321, 1333, 1336, 1357, 1395 — all at https://cwe.mitre.org/data/definitions/<n>.html

**Semgrep registry (rule ids to confirm with `semgrep --validate`):** https://semgrep.dev/p/react · https://semgrep.dev/p/nextjs · https://semgrep.dev/p/owasp-top-ten · https://semgrep.dev/p/secrets · https://semgrep.dev/p/security-audit · https://semgrep.dev/p/javascript · registry browser https://semgrep.dev/r

**Detection tooling:** OSV-Scanner https://google.github.io/osv-scanner/ · gitleaks https://github.com/gitleaks/gitleaks · TruffleHog https://github.com/trufflesecurity/trufflehog · eslint-plugin-no-unsanitized https://github.com/mozilla/eslint-plugin-no-unsanitized · Supabase Database Advisors https://supabase.com/docs/guides/database/database-advisors

**CVEs / advisories:** CVE-2025-29927 https://jfrog.com/blog/cve-2025-29927-next-js-authorization-bypass/ · GHSA-f82v-jwr5-mffw https://github.com/advisories/GHSA-f82v-jwr5-mffw · React2Shell https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components · CVE-2026-44578 https://github.com/advisories/GHSA-c4j6-fc7j-m34r · Vercel May-2026 release https://vercel.com/changelog/next-js-may-2026-security-release

**Supply chain / vibe-code studies:** Slopsquatting https://www.mend.io/blog/the-hallucinated-package-attack-slopsquatting/ · arXiv 2509.22202 https://arxiv.org/pdf/2509.22202 · Shai-Hulud (CISA) https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem · Unit42 https://unit42.paloaltonetworks.com/npm-supply-chain-attack/ · ox.security vibe-coding https://www.ox.security/blog/vibe-coding-security/ · Moltbook https://blog.ogwilliam.com/post/moltbook-hack-supabase-vibe-coding

**FP research (negatives):** Sonar S2068 https://community.sonarsource.com/t/false-positive-for-password-detected-in-this-expression-review-this-potentially-hard-coded-credential/32964 · S5852 https://community.sonarsource.com/t/false-positive-regex-dos-vulnerability/102019 · S4790 https://community.sonarsource.com/t/make-sure-this-weak-hash-algorithm-is-not-used-in-a-sensitive-context-here-false-positive-with-md5/152193 · S6479 https://community.sonarsource.com/t/typescript-s6479-fails-to-account-for-keys-that-include-other-values-with-an-index/107623 · eslint detect-object-injection https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/detect-object-injection.md · eslint fs FP https://github.com/nodesecurity/eslint-plugin-security/issues/26 · semgrep-rules #2168 https://github.com/semgrep/semgrep-rules/issues/2168 · GitLab parameterized-SQLi FP https://gitlab.com/gitlab-org/gitlab/-/issues/471655 · gitleaks placeholder FP https://github.com/gitleaks/gitleaks/issues/1830 · npm audit noise https://overreacted.io/npm-audit-broken-by-design/

**Provider key formats (secret precision):** Supabase API keys https://supabase.com/docs/guides/getting-started/api-keys · Stripe keys https://stripe.com/docs/keys · AWS credential types https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html

---

### Caveats & human decisions needed

1. **Semgrep rule ids are unverified.** Every `‡`-marked id is a plausible registry id from the pack's known scope but MUST pass `semgrep --validate` before wiring into the gate; substitute a custom rule if the registry id doesn't exist or is `.audit.`/MEDIUM (→ `review`).
2. **Lockfile fixture decision.** OSV coverage (Batch 4/5) needs a committed `package-lock.json` in `targets/calibration`. Today the target ships none by design. Human call: add a lockfile fixture (unlocks OSV `high` rows) vs. keep those `review`/documented-miss.
3. **Bundle-scan scope.** `P-SRV-ROLE-IN-BUNDLE` needs scanning built `.next/static` chunks — confirm the harness builds the target or ships a pre-built chunk fixture.
4. **Free-count honesty.** Only ~34 of ~100 are `high`. Recommend NOT chasing "100 in the free count" — the credibility rule caps it. The ~42 `review` + ~18 `connected` are real product value in the paid/connected tiers.
5. **Issue #71 spam comment** — delete the untrusted `.zip`-link comment.
