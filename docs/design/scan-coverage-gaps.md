# Scan-Coverage Gap Analysis — Vibe-Coded Next.js + Supabase

Status: v1 (researched 2026-07-01) · Related issues: #19 (architecture), #5 (M2 pen test), new mechanical-checks + config-audit issues.

> **Corpus build-out (#71):** the first ~100-class corpus derived from these gaps is specified in
> `docs/design/spec-71-security-corpus.md` (batches B1–B8, all built). The **round-2** expansion —
> a deduped, ranked master list of the 5-lens research plus the next build batches (B9–B14) — lives
> in `docs/design/corpus-roadmap-to-100.md`.

Target audience: solo devs, small shops, and AI-assisted "vibe coders" on Next.js (App Router) + Supabase. This doc catalogs failure modes our current 10 modules + `briefs/scan-extras.txt` taxonomy **do not** cover. Each gap is tagged **MECHANICAL** (cheap/deterministic: grep/regex/AST/config-parse/version-check/advisor-API/secret-scanner) or **DEEP** (needs semantic/LLM/dynamic analysis).

## The structural finding

Our covered surface is almost entirely **application-logic** analysis (RLS policy logic, auth/authz flow, concurrency, App-Router boundaries). We have **no secret scanning, no dependency/CVE version-checking, no framework-version hygiene, no infra/config parsing, and no Supabase project-config auditing** — and those are exactly the categories where vibe-coded apps fail most often. ~30 of the ~37 gaps below are MECHANICAL. This is the case for the free mechanical "quick scan" tier (see `quick-scan-tier.md`): the highest-prevalence failures are cheap and deterministic to detect.

Field data cited below: Escape.tech's scan of ~5,600 vibe-coded apps (400+ exposed secrets, 175 PII exposures); a community measurement of ~11% of vibe-coded apps leaking Supabase keys (one platform at ~24%); Tenzai's Dec-2025 controlled study of 15 AI-agent-built apps (**0/15 had CSRF protection, 0/15 set any security headers**); a scan of 107 YC startups finding 61% exposing data.

---

## 1. Secret & credential exposure — highest-yield, cheapest to add

- **1.1 Service-role / `sb_secret_` key shipped to the browser** — CRITICAL · MECHANICAL. Grep source **and the built `.next/static` chunks** for `service_role` JWTs, `sb_secret_` prefixes, `SUPABASE_SERVICE_ROLE_KEY` referenced from a Client Component. Service-role bypasses all RLS = full DB compromise (Moltbook breach, Wiz 2026: 1.5M tokens + 35k emails). We cover service-role *logic*, not the mechanical "key is literally in the bundle."
- **1.2 Secret mis-prefixed `NEXT_PUBLIC_`** — CRITICAL · MECHANICAL. Regex `NEXT_PUBLIC_.*(KEY|SECRET|TOKEN|PASSWORD|SERVICE|PRIVATE)` over `.env*`, source, CI; allowlist `.env.example`. `NEXT_PUBLIC_` is inlined into client JS at build.
- **1.3 Committed `.env` / hardcoded keys (incl. full git history)** — CRITICAL · MECHANICAL. Gitleaks + TruffleHog `--only-verified` over working tree **and history**. Provider patterns: OpenAI `sk-`/`sk-proj-`, Anthropic `sk-ant-`, Stripe `sk_live_`, Supabase `sb_secret_` + `eyJ…` JWTs. Note in findings: deleting from history does not invalidate a leaked credential — only rotation does.
- **1.4 Exposed `.git` / `.env` / source maps / backups on the deployed origin** — HIGH · MECHANICAL. Common when vibe coders deploy a raw folder to a VPS rather than Vercel.
- **1.5 `process.env` spread into client props / `__NEXT_DATA__`** — HIGH · DEEP (MECHANICAL when a direct spread).

## 2. Next.js framework CVEs & version hygiene — absent, trivially mechanical

Parse `package.json`/lockfile → compare to advisory ranges. Vibe coders pin whatever the AI scaffolded and never upgrade.

- **2.1 CVE-2025-29927 middleware auth bypass** — CRITICAL · MECHANICAL. `next` `< 12.3.5 / < 13.5.9 / < 14.2.25 / < 15.2.3`. `x-middleware-subrequest` header skips middleware entirely — devastating for the dominant vibe-coded pattern of auth **only** in `middleware.ts`. Self-hosted only (Vercel auto-patched). Bonus heuristic: flag apps where `middleware.ts` is the *sole* authz layer.
- **2.2 CVE-2025-55182 / 66478 "React2Shell" RSC RCE** — CRITICAL (CVSS 10, CISA KEV) · MECHANICAL. Version-check `next` + `react-server-dom-*`. Affects nearly every App Router app. Fixed: Next 14.2.35 / 15.0.8 / 15.1.12 / 15.2.9 / 15.3.9 / 15.4.11 / 15.5.10 / 16.0.11 / 16.1.5; React `react-server-dom-*` 19.0.1 / 19.1.2 / 19.2.1.
- **2.3 CVE-2026-44578 WebSocket-upgrade SSRF** — HIGH (CVSS 8.6) · MECHANICAL. `next` `>=13.4.13 <15.5.16` or `>=16.0.0 <16.2.5`. Framework-level SSRF (distinct from our app-level stored-URL SSRF). Self-hosted Node only.
- **2.4 May-2026 advisory batch — cache poisoning + DoS + image-optimizer CVEs** — MEDIUM · MECHANICAL. Same version surface (GHSA-wfc6-r584-vfw7, CVE-2025-49826, CVE-2025-57752, CVE-2025-59471, etc.). We cover cache config as *logic*, not known-CVE cache poisoning.
- **2.5 EOL / unsupported Next.js major** — MEDIUM · MECHANICAL. Flag `< 14.x`.

## 3. Supabase misconfigs beyond RLS — the project/config surface

Available mechanically via the Supabase Management API / `get_advisors` (Splinter linter) / `list_extensions`. (61–83% misconfig rates in the field studies above.)

- **3.1 Public Storage buckets / missing `storage.objects` policies** — HIGH · MECHANICAL. Query `storage.buckets` for `public=true`; flag buckets with zero `storage.objects` policies. Recommend folder-ownership pattern `auth.uid()::text = (storage.foldername(name))[1]`.
- **3.2 Auto-exposed `public`-schema tables via PostgREST / `pg_graphql`** — HIGH · MECHANICAL. Tables created via SQL migrations do **not** get RLS auto-enabled but are instantly reachable through the auto-generated REST + GraphQL API. Check `pg_graphql` enabled + Data API not restricted to a non-public schema.
- **3.3 Leaked-password protection off / weak password policy** — MEDIUM · MECHANICAL. Advisor `auth_leaked_password_protection`.
- **3.4 Email confirmation disabled / open anon signups** — HIGH · MECHANICAL. Lets attackers self-provision authenticated accounts and clear the `auth.role()='authenticated'` bar we already flag — but only if we know confirmation is off.
- **3.5 OTP long-expiry / loose auth rate limits** — MEDIUM · MECHANICAL. Advisor `auth_otp_long_expiry`.
- **3.6 Misconfigured OAuth redirect-URL allowlist** — MEDIUM · MECHANICAL (exploitability judgment DEEP). Wildcard / `localhost` / `*` entries → open-redirect / token theft.
- **3.7 `pg_net` / `http` extension SSRF-from-DB** — MED-HIGH · MECHANICAL. `list_extensions` shows them enabled + callable from a SECURITY DEFINER RPC → server-side request forgery from inside the DB.
- **3.8 Edge Function hardcoded secret / service-role proxy** — HIGH · MECHANICAL (hardcode) / DEEP (missing-authz logic).
- **3.9 Outbound DB webhooks with embedded secrets / unsigned** — MEDIUM · MECHANICAL. The outbound/config complement to our inbound webhook-replay coverage.

## 4. AI-coding-specific failure modes

- **4.1 Slopsquatted / hallucinated dependencies** — HIGH · MECHANICAL. Cross-check every `package.json` dep against the live npm registry; flag non-existent names, very-recently-published low-download names, edit-distance-1 mashups. LLMs re-hallucinate stable fake names (43–58%); 205k+ unique fake names observed; `huggingface-cli` slopsquat got 30k downloads.
- **4.2 Unsanitized LLM output rendered as HTML (LLM→XSS)** — HIGH · DEEP (MECHANICAL to flag `dangerouslySetInnerHTML` fed by an LLM variable). OWASP LLM05.
- **4.3 Prompt-injection surfaces** — HIGH · DEEP. LLM features ingesting attacker-controlled content with no instruction/data separation, output driving privileged tool-calls. OWASP LLM01; EchoLeak (CVE-2025-32711, CVSS 9.3).
- **4.4 LLM tool-calls building SQL/shell/paths** — HIGH · DEEP (some AST heuristics MECHANICAL: template literal into `.rpc`/`sql`/`exec`).
- **4.5 TODO/placeholder auth & debug/seed/admin endpoints left enabled** — HIGH · MECHANICAL. Grep `// TODO: auth`, `if (true)`, `isAdmin = true`, `bypassAuth`, commented-out guards; routes named `/debug`, `/test`, `/seed`, `/admin`, `/api/dev/*` with no auth. AI scaffolds these constantly.
- **4.6 Divergent copy-pasted auth clones** — MEDIUM · DEEP (jscpd overlay). Correlate our existing jscpd clone clusters with authz code — one copy fixed, the clone still vulnerable.

## 4b. Classic web-app basics vibe coders skip (Tenzai: 0/15 on the first two)

- **4b.1 Missing security headers / CSP** — HIGH · MECHANICAL. Parse `next.config.js` `headers()`, `middleware.ts`, `vercel.json`, `_headers` for absence of CSP, HSTS, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`; also flag `unsafe-inline`/`unsafe-eval` in `script-src`.
- **4b.2 Permissive CORS** — HIGH · MECHANICAL. `Access-Control-Allow-Origin: *` (esp. with `Allow-Credentials: true`). Commonly pasted by the AI to "fix" a dev CORS error.
- **4b.3 Missing CSRF with cookie auth** — HIGH · MECHANICAL/DEEP. Supabase SSR cookie session + mutating Server Actions with no CSRF token / origin check / `SameSite`.
- **4b.4 XSS via `dangerouslySetInnerHTML` (non-LLM)** — HIGH · MECHANICAL. AI code is 2.74× more likely to introduce XSS (CodeRabbit); 86% of AI code fails XSS defenses (Georgetown CSET).
- **4b.5 Open redirects** — MEDIUM · MECHANICAL/DEEP. `redirect()`/`router.push()` fed by unvalidated `?next=`/`?redirect=`.
- **4b.6 Verbose error pages / stack traces in prod** — MEDIUM · MECHANICAL. Broader than our DB-error-disclosure check: `NODE_ENV` not production, `error.stack` echoed to client, missing `error.tsx`.
- **4b.7 No rate limiting on auth/LLM endpoints** — HIGH · MECHANICAL/DEEP. We cover in-memory limiters as a *correctness* bug, not the *absence* of any limit on `/auth/*`, login, reset, OTP, or cost-DoS-prone LLM endpoints.

## 5. Supply chain / dependency — absent, all mechanical

- **5.1 Known-vulnerable dependencies** — HIGH · MECHANICAL. `npm audit` / OSV-Scanner against the lockfile (also the delivery vector for the §2 CVEs).
- **5.2 Unpinned / floating ranges / missing lockfile** — MEDIUM · MECHANICAL.
- **5.3 Postinstall/lifecycle-script risk (Shai-Hulud class)** — HIGH · MECHANICAL. Flag deps with `preinstall`/`postinstall`; cross-check installed versions against IoC lists. Shai-Hulud (Sept 2025, CISA), 2.0 (Nov 2025), Mini (May 2026, 170+ packages, pre-install execution).
- **5.4 Typosquatted packages** — MEDIUM · MECHANICAL. Edit-distance vs the popular-package corpus.

---

## Priority summary (prevalence × severity)

| # | Gap | Severity | Detect | Prevalence |
|---|-----|----------|--------|------------|
| 1.1 | Service-role / `sb_secret_` key in client bundle | CRITICAL | MECHANICAL | High (~11–24%) |
| 1.2 | Secret mis-prefixed `NEXT_PUBLIC_` | CRITICAL | MECHANICAL | High |
| 1.3 | Committed `.env` / hardcoded keys (git history) | CRITICAL | MECHANICAL | Very High |
| 2.1 | CVE-2025-29927 middleware auth bypass | CRITICAL | MECHANICAL | High (self-hosted) |
| 2.2 | CVE-2025-55182/66478 RSC RCE (CVSS 10, KEV) | CRITICAL | MECHANICAL | Very High |
| 4.5 | TODO/placeholder auth; debug/seed/admin endpoints | HIGH | MECHANICAL | Very High |
| 5.1 | Known-vuln dependencies (OSV/npm audit) | HIGH | MECHANICAL | Very High |
| 4b.1 | Missing security headers / CSP | HIGH | MECHANICAL | Very High (0/15) |
| 4b.4 | XSS via `dangerouslySetInnerHTML` | HIGH | MECHANICAL | High |
| 3.1 | Public Storage buckets / no `storage.objects` policy | HIGH | MECHANICAL | High |
| 3.2 | Auto-exposed `public` tables via PostgREST/`pg_graphql` | HIGH | MECHANICAL | High (61–83%) |
| 4.1 | Slopsquatted / hallucinated dependencies | HIGH | MECHANICAL | High |
| 2.3 | CVE-2026-44578 WebSocket SSRF (CVSS 8.6) | HIGH | MECHANICAL | Med-High (self-hosted) |
| 1.4 | Exposed `.git` / `.env` / source maps on origin | HIGH | MECHANICAL | Med-High |
| 4b.3 | Missing CSRF with cookie auth | HIGH | MECHANICAL/DEEP | Very High (0/15) |
| 4b.2 | Permissive CORS | HIGH | MECHANICAL | High |
| 4b.7 | No rate limiting on auth/LLM endpoints | HIGH | MECHANICAL/DEEP | High |
| 3.4 | Email confirmation off / open anon signups | HIGH | MECHANICAL | Medium |
| 3.8 | Edge fn hardcoded secret / service-role proxy | HIGH | MECHANICAL/DEEP | Medium |
| 5.3 | Postinstall-script risk (Shai-Hulud class) | HIGH | MECHANICAL | Medium |
| 4.2 | Unsanitized LLM output → XSS (LLM05) | HIGH | DEEP | Med (LLM apps) |
| 4.3 | Prompt-injection surfaces (LLM01) | HIGH | DEEP | Med (LLM apps) |
| 4.4 | LLM tool-calls building SQL/shell | HIGH | DEEP | Med (LLM apps) |
| 3.7 | `pg_net`/`http` SSRF-from-DB | MED-HIGH | MECHANICAL | Medium |
| 2.4 | May-2026 cache-poisoning/DoS + image CVEs | MEDIUM | MECHANICAL | Med-High |
| 2.5 | EOL Next.js major | MEDIUM | MECHANICAL | Medium |
| 3.3 | Leaked-password protection off | MEDIUM | MECHANICAL | High |
| 3.5 | OTP long-expiry / loose auth limits | MEDIUM | MECHANICAL | High |
| 3.6 | Misconfigured OAuth redirect allowlist | MEDIUM | MECHANICAL/DEEP | Medium |
| 3.9 | Outbound DB webhooks w/ secrets / unsigned | MEDIUM | MECHANICAL | Low-Med |
| 4b.5 | Open redirects (`?next=` taint) | MEDIUM | MECHANICAL/DEEP | Medium |
| 4b.6 | Verbose error pages / stack traces in prod | MEDIUM | MECHANICAL | High |
| 5.2 | Unpinned deps / missing lockfile | MEDIUM | MECHANICAL | High |
| 5.4 | Typosquatted packages | MEDIUM | MECHANICAL | Low-Med |
| 1.5 | `process.env` leaked to client props | HIGH | DEEP/MECH | Low-Med |
| 4.6 | Divergent copy-pasted auth clones (jscpd overlay) | MEDIUM | DEEP | Medium |

**Three fastest, highest-impact additions:** (1) a secret scanner (Gitleaks/TruffleHog + `NEXT_PUBLIC_`/`service_role`/`sb_secret_` custom rules over source, git history, and built bundle); (2) a dependency + framework-CVE version-checker (OSV + the Next.js/React ranges above, especially CVE-2025-29927 and the CVSS-10 React2Shell RCE); (3) a Supabase project-config auditor calling `get_advisors`/`list_extensions`/Storage-bucket state. All three are the mechanical core of the free quick-scan tier — see `mechanical-toolchain.md` and `quick-scan-tier.md`.

## Sources

CVE-2025-29927: [ProjectDiscovery](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass) · [JFrog](https://jfrog.com/blog/cve-2025-29927-next-js-authorization-bypass/). React2Shell (CVE-2025-55182/66478): [React blog](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components) · [GHSA-9qr9-h5gf-34mp](https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp). CVE-2026-44578: [GHSA-c4j6-fc7j-m34r](https://github.com/advisories/GHSA-c4j6-fc7j-m34r) · [Vercel changelog](https://vercel.com/changelog/next-js-may-2026-security-release). Supabase key leaks / Moltbook: [blog.ogwilliam.com](https://blog.ogwilliam.com/post/moltbook-hack-supabase-vibe-coding) · [Supabase 2025 security retro](https://supabase.com/blog/supabase-security-2025-retro). Supabase misconfig at scale: [deepstrike.io](https://deepstrike.io/blog/hacking-thousands-of-misconfigured-supabase-instances-at-scale) · [modernpentest.com](https://modernpentest.com/blog/supabase-security-misconfigurations). Slopsquatting: [Mend](https://www.mend.io/blog/the-hallucinated-package-attack-slopsquatting/) · [arXiv 2509.22202](https://arxiv.org/pdf/2509.22202). Vibe-code studies: [SecurityBoulevard/Escape.tech](https://securityboulevard.com/2025/10/methodology-how-we-discovered-over-2k-high-impact-vulnerabilities-in-apps-built-with-vibe-coding-platforms/) · [ox.security](https://www.ox.security/blog/vibe-coding-security/). OWASP LLM Top 10: [LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) · [LLM05](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/). Shai-Hulud: [Unit42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/) · [CISA](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem).
