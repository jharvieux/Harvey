# Mechanical Scanning Toolchain — Evaluation & FP Tuning

Status: v1 (researched 2026-07-01) · Related: `scan-coverage-gaps.md`, `quick-scan-tier.md`, mechanical-checks issue.

Context: Next.js + Supabase + TypeScript; audience = solo devs / small shops / vibe coders. A free "quick scan" surfaces a **count** of issues, so **false positives are existential** — a noisy free count destroys credibility. Each tool below is assessed for what it catches, its FP profile, the concrete FP-control mechanism, and whether its raw output is **trustworthy for the free count** or **needs an LLM triage pass** first.

## 1. SonarQube Community Edition ("Community Build")

- **What CE analyzes for JS/TS:** full code-quality (bugs, code smells) + **single-file pattern-matching** security rules, up to ES2024 / TS 5.9.x.
- **The decisive limitation:** cross-file **taint / data-flow analysis** (SQLi, XSS, command injection, SSRF) is **not in CE** — it requires SonarQube Cloud or Developer Edition (~$2,500/yr). CE also lacks branch analysis and PR decoration. So for a *security* product, CE's security value is weak; it's a **maintainability** engine ([Sonar JS/TS docs](https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/languages/javascript-typescript-css), [taint engine thread](https://community.sonarsource.com/t/next-generation-taint-analysis-engine-for-javascript-typescript/148744)).
- **FP-tuning playbook:** copy "Sonar way" into a custom Quality Profile, then deactivate noisy rules there (don't edit built-ins); customize rule severity/params rather than disabling (e.g. raise S3776 threshold); `sonar.exclusions` for `.next/**`/generated/`node_modules`; `sonar.issue.ignore.multicriteria` for ruleKey×filePattern; `//NOSONAR` inline (Sonar also honors ESLint disable comments); mark issues Won't-Fix/False-Positive in the UI. Keep the analyzer's TS version ≥ the project's to avoid parse-level FPs.
- **Notoriously noisy React/TS rules to disable/re-tune:** `S3776` (Cognitive Complexity — over-fires on functional components), `S6479` (array index as JSX key — FPs on index+stable-value composites), `Web:S6853` (label association), `S1481`/`S1854` (unused/dead assignments — duplicate ESLint). Avoid Beta-marked rules entirely.
- **Verdict: NOT in the free security count.** Optional for the paid quality-depth tier only; its output is quality-flavored and React-FP-prone, and the security engine you'd want is paywalled.

## 2. Semgrep OSS (free CLI) — the recommended mechanical-security core

- **Rulesets** (invoke individually, avoid over-broad bundles): `p/typescript`, `p/javascript`, `p/react`, `p/nextjs`, `p/secrets`, `p/owasp-top-ten`, `p/security-audit`. React/Next security rules also live under `typescript.react.*`.
- **`.audit.` rules are for human auditors and are inherently noisier — exclude from the free count.**
- **OSS engine limit:** single-file, intraprocedural taint only; cross-file (interfile) taint needs the proprietary Pro engine (Doyensec: Pro finds 50–71% more). Note: Semgrep's **Team plan is free for ≤10 devs / ≤10 private repos** and includes the Pro engine + Secrets — worth using if the account requirement is acceptable. OpenGrep (Jan 2025 fork) restores cross-function taint license-clean.
- **Custom rules for the product taxonomy** are the right fit here — flag "security off buttons": service-role key in client code (`createClient($URL, process.env.*SERVICE_ROLE*, ...)`, confidence HIGH), `NEXT_PUBLIC_` secret assignment, Server Action / route handler lacking an auth-guard call (confidence MEDIUM → triage).
- **FP control:** per-rule `metadata: confidence: HIGH/MEDIUM/LOW` + `--severity ERROR` to gate the count. Start from high-confidence, medium/high-impact rules only (Trail of Bits).
- **In-repo suppressions are the AUDITED PARTY's, not the auditor's (#1066).** This section used to recommend `// nosemgrep: rule-id` and a `.semgrepignore` as FP controls. That advice is wrong for an external audit: both live in the client's repository, the client controls them, and neither appeared anywhere in the deliverable. Measured 2026-07-25 (semgrep 1.164.0): a bare `// nosemgrep` above a sink removed the finding while the file still appeared in `paths.scanned` — it read as scanned-and-clean; a committed `.semgrepignore` travelled into the scan copy with the git-tracked files and applied; and semgrep's built-in default ignore set silently dropped `tests/`, `test/`, `vendor/`, `dist/`, `build/` — 5 of 8 probed directories, `vendor/` being real shipped code. Harvey now runs with `--disable-nosem` and `--x-ignore-semgrepignore-files`, re-applies the `nosem` marker itself, and emits two counted disclosure rows: **`SEM-SUPPRESS-00`** ("N findings suppressed by in-repo markers", with every location and rule id) and **`SEM-SCOPE-00`** ("N JS/TS source files semgrep did not scan", derived from `paths.scanned` rather than from the flags we passed). A marker still withholds its match from the finding list — but the count is never zero by silence. **Harvey's own FP control is the calibration corpus and the precision gates, not a marker the target can write.**
- **Verdict: primary mechanical-security core.** HIGH-confidence, non-`.audit`, ERROR-severity rules (secrets, `dangerouslySetInnerHTML`, service-role-in-client, `NEXT_PUBLIC` leaks) are **trustworthy for the free count**; MEDIUM/LOW-confidence and heuristic taxonomy rules **need LLM triage**.
- **Rule remediation metadata reaches the report, and a per-file parse error is disclosed, not read as clean (#1077).** MEASURED 2026-07-25 (semgrep 1.164.0): all 915 rules across the six registry packs Harvey loads carry `metadata.references`; Harvey previously dropped it one line before writing a placeholder fix pointing at "the rule's remediation guidance" — 224/386 (58%) of a real deliverable's findings carried that identical placeholder string. `Finding.references` and the composed fix (the rule's own reference links + its `source` page, falling back to the placeholder only for a rule that truly declares none — every `harvey-*` custom rule today) close that. Separately: a client file semgrep could not parse (`errors[]`) still appears in `paths.scanned` — MEASURED, so `SEM-SCOPE-00` above cannot catch it — and semgrep exits 0, so it read as scanned-and-clean. `SEM-ERR-00` now names every such file, plus anything in `paths.skipped` (only populated once the wrapper runs `--verbose` instead of `--quiet` — the two are mutually exclusive).

## 3. Secret scanning — gitleaks vs trufflehog vs GitGuardian

| Tool | Approach | FP profile | Verification |
|---|---|---|---|
| Gitleaks | Regex + entropy | Fast/offline; highest untuned FP (precision ~46%, recall ~88%) | None |
| TruffleHog | Regex/entropy + **live API verification** (800+ types) | FPs collapse with `--only-verified` (~94% of active creds validated) | Yes |
| GitGuardian | ML filtering + platform | Lowest FP (~1–3%), SaaS/paid | Yes + auto-revoke |

- **Count source = TruffleHog `--only-verified`** — live verification is the single best FP killer; a verified secret is effectively a true positive.
- **gitleaks** for speed/pre-commit + custom Supabase rules: match the `service_role` JWT by **decoding the `role` claim** (`--max-decode-depth 2`) rather than token shape — anon and service-role JWTs are structurally identical, so distinguish by the claim; suppress `NEXT_PUBLIC_SUPABASE_ANON_KEY` with a rule-specific allowlist; path-allowlist `.env.example`. Note: rotation ≠ removal — scan full history and purge with `git filter-repo`/BFG.
- **Known-public / test-credential recognizer** (added #210/#211/#225): a maintained set of internal gitleaks correlation-marker rules — **never surfaced as findings themselves** — that recognize intentionally-public or test credentials the raw patterns would otherwise mis-fire on. A high-precision hit co-located with the decoded `iss:"supabase-demo"` claim is the local-dev demo `service_role` key that ships with every `supabase start` (published in Supabase's docs) → **cleared entirely** (it was previously a false Critical). A committed `private-key` sitting beside test/example SAML IdP context (`ENTITY_ID` / `*.example.com`) inside a CI workflow is a SAML integration-test keypair → **down-ranked to `review`, not cleared** (still surfaced for the paid pass). Genuine service-role JWTs / private keys are unaffected and still fire at `high` (calibration-gated per §7).
- **Verdict:** TruffleHog verified secrets = **trustworthy for the free count**; gitleaks custom service-role hit = trustworthy; generic gitleaks regex/entropy = triage.

## 4. Dependency / version checks

- **OSV-Scanner (free, Apache-2.0)** over `package-lock.json`, sourced from osv.dev/GHSA — the mechanical detector for CVE-2025-29927 (matches installed `next` against the vulnerable ranges; fixed = 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3, GHSA-f82v-jwr5-mffw). V2 adds guided remediation + a reachability signal (the FP-reduction lever).
- **`npm audit`** — ecosystem-native, catches transitive vulns (>80% of exploitable CVEs are transitive) but noisier (non-exploitable dev-chain issues).
- **FP nuance:** a version match ≠ exploitable. CVE-2025-29927 only matters if **self-hosted with middleware doing auth**; Vercel/Netlify apps are auto-protected. Surface as "outdated/vulnerable dependency"; gate the *exploitability narrative* behind context/LLM triage.
- **Verdict:** exact match on a **known-critical CVE with a confirmed version range** (e.g. vulnerable `next`) = **trustworthy for the free count**; generic transitive CVEs = triage (reachability unknown).

## 5. ESLint security plugins

- `eslint-plugin-security` — heuristic, ~1:1 TP:FP, `detect-object-injection` is the canonical noise generator, and it **crashes on ESLint 9 flat config** until patched. **Exclude from the free count / drop** (Semgrep covers the same ground with better precision).
- `eslint-plugin-no-unsanitized` (Mozilla) — narrowly scoped to DOM-XSS sinks (`innerHTML`, `insertAdjacentHTML`); **low noise, high signal — the one worth counting** (secondary).
- `@next/eslint-plugin-next` / `typescript-eslint` — correctness/quality, not security sources.

## 6. Supabase's own tooling — the highest-trust mechanical RLS source

- **Security + Performance Advisors** run **Splinter** (open-source Postgres linter) against the live schema — deterministic, schema-truth, very low FP. Available via dashboard, the Supabase MCP `get_advisors` tool, and the CLI.
- Key security lints for the count: **0013 `rls_disabled_in_public`** (public table, RLS off = anyone with the anon key can CRUD), **0002 auth_users_exposed**, **0008 rls_enabled_no_policy**, **0010 security_definer_view**, **0011 function_search_path_mutable**, **0015 rls_references_user_metadata**, **0023 sensitive_columns_exposed**.
- **Verdict: highest-trust source in the toolchain** — advisor security lints reflect ground truth and are **trustworthy for the free count as-is**. But they require DB connection (won't work from a repo-only scan), so this is a "connected" tier, not pure static.

## 7. Calibration & the free-count trust boundary

**How to calibrate FP rate:** build a labeled corpus / deliberately-broken calibration target (issue #9) containing known planted true positives (service-role key in a client component, `NEXT_PUBLIC_` secret, tainted `dangerouslySetInnerHTML`, a public table with RLS off, a pinned vulnerable `next@15.2.1`) **and** known benign lookalikes (anon key in `NEXT_PUBLIC_*`, index+id JSX keys, a dev-only vulnerable dep — NOT a `nosemgrep`-annotated one, per #1066: a marker the target writes is a suppression to disclose, never a corpus label). Run the toolchain, compute per-rule precision. **Promote a rule into the free count only when its corpus precision is ~100%.** Re-run the corpus on every rule/version bump.

**NOT trustworthy for the raw free count (needs LLM triage):** all `eslint-plugin-security` heuristics; Semgrep `.audit.*` and MEDIUM/LOW-confidence + heuristic taxonomy rules; gitleaks unverified regex/entropy; generic transitive-dep CVEs and any "vulnerable version" whose exploitability depends on deployment context; SonarQube code smells and React-FP rules (S3776/S6479/S6853/S1481).

**Trustworthy for the raw free count:** TruffleHog `--only-verified` secrets; gitleaks custom service-role-JWT (decoded `role` claim); OSV-Scanner exact match on a specific known-critical CVE range; Supabase Advisor security lints; `eslint-plugin-no-unsanitized`; Semgrep HIGH-confidence ERROR-severity non-audit security rules.

## Recommended toolchain

| Tool | Role | Rulesets / config | FP-control | Free-count trustworthy? |
|---|---|---|---|---|
| **Semgrep OSS** | Mechanical-security core (SAST + custom taxonomy) | `p/typescript`, `p/react`, `p/nextjs`, `p/owasp-top-ten`; custom: service-role-in-client, `NEXT_PUBLIC` leak, missing-auth-guard | `confidence: HIGH` + `--severity ERROR`; exclude `.audit.*`; in-repo `nosemgrep`/`.semgrepignore` overridden and disclosed (#1066) | HIGH-conf ERROR rules: **YES**; MEDIUM/heuristic: triage |
| **TruffleHog** | Secret detection (count source) | default detectors, `--only-verified`, scan history | live verification | **YES** (verified only) |
| **gitleaks** | Fast pre-commit + custom Supabase secret rules | custom `supabase-service-role-jwt` w/ `--max-decode-depth 2`; anon-key allowlist; `.env.example` allowlist | rule allowlists; decode `role` claim; known-public/test-cred recognizer | custom service-role hit: **YES**; generic: triage |
| **OSV-Scanner (v2)** | Dependency/CVE version check | `package-lock.json`; guided remediation; reachability | reachability; dev-dep filter; exact GHSA range | exact known-CVE match: **YES**; generic transitive: triage |
| **Supabase Advisors** (CLI / `get_advisors`) | RLS/config ground-truth (connected tier) | security lints 0002/0008/0010/0011/0013/0015/0023 | Splinter on real schema | **YES** (requires project connection) |
| **eslint-plugin-no-unsanitized** | Secondary DOM-XSS sink check | `no-unsanitized/method`,`/property` | narrow sink scope | **YES** (secondary) |
| **eslint-plugin-security** | (optional) extra heuristics | disable `detect-object-injection`; fix ESLint 9 compat | broad heuristics ~1:1 | **NO** — triage/drop |
| **SonarQube CE** | (optional) code-quality depth tier | custom profile ex-"Sonar way"; disable S3776/S6479/S6853/S1481; exclude `.next` | custom profile; `//NOSONAR` | **NO** for security count |

**Bottom line:** the free security count is assembled from **verified secrets (TruffleHog + gitleaks decoded service-role rule), Supabase Advisor security lints, exact known-CVE dependency matches (OSV-Scanner), and Semgrep HIGH-confidence ERROR-severity security rules** — every one deterministic or verification-backed. Semgrep is the mechanical-security core; Supabase Advisors are the highest-trust source; **SonarQube CE and eslint-plugin-security add noise and belong behind LLM triage, not in the free count.**

## Sources

[Sonar JS/TS docs](https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/languages/javascript-typescript-css) · [Sonar taint engine](https://community.sonarsource.com/t/next-generation-taint-analysis-engine-for-javascript-typescript/148744) · [Semgrep JavaScript](https://semgrep.dev/docs/languages/javascript) · [Semgrep cross-file](https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-intro) · [Trail of Bits Semgrep](https://blog.trailofbits.com/2024/01/12/how-to-introduce-semgrep-to-your-organization/) · [gitleaks](https://github.com/gitleaks/gitleaks) · [TruffleHog vs Gitleaks](https://secrails.com/blog/trufflehog-vs-gitleaks-github-secret-scanning-guide) · [secret-scanner benchmark arXiv 2307.00714](https://arxiv.org/pdf/2307.00714) · [OSV-Scanner](https://google.github.io/osv-scanner/) · [OSV-Scanner V2](https://security.googleblog.com/2025/03/announcing-osv-scanner-v2-vulnerability.html) · [GHSA-f82v-jwr5-mffw](https://github.com/advisories/GHSA-f82v-jwr5-mffw) · [Datadog CVE-2025-29927](https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/) · [Supabase Database Advisors](https://supabase.com/docs/guides/database/database-advisors) · [eslint-plugin-security benchmark](https://dev.to/ofri-peretz/i-benchmarked-17-eslint-security-plugins-only-one-found-every-vulnerability-c83)
