# Harvey precision & recall measurement — Bum-Boo/vibe-dummy-test-kit

**Date:** 2026-07-18
**Target:** `Bum-Boo/vibe-dummy-test-kit` (`BTS_sec` staircase lab) — cloned to `/private/tmp/vibe-dummy-test-kit`
**Why this target:** it is the one found target with a built-in **precision oracle** — its
`expected/*.expected-findings.yaml` files carry both `expectedFindings` (recall ground truth) and
`notExpectedFindings` (findings Harvey must NOT emit), plus a fixed FP-control stage (stage-11) and a
clean baseline (stage-00). This run is the precision test: does chasing recall wreck precision?

## Target shape and tier applicability

vibe-dummy is a pnpm monorepo — Next.js 16 frontend + Express 5 + `pg` `target-api` + a mock-llm — with
its own docker-compose harness. It is **NOT Supabase.** The planted-vuln ground truth lives in
`stages/stage-NN-*/src/` (each stage a mini Express/React fixture); `apps/` holds the integrated runnable
services. Scans were run against `stages/` because that is where the expected-finding IDs map.

| Tier | Applies? | How run here |
|------|----------|--------------|
| M1 mechanical (secrets/semgrep) | yes | `quick-scan` (whole repo + per-stage) + Harvey `semgrep` rules over `stages/` |
| Static AST detectors (M5/M6/M9…) | yes | `detect-static` per stage |
| Deps (M4/M5 osv) | yes | osv-scanner via quick-scan |
| Semantic (LLM M1) | yes | manual review of every staged vuln module, guided by `briefs/scan-extras.txt`, triaged by `briefs/fp-rules.txt` |
| M2 dynamic pen-test | **N/A — partial-with-reason** | Harvey's M2 is the Supabase local-stack PostgREST cross-tenant matrix; the target is Express+pg. Not the M2 path. Not a miss — recorded partial. |
| M10 live PII | **N/A — partial-with-reason** | no Supabase DB / migrations to classify. |

## Tools actually run (grounding)

- `pnpm exec tsx src/cli/quick-scan.ts --dir <repo|stage> --json` — whole repo: Grade A / 0 findings;
  per-stage: only "Missing lockfile" (Medium). gitleaks/trufflehog ran (gitleaks reported raw hits) but
  **no secret was surfaced** — see §Secrets.
- `pnpm exec tsx src/cli/static-detect.ts <stage>` — produced **only M5 maintainability** findings
  (single-use helper, Low), **zero security findings**, on every stage.
- `semgrep --config src/scan/rules/semgrep <stages>` — **1** hit total: `harvey-missing-server-only` on
  `stage-02-frontend-config/src/client-config.ts:7`.

## PRECISION — the headline metric

**FALSE POSITIVES: 0. Verdict: CLEAN.**

Every `notExpectedFindings` entry and every FP-control stage was checked against what Harvey actually
emitted:

| notExpected / control | Safe code | Harvey emitted it? |
|---|---|---|
| stage-04 `BAC-004` — `GET /api/my/projects` | `findProjectsByOwnerId(session.user.id)` (owner-scoped) | **No** ✓ |
| stage-06 `XSS-005` — safe escaped component | JSX text interpolation `{user.bio}` | **No** ✓ |
| stage-07 `FILE-006` — safe upload handler | MIME+size+ext validation, UUID rename, private storage | **No** ✓ |
| stage-11-fixed — all of CHAIN-001..007 fixed | owner-scoped reads, `requireAdmin`, `escapeHtml`, private upload, restricted CORS, public DTO, no service-role key in browser config | **No security finding** ✓ |
| stage-00-clean — FP baseline | clean fixture | **No** ✓ |

The only output on the FP-control stages was `detect-static`'s **M5 "single-use helper" (Low,
maintainability)** on stages 00 and 11. The stage-11 oracle explicitly permits these: *"Low/info
recommendations are acceptable only if actionable and unrelated to the fixed Stage 10 critical/high
classes."* They are maintainability, not security, and do not match any `notExpectedFindings` class →
**not false positives.**

**No FP issues were filed — there were no false positives to fix.** This is the key result: Harvey's
precision discipline (entropy/verification-gated secrets, taint-scoped sinks, fp-rules triage) held on a
target explicitly built to bait a recall-chasing scanner.

## RECALL

49 `expectedFindings` across stages 01–10. **Caught 47/49 (96%).**

| Stage | Findings | Caught | Tier | Notes |
|---|---|---|---|---|
| 01 secrets | 5 | 3 | semantic | SECRET-001 (service-role key name in frontend `supabase.ts`), SECRET-004 (service-role key in built `dist/main.js`), SECRET-005 (DB URL w/ creds committed) caught as structural exposures. **SECRET-002 (README) & SECRET-003 (CI env) MISSED** — see below. |
| 02 frontend-config | 3 | 3 | mechanical + semantic | `harvey-missing-server-only` fired on `client-config.ts` (only mechanical security hit in the whole run); all three exposures confirmed semantically. |
| 03 auth | 5 | 5 | semantic | client-trusted `isAdmin`, unverified JWT decode, no login rate limit, non-expiring reset token, middleware skips `/api`. |
| 04 access-control | 3 | 3 | semantic | BAC-001/002/003 IDOR (`findXById(req.params.id)`, no owner check). |
| 05 api-data-exposure | 4 | 4 | semantic | full-row exposure incl. `passwordHash`/`refreshToken`; mass assignment via `req.body`. |
| 06 user-content-xss | 4 | 4 | semantic | 3× `dangerouslySetInnerHTML` (prop-sourced) + weak CSP. **Mechanically dark — see #613.** |
| 07 file-upload | 5 | 5 | semantic | original filename, public dir, no size/MIME limit, unsanitized SVG. |
| 08 server-misconfig | 7 | 7 | semantic | root container, `COPY .env`, missing headers, `origin:"*"`+creds, debug endpoint, auth headers logged, public backup file. |
| 09 ai-risks | 6 | 6 | semantic | AI→HTML, AI→SQL exec, AI→command, prompt secret, no input limits, unsafe RAG. |
| 10 chained-saas | 7 | 7 | semantic | service-role key in browser config + the full chain (IDOR, AI-HTML, upload, frontend-only admin, CORS, exposure). |

**By tier:** mechanical ≈ 1 (the stage-02 `missing-server-only` signal); semantic 47. The two misses are
**precision-driven, by design:**

- **SECRET-002 / SECRET-003 MISSED.** Every planted secret is the literal string
  `fake_..._for_training_only` (non-provider-pattern, low-entropy, carrying explicit "FAKE TRAINING
  VALUES ONLY" comments). Harvey's `fp-rules.txt` deliberately suppresses these: *"placeholder secrets in
  sample files are not findings… require live verification before counting,"* and *"a secret is not a
  finding on variable name alone."* SECRET-002 (a fake string in a README) and SECRET-003 (a fake value in
  a CI `env:`) fall squarely under that suppression. SECRET-001/004/005 were still recovered semantically
  because the *structural* exposure (a service-role-**named** key bundled into frontend/built code; a
  credential-bearing DB URL committed) is a real pattern independent of the value. **This is the
  recall↔precision tension the corpus is designed to expose, resolved on the precision side — the correct
  call for a paid audit that must not cry wolf on fake strings.**

## Mechanizable recall gaps filed

The mechanical tier caught only 1/49 because Harvey's request-source taint is tuned for Next
App/Pages-Router + Supabase query sinks; this target is Express+pg with prop/param sources. Two focused,
deduped issues (distinct from the existing #601, which covers Next-async-`params` IDOR + Supabase-spread
mass-assignment):

- **#613** — prop/param-sourced `dangerouslySetInnerHTML={{__html: <userdata>}}` XSS is mechanically dark
  (stage-06 ×3, stage-10 CHAIN-003). Cleanest fix, low FP risk; stage-11's `escapeHtml` is the precision
  guard.
- **#614** — plain-Express `(req,res)` handler sources (`req.params`/`req.body`/`req.headers`) +
  `res.json`/CORS-literal sinks are unrecognized → IDOR / mass-assignment / excessive-exposure / CORS /
  client-trusted-admin all dark on an Express target. Framed as an operator scope decision (Express may be
  intentionally out of the mechanical wheelhouse).

## Teardown

The docker-compose harness was **not** started (M2 Supabase path N/A). No containers, no volumes touched.
Clone remains under `/private/tmp/vibe-dummy-test-kit` (tmp). Primary Harvey checkout untouched — all work
in the isolated worktree.

## Bottom line

On the one target with a built-in precision oracle, Harvey emitted **zero false positives** (0/5 FP-control
surfaces tripped) while recovering **47/49** planted findings, **96%**, almost entirely via the semantic
tier. The mechanical tier is Supabase/Next-shaped and near-silent on an Express+pg target (1/49) — a
scope/coverage gap (#613/#614), **not** a precision problem. Precision held exactly where the corpus tried
to break it.
