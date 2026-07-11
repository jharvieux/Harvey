# SESSION — where we left off (going-forward items)

Running state log (see `CLAUDE.md` → Session log). Forward-looking; overwrite stale items.

_Last updated: 2026-07-10 (…then M7 code-level perf detectors, phase 1 of #170 → PR #173 merged)_

## M7 code layer (#170) — phase 1 merged (PR #173), issue stays open

M7 Performance is no longer DB-advisor-only: `src/detectors/perf-code.ts`
(`detectPerfCodeFindings`, ids `M7C-*`) covers 14 mechanical [M] classes on source alone —
React render waste (ctx-value churn, inline literal props, raw `<img>`, index keys,
sort-in-JSX, state sprawl), N+1 await-in-loop, unbounded `select('*')`, whole-library +
heavy-client imports, manual font links, middleware fetch, sync I/O in route handlers, JSON
deep-clone — each gated by a positive+negative fixture pair (`__fixtures__/perf/`, via
`pnpm verify`). React Compiler config downgrades the manual-memo classes to Info. Coverage
gate: M7 `needs: "source"` now; a no-DB engagement records M7 **partial** (code ran, advisor
n/a), and M7 is `freeTier: true` per the issue's free-count mandate. Runbook:
`docs/m7-performance.md` §2a.

**Queued on #170 (sequenced in the issue comment):** 1) [B] bundle-stats input
(`next build`/`@next/bundle-analyzer` JSON), 2) deferred [M] classes (hook-deps via eslint
runner, `optimizePackageImports` config check, committed-asset size walk), 3) [L] classes fold
into the paid review-pass brief.

## Pen-test kit (M2 / #5) — target-adaptive, monorepo-aware
The dynamic tier evolved from hardcoded calibration paths to discovering the system under test:
- **Route discovery** (`src/pentest/discovery.ts`, PR #156): walks a target's Next.js tree →
  `TargetProfile` (versioned / high-value / public-cache routes, privileged RPCs, seams). The four
  dynamic probes (#145–#148) iterate discovered candidates; a class with no candidate self-reports
  **not-applicable** (the honest result), not a hardcoded-path miss.
- **Monorepo enumeration + completeness gate** (`src/pentest/targets.ts`, PR #157):
  `discoverTargets(repoRoot, envVarNames)` → manifest of **apps** (workspace globs, classified),
  **backends** (distinct Supabase projects by env-var convention; `TEST` = write-safe instance),
  **seams** (service URLs, cross-service webhooks, service JWTs). `assertComplete` FAILS LOUD on any
  enumerated-but-untested target — coverage is now mechanical, not a judgment call (this is what the
  RAG-backend omission exposed).
- **Seam probes** (`src/pentest/verify.ts`, PR #157): DIRECT-SERVICE-CALL, SERVICE-JWT-UNVERIFIED
  (forged `alg:none` token), CROSS-SERVICE-WEBHOOK — the trust boundaries between per-app checks.
- **Intake updated to match** (PR #157): `docs/templates/auth-questionnaire.md` §0 (app/backend
  topology, per-backend connection info, write-safe-env designation, seams),
  `docs/runbooks/engagement-access.md` (manifest step, per-backend creds, seam details),
  `intake-site/index.html` (per-backend DB card + monorepo/apps/backends/seams fields). The three
  stay in sync; the questionnaire is source of truth.

**ATC live-test results (2026-07-10, read/write against TEST, read-only against prod):** tenant
isolation HOLDS on read AND write — attacker (tenant `f5665f08` owner) sees 129 own messages / 0
victim; cross-tenant reassign → `new row violates RLS`, delete → 0 (all rollback). ATC RLS keys on
`users.auth_user_id = auth.uid()` via `auth_user_can_access_conversation` (SECURITY DEFINER). Anon
denied on every sensitive table (401/42501) on both **main** and **rag**. Route discovery over ATC:
289 routes → 0 versioned, 0 public-cache, 10 high-value → SHADOW-API/CACHE-CROSS-USER correctly N/A.
See [[atc-supabase-topology]] for the MCP→project map (main = prod, rag = single prod-serving DB,
aop = off-limits client).

**Open dynamic-tier gap:** NO-RATE-LIMIT loop never run end-to-end — needs the ATC **test app
deployed** (not just the test DB) and careful scoping (its 10 candidate flows include payout/
checkout/Stripe-test paths). The apps/extension surface and the live seam probes against ATC are
also not yet exercised (enumerated, not tested — the completeness gate would flag them).

## Corpus expansion (#71 security, #72 cross-module)
Answer key + rules are per-batch modular (`src/scan/calibration/<batch>.entries.ts` +
`src/scan/rules/semgrep/<batch>.yml` / scanner extensions). Each batch is one PR, self-contained,
gated by `pnpm validate:calibration` (a class ships only if its positive is caught AND its benign
negative cleared; only `high` classes feed the free count).

**Gate after the 2026-07-10 sweep (secrets/git-history #129–#130 + review-tier authz/policy
#131–#139 merged): 142/151 static positives (62 high/free-count), 118/118 negatives cleared, the
review-tier authz/policy positives are documented offline-gate misses (LLM/paid-tier by design) —
PASS.** Connected-tier #140–#144 add live detectors (N/A in the offline static gate).

- **#71 round 1 (built earlier):** B1 secrets, B2 CVE/supply-chain, B3 injection, B4 XSS,
  B5 headers/CORS, B6 crypto, B7 auth, B8 Supabase-connected.
- **#71 round 2 (merged 2026-07-10, PRs #116–#121):** the 5-lens research (OWASP, Next.js surface,
  framework CVEs, Semgrep registry, Supabase) was deduped/ranked into
  `docs/design/corpus-roadmap-to-100.md` (PR #114), then built out in six serial batches:
  - **B9** secrets & config-secret breadth (12) · **B10** dependency-CVE & framework-version (10) ·
    **B11** crypto-API misuse & JWT-verify options (9) · **B12** next-config & client-surface
    misconfig (11) · **B13** Supabase static-config/edge + injection sinks (12) · **B14** app-logic
    heuristics (5, review-tier).
  - **Two new scanners:** `checkPublicDirSensitive` (walks `public/` for committed sensitive files,
    B12) and `supabase-static.ts::checkMigrationRlsStatic` (parses committed migrations for
    `CREATE TABLE` with no `ENABLE RLS` — moves `P-RLS-DISABLED` onto the static free tier, B13).
  - Everything else extended existing scanners/rules. ~59 new mechanical classes total (~36 high,
    ~23 review). One class dropped as a genuine B2 dup (minimist CVE).
- **#71 now has essentially no mechanical backlog.** The 18 excluded-tier candidates (semantic /
  connected / dynamic) in the roadmap §4 are correctly routed to the paid M-series, the connected
  tier, and the #5 pen-test — NOT new mechanical batches. #71 can be closed or narrowed to "connected
  P-REALTIME-NO-AUTHZ + the semantic/dynamic backlog" if you want a clean tracker.
- **#72 cross-module:** M10 PII, M4+M5 dup/dead-code, M8 mutation, M7 perf-advisors (precision-gated);
  M3 hotspots (design+fixture, live `vitals` capture deferred → **#94**); M6 simplification (paid-only).

## Excluded-tier backlog (#123–#125) — DONE, all three trackers CLOSED
The three trackers were split into 18 per-class child issues (#131–#148) and fully delivered:
- **#123 semantic (review-tier)** → children **#131–#139**, all MERGED as corpus fixture pairs
  (B15 Next.js/app-logic authz #131–#136; **B16** storage-RLS/upload/SECURITY-DEFINER policy
  #137–#139). Detection is the paid LLM `/vuln-scan`+`/triage` pass (option (b)); fixtures seeded +
  benign negatives gate-cleared offline.
- **#124 connected (live Supabase)** → children **#140–#144**, all MERGED (PR #150). Five detectors
  in `src/scan/supabase-config.ts`: `checkRealtimeAuthorization`, `checkExposedSchemas`,
  `checkGraphqlIntrospection`, `checkGotrueVersion` (×2 CVE ranges). Live-validated read-only vs ATC.
- **#125 dynamic (running-app probes)** → children **#145–#148**, all MERGED (PR #154). Four
  verify-mode replays in the #5 pen-test kit (`src/pentest/verify.ts`): SHADOW-API-VERSION,
  NO-RATE-LIMIT, CACHE-CROSS-USER, ANON-PRIVILEGED-RPC — each with a seeded positive route/RPC on
  the calibration target (GROUND-TRUTH rows 9–12) + a benign sibling the probe clears. Write probes
  gated behind `allowDestructive`. A live ATC run is the optional supervised outcome-confirmation.
- **Skills vendoring decision** (from #53, closed): reference-harness skills live user-global at
  `~/.claude/skills/`. Open call: vendor into the Harvey repo (#14) vs. keep user-global.

## ATC as live target — project topology (verified 2026-07-10)
The connected/dynamic tiers can validate against ATC. MCP → project mapping:
- **`supabase-main` = `mfaknjyqiwcjojukcnea` = atc-main, ATC PRODUCTION.** MCP applies ARE prod
  applies — **read-only introspection only** (structured tools: `list_tables`/`list_extensions`/
  `get_advisors`; no `execute_sql` exposed, a good fence). Connected-tier #140–#144 were validated
  read-only here: pg_graphql not installed + realtime.messages RLS on (clean negatives), GoTrue
  v2.192.0 w/ Azure enabled (patched — exercises #143's provider branch, no finding).
- **`supabase-rag` = `jjznkprbotkqqnuvcost`** = ATC RAG project (has `execute_sql`).
- **`supabase-aop` = `udsuxdoavlvosvbjwmud`** = the **AoP client** (Age of Piracy) — OFF-LIMITS, not ATC.

## ATC dogfood re-scan (2026-07-10) — expanded corpus validated end-to-end
Ran the full scan → LLM-triage → report pipeline against a git clone of jharvieux/ATC with the
expanded corpus. **286 raw mechanical findings triaged to 4 real (all LOW/hardening); 0 Critical/
High/Medium survived** — tenant isolation and per-route auth hold, matching the June self-audit.
- Real items: `select('*')` PII over-selection (6 routes, the one useful new-detector signal, B13),
  mutable CI action tags, a transitive `@opentelemetry/core` CVE, absent pnpm hardening opts.
- The raw scan's 3 "Criticals" + 91 "Highs" were ALL false positives (fake test-token, trusted-CI
  context, auth-via-unrecognized-guards). Strong proof of the thesis: value is in the triage gate.
- **Fix shipped: #126/PR #127** — broadened `harvey-route-noauth` to recognize custom guard helpers
  (`assertPlatformAdmin`/`assertPermission`/etc.). ATC route-noauth FPs **122 → 0**; locked into the
  #61 gate with a fixture pair. Corpus now 141/141 positives, 109/109 negatives.
- Report renderer takes raw `Finding[]` directly (same schema); render curated findings to a NEW
  `findings.<name>.json` — never overwrite `report-template/findings.atc.json` (protected).
- NOT run this pass: connected-tier live Supabase advisor (#124-adjacent, needs a live stack) and
  the dynamic pen-test (#5).

DONE (merged this session): **#53 CLOSED via PR #111** (pipeline verified end-to-end, 7/8 planted
bugs caught; runbook install path corrected). #71 round-2 corpus via PRs #112, #114–#121. Earlier:
#101/#102/#103, #54/#94/#86/#73/#76.

## Operator / manual action items (not agent-executable)
- **#70 GitGuardian — CLOSED 2026-07-10.** The `targets/calibration/` dashboard ignore works.
  Residual noted at close: FAKE secret-shaped test vectors in `src/scan/calibration.test.ts`
  (`npm_FAKE…`, `AIzaSyD0FAKE…`) sit OUTSIDE the ignored path and can trip GitGuardian on future
  batch PRs (benign; `verify` is the only required check). If it becomes annoying, add that one file
  to the dashboard ignore.
- **Vercel 404 / preview-deploy fail:** still the `harvey` project Root Directory (set to
  `intake-site`) + `RESEND_API_KEY`. PR #121's Vercel preview deploy failed for this same
  project-level reason (not a code regression — `verify` was green); merged on the required check.
- **Cross-repo GitGuardian (2026-07-09):** no other repo needs a path exclusion; ATC's only
  realistic committed secret is a fake Svix doc-example `whsec_` in two resend webhook tests.

## Deferred / not agent-executable
#4 Tier-2 (gated on demand). #10–13 business/legal/GTM. #2 epic. #14 ATC folder removal (atc repo).

## Locked product decisions (memory: `product-shape-decisions.md`)
Free count/grade = high-precision findings only + M3 descriptive map. Review/connected tier scanned
but asserted only in the paid report after verification. M6 paid-only. Gate discipline (#61): no rule
ships/counts unless it catches its positive AND clears its benign negative. **Credibility cap
(`mechanical-toolchain.md` §7): a single wrong "Critical" is credibility-fatal — the 61 high classes
were each gated exact/unambiguous; version-match ≠ exploitable, so the paid report still triages.**

## Resuming live validation (Docker down — colima stopped)
`colima start` → `supabase start -x vector,analytics` + `supabase db reset` in `targets/calibration`.
Seeded logins fail (gotrue) → mint JWTs from `JWT_SECRET`. To run the real advisor against the target:
`psql "$DB_URL" -f splinter.sql` (github.com/supabase/splinter). Scanner binaries all installed.
