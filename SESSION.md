# SESSION — where we left off (going-forward items)

Running state log (see `CLAUDE.md` → Session log). Forward-looking; overwrite stale items.

_Last updated: 2026-07-10 (post-#71: excluded-tier backlog filed #123–#125, #70 closed, ATC re-scan dogfood, route-noauth precision fix #126 merged)_

## Corpus expansion (#71 security, #72 cross-module)
Answer key + rules are per-batch modular (`src/scan/calibration/<batch>.entries.ts` +
`src/scan/rules/semgrep/<batch>.yml` / scanner extensions). Each batch is one PR, self-contained,
gated by `pnpm validate:calibration` (a class ships only if its positive is caught AND its benign
negative cleared; only `high` classes feed the free count).

**Gate after the overnight round-2 train: 140/140 static positives (61 high/free-count), 108/108
negatives cleared, 15 connected-tier N/A — PASS.** (Was 77/77 / 25 high before this session.)

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

## Open agent-doable follow-ups
- **#71 close-out** — mechanical work done. The excluded-tier backlog is now FILED as three issues:
  **#123** (semantic → paid M-series), **#124** (connected → live Supabase advisor), **#125**
  (dynamic → #5 pen-test). #71 can be closed or re-scoped to point at those.
- **#123–#125** — the excluded-tier security classes from the #71 round-2 research, grouped by
  detection mechanism (see `docs/design/corpus-roadmap-to-100.md` §4). Not yet started.
- **Skills vendoring decision** (from #53, closed): reference-harness skills live user-global at
  `~/.claude/skills/`. Open call: vendor into the Harvey repo (#14) vs. keep user-global.

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
