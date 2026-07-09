# SESSION — where we left off (going-forward items)

Running state log (see `CLAUDE.md` → Session log). Forward-looking; overwrite stale items.

_Last updated: 2026-07-09 (corpus expansion complete, connected-tier live-confirmed)_

## Corpus expansion (#71 security, #72 cross-module) — COMPLETE
All mechanical batches merged. Answer key + Semgrep rules are per-batch modular
(`src/scan/calibration/<batch>.entries.ts` + `src/scan/rules/semgrep/<batch>.yml`).
**Corpus: 99 positives + 62 negatives; gate 72/72 static positives (24 high/free-count,
15 connected N/A) / 47/47 negatives — PASS.**
- **#71 security:** B1 secrets, B2 CVE/supply-chain (#65/#66), B3 injection, B4 XSS, B5 headers/CORS,
  B6 crypto, B7 auth, B8 Supabase-connected.
- **#72 cross-module:** M10 PII, M4+M5 dup/dead-code, M8 mutation, M7 perf-advisors (all precision-gated);
  M3 hotspots (design+fixture, ordering-gate — live `vitals` capture deferred → **#94**);
  M6 simplification (paid-only rubric-eval design note + labeled corpus, no precision gate).
- **Connected-tier live-confirmed** (`docs/runbooks/dry-run-calibration.md` §9): every B8 security lint +
  M7 perf lint fires against real Splinter on a live stack. Gap found: `harvey scan --supabase local`
  runs a subset, not full Splinter → **#54** is what unlocks the connected coverage locally.

## Open agent-doable follow-ups (mechanical-scan maturity)
- **#54** wire `splinter.sql` into local Supabase scan (unlocks B8/M7 connected coverage locally; live evidence attached).
- **#94** M3: capture the real `vitals --json` schema + a git-history hotspot fixture + `pnpm validate:hotspots` Layer-2.
- **#86** normalize the calibration gate's `location` matcher to repo-relative (env-independent scoring).
- **#73** OSV dedup (`next@14.2.35` double-matches a curated CVE).
- **#53** LLM `/threat-model`→`/vuln-scan`→`/triage` pipeline unverified (needs reference-harness).

## New product surface
- **#76** epic-builder web UI (opus; design doc first) — closes the "onboarding site has no link to the epic tool" gap.

## Operator / manual action items (not agent-executable)
- **Vercel 404:** set the `harvey` project Root Directory to `intake-site` + add `RESEND_API_KEY`
  (fixes the onboarding-page 404 AND `/api/intake`). Page currently serves at `/intake-site/`.
- **#70 GitGuardian:** dashboard ignore for `targets/calibration/` (fixture fake secrets; the App
  ignores the committed `.gitguardian.yaml`; not a required check, never blocks merges).

## Deferred / not agent-executable
#4 Tier-2 (gated on demand). #10–13 business/legal/GTM. #2 epic. #14 ATC folder removal (atc repo).

## Locked product decisions (memory: `product-shape-decisions.md`)
Free count/grade = high-precision findings only + M3 descriptive map. Review/connected tier scanned
but asserted only in the paid report after verification. M6 paid-only. Gate discipline (#61): no rule
ships/counts unless it catches its positive AND clears its benign negative.

## Resuming live validation (Docker down — colima stopped)
`colima start` → `supabase start -x vector,analytics` + `supabase db reset` in `targets/calibration`.
Seeded logins fail (gotrue) → mint JWTs from `JWT_SECRET`. To run the real advisor against the target:
`psql "$DB_URL" -f splinter.sql` (github.com/supabase/splinter). Scanner binaries all installed.
