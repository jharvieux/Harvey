# SESSION — where we left off (going-forward items)

Running state log (see `CLAUDE.md` → Session log). Forward-looking; overwrite stale items.

_Last updated: 2026-07-09 (corpus + follow-ups done; #53 run against ATC surfaced the scoping gap #101)_

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

## Open agent-doable follow-ups
- **#53** — reference-harness skills (`vuln-scan`/`threat-model`/`triage`/`patch`/`customize`) now
  INSTALLED to `~/.claude/skills/` (Apache-2.0). Load at session start → a fresh session can run the
  full `/threat-model → /vuln-scan --extra docs/scan-extras.txt → /triage --fp-rules docs/fp-rules.txt`
  pipeline against a **git clone** of a client repo. Open call: vendor them into the Harvey repo
  (version-controlled with the venture, #14) vs. keep user-global.

DONE (merged): #101 (scan scopes to git-tracked files / zip exclude-list), #102 (live Anthropic
ModelClient — sonnet-5 flagship / haiku-4.5 standard, behind the seam), #103 (Supabase storage
adapter + Supabase Auth, RLS on both tables; hydrate-run-flush bridge). #54/#94/#86/#73/#76 also done.

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
