# SESSION — where we left off (going-forward items)

Running state log (see `CLAUDE.md` → Session log). Forward-looking; overwrite stale items.

_Last updated: 2026-07-09 (issue-sweep: #53 verified+closed via PR #111; #71 B2 batch landed via PR #112)_

## Corpus expansion (#71 security, #72 cross-module) — all batches landed
Answer key + Semgrep rules are per-batch modular
(`src/scan/calibration/<batch>.entries.ts` + `src/scan/rules/semgrep/<batch>.yml`).
**Gate after PR #112: 77/77 static positives (25 high/free-count) / 49/49 negatives — PASS.**
- **#71 security:** B1 secrets, B3 injection, B4 XSS, B5 headers/CORS, B6 crypto, B7 auth,
  B8 Supabase-connected. **B2 CVE/supply-chain landed for real in PR #112** (a prior session had
  marked it done via #65/#66, but no gate rows existed): 7 classes gated incl. new typosquat +
  non-registry-dep scanner. **Still open on #71:** 7 deferred B2 classes (P-NEXT-EOL, P-REACT-DOM-CVE,
  P-DEP-CVE-CRITICAL, P-MISSING-LOCKFILE, P-KNOWN-IOC-PKG + 2 negatives — reasons in
  `targets/calibration/GROUND-TRUTH.md` §B2) and the research-to-~100 class ranking.
- **#72 cross-module:** M10 PII, M4+M5 dup/dead-code, M8 mutation, M7 perf-advisors (all precision-gated);
  M3 hotspots (design+fixture, ordering-gate — live `vitals` capture deferred → **#94**);
  M6 simplification (paid-only rubric-eval design note + labeled corpus, no precision gate).
- **Connected-tier live-confirmed** (`docs/runbooks/dry-run-calibration.md` §9): every B8 security lint +
  M7 perf lint fires against real Splinter on a live stack. Gap found: `harvey scan --supabase local`
  runs a subset, not full Splinter → **#54** is what unlocks the connected coverage locally.

## Open agent-doable follow-ups
- **#71 remainder** — the 7 deferred B2 classes + the research-to-~100 ranking (see corpus section).
- **Skills vendoring decision** (from #53, now closed): the reference-harness skills live user-global
  at `~/.claude/skills/`. Open call: vendor them into the Harvey repo (version-controlled with the
  venture, #14) vs. keep user-global.

DONE (merged): **#53 CLOSED via PR #111** — the `/threat-model → /vuln-scan → /triage` pipeline ran
end-to-end against `targets/calibration` for real: **7/8 original planted bugs caught** (both RLS
policy bugs + SQLi included); the open-redirect miss is the pipeline's own deliberate severity
filter, documented in `docs/runbooks/dry-run-calibration.md` §10. Runbook step 1 now records the
real install path. Also previously merged: #101 (scan scopes to git-tracked files), #102 (live
Anthropic ModelClient), #103 (Supabase storage adapter + Auth). #54/#94/#86/#73/#76 also done.

## Operator / manual action items (not agent-executable)
- **Vercel 404:** set the `harvey` project Root Directory to `intake-site` + add `RESEND_API_KEY`
  (fixes the onboarding-page 404 AND `/api/intake`). Page currently serves at `/intake-site/`.
- **#70 GitGuardian:** appears RESOLVED — the check passed on PRs #111 and #112 (both touch or sit
  atop calibration fixtures), so the dashboard ignore seems in effect. Confirm and close #70.
  Side-check of the other repos (2026-07-09): no other repo needs a path exclusion; ATC's only
  realistic-looking committed secret is a fake Svix doc-example `whsec_` in two resend webhook tests.

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
