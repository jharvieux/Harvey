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
- **#101** — zip/working-folder scan scoping (NOT a general blocker). A git clone / collaborator
  invite (the primary path) carries only committed files, so gitignored `.env.local` / `.claude/worktrees/`
  never appear — the noise seen against ATC was from scanning a local working checkout. The real case is
  the runbook's **zip-export** option: a working-folder zip can carry `.env*`, `node_modules`, `.claude/`,
  build output. Fix: prefer git-clone access; when a zip IS the target, normalize it (respect `.gitignore`
  or an exclude list) before scanning. Git-history secret scanning still legitimately catches
  committed-then-removed secrets in a clone.
- **#102** epic-builder-web: live Anthropic ModelClient (seam present; MVP ships on scaffold). 
- **#103** epic-builder-web: Supabase storage adapter + Supabase Auth (MVP is filesystem/single-instance).
- **#53** the reference-harness `/threat-model`→`/vuln-scan`→`/triage` SKILLS aren't installed here;
  pipeline verified via Harvey's own scanners against ATC instead. Installing the harness skills (or
  keeping Harvey's own pipeline) is the remaining choice; #101 gates client-readiness either way.

DONE this round (merged): #54 (Splinter wired into local scan), #94 (M3 adapter corrected to the real
vitals schema, captured from a live ATC run), #86 (gate path-matcher), #73 (OSV dedup),
#76 (epic-builder web UI MVP — internal tool, filesystem + scaffold model).

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
