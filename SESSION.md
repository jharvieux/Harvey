# SESSION — where we left off (going-forward items)

Running state log (see `CLAUDE.md` → Session log). Forward-looking; overwrite stale items.

_Last updated: 2026-07-09 (corpus expansion, all mechanical batches complete)_

## Active work: corpus expansion (#71 security → ~100, #72 cross-module)
Built as per-batch PRs. Answer key is modular (`src/scan/calibration/<batch>.entries.ts` + one
spread in `calibration.ts`); Semgrep rules are modular (`src/scan/rules/semgrep/<batch>.yml`).
Each batch validates against the calibration target via `pnpm validate:calibration` (live) +
`pnpm verify` (offline). Batches can't fully parallelize — they share the `CORPUS` spread line
and `GROUND-TRUTH.md`; the supervisor resolves those additive merges serially.

**Done (merged) — all mechanical batches:** #71 B1 secrets, B3 injection, B4 XSS, B5 headers/CORS,
B6 crypto, B7 auth, B8 Supabase-connected (+ B2 CVE/supply-chain via #65/#66) · #72 M10 PII,
M4+M5 dup/dead-code, M8 mutation, M7 perf-advisors. **Corpus: 99 positives + 62 negatives (161
entries), 49 Semgrep rules; gate 72/72 static positives (24 high/free-count, 15 connected N/A) /
47/47 negatives — PASS.**
**In flight:** #72 M3 hotspots — `vitals` confirmed not runnable in this environment and its
`--json` schema is undocumented, so this landed as design + fixture, not a live gate:
`src/hotspot-scan.ts` (adapter, ASSUMED schema) + `src/hotspot-scan.test.ts` (Layer-1 top-K
ordering + boolean-fact gate, `pnpm verify`-green) + `src/scan/calibration/m3.entries.ts`
(boolean sub-signals only, never the rank — a rank isn't a precision measure). Live vitals
schema capture + git-history fixture + `pnpm validate:hotspots` tracked in **#94**.
**Deferred:** #72 M6 simplification (LLM rubric, paid-only — a design note, not a gate).

## Owed: connected-tier live confirmation pass (supervisor, needs Docker)
Once B8/M7 merge, do one live pass: `colima start` → `supabase start -x vector,analytics` +
`supabase db reset` in `targets/calibration` → run the config + perf advisors against it and
confirm the B8/M7 connected fixtures trip the advisors. (The earlier live run already confirmed
`rls_disabled_in_public` catches calibration bug #3.)

## Locked product decisions (memory: `product-shape-decisions.md`)
Free count/grade = high-precision findings only + an M3 descriptive hotspot map. Review/connected
tier scanned but asserted only in the paid report after verification. M6 paid-only. Gate discipline
(#61): no rule ships/counts unless it catches its positive AND clears its benign negative.

## Operator / manual action items (not agent-executable)
- **Vercel 404:** set the `harvey` project Root Directory to `intake-site` + add `RESEND_API_KEY`
  (fixes the onboarding-page 404 AND `/api/intake`). The page currently serves at `/intake-site/`.
- **#70 GitGuardian:** dashboard ignore for `targets/calibration/` (fixture fake secrets; the App
  ignores the committed `.gitguardian.yaml`; not a required check, never blocks merges).

## Open agent-doable follow-ups
- **#86** calibration gate matcher includes the env-dependent absolute checkout path — normalize
  `location` to repo-relative before matching (sonnet).
- **#76** epic-builder web UI (opus; design doc first) — closes the "onboarding site has no link to
  the epic tool" gap.
- **#73** OSV dedup (`next@14.2.35` double-matches a curated CVE). **#54** splinter local advisor
  wiring (needs live DB). **#53** LLM `/threat-model`→`/vuln-scan`→`/triage` (needs reference-harness).

## Deferred / not agent-executable
#4 Tier-2 (gated on demand). #10–13 business/legal/GTM. #2 epic. #14 ATC folder removal (atc repo).

## Resuming live validation (Docker currently DOWN — colima stopped)
`colima start` → `supabase start -x vector,analytics` (vector fails on colima's docker.sock) +
`supabase db reset` in `targets/calibration`. Seeded password logins fail (gotrue) → mint persona
JWTs from `JWT_SECRET`. Scanner binaries (`semgrep`/`gitleaks`/`trufflehog`/`osv-scanner`) installed;
no Docker needed for static/mechanical validation, only the pen-test + Supabase-advisor tiers.
Live results recorded in `docs/runbooks/dry-run-calibration.md` §8.
