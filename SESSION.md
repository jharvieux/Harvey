# SESSION — where we left off (going-forward items)

Running state log (see `CLAUDE.md` → Session log). Forward-looking; overwrite stale items.

_Last updated: 2026-07-09_

## In flight
- **#71 B1 (secrets)** — building the first security-corpus batch **and** modularizing the gate
  answer key (`src/scan/calibration.ts` → per-batch entry files) so later batches fan out in
  parallel without conflicts. When it lands, launch the parallel wave below.

## Queued next (in order — #71 and #72 cannot run concurrently; they share the corpus + gate)
1. **#71 security corpus → ~100** (spec: `docs/design/spec-71-security-corpus.md`). 8 batches:
   B1 secrets (in flight) · B2 CVE/supply-chain (**already done** via #65/#66) · B3 injection ·
   B4 XSS sinks · B5 headers/CORS · B6 crypto · B7 auth heuristics · B8 Supabase connected.
   After B1's modular answer key lands, B3–B8 can run in parallel (each drops its own entry file).
2. **#72 cross-module corpus/gate (M3–M10)** (spec: `docs/design/spec-72-crossmodule-corpus.md`).
   Order: M10 → M4+M5 → M8 → M7 → M3 → M6. M7/M8/M3 need a live env. Sequence after #71.
3. **#76 epic-builder web UI** (opus; design doc first) — closes the "onboarding site has no link
   to the epic tool" gap; link from `intake-site` on completion.

## Locked product decisions (memory: `product-shape-decisions.md`)
- Free count/grade = high-precision findings only + an M3 descriptive hotspot map. Review/
  connected-tier classes are scanned but asserted only in the paid report after verification.
- M3 hotspots: descriptive map free / deeper analysis paid. M6 simplification: paid-only.
- Gate discipline (#61): no rule ships/counts unless it catches its planted positive AND clears
  its benign negative in `targets/calibration`.

## Operator / manual action items (not agent-executable)
- **Vercel 404 fix:** set the `harvey` project Root Directory to `intake-site` (Settings → Build
  & Deployment) and add `RESEND_API_KEY`. Fixes the onboarding-page 404 AND the `/api/intake`
  form endpoint. (Alternative: ask the agent to deploy `intake-site` as its own production project.)
- **#70 GitGuardian:** dashboard-side ignore for `targets/calibration/` so the fixture fake
  secrets stop failing PR checks (the App ignores the committed `.gitguardian.yaml`; not a
  required check, so it never blocks merges).

## Open agent-doable follow-ups
- **#73** OSV dedup — `next@14.2.35` now double-matches a curated CVE (sonnet).
- **#54** wire `splinter.sql` into the local Supabase advisor path (sonnet; needs live DB to validate).
- **#53** the runbook's LLM `/threat-model`→`/vuln-scan`→`/triage` pipeline is unverified (needs
  the reference-harness skills — not available in the sandbox).

## Deferred / not agent-executable
- #4 Tier-2 autonomous pipeline (gated on demand validation). #10–13 business/legal/GTM.
- #2 epic (tracker). #14 ATC folder removal (targets the atc repo).

## Resuming live validation (Docker is currently DOWN — colima stopped to free memory)
1. `colima start`, then in `targets/calibration`: `supabase start -x vector,analytics`
   (the `vector`/analytics container fails on colima's docker.sock mount) + `supabase db reset`.
2. Seeded password logins fail on this stack ("Database error querying schema", gotrue quirk) —
   mint persona JWTs from the local `JWT_SECRET` instead.
3. Scanner binaries (`semgrep`/`gitleaks`/`trufflehog`/`osv-scanner`) are installed; no Docker
   needed for the static/mechanical validation, only for the pen-test and Supabase-advisor tiers.
- Live results so far are recorded in `docs/runbooks/dry-run-calibration.md` §8.
