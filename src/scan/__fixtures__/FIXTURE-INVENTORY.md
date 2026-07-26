# External-tool fixture inventory (conservation invariant 3)

Tracks issue #1130 (the fixture-integrity half of #1109). The rule, from
`docs/design/conservation-of-findings.md` §"Invariant 3": **a fixture standing in for an external
tool's output MUST be a captured artifact from a real run of the pinned version, committed with a
provenance note naming the tool version and the exact command. A hand-written one is a defect**
(the #1063/#1098/#1099 class — a fixture encoding fields the real tool never emits leaves a
detector silently dead against every real target). Records may be DROPPED from a capture; never
EDITED.

This inventory is MEASURED, not recalled: every row below was produced by opening the fixture and
comparing it to the pinned tool's real output shape (or reading its committed provenance). Dates and
tool versions are as observed **2026-07-26** in the sweep-executor environment. Re-derive it; do not
quote a row from memory.

## Scope — what counts as an "external-tool fixture"

IN scope: any fixture (standalone file OR inline literal in a `*.test.ts`) that stands in for the
**raw output of an external tool** at the parse boundary — the JSON/text Harvey's parser consumes
before it becomes a Harvey domain object.

OUT of scope, and why:

- `src/detectors/__fixtures__/**/*.txt` (~300 files) — these are detector **input** source code
  (`.ts`/`.tsx`/`package.json`/`tsconfig.json` under test), i.e. the code Harvey scans, authored
  deliberately. They are not any tool's output.
- `src/scan/__fixtures__/prisma-app/**` — a target application's own source, scan input, not output.
- `reports/atc/captures/m8-mutation-*.json` — Harvey's **own post-parse** `summary` format from a
  historical ATC engagement, not a raw external-tool report.

## Status vocabulary

- **CAPTURED** — byte-faithful (modulo dropped records / re-indentation) output of a real run of the
  pinned tool, with a provenance note (a sibling `PROVENANCE.md` or an inline `_note`) naming
  version + command. Invariant-3 compliant.
- **HAND-WRITTEN** — a literal built by hand; no real run behind it. A defect under invariant 3.
- **TRANSCRIBED-FROM-RUN** — an inline literal whose comment states it was derived from a real run,
  but which is not committed as a byte-faithful artifact (typically trimmed and rebuilt through a
  test helper that injects default fields, so it can never be re-diffed against a fresh capture).
  Better than HAND-WRITTEN, still not invariant-3 compliant — you cannot mechanically re-capture and
  diff it.

"Live backstop" = whether a real run of the pinned binary exercises this tool's parse path anywhere
in an automated gate (so a schema drift would fail loud even though the fixture is frozen).

## A. Standalone fixture files (the #1102 shape)

| # | Fixture | Tool / pinned version | Status | Evidence |
|---|---------|----------------------|--------|----------|
| 1 | `src/scan/__fixtures__/osv/osv-scanner-2.3.8-report.json` | osv-scanner 2.3.8 | **CAPTURED** | Sibling `PROVENANCE.md` (version + command + elided records). Verified 2026-07-26: local `osv-scanner --version` = 2.3.8; fixture's `severity[].score` carries CVSS **vector strings** (`CVSS:3.1/…`, `CVSS:4.0/…`), not the invented bare `"7.5"` that caused #1063. Consumer: `src/scan/dependencies.test.ts`. |
| 2 | `src/scan/__fixtures__/supabase/auth-config-response-schema-2026-07-26.json` | Supabase Management API `AuthConfigResponse` schema (vendor) | **CAPTURED** | Sibling `PROVENANCE.md` (`curl …/api/v1-json \| jq '.components.schemas.AuthConfigResponse'`, 2026-07-26). Vendor schema, not a live project body (that gap is itself a recorded REASON block in the provenance). Consumer: `src/scan/supabase-config.test.ts`. |
| 3 | `src/__fixtures__/lighthouse-opportunity-audit.json` | Lighthouse 13.4.0 | **CAPTURED** | Inline `_note`: "REAL Lighthouse 13.4.0 capture (live run, 2026-07-25) … chrome-launcher + onlyCategories:['performance'] … Trimmed of headings/sortedBy/debugData". Provenance is inline, not a sibling `PROVENANCE.md`. Consumer: `src/lighthouse.test.ts`. |
| 4 | `src/__fixtures__/lighthouse-report-errored.json` | Lighthouse 13.4.0 | **CAPTURED** | Inline `_note`: "REAL Lighthouse 13.4.0 capture (live run, 2026-07-25) … the NO_FCP failure mode". Provenance inline. Consumer: `src/lighthouse.test.ts`. |
| 5 | `src/__fixtures__/lighthouse-report.json` | Lighthouse 13.4.0 | **CAPTURED** (#1130, 2026-07-26) | Was HAND-WRITTEN (round synthetic values, no provenance) — the primary `LighthouseResult` fixture and the highest-risk #1063 row. RE-CAPTURED: real Lighthouse 13.4.0 live run against a deliberately-poor served page (LCP 4650.9089ms, TBT 3149ms, CLS 0.5953202217614142, score 0.32 — non-round), same chrome-launcher + onlyCategories:['performance'] invocation as its two captured siblings; the bundled Playwright chromium yielded NO_FCP (#488/#556) so the system Google Chrome was used. Inline `_note` records provenance (matching siblings). Trimmed to the fields `LighthouseResult` reads; records dropped, never edited. Consumer: `src/lighthouse.test.ts`. |
| 6 | `src/__fixtures__/vitals-report.json` | `vitals` 0.2.0 (Claude Code plugin) | **HAND-WRITTEN** (re-capture split to the #1130 remainder) | Self-declared synthetic; field names/nesting shaped from a #94 capture, values invented. **Correction (#1130, MEASURED 2026-07-26): the earlier "not installed" note has decayed.** `vitals` is NOT a PyPI package but the Claude Code plugin `vitals_cli.py`; version 0.2.0 (the pinned `EXPECTED_VITALS_VERSION`) IS installed at `~/.claude/plugins/cache/vitals/vitals/0.2.0/scripts/vitals_cli.py` (`vitals_cli.py version` → `Vitals v0.2.0`), and a real `report --json` run emits the full 11-key schema. The real blocker is NOT tool availability: this fixture is also the M3 **calibration corpus** plant (`m3.entries.ts`, scored via `buildCoverageMatrix` in `src/hotspot-scan.test.ts`), so a faithful re-capture must reproduce every planted entry (M3-P-HOTSPOT top-K, M3-N-CHURN-TRIVIAL not-top-K, truck_factor 1 vs 3, the a/b coupling edge) from a purpose-seeded git repo AND reproduce the AI-provenance sub-signal (M3-P-AIPROV / M3-N-AIPROV-*) from a seeded `.vitals` provenance DB — a fresh run has `provenance: {"has_data": false}` and would fail the AIPROV corpus entries. That is a corpus-reconstruction task on par with the inline-literal rows below, not a drop-in capture — split to the #1130 remainder. No automated live backstop. |

## B. Inline literals feeding parse functions ("inline literals count")

| # | Tool / pinned version | Location | Status | Live backstop |
|---|----------------------|----------|--------|---------------|
| 7 | semgrep | `src/scan/semgrep.test.ts` — `SemgrepOutput` literals fed to `parseSemgrepFindings` | **HAND-WRITTEN** | YES — real `semgrep` runs in `validate-calibration` / the dry-run harness against `targets/calibration`. |
| 8 | TruffleHog 3.96.0 | `src/scan/secrets.test.ts` — `TruffleHogResult[]` fed to `parseTruffleHogFindings` | **CAPTURED** (#1146, 2026-07-26) — the #1078 rotation/provenance test now loads `__fixtures__/trufflehog/trufflehog-3.96.0-git-unverified.json` (real `trufflehog git --no-verification --results=unverified --json` output; sibling `PROVENANCE.md`). The **verified-secret** path is a recorded REASON (verification is live-only); the grading-path tests override the single `Verified` field, disclosed at the test site. Other `parseTruffleHogFindings` literals in this file (the drop-unverified and #1099 empty-Redacted cases) remain minimal hand-built inputs exercising specific parse branches. | PARTIAL — dry-run runs real `trufflehog`; the verified branch has no offline backstop (recorded REASON, falsifier fires when a live-verified capture is committed). |
| 9 | gitleaks | `src/scan/secrets.test.ts` + `src/scan/calibration.test.ts` — `GitleaksResult[]` fed to `parseGitleaksFindings` | **HAND-WRITTEN** (calibration corpora self-describe as "recorded gitleaks output mirroring the live `pnpm validate:calibration` run") | YES — real `gitleaks` runs in `validate-calibration` / dry-run. |
| 10 | TruffleHog (git-history) | `src/scan/git-history-secret-gate.test.ts` — `TruffleHogGitResult[]` fed to `scoreGitHistoryResults` | **HAND-WRITTEN** ("pure scoring against recorded trufflehog output") | PARTIAL — as row 8. |
| 11 | jscpd 4.0.5 | `src/quality-scan.test.ts` — `JscpdReport` literal fed to `jscpdToFindings` | **TRANSCRIBED-FROM-RUN** ("shaped from real `jscpd --reporters json` output, captured against a throwaway two-file clone") | ON-DEMAND only — real jscpd runs via `check:duplication` / an M4 audit, neither in `pnpm verify`/CI. |
| 12 | knip 5.61.0 | `src/quality-scan.test.ts` — `KnipReport` literals fed to `knipToFindings` | **HAND-WRITTEN** | YES — `pnpm knip` runs inside `pnpm verify` (against Harvey's own repo, not the fixture). |
| 13 | Stryker 9.6.1 | `src/mutation-scan.test.ts` — `report` (schemaVersion "1") is **HAND-WRITTEN** ("not captured from a live Stryker run … deferred"); `m8Report` + the vacuous-run report are **TRANSCRIBED-FROM-RUN** ("REAL Stryker 9.6.1 JSON capture, trimmed" — inline, rebuilt via the `mutant()` helper that injects defaults) | mixed (see cell) | NONE automated — mutation testing runs in no `pnpm verify`/CI gate. |
| 14 | PostgREST / GoTrue HTTP responses | ~20 `src/pentest/*.test.ts`, `src/dynamic-validate.test.ts`, `src/scan/supabase*.test.ts` — inline response-body/error literals | **REASON (live-only)** (#1146) — offline capture is impossible; the block is recorded below. | LIVE-STACK only — real responses come from the M2 two-tenant stack, which is not a CI gate. Large class; not individually enumerated here. |

## What this inventory concludes

- **As of #1130 (2026-07-26), `lighthouse-report.json` (#5) is RE-CAPTURED** (real Lighthouse 13.4.0),
  leaving `vitals-report.json` (#6) as the one remaining HAND-WRITTEN standalone file with no live
  backstop — and its re-capture is blocked not by tool availability (vitals 0.2.0 IS installed) but by
  the corpus-reconstruction it requires (see row 6), so it is split to the #1130 remainder.
- The inline-literal fixtures for semgrep/gitleaks/knip DO have a live real-binary backstop (a schema
  drift would fail a gate elsewhere), which lowers — but does not erase — their risk: the literal
  itself can still encode a field the tool never emits, it just can't leave the tool *entirely* dead.
- TruffleHog's verified-secret path, jscpd, Stryker and the PostgREST class have **no automated live
  backstop**; their only tie to reality is a comment or a manual/live-stack run.

## Re-capture status (criterion 2) and the drift check (criterion 3)

**Landed in #1130:**

- **Row 5 (`lighthouse-report.json`) RE-CAPTURED** — real Lighthouse 13.4.0 run (Chrome IS launchable
  here; the prior "not available in sweep-executor env" note had decayed). `src/lighthouse.test.ts`
  updated to the real non-round values.
- **Criterion 3 — the osv-scanner schema-drift check** (`src/cli/osv-fixture-drift.ts` +
  `src/scan/osv-fixture-contract.ts`, tested with negative controls in
  `src/scan/osv-fixture-contract.test.ts`). It asserts the installed osv-scanner is the pinned 2.3.8,
  re-runs it against `targets/calibration/package-lock.json`, and checks the FRESH output still
  satisfies the schema contract the committed fixture (row 1) and `parseOsvFindings` depend on — the
  #1063 invariant that `severity[].score` is a CVSS vector string, not a bare number. A byte diff is
  not usable (osv.dev advisories churn); the check diffs the SHAPE. The contract + its negative
  controls are under `pnpm verify`; the binary-running CLI is not (like dry-run-drift), and its
  **cadence wiring (an npm-script alias + a conservation.yml / dry-run-drift step) is split to the
  #1130 remainder** because both touch operator-owned paths (`package.json`, `.github/workflows`).

**Split to the #1130 remainder:**

- **Row 6 (`vitals-report.json`)** — the tool IS installed (correction above), but a faithful
  re-capture requires reproducing the M3 calibration corpus from a seeded git repo + a seeded
  `.vitals` provenance DB (see row 6). Corpus-reconstruction scale, not a drop-in capture.
- **Inline-literal rows (7–14)** — restructuring each tool's unit tests to consume committed
  artifacts; per-tool, and some (TruffleHog verified path, PostgREST) need a live provider / the M2
  two-tenant stack, so those get a `REASON:` block where an offline capture is impossible.
- The two #1109 ledger carryovers (producerless `suppressed`/`capped`/`not-applicable` columns; a
  second ledger across `applyBaseline` #457).

## Inline-literal re-capture status (#1146, chunk 3 of the #1130 remainder)

**Landed (this chunk):**

- **Row 8 (TruffleHog, unverified path)** RE-CAPTURED — `__fixtures__/trufflehog/trufflehog-3.96.0-git-unverified.json`
  from a real `trufflehog git --no-verification --results=unverified --json` run (trufflehog 3.96.0,
  2026-07-26), sibling `PROVENANCE.md`. `src/scan/secrets.test.ts`'s #1078 test loads it.
- **Row 8 (TruffleHog, VERIFIED path)** and **Row 14 (PostgREST/GoTrue)** are recorded as live-only
  REASON blocks (the TruffleHog one in `__fixtures__/trufflehog/PROVENANCE.md`; the PostgREST one
  below), because an offline capture is genuinely impossible — not a fabricated fixture.

REASON: PostgREST / GoTrue HTTP response and error literals cannot be captured offline — a faithful response body/status requires the live M2 two-tenant Supabase stack (PostgREST + GoTrue + Postgres with the two-tenant RLS seed) issuing the real request; there is no pinned binary that emits these bodies without the running stack.
KIND: empirical
PROVENANCE: MEASURED 2026-07-26
FALSIFIER: test -f src/pentest/__fixtures__/postgrest-gotrue-live-responses.json

The PostgREST falsifier exits 0 once the M2 stack is brought up and its real responses are captured
and committed at that path, at which point the ~20 inline response literals across
`src/pentest/*.test.ts`, `src/dynamic-validate.test.ts` and `src/scan/supabase*.test.ts` can be
restructured to load the committed capture.

**Split to the #1146 chunk-3 remainder issue (each needs a purpose-built target corpus that
reproduces the specific per-branch assertions, or a tool this environment does not install):**

- **Row 7 (semgrep)** — `parseSemgrepFindings` literals span many distinct rule scenarios
  (service-role-in-client, workflow shell-injection routing, registry-rule cwe/owasp threading,
  references composition, bare-string normalization). Reproducing each from a real `semgrep` run is
  a per-rule target reconstruction, not a single drop-in capture.
- **Row 9 (gitleaks 8.30.1, MEASURED — inventory's unversioned cell)** — `parseGitleaksFindings`
  literals encode many correlation scenarios (demo-marker co-location, allowlist suppression,
  doc-context reclassification) against Harvey's *custom* gitleaks ruleset; reproducing them needs a
  planted-secret corpus run under the custom config.
- **Row 10 (TruffleHog git-history scoring)** — `scoreGitHistoryResults` inputs are minimal scoring
  literals; one is an inherently synthetic negative-control (a benign file trufflehog would never
  flag). Its positive case could later reference the row-8 capture.
- **Row 11 (jscpd 4.2.5, MEASURED — inventory says 4.0.5)** and **Row 12 (knip 5.88.1, MEASURED —
  inventory says 5.61.0)** — the base `jscpdReport`/`knipReport` literals are engineered to hit
  specific threshold bands; a real capture is feasible but requires purpose-built clone/dead-code
  source and updating the downstream assertions to the tool's real counts.
- **Row 13 (Stryker 9.6.1)** — `@stryker-mutator/*` is NOT installed in this environment; a real
  capture requires installing it (touches the supervised `package.json`/lockfile) plus a mutation
  target and a ~15-min run.
