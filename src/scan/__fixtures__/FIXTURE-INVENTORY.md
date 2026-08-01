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
| 2 | `src/scan/__fixtures__/supabase/auth-config-response-schema-2026-07-26.json` | Supabase Management API `AuthConfigResponse` schema (vendor) | **CAPTURED** | Sibling `PROVENANCE.md` (`curl …/api/v1-json \| jq '.components.schemas.AuthConfigResponse'`, 2026-07-26). Vendor schema. The live-project body it did NOT cover is now rows 2a/2b below, and the REASON block that recorded that gap is retired (#1265/#1291, 2026-07-31). Consumer: `src/scan/supabase-config.test.ts`. |
| 2a | `src/scan/__fixtures__/supabase/config-auth-live-2026-07-31.json` | Supabase Management API, LIVE project | **CAPTURED** (#1291, 2026-07-31) | Sibling `PROVENANCE.md`: real `GET /v1/projects/{ref}/config/auth` 200 from an operator-owned project, 242 keys. Every non-empty string value redacted (32 of 242); booleans/integers/nulls verbatim, and the redaction was checked with `gitleaks detect --no-git` (no leaks) and `trufflehog filesystem` (0 records). Settles that the vendor schema is NOT faithful to the wire: 6 live-only keys, and `nimbus_oauth_email_optional` `required` in the schema but absent from the response. Consumer: `src/scan/supabase-config.test.ts`, `src/scan/supabase.test.ts`. |
| 2b | `src/scan/__fixtures__/supabase/database-query-live-2026-07-31.json` | Supabase Management API, LIVE project | **CAPTURED** (#1265, 2026-07-31) | Sibling `PROVENANCE.md`: real `POST /v1/projects/{ref}/database/query` **201** carrying this module's own `TABLES_SQL`, 15 rows. Settles the envelope `managementApiQuery<T>` had only ever ASSUMED — a bare JSON array, no wrapper, with `rlsEnabled` a real JSON boolean rather than `t`/`f`. One disclosed transform: the 15 `name` values are `table_01`…`table_15`; `schema`/`rlsEnabled` verbatim, no row added, removed or reordered. Consumer: `src/scan/supabase.test.ts`. |
| 3 | `src/__fixtures__/lighthouse-opportunity-audit.json` | Lighthouse 13.4.0 | **CAPTURED** | Inline `_note`: "REAL Lighthouse 13.4.0 capture (live run, 2026-07-25) … chrome-launcher + onlyCategories:['performance'] … Trimmed of headings/sortedBy/debugData". Provenance is inline, not a sibling `PROVENANCE.md`. Consumer: `src/lighthouse.test.ts`. |
| 4 | `src/__fixtures__/lighthouse-report-errored.json` | Lighthouse 13.4.0 | **CAPTURED** | Inline `_note`: "REAL Lighthouse 13.4.0 capture (live run, 2026-07-25) … the NO_FCP failure mode". Provenance inline. Consumer: `src/lighthouse.test.ts`. |
| 5 | `src/__fixtures__/lighthouse-report.json` | Lighthouse 13.4.0 | **CAPTURED** (#1130, 2026-07-26) | Was HAND-WRITTEN (round synthetic values, no provenance) — the primary `LighthouseResult` fixture and the highest-risk #1063 row. RE-CAPTURED: real Lighthouse 13.4.0 live run against a deliberately-poor served page (LCP 4650.9089ms, TBT 3149ms, CLS 0.5953202217614142, score 0.32 — non-round), same chrome-launcher + onlyCategories:['performance'] invocation as its two captured siblings; the bundled Playwright chromium yielded NO_FCP (#488/#556) so the system Google Chrome was used. Inline `_note` records provenance (matching siblings). Trimmed to the fields `LighthouseResult` reads; records dropped, never edited. Consumer: `src/lighthouse.test.ts`. |
| 6 | `src/__fixtures__/vitals-report.json` | `vitals` 0.2.0 (Claude Code plugin) | **CAPTURED** (#1146, 2026-07-26) | Was HAND-WRITTEN (self-declared synthetic; and it encoded values real vitals never emits — `churn_label: "MEDIUM"`, `truck_factor: 3` for a 3-equal-author file, that file listed in `knowledge_risk` at all). RE-CAPTURED from real `vitals 0.2.0 report --json` via `src/__fixtures__/vitals-recapture/seed.py`, which builds a purpose-seeded throwaway git repo + `.vitals` provenance DB whose history makes the tool emit every planted M3 corpus relationship (M3-P-HOTSPOT top-K, M3-N-CHURN-TRIVIAL out-of-top-3, `truck_factor` 1 for the sole-author file vs a multi-author file absent from `knowledge_risk`, the a↔b coupling edge, and the AI-provenance sub-signal from the seeded DB). Sibling `PROVENANCE.md` records version + command + the planted-relationship table; inline `_note` mirrors it. Every value comes from the tool; records may be dropped, never edited. Consumer: `src/hotspot-scan.test.ts` (40 assertions pass against the capture unchanged). Live backstop: `pnpm exec tsx src/cli/fixture-drift.ts --tool vitals`, run by `conservation.yml`'s drift tier (#1130/#1170) — the sentence that used to sit here ("no automated live backstop; vitals runs in no `pnpm verify`/CI gate") was already false when #1170 landed. The seed additionally asserts nothing repacked its throwaway corpus mid-build (#1703: git >= 2.54 detaches per-commit auto maintenance, which unlinks loose objects the seed and vitals are still reading). |

## B. Inline literals feeding parse functions ("inline literals count")

| # | Tool / pinned version | Location | Status | Live backstop |
|---|----------------------|----------|--------|---------------|
| 7 | semgrep 1.164.0 | `src/scan/semgrep.test.ts` — `SemgrepOutput` literals fed to `parseSemgrepFindings` | **CAPTURED** (#1156, closes #1150 row 7) — `__fixtures__/semgrep/semgrep-1.164.0-corpus.json` + `PROVENANCE.md` + `build-corpus.mjs`, real output over a purpose-built per-rule corpus; two invented shapes corrected (see below). | YES — real `semgrep` runs in `validate-calibration` / the dry-run harness against `targets/calibration`, AND (#1266) a dedicated schema-drift check (`fixture-drift.ts --tool semgrep`) re-runs `build-corpus.mjs` and asserts the fresh output still satisfies the parser's contract. |
| 8 | TruffleHog 3.96.0 | `src/scan/secrets.test.ts` — `TruffleHogResult[]` fed to `parseTruffleHogFindings` | **CAPTURED** (#1146, 2026-07-26) — the #1078 rotation/provenance test now loads `__fixtures__/trufflehog/trufflehog-3.96.0-git-unverified.json` (real `trufflehog git --no-verification --results=unverified --json` output; sibling `PROVENANCE.md`). The **verified-secret** path is a recorded REASON (verification is live-only); the grading-path tests override the single `Verified` field, disclosed at the test site. Other `parseTruffleHogFindings` literals in this file (the drop-unverified and #1099 empty-Redacted cases) remain minimal hand-built inputs exercising specific parse branches. | PARTIAL — dry-run runs real `trufflehog`; the verified branch has no offline backstop (recorded REASON, falsifier fires when a live-verified capture is committed). |
| 9 | gitleaks 8.30.1 | `src/scan/secrets.test.ts` + `src/scan/calibration.test.ts` — `GitleaksResult[]` fed to `parseGitleaksFindings` | **CAPTURED** (#1156, closes #1150 row 9) — `__fixtures__/gitleaks/gitleaks-8.30.1-corpus.json` + `PROVENANCE.md` + `build-corpus.mjs`, real output over a planted-secret corpus under Harvey's custom ruleset; the #1078 allowlist block stays defanged/synthetic by decision (see below). Calibration corpora (`calibration.test.ts`) remain separately self-describing, not this capture. | YES — real `gitleaks` runs in `validate-calibration` / dry-run, AND (#1266) a dedicated schema-drift check (`fixture-drift.ts --tool gitleaks`) re-runs `build-corpus.mjs` and asserts the fresh output still satisfies the parser's contract, including the #210 demo-key co-location. |
| 10 | TruffleHog 3.96.0 (git-history) | `src/scan/git-history-secret-gate.test.ts` — `TruffleHogGitResult[]` fed to `scoreGitHistoryResults` | **CAPTURED** (#1150) | PARTIAL — as row 8. RE-CAPTURED: `src/scan/__fixtures__/trufflehog-git-history/trufflehog-3.96.0-git-history.json` + `PROVENANCE.md` — the real one-record output of `trufflehog git --no-verification --results=unverified --json` against a `buildGitHistoryFixture`-shaped repo. The benign file's negative control is by necessity synthetic (a real run emits nothing for it); the "false positive" branch's second record stays hand-built and is labelled so. |
| 11 | jscpd 4.2.5 | `src/quality-scan.test.ts` — `JscpdReport` literal fed to `jscpdToFindings` | **CAPTURED** (#1150) | ON-DEMAND only — real jscpd runs via `check:duplication` / an M4 audit, neither in `pnpm verify`/CI. RE-CAPTURED: `src/scan/__fixtures__/jscpd/jscpd-4.2.5-report.json` + `PROVENANCE.md` — a real run against a purpose-built clone corpus engineered for exactly four clones (58L Medium / 17L Low same-file / 10L Info / 8L sub-threshold); every downstream assertion updated to the tool's real line/token counts. Version was MEASURED 4.2.5 (cell said 4.0.5). |
| 12 | knip 5.88.1 | `src/quality-scan.test.ts` — `KnipReport` literals fed to `knipToFindings` | **CAPTURED** (#1150) | YES — `pnpm knip` runs inside `pnpm verify` (against Harvey's own repo, not the fixture). RE-CAPTURED: `src/scan/__fixtures__/knip/knip-5.88.1-report.json` + `PROVENANCE.md` — real `knip --reporter json` output against a mini TS project (one dead file + one file with an unused value export and an unused type). Version was MEASURED 5.88.1 (cell said 5.61.0). The clean-file empty-record skip is now an explicitly-labelled synthetic control (real knip omits fully-used files). |
| 13 | Stryker 9.6.1 | `src/mutation-scan.test.ts` — `m8Report` + `vacuousReport` are **CAPTURED** (#1150); `report`/`untested`/`whollyUntested`/`mostlyStaticReport`/`oneFile` stay **HAND-WRITTEN** (engineered unit inputs, not re-capturable) | NONE automated — mutation testing runs in no `pnpm verify`/CI gate. RE-CAPTURED: `src/scan/__fixtures__/stryker/stryker-9.6.1-m8-calibration.json` + `stryker-9.6.1-m8-vacuous.json` + `PROVENANCE.md` — real `npx stryker run` output against `targets/calibration/test-quality/` (the "not installed" note had DECAYED — `@stryker-mutator/core@9.6.1` runs via npx against the target's own isolated dep tree). |
| 14 | PostgREST / GoTrue HTTP responses | ~20 `src/pentest/*.test.ts`, `src/dynamic-validate.test.ts`, `src/scan/supabase*.test.ts` — inline response-body/error literals | **REASON (live-only)** (#1146) — offline capture is impossible; the block is recorded below. | LIVE-STACK only — real responses come from the M2 two-tenant stack, which is not a CI gate. Large class; not individually enumerated here. |

## What this inventory concludes

- **As of #1146 (2026-07-26), BOTH standalone hand-written files are RE-CAPTURED**:
  `lighthouse-report.json` (#5, #1130, real Lighthouse 13.4.0) and `vitals-report.json` (#6, real
  vitals 0.2.0 via the `seed.py` corpus-reconstruction — see row 6). No standalone fixture file in
  section A remains HAND-WRITTEN. The remaining invariant-3 debt is entirely inline literals (§B) plus
  the live-only backstops noted below.
- semgrep (row 7) and gitleaks (row 9) are ALSO no longer inline literals at risk: both were
  RE-CAPTURED in #1156 (real tool output, same as knip/jscpd/lighthouse/vitals/Stryker) and both
  gained their own drift check in #1266, closing the gap this inventory's own line 112 wrongly
  claimed was already closed. knip/semgrep/gitleaks additionally have a live real-binary backstop
  elsewhere (`validate-calibration` / dry-run / `pnpm verify`) — belt-and-suspenders, not their only
  tie to reality.
- TruffleHog's verified-secret path, jscpd, Stryker and the PostgREST class have **no automated live
  backstop OUTSIDE their own drift check**; jscpd/Stryker's only tie to reality besides the drift
  check is an on-demand/manual run, and TruffleHog-verified/PostgREST's is a comment or the live M2
  stack (their captures don't exist at all — reason-blocked, see rows 8/14).

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
  controls are under `pnpm verify`; the binary-running CLI is not (like dry-run-drift). Its cadence
  wiring (the `osv-fixture-drift` npm-script alias + a `conservation.yml` step) landed with the OSV
  check.
- **Criterion 3 — the drift check extended to every OTHER captured tool** (`src/cli/fixture-drift.ts`
  + `src/scan/fixture-drift-contracts.ts`, negative controls in
  `src/scan/fixture-drift-contracts.test.ts`, all under `pnpm verify`). One parameterized CLI
  (`--tool <jscpd|knip|trufflehog|vitals|stryker|lighthouse|semgrep|gitleaks>`) re-runs each pinned
  tool against a reproducible seed and asserts the FRESH output still satisfies the contract the
  committed fixture and its parser depend on (the #1063 shape invariant), failing loud on a version
  or schema mismatch. The seeds: jscpd → `targets/calibration/dup` (committed; not the fixture's own
  capture corpus, which is not committed — disclosed); knip → a rebuilt throwaway mini-project
  matching row 12's provenance; trufflehog → `buildGitHistoryFixture` (covers BOTH rows 8 and 10 —
  same tool/command/repo); vitals → `seed.py` (row 6's committed re-capture seed); stryker →
  `targets/calibration/test-quality/` (npm ci + `npx stryker run`); lighthouse → a locally-served
  static page via chrome-launcher (shape check, the page's actual performance is irrelevant); semgrep
  and gitleaks (**#1266**) → each tool's own committed corpus builder
  (`__fixtures__/{semgrep,gitleaks}/build-corpus.mjs`, the exact reproducible recipe each
  PROVENANCE.md documents), re-run fresh. Each has an npm-script alias (`<tool>-fixture-drift`) and a
  `conservation.yml` step.
  **"Every CAPTURED fixture now has a drift check" was FALSE from #1170 until #1266**: PR #1165 added
  the semgrep and gitleaks corpus fixtures 24 minutes before #1170 landed this drift-check family, and
  neither was registered in `fixture-drift.ts`'s tool list — a gap this sentence asserted didn't
  exist. **It is true now**: `checkSemgrepFixtureContract`/`checkGitleaksFixtureContract` close it,
  proven live 2026-07-30 against installed semgrep 1.164.0 / gitleaks 8.30.1. The two live-only
  fixtures — trufflehog **VERIFIED** (row 8's REASON block) and **PostgREST/GoTrue** (row 14) — have
  no capture and therefore correctly get NO drift check; they are reason-blocked, not missing.
- **Row 5 (`lighthouse-report.json`) drift check** re-runs Lighthouse 13.4.0; **Row 6
  (`vitals-report.json`) drift check** re-runs the `seed.py` corpus reconstruction — both landed here,
  so the row-6 "split to the #1130 remainder" note below is superseded.

**Still open after the #1130 drift-check work above:**

- **Inline-literal rows (8, 10, 14)** — TruffleHog verified path and PostgREST need a live provider /
  the M2 two-tenant stack, so those stay a `REASON:` block where an offline capture is impossible.
  - **Landed in #1150:** rows 10 (trufflehog git-history), 11 (jscpd 4.2.5), 12 (knip 5.88.1), 13
    (Stryker 9.6.1 — the `m8Report`/`vacuousReport` pair). See their table rows above.
  - **Rows 7 (semgrep) and 9 (gitleaks) are CLOSED, not open** — this bullet used to say otherwise,
    which is the exact contradiction #1266 was filed to fix: rows 7/9 were RE-CAPTURED in #1156 (see
    "Landed (this chunk)" below) and their drift check landed in #1266 (criterion 3, above). Nothing
    remains open for either row.
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
TOUCHES: src/pentest/live-standup.ts

The PostgREST falsifier exits 0 once the M2 stack is brought up and its real responses are captured
and committed at that path, at which point the ~20 inline response literals across
`src/pentest/*.test.ts`, `src/dynamic-validate.test.ts` and `src/scan/supabase*.test.ts` can be
restructured to load the committed capture.

**Split to the #1146 chunk-3 remainder issue (each needs a purpose-built target corpus that
reproduces the specific per-branch assertions, or a tool this environment does not install):**

- **Row 7 (semgrep) — RE-CAPTURED (#1156, closes #1150 row 7).** Real `semgrep 1.164.0` output over a
  purpose-built corpus lives at `__fixtures__/semgrep/semgrep-1.164.0-corpus.json` (+ `PROVENANCE.md`,
  + reproducible `build-corpus.mjs`); `semgrep.test.ts`'s `parseSemgrepFindings` block loads it. Two
  invented shapes were CORRECTED against the real run: the old `#455` no-cwe literal put no cwe on
  `harvey-service-role-in-client`, but every harvey rule now ships cwe; the old `#976` bare-string-cwe
  literal used a fabricated `tainted-sql-string` rule — the real bare-string carrier is
  `bypass-tls-verification`. Two shapes no rule emits (no-cwe result, bare-string `references`) remain
  as labelled synthetic negative-controls (REASON in the PROVENANCE).
- **Row 9 (gitleaks 8.30.1) — RE-CAPTURED (#1156, closes #1150 row 9).** Real `gitleaks 8.30.1` output
  over a planted-secret corpus, under Harvey's custom config, lives at
  `__fixtures__/gitleaks/gitleaks-8.30.1-corpus.json` (+ `PROVENANCE.md`, + `build-corpus.mjs`);
  `secrets.test.ts`'s `parseGitleaksFindings` block loads it. The capture VERIFIED the old literals
  faithful (real RuleIDs, real `Match` values, and — load-bearing — the #210 demo co-location really
  does report both rules on one `File:StartLine`). The `#1078` allowlist block keeps DEFANGED literals
  by decision (a live-shaped key would trip push protection; decisional REASON in the PROVENANCE).
- **Row 10 (TruffleHog git-history scoring)** — `scoreGitHistoryResults` inputs are minimal scoring
  literals; one is an inherently synthetic negative-control (a benign file trufflehog would never
  flag). Its positive case could later reference the row-8 capture.
- **Row 11 (jscpd 4.2.5, MEASURED — inventory says 4.0.5)** and **Row 12 (knip 5.88.1, MEASURED —
  inventory says 5.61.0)** — the base `jscpdReport`/`knipReport` literals are engineered to hit
  specific threshold bands; a real capture is feasible but requires purpose-built clone/dead-code
  source and updating the downstream assertions to the tool's real counts.
- **Row 13 (Stryker 9.6.1)** — `@stryker-mutator/*` is NOT installed in this environment; a real
  capture requires installing it (touches `package.json`/lockfile — **NOT supervised**, operator ruling 2026-07-27) plus a mutation
  target and a ~15-min run.
