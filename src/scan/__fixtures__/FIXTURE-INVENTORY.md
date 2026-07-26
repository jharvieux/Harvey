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
| 5 | `src/__fixtures__/lighthouse-report.json` | Lighthouse 13.x | **HAND-WRITTEN** | No `_note`/provenance. 5 audits with round synthetic values (`performance.score` 0.42, FCP 2100, LCP 4800, TBT 720, CLS 0.24, SI 5200). A real LHR is hundreds of audits / ~0.5–1 MB. This is the **primary** `LighthouseResult` fixture and has **no live backstop** (Lighthouse runs in no `pnpm verify`/CI gate). #1063 shape; its own two siblings (rows 3–4) are captured, so it is an inconsistency as much as a defect. |
| 6 | `src/__fixtures__/vitals-report.json` | `vitals` 0.2.0 (python) | **HAND-WRITTEN** | Self-declared: `"_note": "Synthetic vitals 0.2.0 report fixture, shaped to the REAL schema captured live for issue #94 … Paths and values below are synthetic"`. Field names/nesting shaped from a #94 capture; values invented. `vitals` is a python tool, not a repo dependency, and runs in no automated gate — **no live backstop**. |

## B. Inline literals feeding parse functions ("inline literals count")

| # | Tool / pinned version | Location | Status | Live backstop |
|---|----------------------|----------|--------|---------------|
| 7 | semgrep | `src/scan/semgrep.test.ts` — `SemgrepOutput` literals fed to `parseSemgrepFindings` | **HAND-WRITTEN** | YES — real `semgrep` runs in `validate-calibration` / the dry-run harness against `targets/calibration`. |
| 8 | TruffleHog 3.x (comments cite 3.96.0) | `src/scan/secrets.test.ts` — `TruffleHogResult[]` fed to `parseTruffleHogFindings` | **HAND-WRITTEN** | PARTIAL — dry-run runs real `trufflehog`, but the **verified-secret** path (`Verified:true`) needs live providers, so the verified branch has no offline backstop. Field shapes were MEASURED against trufflehog 3.96.0/v3 per code comments (#1078/#1099). |
| 9 | gitleaks | `src/scan/secrets.test.ts` + `src/scan/calibration.test.ts` — `GitleaksResult[]` fed to `parseGitleaksFindings` | **HAND-WRITTEN** (calibration corpora self-describe as "recorded gitleaks output mirroring the live `pnpm validate:calibration` run") | YES — real `gitleaks` runs in `validate-calibration` / dry-run. |
| 10 | TruffleHog (git-history) | `src/scan/git-history-secret-gate.test.ts` — `TruffleHogGitResult[]` fed to `scoreGitHistoryResults` | **HAND-WRITTEN** ("pure scoring against recorded trufflehog output") | PARTIAL — as row 8. |
| 11 | jscpd 4.0.5 | `src/quality-scan.test.ts` — `JscpdReport` literal fed to `jscpdToFindings` | **TRANSCRIBED-FROM-RUN** ("shaped from real `jscpd --reporters json` output, captured against a throwaway two-file clone") | ON-DEMAND only — real jscpd runs via `check:duplication` / an M4 audit, neither in `pnpm verify`/CI. |
| 12 | knip 5.61.0 | `src/quality-scan.test.ts` — `KnipReport` literals fed to `knipToFindings` | **HAND-WRITTEN** | YES — `pnpm knip` runs inside `pnpm verify` (against Harvey's own repo, not the fixture). |
| 13 | Stryker 9.6.1 | `src/mutation-scan.test.ts` — `report` (schemaVersion "1") is **HAND-WRITTEN** ("not captured from a live Stryker run … deferred"); `m8Report` + the vacuous-run report are **TRANSCRIBED-FROM-RUN** ("REAL Stryker 9.6.1 JSON capture, trimmed" — inline, rebuilt via the `mutant()` helper that injects defaults) | mixed (see cell) | NONE automated — mutation testing runs in no `pnpm verify`/CI gate. |
| 14 | PostgREST / GoTrue HTTP responses | ~20 `src/pentest/*.test.ts`, `src/dynamic-validate.test.ts`, `src/scan/supabase*.test.ts` — inline response-body/error literals | **HAND-WRITTEN** | LIVE-STACK only — real responses come from the M2 two-tenant stack, which is not a CI gate. Large class; not individually enumerated here. |

## What this inventory concludes

- **2 of the 6 standalone files and 0 of the inline-literal classes are HAND-WRITTEN with NO live
  backstop**: `lighthouse-report.json` (#5) and `vitals-report.json` (#6). These are the exact
  #1063 shape and the highest-risk rows.
- The inline-literal fixtures for semgrep/gitleaks/knip DO have a live real-binary backstop (a schema
  drift would fail a gate elsewhere), which lowers — but does not erase — their risk: the literal
  itself can still encode a field the tool never emits, it just can't leave the tool *entirely* dead.
- TruffleHog's verified-secret path, jscpd, Stryker and the PostgREST class have **no automated live
  backstop**; their only tie to reality is a comment or a manual/live-stack run.

## Re-capture status (criterion 2) and what remains

Re-captured in the PR that added this file: **none of the code fixtures were re-captured here** — the
two highest-risk rows cannot be captured in the sweep-executor environment (row 5 needs headless
Chrome + a served page; row 6 needs the `vitals` python tool, which is not installed and is not a
repo dependency), and the inline-literal rows (7–14) require restructuring their unit tests to
consume committed artifacts, which is a per-tool change too large for one reviewable PR. The osv
capture (row 1) was re-verified (version + CVSS-vector-string schema) and found non-drifted.

The remaining re-capture work (criterion 2) and the periodic schema-drift check (criterion 3) are
tracked as the #1130 remainder issue. osv-scanner is the natural first tool for the drift check: it
is fully offline-capturable and version-pinned, so a re-run-and-diff against row 1 needs no live
service.
