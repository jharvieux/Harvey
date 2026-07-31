# Runbooks

Ported verbatim from `jharvieux/atc` (`docs/runbooks/`) on 2026-07-01. They reference ATC's tooling (`pnpm check:*`, `slop-check`, agents) — those gates live in ATC, not here. In this repo they serve as **reference material for the audit modules**:

- `slop-detection.md` — the three-layer slop-detection approach. Methodology behind M5 (slop/dead code).
- `pr-self-review.md` — self-review procedure; feeds M6 (simplification/reuse) recommendations.
- `flaky-test-policy.md` — flaky-test policy; reference for M8 (test quality) recommendations.

The fourth ported runbook, the **D-091 catalog** of 20 recurring bug classes, moved to `briefs/anti-patterns.md`
in #994 — it is the source taxonomy for M1 findings and for the `briefs/scan-extras.txt` brief, and the scanners
read it at runtime, so it lives with the other functional briefs rather than here.

## Written in this repo

Six more runbooks are Harvey's own, and this index used to omit all of them — which made the three
ported ones look like the whole directory:

- `full-engagement-run.md` — the correct end-to-end sequence for a real ten-module engagement.
- `engagement-access.md` — operator checklist for what to request from a client at kickoff, and teardown.
- `connected-access-hardening.md` — DRAFT: least-privilege, revocable, auditable read-only DB access for a paid connected-tier engagement.
- `m2-pentest-ops.md` — operational guide for the M2 probe kit (`src/pentest/`, `src/cli/pentest.ts`).
- `dry-run-calibration.md` — the 2026-07-08 dry-run report against `targets/calibration` (#34).
- `false-decline-audit.md` — how to audit this repo for false declines (#1548): the populations with the
  commands that measure them, the zero-population finding for PR reviews, why a naive vocabulary grep
  over-counts, and the unaudited remainder.
