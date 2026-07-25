# Runbooks

Ported verbatim from `jharvieux/atc` (`docs/runbooks/`) on 2026-07-01. They reference ATC's tooling (`pnpm check:*`, `slop-check`, agents) — those gates live in ATC, not here. In this repo they serve as **reference material for the audit modules**:

- `slop-detection.md` — the three-layer slop-detection approach. Methodology behind M5 (slop/dead code).
- `pr-self-review.md` — self-review procedure; feeds M6 (simplification/reuse) recommendations.
- `flaky-test-policy.md` — flaky-test policy; reference for M8 (test quality) recommendations.

The fourth ported runbook, the **D-091 catalog** of 20 recurring bug classes, moved to `briefs/anti-patterns.md`
in #994 — it is the source taxonomy for M1 findings and for the `briefs/scan-extras.txt` brief, and the scanners
read it at runtime, so it lives with the other functional briefs rather than here.
