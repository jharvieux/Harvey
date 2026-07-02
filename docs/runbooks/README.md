# Runbooks

Ported verbatim from `jharvieux/atc` (`docs/runbooks/`) on 2026-07-01. They reference ATC's tooling (`pnpm check:*`, `slop-check`, agents) — those gates live in ATC, not here. In this repo they serve as **reference material for the audit modules**:

- `anti-patterns.md` — the D-091 catalog of 20 recurring bug classes. Source taxonomy for M1 (multi-tenant security) findings and the `scan-extras.txt` brief.
- `slop-detection.md` — the three-layer slop-detection approach. Methodology behind M5 (slop/dead code).
- `pr-self-review.md` — self-review procedure; feeds M6 (simplification/reuse) recommendations.
- `flaky-test-policy.md` — flaky-test policy; reference for M8 (test quality) recommendations.
