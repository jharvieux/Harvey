# Design docs

| Doc | Covers | Issue |
|---|---|---|
| [architecture.md](architecture.md) | Runtime/deployment phases (CLI → CI → hosted), components, storage split, parallelism, confidentiality invariants | #19 |
| [model-routing.md](model-routing.md) | Cost-tiered LLM strategy: bulk/standard/flagship tiers, current pricing landscape, privacy/ZDR analysis, per-workload routing + escalation | #19 |
| [story-standards.md](story-standards.md) | Researched standards for epics/stories/AC/test derivation + tracker field mapping; justifies `docs/templates/` | #20 |
| [epic-builder.md](epic-builder.md) | AI-assisted epic & user-story builder: state machine, review loop, story fan-out, publishing | #21 |
| [fix-implementation.md](fix-implementation.md) | Fix pipeline for scan findings in client repos: verification contract, safety rails, worktree parallelism | #23 |

| [scan-coverage-gaps.md](scan-coverage-gaps.md) | Failure modes in vibe-coded Next.js+Supabase apps our modules miss; ~30/37 mechanical (secrets, CVEs, Supabase config, supply chain) | #5, mechanical-checks |
| [mechanical-toolchain.md](mechanical-toolchain.md) | Low-FP mechanical scanner toolchain (Semgrep OSS core, TruffleHog, OSV, Supabase Advisors); SonarQube CE tuning + why it stays out of the free count | quick-scan |
| [quick-scan-tier.md](quick-scan-tier.md) | Freemium model (decided): free **diagnosis** (finding + location + why-it-matters), gated **remediation** (the fix) + deep dynamic/semantic scan | quick-scan (#27) |
| [exploratory-pentest.md](exploratory-pentest.md) | Exploratory dynamic pen testing beyond verify-only: local two-tenant harness, PostgREST/Server-Action/storage probe checklist, safety rails | #5 |
| [m6-simplification-eval.md](m6-simplification-eval.md) | M6 rubric: what counts as a simplification/reuse opportunity, LLM rubric-agreement eval (not a precision gate), why M6 is paid-only | #72 |

Tracker adapter implementation details live in the interface sketches of `epic-builder.md` §8 (issue #22).
