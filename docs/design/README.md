# Design docs

| Doc | Covers | Issue |
|---|---|---|
| [architecture.md](architecture.md) | Runtime/deployment phases (CLI → CI → hosted), components, storage split, parallelism, confidentiality invariants | #19 |
| [model-routing.md](model-routing.md) | Cost-tiered LLM strategy: bulk/standard/flagship tiers, current pricing landscape, privacy/ZDR analysis, per-workload routing + escalation | #19 |
| [story-standards.md](story-standards.md) | Researched standards for epics/stories/AC/test derivation + tracker field mapping; justifies `docs/templates/` | #20 |
| [epic-builder.md](epic-builder.md) | AI-assisted epic & user-story builder: state machine, review loop, story fan-out, publishing | #21 |
| [fix-implementation.md](fix-implementation.md) | Fix pipeline for scan findings in client repos: verification contract, safety rails, worktree parallelism | #23 |

Tracker adapter implementation details live in the interface sketches of `epic-builder.md` §8 (issue #22).
