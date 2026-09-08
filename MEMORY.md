# MEMORY.md — Harvey decision log

Durable record of significant, user-approved project decisions. Newest entries stay
on top; prior entries are immutable history. Read `MEMORY-INDEX.md` at session start
and search this file only when a relevant index line points here.

---

## D-001 — 2026-09-07 — Add project-owned durable decision memory

**Decision.** Harvey keeps significant project decisions in this checked-in, prepend-only log. `MEMORY-INDEX.md` is the lean session-start view, `MEMORY-INDEX-ARCHIVE.md` holds older searchable one-liners, and `SESSION.md` remains transient handoff state. The primary supervisor is the sole writer; delegated executors return proposals.

**Why.**
- Durable decisions need to survive compaction, task boundaries, and replacement of transient session state without relying on any one client's private recall.
- A bounded startup index preserves relevant context without loading an ever-growing log, while the archive and full entries remain available on demand.
- Immutable entries, exact index mirroring, branch-base collision detection, and a narrow edit hook make silent rewrites and concurrent identifier reuse fail loud.

**Rejected.**
- *Use `SESSION.md` as the decision history.* It is intentionally overwritten and records current execution state, not lasting rationale.
- *Load the complete log at every session start.* Its cost grows without bound and makes old context compete with the current request.
- *Reconstruct decisions made before this system existed.* That would turn inference into false history; this log begins only with the approved decision to create it.

**Related artifacts.** `AGENTS.md`, `MEMORY-INDEX.md`, `MEMORY-INDEX-ARCHIVE.md`, `.agents/skills/memory-entry/SKILL.md`, `src/memory-validation.ts`, `src/cli/validate-memory.ts`, `tools/memory-apply-patch-guard.mjs`, `.codex/hooks.json`.

---
