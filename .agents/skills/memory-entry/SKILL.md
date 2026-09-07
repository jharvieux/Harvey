---
name: memory-entry
description: Record a significant, user-approved Harvey project decision in the checked-in durable log. Use when the user asks to remember or log a lasting project decision, or explicitly approves recording one; do not use for transient progress, proposals, or paused-workflow state.
---

# Record a durable decision

`MEMORY.md` is immutable history, not a work log. Record only a settled decision whose
rationale will matter in future tasks. A feature completion, status update, tentative
idea, scanner result, or executor conclusion belongs in its ordinary artifact or
`SESSION.md`, not here. Never infer approval to record a decision from implementation
work alone.

Only the primary supervisor writes `MEMORY.md` or either index. A delegated executor
returns a `memory_entry_proposal` with `title`, `decision`, `why`, `rejected`, and
`related_artifacts`; it does not reserve a number or edit the files.

## Before writing

1. Search both indexes for the subject. Read only matching full entries from
   `MEMORY.md`. If the decision duplicates, changes, or supersedes an entry, preserve
   the old entry and make the relationship explicit in the new one.
2. Synchronize with the target base through the task's normal Git workflow. Read the
   newest local header and the target base's newest header; use the next unclaimed
   `D-NNN` number. Concurrent branches can still collide, so the validator remains the
   authority.
3. Confirm the decision is user-approved and gather a title of at most 70 characters,
   the decision, its reasons, rejected alternatives, and concrete related artifacts.

Use today's real `YYYY-MM-DD` date. Never backfill or invent a historical entry.

## Entry format

```markdown
## D-NNN — YYYY-MM-DD — Short title

**Decision.** One to three concrete sentences.

**Why.**
- Reason with provenance or the constraint that drove the choice.

**Rejected.**
- *Alternative.* Why it lost.

**Related artifacts.** `path`, PR or issue, and [[D-NNN]] links when relevant.

---
```

## Apply the change

In one `apply_patch` call, insert the complete entry after the fixed `MEMORY.md`
preamble and before the current newest entry, and insert the exact header text with
`- ` in place of `## ` as the first line under `## Entries` in
`MEMORY-INDEX.md`. New entries never go directly into the archive. Do not edit,
reformat, reorder, or delete any prior `MEMORY.md` bytes, and do not update
`SESSION.md` as a side effect.

Then run:

```bash
pnpm exec tsx src/cli/validate-memory.ts
```

If the validator reports a target-base collision, rebase first and consistently
renumber only this branch's new entry and its index line. If it reports a rewrite,
restore prior history rather than weakening the check. Report the recorded identifier
and title to the user.

Archive maintenance is separate: move an exact one-liner from
`MEMORY-INDEX.md` to `MEMORY-INDEX-ARCHIVE.md` in one patch and run the same validator.
