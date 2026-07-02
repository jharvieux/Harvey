---
# implementation-brief.md — AI-agent task brief (attached to the story)
artifact: implementation-brief
story: ""                     # story id/key this brief implements
title: ""
repo: ""                      # target repository
branch_hint: ""               # e.g. feat/story-123-export-csv
delivery:                     # how the brief reaches the tracker
  jira: attachment            # POST /rest/api/3/issue/{key}/attachments
  github: body-inline-or-repo # no REST attachment upload; inline or commit to docs/briefs/
  azdo: attached-file         # /_apis/wit/attachments + AttachedFile relation
version: 1
---

# Implementation Brief: {title}

## Objective
One paragraph: the behavior change to deliver and who it serves. Link: {story URL}.

## Context
- Current behavior: ...
- Why it changes: ...
- Domain rules that must hold: ...
- Related specs/designs: {links}
- Repo conventions: see AGENTS.md / CLAUDE.md (do not duplicate here).

## File Pointers
| Path | Role |
|---|---|
| `src/...` | entry point — modify |
| `src/...` | pattern to imitate — read only |
| `tests/...` | add tests here |

## Constraints
- Preserve: {public API contracts, DB schema, feature flags}
- Use: {required libs/patterns}; do not add new dependencies without flagging.
- Budgets: {perf/security/accessibility thresholds from AC}

## Non-Goals (do not build/touch)
- {explicitly deferred behavior}
- {files/modules that must not change}

## Implementation Outline
1. [T1] Write failing tests from "Tests to Build" (paths above).
2. [T2] {step — exact file(s)}          (depends on T1)
3. [T3] {step} [P]                       (parallel-safe: different files)

## Verification
Run, in order; all must pass before completion:
```bash
{build command}
{lint command}
{test command — full suite}
{test command — the new tests specifically}
```
Then verify each AC behaviorally:
- AC1: {exact check / command / URL + expected observation}
- AC2: ...

## Task Definition of Done
- [ ] All listed tests exist and pass; no unrelated tests broken
- [ ] Every AC verified as above
- [ ] No changes outside File Pointers scope without explanation
- [ ] Verification command output included in the PR/summary

## Escalate — Do Not Guess
- {ambiguity that requires a human decision}
