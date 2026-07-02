---
# epic.md — tracker-mappable epic template
artifact: epic
title: ""                     # → Jira summary / GitHub title / ADO System.Title
tracker:
  jira:    { project: "", issuetype: "Epic" }
  github:  { repo: "", issue_type: "Epic", project_number: null }
  azdo:    { project: "", work_item_type: "Epic", area_path: "", iteration_path: "" }
labels: []                    # → labels / System.Tags
priority: ""                  # e.g. High
owner: ""                     # → assignee
target_release: ""            # → fixVersion / milestone / iteration
status: draft                 # draft | in-review | approved | created-in-tracker
child_stories: []             # story ids, filled as stories are drafted
---

# Epic: {title}

## Goal
One or two sentences: the user/business problem and the outcome this epic delivers.

## Background & Context
Why now. Links to discovery, data, or the originating prompt/conversation.

## In Scope
- Capability area 1 (candidate stories: ...)
- Capability area 2

## Out of Scope
- Explicit exclusion 1 — and why
- Explicit exclusion 2

## Success Metrics
| Metric | Baseline | Target | How measured |
|---|---|---|---|
|  |  |  |  |

## Stakeholders & Personas
- Persona / stakeholder — interest

## Dependencies, Assumptions, Risks
- Dependency: ...
- Assumption: ...
- Risk: ... (mitigation: ...)

## Epic Definition of Done
- [ ] All child stories done per team DoD
- [ ] Success metrics instrumented and reported
- [ ] Docs/rollout/comms complete

## Open Questions
- [ ] Question — owner — needed by
