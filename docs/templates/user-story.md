---
# user-story.md — tracker-mappable story template
artifact: user-story
title: ""                     # → summary / title / System.Title
epic: ""                      # → Jira parent.key / GitHub parent issue / ADO Hierarchy-Reverse
tracker:
  jira:    { project: "", issuetype: "Story", parent_key: "" }
  github:  { repo: "", parent_issue: null, project_number: null }
  azdo:    { project: "", work_item_type: "User Story", parent_id: null }
labels: []
priority: ""
estimate: null                # story points → custom field / project field / StoryPoints
assignee: ""
status: draft                 # draft | in-review | ready | created-in-tracker
brief: ""                     # path/URL of implementation-brief.md (attached or linked)
---

# Story: {title}

**As a** {persona}, **I want** {capability}, **so that** {benefit}.

## Context
2–4 sentences: where this fits in the epic, current behavior, key domain rules.

## Acceptance Criteria
<!-- Rules-oriented; 3–7 items; each testable, behavior-level, no implementation detail.
     Negative paths and edge cases included. DoD items excluded. -->
1. **AC1 — {rule name}:** {verifiable statement, with thresholds where relevant}
2. **AC2 — {rule name}:** ...
3. **AC3 — {negative path}:** When {failure/invalid input}, the system {observable handling}.

## Tests to Build
<!-- One or more named tests per AC; names are declarative intent, not framework detail.
     Level: unit | integration | e2e — only where it is a genuine requirement. -->
| Test name (intent) | Verifies | Level | Notes / edge data |
|---|---|---|---|
| {behavior}_succeeds_for_{happy_path} | AC1 | e2e |  |
| {behavior}_rejected_when_{invalid_condition} | AC3 | integration | boundary: {values} |

### Key scenarios (Gherkin, declarative)
```gherkin
Scenario: {AC1 happy path}
  Given {precondition}
  When {action}
  Then {observable outcome}
```

## Out of Scope for This Story
- {deferred variation — link to sibling story if split via SPIDR}

## Dependencies & Open Questions
- [ ] {question} — owner
