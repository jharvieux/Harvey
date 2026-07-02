# Epic / User-Story Standards — Research Digest

Status: v1 (researched 2026-07-01) · Issue: #20
Feeds: `docs/design/epic-builder.md` (#21), `docs/templates/` (the three templates this digest justifies).

## 1. Story/epic quality standards

### INVEST

Bill Wake's INVEST mnemonic (2003) remains the canonical quality bar for user stories: **I**ndependent (schedulable in any order, minimal coupling), **N**egotiable (a placeholder for conversation, not a contract), **V**aluable (delivers observable value to a user/customer, vertical slice not horizontal layer), **E**stimable (understood well enough to size), **S**mall (completable within a small fraction of an iteration), **T**estable (has a falsifiable done-check). Wake has said Estimable is the most-abused letter — teams over-rotate on estimation instead of value ([Agile Alliance](https://agilealliance.org/glossary/invest/), [Wikipedia](https://en.wikipedia.org/wiki/INVEST_(mnemonic)), [xp123.com](https://xp123.com/articles/invest-in-good-stories-and-smart-tasks/)).

**Builder implication:** run every AI-drafted story through an INVEST lint pass before showing it to the user; flag violations (e.g. "this story is a horizontal layer — no user-visible value") as inline comments the user can accept or dismiss.

### Epic composition

An epic is a large body of work spanning multiple sprints/teams that decomposes into stories ([Atlassian: Agile epics](https://www.atlassian.com/agile/project-management/epics), [Epics, stories, themes](https://www.atlassian.com/agile/project-management/epics-stories-themes)). A well-formed epic document contains:

- **Goal / problem statement** — why this exists, tied to a user or business outcome.
- **Scope** — the capabilities in play, expressed as candidate story areas.
- **Out-of-scope** — explicit exclusions; scope *change* within an epic is normal, so the out-of-scope list is what keeps drift honest.
- **Success metrics** — measurable outcomes (adoption, conversion, latency, error rate), not output ("shipped 12 stories").
- **Definition of done for the epic** ([Atlassian epics tutorial](https://www.atlassian.com/agile/tutorials/epics)).
- Commonly added: stakeholders/personas, dependencies/assumptions, risks, first-cut story map.

If an epic can't articulate a success metric, it's a theme, not an epic.

### Story-splitting heuristics

**SPIDR** (Mike Cohn) is the most teachable compact model ([Mountain Goat Software](https://www.mountaingoatsoftware.com/blog/five-simple-but-powerful-ways-to-split-user-stories)):

| Letter | Split by | Example |
|---|---|---|
| **S**pike | Extract a research/timeboxed investigation story | "Investigate payment-provider webhooks" |
| **P**aths | Split by user paths through the feature | Pay by card first; Apple Pay later |
| **I**nterfaces | Split by browser/device/API surface | Chrome-only first iteration |
| **D**ata | Restrict the data supported initially | No negative balances in v1 |
| **R**ules | Relax business rules initially | Skip fraud rules in v1 |

The main alternative is **Richard Lawrence / Humanizing Work's story-splitting patterns** — a flowchart of ~9 patterns (workflow steps, business-rule variations, operations/CRUD, data variations, interface variations, major effort, simple/complex core, defer performance, break out a spike) ([Humanizing Work guide](https://www.humanizingwork.com/the-humanizing-work-guide-to-splitting-user-stories/)). Hybrid for the builder: SPIDR as the primary decision menu, Lawrence's patterns as fallback for workflow-heavy stories.

### Sizing discipline

- Cohn's rule of thumb: split until roughly **6–10 stories fit in a sprint**.
- A story with 15+ acceptance criteria is an epic in disguise.
- Builder behavior: warn when a drafted story exceeds ~7 AC or contains multiple user paths, and auto-suggest a SPIDR split.

## 2. Acceptance criteria

### Two dominant formats

**Scenario-oriented (Gherkin / Given-When-Then)** — each criterion is a concrete scenario. Best when behavior varies by state/context, flows have meaningful pre/post conditions, or the team automates AC directly. Cucumber's guidance: write **declaratively** ("what, not how") — if the wording would change when the implementation changes, rework it; keep scenarios under ~10 steps, one behavior per scenario ([Writing better Gherkin](https://cucumber.io/docs/bdd/better-gherkin/), [anti-patterns](https://cucumber.io/docs/guides/anti-patterns/), [Automation Panda](https://automationpanda.com/2017/01/30/bdd-101-writing-good-gherkin/)).

**Rule-oriented / checklist** — bulleted verifiable statements ("Password must be ≥ 12 characters"). Best for constraints, validations, non-functional requirements, simple CRUD ([AltexSoft](https://www.altexsoft.com/blog/acceptance-criteria-purposes-formats-and-best-practices/)).

The synthesis the templates use (per [Marcano](https://antonymarcano.com/blog/2011/10/scenario-oriented-vs-rules-oriented-acceptance-criteria/)): **rules are the criteria; scenarios are the examples of those rules** — rules-oriented AC in the story, Gherkin scenarios derived from each rule as the test layer. This maps directly onto Example Mapping (§4).

### AC anti-patterns to lint for

- **Missing AC entirely** — un-verifiable stories cause mid-sprint clarification churn ([Age-of-Product](https://age-of-product.com/28-product-backlog-anti-patterns/)).
- **Vague/untestable** — "should be intuitive", "should be fast" without thresholds.
- **Implementation-coupled** — AC naming buttons, endpoints, or table columns instead of behavior.
- **DoD leakage** — "code reviewed", "unit tests pass" are Definition of Done items, not AC.
- **Missing negative paths/edge cases** — failures, empty states, permission denied, timeouts are the most commonly forgotten criteria.
- **Conjunction criteria** — one AC bundling several behaviors ("and also…").

### Healthy count

Sources cluster on **3–7 AC per story** (most commonly 3–5); fewer than 3 usually means underspecified, more than 7 signals a split, 15+ means it's an epic. Builder: target 3–7, hard-warn above 8.

## 3. Definition of Ready / Definition of Done

**DoD** is an official Scrum commitment attached to the Increment: a shared quality checklist applying to *every* item — code merged, standards met, reviewed, tests written and passing, AC verified, docs updated, deployed to a target environment ([Scrum.org: DoD vs DoR](https://www.scrum.org/resources/blog/what-difference-between-definition-done-dod-and-definition-ready-dor)).

**DoR** is a team convention (not Scrum Guide) describing when an item can enter a sprint: clear description, AC defined, estimated, dependencies identified, small enough, testable. Many teams literally use INVEST as their DoR ([Atlassian](https://www.atlassian.com/agile/project-management/definition-of-ready), [Scrum.org](https://www.scrum.org/resources/blog/ready-or-not-demystifying-definition-ready-scrum)). Caveat: a rigid DoR becomes a stage-gate that reintroduces waterfall handoffs — treat it as a desirable state, not a contract ([Scrum.org](https://www.scrum.org/resources/blog/walking-through-definition-ready)).

**Builder implication:** the AI review loop *is* a DoR machine. Encode DoR as the exit checklist of the story-drafting stage (all AC testable, sized, dependencies listed); put DoD in team configuration — never generate DoD items into per-story AC.

## 4. Deriving tests from AC (ATDD/BDD)

ATDD/BDD/Specification-by-Example: acceptance tests are written from AC *before* implementation and become both the requirement and its verification ([Agile Alliance](https://agilealliance.org/glossary/atdd/), [Wikipedia](https://en.wikipedia.org/wiki/Specification_by_example), [LogRocket](https://blog.logrocket.com/product-management/acceptance-test-driven-development/)). Cycle: **Discuss → Distill → Develop → Demo**.

**Mapping AC → test cases:** use **Example Mapping** ([Cucumber](https://cucumber.io/blog/bdd/example-mapping-introduction/)): story → rules (the rule-style AC) → examples per rule (concrete Given-When-Then) → questions (unknowns that block readiness). Each rule yields at minimum one happy-path example, one negative example, and boundary examples where the rule has thresholds. Each example becomes one named test case. (LLMs doing the AC→Gherkin step is itself benchmarked: [arXiv 2403.14965](https://arxiv.org/pdf/2403.14965).)

**In the story** (the "Tests to Build" section): test names and intent (behavior-level, declarative — stable against refactors); the AC each test verifies (traceability both ways); the edge cases and negative paths the team agreed matter; test level only where it's a genuine requirement.

**Left to implementation:** framework, file layout, fixtures, mocking strategy, selectors, assertion mechanics, unit-test decomposition below the behavior level, exact step definitions.

## 5. AI-implementable instruction briefs

Two converging practice streams:

- **Spec-driven development (GitHub Spec Kit)**: Constitution → Specify → Plan → Tasks → Implement; tasks carry numbered IDs, dependency order, parallelizable markers, and **exact file paths per task**; test tasks precede implementation tasks ([github/spec-kit](https://github.com/github/spec-kit), [GitHub Blog](https://github.blog/ai-and-ml/generative-ai/spec-driven-development-with-ai-get-started-with-a-new-open-source-toolkit/)).
- **Context files (AGENTS.md and kin)**: persistent repo-level agent context — build/test commands, architecture, explicit prohibitions; highest-value content is functional (commands in backticks, prohibitions), best practice ≤~150 lines with links out ([agents.md](https://agents.md/), [arXiv: Agent READMEs](https://arxiv.org/pdf/2511.12884), [arXiv: Context Engineering in OSS](https://arxiv.org/html/2510.21413v4)).

**Division of labor:** the repo's AGENTS.md/CLAUDE.md carries durable context; the **per-story brief** carries task-specific context. A brief an agent can execute cold needs: objective · context · file pointers (exact paths, including read-only pattern examples) · constraints · non-goals · implementation outline (tests first, dependency/parallel notes) · verification steps (exact runnable commands + per-AC behavioral checks) · task definition of done · escalate-don't-guess list. This is the structure of `docs/templates/implementation-brief.md`.

## 6. Tracker field mapping

### Jira Cloud (REST v3)

- Epic/Story native; the legacy `Epic Link`/`Parent Link` fields are deprecated — use the **`parent` field** uniformly ([deprecation notice](https://community.developer.atlassian.com/t/deprecation-of-the-epic-link-parent-link-and-other-related-fields-in-rest-apis-and-webhooks/54048)).
- Create: `POST /rest/api/3/issue` (bulk up to 50). Story points = site-specific custom field (discover via `GET /rest/api/3/field`) ([API docs](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/)).
- Body format: **ADF JSON** (not markdown) — convert generated markdown → ADF ([ADF structure](https://developer.atlassian.com/cloud/jira/platform/apis/document/structure/)).
- Attachments: two-step — create issue, then `POST .../attachments` as multipart with `X-Atlassian-Token: no-check` ([attachments API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-attachments/)). The md brief attaches natively.

### GitHub

- `POST /repos/{owner}/{repo}/issues` — body is GitHub-flavored markdown; org-level **issue types** ("Epic") supported via `type` since March 2025 ([changelog](https://github.blog/changelog/2025-03-18-github-issues-projects-rest-api-support-for-issue-types/)).
- Hierarchy: **sub-issues REST API** (`POST .../issues/{n}/sub_issues`); limits 100 sub-issues/parent, 8 levels ([docs](https://docs.github.com/en/rest/issues/sub-issues)).
- Projects v2: estimate/status/iteration live on project fields (REST since Sept 2025) ([changelog](https://github.blog/changelog/2025-09-11-a-rest-api-for-github-projects-sub-issues-improvements-and-more/)).
- **No attachment upload via API** ([discussion](https://github.com/orgs/community/discussions/46951)). Workarounds in preference order: inline the brief in the body under `<details>`; commit the brief to the repo (`docs/briefs/…`) and link; gist.

### Azure DevOps

- Work item types depend on the project's process (Agile → User Story; Scrum → PBI) — read the process or make the type configurable ([docs](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/guidance/choose-process)).
- Create: `POST .../_apis/wit/workitems/$User Story?api-version=7.1`, `application/json-patch+json`; `System.Description` is **HTML**; AC has a **dedicated field** `Microsoft.VSTS.Common.AcceptanceCriteria` — map AC there, not into description ([create API](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create?view=azure-devops-rest-7.1)).
- Hierarchy: `System.LinkTypes.Hierarchy-Reverse` relation to the parent.
- Attachments: `POST /_apis/wit/attachments` (octet-stream) → PATCH work item with `AttachedFile` relation ([attachments API](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/attachments/create?view=azure-devops-rest-7.1)). Native md attachment works.

### Cross-tracker mapping summary

| Template field | Jira Cloud | GitHub | Azure DevOps |
|---|---|---|---|
| Title | `summary` | `title` | `System.Title` |
| Body | `description` (ADF) | `body` (markdown) | `System.Description` (HTML) |
| Type | `issuetype` (Epic/Story) | `type` (org issue type) | URL path type (Epic/User Story/PBI) |
| Parent link | `parent.key` | sub-issues API | `Hierarchy-Reverse` relation |
| AC | in description (ADF) | in body (markdown) | `Microsoft.VSTS.Common.AcceptanceCriteria` |
| Labels/tags | `labels` | `labels` | `System.Tags` |
| Estimate | story-points custom field | Projects v2 field | `Microsoft.VSTS.Scheduling.StoryPoints` |
| Priority | `priority` | label or project field | `Microsoft.VSTS.Common.Priority` |
| Brief attachment | native attachments API | body inline / repo commit | `AttachedFile` relation |

## 7. Templates

The ready-to-use templates live at `docs/templates/epic.md`, `docs/templates/user-story.md`, and `docs/templates/implementation-brief.md`. Each has YAML frontmatter carrying the tracker-mappable fields from the table above; the builder (#21) treats the `##` headings as its section schema.
