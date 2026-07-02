# Epic Builder — Design

**Status:** Draft for review · Issue: #21
**Scope:** Phase 1 — operator-run CLI, single user, local files, GitHub publish only
**Code home:** `src/epic-builder/` (TypeScript, strict; tests co-located as `*.test.ts`), CLI entry exposed as `pnpm epic` (bin wrapper)
**Depends on:** `docs/templates/epic.md`, `docs/templates/user-story.md`, `docs/templates/implementation-brief.md` (#20 — consumed here, not defined here); tracker adapters (#22); model routing (`model-routing.md`, #19)

---

## 1. Overview

The epic builder turns a one-paragraph product idea into a published, AI-implementable work breakdown:

```
prompt → clarifying Q&A → epic draft → review loop → story fan-out
       → per-story review loops → consistency pass → publish → summary
```

Every artifact is a plain Markdown file on disk. The AI never has authority to finalize anything — the human accepts each artifact explicitly, and every AI revision is shown as a diff before it touches a file. The filesystem **is** the source of truth; the session file is just a pointer into it, so the tool can crash, be Ctrl-C'd, or be resumed a week later without losing work.

---

## 2. Interaction model

### 2.1 CLI session

```bash
pnpm epic new "Customers should be able to export audit findings as CSV"
pnpm epic resume csv-export          # resume by slug
pnpm epic list                       # list workspaces + their states
pnpm epic publish csv-export         # publish (or re-run publish) explicitly
pnpm epic publish csv-export --dry-run
```

`new` derives a slug from the prompt (`csv-export`), creates the workspace dir, and enters the interactive session. The session is a single readline-style REPL; no TUI framework in phase 1 — numbered prompts and plain-text answers only. This keeps the tool debuggable and pipe-friendly, and matches the operator profile (fluent, terminal-comfortable, not reviewing code).

### 2.2 Clarifying questions — batched, max 2 rounds

- The AI produces **one batch of at most 6 numbered questions** per round, sorted by impact on scope. Each question ships with the AI's default assumption in brackets:

  ```
  1. Who triggers the export — end users, or only org admins? [assume: org admins]
  2. Should exports respect the viewer's row-level permissions? [assume: yes]
  ...
  Answer by number ("1: admins only, 2: yes"), or type "defaults" to accept all assumptions.
  ```

- The user answers inline, may answer a subset (`defaults` fills the rest), or `defaults` for everything.
- **Hard cap: 2 rounds.** Round 2 exists only for genuine contradictions or gaps surfaced by round-1 answers, capped at 3 questions. After round 2 the AI must proceed on stated assumptions; every unresolved assumption is written into the epic draft's `Open assumptions` section so it's reviewable rather than silent. Unbounded Socratic loops are the failure mode this cap exists to prevent — a wrong assumption caught in the epic review loop costs one revision cycle; a fourth round of questions costs user patience every time.
- Q&A (questions, answers, resolved assumptions) is persisted to `intake.md` in the workspace so a resumed session — and the story fan-out agents — have full context.

### 2.3 Accept / revise signals

After rendering any draft (epic or story), the CLI presents one menu:

```
[a] accept    [e] edit file directly (opens $EDITOR, or edit externally and press e)
[c] comment   (add > [!comment] blocks in the file, then press c to trigger revision)
[r] revise with a one-line instruction typed here
[s] skip for now (stories only — come back later)
[q] quit (session saved)
```

- `a` advances the state machine.
- `e` waits, re-reads the file, treats the user's edits as authoritative (no diff shown — the user made the change), and re-presents the menu.
- `c` and `r` both produce an AI revision, which is **always shown as a unified diff and confirmed before applying** (§4.4).
- There is no free-text "looks good" parsing. Single-key intents are unambiguous and resumable.

---

## 3. State machine

### 3.1 States and transitions

```
intake ──► clarify ──► epic-draft ──► epic-review ──► stories-fan-out
                          ▲              │ revise            │
                          └──────────────┘                   ▼
             publish ◄── stories-review ◄─── consistency-pass
                │            │ ▲ per-story revise loops
                ▼
             summary ──► done
```

| State | Meaning | Exits to |
|---|---|---|
| `intake` | Prompt captured, workspace created | `clarify` |
| `clarify` | Q&A rounds (≤2) in progress | `epic-draft` |
| `epic-draft` | AI drafting/redrafting epic from template + intake | `epic-review` |
| `epic-review` | Awaiting accept/edit/comment on `epic.md` | `epic-draft` (revise) or `stories-fan-out` (accept) |
| `stories-fan-out` | Parallel story drafting + consistency pass (§6) | `stories-review` |
| `stories-review` | Per-story review loops; tracks which stories are accepted | `stories-fan-out` (a story needs full redraft), `publish` (all accepted) |
| `publish` | Adapter calls executing (or dry-run) | `summary` on success; stays `publish` on partial failure (idempotent re-run, §8.2) |
| `summary` | Results table rendered, links recorded | `done` |
| `done` | Terminal. `resume` on a done session prints the summary again | — |

Accepting the epic after stories exist (i.e., re-opening `epic.md` from `stories-review`) is deliberately **not** a transition in phase 1 — if the epic is wrong after fan-out, the operator re-runs fan-out (`stories-fan-out` is re-enterable and will regenerate only stories not yet accepted, warning about accepted ones that reference changed epic sections).

### 3.2 Persistence and resume

`session.json` in the workspace root is rewritten atomically (write temp + rename) on every transition and every review action:

```jsonc
{
  "version": 1,
  "slug": "csv-export",
  "state": "stories-review",
  "createdAt": "2026-07-01T14:02:11Z",
  "prompt": "Customers should be able to export audit findings as CSV",
  "clarifyRounds": 2,
  "epic": { "status": "accepted", "revisions": 3 },
  "stories": [
    { "file": "stories/01-export-endpoint.md", "status": "accepted", "revisions": 1 },
    { "file": "stories/02-permission-filter.md", "status": "in-review", "revisions": 2 },
    { "file": "stories/03-ui-trigger.md", "status": "skipped", "revisions": 0 }
  ],
  "publish": { "adapter": "github", "attempts": 0 }
}
```

Resume logic: load `session.json`, re-read the md files (they are authoritative for *content*; the session file is authoritative only for *workflow position*), and drop the user at the current state's prompt. If a file was hand-edited between sessions, that's fine — direct edit is a first-class action.

---

## 4. Draft storage format

### 4.1 Workspace layout

```
.epic-builder/
  csv-export/
    session.json
    intake.md                  # prompt + Q&A transcript + assumptions
    epic.md
    stories/
      01-export-endpoint.md
      02-permission-filter.md
      03-ui-trigger.md
    briefs/
      01-export-endpoint.brief.md      # implementation briefs, generated at accept-time
      02-permission-filter.brief.md
    .revisions/                # proposed revisions awaiting diff-confirm (transient)
```

`.epic-builder/` is gitignored by default (drafts are working material, not repo docs) — the publish step is what makes content durable. Operators who want draft history can un-ignore it; nothing in the tool assumes it's untracked.

### 4.2 File format — Markdown + YAML frontmatter

Every draft's body follows the corresponding `docs/templates/*.md` structure. Frontmatter carries machine state:

```yaml
---
kind: story                    # epic | story
epic: csv-export
sequence: 2
title: Filter exported rows by viewer permissions
status: in-review              # draft | in-review | accepted | skipped
sizing: M                      # S | M | L — consistency pass validates
dependsOn: [01-export-endpoint]
published:                     # written ONLY by the publish step
  adapter: github
  ref: "jharvieux/Harvey#42"
  url: https://github.com/jharvieux/Harvey/issues/42
  contentHash: "sha256:9f2c…"
---
```

### 4.3 Comments: inline `> [!comment]` blocks — chosen over a comments file

The user comments by inserting alert-style blockquotes directly in the draft:

```markdown
## Acceptance criteria
- Export completes in under 30s for 10k findings

> [!comment]
> 30s is too generous — our SLA discussion said 10s. Also add a criterion
> about the empty-results case.
```

**Why inline, not a separate comments file:**

1. **Anchoring is free and exact.** A comments file needs an addressing scheme (line numbers rot the moment the file changes; section IDs need maintenance). An inline block *is* its own anchor — the AI sees the comment in situ, adjacent to the text it criticizes, which is exactly the context a revision prompt needs.
2. **One file per artifact, one mental model.** Direct-edit and comment are the same gesture: open the file. No second file to keep in sync, no orphaned comments after a revision.
3. **Zero parser cost.** `> [!comment]` is a trivially greppable marker, renders as a visible callout in every Markdown preview (GitHub-style alert syntax), and can't be confused with draft content.

**Revision contract:** on `c`, the AI must (a) address every comment block, (b) **delete each comment block it addressed**, replacing it with nothing (the fix goes into the surrounding text), and (c) if it disagrees or can't comply, replace the block with `> [!note] AI:` explaining why — never silently drop a comment. A post-revision lint verifies no `> [!comment]` block survives unanswered.

### 4.4 Diff-before-apply

AI revisions are never written in place. The proposed file lands in `.revisions/`, the CLI renders a colorized unified diff (`git diff --no-index`, falling back to internal diff), and prompts:

```
Apply this revision? [y] apply  [n] discard  [e] apply then open editor
```

Direct user edits (`e` from the review menu) bypass the diff — the user is the author. Only machine-authored changes need human sign-off.

---

## 5. Core types

```typescript
type SessionState =
  | "intake" | "clarify" | "epic-draft" | "epic-review"
  | "stories-fan-out" | "stories-review" | "publish" | "summary" | "done";

type ArtifactStatus = "draft" | "in-review" | "accepted" | "skipped";

interface DraftSession {
  version: 1;
  slug: string;
  state: SessionState;
  prompt: string;
  createdAt: string;                 // ISO 8601
  clarifyRounds: number;             // 0..2
  epic: ArtifactState;
  stories: StoryState[];
  publish: { adapter: string; attempts: number };
}

interface ArtifactState {
  status: ArtifactStatus;
  revisions: number;                 // escalation trigger input (§7)
}

interface StoryState extends ArtifactState {
  file: string;                      // workspace-relative, e.g. "stories/02-….md"
}

/** A single user decision in a review loop. Appended to an in-workspace
 *  action log (session recovery + revision-count bookkeeping). */
type ReviewAction =
  | { kind: "accept"; target: string }
  | { kind: "direct-edit"; target: string }                   // user edited file
  | { kind: "comment"; target: string }                       // > [!comment] blocks added
  | { kind: "revise"; target: string; instruction: string }   // one-liner from CLI
  | { kind: "apply-revision"; target: string; accepted: boolean } // diff confirm
  | { kind: "skip"; target: string }
  | { kind: "quit" };

interface StoryDraft {
  file: string;
  frontmatter: {
    kind: "story";
    epic: string;
    sequence: number;
    title: string;
    status: ArtifactStatus;
    sizing: "S" | "M" | "L";
    dependsOn: string[];
    published?: PublishedRef;
  };
  body: string;                      // template-conformant markdown
}

interface PublishedRef {
  adapter: string;
  ref: string;                       // adapter-native id, e.g. "owner/repo#42"
  url: string;
  contentHash: string;               // sha256 of body at publish time
}
```

---

## 6. Story fan-out

### 6.1 Parallel drafting

On epic acceptance, the AI first emits a **story manifest** — title + one-line scope + rough size for each proposed story (typically 3–8). The user confirms or trims the manifest in one prompt (this is cheap and prevents paying for six parallel drafts of the wrong breakdown). Then:

- **One drafting agent per story**, run concurrently. Each agent receives: the accepted `epic.md`, `intake.md`, the `user-story.md` and `implementation-brief.md` templates, its manifest line, and the *titles* (not bodies) of sibling stories — enough to stay in-lane without cross-contamination.
- Each agent produces the story file **and** its implementation brief (`briefs/NN-<slug>.brief.md`). Every story must carry, per the template: acceptance criteria, applicable tests to build, and the brief.
- Agents write directly into the workspace with `status: draft`; nothing needs diff-confirmation yet because nothing has been reviewed yet.

### 6.2 Consistency pass (higher tier, §7)

A single pass over all drafted stories + the epic, run **before** the user sees any story:

1. **Coverage & dedup** — every epic acceptance criterion maps to ≥1 story; no two stories claim the same work; flag gaps as proposed new stories (user confirms additions).
2. **Dependency ordering** — populate `dependsOn`, verify the graph is acyclic, renumber `sequence` topologically.
3. **Sizing check** — flag any story whose body implies >L (proposes a split) or trivial-S (proposes a merge); consistent sizing scale across the set.
4. **Terminology & contract alignment** — shared names (endpoints, flags, entities) match across stories and briefs.

The consistency pass's changes are machine-authored against unreviewed drafts, so they apply directly but are summarized in a printed report ("merged 04 into 02; reordered 03 after 01; renamed `exportJob` → `ExportJob` in 3 files"). Then `stories-review` begins, walking stories in dependency order with the standard review menu each.

---

## 7. Model tiering hooks

Tiers map to the router's `bulk`/`standard`/`flagship` (see `model-routing.md`):

| Work | Tier |
|---|---|
| Slug/manifest formatting, diff summaries, frontmatter lint | **bulk** |
| Clarifying questions, epic draft, story drafts, comment-driven revisions | **standard** |
| Consistency pass, final pre-publish QA of the accepted set | **flagship** |

**Where escalation triggers live:** in the session controller, not in prompts. The controller checks, before each AI call:

```typescript
interface TierPolicy {
  /** Called before every generation; returns the tier to use. */
  select(ctx: {
    task: "clarify" | "epic-draft" | "story-draft" | "revise" | "consistency" | "qa";
    revisionCount: number;          // from ArtifactState.revisions
    flags: EscalationFlag[];
  }): "bulk" | "standard" | "flagship";
}

type EscalationFlag =
  | "revision-loop"        // revisions >= 3 on one artifact → escalate its next revision
  | "contradiction"        // consistency pass found epic/story conflict → escalate redraft
  | "sizing-anomaly"       // story flagged >L twice → escalate the split proposal
  | "user-requested";      // `r!` instead of `r` in the review menu forces flagship
```

Rationale: escalation on the third revision is the empirical "the cheap model isn't getting it" point; paying the high tier there is cheaper than a fourth failed loop. Tier selection is a pure function of observable session state so it's testable and its decisions appear in the action log.

---

## 8. Publishing

### 8.1 Tracker adapter interface

```typescript
interface TrackerAdapter {
  readonly name: string;                            // "github" | "jira" | "azure-devops"
  readonly supportsAttachments: boolean;

  /** Resolve config + credentials; fail loud before any write. */
  init(config: TrackerConfig): Promise<void>;

  /** Find an existing item created by a previous run (idempotency probe). */
  findByMarker(marker: string): Promise<PublishedRef | null>;

  createEpic(input: {
    title: string;
    body: string;                                   // rendered from epic.md
    marker: string;                                 // idempotency key (§8.2)
  }): Promise<PublishedRef>;

  createStory(input: {
    parentRef: PublishedRef;                        // link to the epic
    title: string;
    body: string;
    dependsOn: PublishedRef[];                      // rendered as links/relations
    marker: string;
  }): Promise<PublishedRef>;

  /** Attach the implementation brief where supported; otherwise the adapter
   *  returns a URL it arranged (committed file, wiki page, gist) and the
   *  caller appends a "📄 Implementation brief: <url>" link to the story body. */
  attachBrief(target: PublishedRef, brief: {
    filename: string;
    content: string;
  }): Promise<{ url: string; mode: "attachment" | "linked" }>;
}
```

Adapters are dumb transport: no retries of the whole plan, no ordering knowledge. The **publish orchestrator** owns sequencing (epic → stories in dependency order → briefs), idempotency, and partial-failure recovery.

### 8.2 Idempotency

Two mechanisms, belt and suspenders:

1. **Local record:** each artifact's `published` frontmatter block (ref, url, contentHash) is written immediately after its create call succeeds. On re-run, artifacts with a `published` block are skipped (or, if `contentHash` differs from the current body, the orchestrator warns "story changed since publish" and offers update-vs-skip; update is adapter `updateStory` — post-MVP, so MVP just warns and skips).
2. **Remote marker:** every created item's body ends with an invisible-ish marker line `<!-- epic-builder:csv-export/02-permission-filter -->`. Before creating, the orchestrator calls `findByMarker`; a hit repairs a lost local record (e.g., the process died between the API call and the frontmatter write) instead of duplicating.

Result: `pnpm epic publish <slug>` is safe to run any number of times; it only ever creates what doesn't exist yet.

### 8.3 Dry-run and summary

`--dry-run` executes the full plan against a no-op adapter that fabricates refs, printing exactly what would be created, in order, with parent links and brief placement mode. Real and dry runs both end with:

```
  #   Item                              Type    Size  Ref                      Brief
  ─────────────────────────────────────────────────────────────────────────────────
  —   CSV export of audit findings      epic     —    jharvieux/Harvey#41      —
  01  Export endpoint                   story    M    jharvieux/Harvey#42      linked ✓
  02  Permission filtering              story    M    jharvieux/Harvey#43      linked ✓
  03  UI trigger                        story    S    jharvieux/Harvey#44      linked ✓

  Epic: https://github.com/jharvieux/Harvey/issues/41
```

The same table is written to `summary.md` in the workspace.

### 8.4 GitHub adapter (MVP behavior)

- Epic = issue with a task-list body linking each story issue; label `epic`.
- Story = issue with label `story`, body from the story md, `Part of #<epic>` + `Blocked by #<dep>` lines (GitHub renders these as references; task-list checkboxes on the epic give rollup).
- Briefs: the GitHub Issues API does **not** support file attachments, so `supportsAttachments = false`. The adapter commits briefs to the target repo at `docs/briefs/<epic-slug>/NN-<story-slug>.md` in a single commit on a `docs/briefs-<epic-slug>` branch and opens one PR (respecting protected-default-branch rules) — `attachBrief` returns the blob URL at that branch, mode `"linked"`. Auth via `gh` CLI's existing token.

---

## 9. Templates dependency

The builder renders drafts *into* the structures defined by:

- `docs/templates/epic.md`
- `docs/templates/user-story.md`
- `docs/templates/implementation-brief.md`

These are owned by #20. Contract this design assumes of them: each is a valid Markdown skeleton with stable `##` section headings, and the story template includes sections for acceptance criteria and tests-to-build. The builder treats template headings as the section schema for its lint ("draft is missing `## Acceptance criteria`") — it never hardcodes section content. If templates change, drafts in flight keep their original structure; only new drafts pick up changes.

---

## 10. MVP cut

**In:**
- `new` / `resume` / `list` / `publish` (+ `--dry-run`) commands
- Batched clarify (≤2 rounds), full review-loop mechanics (edit / comment / revise / diff-confirm)
- Parallel story fan-out + consistency pass, tier policy with the escalation flags in §7
- GitHub adapter only: issues + labels + task-list epic + briefs-as-PR
- Local `.epic-builder/` workspaces, single operator, credentials from `gh` CLI

**Explicit non-goals (phase 1):**
- Jira and Azure DevOps adapters (interface is designed for them; nothing else is — #22)
- Multi-user, remote/shared workspaces, or any server component
- Updating already-published items (re-publish warns and skips changed content)
- Web/TUI interface; any editor integration beyond `$EDITOR`
- Automatic implementation of stories (the briefs are *for* downstream agents; this tool stops at publish)
- Epic re-review after story fan-out (re-run fan-out instead)
- Estimation beyond S/M/L, sprint/iteration assignment, roadmap views

**MVP acceptance test:** operator runs `pnpm epic new "<prompt>"`, answers one batch of questions, accepts the epic after one comment-driven revision, accepts 3 fan-out stories, runs `publish --dry-run` then `publish`, kills the process mid-publish, re-runs `publish`, and ends with exactly one epic issue, three story issues, one briefs PR, and no duplicates.
