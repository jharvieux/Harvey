# Fix Implementation System — Design

Status: draft v1 · Owner: operator · Issue: #23 · Scope: Phase 1 (operator-run) with Phase 2 hooks noted

> **Operator ruling, 2026-07-23 (#885): the execution path IS being built, not shelved.** The question
> that blocked #885 — "decide and record whether the execution path is being built or shelved" — is
> answered: built, narrowest-slice-first, inert diffs before any PR ever touches client code. The
> remainder is tracked issue-by-issue in §9 below; nothing in this design is deferred without an
> issue number next to it. Do not re-litigate this decision — extend §9's ledger instead.
Inputs: a validated `FindingsDocument` (`src/findings.ts`), a client-approved fix list, a local checkout of the client repo, client-granted GitHub access.

Harvey's scan produces findings; this system turns approved findings into reviewed, reversible PRs in the client's repo. Design center: **the PR is the unit of delivery, the operator is the last gate, and nothing merges without the client.** Everything below is built so a solo auditor can run it on a laptop against one engagement at a time, fanning implementation out to parallel subagents.

---

## 1. Pipeline

```
findings.json ──▶ INTAKE ──▶ PLAN ──▶ BATCH ──▶ IMPLEMENT ──▶ VERIFY ──▶ PR ──▶ OPERATOR GATE ──▶ CLIENT HANDOFF
                 (human)   (cheap    (solver)  (worktrees,   (client's  (gh)   (human)          (client merges)
                            model)              parallel)     commands)
```

### 1.1 Intake

- Input is a findings doc that passes `validateFindings()` **plus** an engagement manifest listing which finding ids the client approved for fixing. No approval record, no fix — findings the client hasn't signed off on never enter the pipeline.
- Eligibility filter before anything runs, keyed off the schema:
  - `confidence` must be `Confirmed` or `Likely`. `Review`/`N/A` findings are never auto-fixed; they become "recommended fix" notes.
  - `ease >= 4 && safety >= 4` (the BFTB inputs) for the automated path. Lower scores route to `manual` mode: a fix plan is drafted for the operator, but no subagent touches code.
  - Category must be in the engagement's enabled category set (see MVP cut, §8).
- Intake pins the client repo commit (`meta.commit` from the findings doc must match, or the operator explicitly re-baselines — findings against a stale commit get their `location` re-verified before planning).

### 1.2 Per-finding fix plan (cheap model)

A low-cost-tier subagent reads the finding (`id`, `location`, `evidence`, `fix`) plus the referenced source and drafts a `FixPlan`. The plan is cheap on purpose: it exists to make batching and rail-checking possible *before* any code changes, and to give the operator something reviewable when a fix gets downgraded.

The plan must include a **blast-radius estimate**: the concrete file list the fix will touch, the symbols/routes affected, callers/importers of changed code (from a grep pass, not guesswork), and whether the change is behavior-preserving. A plan whose blast radius exceeds the rails (§3) is downgraded at this stage — cheaply, before a worktree ever spins up.

```typescript
// src/fix/plan.ts
import type { Finding, Severity } from "../findings";

export type FixMode = "auto" | "manual" | "recommend-only";
export type EscalationTier = "cheap" | "standard" | "flagship";

export interface BlastRadius {
  files: string[];              // concrete paths the fix will modify
  createdFiles: string[];       // new files (tests, helpers) — must also pass the allowlist
  symbols: string[];            // functions/routes/policies touched
  callers: string[];            // grep-discovered importers/callers of changed symbols
  behaviorPreserving: boolean;  // false => operator gate is mandatory-with-diff-walkthrough
  estimatedChangedLines: number;
}

export interface FixPlan {
  findingId: string;            // Finding.id — the join key for everything downstream
  severity: Severity;
  category: string;
  mode: FixMode;
  detectorId: string;           // which scan detector produced the finding (re-run in verify)
  approach: string;             // 2–5 sentences: what changes and why it resolves the finding
  blastRadius: BlastRadius;
  verifyCommands: string[];     // discovered client commands this fix must pass (§2)
  testPlan: string;             // which existing tests cover this; what new test (if any) is added
  tier: EscalationTier;         // starting model tier (§5)
  risks: string[];              // e.g. "callers may rely on the silent no-op"
  downgradeReason?: string;     // set when mode === "recommend-only"
}
```

### 1.3 Batching

- Build a conflict graph over eligible plans: nodes are findings, an edge means **overlapping `blastRadius.files`** (or overlapping `createdFiles`). Directory-level overlap is not an edge; file-level is.
- Connected components serialize internally (ordered by severity desc, then BFTB desc); independent components run in parallel up to the concurrency cap (§4).
- Findings the operator marks as one *coherent batch* (e.g. five instances of the same anti-pattern class, like the zero-row-update sites in D-091 #7) collapse into a single node → single worktree → single PR. Batching across *different* pattern classes is prohibited even when files don't overlap — one PR must have one reviewable story.

### 1.4 Implement → Verify → PR

Each node gets an isolated git worktree (§4), a subagent at the plan's tier implements the fix, verification runs (§2), and a PR is opened as **draft**. Failures loop back per the escalation ladder (§5); exhausted attempts downgrade to recommend-only with the failure evidence attached.

### 1.5 Operator gate → client handoff

- Every PR sits in **draft** until the operator reviews the diff and the `VerificationEvidence` block. Marking a PR ready-for-review is a human action, never automated. The operator checklist is the existing `docs/runbooks/pr-self-review.md` plus a slop sweep of the generated diff.
- Client handoff = the PR set plus a fix summary appended to the engagement report: table of finding id → PR link → verification status → recommended merge order (§4). **The client merges. Harvey never merges.**

---

## 2. Verification contract

The contract, in one line: **a fix is "verified" only if the client's own checks pass AND the detector that found the problem no longer fires — both actually executed, in this worktree, with output captured.**

### 2.1 Discover the client's verify commands

Run once per engagement (cached in the engagement manifest, operator-editable):

1. `package.json` scripts, in preference order: `verify` > `check`/`ci` > the union of `typecheck|tsc`, `lint`, `test`. Monorepos: same per affected workspace, plus the root.
2. `.github/workflows/*.yml`: extract `run:` steps from PR-triggered jobs. Anything CI runs that the scripts don't (e.g. `pnpm check:*` gates, knip, jscpd) gets appended. Steps needing secrets/services we don't have are recorded as `skipped: needs-ci` — *explicitly*, in the evidence.
3. Baseline run on the pinned commit **before any fix work starts**. Pre-existing failures are recorded once and treated as ambient: a fix is green if it introduces no *new* failures. Never silently absorb a pre-existing failure — it's listed in every PR body it applies to.

### 2.2 Never report green without running

- The verifier is a separate step from the implementer, and it only trusts captured process output (command, exit code, stdout/stderr tail, duration). A subagent *claiming* tests pass is worth nothing; the harness runs the commands itself. This is the "fail loud / never present a guess as fact" doctrine applied mechanically.
- If a verify command cannot be run locally (needs prod env, needs CI secrets), the fix is **not** reported green — the PR says "local checks green; `<command>` requires CI, will run on this PR" and the operator gate confirms CI went green before handoff.

### 2.3 Re-run the detector

Every plan carries `detectorId` — the scan detector (from `briefs/scan-extras.txt` / the D-091 gate set / the module scanner) that produced the finding. Verification re-runs **that detector scoped to the fixed location** and requires it to no longer fire. Detector-clean without client-checks-green is not done; client-checks-green without detector-clean is not done. Both, or it fails.

### 2.4 Evidence

```typescript
// src/fix/verify.ts
export interface CommandRun {
  command: string;
  cwd: string;
  exitCode: number;
  durationMs: number;
  outputTail: string;           // last ~50 lines, secrets-scrubbed
  skipped?: "needs-ci" | "pre-existing-failure-on-baseline";
}

export interface VerificationEvidence {
  findingId: string;
  worktreeCommit: string;                 // HEAD after the fix
  baselineCommit: string;                 // pinned engagement commit
  detectorBefore: { detectorId: string; fired: true; output: string };   // from the original scan
  detectorAfter:  { detectorId: string; fired: boolean; output: string }; // must be fired: false
  clientChecks: CommandRun[];             // every discovered command, run or explicitly skipped
  newTestAdded?: string;                  // path of regression test, if the plan called for one
  green: boolean;                         // detectorAfter.fired === false && no NEW clientCheck failures
  attempts: number;                       // implementation attempts consumed (§5 escalation input)
}
```

The `detectorBefore`/`detectorAfter` pair goes verbatim into the PR body — before/after evidence is the client-facing proof, not an internal artifact.

---

## 3. Safety rails

### 3.1 Hard rules (violation ⇒ abort, always)

1. **Never push a protected branch.** Push targets are `harvey/fix/<finding-id>` branches only; `main`/`master`/anything in the repo's protected set is refused at the git-wrapper level, not by convention.
2. **Never modify secrets, env, or CI-credential files.** Built-in denylist, non-overridable: `.env*`, `**/secrets*`, `**/*.pem|*.key|*credentials*`, `.github/workflows/**`, `.git/**`, deploy configs that carry tokens. A fix whose correct implementation requires touching these (e.g. "rotate the leaked key") is *by definition* recommend-only.
3. **Path allowlist per engagement.** The client scopes each engagement to a path set (e.g. `apps/main/src/**`, `supabase/**` excluded). The implementer's write surface is the allowlist minus the denylist; a write outside it aborts the fix and logs a rail-violation event.
4. **Max-diff-size guard per PR.** Default: 300 changed lines / 10 files (operator-tunable per engagement, never per finding). Exceeded ⇒ abort and downgrade; a "small mechanical fix" that grows past this was mis-planned, and a big diff defeats the reviewability the whole system depends on.
5. **Dry-run mode.** `--dry-run` runs intake → plan → batch → rails-check and emits the full plan set + would-be PR bodies, with zero worktrees created and zero pushes. First run of every engagement is a dry run, reviewed with the client.
6. **Every change reversible by closing the PR.** Corollaries: no direct commits to any shared branch, no migrations that execute on merge without a client-run step, no dependency additions in the automated path (a `package.json`+lockfile change is not "reversible by closing the PR" in any practical client workflow — it invites drift and supply-chain review the client didn't sign up for).

### 3.2 Abort vs. downgrade

| Situation | Outcome |
|---|---|
| Hard-rule violation attempted (denylist write, protected-branch push, diff cap) | **Abort** the fix, log the event, surface to operator. Repeated rail violations in one engagement pause the whole pipeline. |
| `location` no longer matches the pinned commit (code moved/changed) | **Abort**, flag for re-scan. Fixing stale evidence is how you break things. |
| Correct fix requires: schema/RLS migration, secret rotation, product/UX decision, contract change visible to client's users, or dependency change | **Downgrade** to recommend-only: ship the `FixPlan` prose + a suggested diff sketch in the report, no PR. |
| Verification unrunnable locally and no CI available to the operator | **Downgrade** (a fix we can't verify is a liability, not a deliverable). |
| Verification fails after the escalation ladder is exhausted (§5) | **Downgrade**, attach every `CommandRun` so the failure itself is a finding-grade artifact. |
| Blast radius grows mid-implementation beyond the plan (new files needed, callers must change) | **Abort and re-plan** once; if the second plan also exceeds rails, downgrade. |

Downgrades are not failures of the engagement — they're the honest half of the deliverable. The report's fix section has two tables: "PRs opened" and "Recommended fixes (why not automated)".

---

## 4. Parallelism

- **Worktree per node.** `git worktree add .harvey/wt/<finding-id> <baseline-commit>` inside the operator's client checkout; branch `harvey/fix/<finding-id>` created at the baseline. Worktrees are disposable: green ⇒ push branch + open draft PR + remove worktree; failed ⇒ preserve worktree for operator autopsy until end of engagement.
- **Concurrency cap:** default **4** concurrent implement/verify slots (Phase 1 is a laptop; the binding constraint is the client's test suite runtime, not tokens). Verification slots are the scarce resource — implementation can overlap freely, but at most 2 full client-check runs execute at once to keep timings honest.
- **File-conflict detection** happens twice: statically at batch time (blast-radius overlap, §1.3), and dynamically at completion — before pushing, diff the worktree's changed-file set against every already-pushed fix branch. Late-discovered overlap ⇒ the later fix rebases onto the earlier fix branch *only for local conflict assessment*; if it conflicts, it re-queues to run serially after the earlier PR's disposition. PRs are always cut against the client's default branch, never stacked.
- **Merge-order suggestion:** the handoff summary emits a suggested order — severity desc within each conflict component, components ordered by highest contained severity — with an explicit "PRs #a and #b touch `<file>`; merge #a first, then re-run CI on #b" note wherever dynamic overlap was detected. It's advice to the client, not automation.

---

## 5. Model tiering

Tiers map to the router's `bulk`/`standard`/`flagship` (see `model-routing.md`; "cheap" below = `bulk`):

| Tier | Used for | Rationale |
|---|---|---|
| **cheap** (bulk) | All fix plans; implementation of mechanical MVP classes (§8) | These are pattern-application jobs — the D-091 catalog literally contains the before/after shape. |
| **standard** | Implementation after any escalation trigger; all non-mechanical categories | |
| **flagship** | Final adversarial review of every **Security-category** fix diff before it can leave draft; implementation of fixes that hit two or more escalation triggers | Review is cheaper than implementation and catches the "fix that technically silences the detector" class. |

**Escalation triggers** (any one bumps cheap → standard):

1. `severity` is `Critical` or `High`.
2. Path or plan touches **state-machine, auth/permission, or payment-adjacent code** (matched against an engagement-configured sensitive-path list — the analogue of "sensitive paths never auto-change" — plus keyword heuristics: `assertPermission`, `transition`, `payout`, `stripe`, `webhook`).
3. **Verification failure after N=2 attempts** at the current tier (max 2 attempts per tier; exhausting standard ⇒ downgrade, no flagship implementation retries in Phase 1 — cost discipline).
4. **Cheap-model self-disagreement:** plans are drafted twice by the cheap tier with independent contexts; if the two plans disagree on file set or approach materially, the finding escalates to standard for planning *and* implementation. Agreement is a cheap consistency check; disagreement is a signal the fix isn't mechanical.

Flagship Security review has abort authority: its rejection sends the fix back one tier with the review notes, once; a second rejection downgrades to recommend-only.

```typescript
// src/fix/result.ts
export type FixOutcome = "pr-opened" | "recommend-only" | "aborted";

export interface FixResult {
  findingId: string;
  outcome: FixOutcome;
  plan: FixPlan;
  branch?: string;              // harvey/fix/<finding-id>
  prUrl?: string;               // draft PR
  evidence?: VerificationEvidence;
  tiersUsed: EscalationTier[];  // e.g. ["cheap","standard"] — cost/quality telemetry
  flagshipReview?: { verdict: "approved" | "rejected"; notes: string }; // Security category only
  downgradeOrAbortReason?: string;
  railEvents: string[];         // any rail checks that fired, even non-fatal ones
}
```

---

## 6. Client access modes

### Phase 1 — local checkout + operator's client-granted GitHub access

- Operator clones the client repo with credentials the client granted (collaborator invite or fine-grained PAT the *client* issued, scoped to the one repo). Worktrees, implementation, and verification are all local.
- Rails specific to this mode: the git wrapper refuses any push whose ref isn't `harvey/fix/*`; `gh pr create --draft` is the only PR-affecting command the pipeline may issue (no merge, no ready-for-review, no branch-protection or settings API calls — those aren't wrapped, they're absent). Client code never leaves the operator's machine except as PR diffs to the client's own repo; no client source in Harvey's repo, scratch dirs, or prompts beyond what the fix requires.
- Credential hygiene: PAT lives in the OS keychain, engagement-scoped, revoked (or client uninvites) at engagement close — put it in the engagement-close checklist.

### Phase 2 — GitHub App, least privilege

- A Harvey GitHub App the client installs on **selected repositories only**. Permissions: `contents: write`, `pull_requests: write`, `checks: read`, `metadata: read`. Explicitly **not** requested: `workflows`, `administration`, `secrets`, `environments`, `members`. Short-lived installation tokens per run; nothing long-lived stored.
- Branch rails move from wrapper-enforced to structurally enforced where possible: the client keeps branch protection on their default branch, so even a buggy Harvey cannot push it; Harvey additionally keeps the `harvey/fix/*`-only wrapper as belt-and-braces.
- Phase 2 also unlocks: reading CI results on Harvey's own PRs (`checks: read`) to close the "needs-ci" verification gap in §2.2, and running the pipeline without a full operator-side clone (ephemeral runner). The pipeline stages, rails, and evidence contract are identical — only the transport changes.

---

## 7. PR conventions

- **One finding per PR**, or one coherent same-pattern batch (§1.3). Branch `harvey/fix/<finding-id>`; title `[<finding-id>] <imperative fix summary>` (e.g. `[F-pay-01] Assert affected-row count on payout status transition`).
- Always opened as **draft**; operator flips to ready.
- Body template (generated from `FixResult`):

```markdown
## Fixes finding <id> — <title>
Severity: <severity> · Category: <category> · Confidence: <confidence>
Audit report ref: <report section link> · Engagement commit: <baselineCommit>

### What was wrong
<finding.evidence, trimmed> — <finding.impact, one line>

### What this PR does
<plan.approach>
Files touched: <blastRadius.files>

### Verification
| Check | Result |
|---|---|
| Detector `<detectorId>` before | FIRED (output excerpt) |
| Detector `<detectorId>` after  | clean |
| `<each client command>` | exit 0, 42s (or: skipped — needs CI, see below) |
Pre-existing failures on baseline (not caused here): <list or "none">
New regression test: <path or "n/a — covered by <existing test>">

### Rollback
Close this PR / revert this single commit. No migrations, no dependency changes,
no config changes are included; reverting restores the exact prior behavior.

---
Generated by Harvey fix-implementation · reviewed by <operator> before leaving draft.
```

The rollback section is mandatory and must be *true* — it's the enforcement mirror of rail 3.1(6). If a fix can't honestly write that paragraph, it shouldn't be a PR.

---

## 8. MVP cut

**In-scope finding classes first** — mechanical, high-`safety`, detector-verifiable, all with exact before/after shapes already documented in `briefs/anti-patterns.md`:

1. **Zero-row update returns `error: null`** (D-091 #7) — chain `.select('id')` + assert row count. Purely additive, per-site.
2. **Unchecked Supabase mutations** (D-091 #3) — add error handling on ignored `{ error }`.
3. **Raw error message egress** (D-091 #16) — route through the generic-response helper pattern.
4. **`z.string().url()` on stored/rendered URL fields** (D-091 #17) — swap to a safe-URL validator.
5. **`void`-prefixed async in serverless functions** (D-091 #8) — `await` or platform `waitUntil`.
6. **TODO/stub-shaped code with an obvious completion** (D-091 #1) — only when the finding's `fix` field states the completion; otherwise recommend-only.

Each of these maps to an existing `check:*`-style detector, satisfying §2.3 without new detector work.

**Calibration:** run the full pipeline against the deliberately-broken calibration target (issue #9) before any client engagement. The target's ground-truth doc gives planted instances of classes 1–5; acceptance = every in-scope planted bug yields a green draft PR whose detector-after is clean and whose diff the operator would sign, every out-of-scope planted bug (RLS-off table, `USING (true)` policy, service-role query building) yields a correct recommend-only downgrade with the right reason, and zero rail events fire. That last clause matters: the calibration run validates the *rails*, not just the fixes.

**Explicit non-goals (MVP):**

- No RLS policy or migration changes (anti-patterns #2, #5, #13 are recommend-only — DB-layer enforcement changes need client DBA eyes).
- No auth/permission-matrix, state-machine, or payment-flow rewrites (#9, #11, #14, #15, #18-as-RPC — the escalation triggers in §5 exist precisely because these aren't mechanical).
- No webhook replay-protection *implementation* (#20 needs provider-specific idempotency design; recommend-only with the pattern's reference implementations cited).
- No dependency additions/upgrades, no secret rotation, no CI/workflow edits — hard rails, not just non-goals.
- No auto-merge, no ready-for-review automation, no fixing findings the client didn't approve, no multi-engagement concurrency.
- No Phase 2 GitHub App build — designed for above so nothing in Phase 1 forecloses it, but not built until Phase 1 has run on ≥2 real engagements.

**Proposed file layout:** `src/fix/plan.ts`, `src/fix/verify.ts`, `src/fix/result.ts` (schemas above), `src/fix/rails.ts` (denylist + allowlist + diff-cap checks, pure functions, tested like `findings.ts` is), orchestration as an operator-invoked CLI (`pnpm fix:dry-run <engagement>`, `pnpm fix:run <engagement>`).

---

## 9. Implementation status (issue #23)

Landed as of this PR — the **decision core** of the pipeline, fully unit-tested:

| File | What it provides | Design ref |
|---|---|---|
| `src/fix/plan.ts` | `FixPlan`/`BlastRadius` schema; `screenFinding()` — eligibility + tier assignment | §1.1, §1.2, §5 |
| `src/fix/rails.ts` | denylist / allowlist (glob) / push-ref / protected-branch / diff-cap checks; `checkBlastRadius()` | §3 |
| `src/fix/verify.ts` | `VerificationEvidence` schema; `discoverVerifyCommands()`, `runCommand()` (spawns + captures, never trusts a claim), `computeGreen()`, `scrubSecrets()` | §2 |
| `src/fix/result.ts` | `FixResult` schema; `fixBranch()`, `prTitle()`, `renderPrBody()` (the §7 template) | §5, §7 |
| `src/fix/pipeline.ts` | `intake()` (screen the client-approved subset), `batch()` (file-overlap conflict components), `checkPlanRails()` | §1.1, §1.3 |
| `src/cli/fix-dry-run.ts` | `pnpm exec tsx src/cli/fix-dry-run.ts <findings.json> <manifest.json>` — side-effect-free intake report (rail 3.1(5)) | §3.1 |

### 9.1 The first executing slice (#885, 2026-07-23)

| File | What it provides | Design ref |
|---|---|---|
| `src/fix/execute.ts` | `executeFixDiff()` — rail-checks an implementer-produced unified diff against its REAL file set + line count, then proves it applies against a **detached, disposable worktree** cut at the pinned baseline in `os.tmpdir()`. Disposes the worktree in a `finally`. Refuses Harvey's own repository (`git rev-parse --git-common-dir` comparison, so a Harvey worktree is caught too). | §1.4, §3.1, §4 |
| `src/cli/fix-execute.ts` | `pnpm exec tsx src/cli/fix-execute.ts <findings.json> <manifest.json> --target <checkout> [--out <dir>]` — screens via `intake()`, executes each `auto` finding's `suggestedFix.diff`, writes inert `<id>.diff` + `fix-execution.json`, exits non-zero on any rail block or verification failure. | §1.4, §3.1 |

Deliberate limits of this slice, so nobody reads more capability into it than it has:

- **Inert diffs only.** The client's working tree is never written; no branch is created (the worktree is detached), nothing is pushed, no PR is opened. There is no `gh` call in `src/fix/`.
- **Apply-clean, not §2-green.** It routes through the existing `verifySuggestedFix()` (`src/trackers/fix-diff.ts`): the diff applies, and an optional `effectCommand` holds. The §2 contract — the client's own checks plus a detector that stops firing — is **not** satisfied by this slice, and `outcome: "diff-verified"` deliberately does not say "green".
- **Rails run before git.** A denylisted path, an out-of-allowlist path, or an over-cap diff is refused before a worktree exists, and its `.diff` is not written to the artifacts dir.
- **A rail-blocked or unverified fix is never presented as applied.** The CLI exits non-zero and labels each row with its outcome.

### 9.2 Remaining work — every piece has an issue (#929 is the ledger)

Ruling of record (2026-07-23, #885): **this is being built.** Remaining pieces, each with file paths and acceptance criteria in its issue:

| Issue | Piece | Design ref |
|---|---|---|
| #922 | Implementer: `FixPlan` producer, diff generation, escalation ladder (`FixPlan` has no producer today) | §1.2, §1.4, §5 |
| #923 | Verification harness: client-command discovery against a real checkout, workflow parse, baseline run, `VerificationEvidence` assembly | §2.1, §2.2, §2.4 |
| #924 | Detector re-run — `detectorId` has no producer or consumer, so `computeGreen()` can never return true today | §2.3 |
| #925 | Branch + push + draft-PR transport at a **wrapped** git/`gh` client (`checkPushRef`/`isProtectedBranch` are pure functions no wrapper enforces) | §1.4, §3.1, §6, §7 |
| #926 | Batching (`batch()` has no caller), parallel worktrees, concurrency caps, merge order, client handoff — **landed, see §9.2 below** | §1.3, §1.5, §4 |
| #927 | The §8 calibration acceptance gate | §8 |
| #928 | `verifySuggestedFix()` has no path rails — adjacent hole found while surveying | §3.1 |

Sequencing: #922 → #924 → #923 → #927 → #925 → #926. **#925 is not first** — it is the repo's first privileged, network-writing path, and a PR opened on a fix whose verification cannot yet compute green is the exact failure #885 was filed about.

**Correction (2026-07-23):** this section previously recorded the MVP acceptance run as *"deferred pending issue #9 (the deliberately-broken calibration target), which does not exist in the repo yet."* Measured in a clean worktree: **`targets/calibration/` exists.** The recorded blocker had decayed; the run is unblocked and simply unperformed (#927).

**Update (2026-07-24):**

- **#928 done.** `verifySuggestedFix()` now clears the §3 path/size rails before it touches git, delegating to the one rail implementation (`src/fix/rails.ts` `isDenied`/`checkDiffCap`) and the one shared diff parser (moved to `rails.ts`). A diff touching a denylisted path or over the diff cap returns `verified: false`, so it can never be marked verified nor reach a ticket body (`renderFixSection` is gated on `verified`).
- **#927 partially landed → remainder #957.** `src/fix/calibration-acceptance.test.ts` runs the checkable-today portion offline against the real planted calibration source: the §3 rails + inert-diff verify transport reaches `diff-verified` with zero rail events on a class-4 fix, and denylisted/over-cap diffs are `rails-blocked`. The **full autonomous** §8 run is blocked on the implementer (#922, no diffs), the detector-after re-run (#924), and the fact that `executeFixDiff` refuses `targets/calibration` in place (it lives inside Harvey's own git — the corpus must be materialized into a standalone repo first). Measured record: `docs/design/fix-calibration-acceptance.md`.

**Update (2026-07-24, fix-pipeline execution slice — #922/#923/#924/#925):** the deterministic scaffolding of the remaining execution path landed on one branch. What each piece provides:

| File | What it provides | Design ref | Issue |
|---|---|---|---|
| `src/fix/produce-plan.ts` + `src/cli/fix-plan.ts` | `producePlan()` — a deterministic `FixPlan` producer that reads a screened Finding + the client source and drafts a plan with a **grep-derived** blast radius (real importers of the changed file, not a guess); round-trips through `checkPlanRails()`. The CLI screens, produces a plan per auto/manual finding, rail-checks each, writes `fix-plans.json`. No diff — the implementer that turns an approved plan into `suggestedFix.diff` remains the operator/LLM pass `src/cli/fix-execute.ts` already consumes. | §1.2, §1.4 | #922 |
| `src/fix/escalation.ts` | The §5 ladder as pure functions: `plansDisagree()` (a REAL file-set + approach comparison of two cheap-tier drafts, not an assumption), `planningTriggers()`, `initialTier()`, and `runEscalation()` — max 2 attempts per tier, cheap→standard on verification failure, downgrade with the trigger named, no flagship failure-retries in Phase 1. Feeds `FixResult.tiersUsed`. | §5 | #922 |
| `src/fix/detector-rerun.ts` | §2.3 detector re-run: resolves a finding's `taxonomy` to a runnable AST detector (M5/M6/M7/M9) and re-runs it **scoped to the fixed file**, so an unrelated instance elsewhere doesn't keep the fix red. `DetectorRun.notRun` + `computeGreen` treat an un-re-runnable detector as **not green** (fail loud). `detectorBefore` carried verbatim from the scan. Proven against `targets/calibration` (M5 "Unused parameter" fires before, clean after). | §2.3, §2.4 | #924 |
| `src/fix/verify-harness.ts` | §2.1/§2.2 client-check discovery from a real checkout (root + affected workspaces, provenance recorded), a purpose-built PR-triggered-workflow `run:`-step extractor (no YAML dep), a **baseline run** on the pinned commit, and `buildVerificationEvidence()` — pre-existing baseline failures recorded as `skipped:"pre-existing-failure-on-baseline"`, unrunnable steps as `skipped:"needs-ci"`, `green` **decided** by `computeGreen`, every output secrets-scrubbed. | §2.1, §2.2, §2.4 | #923 |
| `src/fix/transport.ts` | §3.1/§6/§7 the repo's **first privileged, network-writing path**: one wrapped git/`gh` client where the push-ref + protected-branch + Harvey-self rails are enforced at the WRAPPER; `gh pr create --draft` is the only PR-affecting command (merge/ready/settings **absent**, source-guarded by a test); `--dry-run` is the default and withholds every push; `deliverFix()` opens a draft PR ONLY on `evidence.green === true`, aborts a green fix whose diff would falsify the §7 rollback paragraph, and returns `recommend-only` (with evidence) otherwise. | §1.4, §3.1, §6, §7 | #925 |
| `package.json` | `fix-dry-run` / `fix-execute` scripts wired (the operator action item from #929). | — | #929 |

Credential handling (§6: engagement-scoped PAT in the OS keychain, revoked at close) is an operator process, not code — `transport.ts` relies on the ambient `gh`/git auth and never stores a token.

**Update (2026-07-24, #926 — batching, scheduling, merge order, client handoff):**

| File | What it provides | Design ref | Issue |
|---|---|---|---|
| `src/fix/schedule.ts` | The **real caller of `batch()`** (until now it existed only in its own test): `scheduleFixes()` turns eligible fixes into file-overlap conflict components ordered internally (severity desc, then BFTB desc) and against each other (highest contained severity first); `emitMergeOrder()` produces the §4 merge advisory with a "PRs for A and B touch `<file>`; merge A first" note per within-component overlap; `detectLateConflict()` is the pre-push dynamic check (a completed fix's changed-file set vs. every already-pushed branch); `runScheduled()` ENFORCES the §4 caps at a semaphore — default 4 implement/verify slots, at most 2 concurrent full client-check runs — proven observable (peak-concurrency assertions), not documented. | §1.3, §4 | #926 |
| `src/fix/handoff.ts` | `assembleHandoff()` — the §1.5 client-handoff artifact: every APPROVED finding as a row (PR-opened / verified-inert / awaiting-implementer / manual / recommend-only / rails-blocked / verify-failed / aborted / not-approved) with its status, PR link, verification, reason, and merge rank. A downgraded/blocked fix is a ROW WITH A REASON, never a silent omission. Carries the merge-order advisory alongside. | §1.5, §4 | #926 |
| `src/cli/fix-execute.ts` | Now assembles a handoff from intake + executions and writes `fix-handoff.json` next to `fix-execution.json`, and prints the recommended merge order. This is `batch()`'s first non-test caller in a real CLI path. | §1.5 | #926 |
| `report-template/render.mjs` | `fixSection()` renders `data.fixHandoff` (an operator folds `fix-handoff.json` into `findings.<client>.json`): a "Fix delivery" table (merge # → finding → status → PR → verification) plus the merge-order notes, and a "Recommended fixes (why not automated)" downgrade table. Optional — renders only when a `fixHandoff` is present. | §1.5 | #926 |

Deliberate limit of this slice: `runScheduled` is the concurrency ENGINE and `detectLateConflict` the pre-push check, but the one-command runner that drives real worktrees + `transport.deliverFix()` through them end-to-end is not assembled — each piece is unit-proven and composes. The inert-diff `fix-execute` path emits `verified-inert` handoff rows (no live push); a transport-integrated runner would emit `pr-opened` rows via `deliverFix`.

Remaining after this slice: **#957** (the full autonomous §8 calibration run).

**Update (2026-07-24, #957 — the §8 acceptance gate runs the FULL §2 contract autonomously for a resolvable-detector class):**

| File | What it provides | Design ref | Issue |
|---|---|---|---|
| `src/fix/materialize-calibration.ts` | Materializes `targets/calibration` into a STANDALONE throwaway git repo (acceptance-doc blocker 3: `executeFixDiff` refuses the in-place corpus via `assertNotHarveyItself`) and captures a single-file mechanical fix as a git-apply patch. | §8 | #957 |
| `src/fix/acceptance.ts` | `runFixAcceptance()` — composes `executeFixDiff` (apply-clean + §3 rails) AND `rerunDetector` (#924 detector-after, §2.3) into one `green` verdict. Green iff the diff verifies AND the detector no longer fires — the §8 clause-1 gate, not merely apply-clean. | §8, §2.3 | #957 |
| `src/fix/calibration-acceptance.test.ts` | The M5 "Unused parameter" planting reaches GREEN autonomously (fix applies clean, zero rail events, detector-after clean); the gate discriminates (fires on the unfixed source; a no-op edit is NOT green); the semgrep class-4 detector-after is disclosed `notRun` (never a false green); clause 2 (out-of-scope RLS-off → recommend-only) holds. | §8 | #957 |

**#957 is a verified-PARTIAL, split → #1009.** Blockers 2 (detector-after re-run) and 3 (corpus materialization) are CLOSED. Still not fully autonomous, and genuinely out of reach for a mechanical assembly: (a) the fix diffs are still hand-authored — the diff-**generating** LLM implementer is #922's other half, not deterministic code; (b) `rerunDetector` has no semgrep/M1 resolver, so the §8 in-scope classes 1–4 report `notRun` (correct fail-loud) rather than green; (c) classes 1/2/5 aren't planted as before/after fix fixtures. All three are #1009, cross-linked from `docs/design/fix-calibration-acceptance.md`.

**Update (2026-07-24, #1012 + #1009's detector half — the semgrep resolver):** clause (b) above is now CLOSED, and clause (c)'s recorded reason was re-measured and found to be the wrong shape.

| File | What changed | Design ref | Issue |
|---|---|---|---|
| `src/scan/semgrep.ts` | `harveyRuleIds()` reads the replayable rule ids off `src/scan/rules/semgrep/*.yml` (so a renamed/deleted rule stops resolving rather than silently "not firing"), and `runSemgrepOnFile()` runs the custom rule directory against ONE file — returning a per-path semgrep error as a `failure`, because semgrep exits 0 on a syntax error with zero results and that must never be read as a clean file. | §2.3 | #1012 |
| `src/fix/detector-rerun.ts` | Second resolver family beside the AST engines: a finding whose taxonomy names a local `harvey-*` rule is verified by replaying that rule, scoped to the finding's own file. `resolvesToDetector` accepts both the bare id and the config-path-prefixed `check_id` a `--config <dir>` scan emits. Registry-pack rules (network fetch), missing files, unparseable source and an absent binary are each `notRun` **with the reason** — the unverifiable-is-never-resolved posture is widened, not weakened. | §2.3 | #1012 |
| `src/fix/calibration-acceptance.test.ts` | The §8 classes detected by a `harvey-*` rule now run the SAME full gate as the M5 class and reach GREEN against the real planted sources: class 4 (open redirect, `pages/api/redirect.js`), class 3 (raw error egress, `pages/api/verbose.js`), and the planted SQLi (`pages/api/search.js`). The gate follows the DETECTOR, not intent — a host-allowlist `.refine()` the taint path still reaches is NOT green. | §8 | #1009 |

**Re-measured 2026-07-24 — clause (c)'s blocker is upstream of the fixtures.** §8 classes 1 (zero-row update returning `error: null`), 2 (unchecked Supabase mutation) and 5 (`void`-prefixed async) have **no detector anywhere in `src/`** — no `harvey-*` semgrep rule, no AST engine (locked as a test asserting `resolvesToDetector` is false for all three). Planting before/after fixtures for them would produce `notRun` rows, not green ones. The detector has to be built first; the fixture is the second step, not the first.

**#1009's remainder after this slice:** the diff-**generating** LLM implementer (a), and detectors-then-fixtures for §8 classes 1/2/5 (c).

**Still not built, still deliberate:**

- **Model tiering** is config surface only: `escalation.ts` decides which tier each attempt runs at and records the trail in `tiersUsed`, but there is no multi-provider router in `src/` that maps those tiers to real models — see `docs/design/model-routing.md` for the target `bulk`/`standard`/`flagship` mapping. The implementer that actually drafts a diff at a tier is the operator/LLM pass, not code here.
- **End-to-end wiring** of produce-plan → escalation → detector-rerun → verify-harness → transport into a single orchestrating CLI is not assembled; each piece is unit-proven and composes, but the one-command engagement runner is #926's job.
