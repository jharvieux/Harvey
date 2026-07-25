# Harvey runtime architecture

Status: draft v1 · Owner: operator · Scope: runtime design for the audit service, the epic/user-story builder, and the fix-implementation system. Model-selection internals are out of scope (see `model-routing.md`); the router appears here as an interface only.

Related: `briefs/audit-modules.md` (the module spec), `src/findings.ts` (findings schema), `report-template/render.mjs` (report renderer), `docs/go-no-go.md` (venture context). Issue: #19.

---

## 1. Execution environments (phased)

Three phases, one codebase. Every phase runs the same orchestrator and modules; only the **host** and the **repo-access mode** change. The seams that make that true are `ScanTarget`, `RunHost`, and `FindingsStore` (§2.2).

### Phase 1 — MVP: operator-run CLI (build this now)

A Node/TS CLI in this repo, run by the operator on their machine against a **local client checkout**:

```bash
harvey scan --engagement acme --repo ~/clients/acme-app [--modules m1,m3,m4] [--budget 5.00]
harvey report --engagement acme            # findings.json → HTML/PDF via render.mjs
harvey epics --engagement acme             # findings → epics/stories → tracker
harvey fix --engagement acme --finding F-012   # worktree + agent → PR
```

**Phase 1 scope — in:**
- `harvey scan`: orchestrator + module runner over a `LocalCheckout` scan target; per-module findings merged into one validated `FindingsDocument` (existing `validateFindings`).
- Engagement workspace on disk (`~/harvey-engagements/<slug>/`) holding findings, run logs, raw module output. Nothing client-derived leaves the machine.
- `ModelRouter` **client interface** wired through every module; a trivial single-provider implementation behind it until the router effort lands.
- `harvey report` wrapping the existing `report-template/render.mjs` unchanged.
- Supabase used for **metadata only**: engagements, runs, token spend (no code, no findings content).
- `harvey epics` and `harvey fix` as operator-invoked commands against the same local checkout, tracker adapter = GitHub Issues.

**Phase 1 scope — out (deliberately):** any hosted execution, webhooks, queues, client-facing UI, GitHub App, multi-tenant auth, findings stored server-side. None of these earn revenue at Tier-1 (operator-run) and all of them are reachable later through the seams below.

### Phase 2 — CI-hosted (GitHub Action in the client repo)

The same orchestrator packaged as an action. `ScanTarget` = the runner's own checkout (`actions/checkout` already happened); `RunHost` = GitHub Actions job. Findings post back as a run artifact + a summary comment; full report generation stays operator-side. Client code never transits Harvey infrastructure — it stays on GitHub's runner. Requires: results-upload endpoint (small Supabase Edge Function), per-engagement upload token.

### Phase 3 — hosted worker service

A worker pool (containerized) pulling `runs` rows queued in Supabase; `ScanTarget` = shallow clone via GitHub App installation token into an ephemeral volume, destroyed after the run. Same orchestrator binary. Adds: job queue (Supabase table + `FOR UPDATE SKIP LOCKED` is enough at this scale — no Redis), encrypted findings-at-rest, GitHub App, client portal.

### The seams (design now, in Phase 1 code)

```ts
interface ScanTarget {            // where the client code is
  root(): string;                          // absolute path to a readable checkout
  head(): Promise<string>;                 // commit SHA for report meta
  exec(cmd: string[], opts): Promise<ExecResult>;   // run tools (jscpd, stryker) in-target
}
// Phase 1: LocalCheckout. Phase 2: CiWorkspace. Phase 3: EphemeralClone.

interface RunHost {               // where Harvey itself is running
  scratchDir(): string;
  emit(event: RunEvent): void;             // structured run log (JSONL)
  persistRun(meta: RunMeta): Promise<void>;
}

interface FindingsStore {         // where findings live
  save(engagement: string, doc: FindingsDocument): Promise<void>;
  load(engagement: string, runId?: string): Promise<FindingsDocument>;
}
// Phase 1: FileFindingsStore (engagement dir). Phase 3: SupabaseFindingsStore.
```

Modules, the report pipeline, the epic builder, and the fix worker depend only on these three interfaces plus `ModelRouter`. That is the entire anti-rework contract.

---

## 2. Components

### 2.1 Diagram

```
                        ┌────────────────────────────────────────────┐
                        │              harvey CLI (Phase 1)          │
                        │   scan · report · epics · fix · status     │
                        └───────┬───────────────┬───────────┬────────┘
                                │               │           │
                 ┌──────────────▼───────┐  ┌────▼─────┐ ┌───▼──────────────┐
                 │   Scan Orchestrator  │  │  Epic    │ │ Fix-Implementation│
                 │  (module scheduler,  │  │  Builder │ │ Worker            │
                 │   budget, merge)     │  └────┬─────┘ │ (worktree agents) │
                 └──┬────────┬──────────┘       │       └───┬──────┬────────┘
                    │        │                  │           │      │
        fan-out ┌───▼──┐ ┌───▼──┐ …9x           │           │      │ PRs
                │ M1   │ │ M3   │  AuditModule  │           │      ▼
                │module│ │module│  instances    │           │  ┌────────────┐
                └──┬───┘ └──┬───┘               │           │  │ Client repo│
                   │        │                   │           │  │ (git)      │
       ┌───────────▼────────▼───────┐           │           │  └────────────┘
       │  ScanTarget (client code)  │◄──────────┼───────────┘
       │  local checkout / CI ws /  │           │
       │  ephemeral clone           │           ▼
       └────────────────────────────┘   ┌───────────────┐    ┌──────────────┐
                   │                    │ Tracker       │───►│ GitHub Issues│
                   │ findings           │ Adapters      │    │ Jira/ADO     │
                   ▼                    └───────────────┘    │ (later)      │
       ┌────────────────────────────┐                        └──────────────┘
       │  FindingsStore             │
       │  P1: engagement dir (file) │──► Report Pipeline ──► HTML/PDF
       │  P3: Supabase (encrypted)  │    (render.mjs)        (client deliverable)
       └────────────────────────────┘

   cross-cutting, used by every LLM-touching box:
       ┌────────────────────────────────────────────────┐
       │ ModelRouter client (interface only)            │
       │ complete(task, tier, prompt, budget) → result  │──► telemetry → token_spend
       └────────────────────────────────────────────────┘
   metadata only (Phase 1):
       Supabase: engagements · runs · token_spend
```

### 2.2 Responsibility table

| Component | Responsibility | Phase 1 form | Explicitly not its job |
|---|---|---|---|
| Scan orchestrator | Resolve module list, schedule modules with concurrency + token budget, collect/merge/dedupe findings, validate via `validateFindings`, write via FindingsStore, emit run log | `src/orchestrator.ts`, invoked by CLI | Module logic; report formatting |
| Audit modules (M1–M9, +M10 severity input) | One `AuditModule` per module: `{ id, tier, run(ctx): Promise<Finding[]> }`; ctx = ScanTarget + ModelRouter + budget slice + logger | Wrap existing assets: briefs (M1/M9), jscpd (M4), vitals (M3), pii-classify (M10), Stryker harness (M8) | Persisting anything; talking to trackers |
| ModelRouter client | Single LLM entry point: `complete({ task, tier: 'bulk'\|'standard'\|'flagship', prompt, schema?, budgetCents })` → `{ output, usage, model }`; emits telemetry per call; enforces per-run budget, refuses when exhausted | Thin interface + one stub provider; real routing per `model-routing.md` | Model selection logic, retries policy internals — behind the interface |
| FindingsStore | Persist/load `FindingsDocument` per engagement+run; history for re-audit diffing | File store in engagement dir | Rendering; severity logic |
| Report pipeline | findings.json → validated → `render.mjs` → HTML/PDF into engagement dir | Existing renderer, wrapped by `harvey report` | Editing findings |
| Epic builder | findings → remediation epics + user stories (grouped by module/subsystem, ordered by BFTB score from `src/findings.ts`); dry-run preview → push via tracker adapter | `harvey epics`, LLM-drafted via router (`standard` tier), operator approves before push | Writing code fixes |
| Fix-implementation worker | One finding-fix per isolated git worktree: branch, agent implements fix per `finding.fix`, run the client's own verify command, open PR referencing the finding id | `harvey fix`, operator machine, agent loop, `flagship` tier for security-sensitive fixes | Merging; deciding severity; batch auto-fix without operator per-finding approval |
| Tracker adapters | `TrackerAdapter { createEpic, createStory, linkFinding }` | GitHub Issues adapter only | Anything tracker-UI-specific leaking upstream |

---

## 3. State and storage

Rule of thumb: **Supabase holds business metadata; the engagement directory holds client-derived content; everything else is ephemeral.** In Phase 1 no client code, snippet, file path pattern, or finding text goes to Supabase — only counts and costs.

### In Supabase (Harvey's own project — metadata plane)

Schema sketch (key columns only):

```
engagements   id, client_name, slug, tier, status, repo_ref, contract_notes, created_at
runs          id, engagement_id, kind(scan|epics|fix), commit_sha, modules[], status,
              started_at, finished_at, finding_counts jsonb, host(local|ci|worker)
module_runs   id, run_id, module_id, status, duration_ms, finding_count, error
token_spend   id, run_id, module_id, task, model, tier, input_tokens, output_tokens,
              cost_cents, created_at            -- fed by ModelRouter telemetry
tracker_creds id, engagement_id, provider, secret_ref, scopes, created_at
              -- Phase 1: secret_ref points at the operator keychain item, value NOT stored.
              -- Phase 2/3: value in Supabase Vault, this table stays a pointer.
fix_jobs      id, run_id, finding_id, branch, pr_url, status, verify_result   -- Phase 2+
findings      -- Phase 3 only: encrypted-at-rest copy of FindingsDocument rows,
              -- engagement-scoped RLS; does not exist in Phase 1/2.
```

### In the engagement directory (operator disk, per client — data plane, Phase 1)

```
~/harvey-engagements/<slug>/
  findings/<runId>.json        # the FindingsDocument (client data)
  reports/<runId>/             # rendered HTML/PDF
  logs/<runId>.jsonl           # run log / audit trail
  raw/<runId>/<module>/        # module scratch output kept for evidence (jscpd json, stryker report…)
  engagement.json              # local pointer: slug, supabase engagement id, repo path
```

Not in this git repo. `report-template/findings.atc.json` stays as the sample/fixture; real engagement findings move out of the repo (CLAUDE.md already flags them as sensitive — this formalizes it).

### In-repo (this repo — the product)

Briefs (`docs/*.txt`), module code, report template, schema. No engagement state.

### Ephemeral (deleted at run end)

Module scratch not promoted to `raw/`, LLM prompt payloads (never logged verbatim — see §6), Phase 3 clones and their volumes, fix-worker worktrees after PR creation.

---

## 4. Client-environment access modes

| Mode | Phase | How | Trust/safety implications |
|---|---|---|---|
| Local checkout | 1 | Client grants read access (collaborator invite or zip); operator clones to disk | Highest operator trust burden: client code at rest on operator machine → FileVault mandatory, per-engagement dir, `harvey purge <slug>` after retention window. Simplest consent story: "one named human, one machine, deleted after N days" goes in the engagement contract. |
| GitHub PAT / App | 1 (fix PRs), 3 (clones) | Phase 1: client-issued fine-grained PAT scoped to the one repo, `contents:read` + `pull_requests:write`, stored in operator keychain. Phase 3: GitHub App with short-lived installation tokens | PAT is bearer risk — fine-grained + short expiry + revocation instructions in onboarding doc. App tokens are strictly better (auditable, auto-expiring, per-repo): required before any hosted phase. Never request `contents:write` broadly — fix branches only. |
| CI runner (client's own) | 2 | Harvey Action runs inside the client's GitHub Actions; code never leaves GitHub | Best confidentiality story (code stays in client's trust boundary) but inverts the risk: **Harvey's code executes with the client's repo permissions**. Mitigations: pinned action SHA, no secrets required beyond the results-upload token, results payload is findings-only and size-capped, action is source-visible to the client. Also weakest for M2 (dynamic pen test needs a running stack — stays operator-run). |

Anti-goal in every mode: Harvey never holds client **production** credentials. M2/M7 dynamic work runs against a locally seeded stack or a client-provided staging environment, credentialed by the client for the engagement window.

---

## 5. Parallelism model

**Scan fan-out.** The orchestrator runs modules as independent async tasks over a shared read-only `ScanTarget`, `p-limit`-style with concurrency ≈ 4. Two constraint classes: CPU-heavy tool modules (M4 jscpd, M8 Stryker — Stryker manages its own worker pool, so it runs with orchestrator concurrency 1 alongside LLM-bound modules) and LLM-bound modules (M1, M5, M6, M9 — each internally batches files and fans batches to the router; the router's budget/rate limiting is the backpressure, not module-local throttling). Modules are read-only over the target, so no locking is needed. Each module returns `Finding[]`; the orchestrator merges, dedupes by `(location, taxonomy)`, applies M10 data-aware severity weighting as a post-pass, and assigns stable ids.

**Fix fan-out.** Each fix job gets its own `git worktree` off the client repo (`.harvey-worktrees/<finding-id>`, branch `harvey/fix/<finding-id>`), so N fix agents run concurrently without touching each other's working state or the operator's checkout. Per-worktree lifecycle: create → agent implements → run the client's verify command in-worktree → commit → push branch → open PR → remove worktree. Concurrency cap 3 in Phase 1 (verify runs are the bottleneck). A failed verify marks the job failed and leaves the branch for operator inspection — no auto-retry loops burning tokens.

**Cross-run parallelism** (multiple engagements at once) is a non-goal until Phase 3, where it falls out of the worker pool for free.

---

## 6. Security and confidentiality

- **Client code containment (Phase 1 invariant):** client code and findings content exist only in (a) the client checkout, (b) the engagement directory, (c) transient LLM API payloads. Nothing client-derived is written to Supabase, this repo, or any third-party service. The `FindingsStore` interface is the single choke point that enforces this — Phase 1 ships only the file implementation.
- **LLM payloads:** code excerpts sent to model providers are the one unavoidable egress. Mitigate: providers with no-training/zero-retention API terms only (a router requirement, stated in its interface contract as `provider.retention === 'zero'`), and the engagement contract discloses which providers see code. The router telemetry stores usage numbers, never prompt bodies.
- **Secrets:** operator secrets (LLM keys, PATs) live in the macOS keychain / env at invocation, never in files in either repo, never in Supabase in Phase 1. `tracker_creds` stores pointers, not values. Phase 2/3 moves values to Supabase Vault with per-engagement scoping.
- **Audit trail:** every run appends structured JSONL (`logs/<runId>.jsonl`): module start/stop, files-scanned counts, every router call (task, tier, model, tokens, cost — no prompt text), every finding id created, every tracker/PR write with URL. This is both the client-facing "what did you actually do" evidence and the liability record (go/no-go risk #3).
- **Fix-worker blast radius:** fix agents get write access only to their worktree and push access only to `harvey/fix/*` branches; merging is always a human (client or operator) via PR review. No force-push, no default-branch writes, ever — enforced by branch naming + PAT scope, not convention.
- **Retention:** engagement dir purged by `harvey purge` after the contractual window (default 90 days post-delivery); the Supabase metadata rows persist (they contain no client content) for business history and re-audit pricing.

---

## 7. MVP decisions

1. **Phase 1 is a local CLI, not a service** — the operator is the only user; a service adds auth/hosting risk with zero revenue benefit at Tier-1.
2. **Three seams (`ScanTarget`, `RunHost`, `FindingsStore`) are built in the first commit** — they cost ~100 lines now and are the entire difference between "Phase 2 is a packaging job" and "Phase 2 is a rewrite."
3. **Findings live in files, not Supabase, in Phase 1** — client-data-never-leaves-the-machine is a sellable confidentiality guarantee and removes encryption/RLS work from the critical path.
4. **Supabase from day one, but metadata-only** (engagements, runs, token_spend) — token-cost visibility per module/model is needed immediately to price engagements and to feed the router effort real telemetry.
5. **ModelRouter is an interface with a one-provider stub** — modules code against `complete(task, tier, budget)` now; the router effort (#19, `model-routing.md`) drops in behind it without touching module code.
6. **Modules implement one `AuditModule` interface and are read-only over the target** — makes fan-out trivial and keeps "add M11" a one-file change.
7. **Reuse `render.mjs` and `src/findings.ts` unchanged** — the report pipeline is the most client-visible asset and already works; the orchestrator conforms to its schema, not vice versa.
8. **Tracker adapter ships GitHub-Issues-only** — every early client is on GitHub; Jira/ADO are adapter implementations (#22), not architecture.
9. **Epic builder and fix worker are CLI subcommands sharing the engagement dir, not separate systems** — same findings source, same router, same audit log; separation is premature.
10. **Fix worker: one worktree + one branch + one PR per finding, human merge always** — isolation makes parallel fixes safe and the PR boundary is the liability firewall.
11. **Stryker (M8) runs inside the scan with orchestrator concurrency 1** — it saturates the machine on its own; scheduling it alongside LLM-bound modules is free, alongside jscpd is not.
12. **Job queue in Phase 3 is a Supabase table with `SKIP LOCKED`, not Redis/SQS** — at audits-per-week scale, one fewer moving part beats theoretical throughput.
13. **No client portal, webhooks, or GitHub App in Phase 1** — deferred until Phase 2/3 triggers them; the GitHub App is the explicit precondition for any hosted clone (decision recorded so Phase 3 doesn't ship on PATs).
