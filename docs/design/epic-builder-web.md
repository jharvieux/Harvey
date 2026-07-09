# Epic Builder — Web UI Design

**Status:** Draft for review · Issue: #76 · Builds on: #21 (CLI/core), #22 + #50 (tracker layer)
**Scope:** A hosted browser front end + server API that drives the **existing** `src/epic-builder/`
core. It reimplements none of the state machine, drafts, revision protocol, story fan-out, or the
publish orchestrator — it wraps them.
**Code home:** `epic-builder-web/` (a standalone Next.js app with its own `package.json`, excluded
from the root scanner toolkit's build — like `intake-site/` and `targets/`).
**Design of record for the underlying flow:** `docs/design/epic-builder.md`. Read that first; this
doc only covers what the web wrapper adds or changes.

---

## 1. What changes moving from CLI to web

The CLI (`docs/design/epic-builder.md`) assumes three things the web cannot:

1. **A single trusted operator at a terminal** — no auth, ambient `gh` credentials, `$EDITOR` for
   direct edits, a synchronous readline loop for accept/revise decisions.
2. **A local, persistent filesystem** as the source of truth (`.epic-builder/<slug>/`), safe to
   crash and resume because every mutation lands on disk in the same process's working directory.
3. **Synchronous, in-process interaction** — `runClarify`, `reviseArtifact`, and `fanOutStories`
   all take callbacks (`answer`, `confirm`, `confirmManifest`) that block for a human decision
   inside one function call.

The web wrapper replaces exactly those three assumptions — auth, storage, and the
synchronous-callback interaction model — and **keeps everything else** (the state machine, the
frontmatter draft format, the comment/diff revision contract, the tier policy, the idempotent
publish orchestrator, the GitHub adapter) untouched.

Everything below is a decision, not an option list. Options considered are noted where the choice is
non-obvious.

---

## 2. Architecture

```
browser (React)
  │  fetch JSON
  ▼
Next.js Route Handlers  (app/api/*, Node runtime — never Edge)
  │  call thin wrap functions
  ▼
epic-builder-web/lib/core.ts          ← the ONLY new logic; adapts HTTP ⇄ core callbacks
  │  imports, unchanged:
  ├─ src/epic-builder/  (session.ts, publish.ts, workspace.ts, …)
  └─ src/trackers/      (github.ts, types.ts)
       │
       ▼
   GitHub REST API                     ← per-engagement injected token
```

- **The browser never holds a model key, a tracker token, or draft storage credentials.** It speaks
  only to same-origin `/api/*` routes and receives rendered drafts + diffs as JSON.
- `lib/core.ts` is a **dependency-injected seam**: every wrap function takes `{ model, dataDir,
  templates, trackerFactory }`. Production routes pass the real implementations; tests pass a fake
  `ModelClient` and a `GitHubTracker` with a mocked `fetchImpl`. This is what makes the flow
  testable without a live model, a live tracker, or an HTTP server.
- **Node runtime is mandatory** on every route: the core uses `node:fs`, `node:path`, and
  `node:crypto`. Routes are declared `export const runtime = "nodejs"`.

### Why wrap in a `lib/core.ts` seam rather than call the core from routes directly

Route handlers are hard to unit-test (they want a `Request`/`Response`, a running server, cookies).
Pushing all core-driving logic into plain async functions with injected deps means the
draft→revise→publish flow is proven by a fast in-process test, and the routes shrink to
parse-request → call-wrap → return-JSON. It also keeps the browser bundle from ever importing a
server-only module: `lib/core.ts` and everything it pulls in are referenced only from route
handlers, which Next tree-shakes out of the client build.

---

## 3. State machine — reused verbatim, sliced across HTTP requests

The web UI does **not** define a new state machine. It reads `session.state` (the core's
`SessionState`) and renders the matching screen; each user action posts to the route that performs
the matching core transition. The mapping:

| `session.state` | Screen | Action → API → core call |
|---|---|---|
| `intake` | New-epic prompt box | `POST /api/session {prompt}` → `createWorkspace` + `model.clarify(round 1)` for preview |
| `clarify` | Clarifying questions form | `POST /api/clarify {answers}` → `runClarify` then `draftEpic` |
| `epic-review` | Epic editor + review menu | `POST /api/review` → `acceptEpic` / `reviseArtifact` / direct-edit write |
| `stories-fan-out` | Manifest confirm | `GET /api/fanout` (preview) → `POST /api/fanout {keep}` → `fanOutStories` |
| `stories-review` | Per-story editor + review menu | `POST /api/review` (target = story file) |
| `publish` | Publish panel (dry-run / publish) | `POST /api/publish {dryRun}` → `publish` orchestrator |
| `summary` / `done` | Results table + links | `GET /api/session` renders `summary.md` |

Resume is free: a browser refresh is `GET /api/session?slug=…`, which loads `session.json` and the
current draft from storage and drops the user on the screen for `session.state` — identical
semantics to `pnpm epic resume`.

### Two deliberate interaction changes (and why)

The core's callbacks block for a human decision inside one call; HTTP is request/response. Two
places need an explicit MVP decision:

1. **Revision confirmation: apply-then-show-diff, not diff-then-confirm.**
   The CLI writes the proposed revision to `.revisions/`, renders a diff, and applies it only if the
   operator confirms *in the same call*. Splitting that across two HTTP requests would either
   re-run the model on "apply" (non-deterministic, and doubles cost) or require persisting and
   re-reading the proposal with its own lifecycle. For the MVP, `reviseArtifact` is called with
   `confirm: () => true` (auto-apply) and the **unified diff is returned to the browser and shown
   prominently**, with "revise again" and "edit directly" as the undo path. The issue's requirement
   — *visible diffs* — is met; the *pre*-apply gate becomes a *post*-apply review. Two-phase
   confirm (persist proposal → confirm applies without re-running the model) is **deferred** (§9).

2. **Clarify is one round in the MVP.**
   `runClarify` supports up to two rounds via its `answer` callback. The web wrapper supplies an
   `answer` callback that returns the posted answers for round 1 and `"defaults"` thereafter, so the
   loop terminates after the user's single submission (with the offline scaffold model, round 2
   returns no questions anyway). A true multi-round web clarify — persisting round-1 answers, then
   re-prompting — is **deferred** (§9). Unresolved assumptions still land in the epic draft's
   `Open assumptions` section, exactly as in the CLI.

Direct edit (the CLI's `$EDITOR` action) becomes an in-browser textarea: the user edits the draft
body, `POST /api/review {action:"edit", body}` writes it verbatim via `writeDraft`, and
`recordDirectEdit` logs it — the user is the author, so no diff is shown, matching design §4.4.

---

## 4. Draft storage

**Decision — MVP store: the server filesystem, one workspace tree per authenticated user, reusing
`src/epic-builder/workspace.ts` unchanged.**

`workspace.ts` already parameterizes every operation on a `cwd` and builds `${cwd}/.epic-builder/
<slug>/`. The wrapper computes `cwd = ${EPIC_BUILDER_DATA_DIR}/${userId}` and calls the existing
`createWorkspace` / `loadSession` / `readDraft` / `writeDraft` functions with zero changes. Every
draft, `session.json`, `intake.md`, and `.revisions/` file lives on disk exactly as the CLI writes
them; crash-resume semantics are inherited for free. `EPIC_BUILDER_DATA_DIR` defaults to a local
`.data/` directory and is set to a mounted volume in any real deployment.

**Why filesystem for the MVP, and the production caveat.** Reusing `workspace.ts` verbatim is the
single largest reduction in new, untested code — the store *is* the shipped, tested core. The cost:
**Vercel serverless functions have an ephemeral, per-invocation filesystem**, so a multi-instance
Vercel deployment cannot share `.data/` across requests. The MVP is therefore deployable in one of
two honest ways, and **which one is a decision for the operator (§10):**

- **(a)** Run the app on a single persistent instance (a small always-on container / VM, or Vercel
  with a mounted network volume) so `.data/` survives between requests. Fine for a
  single-operator tool, which is what the epic builder is today.
- **(b)** Before real multi-user production use, add a **Supabase Postgres** persistence adapter
  behind the `workspace.ts` seam (see below).

**Production target: Supabase Postgres.** The venture already standardizes on Supabase (it is the
audit target platform and the intended auth provider). The migration is contained: `workspace.ts`
is the single persistence seam — replace its `fs` reads/writes with row reads/writes on two tables
(`epic_sessions(user_id, slug, state, json)` and `epic_drafts(user_id, slug, path, body)`) keyed by
`(user_id, slug)`. Nothing above `workspace.ts` (session controller, publish orchestrator) changes,
because they already treat it as an opaque store. Chosen over Vercel Blob (needs its own listing/
concurrency story) and Postgres-only-without-Supabase (we'd forgo the auth integration below).

---

## 5. Model calls — server-side only

**Decision:** model calls go through the core's existing injected `ModelClient` seam
(`src/epic-builder/types.ts`), constructed **server-side** in `lib/model.ts` and referenced only by
route handlers. **No model key ever reaches the browser**, and the wrap functions take the client as
an injected dependency so tests pass a deterministic fake.

- **MVP default:** the offline `ScaffoldModelClient` (`src/epic-builder/model-scaffold.ts`). It is
  server-side, deterministic, needs no key, and lets the entire flow run end-to-end today. It fills
  templates and — honoring the §4.3 comment contract — never silently drops a comment.
- **Live provider (per `docs/design/model-routing.md` §6):** `lib/model.ts` selects a live client
  when `EPIC_BUILDER_MODEL=anthropic` and `ANTHROPIC_API_KEY` is present. The routing decision from
  model-routing.md maps the builder's tiers to concrete models:
  - `bulk` → slug/manifest/diff-summary work (currently non-LLM in the core);
  - `standard` → **Claude Haiku 4.5** for clarifying questions, epic/story drafts, revisions;
  - `flagship` → **Claude Sonnet 5** for the consistency pass and pre-publish QA.
  The tier is chosen by the core's existing `tier-policy.ts` (a pure function of session state), so
  the live client only has to honor the `Tier` argument on each method. **Client code is never sent
  to a disqualified processor** (model-routing §4): the key is a server env var for an
  Anthropic-ZDR-eligible account; `Fable 5` is excluded (mandatory retention).
- **The live `ModelClient` implementation is deferred** to a follow-up (§9). Shipping five prompt
  methods that cannot be exercised in CI (no key) would be unverified surface; the seam and the
  env-based selector are in place so wiring it is a single-file addition. The MVP proves the flow
  with the scaffold client and a test fake.

---

## 6. Auth

**Decision — MVP: a single shared operator secret gates every route; production: Supabase Auth.**

The epic builder is an operator tool (the CLI is single-operator with ambient `gh` auth). The MVP
keeps that trust model with the minimum viable sign-in: a login form posts a shared secret
(`EPIC_BUILDER_PASSWORD`), the server compares it with a constant-time check and sets a signed,
`httpOnly`, `SameSite=Strict` session cookie; every `/api/*` route and the app shell reject requests
without a valid cookie. The `userId` used to scope storage (§4) is a fixed `"operator"` in the MVP.

- Chosen over "no auth" because the app holds a tracker token and can create issues in a client's
  repo — it must not be world-open. Chosen over standing up full multi-user auth now because the
  tool has exactly one user today and multi-user needs the storage work in §4 first.
- **Production:** reuse the audit-service's Supabase Auth story. `userId` becomes the Supabase user
  id, which is already the storage partition key in §4, so multi-user drops in without touching the
  flow. Deferred with the Supabase storage adapter (§9).

The shared secret and the cookie-signing key are server env vars, never shipped to the client and
never logged.

---

## 7. Tracker credentials

Publishing reuses the `src/trackers/` layer's **injected-token contract** unchanged (see
`src/trackers/types.ts` and `credentials.test.ts`):

- The GitHub token, owner, and repo are **server env vars** (`GITHUB_TOKEN`, `GITHUB_OWNER`,
  `GITHUB_REPO`), read only inside a route handler, passed to `new GitHubTracker({ token, … })`.
  The token is held in the adapter's private `#token` field, so it never appears in
  `JSON.stringify`, an error, or a log line — the existing `credentials.test.ts` guarantees this,
  and the web app adds a test that the token never crosses into a response body or the client bundle.
- **The token never reaches the browser** and is **never written into stored drafts** (only the
  published *refs/URLs* are, in frontmatter — as the CLI already does).
- `POST /api/publish {dryRun:true}` uses the core's `NoopTracker` and needs no token, so the plan
  can be previewed without credentials — same guarantee as `pnpm epic publish --dry-run`.
- Per-engagement tokens (one client repo per engagement) are a natural extension: the env token is
  the MVP default; a production multi-tenant version reads the token from the per-engagement secret
  store the trackers contract already assumes the caller owns. Deferred with multi-user (§9).

---

## 8. Deployment

**Decision:** a Next.js (App Router) app deployed on **Vercel, alongside `intake-site`**, as a
**separate Vercel project with root directory = `epic-builder-web`** (mirroring intake-site's
root-directory pattern). Its `package.json`, build, and dependency tree are independent of the root
scanner toolkit.

- **Keeping it out of the root toolkit's build:** the root `tsconfig` already `include`s only
  `src`; the web app is added to the root **eslint ignores** and **vitest exclude** (like `targets/`
  and `intake-site/`), and its build artifacts are git-ignored. Root `pnpm verify`
  (typecheck + lint + test + knip) never sees the web app. The web app has its own `pnpm verify`.
- **Importing the core across the package boundary:** the core is authored as NodeNext ESM with
  explicit `.js` import specifiers that resolve to `.ts` sources. The web app's bundler is
  configured to resolve `.js`→`.ts` (webpack `resolve.extensionAlias` for Next; a small `resolveId`
  plugin for the app's Vitest), so `lib/core.ts` can `import { publish } from
  "../src/epic-builder/publish.js"` and pull the real, unmodified core into the graph.
- **Templates:** the builder renders into `docs/templates/{epic,user-story,implementation-brief}.md`.
  The app reads them at runtime from the repo (`../docs/templates`). A Vercel deploy rooted at
  `epic-builder-web/` must include those three files (copy them into the app at build, or deploy
  from repo root) — noted in the app README.
- **Env vars (Vercel project settings):** `EPIC_BUILDER_PASSWORD`, `EPIC_BUILDER_SESSION_SECRET`,
  `EPIC_BUILDER_DATA_DIR` (persistent volume), `GITHUB_TOKEN` / `GITHUB_OWNER` / `GITHUB_REPO`, and
  (when the live client lands) `EPIC_BUILDER_MODEL` + `ANTHROPIC_API_KEY`.
- **Link from the onboarding site:** once the app has a real URL, add a footer link from
  `intake-site/index.html` — this closes the original "no link to the epic tool" gap (#76). Deferred
  until a deployment URL exists rather than hardcoding a placeholder (§9).

---

## 9. MVP cut

**In (the working draft→revise→publish path):**

- Auth gate (shared-secret cookie), operator-scoped filesystem storage reusing `workspace.ts`.
- Flow: new prompt → clarifying questions (1 round) → epic draft → epic review (accept / direct-edit
  / comment-driven AI revision / one-line revise, with the diff shown) → story fan-out (manifest
  preview + confirm) → per-story review → publish a GitHub issue set (dry-run and real) through the
  existing `src/trackers` GitHub adapter and the existing idempotent `publish` orchestrator.
- Server-side `ModelClient` seam (scaffold default) and `GitHubTracker` (env token); dry-run via
  `NoopTracker`.
- A flow test that drives `lib/core.ts` end-to-end with a **deterministic fake `ModelClient`** and a
  `GitHubTracker` whose **HTTP is mocked**, asserting draft→revise→publish and no credential leak.

**Deferred (tracked, non-essential to prove the flow):**

- Live `ModelClient` implementation (Anthropic per §5) — seam + selector present, prompts not yet
  written; needs a key + CI eval before it can be trusted. **Tracked: #102.**
- Supabase Postgres storage adapter + Supabase Auth multi-user (§4, §6) — the seam is `workspace.ts`
  and the `userId` partition; nothing above it changes. **Tracked: #103.**
- Two-phase revision confirm and multi-round web clarify (§3) — MVP uses apply-then-show-diff and a
  single clarify round.
- Per-engagement (per-repo) tracker tokens beyond the single env token (§7).
- Real-time fan-out progress, presence/locking for concurrent editors, and polish
  (mobile layout, keyboard shortcuts).
- The `intake-site` footer link (§8) — added once a deploy URL exists.

**Explicitly out (inherited from the CLI design §10):** Jira/Azure adapters, updating
already-published items, automatic implementation of stories, epic re-review after fan-out.

---

## 10. Decisions that want operator review

1. **Storage for the first deployment:** single persistent instance now (fastest to a live URL) vs.
   investing in the Supabase adapter before any deploy (§4). Recommendation: single instance now,
   Supabase before exposing it to more than the operator.
2. **When to wire the live model:** ship the MVP on the offline scaffold (drafts are skeletons the
   operator fleshes out) vs. gate the MVP on the Anthropic client landing first (§5).
   Recommendation: ship on scaffold, wire the live client as the immediate follow-up.
3. **Whether the epic tool should be linked from the client-facing intake site at all**, or kept on
   an internal/unlisted URL — it is an operator planning tool, not a client feature (§8).
</content>
