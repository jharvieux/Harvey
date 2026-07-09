# epic-builder-web — hosted epic/user-story builder (issue #76)

A Next.js app that puts a browser front end on the existing CLI epic builder. It **wraps** the
`src/epic-builder/` core (state machine, drafts, revision protocol, story fan-out, idempotent
publish orchestrator) and the `src/trackers/` GitHub adapter — it reimplements none of it. The only
new logic is `lib/core.ts`, which adapts stateless HTTP onto the core's callback-driven controller.

Design of record: `../docs/design/epic-builder-web.md` (and `../docs/design/epic-builder.md` for the
underlying flow).

## The flow

New prompt → clarifying questions → epic draft → review (edit / comment-driven AI revision / one-line
revise, with the diff shown) → story fan-out (manifest preview + confirm) → per-story review →
publish a GitHub issue set (dry-run or real) → summary with links. Resume/refresh is stateless: the
UI renders whatever screen the persisted `session.state` calls for.

## Run locally

```bash
pnpm install            # in this directory (its own package.json, separate from the root toolkit)
EPIC_BUILDER_PASSWORD=secret pnpm dev
```

Open http://localhost:3000, sign in with the password, and walk the flow. The default model is the
offline `ScaffoldModelClient` (deterministic skeleton drafts — no key needed); publishing needs the
GitHub env vars below (or use **Dry run**, which needs none).

## Test

```bash
pnpm test        # drives lib/core.ts end-to-end with a fake model + mocked GitHub HTTP
pnpm verify      # typecheck + test
```

The flow test (`test/flow.test.ts`) proves intake → clarify → revise → accept → fan-out → publish →
idempotent re-run without a live model, a live tracker, or a running server.

## Environment variables

| Var | Purpose |
|---|---|
| `EPIC_BUILDER_PASSWORD` | Operator sign-in secret (MVP auth). |
| `EPIC_BUILDER_SESSION_SECRET` | HMAC key for the session cookie. |
| `EPIC_BUILDER_DATA_DIR` | Where per-user workspaces are stored (default `./.data`). |
| `GITHUB_TOKEN` / `GITHUB_OWNER` / `GITHUB_REPO` | Per-engagement publish target (real publish only). |
| `EPIC_BUILDER_MODEL` + `ANTHROPIC_API_KEY` | Select the live model client (deferred — see design §5, §9). |

Secrets are read only in server routes; none reach the browser.

## Deploy (Vercel)

Separate Vercel project, **root directory = `epic-builder-web`** (mirrors `intake-site`). Set the env
vars above. Two caveats from the design doc:

- **Storage:** Vercel serverless has an ephemeral filesystem, so the MVP's file-backed store needs a
  single persistent instance / mounted volume, or the deferred Supabase adapter, before real
  multi-user use (design §4).
- **Templates:** the app reads `../docs/templates/{epic,user-story,implementation-brief}.md` at
  runtime; a deploy rooted here must include those three files (copy them in at build, or deploy from
  the repo root). Override the location with `EPIC_BUILDER_TEMPLATES_DIR`.

## Not in the MVP (deferred, see design §9)

Live Anthropic model client · Supabase storage + Supabase Auth multi-user · two-phase revision
confirm · multi-round web clarify · per-engagement tracker tokens · the `intake-site` footer link
(added once a deploy URL exists).
