# PR self-review checklist

Run this **before opening a PR**, not as a replacement for CI. The Claude Code hooks already cover the per-edit and turn-end cases; this catches things that need looking at the whole diff at once.

## Five steps, ~2 minutes

```bash
pnpm typecheck    # strict TS — catches noUncheckedIndexedAccess + types
pnpm lint         # allowlist additions surface here (with the exact suggestion in the error message)
pnpm vitest run --related $(git diff --name-only origin/dev)   # tests that import any changed file
pnpm slop-check   # narrating comments, orphan TODOs, rethrow-only catch, single-expr wrappers
git diff origin/dev...HEAD | less   # eyeball read for D-091 anti-patterns
```

Or batch all of them:

```bash
pnpm verify       # typecheck + lint + full test + slop-check (~2-5 min)
pnpm verify:fast  # just typecheck + lint (~30s)
```

## What each step catches that the others don't

| Step | Catches |
|---|---|
| `typecheck` | Type drift across files, missing exports, strict-mode violations (`noUncheckedIndexedAccess`, etc.) |
| `lint` | Style, hooks rules, custom `atc/*` rules (no-direct-service-role-import, no-unchecked-supabase-mutation, no-money-math, no-orphan-todo, no-narrating-comments) |
| `vitest related` | Tests that import any file you changed — content edits that break content-scanning tests (the #345 class) |
| `slop-check` | D-091 anti-patterns the lint rules don't cover (narrating comments, single-expression wrapper functions, rethrow-only try/catch) |
| `git diff` self-read | Cross-cutting concerns the tools miss: fail-open enforcement, single-layer tenant isolation, zero-row CAS, void-async without justification |

## D-091 anti-pattern checklist (for the diff read)

Per CLAUDE.md, before pushing:

- [ ] Every Supabase `.update() / .insert() / .delete() / .upsert()` either uses `safeAwait()` or destructures `{ error }` and explicit-handles
- [ ] CAS-style status guards use `safeAwaitRowCount()` with expected count, not bare `.eq("status", X)`
- [ ] No `void someAsyncFn()` without an `// allow-void-async: <reason>` justification
- [ ] No fail-open on enforcement-layer errors (Redis down, secret unset, DB error → deny, not permit)
- [ ] No `customer_context: string` body fields (server-resolve refs only — see D-103)
- [ ] Every tenant-scoped query has BOTH app-layer `.eq("tenant_id", …)` AND tenantClient RLS
- [ ] No external credentials in URLs (`Authorization: Bearer ...` headers only)
- [ ] Detector changes follow the [corpus-drift blast-radius rule](../design/corpus-drift.md): remeasure every reachable pinned target/module before editing counted baselines

## When CI catches something this didn't

Update this checklist. The point of shifting left is to keep shifting — each CI catch is a signal that this list is missing a check.

## What this does NOT cover

- **Vercel deploy preview** — CI artifact, not local-runnable
- **Playwright e2e** — too slow for pre-PR (`pnpm exec playwright test` if you really want to run it)
- **Cross-tenant probe** — `pnpm test:cross-tenant` if you touched anything tenant-isolation-shaped
- **Error injection** — `pnpm test:error-injection` if you touched supervisor / abuse / payouts machinery
