# M7 performance-tuning runbook

> The "cost" third of the audit alongside M1 (security) and M3–M6 (maintainability): slow paths
> and what they cost the client, ranked by user-facing impact and mapped into §3b Performance of
> `docs/audit-report-skeleton.md`. See `docs/audit-modules.md` M7 for the one-paragraph spec this
> generalizes, and `report-template/findings.atc.json` (F-04, F-05, F-06, F-07, F-08) for a real
> prior engagement's output shape.

## 0. What's wired vs. manual vs. documented-plan-only

| Layer | Finds | Automated by | Manual / follow-up |
|---|---|---|---|
| **DB** | Unindexed FKs, unused/duplicate indexes, `auth_rls_initplan`, redundant permissive policies | `src/cli/perf-scan.ts` (`pnpm perf-scan`) — pulls the Supabase performance advisor and shapes it into `Finding[]` | Verify each fix against a test DB before recommending (index migrations, RLS rewrites) |
| **API/data** | Over-fetching (`select("*")` with no column list), missing pagination (`.range()`/`.limit()`), missing caching, data-fetching waterfalls, accidental dynamic rendering | Not mechanically wired in this module — **overlaps with M9** (App Router boundary & rendering, `docs/scan-extras.txt`), which already documents fetch-waterfall / cache-config / dynamic-rendering / unbounded-route detectors. M7's job is to pull M9's performance-tagged findings into the §3b Performance rows below, not re-implement the detection | Over-fetch/pagination-specific greps (`.select("*")` without `.range(`/`.limit(`) are a manual/grep pass for now — see §2 |
| **Client** | Bundle weight, Core Web Vitals (LCP/INP/CLS) | **Not implemented — documented plan only** (see §3). No new heavy dependency (`lighthouse` CLI) installed in this PR | Follow-up: wire `next build` output analysis + `lighthouse` CLI once a real client repo exists to run it against |
| **Code** | Inefficient hot-loop algorithms (nested loops over unbounded collections, O(n²) patterns on request-hot paths) | Not mechanically detected — heuristic, human-judgment-heavy | Manual read during the M6 (`/simplify`, `docs/quality-extras.txt`) pass; flag under M7 rather than M6 when the concern is *speed* at scale rather than *maintainability* |

## 1. Running the DB advisor scan

```bash
SUPABASE_ACCESS_TOKEN=sbp_... pnpm perf-scan <client-project-ref> --out findings.perf.json
```

This calls the Supabase Management API's performance advisor for the client's project
(`GET /v1/projects/{ref}/advisors/performance` — same family as the `get_advisors` MCP tool with
`type: "performance"`) and shapes each returned `lints[]` entry into `Finding[]`
(`src/perf-scan.ts`'s `parseAdvisorFindings`; `src/cli/perf-scan.ts` wraps it with the API call
and file I/O, mirroring the `src/quality-scan.ts` / `src/cli/quality-scan.ts` split for M4–M5).

- **Requires:** a Supabase personal access token
  (https://supabase.com/dashboard/account/tokens) scoped to the client's project — ask the
  client to mint one for the engagement rather than reusing a personal token across clients.
- **Grouping:** one `Finding` per advisor rule name, not per row — a real engagement can surface
  100+ unindexed FKs, and the report should read "124 unindexed foreign keys, here's the
  migration," not 124 near-identical rows. Groups are sorted worst-first (highest instance
  count). `M7-01`, `M7-02`, … ids.
- **Curated rules** (severity/value/ease/safety scored from a real prior engagement — see
  `report-template/findings.atc.json` F-04/F-05/F-07 — rather than guessed):
  - `unindexed_foreign_keys` → **Perf**, `value 4 / ease 5 / safety 5`. Sequential scans on
    parent UPDATE/DELETE and FK JOINs. Fix: additive covering-index migration (safe — an index
    add can't break existing queries).
  - `auth_rls_initplan` → **Perf**, `value 4 / ease 4 / safety 4`. `auth.*` calls re-evaluated
    per row in an RLS policy. Fix: wrap in `(select …)` — verify the rewritten policy is
    behavior-identical before shipping (this is why safety is 4, not 5 — it's a policy edit, not
    a pure addition).
  - `unused_index` → **Low**, `value 2 / ease 2 / safety 3`. Write/storage overhead, not a
    hot-path cost — hence Low, not Perf. Fix: `DROP INDEX CONCURRENTLY` after confirming the
    index doesn't back a rare-but-critical path or enforce a `UNIQUE` constraint (state
    OK-when/not-OK-when per `docs/audit-report-skeleton.md` §3 — this is a context-dependent call).
  - `multiple_permissive_policies` → **Perf**, `value 3 / ease 3 / safety 3`. Every permissive
    policy for the same role+action is evaluated — redundant ones multiply per-row cost.
  - `duplicate_index` → **Low**, `value 2 / ease 4 / safety 4`. Wasted storage/write throughput,
    no query benefit.
  - Any other rule name Supabase adds later still produces a `Finding` — it falls back to a
    severity derived from the advisor's own `level` (`ERROR`→High, `WARN`→Perf, `INFO`→Low)
    rather than being silently dropped, per the "never leave a known gap untracked" doctrine.
- **Not yet independently verified:** the `/advisors/performance` Management API path is inferred
  by analogy with the documented `/advisors/security` path and the `get_advisors` MCP tool's
  `type` parameter — it wasn't exercised against a live project while writing this module (no
  client project available yet). Confirm against current Supabase docs or a dashboard
  Network-tab capture before the first live engagement run; flag as a risk if the shape drifts.

## 2. API/data static heuristics (documented method, not wired here)

Two sub-classes:

- **Already covered by M9** (`docs/scan-extras.txt` M9 section): data-fetching waterfalls
  (independent sequential `await`s in a Server Component), missing/unsafe cache config, and
  accidental dynamic rendering (`searchParams`/`headers()`/`cookies()` read high in the tree).
  When M9's static detectors land, M7's report step is to pull their output into the §3b
  Performance table below (Layer = API/data) rather than duplicating the detector.
- **Not yet covered anywhere — over-fetching / missing pagination.** Method for a future pass:
  grep Supabase query builder calls for `.select("*")` (or `.select()` with no column list)
  paired with no `.range(`/`.limit(` on a table that isn't known-small, and for API routes that
  return an array with no page/cursor param. Flag as candidates, not confirmed findings — the
  same static-heuristic caveat as M9's detectors (confirm before reporting; a `select("*")` on a
  3-row config table isn't a finding).

## 3. Client: bundle weight & Core Web Vitals (documented plan — deferred)

**Deliberately not wired in this PR** — this audit module doesn't yet have a real client repo to
run it against, and both pieces below pull in a dependency Harvey doesn't currently have
installed (`lighthouse`), which the issue scoping this module explicitly said to avoid unless a
real run justifies it. Tracked as a follow-up rather than silently skipped:

- **Bundle weight:** run `next build` and parse its stdout/`.next/build-manifest.json` for
  first-load JS per route; flag routes over a threshold (e.g. 200 KB first-load JS) and the
  largest contributing chunks. No new dependency — this is Next's own build output.
- **Core Web Vitals / Lighthouse:** run the `lighthouse` CLI against a running instance of the
  client's app (staging or authorized local), capture LCP/INP/CLS/TBT, and flag pages below
  Google's "Good" thresholds. Requires `lighthouse` (npm) + a headless Chrome, and a running
  target — meaningfully heavier than the rest of Harvey's toolchain (which mostly shells out to
  already-installed CLIs or does static analysis). **Scoped out of this PR**; wire it once a real
  client engagement needs it, following the `src/perf-scan.ts` pure-transform + thin-CLI-wrapper
  pattern established here.

## 4. Mapping into the report (§3b Performance of `docs/audit-report-skeleton.md`)

`findings.perf.json` merges into the client's engagement `findings.<client>.json` (alongside
M1–M6 findings and `meta`) — copy the array entries in, adjust confidence/severity after triage
if the mechanical default doesn't match your read, then
`pnpm validate:findings findings.<client>.json` before rendering.

The skeleton's §3b Performance table is `Finding | Layer (DB/API/render/bundle) | Impact | Fix |
Effort` — map:

- **Layer:** `DB` for every `M7-*` id from `pnpm perf-scan`; `API/data` for M9-sourced
  waterfall/cache/dynamic-rendering findings and any manual over-fetch/pagination read; `bundle`
  / `render` reserved for the deferred Web-Vitals/bundle pass (§3).
- **Impact:** the `Finding.impact` field, as written by `parseAdvisorFindings` for DB rows.
- **Fix:** the `Finding.fix` field.
- **Effort:** derive from `ease` (1–2 → multi-day/week, 3 → ~a day, 4–5 → quick) — the skeleton's
  Performance table doesn't carry BFTB directly, but every `M7-*` finding still gets a BFTB score
  for §1.6 Top bang-for-the-buck the same as every other module.

Anchor example (from the real prior engagement dogfooded in this repo): 124 unindexed FKs → a
single additive covering-index migration (BFTB 80 — cheap, safe, high value); 50
`auth_rls_initplan` hits → wrapped in `(select …)` (BFTB 51 — a policy edit, so safety is 4 not
5). Both advisor-surfaced, both verified against a test DB before being marked fixed.

## 5. Wiring code

- `src/perf-scan.ts` — pure transform: `parseAdvisorFindings`. Tested against a fixture shaped
  from the Management API's documented advisors response (`src/perf-scan.test.ts`) — grouping,
  per-rule severity/BFTB mapping, the unknown-rule fallback, and location list capping are all
  covered with assertions on actual output, not just "it doesn't throw."
- `src/cli/perf-scan.ts` — the CLI: calls the Management API with a caller-supplied access token
  and project ref, calls the pure transform, writes/prints the merged `Finding[]`. Registered as
  `pnpm perf-scan` in `package.json`. Not unit tested (network I/O), matching the existing split
  in this codebase between tested pure transforms and untested thin I/O wrappers.

---

### Deferred / scoped-out follow-ups

- **Bundle/Web-Vitals (§3):** no `lighthouse` integration in this PR — needs a real client repo
  and a decision on where it runs (staging vs. local) before it's worth the new dependency.
- **API/data over-fetch/pagination heuristic (§2):** documented method only; not yet a grep
  script. Low effort to add once M9's detector scaffolding exists, to share conventions.
- **`/advisors/performance` endpoint path:** inferred by analogy, not exercised live — verify on
  the first real engagement (§1).

