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
| **API/data** | N+1 await-in-loop, unbounded `select("*")` (no `.range()`/`.limit()`), data-fetching waterfalls, accidental dynamic rendering, missing caching | **Wired (#170):** await-in-loop and unbounded-select are `src/detectors/perf-code.ts` (§2a). Waterfalls / cache-config / dynamic rendering stay with **M9** (`src/detectors/app-router.ts`) — M7's job is to pull M9's performance-tagged findings into the §3b rows, not re-implement them | Confirm unbounded-select candidates against table size (a 3-row config table is benign) |
| **Client render/bundle** | React render waste (context value churn, inline literal props, index keys, raw `<img>`, sort-in-render, state sprawl), whole-library imports, heavy libs in client chunks, manual font links; **measured first-load JS per route / shared baseline** from a `next build` artifact | **Wired (#170):** `src/detectors/perf-code.ts` (§2a) incl. the React Compiler downgrade gate; bundle ground truth via `src/detectors/bundle-stats.ts` (§2b, ids `M7B-*`) | Turbopack builds (Next 16 default) carry no per-route manifest — the shared baseline is still measured and the attribution gap is emitted as an Info finding; per-route numbers need a bundle-analyzer re-build. Core Web Vitals (`lighthouse`) remain documented-plan-only (§3) |
| **Code hot-path** | Blocking sync I/O in request handlers, fetch-in-middleware, JSON deep-clones | **Wired (#170):** `src/detectors/perf-code.ts` (§2a) | Deeper algorithmic judgment (O(n²) over app-sized collections, "is this computation expensive") stays an [L] review-tier read during the M6 pass; flag under M7 when the concern is *speed* at scale rather than *maintainability* |

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

## 2. API/data overlap with M9

Data-fetching waterfalls (independent sequential `await`s in a Server Component),
missing/unsafe cache config, and accidental dynamic rendering are **M9's detectors**
(`src/detectors/app-router.ts`, `docs/m9-app-router.md`). M7's report step is to pull their
performance-tagged output into the §3b Performance table below (Layer = API/data) rather than
duplicating the detection. The over-fetch/pagination class that used to be a documented grep
here is now mechanical — see §2a's unbounded-select check.

## 2a. Code-level detectors — `src/detectors/perf-code.ts` (#170, [M] tier)

`detectPerfCodeFindings(files: { path, text }[])` — same TypeScript-compiler-API conventions as
the M9 detector (pass the project's full relevant `.ts`/`.tsx` set **plus** its
`next.config.*`/babel config files; no new dependency). Emits `Finding[]` with taxonomy
`M7 — …`, ids `M7C-01…`, `category: "Performance"`. Every class is gated by a
positive-caught + benign-negative-cleared fixture pair in `src/detectors/__fixtures__/perf/`
(`src/detectors/perf-code.test.ts`, enforced via `pnpm verify`) — the #61 calibration
discipline, applied where these detectors live (they run outside `runMechanicalScan`, so the
static-corpus gate doesn't see them).

**Engagement run** (also runs the M9 detectors — this CLI is the entry point for both):

```bash
pnpm detect-static <target-dir> --out findings.static.json
```

**Precision guards from the ATC dogfood run (2026-07-10, 1,130 files — raw 204 → 139 findings):**
render-once contexts (email templates by `emails/` path or `@react-email`/`@react-pdf` import,
where re-render classes don't apply and email clients *require* raw `<img>`) are skipped
entirely; files carrying an explicit `eslint-disable @next/next/no-img-element` are treated as
already adjudicated; `select("*", { head: true })` count-only queries aren't unbounded reads;
chunked-batch loops (`i += BATCH_SIZE`) are the *fix* for N+1, not the bug; and await-in-loop
rolls up to one finding per file, tiered `Likely` on the request path (`app/`/`pages/`) vs
`Review` off it (workers/jobs — job runtime, not user-facing latency).

Classes (severity / confidence — see the detector for per-check evidence and limitations):

| Class | Detects | Sev / Conf |
|---|---|---|
| Context value recreated every render | inline object/array/arrow as `<X.Provider value={…}>` | Perf / Likely |
| Inline literal prop | object/array literal props on components (rolled up, one finding per file) | Low / Review |
| Raw `<img>` | `<img>` instead of `next/image` (rolled up per file) | Perf / Likely |
| Index as list key | `key={i}` bound to the `.map()` index parameter | Low / Likely |
| Sort in render body | `.sort()`/`.toSorted()` directly inside JSX | Low / Review |
| State sprawl | ≥ 8 `useState` hooks in one component | Low / Review |
| Await in loop (N+1) | per-item independent `await` in a `for`/`for-of` (loop-carried-state and `for await` excluded) | Perf / Likely |
| Unbounded select | `select("*")`/`select()` with no `.limit()`/`.range()`/`.single()` | Perf / Review |
| Whole-library import | bare `lodash`/`moment`/`underscore`; namespace imports of known barrels | Perf / Likely |
| Heavy import in client bundle | known-heavy lib (`monaco`, `three`, `xlsx`, …) statically imported in a `'use client'` file | Perf / Likely |
| Manual font stylesheet | Google Fonts `<link rel="stylesheet">` instead of `next/font` | Low / Likely |
| Fetch in middleware | `fetch()` inside `middleware.ts` (every-request hop) | Perf / Review |
| Blocking sync I/O in request handler | `*Sync` fs/crypto/zlib/child_process calls inside a route-handler function (module-scope run-once reads exempt) | Perf / Likely |
| JSON deep-clone | `JSON.parse(JSON.stringify(x))` | Low / Likely |
| Missing hook dependencies | `react-hooks/exhaustive-deps` run programmatically (`src/detectors/hook-deps.ts`, ids `M7H-*` — the upstream rule's analysis, adapted to `Finding[]`, rolled up per file) | Low / Likely |
| Unoptimized barrel import | named imports from known-heavy barrels (`lucide-react`, `@mui/material`, …) on Next < 13.5 with no `optimizePackageImports` — version-gated so modern Next (auto-optimized) is never flagged | Perf / Likely |
| Oversized committed images / media | filesystem walk (`src/detectors/asset-weight.ts`, ids `M7A-*`): images > 500 KB, media > 5 MB, grouped worst-first into one finding per class | Perf / Review |

**React Compiler gate:** when the target's `next.config`/babel config enables React Compiler,
the manual-memo classes (context value, inline literal props) are auto-memoized at build time —
they're downgraded to `Info` (visible, not counted as work) instead of crying wolf on a
compiled codebase.

**Not in this module (deliberate):** the [B] bundle-stats classes live in §2b's separate
build-input module, and the [L] review-tier judgment calls (virtualization, lazy-load
selection, `'use client'` placed too high, Suspense boundaries) are the §6 review-pass
checklist — see #170 for the catalog history.

## 2b. Bundle ground truth — `src/detectors/bundle-stats.ts` (#170, [B] tier)

`parseBundleStats(buildDir)` consumes a real `next build` artifact (the `.next` directory —
the client runs the build, or grants repo access and we run it; same trust class as the
connected DB advisor). Metric: **gzipped first-load JS**, the same number `next build`
prints. `pnpm detect-static` picks the artifact up automatically (`<target>/.next`,
`<target>/apps/*/.next`) or via `--build <path>`, repeatable for monorepos.

- **Webpack builds** (Next ≤ 15 default): full per-route measurement from
  `app-build-manifest.json`/`build-manifest.json`. Findings: `M7B-01` routes over the
  250 KB first-load budget (worst-first, `Confirmed` — measured, not inferred) and `M7B-02`
  shared baseline over 150 KB (the floor every route pays).
- **Turbopack builds** (Next 16 default; verified against a fresh ATC build 2026-07-10):
  no per-route manifest exists. The shared baseline is still measured (`M7B-02`), and the
  per-route gap is **disclosed** as an Info finding (`M7B-03`) instead of silently skipped —
  the fix is a bundle-analyzer re-build.
- **Still deferred on #170:** duplicate-modules-across-chunks and which-dependency-ships-
  where — those need webpack stats (`@next/bundle-analyzer`), an artifact the intake can
  request but the manifest parse can't derive.

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
  waterfall/cache/dynamic-rendering findings plus `M7C-*` await-in-loop / unbounded-select;
  `render` for the `M7C-*` React classes; `bundle` for `M7C-*` import-weight classes (ground-truth
  shipped-KB numbers still come from the deferred [B] bundle-stats pass, §3).
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

## 6. Review-pass perf checklist ([L] tier, #170)

The judgment calls no mechanical detector can decide — worked during the paid LLM/review
pass (the same pass as M6/quality-extras), findings filed under M7 in §3b. For each item the
mechanical output is the *starting map*: the M7C/M7B findings say where the cost is, the
review pass says what the right structure would be.

- **Virtualization:** a list rendering app-scale collections (hundreds+ rows, no
  windowing) — is it user-visible jank, and is `react-window`-style virtualization or
  pagination the right fix here?
- **Lazy-load selection:** of the heavy-client-import candidates (M7C) and the heaviest
  routes (M7B), *which* components should actually move behind `next/dynamic` — is the
  feature behind a click, a tab, a modal? (Never lazy-load the LCP element.)
- **`'use client'` altitude:** could this client boundary sit lower in the tree (or the
  page stay a Server Component with a client leaf)? Look for layouts/pages marked
  `'use client'` whose interactivity is one widget deep.
- **Suspense/streaming boundaries:** slow data fetches with no `loading.tsx`/`<Suspense>`
  above them — should the shell stream while this blocks, or is the fetch fast enough not
  to matter?
- **Expensive compute in render:** the "is this computation actually expensive" judgment on
  render-body work the AST can't price (per-row derivations, large reduce chains) — check
  input sizes before recommending memoization.
- **Unbounded in-memory caches:** module-scope `Map`/object caches with no eviction on the
  server — real leak or bounded-by-domain?
- **PPR / Cache Components adoption (Next 15/16):** would partial prerendering meaningfully
  change the dynamic routes' profile, or is the app too session-bound for it to matter?

---

### Deferred / scoped-out follow-ups

- **Bundle-analyzer depth ([B] tier remainder, #170):** duplicate modules across chunks,
  server-only deps in client bundles, and per-route numbers on Turbopack builds — need an
  `@next/bundle-analyzer` stats artifact on top of §2b's manifest parse. Tracked on #170.
- **Web Vitals (§3):** no `lighthouse` integration — needs a real client repo and a decision on
  where it runs (staging vs. local) before it's worth the new dependency.
- **`/advisors/performance` endpoint path:** inferred by analogy, not exercised live — verify on
  the first real engagement (§1).
