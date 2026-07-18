# Portability audit — provision-or-degrade for a cold third-party target (#512)

Several modules only ever ran end-to-end against ATC, and ATC is our own well-equipped repo: it
already had a StrykerJS config, a live Supabase test DB, two-tenant seed fixtures, and its own
cross-tenant suite. A cold client engagement hands us **a repo and nothing else** (validation
mode), or **a repo plus a read-only DB grant** (paid). This doc enumerates, per module, what the
audit assumes exists beyond Harvey's own checkout, who provides it, how Harvey provisions it for
a cold target, and what the honest degrade is when provisioning fails.

Every row below was grounded by reading the probe/runner code on 2026-07-17 (file references in
each row). Where a behavior could not be exercised here (vitals, live DB, Stryker), the row says
so — per the repo doctrine, an unverified recorded reason must be re-tested before you build on
it.

## Principle

Anything that "worked" on ATC because ATC provided the asset must be re-checked against a target
that provides nothing. An ATC-specific asset must never become an unstated prerequisite, and a
missing asset must never become a silent skip: the ledger records `partial` /
`requires-live-run` **with the reason** (CLAUDE.md coverage guard), and where a sub-pass inside
a module can void, it emits a disclosure finding (M5-00, M7L-00, M8-00, DEP-OSV-00) rather than
an empty result.

## Asset classes

A cold engagement has three distinct provisioning surfaces. The issue's focus is (2), but a
cold-target story that omits (1) or (3) still silently drops tiers, so the table covers all
three:

1. **Operator/Harvey-side** — tools on the scanning machine: semgrep, trufflehog, gitleaks,
   osv-scanner (mechanical tier); jscpd/knip (Harvey's own `node_modules/.bin`, no client
   install — `src/cli/quality-scan.ts`); the vitals plugin; Docker + Supabase CLI (M2);
   Chrome/Playwright chromium (M7 Lighthouse); network egress (TruffleHog verification, OSV,
   npm-registry slopsquat/license checks).
2. **Target-provided** — what must be IN or true of the repo we were handed: lockfile,
   `package.json`, real git history, `supabase/migrations/`, a runnable test suite, a Stryker
   config, a buildable app.
3. **Client-granted** — credentials only the client can mint: read-only `SUPABASE_DB_URL`,
   a scoped `SUPABASE_ACCESS_TOKEN`, a project ref.

## Per-module dependency table

Ledger statuses are what `src/audit-runners.ts` actually records today (read 2026-07-17), not
aspirations. "Pass artifact" = the `<module>.pass.json` mechanism (`pnpm record-pass`,
`docs/design/audit-pass-artifacts.md`); note the artifact's `target` must equal the audited
directory string exactly (`src/audit-pass-artifact.ts`), so record the pass with the same
absolute path `run-audit` will be given.

| Module / tier | Needs (who provides) | Provision path for a cold target | Degrade path | Ledger status |
|---|---|---|---|---|
| **M1 mechanical** (`quick-scan`) | semgrep/trufflehog/gitleaks/osv-scanner + network (operator); lockfile, `package.json`, real `.git` at repo root (target) | Install binaries on the scanning machine; clone the repo with full history (not a tarball/shallow clone) | Missing semgrep/trufflehog/gitleaks binary → the scan **throws**, probe records the reason (fail-loud). Missing/failed osv-scanner → **DEP-OSV-00 disclosure finding** (#512, was a silent empty result). No lockfile → OSV pass skipped but SUP-NO-LOCKFILE finding fires (`src/scan/supply-chain.ts`). No `.git` repo root → git-history secret pass degrades to the **SEC-TH-GH-00 disclosure finding** (#528, was a silent empty result). No `package.json` → supply-chain checks silently skipped (`src/scan/mechanical.ts` `if (pkg)`) — acceptable only because a Next.js target always has one | `partial` always under the orchestrator (mechanical tier alone, #311) |
| **M1 config** (`scan.ts --supabase`) | `SUPABASE_ACCESS_TOKEN` + project ref (client), or a local stack | Client mints a scoped token; or run against the M2 local stack (`--supabase local`) | Not run → covered by M1's standing `partial` reason | folded into M1 `partial` |
| **M1 semantic** (LLM `/vuln-scan → /triage`) | paid-LLM tier (operator) | Operator/skill pass; `pnpm record-pass` emits M1.pass.json | No artifact → `partial` with the #311 reason; stale/wrong-target artifact → rejected with reason | `ran` only via fresh pass artifact |
| **M1 live** (`detect-deeper`) | read-only `SUPABASE_DB_URL` (client) | Client mints a read-only connection string (see `docs/runbooks/connected-access-hardening.md`) | No creds → mechanical-only `partial` | folded into M1 |
| **M2 dynamic** (`pentest.ts`) | NOTHING from the client beyond the repo — Harvey stands up its OWN stack: Docker + Supabase CLI (operator); `supabase/` config + migrations + a buildable app (target); two-tenant seed + HARVEY_* env harness (Harvey provisions — **the ATC-specific piece**, #514) | `pnpm dynamic-validate <repo>` assesses stand-up-ability (GO/NO-GO with limitations); `--execute` runs `supabase start` → `db reset` → build → pentest and writes M2.pass.json only on success (`src/cli/dynamic-validate.ts`). Generic two-tenant seeding is the open provisioning work: #514 (generalize seed/fixtures), #508 (monorepo migration discovery/wiring) | Missing Docker/CLI or failed stand-up → reasoned failure, **no artifact, exit 1** — never a silent pass. Under the orchestrator M2 is `requires-live-run` with reason (a `--dynamic` flag is a claim, not evidence, #356) | `requires-live-run` until a fresh M2.pass.json exists |
| **M3 hotspots** (`hotspot-scan.ts`) | vitals plugin on PATH (operator, #507 — discovery is PATH-only today); the target's **git history** for churn/co-change (target — so the engagement must receive a full clone, not a zip/shallow clone; recorded in #512, **not re-verified here**: vitals is not on PATH in this environment, #357); optional `.vitals` provenance DB (target — absent is normal for a cold target) | Install vitals where the scan runs, or run vitals elsewhere and replay via `--report <capture>` (#314) or an M3 pass artifact | vitals missing/failed → exit 1, probe records `requires-live-run` with the reason (`src/audit-runners.ts` m3). Absent provenance DB → "AI-provenance: no data" stated in output, never silent (`src/cli/hotspot-scan.ts`) | `ran` only with a real table or fresh pass artifact |
| **M4 duplication** (`quality-scan`) | Nothing from the target beyond source — jscpd + diverged-clone pass run from Harvey's own node_modules | None needed | Known hazard: whole-monorepo runs can hang → run per-workspace + timeout→partial (#505, open) | `ran` (jscpd genuinely executes on exit 0, #350) |
| **M5 dead code** (knip via `quality-scan`) | Target's installed deps — `node_modules` (target/provisioned) | **Harvey runs the install** in the target, with `npm install --ignore-scripts` as the standard for untrusted cold repos — the M1 supply-chain pass exists precisely because install scripts of an unvetted repo are an execution vector. **Measured 2026-07-18 (#531)** against `boxyhq/saas-starter-kit` (real Prisma+jest target): knip's JSON output (files/issues) and `quality-scan`'s M4+M5 findings were byte-for-byte identical between `--ignore-scripts` and a normal install, even though `--ignore-scripts` skips `@prisma/client`'s own postinstall (`prisma generate`) and leaves `node_modules/.prisma/client` entirely absent — knip's config/plugin-import resolution doesn't need the generated client. `--ignore-scripts` is now the confirmed default for the install step | Probe pre-checks `node_modules` → `requires-live-run` with install instruction; knip crash mid-run → **M5-00 disclosure finding**, M4 keeps its findings (#223), probe reads M5-00 → `partial` (#350) | `partial`/`requires-live-run` until deps installed |
| **M6 maintainability** | Free indicators: source only (detect-static). Paid verdict: LLM/human reviewer (operator); `package.json` manifests (target — absent → packet says the dependency-tree class is unverifiable, `src/cli/simplify-scan.ts`) | Reviewer pass over the `simplify-scan` packet, then `pnpm record-pass` M6.pass.json | No LLM tier → `partial` on indicators alone (#397); packet built but no verdict → `partial` (#351); no source files → `requires-live-run` | `ran` only via fresh verdict artifact |
| **M7 code tier** (`detect-static`) | Source only | None | 0 files scanned → `requires-live-run` (#350) | `ran` |
| **M7 advisors** (`perf-scan`) | `SUPABASE_ACCESS_TOKEN` + project ref (client) | Client mints scoped token; pass `run-audit --supabase <ref>` | No `--connected` → `partial` "code tier only"; `--connected` without ref → `partial` (#434); advisor call fails → `partial` with reason. Advisors endpoint marked experimental — confirm before first live run (`src/cli/perf-scan.ts` header, unexercised success path #357) | `partial` until connected + ref |
| **M7 Lighthouse** (`lighthouse-scan`) | Buildable+servable target: installed deps, working `npm run build`/`start` (target/provisioned); **a system Chrome** (operator — the Playwright "Chrome for Testing" build NO_FCPs, see below) | Harvey installs deps, builds, serves locally (#387) — or `--url` at an already-running instance | Build/serve/browser failure → **M7L-00 disclosure finding**, exit 0. **Validated end-to-end 2026-07-18 (#488)** against `vandyand/saas-security-teardown`: install → `next build` → `next start` → Chrome → Lighthouse → real `M7L-01` LCP finding (`/security` 3.1s, `/dashboard` 2.6s). Two live bugs fixed: (a) a NO_FCP/errored run silently reported "0 findings" (false clean) — now surfaced as M7L-00 via `lighthouseRunErrorReason`; (b) the default browser (Playwright chromium) NO_FCPs — the CLI now prefers a system Chrome, Playwright is fallback-only. Details: `docs/design/m7-lighthouse-validation.md`. **Orchestrator gap unchanged:** `run-audit`'s M7 probe still never invokes the Lighthouse tier, and an advisors-success M7 reads `ran` without mentioning the unmeasured CWV tier — follow-up filed from #512 | not represented in the M7 ledger row today |
| **M7 bundle [B]** (`detect-static --build/--stats`) | A `next build` artifact `.next` (provisioned: build the target); analyzer stats JSON (optional) | Build the target after installing deps | No build artifact → "[B] findings skipped" stated on **stdout only** — not a finding, not in the ledger (minor; disclosed but not durable) | folded into M7/M9 `ran` |
| **M8 test-intent** (`detect-static`) | Source only, including test files — **no installed deps** (#401) | None | 0 files → folded into the M8 no-deps reason | contributes to `partial` |
| **M8 stub-check** (`mutation-scan --stub-check`) | Runnable test suite: installed deps + a working `npm test` (target; `--test-cmd` overridable) | Harvey installs deps and verifies the suite runs green first (an env-dependent suite voids the run — detect/replicate the target's test env, #503). **Measured 2026-07-18 (#531)** against `boxyhq/saas-starter-kit`: `npx jest` and `mutation-scan --stub-check` produced identical results (same tests passed, same stub-check findings) under `npm install --ignore-scripts` vs. a normal install — the target's one jest unit spec (`__tests__/lib/server-common.spec.ts`) never touches the Prisma client, so the skipped `prisma generate` postinstall had no effect here. **Re-confirmed 2026-07-18 (#540):** boxyhq still has no covered test that imports generated codegen, so this case remains unmeasured *on a real covered suite* — reported honestly rather than papered over. To characterize the failure mode directly, a throwaway probe spec (`import { prisma } from '../../lib/prisma'`, run once and deleted, never part of the target's covered suite) was added to the same clone: under `--ignore-scripts` (no `.prisma/client`) the suite doesn't fail a test, it fails to load at all — `Cannot find module '.prisma/client/default'` — a load-time crash for every spec file that transitively imports the generated client; running `npx prisma generate` first (no live DB needed) fixes it and the suite passes. Practical conclusion: a target whose *actual* covered tests import a generated client will void under `--ignore-scripts` alone; the fix is the same targeted codegen step as the M7 build case below, run once before `npm test`/`mutation-scan` | No covered source files → "nothing was checked; this is NOT a clean result" on stderr | operator-run today (not probed by orchestrator) |
| **M8 Stryker** (`mutation-scan`) | Stryker config for the target's own runner + `stryker` binary installed in/alongside the target + a passing suite (target — **most cold clients have none of these**; ATC did) | Scaffold a config per detected test runner / setup-assisted engagement — companion #513; scoped runs must record `partial` with scope, never `ran` (#504) | No suite/config/test script → **M8-00 zero-coverage finding + `partial` moduleRecord**, exit 0 (#224/#252); missing binary after that gate → throws with install instruction (`src/cli/mutation-scan.ts` runStryker) | `partial` (no suite) / `ran` (real report) |
| **M9 App Router** (`detect-static`) | Source only | None | 0 files scanned → `requires-live-run` (#350) | `ran` |
| **M10 schema tier** (`pii-classify --schema`) | `supabase/migrations/` in the repo (target). The orchestrator probe hardcodes that path (`src/audit-runners.ts` m10); the CLI itself accepts any dir or a single `.sql` — a client on Prisma/Drizzle/pg_dump can be covered by pointing `--schema` at their schema SQL manually | Ask the client for a schema dump when there is no `supabase/migrations/` (no DB access needed — column names/types only) | No migrations and no DB → `requires-live-run` "nothing to classify"; schema tier always `partial` (rows not sampled) | `partial` |
| **M10 live** (`pii-classify`) | Read-only `SUPABASE_DB_URL` (client) | Same credential as M1 live | Connection failure → `requires-live-run` with the error (success path unexercised in CI, #357) | `ran` |

## Cold-engagement provisioning sequence (repo-only, validation mode)

What Harvey does to a bare clone before `run-audit`, in order — each step unlocks the tier named:

1. **Full-history clone** at a pinned commit — unlocks git-history secrets (M1) and vitals churn (M3).
2. `npm install --ignore-scripts` in the target (confirmed default, see M5 row) — unlocks M5 (knip), M8 stub-check/Stryker candidacy, M7 Lighthouse/bundle builds. Two builds were measured:
   - **`vandyand/saas-security-teardown` (2026-07-18, #488/#540):** `next build` succeeds identically under `--ignore-scripts` and a normal install (same route table, same 12 static pages) — but this target has no postinstall codegen (deps: `@supabase/*`, `next`, `react`, `ws`), so it didn't exercise the codegen case.
   - **`boxyhq/saas-starter-kit` (2026-07-18, #540, the codegen-dependent case):** cloned fresh into two dirs, one `npm install --ignore-scripts`, one plain `npm install`. Under `--ignore-scripts`, `@prisma/client`'s own postinstall (`prisma generate`) never runs and `node_modules/.prisma/client` is entirely absent; running `npx next build` directly then **FAILS**: `Type error: Module '"@prisma/client"' has no exported member 'Session'` (the generated type declarations don't exist). Under a normal install `.prisma/client` is present automatically and `npx next build` succeeds outright (full route table, all static/dynamic pages). **Recovery confirmed:** running `npx prisma generate` on the `--ignore-scripts` install (schema-only — no live `DATABASE_URL` connection needed, just `prisma/schema.prisma`) populates `node_modules/.prisma/client`, and the same `next build` then succeeds with an identical route table to the normal install.

   **Verdict (closes #540 case 1):** `npm install --ignore-scripts` alone is unsafe for a build that depends on postinstall codegen — the fix is a mandatory step 2a: after the ignore-scripts install, run the target's codegen command explicitly (`npx prisma generate` for Prisma; the analogous codegen command for GraphQL-codegen/other generators) *before* `next build`/M7's build tier or any M8 suite whose covered tests import the generated client (see M8 stub-check row — same failure mode, same fix, measured on the same target). Detecting which codegen command to run: check `package.json` `scripts.build` / `scripts.postinstall` for a `prisma generate`-shaped step, or the presence of `prisma/schema.prisma`.
3. `next build` (where the app builds) — unlocks M7 bundle tier and Lighthouse serve.
4. `pnpm dynamic-validate <t>` — GO/NO-GO on standing up M2; `--execute` on GO.
5. Operator passes (M1 semantic, M6 verdict, M3 vitals where installed) → `pnpm record-pass` artifacts.
6. `run-audit <t> --llm --dynamic --artifacts-dir <dir> --findings-out …` — the ledger then derives `ran`/`partial`/`requires-live-run` from evidence, never from intent.

Paid adds the client-granted credentials (read-only DB URL, scoped access token + ref) and
`--connected`.

## Gaps this audit found (beyond the companion issues)

- **osv-scanner silent void — FIXED in this PR.** `runOsvScanner` returned `{}` on any failure
  without stdout, including a missing binary: zero CVE findings, no disclosure, in every tier
  that runs the mechanical scan. Now degrades to the `DEP-OSV-00` disclosure finding
  (`src/scan/dependencies.ts`, `src/scan/mechanical.ts`).
- **Git-history secrets silently unassessed for non-git delivery — FIXED (#528).** A target
  delivered as a zip/subdirectory made `runTruffleHogGitHistory` return `[]` with no disclosure
  (`src/scan/secrets.ts`). Now degrades to the `SEC-TH-GH-00` disclosure finding when
  `isGitRepoRoot` trips, same contract as `DEP-OSV-00`/`M5-00`.
- **M7's ledger row can read `ran` while the Lighthouse tier never executed** (see M7 Lighthouse
  row). Follow-up.
- **M7 bundle-tier skip is stdout-only** (see M7 bundle row) — low priority; the skip is at
  least printed.
- **`run-audit`'s M10 schema discovery only knows `supabase/migrations/`** — a schema dump
  elsewhere needs a manual `pii-classify --schema` run today. Follow-up (small).

## Companion issues (the per-module code work)

#502 (M3→M1-LLM sequencing) · #503 (M8 target test env) · #504 (scoped mutation = `partial`) ·
#505 (M4/M5 monorepo hang → per-workspace + timeout) · #506 (monorepo target enumeration) ·
#507 (M3 vitals PATH-only discovery) · #508 (M2 monorepo migrations/seed) · #513 (M8 Stryker
config scaffolding) · #514 (M2 generic two-tenant stack/seed/pentest generalization) ·
#488 (M7 Lighthouse end-to-end) · #159/#161 (M2 live pipeline operator runs).
