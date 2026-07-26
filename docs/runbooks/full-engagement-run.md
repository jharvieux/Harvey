# Full engagement run — the correct end-to-end sequence

Operator runbook for a real (monorepo) engagement: the ten-module audit against a target that
was NOT built for Harvey (unlike `targets/calibration` or Harvey's own repo). Written after the
2026-07-17 ATC dry run (Harvey issue #511) got the ordering, per-app/per-DB fan-out, and M2
stand-up wrong; those gaps are now code (see the companion-issue list at the end), and this doc
is the human sequence that ties them together. It complements, not replaces:

- `docs/runbooks/engagement-access.md` — what to request from the client and when, and the
  delivery-gate coverage rules.
- `docs/design/audit-pass-artifacts.md` — the `<module>.pass.json` mechanism used throughout.
- `docs/design/portability-cold-target.md` — per-module dependency table for a cold (no
  ATC-style prior setup) target; read it if a module's provisioning step below is unclear.
- CLAUDE.md's module table — authoritative on which command runs which module; this doc is
  authoritative on the *order* and the *monorepo fan-out*.

All ten modules carry equal weight in the deliverable — this sequence is not "security first,
quality later"; it interleaves because of real data dependencies (M3's hotspot ranking feeds the
M1 semantic pass and M6's verdict), not priority.

## 0. Enumerate the target

Before anything else, discover what the engagement is actually auditing:

```bash
pnpm exec tsx src/cli/pentest.ts --mode=coverage --repo <target-dir> --tested "" 2>&1 | head -1
```

(or read `discoverTargets` output directly — `src/pentest/targets.ts`). This lists every
workspace **app**, every distinct **Supabase backend** (by env-var convention), and every
inter-service **seam**. Confirm the list against the client's own account of their topology
(`docs/runbooks/engagement-access.md` step 3) — a workspace or backend the target enumeration
misses is a target the whole audit silently skips.

`run-audit` (below) re-runs this enumeration itself for the per-app tiers (M4/M5/M9, M10
schema) and per-DB M7 advisors — you don't need to hand it the list, but you DO need to know it
going in so you can tell if `run-audit`'s own "Monorepo apps enumerated" line looks short.

## 1. Preflight — target install, binaries present

Two separate provisioning surfaces (`docs/design/portability-cold-target.md` §"Asset classes"):

**Operator-side tools** (install once, on the scanning machine, not per engagement):
`semgrep`, `trufflehog`, `gitleaks`, `osv-scanner` (M1 mechanical); the vitals plugin, discovered
via PATH or known plugin-install locations (#507; M3); Docker + the Supabase CLI (M2); Chrome or
Playwright's bundled chromium (M7 Lighthouse). A missing mechanical-tier binary makes the scan
**throw** — fail loud, don't run partially provisioned.

**Target-side install** (per engagement, in the cloned repo):

```bash
git clone --no-single-branch <repo-url> <target-dir>   # FULL history — a shallow/zip delivery
                                                         # silently voids M1 git-history secrets
                                                         # and M3 churn/co-change signal
cd <target-dir> && npm install --ignore-scripts         # (or pnpm/yarn install per the target's
                                                         # own lockfile) — unlocks M5 (knip needs
                                                         # the target's own node_modules to resolve
                                                         # config/plugin imports), M8 stub-check/
                                                         # Stryker candidacy, M7 Lighthouse/bundle
```

`--ignore-scripts` is the standard for an untrusted cold repo (install scripts of an unvetted
repo are the exact execution-vector class M1's supply-chain checks flag). **Measured 2026-07-18
(#531)** against `boxyhq/saas-starter-kit`: knip's output and the M8 stub-check's results were
identical with and without `--ignore-scripts`, even though it skips `@prisma/client`'s postinstall
codegen — see `docs/design/portability-cold-target.md`'s M5/M8 rows for the detail and the one
caveat (a target whose covered tests import a generated client, unlike this one, is unmeasured).
M7 Lighthouse/bundle builds under `--ignore-scripts` are also still unmeasured — a `next build`
can depend on postinstall codegen in ways M5/M8 did not here.

If the target is a monorepo, `npm install` at the workspace root is normally sufficient (pnpm/npm
workspaces hoist), but confirm — a workspace with its own lockfile needs its own install.

**Detect the target's test environment** before any tier that runs the target's own tests
(M5 knip config resolution, M8 stub-check/Stryker). `src/mutation-scan.ts`'s `detectTestEnv`
already does this for M8 automatically — it reads `TZ`/`LANG`/`LC_ALL` out of the target's CI
workflow (`.github/workflows/*.yml`), `package.json` test scripts, and vitest/jest setup files,
and replicates the detected env when invoking Stryker or `--stub-check` (#503). You do not need
to hand-set these — `mutation-scan` and `--stub-check` do it themselves — but if a `--stub-check`
or Stryker dry run fails, check the emitted finding: it names the detected env var and its
source file (e.g. `TZ=Pacific/Honolulu (from ci.yml)`), which is almost always the actual root
cause (this is precisely the ATC failure mode this runbook exists to prevent repeating).

## 2. Free / mechanical pass

```bash
pnpm run-audit <target-dir>
```

This is `pnpm exec tsx src/cli/run-audit.ts <target-dir>` (aliased in `package.json`). With no
flags it runs every module's **source-only** tier and derives a coverage ledger from what each
probe actually reported — it does not skip a module, it records `partial`/`requires-live-run`
with a reason for tiers that need an environment not yet in scope. On a monorepo it:

- enumerates the workspace apps (#506) and fans M4/M5/M9 (and M10's schema tier) out **once per
  app**, one ledger row each — a per-workspace hard timeout keeps one hung workspace (jscpd/knip
  stalling on a root it doesn't recognize, #505) from taking the whole run down; a workspace that
  times out records its own `partial`, the rest still complete;
- prints an **execution plan** (`buildExecutionPlan`, #502) naming every out-of-orchestrator pass
  in the correct dependency order — read it now, it is the answer to "what do I run next and in
  what order" for the rest of this doc.

Read the printed coverage table. Every module should show `ran` (mechanical scope), `partial`
(some classes ran, reason given), or `requires-live-run` (reason given) — never a missing row.

## 3. Operator/LLM passes — in dependency order

`run-audit` cannot run these itself (they're operator/skill passes, not CLI subprocesses), but it
printed their correct order in step 2's execution plan. **Do not run the M1 semantic pass before
M3** — that silently un-prioritizes it (the ATC engagement's actual mistake). The chain:

### 3a. M3 vitals hotspots (first — everything downstream reads its ranking)

```bash
pnpm exec tsx src/cli/hotspot-scan.ts <target-dir> --hotspots-out hotspots.txt --out M3.json
```

Wraps the external `vitals_cli.py report --json` plugin. If vitals isn't on PATH, pass
`--report <capture>` from wherever it did run (#314). Produces `hotspots.txt`, which both the M1
semantic focus brief and M6's `simplify-scan --hotspots` consume next.

### 3b. M1 semantic focus brief, then the LLM pass

```bash
pnpm scan-focus hotspots.txt --out focus.md
/vuln-scan --extra briefs/scan-extras.txt --extra focus.md
/triage --fp-rules briefs/fp-rules.txt
```

`scan-focus` must run after M3 (it reads `hotspots.txt`); `/vuln-scan` must run after
`scan-focus` (it reads `focus.md`). Running `/vuln-scan` without the hotspot focus still produces
findings, just un-prioritized against the hottest files — the exact ATC-run defect.

### 3c. M6 maintainability verdict (also depends on M3)

```bash
pnpm simplify-scan <target-dir> --hotspots hotspots.txt --out packet.md
```

This assembles a review **packet**, not a verdict — a human or LLM reviewer reads `packet.md`
and produces the actual triage (which indicators are genuine reinventions, and what to name as
the replacement). Printing the packet is not running M6 (#351); the reviewed verdict is the
thing that clears M6's `partial` status.

### 3d. Bank each pass as evidence

Every out-of-orchestrator pass above needs to leave a `<module>.pass.json` so a later `run-audit`
run can derive `ran` from evidence instead of staying honestly not-run:

```bash
pnpm record-pass --module M1 --target <target-dir> --pass semantic --out <artifacts-dir> \
  --findings vuln-scan-findings.json --summary "42 findings, 7 high" --hotspot-focus
pnpm record-pass --module M6 --target <target-dir> --pass verdict --out <artifacts-dir> \
  --summary "reviewed packet.md — 3 confirmed reinventions"
```

`--target` must equal the exact path string `run-audit` will be given (`docs/design/
audit-pass-artifacts.md`); a mismatched or stale (>30 days) artifact is rejected, not silently
accepted.

## 4. Dynamic M2 — stand up Harvey's own two-tenant stack

M2 needs nothing from the client beyond the repo — Harvey stands up its **own** local Supabase
stack, it never touches the client's database:

```bash
pnpm dynamic-validate <target-dir>              # GO/NO-GO assessment, no side effects
pnpm dynamic-validate <target-dir> --execute     # supabase start → db reset → build → pentest,
                                                  # writes M2.pass.json only on success
```

`--execute` runs the full stand-up-and-probe cycle and only banks the pass artifact on success —
a failed stand-up is a reasoned failure with a non-zero exit, never a silent pass. See
`docs/runbooks/m2-pentest-ops.md` for the manual stand-up steps, safe-scope rules (local-only by
default, `--allow-non-local` needs separate written authorization, destructive probes need
`--allow-destructive` and run only against the disposable seed), and how to interpret
explore/verify output.

Once every enumerated app/backend/seam has a recorded test result, confirm completeness:

```bash
pnpm exec tsx src/cli/pentest.ts --mode=coverage --repo <target-dir> --tested <id,id,...>
```

This throws, naming any enumerated target `--tested` didn't cover — the M2-specific version of
the coverage guard.

### 4a. External targets — an app Harvey did not provision (#965)

When the engagement gives you a **running** app rather than a repo Harvey can stand up — a
non-Supabase API, another language, a staging URL — use the external runner instead of
`dynamic-validate`:

```bash
pnpm exec tsx src/cli/pentest.ts --mode=external \
  --app-url <origin> \
  --openapi <spec.json> \            # or --routes <routes.json>; at least one must yield a route
  --victim-token <jwt> --attacker-token <jwt> \
  --victim-id <scope-value> --attacker-id <scope-value> \
  [--admin-token <jwt>] [--victim-object-id <id>]... [--id-key <name>]... [--scope-key <name>]... \
  [--allow-destructive] [--allow-non-local] [--out <file>]
```

**Every flag above the optional block is REQUIRED — the run throws before it sends a single request
if any is missing.** Two real identities are genuinely needed: a BOLA cannot be proven with one.

- `--victim-token` / `--attacker-token` — a live bearer token for each of two real accounts on the
  target. The attacker is the identity that must NOT be able to reach the victim's objects.
- `--victim-id` / `--attacker-id` — each identity's **owning-scope value as it appears in the
  target's RESPONSES** (crAPI: the user's email; a tenant app: the tenant uuid), not an internal row
  id. This is what the leak-confirmation predicate matches on, so a value that never appears in a
  response body makes every verdict unprovable.
- `--openapi` **or** `--routes` — the run needs at least one route. `--openapi` ingests a spec;
  `--routes` takes a hand-written `DiscoveredRoute[]` JSON file for a target with no spec. Supplying
  both merges them.
- `--admin-token` is genuinely optional: pass it to add a third, privileged identity so BFLA-ADMIN
  has a real admin to compare against; omit it and that class simply reports not-applicable.
- `--victim-object-id` seeds the foreign ids directly when the victim's own collection routes do not
  expose them; `--id-key` / `--scope-key` name the target's own identity/ownership fields (crAPI's
  `carId`, VAmPI's `username`) so the confirmation predicate can see them. All three are repeatable.

It adapts an OpenAPI spec into routes (templated params keep their domain names; per-path `servers`
become per-route origins, so a multi-service topology works), and it obtains the victim object ids
IDOR needs without a PostgREST oracle — operator seed (`--victim-id`) first, then the victim's own
authenticated self-read. Leak confirmation walks the response body rather than matching a fixed
Supabase key list.

**Read the scope rows before writing any sentence about this run.** An external run probes the
**route-adaptive tier only**: the DB oracle, every Supabase platform surface, and every
schema-derived probe are disclosed as not-probed rows, never as coverage. MASS-ASSIGNMENT reports
not-applicable off-Supabase rather than a false clean, because it needs a read-back oracle an
external target does not expose (#995).

## 5. Connected tiers — per backend

Only after the client has granted read-only DB access and (for the advisor/auth-config surface) a
scoped Supabase Management API token per backend (`docs/runbooks/engagement-access.md` steps
4/4a, `docs/runbooks/connected-access-hardening.md` for the credential ladder). Run once **per
enumerated Supabase backend** — a monorepo with more than one project needs one pass each, not one
for the repo:

```bash
SUPABASE_DB_URL=<backend-1-conn-string> pnpm detect-deeper                    # M1 live, per backend
SUPABASE_ACCESS_TOKEN=<backend-1-token> pnpm perf-scan <backend-1-project-ref> # M7 advisors, per backend
SUPABASE_DB_URL=<backend-1-conn-string> pnpm pii-classify                     # M10 live, per backend
```

`run-audit --supabase <ref>` (repeatable, once per project — #506) fans M7's advisor tier out
over every ref you pass it and folds each into its own ledger row; `SUPABASE_ACCESS_TOKEN` still
comes from the environment. `--connected` alone (no ref) records `partial` — a flag declares
intent, the ref is what lets the advisor call actually reach a project.

M10's **live** tier is per-DB too (#520): the orchestrator classifies EACH `--supabase` project
against its own connection string, read from a per-project env var `SUPABASE_DB_URL_<REF>` — the ref
uppercased with every non-alphanumeric char turned into `_` (e.g. ref `proj-rag` →
`SUPABASE_DB_URL_PROJ_RAG`). The first `--supabase` ref also falls back to the plain
`SUPABASE_DB_URL`, so a single-project engagement needs no new var. A project with no URL supplied
keeps its own honest `requires-live-run` row — never a silent skip. So a two-backend run sets:

```bash
SUPABASE_DB_URL_<BACKEND_1_REF>=<backend-1-conn-string> \
SUPABASE_DB_URL_<BACKEND_2_REF>=<backend-2-conn-string> \
SUPABASE_ACCESS_TOKEN=<token> \
pnpm exec tsx src/cli/run-audit.ts <target-dir> --connected \
  --supabase <backend-1-ref> --supabase <backend-2-ref> --findings-out engagement-findings.json
```

For M10's **schema** tier, a target whose SQL is not at `supabase/migrations` is probed at the
conventional locations (`prisma/migrations`, `drizzle/`, `db/`, `schema.sql`) automatically (#529);
pass `--schema <path>` to point at an unconventional one. `--schema` is repeatable and, on a
monorepo, takes a per-app form (#538): `--schema <app-name>=<path>`, keyed by the app name run-audit
discovers (printed at startup as "Monorepo apps enumerated" — see below). Each app without its own
`--schema <app-name>=<path>` still falls back to the conventional-location probe, so a two-backend
run where only one app has an unconventional layout sets:

```bash
pnpm exec tsx src/cli/run-audit.ts <target-dir> \
  --schema apps/rag=packages/rag-db/sql --findings-out engagement-findings.json
```

The bare `--schema <path>` form only applies on a single-target run (≤1 app enumerated) — it is
never smeared across a monorepo's per-app fan-out.

## 6. Full M8 mutation run — correct env, full scope, every app

Now that the target's test env is known (step 1) and its apps are enumerated (step 0), run the
real mutation scores:

```bash
pnpm mutation-scan <app-1-path> --hotspots hotspots.txt --out M8-app1.json
pnpm mutation-scan <app-2-path> --hotspots hotspots.txt --out M8-app2.json --install   # if Stryker
                                                                                         # isn't
                                                                                         # already
                                                                                         # installed
```

Run once per app — not once for the whole monorepo. A target that ships its own Stryker config
runs under it; one that doesn't gets a config scaffolded for its detected runner
(vitest/jest/mocha, #513). Missing Stryker packages install with `--no-save` **only** under
`--install` — an implicit install runs the target's package lifecycle scripts, so this needs
explicit operator consent, never a default (open follow-up: the orchestrator's own M8 probe
cannot yet pass `--install` through, #523 — run `mutation-scan` directly for the full pass, as
above). A scoped run (covering less than the configured mutate globs) records `partial` with the
scope named, never gets banked as the module's full measurement (#504); a suite that fails its
own unmutated dry run surfaces as a distinct env-fragile-suite verdict rather than a generic void
(#503). Bank the result:

```bash
pnpm record-pass --module M8 --target <app-1-path> --pass mutation --out <artifacts-dir> \
  --summary "mutation score 78%, 12 surviving on hotspots"
```

## 7. Assemble the deliverable

```bash
pnpm exec tsx src/cli/run-audit.ts <target-dir> \
  --connected --dynamic --llm \
  --artifacts-dir <artifacts-dir> \
  --supabase <backend-1-ref> --supabase <backend-2-ref> \
  --findings-out engagement-findings.json \
  --meta engagement-meta.json \
  --out coverage.json
```

- `--artifacts-dir` makes the M1 semantic/live, M2 dynamic, M3 vitals, and M6 verdict probes
  derive `ran` from the `<module>.pass.json` files banked in steps 3–6, instead of staying
  honestly not-run.
- `--findings-out` assembles ONE engagement findings document: every captured module's findings
  plus the derived coverage ledger, in the shape `report-template/` and `pnpm validate:findings`
  consume. Omit `--meta` and the file still writes, but with a placeholder meta and a loud warning
  — client/health/headline/scope are human judgement, not derivable.
- `--baseline <prior-findings.json>` (repeat engagements only) classifies each current finding
  resolved/persistent/new against the client's last audit.
- Re-run **after** every operator pass artifact is banked — a stale re-derivation just re-reports
  the same `partial`s.

Validate before it ships:

```bash
pnpm validate:findings engagement-findings.json
```

## 8. Coverage-ledger completeness check — the last gate before delivery

`run-audit` exits non-zero on any coverage gap, never-run module, or crashed runner — a clean exit
(the final line reads `COVERAGE PASS — all ten modules accounted for, derived from actual
execution.`) is the honest-degrade-aware completeness proof: every module is `ran`, `partial`
with a reason, or `requires-live-run` with a reason. None is silently absent.

Read the printed table (or `coverage.json`) module by module against
`docs/runbooks/engagement-access.md`'s delivery-gate definitions:

- **ran** — all in-scope classes executed. "No tests exist" is a *ran* M8 result (the finding
  itself), not a skip.
- **partial** — some classes ran, others didn't, with a reason. Disclosed, doesn't block delivery,
  never counts as full coverage.
- **requires-live-run** — a prereq (an environment tier: `--connected`/`--dynamic`/`--llm`) was
  absent, with a reason.

A bare skip, or a `partial`/`requires-live-run` with no reason, is a gap and the tool throws
naming it — that is the honest-degrade path this whole sequence protects: an environment the
engagement doesn't have is a recorded, reasoned gap in the client-facing report, never a silent
clean bill of health.

## Companion issues — harness gaps this sequence works around today

This is the human-run version of what `run-audit` should eventually orchestrate on its own.
Tracked gaps, current as of this sweep:

**All five gaps this section used to list are now CLOSED** (verified against the tracker
2026-07-24) and are recorded here only so a reader who remembers them knows where they went:

- **#523 CLOSED** — `run-audit` now threads mutation-install consent to the M8 probe as
  `--allow-target-install`. Without it, M8 degrades to the loud "re-run with `--install`" partial
  rather than installing into a client target silently. You no longer need to run `mutation-scan
  --install` out of band.
- **#159 / #161 CLOSED** — the seam probes and the NO-RATE-LIMIT loop have both been exercised
  live to a finding-producing verdict; `dynamic-validate --execute` provisions its own stack with
  no operator step. It is still driven as its own command (step 4) and banks an `M2.pass.json` for
  `--artifacts-dir`, which is the intended shape, not a gap.
- **#508 CLOSED** — M2 discovers and applies migrations per-DB across a monorepo's Supabase
  projects (#610).
- **#514 CLOSED** — M2 stands up its own stack and seeds a generic two-tenant fixture, inferring
  per-user owner columns from the FK-to-`auth` graph (#617/#1001). Nothing ATC-specific remains in
  the path.

Older items closed and reflected above rather than listed as a gap: #502 (M3→M1 sequencing),
#503 (M8 target test-env detection/replication), #504 (scoped mutation runs), #505 (M4/M5
per-workspace + timeout), #506 (monorepo target enumeration), #507 (M3 vitals plugin-location
discovery), #509 (report completeness derived from the coverage ledger), #513 (M8 Stryker config
scaffolding + gated install).
