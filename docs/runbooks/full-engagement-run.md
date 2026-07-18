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
cd <target-dir> && npm install                          # (or pnpm/yarn install per the target's
                                                         # own lockfile) — unlocks M5 (knip needs
                                                         # the target's own node_modules to resolve
                                                         # config/plugin imports), M8 stub-check/
                                                         # Stryker candidacy, M7 Lighthouse/bundle
```

For an untrusted cold repo, consider `--ignore-scripts` on the install (install scripts of an
unvetted repo are the exact execution-vector class M1's supply-chain checks flag) — verify knip
still resolves before adopting that as standard; it hasn't been measured yet.

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
/vuln-scan --extra docs/scan-extras.txt --extra focus.md
/triage --fp-rules docs/fp-rules.txt
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

- **#523** — the orchestrator's own M8 probe cannot yet pass `--install` through; run
  `mutation-scan --install` directly (step 6) rather than through `run-audit`.
- **#159 / #161** — the M2 live pipeline (`dynamic-validate --execute`) is operator-run
  end-to-end, not yet wired into `run-audit` itself.
- **#508** — M2 monorepo migration discovery/wiring for a target with more than one
  `supabase/` config is still being generalized.
- **#514** — the two-tenant seed/fixture harness M2 depends on is still ATC-specific in places;
  generalizing it for an arbitrary client schema is open.

Closed this sweep and reflected above rather than listed as a gap: #502 (M3→M1 sequencing),
#503 (M8 target test-env detection/replication), #504 (scoped mutation runs), #505 (M4/M5
per-workspace + timeout), #506 (monorepo target enumeration), #507 (M3 vitals plugin-location
discovery), #509 (report completeness derived from the coverage ledger), #513 (M8 Stryker config
scaffolding + gated install).
