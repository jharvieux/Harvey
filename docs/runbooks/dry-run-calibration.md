# Dry-run report: calibration target (issue #34)

**Date:** 2026-07-08. **Target:** `targets/calibration` (deliberately-vulnerable calibration
app, answer key at `targets/calibration/GROUND-TRUTH.md`). **Environment:** sandbox — no
Docker daemon running (`colima`/`docker.sock` not up), so no `supabase start`, no live
Postgres, no running Next.js app. `semgrep`, `gitleaks`, `trufflehog`, `osv-scanner`, and the
`supabase` CLI binaries were all present and used for real.

**Everything in this document is either the literal output of a command that was actually run
(pointers to the raw JSON are given throughout) or explicitly labeled as not run.** No timing
number, coverage verdict, or finding below was estimated or invented.

## TL;DR

- Ran for real: the mechanical scan (secrets/deps/semgrep/supply-chain/leftover-auth), M1
  detect-deeper (grant/definer classifiers fed from parsed migration SQL), M10 PII data map,
  M4/M5 quality-scan, and the findings→report render pipeline.
- **Coverage scorecard: 0 of 8 `GROUND-TRUTH.md` bugs caught, 5 missed by modules that ran, 3
  require a live environment.** This is the single most important number in this report — see
  §3.
- Filed 5 gap issues (#52–#56): the biggest is that the LLM-driven `/threat-model` →
  `/vuln-scan` → `/triage` pipeline the runbook centers on could not be verified in this
  environment at all (#53) — it's the mechanism that's supposed to catch what the mechanical
  scan misses.
- Not run: anything needing Docker/a live DB/a running app (Supabase Advisors, M2 pentest, M7
  perf, M8 mutation testing) or the reference-harness LLM skills. Exact commands to complete
  those are in §5.

## 1. What actually ran, and per-module timing

| Module | What ran | Wall clock | Findings |
|---|---|---|---|
| M1 (mechanical) | `runMechanicalScan()` — TruffleHog (filesystem + git-history) + gitleaks + OSV-Scanner + curated Next.js CVE ranges + Semgrep (registry packs + custom rules) + supply-chain checks + leftover-auth grep, via `src/cli/dry-run.ts` | **5912.5 ms** | 6 |
| M1 detect-deeper | Grant/definer classifiers (`src/grant-classifier.ts`, `src/definer-classifier.ts`), fed from **parsed migration SQL** instead of a live DB (`src/migration-sql-parse.ts`) | **0.5 ms** | 0 |
| M10 | PII/PHI/PCI data map (`tools/pii-classify.mjs`), fed from the same parsed migration columns | **1.8 ms** | 3 tables with hits (31 columns classified) |
| M4 + M5 | `pnpm quality-scan` (jscpd duplication + knip dead code), run separately against the same target | **1291 ms** | 0 (correct — a hand-written 7-table/5-route app has no duplication or dead code, and no M4/M5-class bug is planted) |
| M9 | Next.js App Router boundary detectors (`src/detectors/app-router.ts`) | not run | **N/A, confirmed by inspection**: `targets/calibration` has no `app/` directory or `.tsx` files — it's Pages Router only, so M9's detectors have zero applicable input. Zero-cost to state; running it would produce nothing. |
| M2 (pentest), M7 (perf), M8 (mutation) | — | not run | needs a live DB and/or a running app — see §5 |
| Supabase Advisors (`rls_disabled_in_public` etc.) | — | not run | needs `supabase start` (Docker) or hosted Management API access — see §5, and issue #54 (local mode doesn't actually run Splinter yet) |
| LLM `/threat-model` → `/vuln-scan` → `/triage` (runbook step 1) | — | not run | reference-harness skill package not available in this environment — see §4 and issue #53 |
| Report assembly (findings.json → report.html/pdf) | `report-template/render.mjs` against the 6 real M1 findings | **ran successfully** (chromium was already installed; no `playwright install` needed this session) | see §6 |

Raw output: `dry-run/timing.json`, `dry-run/findings.json`, `dry-run/pii-data-map.json`.

One methodology note on the M1 mechanical timing: the target directory had to be a real git
repo for TruffleHog's git-history pass to run at all (see issue #55) — the number above is from
a git-initialized scratch copy of `targets/calibration`, mirroring how a real engagement clones
a standalone client repo. A first attempt directly against `targets/calibration` (a plain
subdirectory of this monorepo, not its own git repo) crashed the entire mechanical scan instead
of degrading gracefully.

## 2. Findings produced (real output)

6 findings from the mechanical scan, 0 from M1 detect-deeper (see §3 for why), 0 from M4/M5.
Full JSON: `dry-run/findings.json`.

| id | severity | taxonomy | location |
|---|---|---|---|
| DEP-CVE-2025-29927 | Critical | Known-vulnerable dependency | `next@14.2.5` — middleware auth bypass |
| DEP-CVE-2025-55182 | Critical | Known-vulnerable dependency | `next@14.2.5` — "React2Shell" RSC RCE |
| DEP-CVE-2026-44578 | High | Known-vulnerable dependency | `next@14.2.5` — WebSocket-upgrade SSRF |
| SEM-1 | Critical | `harvey-service-role-in-client` | `lib/supabaseAdmin.js:7` |
| SUP-UNPINNED | Low | Unpinned dependency | `package.json` (6 deps) |
| SUP-NO-LOCKFILE | Medium | Missing lockfile | target root |

All 6 are real (the target's `package.json` genuinely pins `next@^14.2.5`, has no lockfile, and
`lib/supabaseAdmin.js` genuinely references `SUPABASE_SERVICE_ROLE_KEY` with no `server-only`
guard). **None of them correspond to a `GROUND-TRUTH.md` planted bug** — they're real
infrastructure/hygiene findings the target happens to also have, not hits on the calibration
answer key. `SEM-1` is flagged in issue #56 as a likely false positive on a Pages-Router app
specifically (the `server-only` guard convention it checks for is an App-Router concern).

While fixing a blocking issue in the custom Semgrep rules to even get this far (see §4), the
`harvey-open-redirect` rule was exercised against `pages/api/redirect.js` and confirmed *not* to
match — consistent with the scorecard's `OPEN-REDIRECT: missed` verdict below.

PII data map (`dry-run/pii-data-map.json`): `profiles.email` → EMAIL/PII/high (correct);
`tenants.name` and `counters.name` → NAME?/PII/low (the module's own documented ambiguous-name
class — "name" columns that are product/display names, not person names; both are correctly
low-confidence here, not asserted as PII).

## 3. Coverage scorecard — the headline result

Scored by `src/cli/dry-run-scorecard.ts` (pure logic in `src/coverage-scorecard.ts`, unit
tested) against the real findings above. Full JSON: `dry-run/scorecard.json`.

**0 caught / 5 missed / 3 require a live run — of 8 planted bugs.**

| # | Bug | Severity | Status | Why |
|---|---|---|---|---|
| 1 | RLS-USING-TRUE | Critical | requires-live-run | Needs a semantic RLS-policy-predicate read (the runbook's LLM `/vuln-scan`+`/triage` pass, or manual hand-verify) — no mechanical module evaluates policy semantics. Not run; see issue #53. |
| 2 | RLS-AUTH-ROLE | Critical | requires-live-run | Same as #1. |
| 3 | RLS-DISABLED | High | requires-live-run | The `rls_disabled_in_public` Supabase Advisor lint would catch this, but needs a live DB (`supabase start`, Docker) and, per issue #54, isn't actually wired into local-mode scanning yet even when Docker *is* available. |
| 4 | SQLI-SERVICE | Critical | **missed** | Semgrep ran; no registry/custom rule matches raw-SQL-string-concat into a query. See issue #52. |
| 5 | WEBHOOK-REPLAY | Medium | **missed** | Semgrep ran; no rule targets missing replay/nonce protection. |
| 6 | COUNTER-RACE | Medium | **missed** | Semgrep ran; no rule targets non-atomic read-modify-write races. |
| 7 | UPDATE-UNSCOPED | High | **missed** | Semgrep ran; no rule targets an unscoped service-role `.update()` call. |
| 8 | OPEN-REDIRECT | Low | **missed** | Semgrep ran; the `harvey-open-redirect` custom rule exists but is written for the App-Router shape and doesn't match this Pages-Router zod-validated-URL shape. |

Read plainly: **every mechanical module that could run in this sandbox, did run — and caught
none of the planted bugs.** That's not a harness bug; it's an accurate measurement. The 5
"missed" bugs are all classes no current rule targets (issue #52); the 3 "requires-live-run"
bugs need either a live DB (issue #54) or the still-unverified LLM triage pipeline (issue #53).

True negatives held: none of `notes`' RLS policy, `counters`' RLS policy, the webhook HMAC
check, or `profiles`/`tenants`' self-scoped policies (`GROUND-TRUTH.md`'s intended
true-negatives list) were falsely flagged by anything that ran.

## 4. Process gaps — walking `docs/tier1-runbook.md` step by step

Filed as issues (non-trivial, per `CLAUDE.md`):

- **#52** — mechanical toolchain has zero rule coverage for 5 of 8 calibration-target bug
  classes (the coverage-scorecard finding above, filed for tracking + a concrete fix list).
- **#53** — runbook step 1's `anthropics/defending-code-reference-harness` skills
  (`/threat-model`, `/vuln-scan`, `/triage`) were not available in this environment; the entire
  LLM-driven semantic pass is unverified end-to-end.
- **#54** — runbook §2 promises `splinter.sql`-based local DB-advisor-equivalent coverage, but
  no such file exists in the repo and `src/scan/supabase.ts`'s local mode explicitly skips
  advisor lints (own header comment confirms it) — `rls_disabled_in_public` isn't actually
  available even with a live local Postgres, as currently implemented.
- **#55** — the mechanical scan crashes entirely (not gracefully degrades) if the target isn't
  its own git repo; blocked this dry run's first attempt outright.
- **#56** — `harvey-service-role-in-client` assumes App-Router bundling semantics and likely
  false-positives on Pages-Router apps (`SEM-1` above).

Fixed inline during this pass (small, mechanical, no issue needed):

- `src/scan/rules/semgrep-nextjs-supabase.yml` had an **invalid YAML syntax error** on the
  `harvey-dangerously-set-inner-html` rule's pattern (an unquoted `<$EL ... {{ __html: $VAL
  }} />` — the embedded `:` broke YAML's flow-mapping parser). The file's own header comment
  admitted it had "not [been] validated against a live `semgrep` binary" — confirmed true, and
  now fixed (quoted the pattern; `semgrep --validate` passes, 4/4 rules load).

Trivial wording gaps, noted here per the task's "list trivial ones inline" — not filed as
issues, and `docs/tier1-runbook.md` itself is a supervised path this pass didn't touch:

- Step 4's example invocation is `/vuln-scan <repo>/src --extra docs/scan-extras.txt` — this
  assumes a `src/`-rooted app layout. `targets/calibration` (and plenty of real Pages-Router
  apps) have no `src/` directory at all; the wording should say "the app's source root," not
  literally `src`.
- Step 1's `export CLAUDE_CODE_SUBAGENT_MODEL=<model-id>` — I could not independently verify
  this environment variable is real/current in this session; flagging per `CLAUDE.md`'s "never
  present a guess as fact" rather than asserting either way.

Steps that worked exactly as written: step 0 (engagement/brief-file prerequisites —
`docs/scan-extras.txt`, `docs/fp-rules.txt`, `docs/audit-report-skeleton.md` all exist and are
current); step 2 (repo/scope/commit capture — straightforward for a local target).

## 5. Requires live environment

Everything below needs infrastructure this sandbox didn't have. Exact commands for an operator
with Docker running:

**Supabase Advisors + full M1 detect-deeper with real grants (not the assumed-default exposure
this dry run used):**
```bash
cd targets/calibration
supabase start          # needs Docker
supabase db reset       # applies migrations + seed.sql
SUPABASE_DB_URL=postgresql://postgres:postgres@127.0.0.1:54322/postgres \
  pnpm detect-deeper
pnpm exec tsx src/cli/scan.ts --supabase local
```
(Per issue #54, local-mode Supabase Advisor coverage is currently incomplete — the
`rls_disabled_in_public` lint won't come back from this today; use hosted Management API access
per runbook §2 Tier 3 to get real Advisor output in the meantime.)

**Running the Next.js app, to exercise the API-route bugs (#4–#8) dynamically and get M2
pentest data:**
```bash
cd targets/calibration
npm install
export SUPABASE_URL=http://127.0.0.1:54321
export SUPABASE_SERVICE_ROLE_KEY=<from `supabase start` output>
export DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:54322/postgres
export WEBHOOK_SECRET=dev-secret
npm run dev   # http://localhost:3100
```

**M7 (perf advisors):** needs a live Supabase project (local or hosted) —
`pnpm perf-scan <project-ref|local>`.

**M8 (mutation testing):** needs the target's own test suite (`targets/calibration` has none —
out of scope for a calibration app whose purpose is planted bugs, not test coverage) —
`pnpm mutation-scan <target-dir>`.

**LLM `/threat-model` → `/vuln-scan` → `/triage` pass (issue #53):** once the
`anthropics/defending-code-reference-harness` skills are confirmed installed/available, re-run
runbook steps 3–5 against `targets/calibration` and update the scorecard above — this is the
highest-value remaining gap, since it's the mechanism expected to catch `RLS-USING-TRUE` and
`RLS-AUTH-ROLE` (2 of the 3 Critical bugs) plus everything in §3's "missed" list.

## 6. Report render (findings.json → report)

`report-template/render.mjs` ran successfully against the 6 real findings (chromium already
installed; `pnpm exec playwright install chromium` was not needed this session). Output:
`report-template/out/dry-run/{report.html,report.pdf,page1.png}` — gitignored, not committed
(matches this repo's existing convention for `report-template/out/`). The report's meta fields
are explicit that this is a partial dry run, not a scored client audit — see
`dry-run/build-report-doc.mjs`.

## 7. Artifacts

- `dry-run/findings.json` — the 6 real mechanical-scan findings.
- `dry-run/pii-data-map.json` — real M10 output.
- `dry-run/timing.json` — real per-phase wall-clock from `src/cli/dry-run.ts`.
- `dry-run/scorecard.json` — the coverage scorecard (§3), from `src/cli/dry-run-scorecard.ts`.
- `dry-run/findings-report.json` / `dry-run/build-report-doc.mjs` — the findings.json wrapped
  with report meta, used for §6's render.
- `src/cli/dry-run.ts`, `src/cli/dry-run-scorecard.ts` — the harness, re-runnable:
  `pnpm exec tsx src/cli/dry-run.ts --target targets/calibration --out dry-run` (git-init a
  scratch copy first per issue #55 to avoid the crash), then
  `pnpm exec tsx src/cli/dry-run-scorecard.ts`.
- `src/migration-sql-parse.ts`, `src/coverage-scorecard.ts` — the new pure logic, unit tested
  (`src/migration-sql-parse.test.ts`, `src/coverage-scorecard.test.ts`).
