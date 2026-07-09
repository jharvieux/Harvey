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

> **UPDATE — 2026-07-08, Docker up (live run):** the environment above was later unblocked
> (colima started). The live run of the config auditor + dynamic pen-test against a real
> `supabase start` stack + running app is in **§8**, and it changes the picture materially:
> the **dynamic pen-test caught all 3 cross-tenant RLS bugs with zero false positives**, and
> live exploitation established the true status of every one of the 8 planted bugs. Read §8
> alongside §3 — §3's "requires-live-run" / "missed" verdicts are now resolved there.

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

## 8. Live run addendum (2026-07-08, Docker up)

After the sandbox run above, `colima` was started and the full stack was stood up:
`supabase start -x vector,analytics` (the `vector`/analytics container fails on colima's
`docker.sock` mount — exclude it), `supabase db reset`, and a production `next build && next
start -p 3100` of the target app. Personas were minted as JWTs signed with the local
`JWT_SECRET` (the seeded password logins fail with "Database error querying schema", a gotrue
quirk on this stack). Every row below is the literal result of a command run against that live
stack.

### 8.1 The target is genuinely vulnerable (ground truth confirmed by raw exploit)

| # | Bug | Live exploit result |
|---|---|---|
| 1 | RLS-USING-TRUE | anon `GET /rest/v1/documents` returned **both** tenants' rows (`aaaaaaaa` + `bbbbbbbb`) |
| 2 | RLS-AUTH-ROLE | Alice's JWT `GET /rest/v1/invoices` returned **both** tenants' rows |
| 3 | RLS-DISABLED | anon `GET /rest/v1/audit_logs` returned all tenants' rows |
| 4 | SQLI-SERVICE | `q=' UNION SELECT id, id, encrypted_password FROM auth.users --` **exfiltrated 2 bcrypt password hashes** |
| 5 | WEBHOOK-REPLAY | one valid signed request POSTed 3× → **3** `audit_logs` rows inserted |
| 6 | COUNTER-RACE | 30 concurrent `POST /api/counter/increment` → final counter value **1** (29 lost updates) |
| 7 | UPDATE-UNSCOPED | **NOT exploitable as planted** — PostgREST rejects the unqualified UPDATE (`{"error":"UPDATE requires a WHERE clause"}`), both profiles unchanged. Ground-truth defect → issue #59 |
| 8 | OPEN-REDIRECT | `GET /api/redirect?url=https://evil.example/phish` → `302 Location: https://evil.example/phish` |

True-negatives held: anon reads of the correctly-scoped `notes` returned 0 rows.

### 8.2 What Harvey's tools caught against that live stack

| # | Bug | Sev | Really exploitable? | Config auditor (#26) | Pen-test (#5) | Net |
|---|---|---|---|---|---|---|
| 1 | RLS-USING-TRUE | Crit | yes | ❌ (RLS on + policy present — advisor lints can't judge policy quality) | ✅ explore | **caught** |
| 2 | RLS-AUTH-ROLE | Crit | yes | ❌ same | ✅ explore | **caught** |
| 3 | RLS-DISABLED | High | yes | ✅ `SB-EXPOSED` | ✅ explore | **caught** |
| 4 | SQLI-SERVICE | Crit | yes | — | ❌ verify probe 500s (type-incompatible UNION) → #58 | **missed (real bug)** |
| 5 | WEBHOOK-REPLAY | Med | yes | — | ❌ no automated replay probe → #60 | **missed (real bug)** |
| 6 | COUNTER-RACE | Med | yes | — | ❌ no concurrency probe → #60 | **missed (real bug)** |
| 7 | UPDATE-UNSCOPED | High | **no** | — | ✅ correctly `unproven` | **correct** |
| 8 | OPEN-REDIRECT | Low | yes | — | ✅ verify `proven` | **caught** |

Live dynamic tooling gives **correct verdicts on 5 of 8** (4 real bugs proven + the 1 mis-plant
correctly cleared), zero false positives on the correctly-scoped tables. The 3 misses are all
real bugs and all tracked: #58 (SQLi probe payload), #60 (replay + race probes).

### 8.3 The mechanical/static layer, re-run live — the part to distrust

`semgrep --config src/scan/rules/semgrep-nextjs-supabase.yml targets/calibration` produced
**exactly one finding: `harvey-service-role-in-client` on `lib/supabaseAdmin.js:7` — a false
positive** (that file is a server-only admin client that is *supposed* to hold the service-role
key; see issue #56). It caught **none** of the 8 planted bugs. Two reasons, both structural:

- **#4 SQLi has no rule at all** — the ruleset has no pattern for untrusted input concatenated
  into a raw SQL string / template literal. It cannot catch the most classic web vuln present.
- **#8 open-redirect's rule targets the wrong framework** — it matches the App-Router
  `res.redirect(req.nextUrl.searchParams.get(...))` shape; the target (and many real apps) use
  the Pages-Router `req.query` idiom, so it never fires.

**Live mechanical score on this target: 0 true positives, 1 false positive.** This is not a
payload-tuning problem — the layer has essentially no working detection today. Six of the eight
bugs (the RLS/replay/race/unscoped-update classes) are logic/config bugs that *no* pattern
scanner can find by design; the remaining two are in a scanner's wheelhouse and are missed
because the rules are absent or framework-mismatched. See §8.4.

### 8.4 Confidence read (honest)

- **Do not present the mechanical/static layer as a bug-finder.** Signature scanners only find
  what they have a validated rule for; ours currently has near-zero validated true-positive
  coverage and a demonstrated false positive. Its legitimate role is high-precision *known*
  issues (verified secrets, known CVEs) — and even that is unvalidated against ground truth.
  This directly affects the free quick-scan tier (#27), which draws on this layer: a free scan
  that finds nothing (or one FP) is worse than none. Tracked under #52; a calibration-gated
  rule-validation harness ("prove coverage before claiming it") is issue **#61**.
- **The dynamic pen-test explore is the mechanism that generalizes to unknown bugs.** It found
  the cross-tenant leaks *without being told they existed* — it enumerates the real attack
  surface (table × persona × verb) and diffs against a service-role oracle. It's deterministic
  (no model), so its true positives are trustworthy. This is the part that plausibly finds
  unknown bugs in a third-party repo — but so far it's validated only on the cross-tenant class
  against a target whose bugs we knew. **Next confidence step: run explore against a real
  third-party Supabase/Next repo where the bugs are unknown.**
- **The logic-bug classes (race, replay, novel auth flaws) that neither signatures nor
  oracle-diffing cover are the semantic/LLM tier's job — and that tier is entirely unvalidated
  (no provider keys set).**

### 8.5 Issues filed from the live run

- **#58** — M2 SQLi verify probe uses a type-incompatible UNION → false-negative on a real
  Critical. Highest-priority tool fix.
- **#59** — calibration bug #7 (unscoped update) isn't exploitable as planted (PostgREST blocks
  unqualified UPDATE); fix the plant or relabel it a true-negative.
- **#60** — add automated WEBHOOK-REPLAY and COUNTER-RACE probes to verify mode (both confirmed
  real by hand).
- **#61** — mechanical layer: gate rules on calibration validation; treat unvalidated rules as
  non-shipping (the confidence fix; supersedes #52's framing).
