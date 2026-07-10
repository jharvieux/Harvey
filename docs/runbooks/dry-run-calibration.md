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
- Filed 5 gap issues (#52–#56): the biggest was that the LLM-driven `/threat-model` →
  `/vuln-scan` → `/triage` pipeline the runbook centers on could not be verified in this
  environment at all (#53) — it's the mechanism that's supposed to catch what the mechanical
  scan misses.
  **Update 2026-07-09: #53 is resolved.** The skills are present in this environment as
  user-scope Claude Code skills, and a real run against `targets/calibration` caught **7 of
  the 8** planted bugs (the 8th, OPEN-REDIRECT, is excluded by the pipeline's own built-in
  rules, not missed by omission). See §10 for the full write-up — this is now the strongest
  single result in this document.
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
| 1 | RLS-USING-TRUE | Critical | requires-live-run (superseded — see §10) | Needs a semantic RLS-policy-predicate read (the runbook's LLM `/vuln-scan`+`/triage` pass, or manual hand-verify) — no mechanical module evaluates policy semantics. Not run in this mechanical-only pass; **now run for real, caught — see §10.** |
| 2 | RLS-AUTH-ROLE | Critical | requires-live-run (superseded — see §10) | Same as #1. **Now run for real, caught — see §10.** |
| 3 | RLS-DISABLED | High | requires-live-run (superseded — see §10) | The `rls_disabled_in_public` Supabase Advisor lint would catch this, but needs a live DB (`supabase start`, Docker) and, per issue #54, isn't actually wired into local-mode scanning yet even when Docker *is* available. **The LLM pipeline route to this same bug has since been run for real and caught it — see §10.** |
| 4 | SQLI-SERVICE | Critical | **missed by this layer** (LLM pipeline caught it — §10) | Semgrep ran; no registry/custom rule matches raw-SQL-string-concat into a query. See issue #52. |
| 5 | WEBHOOK-REPLAY | Medium | **missed by this layer** (LLM pipeline caught it — §10) | Semgrep ran; no rule targets missing replay/nonce protection. |
| 6 | COUNTER-RACE | Medium | **missed by this layer** (LLM pipeline caught it — §10) | Semgrep ran; no rule targets non-atomic read-modify-write races. |
| 7 | UPDATE-UNSCOPED | High | **missed by this layer** (LLM pipeline caught it — §10) | Semgrep ran; no rule targets an unscoped service-role `.update()` call. |
| 8 | OPEN-REDIRECT | Low | **missed** (still missed — §10) | Semgrep ran; the `harvey-open-redirect` custom rule exists but is written for the App-Router shape and doesn't match this Pages-Router zod-validated-URL shape. The LLM pipeline also doesn't catch this one, but for a different reason: both `/vuln-scan` and `/triage` have this bug class hardcoded into their own built-in exclusion lists — see §10. |

Read plainly: **every mechanical module that could run in this sandbox, did run — and caught
none of the planted bugs.** That's not a harness bug; it's an accurate measurement of *that
layer alone*. The 5 "missed" bugs are all classes no current mechanical rule targets (issue
#52); the 3 "requires-live-run" bugs needed either a live DB (issue #54, still open for the
Advisor-lint route) or the LLM triage pipeline, which per §10 has since been run for real and
independently catches 7 of these 8 bugs by semantic code reading rather than pattern matching.

True negatives held: none of `notes`' RLS policy, `counters`' RLS policy, the webhook HMAC
check, or `profiles`/`tenants`' self-scoped policies (`GROUND-TRUTH.md`'s intended
true-negatives list) were falsely flagged by anything that ran.

## 4. Process gaps — walking `docs/tier1-runbook.md` step by step

Filed as issues (non-trivial, per `CLAUDE.md`):

- **#52** — mechanical toolchain has zero rule coverage for 5 of 8 calibration-target bug
  classes (the coverage-scorecard finding above, filed for tracking + a concrete fix list).
- **#53** — runbook step 1's reference-harness skills (`/threat-model`, `/vuln-scan`, `/triage`)
  were not available/verified in this environment as of this pass; the entire LLM-driven semantic
  pass was unverified end-to-end. **Resolved 2026-07-09** — see §10.
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

**LLM `/threat-model` → `/vuln-scan` → `/triage` pass (issue #53): done, see §10.** This was the
highest-value remaining gap, since it's the mechanism expected to catch `RLS-USING-TRUE` and
`RLS-AUTH-ROLE` (2 of the 3 Critical bugs) plus everything in §3's "missed" list — it now has a
real, ground-truth-scored result.

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

## 9. Connected-tier live confirmation (2026-07-09)

The B8 (Supabase security advisors) and M7 (performance advisors) corpus fixtures are
`connected` tier — built offline against recorded advisor JSON, N/A in the static gate. This
section is the deferred **live** confirmation, run against a real local stack
(`colima` + `supabase start -x vector,analytics` + `supabase db reset` on `targets/calibration`,
which applies the B8/M7 advisor migrations).

**All planted advisor fixtures fire against the real advisor.** Ran the open-source Supabase
advisor engine (`splinter.sql`) directly against the live DB via `psql`:

- **B8 security lints (caught):** `auth_users_exposed`, `rls_enabled_no_policy` (×2),
  `security_definer_view` (×2), `function_search_path_mutable`, `rls_disabled_in_public`,
  `rls_references_user_metadata`, `anon_security_definer_function_executable` (×2),
  `authenticated_security_definer_function_executable` (×2).
- **M7 performance lints (caught):** `unindexed_foreign_keys` (×14), `auth_rls_initplan` (×4),
  `unused_index` (×3).

So the fixtures are genuine — a real advisor run detects every one.

**Gap found (reinforces #54):** Harvey's own `harvey scan --supabase local` caught only **3** of
these live (`SB-BUCKET-avatars` public storage bucket, `SB-EXPOSED-public-audit_logs`,
`SB-EXT-pg_net`) — its local mode implements a *subset* of checks, it does **not** run the full
Splinter lint set. So delivering the B8/M7 connected coverage requires either wiring `splinter.sql`
into local mode (**#54**) or running `get_advisors` against a *connected remote* project (which
does run full Splinter). The connected-tier corpus is therefore validated as ground-truth-correct,
but Harvey's local scanner needs #54 to actually surface it against a `supabase start` stack.

## 10. LLM pipeline live confirmation (2026-07-09, issue #53)

This section resolves issue #53: whether the runbook's `/threat-model` → `/vuln-scan` → `/triage`
pipeline (`docs/tier1-runbook.md` steps 1, 3–5) is real, installed, and actually catches the
cross-tenant/logic-bug classes the mechanical layer structurally cannot (§3's 5 "missed" + 3
"requires-live-run" rows). It was run for real against `targets/calibration`.

### 10.1 Install path — verified

The skills (`customize`, `patch`, `quickstart`, `threat-model`, `triage`, `vuln-scan`) are present
in this environment as **personal, user-scope Claude Code skills** at `~/.claude/skills/<name>/SKILL.md`
(plus a shared `~/.claude/skills/_lib/checkpoint.py` helper) — **not** installed via the Claude Code
plugin/marketplace system (absent from `~/.claude/plugins/installed_plugins.json` and every known
marketplace). They are invoked directly, e.g. `/threat-model bootstrap <repo>`. The runbook's
previous claim that they're installed "from `anthropics/defending-code-reference-harness`" could
not be independently confirmed from anything on disk in this environment — no plugin manifest,
marketplace record, or in-repo file references that exact repo name, though the skills' own content
(canary-target and vuln-pipeline references inside `quickstart`) is consistent with that package.
`docs/tier1-runbook.md` step 1 has been corrected to state the verified reality and flag this
residual uncertainty rather than assert an unconfirmed install command.

One real operational gotcha found while running them: the skills' own instructions invoke their
checkpoint helper via the *relative* path `.claude/skills/_lib/checkpoint.py`, which assumes a
project-local install. In this user-scope install, that path doesn't resolve from a repo's working
directory — the absolute path (`~/.claude/skills/_lib/checkpoint.py`) is needed instead. Noted in
the runbook.

### 10.2 What ran

All three stages ran for real against `targets/calibration` (scoped to `app/`, `pages/`, `lib/`,
`components/`, `middleware.ts`, `supabase/` — excluding `dead/`, `dup/`, `simplify/`,
`test-quality/`, which are separate M4/M5/M8 quality-module fixtures per the target's own `README.md`,
not part of "the app"):

1. **`/threat-model bootstrap`** — ran the full 5-stage pipeline (research swarm of 5 parallel
   subagents: docs reader, surface mapper, infra reader, asset finder, history miner; synthesis;
   threat clustering; STRIDE gap-fill; emit). Wrote `THREAT_MODEL.md` with 24 entry points and 18
   threats. The swarm alone surfaced several of the ground-truth bugs directly (the RLS gaps, the
   raw-SQL routes, the unscoped UPDATE) before `/vuln-scan` even ran, which is exactly the intended
   effect of threat-modeling before scanning blind.
2. **`/vuln-scan --extra docs/scan-extras.txt --no-score`** — scoped by the `THREAT_MODEL.md` from
   step 1, fanned out to 10 focus-area subagents (RLS/PostgREST, raw SQL, service-role
   scoping/IDOR, webhook replay, concurrency, XSS/redirect, middleware/CORS, server actions,
   Postgres functions/views, secrets/supply-chain). `--no-score` (skips the skill's optional
   per-finding confidence pass) was used as a disclosed adaptation given the scan surfaced 45 raw
   candidates — well beyond the original 8-bug scope — to keep the run tractable; every finding
   still reached `/triage` unfiltered. Wrote `VULN-FINDINGS.json`/`.md` (45 findings: 33 HIGH / 9
   MEDIUM / 3 LOW, scanner-claimed severities).
3. **`/triage --fp-rules docs/fp-rules.txt --auto`** — ran Phase 1 (ingest), Phase 2 (light dedupe),
   Phase 3 (adversarial verification: one independent subagent per finding, reading source itself
   and applying both the skill's 16 built-in exclusion rules and `docs/fp-rules.txt`'s org-specific
   rules). **`--votes 1` instead of the skill's default 3** was used as a disclosed adaptation for
   the same volume reason as above — a full 3-vote run remains available as a stricter follow-up.
   Phase 4 (severity re-ranking) and Phase 5 (owner routing) were **not** run this pass — confirmed
   findings keep the scanner's originally-claimed severity, unadjusted; re-ranking wasn't needed to
   answer #53's catch/miss question. Wrote `TRIAGE.json`/`.md`: 33 confirmed true positives, 11
   false positives, 1 duplicate.

Pipeline output files (`THREAT_MODEL.md`, `VULN-FINDINGS.*`, `TRIAGE.*`) were generated inside
`targets/calibration/` during the run and are **not committed** — they're run artifacts, same
convention as `dry-run/` and `report-template/out/`.

### 10.3 Ground-truth scorecard — the result

**7 of the 8 planted bugs confirmed TRUE_POSITIVE**, each independently re-derived from source by
a skeptical verifier (not just carried over from the scan stage's claim):

| # | Bug | Severity | Status | Evidence |
|---|---|---|---|---|
| 1 | RLS-USING-TRUE | Critical | **caught** | `documents_select_all` policy is `USING (true)`, verified reachable via PostgREST with no compensating grant restriction |
| 2 | RLS-AUTH-ROLE | Critical | **caught** | `invoices_select_authenticated` checks only `auth.role() = 'authenticated'`, no tenant predicate |
| 3 | RLS-DISABLED | High | **caught** | no `ENABLE ROW LEVEL SECURITY` anywhere for `audit_logs` in any migration, confirmed by exhaustive grep |
| 4 | SQLI-SERVICE | Critical | **caught** | `pages/api/search.js` string-concat SQLi confirmed (plus an independent second instance in `pages/api/report.js`'s `exec_sql` RPC) |
| 5 | WEBHOOK-REPLAY | Medium | **caught** | HMAC check correct; verifier confirmed no nonce/timestamp/dedup exists anywhere in the path |
| 6 | COUNTER-RACE | Medium | **caught** | verifier explicitly reasoned through "is this a realistic concurrent-request window or theoretical" (the pipeline's own exclusion rule 16 for theoretical-only races) and confirmed it's realistic |
| 7 | UPDATE-UNSCOPED | High | **caught, with a nuance** | verifier confirmed the route uses the raw `pg.Pool` (`lib/db.js`), not PostgREST — so it is **not** protected by the PostgREST "UPDATE requires WHERE" guard that made this bug non-exploitable-as-planted in §8's live dynamic-pentest run (issue #59). The static/LLM read and the dynamic pen-test are both correct; they're reading different reachability paths to the same planted code. |
| 8 | OPEN-REDIRECT | Low | **missed — by design, not by gap** | `pages/api/redirect.js` was explicitly seen by the `/vuln-scan` subagent scoped to that route, and explicitly *not* reported, because the skill's own built-in review brief hardcodes "open redirect" into its default DO-NOT-REPORT list — independent of `docs/scan-extras.txt`, which doesn't add an override. `/triage`'s own built-in verifier exclusion rule #12 separately classifies open redirect as a "low-impact nuisance" false positive, so it's excluded twice over. This is **not** a scanning gap the way the mechanical layer's misses are (§3) — it's a deliberate, hardcoded suppression shipped with the reference-harness skills themselves. If open-redirect coverage matters for an engagement, this pipeline as shipped won't surface it; use the kickoff questionnaire (runbook §3) or a manual check instead. |

**Read plainly: the LLM pipeline is the strongest detection layer measured against this calibration
target so far** — 7/8 vs. the mechanical layer's 0/8 (§3) and the dynamic pen-test's 5/8-with-correct-verdicts
(§8.2). It found real bugs the mechanical scanner structurally cannot (RLS policy semantics, SQL
injection via string concat, a webhook replay gap, a counter race, framework-specific CORS/auth
issues) by reading and reasoning about source rather than pattern-matching, and it correctly
distinguished true bugs from false positives 11 times without being told the answer key — including
catching that a claimed CSRF finding is actually already mitigated by a Next.js framework default,
that one Postgres view finding wasn't actually reachable given the deployment's grant configuration,
and that a hardcoded AWS-shaped key was the deliberately-planted case rather than the AWS docs'
well-known example key (`docs/aws-setup.md`).

### 10.4 Beyond the original 8 — what else the pipeline surfaced

`docs/scan-extras.txt`/`docs/fp-rules.txt` scope the pipeline for a real audit, and this calibration
target's source tree also holds planted bugs from later batches (B1/B3/B4/B5/B6/B7/B8, tracked
separately under issue #71/#72 for the *mechanical* scanner's coverage). Scanning the same
directories inevitably surfaced some of those too — the LLM pipeline confirmed 33 true positives
total, 25 beyond the original 8-bug list, including multiple independent service-role-key-exposure
patterns, a middleware JWT-decode auth bypass paired with a reflected-origin CORS misconfiguration,
an `eval()` remote-code-execution route, several IDOR/mass-assignment/missing-authorization routes,
and cross-tenant issues in Postgres views/functions (`user_directory`, `internal_notes_admin_read`,
`fetch_webhook_preview`'s SSRF). These are real findings but **out of this pass's scoring scope** —
issue #53 was specifically about the 8-bug headline scorecard above; a fuller comparison against the
B1–B8 batches' own ground-truth sections would be its own dedicated effort. Full detail:
`targets/calibration/TRIAGE.json`/`.md` (not committed — see §10.2).

One miss worth flagging honestly: `/triage`'s verifier dismissed `lib/admin.js`'s hardcoded
service-role JWT as a false positive on "no importers found" (its dead-code exclusion rule), even
though `GROUND-TRUTH.md` tags it a genuine planted secret-scanning positive. This looks like a real
pipeline limitation, not a correct call: secret-scanning findings are presence-based (a leaked
credential is a leak the moment it's committed, regardless of whether any code currently imports the
file), not reachability-based like the injection/auth-bypass classes the exclusion rules were
designed for. Worth a manual override in a real engagement if a secrets-scan finding gets dismissed
this way; not filing a new issue for it since `docs/fp-rules.txt` is an operator-owned file and the
fix (if any) belongs there, not in the pipeline's shipped defaults.

### 10.5 Confidence read

- **The threat-model → vuln-scan → triage pipeline is now verified end-to-end on one target with a
  known answer key.** Treat its 7/8 result here as real signal, not a demo — every verdict came from
  an independent subagent reading the actual source and citing file:line evidence, not from being
  told the ground truth.
- **Two structural blind spots are now documented, not just theorized:** open redirect is
  hardcoded-excluded at both the scan and triage stages; race conditions and "unreferenced code"
  secrets sit close to built-in exclusion rules that can (and in one case did) suppress a real
  finding. `docs/tier1-runbook.md` now calls these out explicitly so an operator running a live
  engagement knows to double-check them rather than trust the pipeline blindly.
- **Next confidence step**, mirroring §8.4's note for the dynamic layer: run this same pipeline
  against a real third-party Supabase/Next.js repo where the bugs are genuinely unknown, not a
  calibration fixture with an answer key — that's the test that would validate generalization rather
  than recall-on-a-known-set.
