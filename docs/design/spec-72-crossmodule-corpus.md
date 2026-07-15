> **Product decisions (locked 2026-07-09) — these govern how this spec is built:**
>
> 1. **Free count = high-precision (~100%) findings only.** The `review`-tier (heuristic)
>    and `connected`-tier (live-advisor) classes are still *scanned*, but they are NOT
>    asserted in the free report and do NOT affect the free A–F grade (asserting a heuristic
>    "Critical" to a stranger is the credibility-fatal failure mode). They become **verified
>    candidate findings in the PAID report** — LLM triage → human sign-off → dynamic
>    confirmation for high-severity — before they are asserted. So: free = the high-precision
>    findings + the grade; paid = those plus the verified review/connected findings.
> 2. **Judgment-heavy modules:** M3 hotspots may appear in the free report ONLY as a limited,
>    deterministic **descriptive map** (churn×complexity, top-K) — factual (client's own data),
>    false-positive-safe, not asserted as findings; deeper coupling/knowledge-risk stays paid.
>    **M6 simplification splits: free lists hand-rolled-looking code as non-grading indicators
>    ("this looks hand-rolled; may be worth investigating"); paid triages each and names the
>    replacement** (revised 2026-07-15, was paid-only — see below). Principle: factual/descriptive
>    & FP-safe can be free; asserted judgments cannot.
>
>    _Revision (2026-07-15, operator):_ "Free tier can list items that look hand rolled and say
>    they may be worth investigating. Paid tier triages and says what each one should be replaced
>    with." This **applies** the principle rather than excepting it: that a given shape is present
>    is a fact the reader can check; *which replacement it warrants* is the asserted judgment, and
>    that stays paid. M6 therefore takes the same free/paid form as the M1 source-tier RLS/authz
>    indicators (#227 decision item 3): indicators free and non-grading, verdicts paid. The
>    hedged wording is load-bearing — copy that drifts to "should be replaced" re-asserts the
>    judgment and voids the split. Free M6 indicators must NOT move the grade (#213/#227).
>    Tracked: #267.

# Spec — Issue #72: extend the calibration corpus + #61 validation gate beyond M1 (security) to the rest of the deliverable

Status: research draft (2026-07-08). Scope authority: `docs/audit-modules.md` (module definitions), `docs/design/calibration-corpus-spec.md` + `src/scan/calibration.ts` + `targets/calibration/GROUND-TRUTH.md` (the security corpus + gate this replicates), `docs/quality-extras.txt` (M5/M6/M8 briefs), `docs/m4-m6-quality.md` / `docs/m7-performance.md` / `docs/m8-test-quality.md` (the already-built module scanners' runbooks), `tools/pii-classify.mjs` (M10).

> This is a research deliverable. It defines what #72 should build. It does **not** change any rule, fixture, or scanner.

---

## 1. Why this matters — the same blind spot that gave M1 its 0/8

Harvey markets on the security wedge (M1) but *sells* the full 9-module audit. M1 is now the only module with a measured precision/recall: `pnpm validate:calibration` scores the mechanical security layer against 16 planted positives + 15 benign-lookalike negatives and gates the free count at "zero free-count false positives." Before that harness existed, the mechanical layer's real score was **0 true positives / 1 false positive** (`docs/runbooks/dry-run-calibration.md` §8.3) — a scanner everyone *assumed* worked and that actually caught nothing while emitting a credibility-fatal FP.

Every other module — M3 vitals, M4 jscpd, M5 knip, M6 `/simplify`, M7 Supabase advisors, M8 StrykerJS, M10 the PII classifier — is in exactly that pre-#61 state: **tooled but never measured.** Each has a scanner (`src/quality-scan.ts`, `src/perf-scan.ts`, `src/mutation-scan.ts`, `tools/pii-classify.mjs`) that has only ever been exercised against synthetic fixtures shaped from a tool's documented JSON schema — never against a labeled target with known answers, and never gated. We claim "a complete codebase-health audit"; we can currently *prove* precision on one ninth of it.

**#72's objective:** give M3–M10 (excluding M1 which is done, M2 which is dynamic-pentest, M9 which is static-review and out of this batch) the same treatment M1 got — planted POSITIVE + benign NEGATIVE lookalike + a detection + a two-layer gate — so "validated precision/recall across the deliverable" becomes a defensible claim **for the modules where precision is even the right word**, and an honest "validated methodology / regression-gated" claim for the two that are irreducibly judgment-heavy.

The #61 two-layer pattern to replicate everywhere:
- **Layer 1 (`pnpm verify`, binary-less CI):** a unit test scores the scanner's *shaping/scoring logic* against a **recorded** tool output (the pattern in `src/scan/calibration.test.ts`, `src/perf-scan.test.ts`, `src/mutation-scan.test.ts`). Runs on every push, no external binary/DB/network.
- **Layer 2 (`pnpm validate:*`, live):** a command runs the *real* tool against `targets/calibration` and scores it against the answer key (the pattern in `src/cli/validate-calibration.ts`). Run on demand / pre-release.

---

## 2. Per-module sub-specs

Each sub-spec gives: (a) planted POSITIVEs, (b) benign NEGATIVE lookalikes, (c) the tool + invocation, (d) precision tier, (e) the live-env dependency and how to gate it the two-layer way.

Terminology carried from `src/scan/calibration.ts`: `expectedTier` ∈ {`high`, `review`, `connected`}. `high` = ~100% precise, countable; `review` = triage-tier; `connected` = only detectable against a live DB (reported N/A in a static run, validated in a live run — see P-RLS-DISABLED).

---

### M3 — Hotspots (vitals: churn×complexity, coupling, knowledge-risk, AI-provenance)

**What "precision/recall" even means here (read first):** a hotspot *rank* is not a true/false finding. "This file is #1 by churn×complexity" is an ordering over a continuous score, not a boolean a tool is right or wrong about. So M3 does **not** get a precision number. What *is* gateable is (1) the deterministic sub-signals vitals computes — truck-factor-1 / sole-author (a boolean fact given git blame), a co-change coupling edge (a fact given git log), AI-provenance attribution (a fact given the provenance log) — and (2) **rank stability**: the planted "obvious hotspot" must land in the top-K and stay there across runs. Gate M3 as a **regression/ordering check on facts**, not a precision measure.

(a) **Planted positives**

| id | fixture | what vitals must produce | gate type |
|---|---|---|---|
| M3-P-HOTSPOT | a core module file with scripted high churn (many commits) **and** high cyclomatic complexity | ranks in the top-K of the churn×complexity table | rank regression |
| M3-P-TRUCK1 | a complex file committed only ever by one author in the seeded history | flagged truck-factor-1 / sole-author | boolean fact |
| M3-P-COUPLING | two files (`a.ts`, `b.ts`) that are always committed together in the seeded history | reported as a co-change coupling edge | boolean fact |

(b) **Benign negative lookalikes (the vitals FP class)**

| id | fixture | must NOT happen |
|---|---|---|
| M3-N-CHURN-TRIVIAL | a generated/lockfile-like file (`*.gen.ts`, or a config) with very high churn but trivial complexity | must not top the hotspot table (vitals' core>test, complexity-weighted ROI ranking should sink it) |
| M3-N-MULTIAUTHOR | a file committed by ≥3 distinct seeded authors | must not be flagged truck-factor-1 |

(c) **Tool + invocation:** the `vitals` plugin, `vitals_cli.py report --json <path>` (per `docs/audit-modules.md` M3 — "run, don't build"). There is **no Harvey scanner module** for M3 today; #72 must add a thin adapter that (i) runs `vitals_cli.py report --json`, (ii) parses its JSON, (iii) maps hotspot rows / truck-factor flags / coupling edges into the answer-key scorer (§3).

(d) **Precision tier:** N/A — regression-gated, not precision-gated. Boolean sub-signals (truck-factor, coupling) can be asserted as pass/fail; the ranking is asserted only as "planted hotspot ∈ top-K."

(e) **Live-env dependency:** **git history.** Churn, coupling, and knowledge-risk are all derived from commit history — you cannot plant them as static files; you need a repo with real commits by distinct authors. This is the expensive fixture. Options:
- A **build script** (`targets/calibration-vitals/build-history.sh`) that scaffolds files and replays a scripted `git commit --author=...` sequence into a throwaway repo, then runs vitals against it. Deterministic if the script pins dates/authors.
- Or a **committed git bundle** (`targets/calibration-vitals/history.bundle`) unpacked at gate time (avoids re-deriving history each run; version it as a binary fixture).
- Two-layer gate: **Layer 1** — unit test the JSON-parsing/mapping adapter against a **recorded** `vitals_cli.py --json` output committed as a fixture (proves the mapping + rank-check logic in `pnpm verify`, no git/python needed). **Layer 2** — `pnpm validate:hotspots` builds/unpacks the history fixture, runs vitals live, asserts the boolean facts + top-K membership.

---

### M4 — Duplication (jscpd)

(a) **Planted positives**

| id | fixture | detection | tier |
|---|---|---|---|
| M4-P-CLONE-A | `dup/invoice-total.ts` and `dup/order-total.ts` sharing a genuine ≥15-line copy-pasted block (tax/rounding logic) | jscpd reports the clone cluster; `jscpdToFindings` emits an `M4-*` Low/Medium finding | high |
| M4-P-CLONE-B | a second, larger (≥50-line) clone across two more files to exercise the Medium-severity threshold | jscpd cluster; `severityForClone` → Medium | high |

(b) **Benign negative lookalikes (jscpd's FP class = "duplicated text that is not a defect")**

| id | fixture | why benign / suppression |
|---|---|---|
| M4-N-GENERATED | `dup/generated/schema.gen.ts` — a generated file that legitimately repeats a block found elsewhere | generated code is not hand-maintained; path-excluded via `.jscpdignore` / the CLI's existing `node_modules,dist,.next` exclusions extended to the generated glob (`docs/m4-m6-quality.md` §1 FP class "intentional/structural clones") — jscpd must not report a *defect* here |
| M4-N-BOILERPLATE | two Next.js route handlers that share the framework-mandated verbatim boilerplate (e.g. identical `export const config = {...}` + handler signature) below the token threshold | structural clone a framework requires; kept under the min-token threshold / excluded so it is not flagged |

(c) **Tool + invocation:** jscpd via `pnpm quality-scan <dir>` → `src/quality-scan.ts::jscpdToFindings`. Already built. jscpd runs with `--threshold 100` (raw report, not jscpd's own pass/fail).

(d) **Precision tier:** `high`. jscpd's *text-match* precision is ~100% (it does not hallucinate duplication); the only FP is the semantic "is this clone a defect," which the negatives + exclusion config pin. The gate is a real precision measure of *that* decision.

(e) **Live-env:** none. **Fully self-contained PR.** Two-layer: **Layer 1** — extend `src/quality-scan.test.ts` to score `jscpdToFindings` on a recorded jscpd JSON report over these fixtures (positives present, negatives absent). **Layer 2** — the live `validate` command runs real jscpd over `targets/calibration/dup/`.

---

### M5 — Slop / dead code (knip)

(a) **Planted positives**

| id | fixture | detection | tier |
|---|---|---|---|
| M5-P-DEAD-EXPORT | `dead/orphan.ts` exporting `unusedHelper()` imported nowhere | knip `issues[].exports`; `knipToFindings` → `M5-*` | high |
| M5-P-DEAD-FILE | `dead/never-imported.ts` — a whole file no entry point references | knip top-level `files[]`; `knipToFindings` → `M5-*` (measured line count) | high |

(b) **Benign negative lookalikes (knip's known FP class — dynamically-referenced / framework / public-API exports)**

| id | fixture | why benign / suppression |
|---|---|---|
| M5-N-NEXT-MAGIC | a `pages/`/`app/` file with a default-export page **and** framework-magic exports (`getServerSideProps`, or App-Router `metadata` / `generateStaticParams` / `GET`) | Next.js calls these by convention, not by import; knip must treat them as entry points via `knip.json` `entry` globs — must NOT be flagged (`docs/m4-m6-quality.md` §1 FP class "public-API exports, dynamically-referenced exports") |
| M5-N-DYNAMIC-REF | `dead/registry.ts` exporting `handlerA` referenced only by string lookup (`handlers["handlerA"]`) | static analysis can't see the string reference; encode as a knip `ignore`/known-dynamic export — must NOT be flagged |
| M5-N-PUBLIC-API | a package `index.ts` re-export declared in `package.json` `exports` | intended for external consumers; knip's `exports`-aware config keeps it silent |

(c) **Tool + invocation:** knip via `pnpm quality-scan <dir>` → `src/quality-scan.ts::knipToFindings`. Already built. Requires the target has a `package.json` and a `knip.json` (`entry`/`project` globs) so the framework-magic negatives resolve — the target currently ships neither for a `dead/` subtree; #72 adds a minimal `knip.json`.

(d) **Precision tier:** `high`. knip is deterministic; the FP class is entirely "things referenced in ways static analysis can't see," which the three negatives cover. Real precision measure.

(e) **Live-env:** none. **Self-contained PR** (pairs naturally with M4 — same `quality-scan` CLI, same `quality-scan.test.ts`). Two-layer as M4.

---

### M6 — Simplification / reuse / maintainability

**What "precision/recall" even means here (read first):** M6 has **no mechanical detector** — it is the `/simplify` LLM review against `docs/quality-extras.txt` (`docs/m4-m6-quality.md` §0: "Not mechanically detectable"). You cannot gate an LLM suggestion with a precision number the way you gate jscpd. #72 must **not** manufacture one. What #72 *can* build is a **labeled rubric-eval set**: known hand-rolled-vs-stdlib patterns the reviewer *should* flag + benign lookalikes it *should* spare, run through `/simplify`, reported as an **agreement rate against the rubric**, explicitly not a "precision" claim.

(a) **Planted positives (should be flagged for replacement)**

| id | fixture | the standard replacement `/simplify` should name |
|---|---|---|
| M6-P-DEBOUNCE | `simplify/debounce.ts` — a hand-rolled `setTimeout`-based debounce | a stdlib/existing-dep debounce |
| M6-P-GROUPBY | `simplify/group.ts` — a hand-rolled array group-by reduce | `Object.groupBy` / `Map.groupBy` / lodash-es `groupBy` |
| M6-P-UUID | `simplify/id.ts` — a hand-rolled random-id string builder | `crypto.randomUUID()` |
| M6-P-OVERABSTRACT | `simplify/manager.ts` — a single-implementation `interface` + factory wrapping one concrete class | collapse to the concrete code |

(b) **Benign negative lookalikes (should NOT be flagged — `quality-extras.txt` "FALSE POSITIVES")**

| id | fixture | why benign |
|---|---|---|
| M6-N-DEPDROP | a small reimplementation with a `// WHY:` comment explaining it deliberately drops a heavy dependency | "a re-implementation chosen deliberately to drop a heavy dependency — note the tradeoff, don't flag" |
| M6-N-FRAMEWORK | an abstraction mandated by a framework/library contract (e.g. a required provider/adapter shape) | "an abstraction mandated by a framework/library contract (not gratuitous)" |

(c) **Tool + invocation:** the `/simplify` skill / pre-pr-reviewer doctrine, run against the `simplify/` fixture dir. Output is prose recommendations, not `Finding[]` — the eval harness must parse "did the reviewer name fixture X" (by file/line mention).

(d) **Precision tier:** N/A — **rubric agreement rate**, not precision. Report "reviewer flagged 4/4 planted reinventions and spared 2/2 benign lookalikes on this rubric set," never "M6 precision = X%."

(e) **Live-env:** none (but needs a model invocation, so it is not a `pnpm verify` unit gate — it is an eval run). Gate: a `docs/`-tracked rubric eval, run on demand, treated like an LLM-judge eval (regression-watch on the agreement rate), **not** a blocking CI gate.

---

### M7 — Performance (Supabase perf advisors) + bundle/CWV

(a) **Planted positives** (migrations under `targets/calibration/supabase/migrations/`)

| id | fixture | advisor lint | `perf-scan` mapping | tier |
|---|---|---|---|---|
| M7-P-UNINDEXED-FK | a child table with a FK column and **no** covering index | `unindexed_foreign_keys` | `LINT_PROFILES.unindexed_foreign_keys` → Perf | connected |
| M7-P-RLS-INITPLAN | an RLS policy using bare `auth.uid()` (not wrapped in `(select …)`) | `auth_rls_initplan` | `LINT_PROFILES.auth_rls_initplan` → Perf | connected |
| M7-P-UNUSED-INDEX | an index on a column no seeded query touches | `unused_index` | `LINT_PROFILES.unused_index` → Low | connected |

(b) **Benign negative lookalikes**

| id | fixture | why benign |
|---|---|---|
| M7-N-INDEXED-FK | a FK column **with** its covering index | advisor must not raise `unindexed_foreign_keys` |
| M7-N-WRAPPED-RLS | an RLS policy already using `(select auth.uid())` | advisor must not raise `auth_rls_initplan` |
| M7-N-USED-INDEX | an index that backs a seeded/hot query | advisor must not raise `unused_index` (and its removal would be a false "unused" call) |

(c) **Tool + invocation:** `pnpm perf-scan <project-ref>` → `src/perf-scan.ts::parseAdvisorFindings` over the Management API performance advisor (`GET /v1/projects/{ref}/advisors/performance`, same family as the `get_advisors` MCP tool `type: "performance"`). Bundle/CWV (Lighthouse, `next build` first-load JS) is **documented-plan-only** (`docs/m7-performance.md` §3) and out of scope for #72's corpus — flag as a follow-up, don't fake a fixture for it.

(d) **Precision tier:** `connected`. Supabase advisors run Splinter against the **live schema** — deterministic, schema-truth, very low FP (`mechanical-toolchain.md` §6, "highest-trust source"). But they need a DB connection, so — exactly like P-RLS-DISABLED in the M1 corpus — these are `connected`-tier: **N/A in a static run, validated in a live run.** Real precision measure once connected.

(e) **Live-env dependency:** **a live Supabase project/branch.** The MCP toolset here (`mcp__supabase-*__create_branch`, `apply_migration`, `get_advisors`, `delete_branch`) makes this cheap: **Layer 1** — extend `src/perf-scan.test.ts` to score `parseAdvisorFindings` against a **recorded** advisor JSON that contains the three planted lints and omits the benign ones (proves the shaping in `pnpm verify`). **Layer 2** — `pnpm validate:perf-calibration` creates a throwaway branch, applies the fixture migrations, pulls `get_advisors(performance)`, asserts exactly the three positives fire and the three negatives don't, then deletes the branch. (Also verify the `/advisors/performance` path shape live — `docs/m7-performance.md` §1 flags it as inferred-by-analogy, not yet exercised.)

---

### M8 — Test quality (StrykerJS mutation)

(a) **Planted positives** (a source-under-test + a weak test whose weakness makes a specific mutant survive)

| id | fixture | weakness class (`quality-extras.txt` M8) | expected Stryker result |
|---|---|---|---|
| M8-P-TAUTOLOGICAL | `test-quality/discount.ts` + `discount.tautological.test.ts` that asserts a value it just set / mocks the function under test | Tautological | a `ConditionalExpression`/`ArithmeticOperator` mutant on `discount.ts` **survives** |
| M8-P-HAPPYPATH | `test-quality/authz.ts` (allow/deny) + `authz.happy.test.ts` asserting only the allow path | Happy-path only | the mutant that flips the deny branch **survives** (no denial assertion to kill it) |
| M8-P-DBMOCKED | `test-quality/tenant.ts` + `tenant.mocked.test.ts` that mocks the DB/RLS layer | Mocks the database/RLS | the tenant-scope mutant **survives** (mock can't observe it) |

(b) **Benign negative lookalikes**

| id | fixture | why benign / must NOT be flagged |
|---|---|---|
| M8-N-STRONG | `test-quality/discount.ts` also covered by `discount.strong.test.ts` asserting the boundary + the denial | kills every mutant on `discount.ts` → **zero surviving mutants** → not on the false-confidence list |
| M8-N-NOCOV-INTENTIONAL | a trivial type-only/re-export file with no logic to mutate | no valid mutants → must not appear as a low-score module (avoid a "0% score" artifact on a file with nothing to test) |

(c) **Tool + invocation:** `pnpm mutation-scan <dir>` → `src/mutation-scan.ts::summarizeMutationReport`. StrykerJS is an external per-engagement tool (not a Harvey dep), needs a Stryker config with `coverageAnalysis: "perTest"` and a test-runner plugin. The target must have a **working test suite** — the calibration target has none today; #72 adds a mini vitest suite + `stryker.conf.json` (vitest runner) under `test-quality/`.

(d) **Precision tier:** `high` *on the mutant fact* (a survived mutant at a location is deterministic given the suite). **Honesty caveat:** the leap from "a mutant survived" to "this test is bad" is a proxy, and the reverse ("no mutant survived" ⇒ "test is good") is *false* (a mutant can die by accident — `docs/m8-test-quality.md` §4). So the gate measures **mutant-level recall** (planted weak test ⇒ ≥1 survived mutant at the expected location; strong test ⇒ 0), which is real and deterministic; it does **not** validate the qualitative "tests-for-intent" hand-review half — that stays a documented manual method.

(e) **Live-env dependency:** a **working test runner in the target** (local, no external service). Two-layer: **Layer 1** — `src/mutation-scan.test.ts` already scores `summarizeMutationReport` against a recorded Stryker JSON; extend it with a recorded report over these fixtures asserting the survived mutants land on the weak-test sources and none on the strong-test source. **Layer 2** — `pnpm validate:mutation-calibration` installs Stryker (`--no-save`), runs it live against `targets/calibration/test-quality/`, asserts the survived-mutant locations match the answer key. Also closes the `docs/m8-test-quality.md` "Deferred: live timed run" gap.

---

### M10 — Data classification (PII / PHI / PCI)

This is the cleanest module to fold in — `tools/pii-classify.mjs` **already ships a selftest that is a precision measure**, with positives *and* the exact FP negatives baked in (`email_category`, `awaiting_dob_reprompt`, `vendor_health`). #72's job is to promote that selftest into the shared corpus/gate format and back it with a schema fixture in `targets/calibration`.

(a) **Planted positives** (columns in a schema fixture — a `_pii.sql` migration or an `information_schema.columns`-shaped JSON)

| id | column | classifier result |
|---|---|---|
| M10-P-EMAIL | `email` | EMAIL / PII / high |
| M10-P-DOB | `date_of_birth` | DOB / PII / high |
| M10-P-SSN | `customer_ssn` | US_SSN / SENSITIVE_PII / high |
| M10-P-PASSPORT | `passport_number` | PASSPORT / SENSITIVE_PII / high |
| M10-P-CVV | `cvv` | CVV / PCI / high (severity-override → Critical) |
| M10-P-CARD | `card_last4` | CARD / PCI / high |

(b) **Benign negative lookalikes (the classifier's own exclusion pass — `exclusionReason`)**

| id | column | why excluded |
|---|---|---|
| M10-N-EMAIL-CAT | `email_category` | descriptor suffix — categorizes the concept, not the value |
| M10-N-DOB-FLAG | `awaiting_dob_reprompt` | boolean-flag naming, not a data value |
| M10-N-VENDOR-HEALTH | `vendor_health` | infra/system health, not medical health |
| M10-N-NAME-AMBIG | `product_name` | ambiguous `NAME?` → low confidence, review-tier not an assertion |

(c) **Tool + invocation:** `tools/pii-classify.mjs` — `classifyColumn(name, sqlType)` / `buildDataMap(columns)`. `node pii-classify.mjs --selftest` already asserts most of the above; the inventory path reads `information_schema.columns` from a live DB but the classifier is **pure name/type** and runs statically on a schema fixture with no DB.

(d) **Precision tier:** `high` for high-confidence infotypes; `review` for low-confidence/ambiguous (`NAME?`) — the classifier already encodes this in its `confidence` field, matching the corpus tier vocabulary. Real precision measure (name-match determinism + a validated exclusion pass).

(e) **Live-env:** **none** — name/type only, no DB. **Fully self-contained PR.** Two-layer: **Layer 1** — the existing `--selftest` (or a ported vitest) IS the unit gate; extend it to the full positive+negative table above and run it in `pnpm verify`. **Layer 2** — optional: a `pnpm validate:pii-calibration` that runs `buildDataMap` over the committed schema fixture and scores it into the shared matrix (§3).

---

## 3. Consolidated fixture + answer-key plan

### 3a. New files/dirs the calibration target needs

Under `targets/calibration/` (extending the existing security fixtures; the target already has `pages/`, `lib/`, `components/`, `supabase/migrations/`):

```
targets/calibration/
  dup/                         # M4
    invoice-total.ts           # M4-P-CLONE-A (½)
    order-total.ts             # M4-P-CLONE-A (½)
    report-a.ts, report-b.ts   # M4-P-CLONE-B (≥50-line clone)
    generated/schema.gen.ts    # M4-N-GENERATED (jscpdignore)
  dead/                        # M5
    orphan.ts                  # M5-P-DEAD-EXPORT
    never-imported.ts          # M5-P-DEAD-FILE
    registry.ts                # M5-N-DYNAMIC-REF (string-lookup export)
    index.ts                   # M5-N-PUBLIC-API (package exports)
  pages/dead-page.js           # M5-N-NEXT-MAGIC (default + getServerSideProps)
  knip.json                    # entry/project globs so magic exports resolve
  .jscpdignore                 # dup/generated/**
  simplify/                    # M6 (rubric eval, not a gate)
    debounce.ts, group.ts, id.ts, manager.ts   # M6-P-*
    depdrop.ts, framework-adapter.ts            # M6-N-*
  test-quality/                # M8
    discount.ts, authz.ts, tenant.ts           # sources-under-test
    *.tautological/happy/mocked.test.ts        # M8-P-* weak tests
    discount.strong.test.ts                    # M8-N-STRONG
    stryker.conf.json                          # coverageAnalysis: perTest, vitest runner
  supabase/migrations/
    <ts>_perf_calibration.sql  # M7-P-* (unindexed FK, bare auth.uid, unused index)
                               # + M7-N-* (indexed FK, (select auth.uid()), used index)
    <ts>_pii_calibration.sql   # M10 schema (or a schema JSON fixture)
targets/calibration-vitals/    # M3 (separate — needs its own git history)
  build-history.sh  OR  history.bundle
```

Recorded-output fixtures for the Layer-1 unit gates (no binaries), colocated with the tests they feed:
- `src/quality-scan.test.ts` fixtures: recorded jscpd + knip JSON over `dup/` and `dead/`.
- `src/perf-scan.test.ts` fixture: recorded advisor JSON with the M7 planted lints.
- `src/mutation-scan.test.ts` fixture: recorded Stryker JSON with the M8 survived mutants.
- M10: the classifier's own selftest table.
- M3: recorded `vitals_cli.py --json` output.

### 3b. How each maps into `GROUND-TRUTH.md` + `src/scan/calibration.ts`

**`GROUND-TRUTH.md`:** add a per-module section mirroring the existing "Mechanical-scan calibration corpus" section — a positives table (id · location · detection · tier) and a negatives table (id · location · why benign) for M3, M4, M5, M6, M7, M8, M10. Keep the "Live result" line format so each module records its last measured score.

**`src/scan/calibration.ts`:** the `CorpusEntry`/`scoreEntry`/`buildCoverageMatrix` machinery is **already generic over `Finding[]`** — `scoreEntry` only needs a finding's `location`, `precisionTier`, and text. So:

1. **Add a `module?: string` field to `CorpusEntry`** (default `"M1"`), and split `CORPUS` into per-module arrays (`CORPUS_M4`, `CORPUS_M5`, …) or tag entries and filter. `buildCoverageMatrix(findings, corpus)` already takes the corpus as a parameter — pass the module's slice.

2. **Modules whose scanner already emits `Finding[]` with `precisionTier` reuse the scorer directly:** M4 (`jscpdToFindings`), M5 (`knipToFindings`), M7 (`parseAdvisorFindings`, at `connected` tier). Give their findings a `precisionTier` (jscpd/knip → `high`; advisor → `high` but `connected`) and they score through `buildCoverageMatrix` unchanged.

3. **Modules whose native output is not `Finding[]` need a thin adapter** that emits a synthetic `Finding[]` for the scorer:
   - **M8:** map each surviving mutant → a `Finding` with `location = file:line`, `precisionTier: "high"`, so "planted weak test's source shows a survived mutant" scores as a positive and "strong test's source shows none" scores as a negative pass.
   - **M10:** map each classified table/column → a `Finding` (`location = column`, `precisionTier` from `confidence`), so the exclusion-pass negatives score as "not flagged."
   - **M3:** map truck-factor-1 files and coupling edges → `Finding`s (boolean facts); handle the top-K rank check as a **separate assertion** (not a `Finding` relevance match) since rank is not a location match.

4. **New CLI gates** mirroring `src/cli/validate-calibration.ts`: `validate:quality-calibration` (M4+M5, static, joins `pnpm verify`-adjacent), `validate:perf-calibration` (M7, connected/live), `validate:mutation-calibration` (M8, live-local), `validate:pii-calibration` (M10, static), `validate:hotspots` (M3, live-git). Each prints the same coverage-matrix format and exits non-zero on a free-count FP / a high-tier miss.

---

## 4. Build sequencing

| order | module | PR shape | why here |
|---|---|---|---|
| 1 | **M10 PII** | single self-contained PR | cleanest — selftest already exists and *is* a precision measure; name-only, no live env; proves the "fold an existing FP-disciplined tool into the shared gate" pattern |
| 2 | **M4 + M5 (quality-scan)** | one PR (shared CLI + `quality-scan.test.ts`) | static, scanners built, self-contained; deterministic tools with a clear FP class |
| 3 | **M8 mutation** | one PR | static-ish but needs a vitest suite + Stryker config in the target (net-new for the target); live command runs locally, no external service; closes the m8 "deferred live run" gap |
| 4 | **M7 perf advisors** | one PR | connected tier — needs a live Supabase branch (MCP `create_branch`/`apply_migration`/`get_advisors` make it cheap); also verifies the inferred `/advisors/performance` path live |
| 5 | **M3 hotspots** | one PR (heaviest fixture) | needs a scripted git-history fixture and a net-new vitals adapter; gate is regression/ordering, not precision — build last so the precision-modules land the headline claim first |
| 6 | **M6 simplify** | separate track (eval, not a gate) | no mechanical detector; a rubric-agreement eval, not a blocking gate — decoupled from the CI gate work |

**Single self-contained PRs (fixtures + Layer-1 unit gate in `pnpm verify`, no external dep):** M10, M4+M5. Plus the Layer-1 *shaping* tests for M7 and M8 (recorded-output fixtures) land in their PRs even though Layer-2 needs live env.

**Need live-env work for the real measurement:** M7 (Supabase branch), M8 (vitest+Stryker install & run), M3 (git history + python vitals).

**Not a gate at all:** M6 (LLM rubric eval).

---

## 5. Honest scoping — mechanical vs. judgment-heavy, and what the gate actually proves

| module | nature | what the gate is | claim it supports |
|---|---|---|---|
| **M10** classifier | deterministic (name/type match + exclusion pass) | **real precision measure** | "validated precision on PII classification" |
| **M4** jscpd | deterministic (text match); FP is the semantic defect call | **real precision measure** on the defect-vs-benign-clone decision | "validated precision on duplication" |
| **M5** knip | deterministic; FP is dynamic/framework/public-API exports | **real precision measure** | "validated precision on dead-code" |
| **M7** advisors | deterministic on a live schema | **real precision measure, connected tier** (N/A static) | "validated precision on DB performance advisories (connected)" |
| **M8** Stryker | deterministic mutant fact; "bad test" is a proxy | **real recall measure at the mutant level**; does NOT validate the qualitative intent-review half | "validated mutation-level recall; qualitative review is a documented method" |
| **M3** vitals | churn/complexity/coupling deterministic; **rank is an ordering, not a boolean** | **regression/ordering check on facts** (truck-factor, coupling) + top-K stability — NOT a precision % | "regression-gated hotspot signals + reproducible ranking" — **never** "M3 precision = X%" |
| **M6** simplify | LLM judgment, no detector | **rubric agreement rate** (LLM-judge eval), not a gate | "measured against a labeled rubric set" — **never** a precision number |

**The discipline line (do not cross it):**
- A jscpd clone, a knip dead export, an advisor lint, a survived mutant, and a PII name-match are **true/false facts** — precision/recall is meaningful and the gate is a real measure.
- A hotspot **rank** and a simplification **suggestion** are **not** true/false findings. For M3 the honest artifact is "the planted hotspot reproducibly lands in the top-K and the deterministic sub-signals are correct" (a regression check). For M6 it is "the reviewer agreed with the labeled rubric on N/N items" (an eval). Reporting either as a precision percentage would be the exact over-claim #61 exists to prevent.
- **Connected-tier caveat (M7):** like P-RLS-DISABLED, a static `pnpm verify` run reports M7 as N/A, not as passing — the precision claim is only earned by the live-branch run. Don't let a green `pnpm verify` imply M7 precision was measured.

**Uncertain / to confirm before building:**
- The `/advisors/performance` Management API shape is inferred by analogy (`docs/m7-performance.md` §1) — confirm live on the first branch run.
- Stryker's default JSON output path (`reports/mutation/mutation.json`) is not version-pinned (`docs/m8-test-quality.md` §1) — confirm against the installed version.
- vitals `--json` schema (hotspot rows, truck-factor flags, coupling edges) is **not documented in this repo** — needs a real `vitals_cli.py report --json` capture before the M3 adapter can be written; I could not verify its field names.
- Whether the M3 git-history fixture should be a build script (reproducible, needs git+python at gate time) or a committed bundle (binary fixture, faster) is a build-time trade-off left open.

---

## 6. Sources

Repo (authority, reused not re-derived): `docs/audit-modules.md`, `docs/design/calibration-corpus-spec.md`, `docs/design/mechanical-toolchain.md` §6–§7, `docs/quality-extras.txt`, `docs/m4-m6-quality.md`, `docs/m7-performance.md`, `docs/m8-test-quality.md`, `targets/calibration/GROUND-TRUTH.md`, `src/scan/calibration.ts`, `src/cli/validate-calibration.ts`, `src/quality-scan.ts`, `src/perf-scan.ts`, `src/mutation-scan.ts`, `src/findings.ts`, `tools/pii-classify.mjs`.

Tool methodology:
- jscpd (copy/paste detection, token threshold): https://github.com/kucherenko/jscpd
- knip (dead exports/files; dynamic-reference & entry-point FP class): https://knip.dev/
- StrykerJS (mutation testing; `coverageAnalysis: perTest`, mutation score = detected/valid; mutation ≠ line coverage): https://stryker-mutator.io/docs/stryker-js/ · mutation-testing-elements schema: https://github.com/stryker-mutator/mutation-testing-elements
- Supabase database advisors / Splinter (performance lints: `unindexed_foreign_keys`, `unused_index`, `auth_rls_initplan`): https://supabase.com/docs/guides/database/database-advisors · RLS initplan (`(select auth.uid())`): https://supabase.com/docs/guides/database/postgres/row-level-security#call-functions-with-select
- vitals plugin (churn×complexity ROI ranking, truck-factor, co-change coupling, AI-provenance): `docs/audit-modules.md` M3 (external `vitals_cli.py`; no public doc captured — schema unverified).
- PII taxonomies the classifier aligns to: Google Cloud DLP infoTypes https://cloud.google.com/dlp/docs/infotypes-reference · Microsoft Presidio https://microsoft.github.io/presidio/ · HIPAA 18 identifiers · GDPR Art. 9 · PCI-DSS cardholder/SAD.
- #61 two-layer gate pattern: `src/scan/calibration.ts` + `src/scan/calibration.test.ts` + `src/cli/validate-calibration.ts`.
