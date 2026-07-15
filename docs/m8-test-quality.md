# M8 test quality & intent runbook — mutation testing + tests-for-intent review

> The headline: *your coverage number is lying to you, here's where.* Two facets — a mechanical
> mutation scan (StrykerJS, whole repo) for the quantitative blind-spot map, and a manual
> tests-for-intent read of the high-value tests (auth, tenant isolation, payments, state
> machines) for the qualitative "would this test catch a real regression" read. See
> `docs/audit-modules.md` M8 for the module catalog entry this generalizes, and
> `docs/quality-extras.txt`'s "TEST QUALITY / INTENT (M8)" section for the hand-review brief.

## 0. What's wired vs. manual

| Facet | Tool | Automated by | Manual step |
|---|---|---|---|
| Mutation scan | StrykerJS (external CLI, not an npm dep of this repo) | `src/cli/mutation-scan.ts` (`pnpm mutation-scan`) shapes the report | Running Stryker itself (needs the client's own test-runner config); triaging surviving mutants |
| Tests-for-intent review | `quality-extras.txt` M8 brief | Not mechanically detectable | Fully manual, brief-driven read of high-value tests |

## 1. Running the mutation scan

StrykerJS is **not** an npm dependency of this repo — it's a per-engagement external tool,
installed into (or alongside) the client repo, the same pattern `src/scan/secrets.ts` uses for
TruffleHog/gitleaks:

```bash
npm install --no-save -D @stryker-mutator/core <test-runner-plugin-for-the-client's-runner>
# e.g. @stryker-mutator/vitest-runner, @stryker-mutator/jest-runner, @stryker-mutator/mocha-runner
```

**Prerequisite:** the client repo needs a working Stryker config (`stryker.conf.json/.mjs/.cjs`)
for its own test runner — Stryker can't infer which runner a repo uses, and this wrapper
deliberately does not generate one from scratch (test-runner choice is too client-specific to
default sensibly). The config **must** set:

- **`coverageAnalysis: "perTest"`** — only re-runs the tests that actually cover each mutant,
  instead of the whole suite per mutant. This is the setting that makes a whole-repo scan
  tractable; without it, mutation testing on anything beyond a toy repo won't finish in the audit
  window.
- **`reporters: ["json"]`** (or include `"json"` alongside whatever human-readable reporter the
  client config already has) — the machine-readable output this wrapper consumes.

Then invoke:

```bash
pnpm mutation-scan <client-repo-path> \
  --concurrency <n> \
  --incremental \
  [--config <path-to-stryker-config>] \
  [--hotspots <hotspot-file-list.txt>] \
  --out findings.mutation-summary.json
```

- **`--concurrency <n>`** — parallel Stryker workers. Set to the audit machine's core count minus
  1–2 (leave headroom for the OS); this is the main lever on wall-clock time for a whole-repo run.
- **`--incremental`** — writes/reads Stryker's incremental file so a **re-run** after a client
  fixes a batch of surviving mutants only re-tests what changed, not the whole repo again. Use it
  on every run (first run pays the full cost and seeds the incremental file; subsequent runs are
  fast).
- **This is a one-time whole-repo batch job**, not a subset scan — per `docs/audit-modules.md` M8,
  don't scope it down to "just the auth module." A partial scan can't produce a credible overall
  mutation score, and the surviving-mutant map is only a complete blind-spot map if it's whole-repo.
- The wrapper shells out to the `stryker` binary (`execFileSync("stryker", ...)`); it throws a
  clear error if the binary isn't on PATH rather than failing silently.
- If a JSON-format Stryker config is in play, the wrapper does a best-effort check that
  `coverageAnalysis` is `"perTest"` and warns to stderr if not (it can't inspect `.mjs`/`.cjs`
  configs statically — check those by hand).

**No test suite at all (#224):** if the target has no real `scripts.test` (missing, or still
npm/pnpm init's `"Error: no test specified"` placeholder), no known test-runner dependency
(vitest/jest/mocha/ava/tape/jasmine/karma/cypress/`@japa/runner`/uvu/tap, or a `--test` script),
and no `stryker.conf.*`/`stryker.config.*` file, `pnpm mutation-scan` doesn't error out with a
"binary not found"-shaped failure — it detects the no-test-suite case
(`src/mutation-scan.ts`'s `detectNoTestSuite`) up front and instead writes `{ finding,
moduleRecord }`: a single High-severity `M8-00` finding ("No automated test suite — mutation
coverage undefined") plus a `{ status: "partial", note }` module record, then exits 0. That is the
M8 report content for that target — a security-critical codebase with zero automated regression
coverage is itself the finding, not a reason the scan failed to run. This shape replaces the usual
`{ summary, reportRows }` output (§2) for that run; the CLI still honors `--out` for it.

**Report path assumption (flagged, not asserted as fact):** Stryker's `json` reporter writes to
`reports/mutation/mutation.json` relative to the repo root by default. This is accurate for
recent Stryker versions at time of writing but **is not version-pinned here** — if the installed
Stryker version writes elsewhere, pass `--report <path>` explicitly (the wrapper skips invoking
Stryker entirely when `--report` is given, so it also works to just shape a report from a run
that already happened).

### Calibration target

`targets/calibration/` (issue #9) is a small deliberately-broken sample app with a
`GROUND-TRUTH.md` of known issues — a reasonable target to validate this wrapper's *shaping*
logic against once it has a test suite and Stryker config of its own. **A live timed run against
it was out of scope for this pass** (see "Deferred" below) — this doc's mutation-scan wiring was
verified against synthetic fixtures shaped from Stryker's documented JSON schema, not a real
Stryker execution.

## 2. Interpreting the output

`pnpm mutation-scan` writes/prints `{ summary, reportRows }`:

- **`summary.overall`** — mutation score across every file (`src/mutation-scan.ts`'s
  `mutationScore()`): `(Killed + Timeout) / valid` where `valid` excludes `Ignored`,
  `CompileError`, and `Pending` mutants. `NoCoverage`, `Survived`, and `RuntimeError` all count
  *against* the score — each is a mutant the suite failed to prove itself against. This mirrors
  Stryker's own published mutation-score metric; if a specific Stryker version's dashboard number
  disagrees by a fraction of a percent, trust Stryker's own report — this wrapper's score is for
  the audit's independent shaping, not a re-implementation guaranteed bit-for-bit identical to
  Stryker's internal calculation.
- **`summary.byModule`** — one row per directory (the generic proxy for "module" a whole-repo
  scan can use without client-specific config), sorted **worst score first** so the weakest test
  coverage surfaces immediately.
- **The line-coverage-vs-mutation-score gap** — Stryker's mutant-level report doesn't carry line
  coverage, so pull that number from the client's own coverage tool (`vitest --coverage`, `jest
  --coverage`, etc.) per module and put it in the `Line cov` column by hand (see §4 mapping). A
  module at 95% line coverage and 40% mutation score is the single most useful sentence in this
  section of the report — it means the tests execute the code but don't assert its behavior.
- **`summary.survivingMutants`** — every `Survived`/`NoCoverage` mutant, with `file`, `line`,
  `column`, `mutatorName`, `replacement` (what the mutant changed the code to), and a `hotspot`
  boolean. Sorted hotspot-flagged first, then file/line.

### Ranked "tests that give false confidence" list

Build this list by hand from `survivingMutants`, not purely mechanically — a surviving mutant
proves a blind spot exists, but the *report format* the client reads needs the rule the test
fails to assert, which requires reading the covering test (if any: `coveredBy` in the raw Stryker
report names it). Format per row:

| Location | Mutator / what changed | Rule the test fails to assert | Priority |
|---|---|---|---|
| `src/scan/supabase.ts:42` | `EqualityOperator`: `===` → `!==` on a tenant_id check | Test never asserts a cross-tenant row is excluded | Critical (hotspot) |

- **Location + the rule the test fails to assert** is the required minimum per the issue spec —
  don't ship a bare mutant list without the "what should have been asserted" read.
- **Priority** comes from §3 below (hotspot/finding cross-reference), not from the mutant alone.

## 3. Cross-referencing surviving mutants against M1 findings / M3 hotspots

Pass `--hotspots <file>` — a plain text file, one repo-relative path per line — to flag surviving
mutants that sit on a file already flagged as a security finding (M1) or a churn+complexity
hotspot (M3). Build that file from whichever of those two ran first in the engagement:

```bash
# from M3 hotspot output (adjust to however hotspots are stored — a Finding[] json or a table)
jq -r '.[] | .location | split(":")[0]' findings.hotspots.json | sort -u > hotspots.txt
# or from M1 findings' locations, same idea, then concatenate + dedupe both lists
```

A surviving mutant on a hotspot file gets `hotspot: true` in the output and sorts to the top of
`survivingMutants` — that's the "top-priority flagging" the issue asks for: an untested mutant on
a security-critical or high-churn path is worse than the same mutant on a stable utility file,
because it's both more likely to hide a real bug *and* more likely to change again. Reflect that
in the ranked table's `Priority` column (Critical/High for hotspot-flagged rows, lower otherwise)
rather than treating every surviving mutant as equally urgent.

## 4. Tests-for-intent hand-review method

The mutation scan is the mechanical half; this is the qualitative half — apply
`docs/quality-extras.txt`'s M8 section directly. Scope the review to **high-value tests only**:
auth, tenant isolation, payments/money math, state machines. Don't attempt to hand-review the
whole suite — that's what the mutation scan is for; the manual read exists because a mutant
surviving *is* proof of a blind spot, but a mutant that *doesn't* survive doesn't prove the test
is good (a test can kill a mutant for an accidental reason and still be intent-less on the actual
business rule). For each high-value test, ask the litmus test from `quality-extras.txt`:

> If you deleted or inverted the logic it covers, would this test go red?

Flag it when the answer is no, using the six categories from `quality-extras.txt`:

1. **Tautological** — asserts a value it just set, or mocks the very thing under test.
2. **Snapshot-only** — a snapshot is the only assertion; "update snapshots" silently absorbs
   regressions.
3. **Asserts WHAT, not WHY** — checks a shape/count/string but not the business rule (e.g.
   "returns 200" without asserting the row is tenant-scoped).
4. **Would pass if the behavior broke** — the general form of the litmus test.
5. **Happy-path only** — no failure/denial/edge assertion on a security- or money-critical path.
6. **Mocks the database/RLS** — a "tenant isolation" test that mocks the DB layer can't observe
   an RLS regression.

Report as the same ranked "tests that give false confidence" list from §2 — merge the hand-review
findings into it (they don't have a Stryker mutant backing them, so leave the "Mutator / what
changed" column blank or note "manual read" there) so the report has one list, not two.

## 5. Feeding the §3b Test-quality table

`docs/audit-report-skeleton.md` §3b "Test quality & intent (M8)" wants:

```
| Module / file | Line cov | Mutation score | Surviving mutants (critical) | Action |
```

Map `pnpm mutation-scan`'s `reportRows` (`src/mutation-scan.ts`'s `toReportRows()`) into it:

- **Module / file** ← `reportRows[].module`
- **Line cov** ← pulled by hand from the client's coverage tool (not in Stryker's report — see §2)
- **Mutation score** ← `reportRows[].mutationScore`
- **Surviving mutants (critical)** ← `reportRows[].hotspotSurvivingCount` (the hotspot-flagged
  subset — that's the "critical" column, not the raw `survivingCount`, so the table matches the
  action-plan priority framing rather than just a raw defect count)
- **Action** ← written by hand per row, e.g. "write a denial-path test for the RLS policy at
  line 42" — pull the specific rule from the ranked false-confidence list in §2/§4.

Also feed the three report-level bullets `docs/audit-report-skeleton.md` §3b M8 already
specifies directly from this wrapper's output: `summary.overall.mutationScore` (mutation score
overall), the per-module rows above (mutation score per module), and the top of
`summary.survivingMutants` / the merged false-confidence list (the "tests that can't fail" and
"surviving mutants on a hotspot" bullets).

## 6. Wiring code

- `src/mutation-scan.ts` — pure transforms: `mutationScore`, `summarizeMutationReport`,
  `toReportRows`, plus the `StrykerReport`/`StrykerMutant` types (the
  mutation-testing-elements JSON schema). Also `detectNoTestSuite`/`noTestSuiteFinding`/
  `noTestSuiteModuleRecord` — the #224 no-test-suite detection and finding/module-record shaping.
  Tested against synthetic fixtures shaped from Stryker's documented schema
  (`src/mutation-scan.test.ts`).
- `src/cli/mutation-scan.ts` — the CLI: invokes `stryker run` against a target repo (or reads an
  already-written report via `--report`), calls the pure transforms, and writes/prints the
  merged summary. Registered as `pnpm mutation-scan` in `package.json`.

---

### Targets/calibration structure: real test fixture vs. no-test-suite demo

`targets/calibration/test-quality/` (added #72) is the **real mutation-shaping-logic target** — it
ships its own `package.json` + `stryker.config.json` with a test suite configured for
`coverageAnalysis: "perTest"`. Pointing `pnpm mutation-scan` at this nested fixture exercises the
normal (Stryker-running) code path.

Pointing `pnpm mutation-scan` at the root `targets/calibration/` instead exercises the **#224
no-test-suite detection path** — it detects no executable test suite at the root and emits the
`M8-00` finding ("No automated test suite") + a `partial` module record, then exits cleanly. This
is the intended demo of what an audit finds when hitting a completely untested app.

Pre-engagement calibration runs (e.g., timing, verifying the Stryker JSON-report shaping) should
target `targets/calibration/test-quality/` for realistic mutation-testing performance data. The
root `targets/calibration/` no-test-suite demo is a separate assertion that the #224 no-test-suite
path is wired correctly — do not rely on it as a performance baseline.
