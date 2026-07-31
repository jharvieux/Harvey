# The interprocedural-taint ROI denominator, re-measured on real code (#1289)

**Date: 2026-07-31.** Every figure below was produced by a run in this worktree on that date.
Re-run rather than quote.

## What #1289 charged

#989 closed with *"don't buy interprocedural taint"*, and #1289's adversarial review found both legs
of that answer unsound:

1. **Leg 1 — the benchmark was never run.** `semgrep login` had never been attempted; Semgrep's Free
   Edition includes Pro Engine for a 1-contributor, 1-repo project, so the benchmark the issue asked
   for was free and one login away. The *"or an OSS interprocedural engine"* half was never touched
   either.
2. **Leg 2 — the census that carried the verdict is a generator artifact.** The 274-guard
   interprocedural remainder is 100% authz/authn, but that 100% comes from **two helper names** across
   a synthetic corpus whose generator only emits cross-file helpers inside its authz/authn templates.
   And the largest bucket — 474 guards, 32.2%, *"other guard expression"* — was recorded
   *"mixed — not modeled here"* and never classified.

Both are addressed below. Leg 1's outcome is a credential blocker with a relay; leg 2 is settled, and
it moves the verdict — in the opposite direction from the one the issue expected.

## Reproduction control — the census is the same population

Before classifying anything, the census in `a2-validator-guard-taint-989.md` was reproduced from the
BenchProctor JS/Express quicktest slice (`TheAuditorTool/BenchProctor` at `4fab122`, release
2026.07.22, 6,202 case files), by a classifier written fresh rather than by re-running `census.py`,
which is not committed.

| guard form | this run | `a2-validator-guard-taint-989.md` |
|---|---:|---:|
| other guard expression | 460 | 474 |
| enum `.includes` allowlist | 422 | 408 |
| **helper call, imported/cross-file** | **274** | **274** |
| anchored positive-class regex | **206** | **206** |
| anchored NEGATED-class regex (denylist) | **108** | **108** |
| **total guards / files carrying one** | **1470 / 1470** | **1470 / 1470** |

Three buckets, the total, and the file count reproduce EXACTLY, and so does the decisive detail: the
whole cross-file helper population is `authzCheck` (196) and `authCheck` (78), **nothing else**. The
14-guard difference between the `other` and `enum` columns is a classifier boundary
(`.some(e => x.endsWith(e))` reads as an affix test here and as an allowlist there) and does not move
any conclusion. The doc's census is confirmed as a measurement of what it says it measured.

## Leg 2a — the 474-guard bucket, CLASSIFIED

| shape | count | share |
|---|---:|---:|
| schema-validator `.success` (zod/valibot) | 181 | 39.3% |
| session/identity presence (`!req.session \|\| !req.session.user`) | 100 | 21.7% |
| affix test (`[".jpg",…].some(e => name.endsWith(e))`) | 79 | 17.2% |
| bare truthiness of a local value (`!row`) | 50 | 10.9% |
| numeric coercion / range (`!Number.isFinite(n) \|\| n > 1048576`) | 50 | 10.9% |
| **cross-file helper call** | **0** | **0%** |

Top categories: `sessionfixation` 52, `fileupload` 50, `null_deref` 50, `intoverflow` 50,
`directory_listing_exposure` 25, `debug_code_production` 24, `pathtraver` 19.

**The bucket contains zero cross-file guards.** Every shape in it resolves inside the file, and the
largest slice (39.3%) is the zod `safeParse().success` form the (a2) schema-validator sanitizer
**already models**. #1289's hypothesis — that this is *"exactly where real-code cross-file guards
(`validateEmail`, `sanitizeInput`, shared schema modules) would land"* — is **false for this corpus**.
Classifying it does not rescue the ROI case; it removes the last place an unclassified remainder could
have been hiding.

## Leg 2b — the denominator on REAL code, which is the charge that stands

The self-selection charge is correct and is now measured rather than asserted. The same classifier was
run over four real repositories — the three pinned MIT libraries the M1 precision corpus uses, plus
Harvey's own `src/`:

| repo | source files | negated early-return guards | helper-call guards | **defined in ANOTHER file** | distinct helper names |
|---|---:|---:|---:|---:|---:|
| `s1owjke/prisma-rls` @3393442 | 17 | 46 | 1 | 0 | 1 |
| `zenstackhq/zenstack` @ef0db7f | 837 | 549 | 43 | 33 | 25 |
| `Errorname/prisma-multi-tenant` @16f7bff | 120 | 25 | 2 | 1 | 2 |
| Harvey `src/` | 590 | 618 | 120 | 52 | 44 |
| **total** | **1564** | **1238** | **166** | **86** | **72** |
| *BenchProctor JS/Express quicktest* | *6202* | *1470* | *274* | *274* | ***2*** |

Two findings, and they point the same way.

**(1) The generator's shape is confirmed synthetic.** BenchProctor's entire cross-file-guard
population is **two** function names, both authz-shaped, each appearing a round 196/78 times. Real
code has **72 distinct helper names** across four repos, and they are ordinary type predicates and
filesystem checks — `existsSync` (39), `ok` (17), `isRecord` (7), `isPromise` (6),
`isDelegateModel` (4), `isDataFieldReference` (2). Essentially none is an authorization decision.
#1289 is right that the population was defined such that the conclusion follows.

**(2) Correcting the self-selection makes the ROI case WEAKER, not stronger.** The interprocedural
share on real code is **86/1238 = 6.9%**, against BenchProctor's **274/1470 = 18.6%** — the generator
*over*-represents cross-file guards by a factor of ~2.7. And of the 166 helper-call guards in real
code, **80 (48%) are defined in the SAME FILE**, so a single-file engine already reaches them; the
BenchProctor figure counts none of that, because its helpers are cross-file by template.

So the "don't buy" verdict survives leg 2, on a denominator that now includes real code. What #1289
correctly removed is the *reasoning* that supported it: the original argument was "the remainder is
100% authz/authn, a class we score 0% on". That argument is a generator artifact and should not be
repeated. The replacement argument is arithmetic — the remainder is 6.9% of guards on real code, half
of it same-file — and it is re-measurable.

**Bound on this measurement, so its silence is not read as coverage.** The classifier is regex-based
over `if (!…) return` shapes, not AST-based: it does not see guards written as `if (cond) { ok } else
{ return }`, ternaries, or `assert`-style throws, and its same-file/cross-file split is a textual
definition search rather than a resolved import. Four repos is also not a sample frame — it is the
repos this worktree already had. What it IS is the first measurement of this quantity on code nobody
generated, against a figure that had only ever been measured on code somebody did.

## Leg 1 — the Pro benchmark, attempted and blocked on a credential

Attempted 2026-07-31, in this order:

- `semgrep --version` → `1.164.0`.
- `semgrep install-semgrep-pro` → *"Run `semgrep login` before running `semgrep install-semgrep-pro`.
  Or in non-interactive environments, ensure your SEMGREP_APP_TOKEN variable is set correctly."*
- `semgrep login < /dev/null` → *"Error: semgrep login is an interactive command: run in an
  interactive terminal (or define SEMGREP_APP_TOKEN)"*. `~/.semgrep/settings.yml` still holds only
  `has_shown_metrics_notification` and `anonymous_user_id`; `env | grep -c SEMGREP` is `0`.
- `command -v codeql joern infer` → all absent (exit 1), and `brew list` carries none of them.

#1289's central factual claim is therefore CONFIRMED — login had never been run, and nothing about
Pro's availability was ever tested. What it costs to finish is one operator action, not a purchase:

REASON: `semgrep --pro` has still never been benchmarked against the OSS engine, so the delta between them is unmeasured — the ROI verdict rests on the guard-form census above and not on a differential run.
KIND: empirical
PROVENANCE: TRIED 2026-07-31 — `semgrep install-semgrep-pro` refuses without a login; `semgrep login` with stdin closed answers "semgrep login is an interactive command: run in an interactive terminal (or define SEMGREP_APP_TOKEN)"; `env | grep -c SEMGREP` is 0 and ~/.semgrep/settings.yml carries only anonymous_user_id. This is a missing-credential blocker and an interactive-terminal one, not a licence cost — Semgrep's Free Edition covers a 1-contributor, 1-repo project. The falsifier as FIRST committed pointed `--config` at `/dev/null`, which semgrep rejects with "config location `/dev/null` is not a file or folder!" — MEASURED 2026-07-31 it exits 7 even with `--pro` REMOVED, so it could never have exited 0 and would have read as "still blocked" forever, the #1345 shape. Re-pointed at this repo's own rule directory and exercised in all three directions the same day, each command run verbatim through `sh -c`: exit 2 as committed, on "Failed to find semgrep-core-proprietary in PATH or in the semgrep package" (Pro engine absent — the blocker); exit 0 for the identical command with `--pro` dropped, which is what the named engine BEING present looks like and is the proof this command has a 0 direction at all; exit 127 with semgrep off PATH (`env PATH=/usr/bin:/bin`), i.e. unverifiable rather than blocked.
FALSIFIER: command -v semgrep >/dev/null 2>&1 || exit 127; semgrep --pro --config src/scan/rules/semgrep/injection.yml --quiet targets/calibration/pages/api/calc.js >/dev/null 2>&1
TOUCHES: src/scan/rules/semgrep

The OSS half is a different shape of open: `joern`, `codeql` and `infer` are all installable, so
declining them would be a budget statement, not an impossibility one. Not attempted this round —
Joern is a JVM CPG toolchain with its own build step, which is a session of work rather than a
command, and leg 2's arithmetic already answers the question #989 asked. Recorded so the next person
can pick it up rather than re-deriving that it was never tried.

## Reproducing

```bash
git clone --depth 1 https://github.com/TheAuditorTool/BenchProctor.git
unzip BenchProctor/Benchmarks/quicktest/javascript/benchproctor-javascript-quicktest-2026.07.22.zip -d js-quicktest
# then: classify `if (!<cond>) return`/`if (!<cond>) { … return }` in js-quicktest/express/testcode,
# mapping each file to its category through express/expectedresults-2026.07.22.csv, and run the same
# classifier over the real repos above. The reproduction control is the table at the top: 1470
# guards in 1470 files, helper-call exactly 274, and exactly two helper names.
```
