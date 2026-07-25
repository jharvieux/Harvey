# (a2) validator-guard taint — engine evaluation and per-class ROI (#989)

**Question the issue asked:** the (a2) half of the #977 deterministic-triage split — a tainted value
*gated* by a control-flow validator that returns on failure, rather than *transformed*. #977 recorded
these as needing "control-flow / interprocedural taint — semgrep `--pro` or a richer engine," and
told us to **measure per-class ROI before committing to a large engine investment**.

**Verdict: DON'T buy the engine. The (a2) win is reachable in semgrep OSS and SHIPPED here.** The
part that genuinely needs interprocedural analysis is, measurably, **100% authz/authn** — the (b)
intent population #977 already ruled not taint-decidable. Buying interprocedural taint to reach it
would buy reach into territory taint cannot decide anyway.

Every number below is from a run in this session (2026-07-24), on this branch, against the pinned
BenchProctor release `2026.07.22` JS/Express quicktest corpus and Harvey's own gates. Nothing is
recalled. Reproduction at the end.

## The recorded premise was wrong — re-tested, not repeated

#977 recorded (a2) as requiring `--pro`. Re-tested rather than inherited:

- `semgrep --pro` is **not available on this machine** (`Failed to find semgrep-core-proprietary`),
  so no `--pro` number is claimed here — that is a disclosure, not a measurement.
- Installed OSS engine: **semgrep 1.164.0**.
- **OSS `pattern-sanitizers` with `by-side-effect: true` CAN model an intraprocedural validator
  guard.** That capability is what makes the (a2) win affordable, and it is what #977 did not test.

## The trap: the obvious modeling is UNSOUND, and its unsoundness is invisible in a J score

A 6-vuln / 4-safe adversarial fixture set was built specifically to catch a guard model that clears
real bugs (scratch; the six shipped calibration fixtures below are its permanent form).

| sanitizer shape | TPR | FPR | J | real vulns silently cleared |
|---|---:|---:|---:|---:|
| no guard sanitizer (baseline) | 100% | 100% | +0% | 0 |
| `pattern: $RE.test($X)` / `$ARR.includes($X)` (the obvious form) | 100% | 100% | +0% | 0 (never fires) |
| the same, `by-side-effect: true` | 50% | 50% | **+0%** | **3** |
| **whole-STATEMENT + anchored + positive-class** | **100%** | **50%** | **+50%** | **0** |

The third row is the danger: **Youden's J is identical (+0%) to doing nothing, while three real
injections have been silently cleared.** A precision-only measurement would have called that row
harmless. The three it cleared:

1. **failure branch does not return** — validator runs, result discarded, execution falls through;
2. **inverted polarity** — returns on VALID input, falls through to the sink on INVALID;
3. **unanchored allowlist regex** — `/[a-zA-Z0-9_]+/` matches a prefix, so `id; drop table t--` passes.

### The three soundness constraints that make it correct

- **Match the whole guard STATEMENT** (`if (!<test>) { … return; }`), not the bare test expression —
  this is what ties the suppression to the early return and kills cases 1 and 2.
- **Require an ANCHORED regex** (`^…$`) via `metavariable-regex` — kills case 3.
- **Require a POSITIVE character class.** Found empirically: the first anchored-only version lost a
  real BenchProctor vuln, `benchmark_test_04195.js`, whose guard is `/^[^\x00-\x08\x0e-\x1f\x7f]+$/`
  — anchored, returns on failure, wears the exact safe-twin shape, but the class is **negated**, so
  it is a denylist stripping control characters while quotes and `--` pass. Excluding negated classes
  recovered it with no FP cost (FPR stayed 0%).

That third constraint was **not predicted; it was measured.** It is the reason a "looks obviously
safe" guard shape must be proven against real vuln twins rather than reasoned about.

## Measured — per-class ROI, Harvey's REAL shipped rules, before vs after

Not a prototype rule: `src/scan/rules/semgrep/` as it ships on `main` vs as it ships on this branch,
scored over BenchProctor category slices (50 vuln + 50 safe each, answer-keyed). A case counts
flagged if **any** rule fires on it.

| Category | J before | **J after** | FPR before → after | safe twins cleared | **real vulns lost** |
|---|---:|---:|---:|---:|---:|
| eval_injection | +18% | **+80%** | 62% → 0% | 31 | **0** |
| cmdi | +2% | **+38%** | 70% → 34% | 18 | **0** |
| argument_injection | +10% | **+56%** | 68% → 22% | 23 | **0** |
| sqli | +42% | **+60%** | 18% → **0%** | 9 | **0** |
| pathtraver | +4% | **+16%** | 26% → 14% | 6 | **0** |
| xss | +0% | +0% | 0% → 0% | 0 | 0 |
| **total** | | | | **87** | **0** |

**87 adversarial safe twins retired deterministically across five classes, zero recall loss in every
class, no LLM pass.** Recall (TPR) is *byte-identical* before and after in all six — the sanitizer
only ever removed findings on safe twins.

`xss` is 0/0 because Harvey's rules do not fire on that slice at all (a pre-existing corpus-fit gap
recorded in `benchproctor-evaluation.md`, unchanged by this work) — reported, not hidden.

### The sqli slice reproduces #977 exactly, then extends it

Same slice, same scorer, this session: `before` TPR 60.0% / FPR 32.0% / J +28.0%; `+a1 numeric
sanitizer` TPR 60.0% / FPR 18.0% / J +42.0%. That **reproduces #977's recorded (a1) numbers to the
decimal** — the one recorded claim in that spike that re-tested true. Adding (a2) takes it to **FPR
0.0% / J +60.0%**, clearing all 9 residual safe-twin FPs #977 predicted were (a2)-shaped. Inspected
individually: all 9 are anchored-allowlist or enum-allowlist early-return guards. #977's
classification of the residual was correct.

## Measured — the ROI denominator: how much is left for an interprocedural engine?

Census of **every** early-return guard across all 6,200 JS/Express cases (`census.py`, below):
1,470 guards in 1,470 files.

| Guard form | count | share | reachable in OSS? |
|---|---:|---:|---|
| other guard expression (Zod `.success`, `Set.has`, `.endsWith`, numeric range, session presence…) | 474 | 32.2% | mixed — not modeled here |
| enum `.includes` allowlist | 408 | 27.8% | **yes — shipped** |
| **helper call, imported/cross-file** | **274** | **18.6%** | no — needs interprocedural |
| anchored positive-class regex allowlist | 206 | 14.0% | **yes — shipped** |
| anchored NEGATED-class regex (denylist) | 108 | 7.3% | must NOT sanitize — correctly excluded |

**The decisive finding — what the interprocedural remainder actually is.** Classifying those 274
cross-file helper guards by BenchProctor category:

| category | count | share |
|---|---:|---:|
| authzincorrect (CWE-863) | 50 | 18.2% |
| missingcritauthn (CWE-306) | 50 | 18.2% |
| authnfailure | 50 | 18.2% |
| idor (CWE-639) | 50 | 18.2% |
| authzfailure (CWE-862) | 50 | 18.2% |
| privescalation (CWE-269) | 24 | 8.8% |
| **anything else** | **0** | **0%** |

**100% of the interprocedural-guard population is authz/authn**, and the helper being called is
`authzCheck` (196) or `authCheck` (78) — nothing else. Two independent prior measurements agree that
this is exactly where deterministic triage does not help:

- `benchproctor-evaluation.md`: Harvey scores **0.0% TPR on all five of those categories in both
  scoring modes** — an interprocedural sanitizer cannot suppress FPs on findings that are never
  produced.
- `deterministic-triage-ceiling-977.md`: "is this guard sufficient for the intended authority" is
  **(b) intent** — a guard's *existence* is detectable; its *sufficiency* is a judgment. Resolving
  `authzCheck(user, resource)` interprocedurally tells you a check happened; it cannot tell you the
  check was the right one.

So the engine investment would buy reach into a population that (i) Harvey's rules do not flag, and
(ii) taint cannot adjudicate even with perfect call-graph resolution. **That is the ROI answer #989
asked for, and it is negative.**

## What shipped

The (a2) guard sanitizer, on the 11 taint rules whose sink can be guarded this way:

`harvey-sql-injection-template`, `harvey-sql-injection-rpc`, `harvey-command-injection`,
`harvey-argument-injection`, `harvey-code-injection-eval`, `harvey-path-traversal`,
`harvey-html-template-literal`, `harvey-dangerously-set-inner-html`,
`harvey-dangerously-set-inner-html-stored`, `harvey-dom-innerhtml`, `harvey-crlf-header-injection`.

**Deliberately NOT applied to `harvey-open-redirect`** — measured, not assumed. Its slice was
unaffected (J −6% → −6%, 0 cleared, 0 lost) because all 50 of its safe twins guard a **projection**
(`new URL(data).hostname`) while the sink receives the original value. The guarded variable and the
sunk variable differ, so a by-side-effect sanitizer on the guarded one is correctly inert. Modeling
projection-guards is a distinct piece of work; see the remainder issue.

### Six calibration fixtures — three of them soundness positives

Half of this change is regression-proofing the unsoundness above, so no future edit can quietly
re-introduce it:

- `N-SQLI-REGEX-GUARD`, `N-SQLI-ENUM-GUARD`, `N-CMD-ENUM-GUARD` — safe twins that must **clear**
  (the third proves the model generalizes past SQL to the command-injection sink).
- `P-SQLI-DENYLIST-GUARD`, `P-SQLI-UNANCHORED-GUARD`, `P-SQLI-GUARD-NO-RETURN` — real injections
  wearing the safe-twin shape that must **still fire at high tier**. Each maps to one soundness
  constraint; drop the constraint and its fixture fails loud.

These were verified to fail before they passed: with an anchoring/polarity-blind sanitizer all three
positives regressed to `NOT caught by any rule` and the gate failed. They are a working alarm, not
decoration.

## Gate results on this branch (run here, not recalled)

- `validate-calibration`: **GATE PASS** — TP 218 FN 3 FP 0 TN 208, precision 100.0%, recall 98.6%,
  FPR 0.0%, J 0.986; M1 negatives cleared **208/208**. (On `main` immediately before this change,
  same command: TP 215 FN 3 FP 0 TN 205, recall 98.6%. +3 positives / +3 negatives are this change's
  fixtures; **recall and FPR are unchanged**.)
- `validate-source-recall`: **GATE PASS** — TP 38 FN 1 FP 0 TN 31, recall 97.4%, FPR 0.0%; M9 source
  tier 3/3, negatives 2/2. Unchanged from `main`.
- `pnpm verify`: exit 0, 3167 tests / 172 files pass.
- Dry-run artifacts regenerated with all four mechanical binaries present (no `DEP-OSV-00`).

## Honest scope

- **No `--pro` comparison was run** — the proprietary engine is not installed on this machine. The
  recommendation rests on (i) what OSS was measured to do, and (ii) what the interprocedural
  remainder was measured to *consist of*. Both are corpus-measured; neither is a `--pro` benchmark.
- **BenchProctor is synthetic** (`benchproctor-evaluation.md`, DON'T-ADOPT as a gate). It is used
  here as a **before/after differential on the same corpus**, which is far more robust than its
  absolute scores — but the guard-form census reflects BenchProctor's generator, not field frequency.
  The real-code question remains #960.
- **Category J values are not capability claims.** Absolute TPR is dominated by corpus fit; only the
  before→after deltas are this change's result.
- The (b) authorization-intent population is untouched and remains LLM/human, exactly as #977 stated.

## Reproduction

```bash
# BenchProctor quicktest JS/Express, pinned 2026.07.22, extracted per benchproctor-evaluation.md.
# 1. per-class before/after over the REAL shipped rules (a case is flagged if any rule fires):
python3 slice_score.py <category> <rules-dir-before> <rules-dir-after>
# 2. guard-form census over all 6,200 cases (the ROI denominator):
python3 census.py
# 3. category breakdown of the interprocedural remainder:
python3 interproc_class.py
# 4. Harvey's own gates:
pnpm exec tsx src/cli/validate-calibration.ts
pnpm exec tsx src/cli/validate-source-recall.ts
```
