# M6 — Simplification / reuse eval design (issue #72, M6 slice)

> **Not a gate.** This document defines a paid-tier LLM rubric-agreement eval for M6, not a
> precision/recall gate. M6 has no mechanical detector — there is no false-positive-safe
> automated free version, and no `pnpm validate:*` command this batch adds. Read
> `docs/design/spec-72-crossmodule-corpus.md` §M6 (locked decision, "Product decisions" preamble
> item 2) before extending this: **do not** build a detector, an `expectedTier` for M6, or any
> claim shaped like "M6 precision = X%."

## 1. What M6 is

M6 is the "simplification / reuse / don't reinvent the wheel" third of the maintainability
audit (alongside M4 duplication and M5 dead code — `docs/m4-m6-quality.md`). Where M4/M5 are
mechanical (jscpd text-match, knip static analysis), M6 is a judgment call: "is this code more
complicated than it needs to be, and if so, what's the concrete simpler shape?" That's an LLM
opinion (the `/simplify` skill run against the `docs/quality-extras.txt` M6 brief), not a
true/false fact a tool can assert.

## 2. The rubric

Drawn from `docs/quality-extras.txt`'s SIMPLIFICATION / REUSE section and the repo's own D-091
anti-pattern doctrine (`docs/runbooks/anti-patterns.md`, `docs/runbooks/slop-detection.md`),
which independently converged on the same classes for a different codebase (ATC) — evidence this
rubric generalizes rather than being Harvey-specific.

**Flag for replacement (the M6 positive classes):**

| class | symptom | what to name |
|---|---|---|
| Hand-rolled primitive | a bespoke implementation of something the language/stdlib already provides: date math, deep-clone/equal, debounce/throttle, UUID, query-string parsing, array group-by/chunk, deep-merge, env parsing | the standard replacement (stdlib function, or `crypto.randomUUID()`-class built-in) |
| Hand-rolled dependency feature | reimplementing what an already-in-the-dependency-tree library does (zod, date-fns, lodash-es, the framework router) | the existing dep's equivalent — prefer it over a new dep |
| Over-abstraction | an interface/factory/generic with a single implementation or single call site; a "manager/handler/service" wrapper adding indirection without behavior | collapse to the concrete code |
| Premature/speculative generality | config flags, plugin hooks, extension points with exactly one user | remove until a second user exists |
| Inconsistent patterns | the same task done three different ways across the codebase | converge on one, name which |
| Overcomplicated | would a senior engineer call this overcomplicated for what it does? | propose the simpler shape |

**Spare — do not flag (the M6 negative/FP class, `quality-extras.txt` "FALSE POSITIVES"):**

- A single-use helper kept for testability/seam reasons, or clearly about to gain a second
  caller.
- An abstraction mandated by a framework/library contract (not gratuitous) — e.g. a shape
  `getServerSideProps` or a provider/adapter interface requires even with one implementation
  today.
- A deliberate re-implementation that trades a small amount of hand-rolled code for **not**
  pulling in a heavy dependency — the tradeoff should be noted, not flagged as a defect. The
  signal that separates this from a genuine positive: an explicit `// WHY:` comment recording the
  tradeoff (`docs/runbooks/anti-patterns.md`'s broader doctrine: WHY comments are the good kind).

This is the same discipline M1 already applies to security findings (a rule has a positive class
and a documented FP/negative class) — M6 just can't be scored by a tool the way a Semgrep rule
can.

## 3. How it's assessed — rubric agreement, not precision

There is no `Finding[]`-emitting scanner for M6, so it cannot plug into
`src/scan/calibration.ts`'s `buildCoverageMatrix` the way M4/M5/M7/M8/M10 do (those all have an
adapter that maps a real tool's output into `Finding[]` with a `precisionTier`). M6's output is
prose — a reviewer's writeup, produced by running the `/simplify` skill (or an M6-scoped LLM
review pass) against a target directory.

**The eval, concretely:**

1. Run the reviewer against `targets/calibration/simplify/` (the labeled corpus, §4 below).
2. For each labeled item, check whether the reviewer's writeup names that file (by path, and
   ideally by the specific pattern) as something to simplify — a positive is "named," a negative
   is "not named."
3. Report **agreement**: "the reviewer flagged N/4 planted reinventions and spared M/2 benign
   lookalikes on this rubric set." Track this per run as a regression watch (did a prompt/model
   change make the reviewer worse against the same fixed labeled set?), the same spirit as a
   regression test but for an LLM judge, not a blocking CI gate.

**What this is explicitly NOT:**

- Not a precision percentage on live client code — the labeled set is small and curated
  specifically to be unambiguous; it does not sample the true distribution of a client
  repository, so "4/4 on the rubric set" says nothing about the reviewer's false-positive rate on
  code nobody labeled.
- Not wired into `pnpm validate:calibration`'s `runMechanicalScan` gate, and not added as
  `CorpusEntry` rows in `src/scan/calibration.ts`. `CorpusEntry`/`buildCoverageMatrix` compute a
  precision/recall-shaped coverage matrix over `Finding[]` — feeding M6 through that same
  machinery (even filtered out of the *current* gate, the way M8's mutant-entries or M10's
  classifier-entries are) would leave a `CorpusEntry` sitting in the shared type with an
  `expectedTier` that reads like `"high"`/`"review"`, one line-of-code away from being folded into
  a future gate that quietly asserts an LLM-judge agreement rate as if it were a scanner precision
  number. That's the exact over-claim the locked decision (spec preamble item 2) exists to
  prevent, so M6 stays out of that file entirely. The labeled corpus lives only as fixtures +
  `GROUND-TRUTH.md` prose (§4/§5 below).
- Not a blocking CI gate. `pnpm verify` never invokes an LLM (it's typecheck + lint + tests +
  knip — deterministic, offline). An M6 eval run is a model invocation, on demand, like any other
  LLM-judge eval.

## 4. The labeled corpus

`targets/calibration/simplify/` — six files, four positives + two negatives (paired 1:1 by shape
so each positive has a visually-similar negative that should NOT be flagged, forcing the reviewer
to reason about the *why*, not just pattern-match "this shape looks reusable").

| id | file | class | should flag? |
|---|---|---|---|
| M6-P-DEBOUNCE | `debounce.ts` | hand-rolled `setTimeout`-based debounce | yes — name a stdlib/dep debounce |
| M6-P-GROUPBY | `group.ts` | hand-rolled array group-by reduce | yes — name `Object.groupBy`/`Map.groupBy`/lodash-es `groupBy` |
| M6-P-UUID | `id.ts` | hand-rolled random-id string builder | yes — name `crypto.randomUUID()` |
| M6-P-OVERABSTRACT | `manager.ts` | single-implementation `interface` + factory wrapping one concrete class | yes — collapse to the concrete code |
| M6-N-DEPDROP | `depdrop.ts` | small reimplementation, `// WHY:` comment records a deliberate heavy-dep tradeoff | no |
| M6-N-FRAMEWORK | `framework-adapter.ts` | interface + factory shaped like `manager.ts`, but mandated by a Next.js `getServerSideProps`-style framework contract | no |

Full answer key with reasoning: `targets/calibration/GROUND-TRUTH.md` §"M6 (#72) — Simplification
/ reuse rubric-eval corpus".

## 5. Why M6's verdict is paid

> **Revised 2026-07-15** (operator, #267). This section previously read "Why M6 is paid-only" and
> concluded that M6 had no free form at all. The reasoning below is unchanged and still holds —
> only its scope narrowed: it explains why the **verdict** is paid, not why the module is. See
> §5.1 for the free indicator tier.

M6's *verdict* is inherently an opinion, not a fact a stranger can independently verify from the
report alone the way "this file is duplicated 52 lines" (M4) or "this file is never imported"
(M5) can. Asserting "your `debounce` implementation should be replaced" to a client who hasn't
engaged us yet — with no human sign-off, on code the model may be reading with insufficient
context (maybe the hand-rolled version exists for a reason not visible in the diff) — is
presumptuous in exactly the way a free automated report cannot afford to be; a wrong or
tone-deaf M6 call reads as "the tool doesn't understand our codebase," which is the credibility
failure mode the whole free/paid split exists to avoid (`docs/design/spec-72-crossmodule-corpus.md`
preamble item 1: heuristic/judgment classes are scanned but not asserted free, only after
triage + human sign-off in the paid report).

So M6's verdict, like the deeper M3 coupling/knowledge-risk analysis, is **paid**: the LLM review
runs, but its output goes through human review before it reaches a client, same as any other
`review`-tier finding — except M6 has no tier at all in the precision-gate sense, because there is
no mechanical baseline to triage against. The rubric-agreement eval in this document is how we
keep confidence that the reviewer is still doing its job as the prompt/brief/model evolves — it is
an internal quality bar for the paid deliverable, not a metric we show a client.

### 5.1 The free indicator tier (2026-07-15)

Operator ruling: *"Free tier can list items that look hand rolled and say they may be worth
investigating. Paid tier triages and says what each one should be replaced with."*

This **applies** the locked principle rather than excepting it. Split the claim in two:

| claim | example | tier |
|---|---|---|
| a shape is present | "`id.ts` builds an id from `Math.random()`; this looks hand-rolled and may be worth investigating" | **free** — descriptive, reader-checkable, hedged |
| what it warrants | "replace it with `crypto.randomUUID()`" | **paid** — the asserted judgment §5 is about |

Why this defuses the FP problem rather than ignoring it: under the free wording, `depdrop.ts`
(M6-N-DEPDROP) is **not a false positive**. It genuinely is a hand-rolled throttle; its `// WHY:`
comment is precisely what an investigation surfaces, in seconds. The free tier was honest and the
reader resolved it. Only the flat assertion "replace this with lodash `throttle`" is *wrong* on
that file — and that assertion is paid.

**Consequence for detector design (#267):** the graduation bar "a pattern only ships if its
negative is mechanically distinguishable" **relaxes at the free indicator tier** — free isn't
ruling on the negative. It still binds at the paid tier, where the replacement is named.

**What binds the free tier:**

1. **Non-grading** (#213/#227). M6 indicators must not move the grade — same treatment as the
   source-tier RLS/authz indicators. M6 now takes that identical form: a non-grading
   "verify in deep scan" section. One framing across two modules, not a special case.
2. **The hedged wording is load-bearing.** "Looks hand-rolled / may be worth investigating" is
   what keeps this on the free side of the principle. Copy that drifts to "should be replaced"
   re-asserts the judgment and voids the split.
3. **Volume replaces FP as the risk.** Forty "may be worth investigating" items read as padding
   and bury the real signal. That is a presentation problem (cap / group / density rule), not a
   detection one — decide it before wiring.
4. **Tone.** Hedging buys latitude, not immunity: an indicator on something obviously justified
   still reads as the tool not understanding the codebase.

The eval in §3 is unaffected — it assesses the reviewer's rubric agreement, which is the paid
pass's quality bar either way.

## 6. Sources

`docs/design/spec-72-crossmodule-corpus.md` §M6 (locked scope authority), `docs/quality-extras.txt`
(the M6 brief), `docs/m4-m6-quality.md` §0/§2 (M6's existing "not mechanically detectable" status
and report-mapping guidance), `docs/runbooks/anti-patterns.md` + `docs/runbooks/slop-detection.md`
(the D-091 catalog this rubric cross-checks against), `src/scan/calibration.ts` +
`src/scan/calibration/types.ts` (the `CorpusEntry`/`buildCoverageMatrix` machinery this eval
deliberately does not join), `targets/calibration/GROUND-TRUTH.md` (existing per-module corpus
section format this follows).
