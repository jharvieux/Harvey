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

### 3.1 Run log — first execution (2026-07-15, #265)

The eval had never been executed since the corpus landed 2026-07-09 (#72). First run below.

| run | date | reviewer | positives flagged | negatives spared | verdict |
|---|---|---|---|---|---|
| 1 | 2026-07-15 | Claude Opus 4.8, M6 brief (`docs/quality-extras.txt` §SIMPLIFICATION) as the prompt, no other context | 4/4 | 2/2 | **contaminated — do not treat as a pass** |
| 2 | 2026-07-15 | Claude Opus 4.8, M6 brief as the prompt, against the de-labelled corpus | 4/4 | **1/2** | **usable baseline** — one negative flagged (`framework-adapter.ts`); see §3.2 |

**Procedure followed.** The reviewer read the M6 brief, then the six fixture files, wrote up
what it would flag, and only then opened `targets/calibration/GROUND-TRUTH.md` to score. Answer
key strictly after the review, per §3.

**Result as scored: 4/4 positives named (`debounce.ts`, `group.ts`, `id.ts`, `manager.ts`),
2/2 negatives spared (`depdrop.ts`, `framework-adapter.ts`).**

**Why that number is worthless, and the real finding of this run:**

Every one of the six fixtures opens with a header comment naming its own expected verdict —
`// simplify/debounce.ts — PLANTED (M6-P-DEBOUNCE)`, `// simplify/depdrop.ts — BENIGN
(M6-N-DEPDROP)` — several of which additionally cite the exact rubric clause that decides them
("quality-extras.txt 'FALSE POSITIVES' — an abstraction mandated by a framework/library
contract") and state the expected outcome outright ("The rubric must NOT flag this one").

The eval's stated purpose (§3/§4) is to force the reviewer to *reason about the why* — the
`// WHY:` tradeoff comment, the framework contract — rather than pattern-match on shape. The
labels defeat that: a reviewer that read nothing but the first line of each file scores 6/6.
The negatives, which the design doc correctly identifies as the whole point, are the most
contaminated of the six — `framework-adapter.ts` line 3 *tells the reviewer not to flag it*.

This reviewer cannot certify which signal it actually used. Both the labels and the genuine
discriminators (`depdrop.ts`'s `// WHY:` comment; `framework-adapter.ts`'s
`getServerSideProps` contract) were in context simultaneously, and introspective claims about
which one drove the verdict are not evidence. **Assume the labels were sufficient**, because
they were. 4/4 + 2/2 is consistent with a reviewer doing the rubric perfectly and equally
consistent with one grepping for `PLANTED`. The run does not distinguish them.

The design doc already warned this corpus "says nothing about the reviewer's false-positive
rate on code nobody labeled" (§3, *What this is explicitly NOT*). That warning was about
curation and sample size. This is a strictly worse defect: as it stands, run 1 does not measure
the reviewer against the *rubric* at all, only against a header comment. **Recorded as a
contaminated baseline — not a pass, and not a regression-watch datum** (a future prompt/model
change would be compared against a number that never measured the thing it names).

**What run 2 needs** (tracked as a follow-up, not fixed here — restructuring the corpus is
outside #265's "run the eval" scope, and the fix has a real design choice in it):

- Strip the verdict-bearing header comments from the six fixtures, moving the labels into
  `GROUND-TRUTH.md` only (which the reviewer reads after, per §3). The corpus is scored by
  file path, so nothing about the eval mechanism needs the in-file id.
- **The one comment that must survive is `depdrop.ts`'s `// WHY:` block** — that is not a
  label, it is the fixture's actual discriminator, the in-code signal §2 names as separating a
  deliberate dep-drop from a genuine positive. Deleting it would delete the test. The line to
  cut is the `— BENIGN (M6-N-DEPDROP)` header above it, not the `// WHY:` rationale below.
  Same for `framework-adapter.ts`: the `getServerSideProps` shape stays and must be inferable
  from the code; the "rubric must NOT flag this one" header goes.
- Re-run and record as run 2. Only run 2 is a usable baseline.

Until then this table has one row and no trustworthy datum in it. That is a more honest state
than the blank it replaced, but it is not the eval the design doc specifies.

### 3.2 Run log — second execution (2026-07-15, #265 follow-up)

The six fixtures were de-labelled first (verdict headers stripped to `GROUND-TRUTH.md`; `depdrop.ts`'s
`// WHY:` block and `framework-adapter.ts`'s `getServerSideProps` shape kept — those are the
discriminators §2 names, not labels). Run 2 is the first execution against a corpus that does not
announce its own answers.

**Procedure.** The reviewer was a subagent with no prior context: it read the `quality-extras.txt`
M6 section, then the six files, and produced a FLAG/SPARE verdict per file. It was instructed not
to open `GROUND-TRUTH.md`, this document, or git history, and confirmed it read none of them
(it noted `GROUND-TRUTH.md` appeared in a directory listing but was not opened). Scoring happened
only after the writeup. Delegating to a fresh context was deliberate: the operator prompt that
commissioned this run described the fixtures and their traps, so the orchestrating session was
itself contaminated and could not serve as the reviewer without reproducing run 1's defect in a
subtler form.

**Result: 4/4 positives flagged, 1/2 negatives spared.**

- Positives, all named with a concrete replacement: `debounce.ts` (lodash `debounce`), `group.ts`
  (`Object.groupBy`/lodash `groupBy`), `id.ts` (`crypto.randomUUID()`), `manager.ts` (collapse to a
  plain function).
- `depdrop.ts` — **spared, for the right reason.** The reviewer cited the `// WHY:` comment as a
  bounded tradeoff with a revisit trigger. This is the result the de-labelling was for: the
  discriminator §2 designed carried the verdict on its own, with no label present.
- `framework-adapter.ts` — **flagged. A miss against the answer key.**

**The miss, unrationalized.** M6-N-FRAMEWORK is labeled "do not flag: mandated by a framework
contract." The reviewer flagged it as over-abstraction, explicitly considering and rejecting the
framework-contract FP class. Its argument: Next.js's real contract is a module-level
`export async function getServerSideProps(ctx)` — it never discovers or invokes a *class method* —
so `InvoicePageAdapter` cannot be called by the framework at all, the interface has one
implementation, and nothing imports it. It corroborated this against `pages/dead-page.js` elsewhere
in the same target, which uses the module-level form.

**That argument appears to be correct, which makes this a fixture defect, not (only) a reviewer
defect.** Next.js does dispatch `getServerSideProps` as a module-level export; a class method named
`getServerSideProps` is not a framework contract, it is a shape borrowed from one. Run 1's header
comment asserted the contract ("Next.js's `getServerSideProps` middleware convention requires a
context object shaped like this") and that assertion is what made the fixture read as benign —
i.e. the label was not merely *sufficient* to score it, the label was **the only thing** making the
intended verdict correct. Strip the label and the code no longer supports the ground truth. That is
a strictly more useful finding than 6/6 would have been, and it was invisible while the labels were
in place.

**Consequences (not fixed here — this run reports, it does not redesign the corpus):**

1. `M6-N-FRAMEWORK` does not currently test what §4 claims. Either the fixture must become a real
   framework contract whose shape is genuinely mandated *and inferable from the code* (a provider
   interface a library actually calls, an abstract base a framework requires), or the label must
   flip to a positive and the corpus loses its second negative. Filed as a follow-up.
2. Scoring stays **1/2 negatives** for this run. It is not re-scored to 2/2 on the theory that the
   reviewer was "actually right" — the eval measures agreement with the recorded key, and the key
   is what is now in doubt. Reporting 2/2 here would be exactly the rationalized pass §3.1 warns
   against.
3. The one genuinely-load-bearing negative left is `depdrop.ts`, and the reviewer got it right on
   the code alone. A single negative is a thin FP test; restoring a second real one is the open work.

**Caveats on this datum.** The reviewer also volunteered two out-of-scope routings (the
`Math.random()` id as an M1 concern if used as a token; a vulnerable `lodash` pin) — correct
behavior per the brief, and noted here only because it is evidence the reviewer engaged the code
rather than a label. As with any n=6 curated set, this says nothing about false-positive rate on
unlabeled client code (§3, *What this is explicitly NOT*). Report it as **"the reviewer agreed 4/4
positives and 1/2 negatives on this rubric set"** — never as an M6 precision figure.

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
