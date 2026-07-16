# M6 — Simplification / reuse eval design (issue #72, M6 slice)

> **Not a gate.** This document defines a paid-tier LLM rubric-agreement eval for M6, not a
> precision/recall gate. M6's verdict has no mechanical detector, and no `pnpm validate:*`
> command exists for it. Read `docs/design/spec-72-crossmodule-corpus.md` §M6 ("Product
> decisions" preamble item 2, as revised 2026-07-15) before extending this: **do not** build an
> `expectedTier` for M6 or any claim shaped like "M6 precision = X%."
>
> _Revision (2026-07-16, #267):_ this preamble previously also said "M6 has no mechanical
> detector … do not build a detector." That sentence predated the operator's free-indicator
> ruling (§5.1) and is superseded for the **indicator** layer only: `src/detectors/handrolled.ts`
> now emits hedged, Info-only, non-grading `M6 — Indicator: …` shape-presence findings (run via
> `pnpm detect-static`, gated by its own fixture pairs in `handrolled.test.ts`). The VERDICT —
> what a shape should be replaced with — still has no detector and never gets one; everything
> else in this document is about that verdict and stands.

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
| 2 | 2026-07-15 | Claude Opus 4.8, M6 brief as the prompt, against the de-labelled corpus | 4/4 | **1/2** | **usable baseline** — one negative flagged (`framework-adapter.ts`), correctly: the fixture was defective, rebuilt in #290. Scored 1/2 against the key it ran against, not re-scored; see §3.2 |
| 3 | 2026-07-16 | Claude Fable 5 (fresh-context subagent), the `pnpm simplify-scan` packet as the sole input, against the corrected corpus (#290 rebuild) | 4/4 | **2/2** | **first trustworthy negative datum** — both negatives spared on code evidence alone; see §3.3 |
| 4 | 2026-07-16 | Claude Fable 5 (a second, distinct fresh-context subagent), the packet as the sole input, against the seven-file corpus (M6-N-SEAM added, #325) | 4/4 | **2/3** | the new seam negative spared for the designed reason; `framework-adapter.ts` flagged on a new, self-rated-low-confidence argument the packet gave it no way to check — see §3.4 |

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
  Same for `framework-adapter.ts`: the framework-contract shape stays and must be inferable
  from the code; the "rubric must NOT flag this one" header goes. (Run 2 then showed that
  fixture's shape was *not* in fact inferable from the code — it was only asserted in the header
  being stripped. Rebuilt in #290; see §3.2.)
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

1. `M6-N-FRAMEWORK` did not test what §4 claims. **Resolved 2026-07-15 (#290): rebuilt, not
   relabeled.** The fixture now implements `SupportedStorage` (a `@supabase/supabase-js` type this
   target already depends on) and hands the instance to `createClient`'s `auth.storage` option — a
   provider interface the library actually calls, with the method names and `string | null` return
   fixed by the library's own type rather than asserted in a comment. The negative survives on
   code-evident grounds and the corpus keeps two. Rationale and the verified type signature:
   `GROUND-TRUTH.md` §"M6-N-FRAMEWORK rebuild".
2. Scoring stays **1/2 negatives** for this run. It is not re-scored to 2/2 on the theory that the
   reviewer was "actually right" — the eval measures agreement with the recorded key, and the key
   is what is now in doubt. Reporting 2/2 here would be exactly the rationalized pass §3.1 warns
   against.
3. At the time of this run the one genuinely-load-bearing negative was `depdrop.ts`, and the
   reviewer got it right on the code alone. #290's rebuild restored the second, so run 3 faces two
   real negatives. (Run 3 executed 2026-07-16 — §3.3.)

**Caveats on this datum.** The reviewer also volunteered two out-of-scope routings (the
`Math.random()` id as an M1 concern if used as a token; a vulnerable `lodash` pin) — correct
behavior per the brief, and noted here only because it is evidence the reviewer engaged the code
rather than a label. As with any n=6 curated set, this says nothing about false-positive rate on
unlabeled client code (§3, *What this is explicitly NOT*). Report it as **"the reviewer agreed 4/4
positives and 1/2 negatives on this rubric set"** — never as an M6 precision figure.

### 3.3 Run log — third execution (2026-07-16, #324)

The first run against the corrected key: #290's rebuilt `framework-adapter.ts` plus the five
fixtures run 2 already faced. The question this run existed to answer (#324): does a reviewer
spare the rebuilt negative on the code evidence alone — `implements SupportedStorage` and the
instance handed to `createClient({ auth: { storage } })` — with no comment telling it to?

**Procedure.** Two deliberate properties, both continuing §3.2's discipline:

- **Fresh-context reviewer.** A subagent (Claude Fable 5) with no prior context, instructed to
  read exactly one file and nothing else — no repo files, no `GROUND-TRUTH.md`, no design docs, no
  git history — and to confirm afterwards what it read (it confirmed: the packet only). The
  orchestrating session had read the answer key and did not review, per §3.2's contamination
  reasoning.
- **The production packet as the input.** Unlike runs 1–2 (brief + files read separately), run 3's
  sole input was the packet emitted by `pnpm simplify-scan targets/calibration/simplify` — the
  first eval run through the #266 runner path, so the run also exercises the packet M6 actually
  ships. The packet embeds the same M6 brief + FALSE POSITIVES sections the earlier runs read, so
  the rubric content is unchanged; the framing prose (the two standing rules in `renderPacket`) is
  the production framing, recorded here as a procedural difference from run 2.

Scoring happened only after the writeup, by the orchestrator, against the `GROUND-TRUTH.md` key.

**Result: 4/4 positives flagged, 2/2 negatives spared.**

- Positives, each with a concrete replacement: `debounce.ts` (lodash-es `debounce`, or consolidate
  with the throttle), `group.ts` (`Object.groupBy`/`Map.groupBy`), `id.ts` (`crypto.randomUUID()`,
  plus the predictability point), `manager.ts` (collapse to a plain function — it read
  `manager.ts`'s "no second implementation is planned" comment as evidence *for* the finding,
  which is exactly right).
- `depdrop.ts` — **spared on the `// WHY:` block**, the designed discriminator, same as run 2.
- `framework-adapter.ts` — **spared on the library contract in the code**: the reviewer named
  `SupportedStorage` and the `auth.storage` option as the reason the class shape is mandated, with
  no header comment present to assert it. This is the datum #290's rebuild was built to make
  possible and run 2 could not provide.

**What can now be said about M6's negative side, and what still can't.** The corrected corpus has
a measured run: *the reviewer agreed 4/4 positives and 2/2 negatives on this rubric set*. That is
the regression-watch baseline for future prompt/model changes. It is still an n=6 curated set —
it says nothing about the false-positive rate on unlabeled client code, and must never be quoted
as "M6 precision" (§3, *What this is explicitly NOT*).

**Corpus artifact worth knowing (not a miss).** The reviewer cross-read the fixtures as one
codebase: it observed that `debounce.ts`'s existence arguably satisfies the "second lodash-es
need" revisit trigger in `depdrop.ts`'s `// WHY:` comment, and folded that into its `debounce.ts`
recommendation (while still sparing `depdrop.ts`). Correct reasoning over the directory as given;
just remember the six files were authored as independent fixtures, so cross-file inferences like
this are artifacts of co-location, not planted signals.

### 3.4 Run log — fourth execution (2026-07-16, #325)

Same procedure as §3.3 (a second, distinct fresh-context Claude Fable 5 subagent; the regenerated
`pnpm simplify-scan` packet as its only input; confirmed it read nothing else; scored after the
writeup by the contaminated orchestrator, who did not review). First run over the seven-file
corpus: `reconcile.ts` (M6-N-SEAM, added by #325 for the third `quality-extras.txt` FP class) now
in the set.

**Result: 4/4 positives flagged, 2/3 negatives spared.**

- **M6-N-SEAM: spared, for the designed reason** — the reviewer named the pure-`reconcileTotals` /
  I/O-`monthlyReconciliation` split as "exactly the 'single-use helper that exists for
  testability/seam reasons' the FALSE POSITIVES section protects — the pure function is
  unit-testable without a database." That is the new fixture's discriminator carrying the verdict
  from code alone on its first exposure, the datum #325 wanted.
- `depdrop.ts`: spared on the `// WHY:` block, consistent with runs 2–3.
- `framework-adapter.ts`: **flagged — a miss against the key**, but NOT run 2's argument (the
  #290 rebuild killed that one for good: this reviewer explicitly accepted that `SupportedStorage`
  mandates the class shape). Its new argument: the file as a whole duplicates what `@supabase/ssr`
  provides. It self-rated this "my lowest-confidence flag," conceding it could not see whether
  `@supabase/ssr` is installed — and it is not: the rubric class it invoked is *hand-rolled
  versions of an **already-in-the-dependency-tree** library's feature*, and the premise was
  unverifiable from the packet, which contains no dependency manifest. Scored as a miss against
  the recorded key, per the same no-rationalizing rule as run 2.

**What run 4 adds beyond the score.** Two findings about the eval itself:

1. **Reviewer variance is now measured, not hypothesized.** Runs 3 and 4 saw the same
   `framework-adapter.ts` under the same rubric and split on it. This is what the
   regression-watch framing (§3) is for — single runs are datapoints, not verdicts — and it is
   also the concrete argument for the paid tier's human sign-off (§5).
2. **The packet gives a reviewer no way to apply the "already-in-the-dependency-tree" rubric
   class.** `simplify-scan` packets carry source files only, so any dep-tree claim a reviewer
   makes is a guess; run 4's miss is exactly that guess going wrong. Follow-up: include the
   target's `package.json` (or a dependency list) in the packet. Tracked as a follow-up issue
   from the #325 batch.

Report run 4 as **"the reviewer agreed 4/4 positives and 2/3 negatives on this rubric set"** —
never as an M6 precision figure.

## 4. The labeled corpus

`targets/calibration/simplify/` — seven files, four positives + three negatives (paired by shape
so each positive has a visually-similar negative that should NOT be flagged, forcing the reviewer
to reason about the *why*, not just pattern-match "this shape looks reusable"). The three
negatives now cover all three FP classes `quality-extras.txt` names: the deliberate dep-drop, the
framework/library contract, and — added 2026-07-16, #325 — the single-use helper kept as a
testability seam.

| id | file | class | should flag? |
|---|---|---|---|
| M6-P-DEBOUNCE | `debounce.ts` | hand-rolled `setTimeout`-based debounce | yes — name a stdlib/dep debounce |
| M6-P-GROUPBY | `group.ts` | hand-rolled array group-by reduce | yes — name `Object.groupBy`/`Map.groupBy`/lodash-es `groupBy` |
| M6-P-UUID | `id.ts` | hand-rolled random-id string builder | yes — name `crypto.randomUUID()` |
| M6-P-OVERABSTRACT | `manager.ts` | single-implementation `interface` + factory wrapping one concrete class | yes — collapse to the concrete code |
| M6-N-DEPDROP | `depdrop.ts` | small reimplementation, `// WHY:` comment records a deliberate heavy-dep tradeoff | no |
| M6-N-FRAMEWORK | `framework-adapter.ts` | single-implementation class shaped like `manager.ts`, but `implements SupportedStorage` (a `@supabase/supabase-js` type) and is passed to `createClient`'s `auth.storage` — the library calls it; rebuilt 2026-07-15 (#290) | no |
| M6-N-SEAM | `reconcile.ts` | single-use helper shaped like the over-abstraction class (`reconcileTotals`, one caller), but it is the exported pure money-math half of a function whose other half is Supabase I/O — inlining it would entangle the logic with the network (the brief's own MISSING SEAMS failure); added 2026-07-16 (#325) | no |

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
