# Deterministic (non-LLM) triage ceiling — spike #977

**Question (measure-first, decision stays operator-gated):** how much of the paid-LLM triage step
that suppresses mechanical-tier false positives can be made **deterministic** (sanitizer-aware taint),
and where does the LLM/human boundary genuinely remain? Every number below is from a run in this
session (2026-07-24) against the BenchProctor `2026.07.22` JS/Express quicktest slice + Harvey's own
`docs/fp-rules.txt` + a real engagement's recorded triage decisions. Nothing is recalled.

## Answer in one line

FP-suppression splits by **corpus**, not by a single ratio: on the **generic injection/XSS/SSRF
classes the suppression is overwhelmingly guard-decidable (a)** and a sanitizer/guard-aware taint pass
can retire most of it deterministically; on Harvey's **multi-tenant / authorization core it is
overwhelmingly intent-requiring (b)** — not mechanizable, and not benchmarkable by BenchProctor.
**Recommendation: a hybrid split — deterministic taint handles (a); the LLM/human tier is retained
for (b).**

## The (a)/(b) framework (from the issue)

- **(a) guard-decidable** — "a sanitizer/validator/authz-check on the path makes this safe." Decidable
  from the code by sanitizer-aware taint. Sub-splits into:
  - **(a1) transformation sanitizers** — the tainted value is *transformed* to a safe form
    (`parseInt`, `Number`, an escaper, `DOMPurify.sanitize`, a parameterized-query bind). Cleanly
    modelable as a semgrep taint `pattern-sanitizer`. **The cheap win.**
  - **(a2) validator guards** — the value is *gated* by a control-flow check that returns on failure
    (`if (!/^[\w.-]+$/.test(x)) return`, `if (!["asc","desc"].includes(x)) return`, an interprocedural
    `verifyWebhook(sig)` upstream). Deterministic in principle but needs **control-flow / interprocedural
    taint** — the #873 ceiling (most rules are syntactic today).
- **(b) intent-requiring** — "is this endpoint meant to be public / is this cross-tenant read authorized
  by design / is this deny-all table intentional." Business-logic authorization judgment. **Not taint-
  decidable.** This is Harvey's multi-tenant core.

## Measured — BenchProctor safe-twin discrimination (the (a) benchmark)

BenchProctor's vuln/safe twins differ by exactly one guard, so its safe twins are a purpose-built test
of the (a) safeguard-reasoning population. Measured on the disclosed **sqli** category (50 vuln + 50
safe), where the false-positives come from **Harvey's own** `harvey-sql-injection-template` taint rule
(the XSS FPs, by contrast, come from registry rules Harvey can't add sanitizers to — itself a finding:
a deterministic-triage engine must own its taint, not inherit registry-rule flags).

**Every one of the 10 safe-twin FPs on `harvey-sql-injection-template` is guard-decidable (a):**

| Guard shape | count | (a) sub-type |
|---|---:|---|
| numeric coercion (`parseInt(x,10)`) | 3 | a1 (transformation) |
| char-class allowlist (`/^[\w.-]+$/.test(x)`) | 3 | a2 (validator guard) |
| enum allowlist (`["asc","desc",…].includes(x)`) | 2 | a2 (validator guard) |
| other deterministic guard | 2 | a2 |

**None** of the 15 vuln twins the rule flags launders through any of these guards — so modeling them as
sanitizers clears safe twins **without** dropping a real detection.

### Prototype: a single (a1) sanitizer, measured before/after

A prototype taint rule (`req.*` sources → `.query($SQL)` sink) with vs without a numeric-coercion
`pattern-sanitizer` (`parseInt`/`parseFloat`/`Number`), run over the 100 sqli cases:

| | vuln recall (TPR) | safe FP (FPR) | Youden J |
|---|---:|---:|---:|
| before (no sanitizer) | 60% (30/50) | 32% (16/50) | +28% |
| **after (+ numeric-coercion sanitizer)** | **60% (30/50)** | **18% (9/50)** | **+42%** |

**7 safe twins cleared, 0 vuln lost** (+14 pts Youden from one transformation-sanitizer). The residual
9 FPs are the (a2) validator-guards — deterministic but needing control-flow-aware taint, not a pattern-
sanitizer. So even within a single category the (a1) cheap win is real and measured, and the (a2)
remainder maps exactly onto the #873 syntactic→interprocedural-taint gap.

## Measured — the (b) population, from real triage decisions

`docs/fp-rules.txt` (Harvey's *already-mechanized* FP catalogue) is 14/16 (a) and 2/16 (b) — but it is
selection-biased toward what could be written as a deterministic rule, so it is not the ratio. The
honest (b) sample is the **recorded triage decisions from a real engagement** (`docs/design/aop-audit-
2026-07-18.md`, "Triaged OUT"). Classifying them:

- `verify_jwt=false` edge fns that authenticate internally (Stripe HMAC / `Bearer CRON_SECRET`) →
  **(a2)** interprocedural guard-detection (the replay-protection-lives-upstream fp-rule).
- `.env.local` gitleaks hit → **(a)** trivially decidable (`git ls-files`).
- **`community_maps` RLS-enabled-no-policy = "intentional deny-all, edge-function-only authority,
  clients never SELECT directly"** → **(b) INTENT.** Grants tell you it is deny-all to clients (partly
  (a)), but "this is the intended access model" is a judgment.
- **`match_seed(uuid)` SECURITY DEFINER "guards the caller (seat + finished-status / `auth.uid()` with
  no spoofable arg) — sufficient"** → **(b) INTENT.** A guard exists (detectable), but "is this guard
  sufficient for the intended authority" is the judgment.

The (b) core is uniform: **authorization / tenant-isolation intent** — "is this deny-all intentional,"
"is this cross-tenant/definer path authorized by design, and is its guard sufficient." **BenchProctor
contains none of it** (0 tenant/owner_id/org_id across 6,203 files, per #973), and taint cannot decide
it. This is the boundary the issue told us to state, not blur.

## The deterministic-triage ceiling

| FP-suppression population | mechanizable? | how |
|---|---|---|
| (a1) transformation sanitizers | **yes, cheaply** | semgrep taint `pattern-sanitizers` (demonstrated: sqli FPR 32%→18%, 0 recall loss) |
| (a2) validator / interprocedural guards | **yes, harder** | control-flow / interprocedural taint (#873); semgrep `--pro` or a richer engine |
| (b) authorization / tenant-isolation intent | **no** | genuinely LLM or human — Harvey's multi-tenant core |

**Ceiling, stated honestly:** for the **generic injection/XSS/SSRF classes**, a sanitizer- and guard-
aware taint pass can retire the **large majority** of the LLM's FP-suppression work (all 10/10 sqli
safe-twin FPs are guard-decidable; the a1 slice is a measured, immediate win). For the **multi-tenant
core** — the bulk of the value of a paid Harvey engagement — the deterministic ceiling is **low**: the
suppressions are (b) intent, which is exactly why the semantic tier exists (#870/#912) and why it
cannot be gated away.

## Recommendation — hybrid split (operator-gated decision, not taken here)

1. **Build the (a1) sanitizer models into Harvey's own taint rules** (`pattern-sanitizers` for numeric
   coercion, known escapers/sanitizers, parameterized binds — parameterized-query is already excluded).
   Cheap, improves *free-tier* precision and *reproducibility* (deterministic, same input → same
   verdict), and shrinks LLM load on the generic classes. This is the #900 mechanization pipeline
   applied to guard-decidable suppressions.
2. **Escalate (a2) to interprocedural taint (#873)** as a follow-on — deterministic but a real engine
   investment; measure per-class ROI before committing.
3. **Keep the LLM/human tier for (b)** — multi-tenant authorization intent. Do **not** market or design
   it as retirable: BenchProctor cannot benchmark it, taint cannot decide it, and it is the audit's
   differentiator. Reproducibility/defensibility for (b) come from recording the LLM's rationale
   (`record-pass` artifacts), not from removing the LLM.

## Honest scope

- The (a):(b) ratio is **corpus-dependent** and reported as such — a single global number would be
  misleading (it would move with the corpus mix). The product-relevant statement is per-population.
- The prototype is a **measurement**, not a shipped engine — no shipped rule was changed by this spike;
  the sanitizer prototype lives in scratch. Building #977's recommendation into the rules is the
  operator-gated decision this spike informs.
- BenchProctor benchmarks (a) only; **the multi-tenant core (b) is NOT benchmarkable by it**, and
  real-code realism remains #960 (BenchProctor is synthetic).

## Reproduction

```bash
# BenchProctor JS quicktest extracted per docs/design/benchproctor-evaluation.md (#976).
# 1. numeric-coercion sanitizer prototype, before/after taint rules (scratch):
#    proto-rules/sqli-before.yml (req.* sources -> .query sink)
#    proto-rules/sqli-after.yml  (+ pattern-sanitizers: parseInt/parseFloat/Number)
semgrep --config sqli-before.yml <sqli-testcode> --json -o before.json
semgrep --config sqli-after.yml  <sqli-testcode> --json -o after.json
# 2. classify each finding's file against expectedresults CSV (real vuln vs safe) -> TPR/FPR.
```
