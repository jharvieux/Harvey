# Free (mechanical) tier — recall measurement

**Issue:** jharvieux/Harvey#868 (the measurement half).
**Date of this record:** 2026-07-26.

This is the free-tier-only recall figure #868 asked for: the FREE (mechanical, source-only) tier's
recall, reported as its own number and **never blended** with the paid semantic tier that carries
the 100% headlines. Every number below is either (a) from a gate re-run in the foreground on this
date, with the command named, or (b) explicitly cited from a dated measurement doc and marked
`recorded — not re-run here` with the reason it could not be re-run automatically. No number here
is quoted from memory.

The framing question this raises — how a shape-dependent, sometimes-low free-tier number should be
presented publicly (`docs/free-tier-scope.md` currently makes the free scan the acquisition funnel) —
is **the operator's decision**. This document records the measured number neutrally and stops there.

---

## 1. The internal gates — re-run 2026-07-26, against Harvey's OWN fixtures

These are fully automated and were re-run in the foreground on this date with the mechanical
binaries on PATH (`semgrep`, `trufflehog`, `gitleaks`, `osv-scanner`). **They score Harvey's own
planted fixtures**, which is exactly the limitation #868 raises: high internal recall is not the
same as recall against keys other people wrote (§2).

### M1 mechanical MIXED corpus — `pnpm exec tsx src/cli/validate-calibration.ts`

```
TP 239  FN 3  FP 0  TN 220 | precision 100.0%, recall 98.8%, F1 99.4%, FPR 0.0%, Youden's J 0.988
```

- OWASP-Benchmark scoring model (#881). Recall 98.8% is **M1 recall on the mixed corpus**, whose
  answer key spans the SCA / secret / header / crypto / config / RLS-schema tiers as well as
  request→sink source rules. Those non-source tiers are high-recall and lift the blended number.
- Heuristic precision gates (labeled fixtures, #823/#896): M1 tenant-scope TP 1 / FN 0, M7 TP 22 /
  FN 0, M8 TP 11 / FN 0 — all precision 100% / recall 100%.
- Severity correctness (#1157): 12/12 annotated positives delivered at the rated severity.
- Git-history secret gate (#129): caught (1 hit recovered from history); benign control cleared.
- Verdict: GATE PASS.

### App-layer request→sink SOURCE tier — `pnpm exec tsx src/cli/validate-source-recall.ts`

This gate exists specifically to produce the free-tier source-detection number (#945). Re-run
2026-07-26:

```
SOURCE-DETECTOR RECALL (app-layer, request→sink):
  38/39 positives caught at ANY tier (97.4%);  8/39 at HIGH (free-count) tier.
  Negatives cleared: 31/31.
  TP 38  FN 1  FP 0  TN 31 | precision 100.0%, recall 97.4%, F1 98.7%, FPR 0.0%
```

**The load-bearing split inside this number:** of the 39 request→sink source bugs, **only 8 (20.5%)
fire at the HIGH / free-count confidence tier**; the other 30 fire only at the `review` tier
(surfaced as lower-confidence indicators, per the "indicators, not verdicts" framing in
`free-tier-scope.md`). So even on Harvey's own fixtures, the high-confidence free-count source recall
is **20.5%**, not 97.4%. The 97.4% is "surfaced as an indicator at any tier."

- M9 source-code (non-taint) tier, scored separately (#1011): 3/3 positives, 2/2 negatives cleared.
- Verdict: GATE PASS (a low recall is the measurement, not a failure — the gate fails only on a
  free-count false positive or a lost high-tier catch).

### Detector inventory — `pnpm exec tsx src/cli/detector-census.ts` (2026-07-26)

M1 182 detectors; total 378 distinct detectors across M1–M10. This counts detectors capable of
firing, which is **distinct from recall** — a detector existing does not mean it fires on an
arbitrary target's shape (§2 is the demonstration of exactly that gap).

---

## 2. Independent answer-keyed targets — the number #868 is actually about

These are the recall figures against keys **other people wrote** (each target's own
CASE-STUDY / README / REMEDIATION-REPORT). They are the honest free-tier number, and they are
materially lower and highly **target-shape-dependent**. All values below are `recorded — not re-run
here`: re-running them requires cloning an external repo and then **manually scoring each raw finding
against the planted answer key**, which is a semantic/manual judgement (the same work the paid tier
does), not a one-command gate. The dates and sources are the measurement docs in `docs/design/`.

| Target | Independent key | FREE mechanical (source-only) | Notes | Doc date |
|---|---|---|---|---|
| `yoanbernabeu/SupatestVibeDemo` | README, 9 planted | **0 / 9 asserted** | engineered to defeat linters (`USING(true)` tautologies); discloses F3/F9 as unassessed indicators | 2026-07-18 |
| `yagaMI-Reverse/nocode-rescue` | CASE-STUDY.md, 8 planted | **1/8 static-only → 3/8** after the Vite campaign | Vite/no-code SPA shape; #565/#576/#589 closed two of the gaps | 2026-07-18 |
| `vandyand/saas-security-teardown` | README + `fixed` diff, 8 | **4 / 8 static outright** (+1 indicator, +1 partial) | 6/8 only when M2 **dynamic** is counted — dynamic is NOT free-tier | 2026-07-18 |
| `thecipherxpro/cipherx-vulnerability-lab` | reconstructed key, 20 real | **7 / 20 outright** (+7 partial = 14/20 touched) | strongest App-Router mechanical result measured; permissive-RLS pass + live SSRF | 2026-07-18 |
| `SuperRedHat/secure-code-review-demo` | REMEDIATION-REPORT, 12 | **6/12 → 11/12** after the App-Router campaign | mechanical rose 6→11 once the App-Router taint detectors fired | 2026-07-18 |

**Range: from 0/9 to 11/12, entirely a function of how closely the target matches the
org-tenant / Supabase-Auth / App-Router / migration-SQL shapes Harvey's rules are written against.**
There is no single defensible mechanical number across independent keys — the honest statement is a
range with the shape-dependence named. A rough central tendency across these five is on the order of
40–55% of planted findings caught mechanically, but that average hides the skew (0/9 and 11/12 both
sit inside it), so the range and the shape-dependence are the honest form, not the mean.

### Two corrections to the #868 table (the table itself has decayed)

The #868 table was a 2026-07-23 read and its mechanical column is **stale for two targets** — the
measurement docs' OWN re-scores (same 2026-07-18 date, further down each doc) already show a higher
mechanical number after the Vite / App-Router coverage campaigns:

- **nocode-rescue:** #868 says 1/8; the re-score in `nocode-rescue-recall-measurement.md` records
  **3/8 mechanical**.
- **superredhat:** #868 says 6/12; the re-score in `superredhat-recall-measurement.md` records
  **11/12 mechanical**.

The "12%–75%" range in the issue is therefore drawn partly from pre-campaign numbers. The *current*
mechanical range is wider on both ends: **0/9 (supatest) to 11/12 (superredhat)**. The core thesis
of #868 survives the correction — the free tier is shape-dependent and often low, the 100% headlines
are the paid tier — but the specific per-target numbers should be quoted from the re-scores, not the
issue table.

### One refinement the issue table omits: "±dynamic" is not free-tier

The #868 column is labeled "Mechanical (±dynamic)". Dynamic (M2 pen-test) is a **paid** tier, not
free. Where a target's number leans on dynamic, the true free (source-only) number is lower — e.g.
vandyand is **4/8 source-only** but 6/8 once the dynamic cross-tenant proof is counted. The free
report ships source-only, so 4/8 is the free-tier figure for that target.

---

## 3. External real-CVE SCA corpus — SecBench.js (`recorded — not re-run here`)

`docs/design/secbench-recall-measurement.md`, dated **2026-07-24** (#879). Held-out corpus of ~600
real npm CVEs. `recorded — not re-run here`: the gate (`validate-secbench.ts`) needs a SecBench
checkout plus an out-of-process, network-bound `npm install --package-lock-only` + osv-scanner pass
per entry — too heavy for this session.

- **Dependency-CVE (SCA) recall: 433/594 (72.9%)** any-advisory; 403/594 (67.8%) exact-CVE.
- **Source-pattern (semgrep) recall: 0/600** — a measured zero, not an estimate. SecBench's bug
  lives inside the vulnerable library with no HTTP request source, so Harvey's taint-mode source
  rules have nothing to match. On this corpus the free tier's value is entirely the SCA engine.

---

## 4. The paid SEMANTIC tier — for contrast only (`recorded — not re-run here`)

`validate-semantic.ts` needs recorded manual LLM pass artifacts (`M1.pass.json` per target, via
`record-pass`). None are checked in, so the semantic gate could only print its corpus on this date,
not score a run — the semantic tier is a manual LLM review, not an automated gate re-runnable here.
The recorded semantic tallies (from the same measurement docs) are:

| Target | Semantic tier | Recorded on |
|---|---|---|
| nocode-rescue | 8 / 8 | 2026-07-18 |
| supatest | 9 / 9 | 2026-07-24 |
| cipherx | 20 / 20 | 2026-07-18 |
| superredhat | 12 / 12 | 2026-07-24 |
| vandyand | (carried the union to 6/8+) | 2026-07-18 |

**This is the split #868 is about: every 100% / near-100% union headline is the SEMANTIC tier
clearing the board. The FREE mechanical tier lands the §2 range underneath it.**

---

## 5. The honest split, in one place

- **Internal fixtures (re-run 2026-07-26):** M1 mixed-corpus recall **98.8%**; but the request→sink
  SOURCE subset is **97.4% surfaced as any-tier indicator, 20.5% (8/39) at high-confidence
  free-count**. High internal recall is inflated by the non-source tiers and by counting review-tier
  indicators.
- **Independent answer keys (recorded 2026-07-18):** free/source-only mechanical recall ranges
  **0/9 to 11/12**, target-shape-dependent, no single defensible number — report the range and the
  shape-dependence.
- **Real-CVE SCA (recorded 2026-07-24):** **72.9%** dependency-CVE recall; **0/600** source-pattern.
- **Paid semantic tier (recorded):** carries the 8/8, 9/9, 12/12, 20/20 union headlines.

The blended "100%" hides the mechanical number precisely because it is a **union across tiers** with
the semantic (paid) tier doing the clearing. Stated as a free-tier-only number, the mechanical tier
is shape-dependent and frequently well below 100%.

---

## 6. Positioning question — for the operator (NOT decided here)

`docs/free-tier-scope.md` makes the free (source-only) scan the acquisition funnel — "the first and
often only artifact a prospect sees" — and already frames findings as **indicators, not verdicts**.
The measured free-tier recall against independent keys is the §2 range (0/9 to 11/12,
shape-dependent) with a high-confidence source-detection rate of ~20% on our own fixtures.

**Decision for the operator (§2 of #868, explicitly not made in this measurement):** invest in
mechanical recall, or make the "indicated vs proved" framing louder so the gap is doing honest work?
This is a positioning call and is the operator's to make. This document only records the number.
