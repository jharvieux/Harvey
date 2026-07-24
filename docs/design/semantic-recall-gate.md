# The M1 semantic (LLM) recall gate (#870)

The mechanical tier has a scored gate (`pnpm validate:calibration`). The M7/M8 heuristics have one
(`pnpm exec tsx src/cli/validate-precision.ts`). The **paid semantic pass** — `/vuln-scan --extra
docs/scan-extras.txt` → `/triage --fp-rules docs/fp-rules.txt` — had **none**, and the answer-keyed
measurements say it is the tier carrying the product: it is the difference between 1/8 and 8/8 on
nocode-rescue, 6/12 and 12/12 on SuperRedHat, and 100% of the catch on SupatestVibeDemo. A brief
edit, a model change or an `fp-rules.txt` tweak could degrade it and nothing would fail.

This is that gate. It does not run the LLM — it **scores the artifact a semantic pass leaves**.

## The corpus

`src/scan/semantic-corpus.ts` holds the answer key for the four targets whose semantic tier was
measured against a published key, transcribed from the per-finding tables of the measurement docs:

| slug | repo | key | positives | negatives |
|------|------|-----|-----------|-----------|
| `nocode-rescue` | `yagaMI-Reverse/nocode-rescue` (`before/`) | `docs/design/nocode-rescue-recall-measurement.md` | 8 | 0 |
| `superredhat` | `SuperRedHat/secure-code-review-demo` (`vulnerable` branch) | `docs/design/superredhat-recall-measurement.md` | 12 | 0 |
| `supatest` | `yoanbernabeu/SupatestVibeDemo` | `docs/design/supatest-recall-measurement.md` | 9 | 0 |
| `cipherx` | `thecipherxpro/cipherx-vulnerability-lab` | `docs/design/cipherx-recall-measurement.md` | 20 | 1 |

Counts are the corpus as committed — print the current key with
`pnpm exec tsx src/cli/validate-semantic.ts --corpus` rather than quoting this table.

Each entry carries a **location anchor** and **mechanism keywords**, so a right-file/wrong-mechanism
finding (the "partial" those docs record for the mechanical tier) does not score as a catch.

The one negative is cipherx **CX-21**: an endpoint the target *advertises* as an "outdated
dependencies" bug that actually returns a hard-coded mock CVE list over current dependencies.
Reporting it means the pass believed the repo's marketing over its code. **One negative across four
targets means semantic PRECISION is effectively ungated** — the tool says so in its own output
rather than letting the silence read as a clean bill of health.

## Running it

The semantic pass is an operator/LLM pass, so it leaves its evidence the way every other
out-of-orchestrator pass does (`docs/design/audit-pass-artifacts.md`):

```bash
# 1. clone the target at the ref the key describes
git clone https://github.com/SuperRedHat/secure-code-review-demo /tmp/srh
git -C /tmp/srh checkout vulnerable

# 2. run the semantic pass over it and write the triage output as report-schema findings
#    (/vuln-scan --extra docs/scan-extras.txt → /triage --fp-rules docs/fp-rules.txt)

# 3. record it under the target's slug
pnpm record-pass --module M1 --pass semantic --target /tmp/srh \
    --findings triage.json --out artifacts/superredhat

# 4. score every corpus target
pnpm exec tsx src/cli/validate-semantic.ts --artifacts-dir artifacts
```

`--json` emits the raw matrix.

## What makes it a gate rather than a report

- **Regression floor.** Each target records the semantic tally its measurement doc recorded, with
  the date. Catching fewer than that fails. The recorded number is a claim about the past; only a
  scored run produces a present one.
- **FP trap.** Reporting a recorded non-vulnerability fails.
- **Nothing scored is not a pass.** If no target has a fresh, well-formed artifact the gate exits 1.
  A gate that measured nothing has not passed.
- **No silent drops.** Every corpus target prints a row. A target with no pass is `NOT SCORED` with
  the reason and the exact `record-pass` command that would fix it — it is never a zero, because a
  zero would read as "the tier found nothing" instead of "nobody looked". Unscored targets are
  excluded from the ratio's *denominator* too, so the headline percentage never quietly averages in
  work that was never done.
- **Generous matching, disclosed.** Location+keyword matching means one broad finding can satisfy
  two adjacent entries (three of supatest's nine sit in one migration file). The tool counts those
  findings and prints the caveat next to the number.

It is deliberately **not** wired into `pnpm verify`: like `validate:calibration` (which needs the
mechanical binaries), it needs an input `pnpm verify` cannot manufacture. The scoring logic is unit
tested in `src/scan/semantic-corpus.test.ts`, which does run in verify.

## Live validation — 2026-07-23

Proven end-to-end on one target, not just unit tested. `yagaMI-Reverse/nocode-rescue` was cloned to
a scratch dir, a semantic pass was run over `before/` (5 files, 155 lines) guided by
`docs/scan-extras.txt` and triaged against `docs/fp-rules.txt`, its 9 findings were recorded with
`pnpm record-pass`, and the gate scored them: **8/8 planted findings caught, GATE PASS**, with the
generous-match caveat firing on 2 findings that each satisfied two entries. The other three targets
printed as `NOT SCORED` with their reasons and stayed out of the ratio, which is the behaviour that
matters most here.

Standing gap, recorded rather than left implicit: **three of the four targets have never been scored
by this gate.** The recorded baselines for superredhat / supatest / cipherx remain claims about
2026-07-18 until a pass is run and scored against each.
