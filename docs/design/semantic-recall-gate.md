# The M1 semantic (LLM) recall gate (#870)

The mechanical tier has a scored gate (`pnpm validate:calibration`). The M7/M8 heuristics have one
(`pnpm exec tsx src/cli/validate-precision.ts`). The **paid semantic pass** — `/vuln-scan --extra
briefs/scan-extras.txt` → `/triage --fp-rules briefs/fp-rules.txt` — had **none**, and the answer-keyed
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
| `superredhat` | `SuperRedHat/secure-code-review-demo` (`vulnerable` branch) | `docs/design/superredhat-recall-measurement.md` | 12 | 1 |
| `supatest` | `yoanbernabeu/SupatestVibeDemo` | `docs/design/supatest-recall-measurement.md` | 9 | 1 |
| `cipherx` | `thecipherxpro/cipherx-vulnerability-lab` | `docs/design/cipherx-recall-measurement.md` | 20 | 2 |

Counts are the corpus as committed — print the current key with
`pnpm exec tsx src/cli/validate-semantic.ts --corpus` rather than quoting this table.

Each entry carries a **location anchor** and **mechanism keywords**, so a right-file/wrong-mechanism
finding (the "partial" those docs record for the mechanical tier) does not score as a catch.

The negatives are recorded semantic FP traps — reporting one means the pass believed appearance over
code, so the gate FAILS. cipherx **CX-21** is an endpoint the target *advertises* as an "outdated
dependencies" bug that actually returns a hard-coded mock CVE list over current dependencies. #912
added three more (one per re-scored target): superredhat **F-N1** (the `notes`/`import` routes reported
as *unauthenticated* — false: both call `getUser()` and 401, the measured #562 false-premise trap),
supatest **F-N1** and cipherx **CX-22** (the browser Supabase *anon/publishable* key reported as an
exposed secret — public by design; cipherx also commits a real `service_role` key, so this is the
`role`-claim distinction fp-rules.txt turns on). **Four negatives across the scored targets** means
semantic PRECISION is now gated — the "essentially ungated" caveat the tool used to print no longer
fires.

## Running it

The semantic pass is an operator/LLM pass, so it leaves its evidence the way every other
out-of-orchestrator pass does (`docs/design/audit-pass-artifacts.md`):

```bash
# 1. clone the target at the ref the key describes
git clone https://github.com/SuperRedHat/secure-code-review-demo /tmp/srh
git -C /tmp/srh checkout vulnerable

# 2. run the semantic pass over it and write the triage output as report-schema findings
#    (/vuln-scan --extra briefs/scan-extras.txt → /triage --fp-rules briefs/fp-rules.txt)

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
tested in `src/scan/semantic-corpus.test.ts`, and the three re-scored passes' actual findings are
carried in `docs/design/semantic-corpus-passes/*.triage.json` and re-scored in
`src/scan/semantic-corpus-passes.test.ts` — both run in verify, so a corpus edit that drops a
planted-flaw match or weakens a precision negative fails there without needing a live pass.

## Live validation — 2026-07-23

Proven end-to-end on one target, not just unit tested. `yagaMI-Reverse/nocode-rescue` was cloned to
a scratch dir, a semantic pass was run over `before/` (5 files, 155 lines) guided by
`briefs/scan-extras.txt` and triaged against `briefs/fp-rules.txt`, its 9 findings were recorded with
`pnpm record-pass`, and the gate scored them: **8/8 planted findings caught, GATE PASS**, with the
generous-match caveat firing on 2 findings that each satisfied two entries. The other three targets
printed as `NOT SCORED` with their reasons and stayed out of the ratio, which is the behaviour that
matters most here.

## Live re-score — 2026-07-24 (#912)

The other three targets were cloned (`superredhat` at the `vulnerable` branch, `supatest` and
`cipherx` at `main`), a semantic pass was run over each target's shipped source + migrations guided by
`briefs/scan-extras.txt` and triaged against `briefs/fp-rules.txt`, and the passes were recorded and
scored. Every planted flaw was re-confirmed present in the current source (cipherx's later
`*_fix_*`/`*_legacy_compat_*` migrations resolve an RLS recursion error only — the weak policies
remain), and the gate scored:

- **superredhat 12/12 (100%)**, negatives cleared 1/1 — GATE PASS
- **supatest 9/9 (100%)**, negatives cleared 1/1, generous-match caveat on 2 findings — GATE PASS
- **cipherx 20/20 (100%)** (CX-21 correctly not reported), negatives cleared 2/2, caveat on 2 — GATE PASS

Aggregate over the three: **41/41 planted findings caught, 4/4 recorded non-vulnerabilities cleared,
GATE PASS.** The 2026-07-18 baselines (12/9/20) **held** — they were confirmed, not merely carried —
so each target's `recordedOn` is refreshed to 2026-07-24. The exact triage findings scored are
committed at `docs/design/semantic-corpus-passes/*.triage.json`; `nocode-rescue` was already scored
2026-07-23 (above) and was not re-run here, so a run scoping `--artifacts-dir` to only the three prints
it `NOT SCORED`, which is honest.

Standing gap now closed: all four corpus targets have been scored by this gate at least once. What
remains is routine re-scoring (each pass artifact is stale after 30 days by design).
