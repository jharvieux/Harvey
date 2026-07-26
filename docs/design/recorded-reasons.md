# Recorded reasons: the empirical/decisional split, the falsifier, and the gate

Design record for #1033 — the general version of #321.

## The defect

A recorded reason is a blocker, a `not-run` explanation, a "we can't do X" in an issue body, a design
doc or a code comment. **It is a claim about the world, and claims decay.** A 2026-07-24 sweep
re-tested four recorded blockers before building against them and **all four were false**. A
follow-up inventory that session found the population and its shape (numbers below are that
measurement, dated — do not quote them as current):

- 40 open issues, **20 carrying claim-shaped text**, split ~11 empirical / 9 decisional
- **86 claim lines across 33 of 51** `docs/design/*.md`
- 193 `reason:` strings in `src/`, of which **13 assert a standing impossibility** (5 already
  re-validated by #321), leaving ~8 unguarded
- **zero stored falsifiers anywhere**, and `docs/design` carried **2** provenance tags against
  `src/`'s **119** — the prose is the weak surface, not the code

Why these are born wrong: a blocker is written **at the moment work stops**, as the justification for
stopping, so nobody stress-tests it and by construction nobody exercises the path it forbids. And a
negative claim is self-sealing — "X works" fails loudly when it stops being true, "X can't be done"
fails silently forever. Harvey has many gates against overclaiming and, before this, none against
underclaiming.

## The convention

A recorded reason is a contiguous block of `FIELD: value` lines, readable through a `//` comment, an
HTML comment, a Markdown quote, a bullet or a table cell. A blank line ends the block.

```
REASON: <the claim, in one line>
KIND: empirical | decisional
PROVENANCE: MEASURED|TRIED|ASSUMED YYYY-MM-DD
FALSIFIER: <command>        # empirical only — REFUSED on decisional
OWNER: <person or role>     # decisional only
DECISION: <doc path or issue ref>   # decisional only
TOUCHES: <paths>            # optional; drives the subsystem-drift check
```

**KIND is the load-bearing field.**

- **empirical** — re-testable against the world: "the loader does not read `.svelte`", "no detector
  exists for this class", "that surface is unreachable". These decay, so they carry a falsifier and
  get re-run.
- **decisional** — awaiting a human ruling: scope, privacy, liability, product shape. These do not
  decay the same way. A falsifier on one is **refused, not merely unrequired** — re-running a command
  against a product ruling is a category error, and since decisional was ~45% of the tracker, letting
  it into the re-test pass would generate the noise that trains people to ignore the gate.

**PROVENANCE is the register.** The four blockers falsified on 2026-07-24 were all ASSUMED written in
MEASURED's confident register; the tag makes the difference legible instead of leaving it to prose
tone. MEASURED means a command was run (name it and date it); TRIED means something was attempted and
this is what it did; ASSUMED means inferred, never tested.

**The falsifier contract is one-way: the command EXITS 0 WHEN THE BLOCKER IS GONE.** So the canonical
shape is `grep -q <the thing that must not exist>`. A reason with no falsifier is unfalsifiable and
therefore permanent, which is exactly what made the four wrong claims survive.

## The gate

```bash
pnpm exec tsx src/cli/validate-reasons.ts               # structural only, runs no commands
pnpm exec tsx src/cli/validate-reasons.ts --revalidate  # also runs every empirical falsifier
pnpm exec tsx src/cli/validate-reasons.ts --root <dir> --list
```

- **Structural pass** — every block declares its kind, carries a dated provenance tag, and (if
  empirical) a falsifier that is a command rather than a placeholder. Enforced under `pnpm verify` by
  `src/recorded-reasons.test.ts`, which also asserts the repo carries reasons of **both** kinds so the
  gate cannot pass on an empty set (the `requires-live-run: 0` failure of #345).
- **`--revalidate`** — runs each empirical falsifier. Exit 0 is a **STALE** row and a non-zero gate
  exit: the blocker is gone and the text still asserts it. A falsifier that cannot run (exit 127, a
  signal, a timeout) is **UNVERIFIABLE**, also failing — otherwise a mistyped command's non-zero exit
  reads as "still blocked", the exact silent pass this exists to prevent. Decisional reasons are
  excluded by kind, and the run says how many it excluded.
- **Subsystem drift** — for a reason declaring `TOUCHES:`, commits landing on those paths after the
  reason's date are reported for review. This is the complement that catches the shape which actually
  broke: #1035's reason asserted knip could not run without `node_modules` while a sibling module grew
  exactly that path a week later. Nobody had to re-run anything — the referenced subsystem had moved.
  Advisory, never a failure: a sibling commit is a prompt to re-read, and failing on it would make the
  gate cry wolf on every merge.

Seeded proof, per the acceptance criteria — a gate that has never fired on a known-bad input is not
evidence: `src/cli/validate-reasons.test.ts` runs the real CLI against a planted corpus containing a
reason whose falsifier now succeeds, and asserts the gate exits 1 naming it.

## Relationship to #321

`revalidateNotRunReasons` (`src/scan/external-corpus.ts`) does exactly this for one narrow slice:
external-corpus `not-run` baselines, re-tested by the drift run's own re-attempt rather than by a
stored command. It stays as it is — it has a better oracle than a stored falsifier (the run itself)
for the targets it covers. This is the same doctrine generalized to every other surface, with the
command written down because nothing else re-attempts them.

## First tranche (2026-07-25) and what remains

Migrated in the #1033 PR — three empirical, two decisional:

| Where | Kind |
|---|---|
| `src/scan/sfc-coverage.ts` — SFC files unread by the shared source loader (#920) | empirical |
| `docs/design/m6-simplification-eval.md` §3 — M6 absent from `buildCoverageMatrix` | empirical |
| `src/scan/handrolled-frequency.ts` entry 102 — no countable signature | empirical |
| `docs/design/infrastructure-out-of-scope.md` — IaC out of scope (#886) | decisional |
| `docs/design/source-detector-recall.md` — SecBench is the SCA yardstick (#946) | decisional |

Three false claims were found and corrected in the course of writing them, all by the
verify-before-you-record step rather than by the gate:

1. `docs/design/fix-implementation.md` **and** `docs/design/fix-calibration-acceptance.md` both said
   §8 classes 1/2/5 have "no detector anywhere in `src/`". #1058 landed all three detectors the day
   before. Two documents, one measurement — the laundering pattern the doctrine names.
2. `docs/design/superredhat-recall-measurement.md` **and** `src/scan/semantic-corpus.ts` both said
   F-11 has "no static detector at all". `harvey-csrf-missing` and `leftover-auth.ts`'s rate-limit
   checks exist; neither *reaches* F-11's shape. Same two-places-one-guess shape.
3. `docs/design/spec-72-crossmodule-corpus.md` restated "M6: no detector" independently of
   `m6-simplification-eval.md`, which had already corrected it. Replaced with a pointer.

**Remaining, tracked as the split remainder:** the claims whose falsifier needs a live tier (M2
two-tenant stacks, Lighthouse/CWV, SecBench, the paired Supabase security labs) have no offline
command and are not yet migrated — the gate needs a way to record a falsifier that is legitimately
live-only without either failing as UNVERIFIABLE or quietly passing. Likewise the ~15 remaining
`docs/design` claim lines and the open-issue bodies, which live outside the repo entirely.
