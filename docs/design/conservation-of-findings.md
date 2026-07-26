# Conservation of findings — what shipped, and what is still awaiting a ruling

Design record for #1064. **Scope of this document: invariants (4) and (5) only.** Invariants (1),
(2) and (3) are recorded here as deferred, with the reason, and tracked in the remainder issue.

## The defect this closes

The coverage guard proves a module was **accounted for**. It does not prove that module's findings
**reached the deliverable**, and every defect of one recurring class lives in that gap: #1040 (385
findings discarded), #1050 (a knip category dropped at a type boundary), #1042, #1045, #1043,
#1051, #1061 (SARIF export 97% empty), #1062 (M7's code tier capturing nothing), #1063.

In every one of them the detector worked. The finding was produced and then dropped at a
producer→consumer seam, the ledger read clean, and the run exited 0 with `COVERAGE PASS`. Unit
tests could not see it — each break was *between* two units, and a unit test by construction does
not span a seam.

## What shipped

### Invariant 4 — per-module end-to-end plant-and-assert

`pnpm exec tsx src/cli/validate-conservation.ts` runs the **real** ten-module orchestrator
(`runAudit` over `AUDIT_RUNNERS`) against `targets/calibration`, assembles the **real** deliverable
(`assembleEngagementDocument`, then `validateFindings` — a document that fails the report schema is
not a deliverable at all), and for each module asks two questions in order:

1. **PRODUCED** — did *this module's own probe* emit the finding planted for it?
2. **DELIVERED** — did that finding survive into the assembled document?

The plants live in `CALIBRATION_PLANTS` (`src/audit-conservation.ts`), one per module, each anchored
on **taxonomy *and* location** so the row names an actual planted defect. A taxonomy-only match
would be satisfied by any other finding of the same class, which is how a shrinking scan passes a
gate that thinks it is watching.

### Invariant 5 — zero-is-suspicious on the fixture

Question 1 above *is* invariant 5. Zero findings is a legitimate answer in the field; on a fixture
that carries a planted defect for the module it never is. A module that produces zero for its plant
fails the gate (`GONE`), with the probe's own ledger reason quoted into the failure so the row says
*why* and not only *what*.

No existing gate could carry this. `validate-calibration` scores only the M1 mechanical corpus via
`runMechanicalScan` and never runs the other nine modules; `dry-run` is the same mechanical scan
plus M10's classifier; `audit-coverage` reads a ledger and has no findings at all. The
zero-is-suspicious question needs **per-module findings from a ten-module run**, which only the
orchestrator path produces.

### Why the two questions are separate

Asking only about the deliverable is not enough, and this is the load-bearing design point.

On a single-target run the M9 probe captures `detect-static` **unfiltered**, so it re-collects M6,
M7 and M8 rows. An M7 capture that broke *entirely* would still leave M7 taxonomies in the assembled
document. That is precisely how #1062 hid. So question 1 reads `findingsByModule` — per-probe
attribution added to `runAudit` for this gate — rather than the merged array, in which module
attribution is destroyed by construction.

The gate demonstrates this on itself: `--seed-loss M7` discards everything M7's probe produced, and
the run reports `GONE M7 produced=0 delivered=1` and exits 1. The deliverable still carries the row;
the gate fails anyway.

### The M2 exception, recorded rather than dropped

M2 drives a stood-up two-tenant Supabase stack over HTTP. This gate is offline and does not
provision one, so `targets/calibration` carries no M2 plant. M2 is therefore listed in `UNEXERCISED`
with a #1033 reason block — `KIND: empirical`, dated provenance, and the falsifier
`pnpm exec tsx src/cli/validate-conservation.ts --require M2`, which exits 0 the day M2 delivers
findings from this fixture, i.e. the day the excuse stops being true.

A module in **neither** `CALIBRATION_PLANTS` nor `UNEXERCISED` throws at module load. A gate that
can silently omit a module is the exact shape it exists to catch.

## Where the gate runs, and where it does not

`validate-conservation` needs the mechanical binaries (semgrep, trufflehog, gitleaks, osv-scanner)
and a full git history for the target. The CI `verify` job installs none of them — which is why
`dry-run-drift`, `corpus-drift` and `corpus-m8` are separate workflows — so this CLI is
**deliberately not part of `pnpm verify`**, on the same precedent.

What *is* under `pnpm verify`:

- `src/audit-conservation.test.ts` — the gate's **logic**, with each violation shape seeded and
  proven to fail. Fast, offline, no binaries.
- `src/cli/validate-conservation.test.ts` — the **wiring**, through the real CLI against
  `targets/calibration`. Self-skips with a printed reason where the binaries are absent, and carries
  a reason block naming the falsifier for that skip. It runs the orchestrator **once**, with
  `--seed-loss M7`, and asserts both directions from that one output: M7 fails, and the other eight
  plants all travelled probe → deliverable intact. Two runs starved the vitest worker RPC
  (`Timeout calling "onTaskUpdate"`, twice in three `pnpm verify` runs on 2026-07-26; clean with the
  file excluded) — each run is a ~30s synchronous `execFileSync` that blocks its worker, alongside
  the suite's existing heavy child-process files.

**Open, needs an operator action:** wiring the CLI into a scheduled/PR workflow alongside
`dry-run-drift`. `.github/workflows/` is a supervised path — an agent may not add it.

## Proof, dated

Measured 2026-07-26 on this branch, `targets/calibration`:

| Command | Result |
| --- | --- |
| `pnpm exec tsx src/cli/validate-conservation.ts` | exit 0 — `CONSERVATION PASS`, 9 modules `PASS`, M2 `SKIP` |
| `pnpm exec tsx src/cli/validate-conservation.ts --seed-loss M7` | exit 1 — `GONE M7 produced=0 delivered=1`, `GATE FAIL — M7 produced NOTHING here` |
| `pnpm exec tsx src/cli/validate-conservation.ts --require M2` | exit 1 — M2's recorded reason still holds |
| `pnpm exec vitest run src/audit-conservation.test.ts` | 8 passed |
| `pnpm verify` | exit 0, 184 files / 3403 tests, twice consecutively |

## Deferred — invariants 1, 2 and 3

Not built here, and **not** because they are wrong. Recorded so the deferral is legible:

- **(1) the conservation ledger** (`produced == delivered + suppressed + deduped + capped +
  not_applicable`, every non-delivered finding carrying a reason code) and **(2) typed non-empty
  results** (`Examined | NotAssessed` instead of a bare `Finding[]`) are a **product-shape decision
  the operator has not ruled on**, and both are large cross-cutting refactors touching every probe.
  They want a tranche plan, not a big-bang rewrite.
- **(3) captured-fixtures-only for external tools** — the #1063 case, where an invented
  `score: "7.5"` the tool never emits produced a fixture, a test that confirmed the fixture, and
  every dependency CVE mis-rated. Independent of (1)/(2) and separately schedulable.

(4) and (5) were built first on the issue's own recommendation: they catch most of what shipped
broken this year at a fraction of the cost.
