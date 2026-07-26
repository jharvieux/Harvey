# Conservation of findings — the contract

Design record for #1064 and #1096. Invariants **(1), (4) and (5)** are built and enforced; **(2)**
is built and migrated for three of ten probes, with the split declared in code; **(3)** is a rule,
recorded below, whose motivating case (#1063) is closed.

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

`validate-conservation` needs the mechanical binaries (semgrep, trufflehog, gitleaks, osv-scanner),
the `vitals` plugin, and a full git history for the target. The CI `verify` job installs none of
them — which is why `dry-run-drift`, `corpus-drift` and `corpus-m8` are separate workflows — so this
CLI is **deliberately not part of `pnpm verify`**, on the same precedent.

`vitals` is in that list because of M3, and the reason is worth stating plainly: M3's plant is a
truck-factor-1 row, and knowledge-risk analysis exists only in vitals' full tier. Without the plugin
`hotspot-scan` falls back to the reduced churn×complexity tier (#807), which produces a ranking and
no knowledge-risk at all, so the gate reports `GONE M3` — **correctly**, because M3 really did not
run in full. That is the shape a coverage guard is supposed to have: the missing toolchain surfaces
as a named failure rather than as a quietly narrower scan. It is fixed by installing the tool, never
by softening the plant — `conservation.yml` fetches vitals from source at a pinned commit.

One decay risk is tracked rather than assumed away: vitals derives truck-factor from files churning
in a **90-day** window (`vitals_cli.py:103,131`), so if `targets/calibration` goes that long without
two commits to a qualifying source file, M3 reddens with no scanner defect behind it. Measured
2026-07-26: 2 qualifying files, i.e. a thin margin. Issue #1112 holds the options.

What *is* under `pnpm verify`:

- `src/audit-conservation.test.ts` — the gate's **logic**, with each violation shape seeded and
  proven to fail. Fast, offline, no binaries.
- `src/cli/validate-conservation.test.ts` — the **wiring**, through the real CLI against
  `targets/calibration`. Self-skips with a printed reason where the binaries **or vitals** are
  absent (asserting `PASS M3` on a vitals-less machine would fail for a toolchain gap and read as a
  conservation break), and carries a reason block naming the falsifier for each skip. It runs the
  orchestrator **once**, with `--seed-loss M7`, and asserts both directions from that one output:
  M7 fails, and the other eight
  plants all travelled probe → deliverable intact. Two runs starved the vitest worker RPC
  (`Timeout calling "onTaskUpdate"`, twice in three `pnpm verify` runs on 2026-07-26; clean with the
  file excluded) — each run is a ~30s synchronous `execFileSync` that blocks its worker, alongside
  the suite's existing heavy child-process files.

Scheduled since #1096: `.github/workflows/conservation.yml` (weekly Mondays 07:30 UTC, on
`workflow_dispatch`, and on any PR touching the pipeline), installing the same binary set as
`dry-run-drift` plus `vitals`, cloned from source at a pinned commit and asserted to report
`EXPECTED_VITALS_VERSION` in its own step — so a failed install reads as "vitals is missing" there
rather than as "M3 detected nothing" three steps later. **Its negative controls are part of the
job**: after the gate passes, the workflow runs `--seed-loss M7` and `--seed-unaccounted` and fails
if either exits 0. A green run therefore means "the gate passed AND the gate can still fail" — a
materially stronger claim than "the gate passed", and the one #1065 showed is worth paying for.

## Proof, dated

Measured 2026-07-26 on this branch, `targets/calibration`:

| Command | Result |
| --- | --- |
| `pnpm exec tsx src/cli/validate-conservation.ts` | exit 0 — `CONSERVATION PASS`, 9 modules `PASS`, M2 `SKIP` |
| `pnpm exec tsx src/cli/validate-conservation.ts --seed-loss M7` | exit 1 — `GONE M7 produced=0 delivered=1`, `GATE FAIL — M7 produced NOTHING here` |
| `pnpm exec tsx src/cli/validate-conservation.ts --require M2` | exit 1 — M2's recorded reason still holds |
| `pnpm exec vitest run src/audit-conservation.test.ts` | 8 passed |
| `pnpm verify` | exit 0, 184 files / 3403 tests, twice consecutively |

Re-measured 2026-07-26 after #1096 landed the ledger and the typed-result tranche:

| Command | Result |
| --- | --- |
| `pnpm exec tsx src/cli/validate-conservation.ts` | exit 0 — `LEDGER PASS` (605 = 575 + 30 deduped + 0 unaccounted) and `CONSERVATION PASS` |
| `pnpm exec tsx src/cli/validate-conservation.ts --seed-loss M7` | exit 1 — `GATE FAIL — M7 produced NOTHING here` |
| `pnpm exec tsx src/cli/validate-conservation.ts --seed-unaccounted` | exit 1 — `LEDGER FAIL … LOST SEC-TH-GH-00 (produced by M1)`, while the plant-and-assert still passed |
| `pnpm exec tsx src/cli/run-audit.ts targets/calibration --findings-out …` | exit 0 — ledger balanced, 575 findings written, M9 row reads `[examined 388 product source files]` |
| `pnpm exec vitest run src/conservation-ledger.test.ts src/probe-result.test.ts` | 19 passed |
| `pnpm exec tsx src/cli/validate-calibration.ts` | `GATE PASS` — 230/233 static positives, 218/218 negatives (unchanged by this work) |

Re-measured 2026-07-26 after the workflow's own first run reported `GONE M3`. The CI environment was
reproduced locally by pointing `HOME` at an empty directory, which hides the `~/.claude/plugins`
install and is the only way vitals reaches a Harvey run — the no-vitals row below matches the CI
failure line for line, including its ledger arithmetic:

| Command (all with `HOME` pointed at an empty dir) | Result |
| --- | --- |
| gate, no vitals anywhere | exit 1 — `598 = 568 + 30`, `GONE M3 produced=0 delivered=0`, probe reason `vitals plugin unavailable — reduced M3 tier` (identical to the CI run) |
| gate, with vitals fetched at the pinned commit onto `PATH` | exit 0 — `605 = 575 + 30`, `PASS M3 produced=2 delivered=2`, `CONSERVATION PASS` |
| `--seed-loss M7`, same vitals-on-PATH environment | exit 1 — `GONE M7 produced=0 delivered=1` |
| `--seed-unaccounted`, same environment | exit 1 — `LEDGER FAIL … UNACCOUNTED 1` |

The 7-finding gap between the two ledgers is exactly M3's vitals-only sub-signals (2 truck-factor-1,
5 co-change coupling) — the reduced tier does not produce them, so the plant has nothing to match.

## Invariant 1 — the conservation ledger (#1096)

(4) and (5) watch **ten rows**: the one finding planted per module. They cannot see the other 595.
The ledger is the arithmetic over the whole set, and it needs no fixture and no plant — so unlike
(4)/(5) it holds on a real client engagement.

At the produce→assemble seam (`src/conservation-ledger.ts`):

```
produced  == delivered_from_produced + deduped + suppressed + capped + not-applicable + UNACCOUNTED
delivered == delivered_from_produced + synthesized
```

Every produced finding must land in exactly one column, and every non-delivered one carries the
reason it did not arrive. A finding in no column is `unaccounted` — produced, absent from the
deliverable, and nothing in the pipeline says why. That is #1040 (385 findings discarded), #1050,
#1061 and #1062 expressed as a single number, and it exits non-zero.

**Where it is asserted.** Both gates: `validate-conservation` prints it, and — more importantly —
`run-audit` asserts it before writing `--findings-out`/`--sarif-out`. Every break in this class
shipped through that function and every one of them exited 0. The check is on the path a client's
report actually takes, not only on the fixture.

**It is independent by construction.** It does not read the assembler's own bookkeeping; it recounts
`produced` against `delivered`. If `dedupeFindings` were ever changed to drop something that is not
a byte-identical duplicate, the drop surfaces here as unaccounted instead of being blessed by the
same code that made it. One implementation grading its own homework is not evidence.

**The columns that are zero, and why they exist anyway.** `suppressed`, `capped` and
`not-applicable` have no producer in the pipeline today, and are printed as explicit zeros rather
than omitted: the slot is where the next transform declares itself, and a reader can see that
nothing is hiding in it. Today the only legitimate disposition is `deduped` — the shared-CLI double
capture (`quality-scan` under M4+M5, `detect-static` under M6/M7/M8/M9) that the assembler collapses.

**Gains are checked too.** A report that grows rows from nowhere is as wrong as one that loses them.
A delivered finding no probe produced must be on the declared `SYNTHESIZERS` list — today exactly
one entry, `M10-ESCALATION-00` (the #1049 not-assessed row the assembler adds when there is no data
map). Anything else fails, as does an id delivered more times than it was produced.

**Seam boundary, stated rather than assumed.** The ledger covers probes → `assembleEngagementDocument`.
The baseline diff (#457, `applyBaseline`) runs *after* it and legitimately carries resolved rows in
from a prior engagement, so it sits outside this ledger.

### Proving it can fail

`--seed-unaccounted` drops one row out of the assembled deliverable with no disposition — what an
undeclared filter at a consumer boundary does. Measured 2026-07-26 on `targets/calibration`:

| Run | Ledger | Plant-and-assert |
| --- | --- | --- |
| clean | `produced 605 = delivered 575 + deduped 30 + UNACCOUNTED 0` — PASS | PASS |
| `--seed-unaccounted` | `UNACCOUNTED 1`, `LOST SEC-TH-GH-00 (produced by M1)`, exit 1 | **still PASS** |

The second row is the argument for having both gates. The plant-and-assert saw nothing wrong,
because the finding that vanished was not one of the ten it watches.

## Invariant 2 — the typed non-empty result (#1096, three of ten probes)

The state `ProbeOutcome` permitted for its whole life:

```ts
{ status: "ran", detail: "pnpm detect-static", findings: [] }
```

"The module ran and found nothing" — with no statement of what was looked at. That one sentence is
how a broken capture (#1062), a scan that loaded zero product source files (#1065) and a genuinely
clean tool all read identically, and the reassuring reading is the one that ships.

```ts
Examined    { kind; unitsExamined; scope; detail; findings; reason?; … }
NotAssessed { kind; reason; provenance: "MEASURED"|"TRIED"|"ASSUMED"; falsifier; … }
```

Three properties:

1. **The silent version does not compile.** `{ kind: "examined", findings: [] }` without
   `unitsExamined`/`scope` is a type error — asserted by `@ts-expect-error` in
   `src/probe-result.test.ts`, so the day the type stops rejecting it, `pnpm typecheck` fails on the
   unused directive.
2. **Zero units is not a clean scan.** An `Examined` with `unitsExamined: 0` throws at normalization
   rather than becoming a `ran` row. That is #1065's defect expressed in the type system.
3. **The #1033 reason contract is structural.** A `NotAssessed` cannot be written without a
   provenance tag and a falsifier — the shape the four blockers falsified on 2026-07-24 were
   missing. Both are folded into the ledger row's reason, so the deliverable carries them.

The payoff is visible in the report: M9's row now reads
`pnpm detect-static <target> [examined 388 product source files]`. A zero-finding row that also
names zero files read is no longer expressible; one that names 388 is a claim the client can check.

### The migration, declared rather than implied

**Migrated (3):** M6, M7, M9 — the three `detect-static` consumers, chosen because the tool prints a
real product-source-file count that can legitimately be zero, which is what gives the invariant
teeth rather than a rubber-stamp `unitsExamined: 1`.

**Not migrated (7):** M1, M2, M3, M4, M5, M8, M10. Each carries its blocker in `UNTYPED_PROBES`
(`src/audit-runner.ts`) — mostly "the tool's unit count is on stderr, which `ctx.exec` discards on
success" (M4/M5) or "the probe's branch ladder wants its own pass" (M8).

Two mechanisms keep the half-migration from becoming invisible:

- every module of M1–M10 must be in `TYPED_PROBES` or `UNTYPED_PROBES`, checked at module load —
  the same rule `CALIBRATION_PLANTS`/`UNEXERCISED` follow;
- the declared list and the real registry must agree (`AUDIT_RUNNERS` marks the migrated runners
  `typed: true`), and a runner that declares itself typed and returns a legacy outcome fails loud in
  `runAudit`. Without that the union would be a hole: a wrapper could quietly hand the legacy shape
  back and the compile-time guarantee would still read as kept.

## Invariant 3 — captured fixtures only, for every external tool

**The rule.** A fixture standing in for an external tool's output MUST be a captured artifact from a
real run of the pinned version, committed with a provenance note naming the tool version and the
exact command. **A hand-written one is a defect.** Records may be dropped from a capture to keep it
small; they may not be edited. If a fixture needs to change, re-capture it.

**Why.** #1063: `src/scan/dependencies.test.ts` asserted against `score: "7.5"`, a value invented
from Harvey's own TypeScript type. osv-scanner never emits a bare number there — OSV mandates
`severity[].score` be a CVSS *vector string* — so `severityFromCvss` returned `NaN` for every real
advisory, every dependency CVE shipped as Medium, and the test stayed green. The type was invented,
the fixture derived from the invented type, the test confirmed the fixture. Nothing in that loop
ever touched the real tool.

**Status:** the motivating case is CLOSED (#1102): the fixture is a captured osv-scanner 2.3.8
report with `src/scan/__fixtures__/osv/PROVENANCE.md` recording version, command, capture date, and
exactly what was elided. 19 of 35 rows had been mis-rated. The remaining work is the *general* form
— an inventory of every external-tool fixture in the repo held to this rule, plus a periodic
re-capture-and-diff check for schema drift — and it is independent of (1)/(2), so it is scheduled
separately rather than folded in here (#1109).
