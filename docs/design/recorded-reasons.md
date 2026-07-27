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
FALSIFIER-TIER: <name>      # optional, empirical only — the live tier the FALSIFIER needs (see below)
OWNER: <person or role>     # decisional only
DECISION: <doc path or issue ref>   # decisional only
TOUCHES: <paths>            # optional; adds to the subsystem-drift paths derived from FALSIFIER
```

**KIND is the load-bearing field.**

- **empirical** — re-testable against the world: "the loader does not read `.svelte`", "no detector
  exists for this class", "that surface is unreachable". These decay, so they carry a falsifier and
  get re-run.
- **decisional** — awaiting a human ruling: scope, privacy, liability, product shape. These do not
  decay the same way. A falsifier on one is **refused, not merely unrequired** — re-running a command
  against a product ruling is a category error, and since decisional was ~45% of the tracker, letting
  it into the re-test pass would generate the noise that trains people to ignore the gate.

### Work parked on an external event needs a falsifier, not a `deferred` label (2026-07-27)

An issue blocked on something outside this repo — an upstream PR merging, a third-party release, a
service becoming available — is **empirical**, and labelling it `deferred` (or closing it) is the
wrong parking place. `deferred` makes sweeps skip it at fetch time, so nothing notices when the
blocker clears; it waits for a human to remember. That is this repo's silent-omission defect
relocated to the issue tracker. A falsifier makes the external event **fire an alarm**: the daily
`reasons-drift.yml` run executes it and fails loud the day it starts exiting 0.

Three constraints on writing one:

- **The block must live in a FILE.** The daily job never executes a falsifier found in an issue body
  — that is attacker-writable input — so an issue-recorded block is reported `NOT RE-TESTED` and
  guards nothing. Mirror it into the file the claim constrains.
- **A lookup that fails must not read as "still blocked."** A remote query exits non-zero on an auth
  failure, a network failure or a missing binary, which the one-way contract would read as the
  blocker holding. Trap that case and `exit 127`, so the gate reports UNVERIFIABLE and fails rather
  than passing green on a query that never ran.
- **Exercise it in both directions before shipping it.** Confirm it exits non-zero today for the
  right reason, and confirm it exits 0 against a state where the blocker is gone (swap in an
  already-merged PR number, an already-published version). Worked example: the block at the head of
  `src/scan/calibration/owasp-react.entries.ts`, wired for #1241 / OWASP/CheatSheetSeries#2196.

A **decisional** deferral is different and stays a label: #920/#921 (cost with no current demand),
#882 and #4 (operator go/no-go) wait on a human ruling, not on an event a command can observe.

**PROVENANCE is the register.** The four blockers falsified on 2026-07-24 were all ASSUMED written in
MEASURED's confident register; the tag makes the difference legible instead of leaving it to prose
tone. MEASURED means a command was run (name it and date it); TRIED means something was attempted and
this is what it did; ASSUMED means inferred, never tested.

**The falsifier contract is one-way: the command EXITS 0 WHEN THE BLOCKER IS GONE.** So the canonical
shape is `grep -q <the thing that must not exist>`. A reason with no falsifier is unfalsifiable and
therefore permanent, which is exactly what made the four wrong claims survive.

### A budget limit must not borrow impossibility's vocabulary (#1319)

Four claims recorded in this repo asserted that the *world* forecloses something while describing the
author's remaining afternoon:

| claim | falsified |
|---|---|
| #951 — "a full pull is out of budget" | the next executor pulled the whole stack and shipped a merged live proof **26 minutes** later, and the capture found a real bug the guess would have missed |
| #957 — "genuinely out of reach for a mechanical assembly" | landed **3h25m** later: 98 lines, no new dependency, no API key |
| #52 — "correctly NOT mechanically detectable" | detectors now exist for all three named classes |
| #873 — "our mechanical tier structurally cannot see that shape" | `buildImportGraph` had shipped a week earlier and M9 already used it |

A budget claim invites the next person to just do it. An impossibility claim closes the file — and
closes it *silently*, because by construction nobody exercises a path recorded as foreclosed.

`PROVENANCE:` already records whether anyone went and looked, so this is checkable rather than
exhortation: **impossibility vocabulary in a `REASON:` whose provenance is `ASSUMED` is a structural
error**, of either kind. Three honest exits, all one line — go look and re-tag it `MEASURED`/`TRIED`;
name the real constraint (*"not attempted this round; the pull is ~20s, the stand-up is documented in
X"*); or ask it as a question (*"does the token store expose non-owner reads?"*), which invites the
next person to test it where an assertion ends the file. The vocabulary is the same list the
untriaged-claim census uses, so the two cannot drift apart; it is matched literally, including inside
a denial (*"not technically impossible"*), because re-tagging a denial as `MEASURED` is cheaper than
teaching a regex to read sentences.

**What stays prose.** The rule also applies to PR bodies and issue comments, which this gate cannot
reach — `collectSources` reads files, and `--issues` fetches issue text but nothing renders a PR
description. That half is doctrine, not a check, and is recorded here so the next reader does not
mistake it for an oversight. #1318 (Gate 6) is where a wider claim ratchet would live.

### A supervised path produces a relay, not a silent close (#1319)

**No executor has ever recorded "asked the operator, was refused."** Grants, meanwhile, are routine
and on the record — #1141 carries a verbatim *"Workflow changed approved"*, #1205 promoted a check to
required, #1216 moved a watch into CI. Yet "that path is supervised" silently terminated acceptance
criteria in #945 (*"the gate runs in CI"* — unmet, unmentioned), #1056, #472 and #381.

Supervision is not a fact a command can re-test; it is a question awaiting a human. So a `REASON:`
that **cites a supervised path as its blocker** must be `decisional`, and its `DECISION:` must name
the venue where the operator was actually asked — an issue ref or a decision-record path. A
`DECISION:` with neither is a relay with no venue, which is the silent close wearing a field name.

Both halves must match before the rule fires: the claim names a supervised path (`.github/workflows`,
`CLAUDE.md`, `report-template/findings.*`, `docs/**/*.md` — mirroring CLAUDE.md's *Sensitive paths*
list, which is the authority) **and** cites supervision as the reason. A claim that merely *mentions*
`.github/workflows/ci.yml` is describing CI, which is what both reasons at the head of
`src/cli/validate-conservation.test.ts` legitimately do.

`package.json` and `pnpm-lock.yaml` are deliberately **absent** from that list — operator ruling
2026-07-27, after a folk belief that they were supervised was found blocking five separate pieces of
work. Adding a dependency is an ordinary change.

The rest of the doctrine — that a supervised-path blocker is a `relayed` disposition on the issue
rather than a closed criterion — is enforced by Gate 1 (#1315), not here. This gate only reaches the
reason registry.

**FALSIFIER-TIER — for a falsifier that can only run against a live environment (#1072).** Some
empirical blockers are only re-testable on a tier that is not present on a normal offline run: a
two-tenant M2 stack, a Lighthouse/CWV pass, a SecBench run, the paired Supabase security labs.
Recording those with a plain `FALSIFIER:` forces one of two dishonesties — a fake offline proxy
command that re-tests nothing, or an `UNVERIFIABLE` failure on every offline run. `FALSIFIER-TIER:`
names the environment the command needs. On an offline run the falsifier is **SKIPPED-LIVE** —
disclosed and counted, never dropped and never a failure — and on a run that declares that tier
available it runs exactly like any other falsifier. It is optional, empirical-only (refused on a
decisional reason, which must carry no falsifier at all), and its value must be one of the registered
tiers — `m2-stack`, `lighthouse`, `secbench`, `supabase-labs`. A value outside that set is
**malformed**, not silently always-skipped, because a typo would make the falsifier permanently
skip. The registry is the `KNOWN_FALSIFIER_TIERS` set in `src/recorded-reasons.ts` — the single
place a new live tier is added (like #341's `OWNERS` map).

### `<placeholder>` bindings — how a live-tier falsifier names a target that is not in the repo

A live-only falsifier cannot hard-code its target: the crAPI gateway URL, the external SecBench
clone, the served origin, the paired lab variants are all stood up by whoever brings the tier up. All
five live falsifiers were originally written with the target as angle-bracket prose — `--dir
<superredhat-clone>` — and **that made every one of them a false green**. `sh -c` reads `<` as an
input redirect: the command died on "No such file or directory" and exited non-zero, which the
falsifier contract reads as *the blocker still holds*. Five checks reported green daily while
executing nothing (measured 2026-07-27, #1072).

So a placeholder is a **declared binding**, and this is the contract:

- A `<lowercase-with-hyphens>` token in a `FALSIFIER:` is a run-time binding, resolved from the
  environment variable `HARVEY_FALSIFIER_<UPPER_SNAKE>` — `<superredhat-clone>` reads
  `HARVEY_FALSIFIER_SUPERREDHAT_CLONE`.
- It is **legal only on a reason that carries `FALSIFIER-TIER:`**. A placeholder in an offline
  falsifier is a structural error, because offline the command really is run as written and really
  does hit the redirect. Write a real path instead, or declare the tier.
- **Unbound, the falsifier is `UNVERIFIABLE` and is NOT executed.** Not skipped, not passed, not run
  and read: an unbound run would exit non-zero for a reason indistinguishable from the blocker
  holding, so refusing to run it is the only honest option.
- Lowercase-and-hyphens only, so real shell syntax (`< /dev/null`, `2>&1`, `<<EOF`) is never mistaken
  for a binding.
- Offline, a `SKIPPED-LIVE` row **names the bindings the live run will need**, so the operator does
  not have to read the command to find out what to export.

```bash
HARVEY_FALSIFIER_SUPERREDHAT_CLONE=/clones/superredhat \
  pnpm validate-reasons --revalidate --tier secbench
```

The negative control lives in `.github/workflows/reasons-drift.yml`: a planted live-tier reason with
an unbound placeholder must fail, or the binding rule has stopped being enforced.

### `TOUCHES:` is declared **or derived** — and never mandatory

Subsystem drift only ever watched the reasons whose author happened to declare `TOUCHES:` — 9 of 15
empirical reasons (measured 2026-07-27). Making the field **mandatory** was the obvious fix and is
**rejected**: the three fixture-planting negative controls in `reasons-drift.yml` plant reasons that
carry no `TOUCHES:`, so a mandatory field would make all three exit non-zero for the wrong reason. A
green job whose own controls no longer prove anything is precisely the false green this whole family
exists to kill. The rule generalises past `TOUCHES:`: **no new mandatory field may be added to a
reason block without first adding it to those three planted heredocs.**

**Open weakening, recorded rather than left silent (#1319).** The second planted heredoc reads
`REASON: planted claim with no way to re-test it` / `PROVENANCE: ASSUMED 2026-07-27`, which now trips
the impossibility-register rule as well as the missing-`FALSIFIER:` rule it was planted for. That
control asserts only a non-zero exit, so it still fails — but it no longer *isolates* the rule it
names. `.github/workflows/` is supervised, so the one-word fix (`no way to re-test it` → `nothing
here re-tests it`) needs an operator pass; until then the isolation is asserted by
`src/cli/validate-reasons.test.ts`'s own planted corpus instead.

Instead the paths are **derived from the falsifier the author already wrote** (#1246): a token in the
`FALSIFIER:` naming a path that exists in this checkout is a subsystem the claim depends on.
Existence is the entire filter, which is why an unbound `<placeholder>`, a `/tmp` scratch file and a
bare flag all drop out with no special case; requiring a `/` keeps a bare `src/` — which would file
every commit under every reason — out, and `node_modules/` is excluded because a path outside this
repo's history can only ever report zero commits.

Two guards come with it, both against the same shape:

- A **declared** `TOUCHES:` path that does not resolve is a structural error. `git log -- <typo>`
  reports zero commits forever, so the reason reads as watched while nothing watches it.
- The gate **counts** the empirical reasons drift cannot watch, and names them. Silence from a reason
  with nothing to watch looks exactly like silence from a quiet subsystem; the count is what keeps
  those two apart. A claim about a third-party package pinned outside the repo legitimately has no
  in-repo subsystem and stays on that list — the list is a disclosure, not a to-do.

## The gate

```bash
pnpm validate-reasons                          # structural only, runs no commands
pnpm validate-reasons --revalidate             # runs every OFFLINE falsifier; live-tier ones are SKIPPED-LIVE
pnpm validate-reasons --revalidate --live      # also runs every FALSIFIER-TIER falsifier
pnpm validate-reasons --revalidate --tier m2-stack  # enable one live tier (repeatable)
pnpm validate-reasons --issues                 # also lint the claims recorded in open GitHub issues
pnpm validate-reasons --census                 # list the claim-shaped prose outside every block
pnpm validate-reasons --root <dir> --list
```

- **Structural pass** — every block declares its kind, carries a dated provenance tag, and (if
  empirical) a falsifier that is a command rather than a placeholder; since #1319 it also refuses
  impossibility vocabulary over an `ASSUMED` provenance, and refuses a supervised-path blocker
  recorded as anything but a decisional reason with a named relay venue. Enforced under `pnpm verify`
  by `src/recorded-reasons.test.ts`, which also asserts the repo carries reasons of **both** kinds so
  the gate cannot pass on an empty set (the `requires-live-run: 0` failure of #345). Each #1319 rule
  additionally has a **child-process negative control** in `src/cli/validate-reasons.test.ts` — a
  planted violation must take the real CLI to a non-zero exit, or the rule is unit-tested prose.
- **`--revalidate`** — runs each empirical falsifier. Exit 0 is a **STALE** row and a non-zero gate
  exit: the blocker is gone and the text still asserts it. A falsifier that cannot run (exit 127, a
  signal, a timeout) is **UNVERIFIABLE**, also failing — otherwise a mistyped command's non-zero exit
  reads as "still blocked", the exact silent pass this exists to prevent. Decisional reasons are
  excluded by kind, and the run says how many it excluded. A falsifier carrying a `FALSIFIER-TIER:`
  whose tier is not made available (`--tier <name>`, repeatable, or `--live` for all) is
  **SKIPPED-LIVE** — reported and counted, never run and never a failure — so a live-only re-test is
  disclosed rather than either faked or failed. An unknown `--tier` is refused loudly.
- **Subsystem drift** — commits landing after the reason's date on the paths it declares in
  `TOUCHES:` **plus the paths its `FALSIFIER:` names that exist here** (above) are reported for
  review. This is the complement that catches the shape which actually broke: #1035's reason asserted
  knip could not run without `node_modules` while a sibling module grew exactly that path a week
  later. Nobody had to re-run anything — the referenced subsystem had moved. Advisory, never a
  failure: a sibling commit is a prompt to re-read, and failing on it would make the gate cry wolf on
  every merge.
- **`--issues`** — folds the open issues' bodies and comments in as extra surfaces. `collectReasons`
  reads files, so a blocker recorded in an issue was gated by nothing at all: three reason blocks
  were posted as issue comments on #920/#921/#1163 (2026-07-26), and by 2026-07-27 one of the three
  had already decayed — #1163's "a migrationsDir-less Prisma-7 target cannot stand up", retired by
  `prismaV7ApplyArgs` in `src/prisma-dynamic.ts` — with nothing anywhere to say so. Blocks found in
  an issue are held to the same structure, and their claim-shaped prose is censused with everything
  else. Two boundaries, both deliberate and both stated in the output rather than left silent:
  - **Their falsifiers are never executed.** An issue body is input anyone with comment access can
    write; running its commands would turn a scheduled gate into a remote-execution surface with the
    repo checked out. Each is reported `NOT RE-TESTED` with the remedy: **mirror the block into the
    file it constrains** and the in-repo copy comes under `--revalidate` (this is what #920/#921's
    comments do against `src/scan/sfc-coverage.ts`).
  - **Closed issues are out of scope by decision** — a blocker on a closed issue no longer steers
    work, and the population is unbounded.

  It needs an authenticated `gh` and **fails loud** when the fetch fails, rather than reporting zero
  issue-recorded claims, which would be the silent pass in miniature.
- **The untriaged claim census** — printed on every run, listed under `--census`. "N blocks, all
  well-formed" is a statement about the blocks that EXIST, and reads as a clean bill of health over
  the repo's claims; the #1033 inventory measured 86 claim-shaped lines across 33 of 51 design docs
  that were never triaged into empirical/decisional at all. So the untriaged population is **counted
  on every run** instead of quoted from a doc. It is explicitly a **lower bound** over a fixed
  vocabulary of standing-impossibility phrasings, and prose-only — the same inventory measured
  `docs/design` carrying 2 provenance tags against `src/`'s 119, so prose is the weak surface.
  Advisory, never a gate failure: a hard gate over a heuristic gets argued down or suppressed, and
  what this needs to do is stay visible while the number shrinks. **Do not quote the number from
  here — run the tool.**

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

**The live-tier remainder — now CLOSED (#1072).** The claims whose falsifier needs a live tier (M2
two-tenant stacks, Lighthouse/CWV, SecBench, the paired Supabase security labs) had no offline
command. #1167 gave the gate a way to record a legitimately live-only falsifier without either
failing as UNVERIFIABLE or quietly passing — `FALSIFIER-TIER:` (above), SKIPPED-LIVE offline and
run under `--tier`/`--live`. #1072 then migrated the five named live-tier claims into
`FALSIFIER-TIER:` blocks:

| Where | Tier |
|---|---|
| `docs/design/vandyand-recall-measurement.md` — M2 cannot reach orgs/line_items | `m2-stack` |
| `docs/design/crapi-m2-portability-measurement.md` — IDOR-OBJECT crAPI-shape not re-run live | `m2-stack` |
| `docs/design/supabase-security-labs-paired-validation.md` — static tier cannot distinguish the pair (cause 1) | `supabase-labs` |
| `docs/design/m7-chrome-provisioning.md` — CWV needs a Lighthouse-compatible Chrome | `lighthouse` |
| `docs/design/superredhat-recall-measurement.md` — F-11 static-missed (detectors exist, do not reach the shape) | `secbench` |

Verifying-before-wrapping caught two decayed claims along the way, corrected rather than wrapped:
`m7-lighthouse-validation.md`'s "Playwright-only machines still can't measure CWV" (resolved by
#556/#818/#840) and its bad-`LIGHTHOUSE_CHROME_PATH`-exits-1 note (resolved by #556 Part 2).

## Second tranche (2026-07-27, #1246) — the population, not the mechanism

#1072 finished the mechanism. What was left was **who the mechanism reaches**, and three of those
four items are closed here:

| Was | Now |
|---|---|
| Claims in GitHub issue bodies were read by nothing | `--issues` lints them structurally and censuses them **on the daily `reasons-drift.yml` schedule**; falsifiers stay unexecuted, with mirroring named as the remedy |
| `TOUCHES:` optional, so drift watched 9 of 15 empirical reasons | Declared **or derived from the falsifier**; a declared path that does not resolve is now an error; the unwatchable ones are counted and named |
| The untriaged `docs/design` population was a number in this document | Counted on every run (`--census`), so it is measured rather than recalled |
| The `<placeholder>` binding contract was undocumented | Documented above — the next person to write a live-tier falsifier does not have to rediscover #1072's redirect bug |

### The cadence for issue-recorded claims

A mechanism nothing invokes is the same green-but-proving-nothing failure as no mechanism, so
`.github/workflows/reasons-drift.yml`'s daily job runs `pnpm validate-reasons --revalidate --issues`
— one step, because `--issues` is a strict superset of the surfaces the repo-only run reads. It
needs `GH_TOKEN` in the step env; it needs no new permission, since the job already holds
`issues: write` for its tracking issue.

Three properties the cadence has to preserve:

- **Issue-recorded falsifiers are still never executed**, `--revalidate` on the same run or not. The
  CLI filters them out of the re-validation pass and prints `ℹ NOT RE-TESTED` per row. This is a
  security boundary, not an ergonomic one: an issue body is writable by anyone with comment access,
  and a scheduled job runs it with the repo checked out and a token in the environment. Path data
  that reaches `git log` from an issue-recorded `TOUCHES:`/`FALSIFIER:` is passed as `spawnSync`
  argv, never through a shell, and only after `watchedPaths` has filtered it to paths that already
  exist in the checkout.
- **A fetch that reads nothing fails loud.** "0 issue-recorded claims" from a `gh` that never worked
  is indistinguishable from a clean tracker. The fourth negative control plants an unusable
  credential and asserts both that the run exits non-zero *and* that it does so for that reason.
- **The three fixture-planting controls deliberately omit `--issues`.** Pointed at the real tracker,
  an unrelated malformed issue block anywhere would make all three exit non-zero for the wrong
  reason and they would pass vacuously — the same shape as the mandatory-`TOUCHES:` trap above.

**Still remaining, and split out rather than silently narrowed:**

1. **The four live tiers still execute nowhere on a cadence.** No CI job stands up a two-tenant M2
   stack, a Lighthouse-capable Chrome against a served target, a SecBench clone, or the paired
   supabase-security-labs variants. With the bindings above they are runnable **by hand** where the
   tier exists; putting them on a schedule needs the tier itself, which is the real blocker — not
   the workflow syntax.
2. **Triaging the censused claims into blocks.** The count makes the population visible; shrinking it
   is per-claim work, and each one must be **re-verified before it is recorded**, never wrapped in a
   block as-is. Wrapping an unverified claim in a `PROVENANCE:` tag launders it, which is the failure
   this whole convention was built against.
