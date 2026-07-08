# M4–M6 quality runbook — duplication, slop, simplification

> The maintainability third of the audit: wiring already-existing tooling (jscpd, knip) plus the
> `/simplify` review doctrine into §3b of the deliverable. Security (M1, `docs/tier1-runbook.md`)
> leads the pitch; this is what makes the engagement a *full* audit and the reason a one-time audit
> becomes a recurring relationship (see `docs/audit-modules.md` for the module catalog this
> generalizes).

## 0. What's wired vs. manual

| Module | Tool | Automated by | Manual step |
|---|---|---|---|
| M4 Duplication | jscpd | `src/cli/quality-scan.ts` (`pnpm quality-scan`) | Pick consolidation approach per cluster |
| M5 Slop / dead code | knip + `quality-extras.txt` checklist | `src/cli/quality-scan.ts` for dead exports/files; the rest (narrating comments, single-use helpers, stub-shaped code) is a manual read against `quality-extras.txt` | Manual read for the anti-pattern classes knip can't see |
| M6 Simplification / reuse | `/simplify` + `quality-extras.txt` | Not mechanically detectable — `/simplify` review | Fully manual, brief-driven |

## 1. Running the scan (M4 + M5)

```bash
pnpm quality-scan <client-repo-path> --out findings.quality.json
```

This runs Harvey's own jscpd and knip (no install needed in the client repo — the CLI resolves
`node_modules/.bin/{jscpd,knip}` from Harvey itself) against the target path and shapes the output
into `Finding[]` (`src/findings.ts` shape): `src/cli/quality-scan.ts` wraps the pure transforms in
`src/quality-scan.ts` (`jscpdToFindings`, `knipToFindings`, `duplicationSummary`).

- **M4 ids:** `M4-01`, `M4-02`, … — one per clone cluster, worst (most duplicated lines) first.
  Severity scales with cluster size: ≥50 duplicated lines → Medium, ≥15 → Low, else Info.
- **M5 ids:** `M5-01`, `M5-02`, … — one per fully-unused file (knip's top-level `files`) and one
  per file with unreferenced exports/types (knip's `issues`). Fully-dead files report a measured
  line count (the CLI reads the file); partial dead-export findings deliberately do **not** claim
  a precise line-reduction number — knip reports the declaration, not the body size, and asserting
  one would be a guess, not a fact.
- Requires: the client repo has a `package.json` (knip) and no crashing tsconfig. If the client
  repo has no `knip.json`, knip falls back to its own zero-config heuristics — expect a noisier
  first pass that needs more triage; if it's noisy enough to be unusable, add a minimal
  `knip.json` (`entry`/`project` globs) for the duration of the engagement rather than shipping
  the raw zero-config output.
- `jscpd` is run with `--threshold 100` (so a client's own strict `.jscpd.json` threshold can't
  fail the scan — we want the raw report, not jscpd's own pass/fail gate) and excludes
  `node_modules`, `dist`, `.next`.

**Prerequisite check before running:** confirm the target path doesn't include generated/vendored
code the client didn't author (build output, `node_modules` if `.gitignore` is missing it,
committed lockfiles) — jscpd and knip will happily report duplication/dead-code noise on code that
was never meant to be hand-maintained.

### Triage the mechanical output

Run the FP-control funnel from `docs/tier1-runbook.md` §4 before anything ships:
- **Correctness gate:** confirm the clone/dead-export is real, not a jscpd/knip artifact (check
  the fp-rules-equivalent classes below).
- Known FP classes (`quality-extras.txt` "FALSE POSITIVES"):
  - A "single-use" helper that exists for testability/seam reasons, or clearly about to gain
    callers.
  - An abstraction mandated by a framework/library contract (not gratuitous).
  - A deliberate re-implementation chosen to drop a heavy dependency — note the tradeoff, don't
    flag as a defect.
  - knip specifically: public-API exports meant for external consumers, dynamically-referenced
    exports (string-based lookups, plugin registries) knip's static analysis can't see.
  - jscpd specifically: intentional/structural clones (e.g. boilerplate a framework requires
    verbatim in multiple places).

## 2. Mapping into the report (§3b of `docs/audit-report-skeleton.md`)

`findings.quality.json` produced by `pnpm quality-scan` merges into the client's engagement
`findings.<client>.json` (alongside M1/M2/M3 findings and `meta`) — copy the array entries in,
adjust confidence/severity after triage if the mechanical default doesn't match your read, then
`pnpm validate:findings findings.<client>.json` before rendering.

- **§3b Duplication (M4):** report the overall duplication % (`duplicationSummary()` — printed to
  stderr by the CLI run) plus the worst clone clusters (already ranked by the CLI), each with its
  consolidation suggestion (the `fix` field: "extract the shared logic into one function/module").
  Frame the risk as fix-once vs. fix-in-N-places: a bug fixed in one clone and missed in the others
  is the concrete cost.
- **§3b Slop / dead code (M5):** group the `M5-*` findings into a delete/inline/simplify list.
  Files are unambiguous deletes (pending a "is this a planned entry point" check); unused-export
  findings are per-file so the client can review each list of dead names together. State the line
  reduction only where it's measured (whole files); for partial dead exports, say so plainly rather
  than estimating.
- **§3b Simplification / reuse (M6):** this module has no mechanical detector — it's the
  `/simplify` skill applied whole-repo against `docs/quality-extras.txt`'s SIMPLIFICATION section
  (hand-rolled primitives, hand-rolled versions of an already-in-the-dependency-tree library,
  over-abstraction, premature generality, inconsistent patterns, "would a senior engineer call this
  overcomplicated"). For each item found: the current code → the concrete replacement (stdlib,
  framework primitive, existing dep, or "collapse to inline") → the maintenance/onboarding cost it
  removes. This is the section that lands with clients who don't believe they have a security
  problem — lead with the recurring-cost framing, not just "this could be simpler."

## 3. Test quality (M8) note

`quality-extras.txt` also carries the M8 test-quality brief (tests that can't fail — tautological,
snapshot-only, asserts-what-not-why, mocks the thing under test). That module runs on StrykerJS
mutation output, not jscpd/knip, and is tracked separately — out of scope for this runbook's wiring
(see `docs/audit-modules.md` M8 status: net-new, needs a working test runner in the client repo
before it can run at all).

## 4. Wiring code

- `src/quality-scan.ts` — pure transforms: `jscpdToFindings`, `knipToFindings`,
  `duplicationSummary`. Tested against fixtures shaped from real `jscpd --reporters json` /
  `knip --reporter json` output (`src/quality-scan.test.ts`).
- `src/cli/quality-scan.ts` — the CLI: runs jscpd + knip against a target path, reads dead-file
  line counts off disk, calls the pure transforms, and writes/prints the merged `Finding[]`.
  Registered as `pnpm quality-scan` in `package.json`.

---

### Deferred: live dry-run validation

Verified against fixture repos with real jscpd/knip output during development (see the wiring
code's tests), but not yet run end-to-end against a full third-party sample repo to produce a real
§3b section — that dry run is a manual follow-up, out of scope for this automated pass.
