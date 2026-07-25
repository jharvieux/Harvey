# M4–M6 quality runbook — duplication, slop, simplification

> The maintainability third of the audit: wiring already-existing tooling (jscpd, knip) plus the
> `/simplify` review doctrine into §3b of the deliverable. Security (M1, `docs/tier1-runbook.md`)
> leads the pitch; this is what makes the engagement a *full* audit and the reason a one-time audit
> becomes a recurring relationship (see `briefs/audit-modules.md` for the module catalog this
> generalizes).

## 0. What's wired vs. manual

| Module | Tool | Automated by | Manual step |
|---|---|---|---|
| M4 Duplication | jscpd | `src/cli/quality-scan.ts` (`pnpm quality-scan`) | Pick consolidation approach per cluster |
| M5 Slop / dead code | knip + `src/detectors/slop.ts` + `briefs/quality-extras.txt` checklist | `src/cli/quality-scan.ts` for dead exports/files; **`detectSlopFindings` (`src/detectors/slop.ts`, ids `SLOP-*`, run via `pnpm detect-static`)** now mechanizes 11 AI-slop classes — see §5; the residue (judgment-heavy simplification) stays a manual read against `briefs/quality-extras.txt` | Manual read for the classes neither knip nor the slop detector can see |
| M6 Simplification / reuse | `pnpm simplify-scan` + `briefs/quality-extras.txt` | Not mechanically detectable — the runner assembles a brief+source review packet (`src/cli/simplify-scan.ts`); a reviewer judges it | Fully manual, brief-driven |

## 1. Running the scan (M4 + M5)

```bash
pnpm quality-scan <client-repo-path> --out findings.quality.json
```

This runs Harvey's own jscpd and knip (no install needed in the client repo — the CLI resolves
`node_modules/.bin/{jscpd,knip}` from Harvey itself) against the target path and shapes the output
into `Finding[]` (`src/findings.ts` shape): `src/cli/quality-scan.ts` wraps the pure transforms in
`src/quality-scan.ts` (`jscpdToFindings`, `knipToFindings`, `duplicationSummary`).

- **M4 ids:** `M4-01`, `M4-02`, … — one per clone cluster, worst (most duplicated lines) first.
  Severity scales with cluster size: ≥50 duplicated lines → Medium, ≥15 → Low, else Info. Clusters
  are gated on being cross-file (a file matched against itself — e.g. an SVG icon-path table
  repeating internally — is repetitive data, not a refactor candidate) and ≥10 significant lines
  (`MIN_SIGNIFICANT_LINES` in `src/quality-scan.ts`); the reported dup% (`duplicationSummary()`) is
  recomputed from that same significant-clusters set, not jscpd's raw total, so the headline number
  and the findings agree.
- **M5 ids:** `M5-01`, `M5-02`, … — one per fully-unused file (knip's top-level `files`) and one
  per file with unreferenced exports/types (knip's `issues`). Fully-dead files report a measured
  line count (the CLI reads the file); partial dead-export findings deliberately do **not** claim
  a precise line-reduction number — knip reports the declaration, not the body size, and asserting
  one would be a guess, not a fact. A file or export whose path touches auth/guard/middleware/
  security (tokenized on separators and camelCase boundaries, so `AuthGuard.tsx` and
  `useAuthMiddleware.ts` match but "authors" doesn't) elevates from Low to Medium and cross-links
  the M1 authorization review — dead code in that class of path preceded a real cross-tenant
  Critical in a past engagement (a guard helper written and never wired in). If knip itself fails
  to run (most commonly the target's own `node_modules` isn't installed, so it can't resolve
  config/plugin imports), M4's jscpd output still ships and M5 substitutes a single `M5-00`
  Info-severity "M5 dead-code scan (knip) did not run" finding — a disclosed coverage gap, not a
  crash or a silent skip.
- Requires: the client repo has a `package.json` (knip) and no crashing tsconfig. If the client
  repo has no `knip.json`, knip falls back to its own zero-config heuristics — expect a noisier
  first pass that needs more triage; if it's noisy enough to be unusable, add a minimal
  `knip.json` (`entry`/`project` globs) for the duration of the engagement rather than shipping
  the raw zero-config output.
- `jscpd` is run with `--threshold 100` (so a client's own strict `.jscpd.json` threshold can't
  fail the scan — we want the raw report, not jscpd's own pass/fail gate) and excludes
  `node_modules`, `dist`, `.next`, plus generated/vendored/demo paths (`JSCPD_IGNORE_GLOBS` in
  `src/quality-scan.ts`: generated Supabase types `database.types.ts`/`types_db.ts`, `*.gen.ts`,
  `generated/`, `vendor/`, `patches/`, `*demo*` files/dirs) — a 6-repo calibration sweep found
  these inflating dup% in most repos triaged without being hand-maintained duplication.

**Prerequisite check before running:** jscpd auto-excludes the common generated/vendored/demo
shapes above; still confirm the target path doesn't include other build output or vendored code
the client didn't author (`node_modules` if `.gitignore` is missing it, committed lockfiles) —
both tools will happily report duplication/dead-code noise on code that slips past the exclusions
and was never meant to be hand-maintained.

### Triage the mechanical output

Run the FP-control funnel from `docs/tier1-runbook.md` §4 before anything ships:
- **Correctness gate:** confirm the clone/dead-export is real, not a jscpd/knip artifact (check
  the fp-rules-equivalent classes below).
- Known FP classes (`briefs/quality-extras.txt` "FALSE POSITIVES"):
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
  than estimating. Auth/guard/security-path findings (elevated to Medium) belong alongside the M1
  authorization review, not just this list — cross-link them. If M5 didn't run this pass (`M5-00`),
  state that plainly as a disclosed coverage gap rather than implying zero dead code.
- **§3b Simplification / reuse (M6):** this module has no mechanical detector — run
  `pnpm simplify-scan <target>` to assemble the review packet, then review it against
  `briefs/quality-extras.txt`'s SIMPLIFICATION section
  (hand-rolled primitives, hand-rolled versions of an already-in-the-dependency-tree library,
  over-abstraction, premature generality, inconsistent patterns, "would a senior engineer call this
  overcomplicated"). For each item found: the current code → the concrete replacement (stdlib,
  framework primitive, existing dep, or "collapse to inline") → the maintenance/onboarding cost it
  removes. This is the section that lands with clients who don't believe they have a security
  problem — lead with the recurring-cost framing, not just "this could be simpler."

## 3. Test quality (M8) note

`briefs/quality-extras.txt` also carries the M8 test-quality brief (tests that can't fail — tautological,
snapshot-only, asserts-what-not-why, mocks the thing under test). That module runs on StrykerJS
mutation output, not jscpd/knip, and is tracked separately — out of scope for this runbook's wiring
(see `briefs/audit-modules.md` M8 status: net-new, needs a working test runner in the client repo
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

## 5. Mechanical AI-slop detectors — `src/detectors/slop.ts`

`detectSlopFindings(files)` runs 11 AI-slop classes over TS/TSX source (taxonomy `M5 — …`,
ids `SLOP-*`, category Maintainability), run via `pnpm detect-static`. Each class is gated by a
positive+negative fixture pair (`src/detectors/__fixtures__/slop/`, `slop.test.ts`) — the #61
discipline. Two provenance groups:

**Ported from ATC's `scripts/slop-check.ts`** (which only runs on ATC's own diffs; these now run
on any target's whole source): Orphan TODO (marker with no owner/issue ref), Narrating comment
(verb-first comment restating the next line), Rethrow catch (`catch (e) { throw e }`), Single-call
wrapper (an exported function whose body is `return freeFn(sameParams)` — bare-identifier callee
only, so meaningful `.has()`/`.includes()` predicates aren't flagged).

**Additional researched classes:** Placeholder stub (`throw new Error("not implemented")`,
`// TODO: implement`), Elision placeholder (`// ... existing code ...` — ellipsis-adjacent or a
short standalone marker, never a phrase embedded in prose), AI comment phrasing (tutorial voice:
"this function is responsible for", "as you can see"), Redundant boolean (`cond ? true : false`
only — the `=== true` comparison form is type-dependent and deliberately not flagged), Else after
return, Decorative emoji (colourful pictographs + ✅❌❗ in comments/logs; excludes functional
`⚠`/`↗`/`✓`), Redundant JSDoc (`@param userId The user id`).

**FP calibration (dogfood 2026-07-11):** tuned against Harvey's own source (→ 2 findings) and ATC's
1,127 files (→ 12, all defensible). Confidence tiers: high-signal structural classes are `Likely`;
the comment-style classes (narrating, AI phrasing, emoji, JSDoc, wrapper) are `Review`. Findings
map into §3b Slop / dead code (M5) alongside the knip `M5-*` output.
