# Harvey recall measurement — SecBench.js (external, held-out, real CVEs)

**Date:** 2026-07-24
**Target:** `cristianstaicu/SecBench.js` @ `bc315621913899dcaa7613cd60948514ae63bdfe` (ICSE 2023;
Staicu et al., "An Executable Security Benchmark Suite for Server-Side JavaScript"). ~600 **real,
publicly-reported npm vulnerabilities** across five server-side-JS classes, each shipping a pinned
vulnerable package version, an executable jest exploit, and ground-truth metadata (CVE id where
one exists, advisory links, sink location). Cloned to scratch (deleted after); no source vendored.
**Issue:** jharvieux/Harvey#879.

This is a MEASUREMENT — every number below is from a run performed on this date in a worktree, with
the mechanical-tier binaries on PATH (`semgrep 1.x`, `osv-scanner 2.3.8`). No Harvey detector was
changed. SecBench is Harvey's **first held-out corpus of real CVEs** — the six external-corpus
targets are planted-bug teaching labs, and the M1 calibration corpus is planted fixtures.

## Headline: what the mechanical tier scores, and by which pathway

**Harvey's mechanical tier detects SecBench.js vulnerabilities through its dependency-CVE (SCA)
engine only. Its 92 semgrep source rules detect ZERO of them — a measured 0/600, not an estimate.**

| SecBench class | entries | installable | SCA recall (osv, any advisory) | exact-CVE recall |
|----------------|--------:|------------:|-------------------------------:|-----------------:|
| prototype-pollution | 192 | 192 | 169/192 (88.0%) | 160/192 (83.3%) |
| redos               |  97 |  97 |  70/97 (72.2%)  |  57/97 (58.8%)  |
| command-injection   | 101 |  96 |  76/96 (79.2%)  |  72/96 (75.0%)  |
| path-traversal      | 170 | 169 |  87/169 (51.5%) |  86/169 (50.9%) |
| code-injection      |  40 |  40 |  31/40 (77.5%)  |  28/40 (70.0%)  |
| **ALL**             | **600** | **594** | **433/594 (72.9%)** | **403/594 (67.8%)** |

- **SCA recall (any advisory):** osv-scanner reported ≥1 advisory on the entry's OWN target package
  at the pinned version. This is Harvey's actual SCA job (flag the known-vulnerable dependency).
- **exact-CVE recall:** the reported advisory's id/aliases matched the specific CVE/GHSA SecBench
  curated. Lower because advisories get renumbered and some SecBench ids are Snyk-only.
- **Source-pattern (semgrep) recall: 0/600.** Both Harvey's `harvey-*` custom rules AND the full
  registry security packs (`p/owasp-top-ten`, `p/security-audit`, …) — the exact config
  `runMechanicalScan` runs — fired on ZERO of the 600 exploit test files.

## Why the source rules score zero (the load-bearing portability finding)

SecBench's vulnerability lives **inside the vulnerable library** (the sink is e.g. `index.js:18:3`
in the dependency's own code). The exploit is a jest test that `require`s the library and calls it
with a hardcoded malicious payload — e.g. `aaptjs.list("; touch aaptjs", cb)`. There is **no HTTP
request source and no in-tree sink**. Harvey's injection rules (`harvey-command-injection`,
`harvey-code-injection-eval`, `harvey-prototype-pollution`, `harvey-path-traversal`, `harvey-redos`,
…) are **taint-mode** rules whose sources are `req.query` / `req.body` / `req.params` /
`searchParams` and whose sinks are in the scanned application tree. Neither is present in a SecBench
entry: the payload is a constant, and the real sink is in `node_modules`, which is not scanned.

**The issue's hypothesis — "It exercises M1's injection / XSS / prototype-pollution / path-traversal
/ command-injection rules — the syntactic majority of our 92 rules" — is FALSIFIED by measurement.**
SecBench is a **known-vulnerable-dependency (SCA) corpus**, not a source-taint corpus. It measures
Harvey's dependency-CVE tier, which is the correct tier for it, and says nothing about the source
rules. This is the same distinction the repo draws elsewhere between what a corpus covers and what
a number claims.

## The free/mechanical-tier answer for #868

**Harvey's free/mechanical-tier recall on SecBench.js is a dependency-CVE (SCA) number: 433/594
(72.9%) of installable entries flagged as known-vulnerable. The source-detector recall is a measured
0/600.** These are separate tiers and MUST NOT be blended into one "free-tier recall on real CVEs"
figure — a blended number would read as source-detector performance, which is 0 here. #868 should
cite the SCA number as an SCA number, explicitly scoped, or not at all.

## Why the misses are misses (verified, not assumed)

594 installable, 433 flagged → **161 installable misses.** Cause, checked against each entry's
metadata (not inferred):

- **The dominant cause is OSV/GHSA database coverage.** The overwhelming majority of misses are
  entries whose only advisory link is **Snyk or Huntr, with no GHSA and no CVE id** — SecBench
  curated them from Snyk/Huntr, and they were never issued a GHSA, so they are not in the OSV
  database osv-scanner queries. **path-traversal is worst (51.5%) for exactly this reason:** it is
  dominated by tiny, obscure static-file-server packages (`basic-static`, `aso-server`, `der-server`,
  `caihong`, …) disclosed only via Snyk/Huntr. This is not a Harvey detector gap and not a matcher
  bug — it is the ceiling any OSV-backed SCA tool hits on this corpus. A Snyk-fed SCA engine would
  score higher on these specific entries; Harvey uses OSV.
- A smaller set are **transitive-only or version-range** cases: osv flagged a *transitive* dependency
  of the pinned package (correctly NOT counted as catching the SecBench target vuln — the matcher
  scopes to the entry's own package), or the pinned version fell outside OSV's recorded affected
  range. These are correct behavior, not misses to "fix".

## Declared gap (coverage guard): 6 packages no longer installable

6/600 entries have NO osv data because their pinned package/version **no longer resolves from the
npm registry** (unpublished/removed), so no lockfile could be generated:
`command-injection/{gity_1.0.5, corenlp-js-interface_1.0.3, corenlp-js-prefab_1.0.1, effect_1.0.4,
jison_0.4.17}` and `path-traversal/srverqq_1.0.0`. These are an **environment gap, not a detector
miss** — excluded from the recall denominator and named here rather than silently dropped (which
would have inflated recall by shrinking the denominator, the exact trap #879 warns about).

## The harness (committed) — loader + matcher + scorer, following the external-corpus pattern

- `src/scan/secbench.ts` — pure loader (`loadSecbenchCorpus`), osv indexer (`indexOsvByEntry`),
  per-entry matcher (`matchEntryOsv`, scoped to the entry's OWN target package), and scorer
  (`scoreSecbench`). The scorer takes the **installable set separately** from the osv report,
  because osv-scanner omits clean lockfiles from its JSON — using the report's own keys as the
  denominator would drop every real miss and manufacture a higher number.
- `src/cli/validate-secbench.ts` — the CLI that joins the three inputs and prints the per-class
  table above. Runs the semgrep source pass live (or reads a precomputed `--semgrep-json`).
- `src/scan/secbench.test.ts` — offline Layer-1 test (in `pnpm verify`, no clone, no network):
  proves the loader, the target-package scoping, the transitive-dep exclusion, and the denominator
  honesty (an installable-but-clean entry is a MISS, not dropped).

No `pnpm` script alias was added (`package.json` is a supervised path); invoke via
`pnpm exec tsx src/cli/validate-secbench.ts`, the same convention as `validate-precision.ts`.

## Reproduction (exact commands, 2026-07-24)

```bash
# 1. Clone at the pin.
git clone https://github.com/cristianstaicu/SecBench.js
git -C SecBench.js checkout bc315621913899dcaa7613cd60948514ae63bdfe

# 2. For each entry, write a package.json with its single pinned dependency into a work tree
#    <work>/<class>/<slug>/package.json, then generate a lockfile (no install, no audit):
#      (cd <work>/<class>/<slug> && npm install --package-lock-only --no-audit --no-fund)
#    594/600 succeeded; 6 packages no longer resolve from npm (listed above).

# 3. One recursive osv-scanner pass over the whole lockfile tree:
osv-scanner --format json -r <work> > osv-report.json     # exits 1 when vulns are found

# 4. Score (semgrep run live over the clone's class dirs, or pass a precomputed --semgrep-json):
pnpm exec tsx src/cli/validate-secbench.ts \
    --dir SecBench.js --osv-report osv-report.json --lockfile-tree <work>
```

## Guardrail honored

Per #879: **the vibe-dummy FP oracle (0 false positives) remains the precision gate — untouched.**
SecBench has no benign negatives (every entry is a positive), so precision/FPR are not measurable
from it; this gate reports RECALL only, and nothing was tuned in response to the score.

## Provenance

Every number is from a run observed 2026-07-24 on the cloned source (deleted after). `osv-scanner
2.3.8`; semgrep with the same config `runMechanicalScan` uses. Full corpus scored (600 entries; 594
installable; 6 declared env gaps). No Harvey detector changed; no benchmark chasing.
