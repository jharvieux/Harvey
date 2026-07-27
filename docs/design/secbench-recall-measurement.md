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

## RE-MEASURED 2026-07-27 (#1222) — what changed and what did not

The gate was re-run end to end on **2026-07-27** (semgrep 1.164.0, osv-scanner 2.3.8, npm 11.12.1,
same pin) to discharge #1222's acceptance criterion after PR #1235 excluded the seven App-Router
HTTP-method names from the `harvey-lib-*` entry-point source. **Where the 2026-07-27 numbers differ
from the 2026-07-24/26 ones below, the 2026-07-27 numbers are current and the older ones are kept
as dated history, not deleted.**

- **SCA recall: IDENTICAL to 2026-07-24**, per class and overall — 433/594 (72.9%) any-advisory,
  403/594 (67.8%) exact-CVE, with the same 6 no-longer-resolvable packages. Reproduced exactly.
- **Request-sourced (semgrep) recall: 1/600, superseding the 0/600 recorded 2026-07-24.** The single
  hit is `harvey-redos-literal` on `redos/react-native_0.63.0-rc.0/react-native.test.js` — a rule
  that landed in commit 6fafa61 (#1200–#1203, the OWASP Node.js gaps) AFTER the 2026-07-24 run. It
  is a pattern rule over a regex literal, not a taint rule, so the structural explanation in "Why
  the source rules score zero" is unchanged: 0 of the 600 came from a request→sink taint path.
- **Library-internal source recall: 154/296 (52.0%)** over a near-complete tree (see the table
  below), superseding the 33/97 (34.0%) SUBSET measured 2026-07-26. The rules were not changed to
  raise it — a like-for-like A/B (next bullet) shows the rules score identically before and after
  #1235. The difference from 33/97 is DENOMINATOR: this run installed every installable
  single-target-package entry in the three rule-covered classes (296) instead of a 97-entry subset.
- **#1222 regression check — none.** The same 296 installed target-package sources were scanned
  twice, with the CURRENT `library-taint.yml` and with the pre-#1235 version (`git show 1caa9e3^`).
  Result: **0 entries lost all findings, 0 entries gained findings, 0 entries changed finding count,
  and the raw finding total is 197 in both arms.** The exclusion is anchored, case-sensitive and
  named-export-only, and SecBench's published packages are overwhelmingly CommonJS
  (`module.exports`/`exports.x`) — not one of them exports a function literally named
  `GET`/`POST`/`PUT`/`PATCH`/`DELETE`/`HEAD`/`OPTIONS`. **#1235 cost zero library-internal recall on
  594 real npm CVEs.**

## Headline: what the mechanical tier scores, and by which pathway

**Harvey's mechanical tier detects SecBench.js vulnerabilities through its dependency-CVE (SCA)
engine only. Its request-sourced semgrep rules detect essentially none of them — a measured 0/600
on 2026-07-24 and 1/600 on 2026-07-27 (one regex-literal rule, no taint path), not an estimate.**

The table below was measured 2026-07-24 and **re-measured 2026-07-27 with identical results** in
every cell.

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
- **Request-sourced (semgrep) recall over the exploit dirs: 0/600 (2026-07-24), 1/600 (2026-07-27).**
  Both Harvey's `harvey-*` custom
  rules AND the full registry security packs (`p/owasp-top-ten`, `p/security-audit`, …) — the exact
  config `runMechanicalScan` runs — fired on ZERO of the 600 exploit test files on 2026-07-24, and on
  ONE (`harvey-redos-literal`, added after that run in #1200–#1203) on 2026-07-27. This is a property of
  WHAT is scanned and WHERE the source is (below), not a detector gap that tuning the request rules
  could close. **#946 opened the complementary axis — library-internal parameter-sourced taint over
  the INSTALLED target-package source — which moves this number off 0; measured below.**

## Why the source rules score zero (the load-bearing portability finding)

SecBench's vulnerability lives **inside the vulnerable library** (the sink is e.g. `index.js:18:3`
in the dependency's own code). The exploit is a jest test that `require`s the library and calls it
with a hardcoded malicious payload — e.g. `aaptjs.list("; touch aaptjs", cb)`. There is **no HTTP
request source and no in-tree sink**. Harvey's injection rules (`harvey-command-injection`,
`harvey-code-injection-eval`, `harvey-prototype-pollution`, `harvey-path-traversal`, `harvey-redos`,
…) are **taint-mode** rules whose sources are `req.query` / `req.body` / `req.params` /
`searchParams` and whose sinks are in the scanned application tree. Neither is present in a SecBench
entry: the payload is a constant, and the real sink is in `node_modules`, which is not scanned.

**The single 2026-07-27 hit does not weaken this.** `harvey-redos-literal` is a PATTERN rule over a
regex literal, not a taint rule: it fired on the exploit file's own hardcoded regex, with no source
and no flow. The taint count over the exploit dirs is still zero, which is what this section
explains — a new non-taint rule finding something in a test file is a different (and welcome) event.

**The issue's hypothesis — "It exercises M1's injection / XSS / prototype-pollution / path-traversal
/ command-injection rules — the syntactic majority of our 92 rules" — is FALSIFIED by measurement.**
SecBench is a **known-vulnerable-dependency (SCA) corpus** for the REQUEST-sourced rules, not a
request-source-taint corpus. It measures Harvey's dependency-CVE tier via those rules, and says
nothing about them beyond "the app-layer request shape is absent." This is the same distinction the
repo draws elsewhere between what a corpus covers and what a number claims.

## Library-internal source recall (#946) — moving the 0 with parameter-sourced taint

The zero above is a request-shape zero: the SOURCE in a SecBench entry is not an HTTP request, it is
a **parameter of a library entry point** — either an exported function's argument (`@vivaxy/here`'s
`read-file(file)`) or, for the dominant path-traversal population, a **raw node http/https server's
request callback** (`http.createServer((req,res) => { var p = "./" + req.url; fs.readFile(p) })`).
#946 added `src/scan/rules/semgrep/library-taint.yml` — three taint rules (`harvey-lib-path-traversal`,
`harvey-lib-command-injection`, `harvey-lib-code-injection`) whose SOURCE is exactly those two
parameter shapes, gated to the PUBLIC API surface (exported functions + server request callbacks) and
review-tier (a function parameter is a far broader source than a request object, so never free-count).
Scanning the **installed target-package source** (not the exploit dir) scores this axis.

**Measured 2026-07-26** (semgrep 1.164.0) on an installable SUBSET — the target package of each entry
installed via `npm install` into `<tree>/<class>/<slug>/node_modules/<pkg>`, then scanned with the
`harvey-lib-*` rules through `validate-secbench.ts --library-source-tree`:

| SecBench class | scanned | library-internal source recall |
|----------------|--------:|-------------------------------:|
| path-traversal      | 40 | 25/40 (62.5%) |
| command-injection   | 27 |  4/27 (14.8%) |
| code-injection      | 30 |  4/30 (13.3%) |
| **subset ALL**      | **97** | **33/97 (34.0%)** |

**SUPERSEDED — re-measured 2026-07-27** (semgrep 1.164.0) over a NEAR-COMPLETE tree instead of a
97-entry subset. Quoted verbatim from `validate-secbench.ts --library-source-tree`:

| SecBench class | scanned | library-internal source recall |
|----------------|--------:|-------------------------------:|
| command-injection   |  91 |  29/91 (31.9%)  |
| path-traversal      | 167 | 121/167 (72.5%) |
| code-injection      |  38 |   4/38 (10.5%)  |
| **ALL**             | **296** | **154/296 (52.0%)** |

The denominator is now everything the pathway can address: the three classes whose sinks the
`harvey-lib-*` rules model (prototype-pollution and redos have no library-taint rule, so scanning
them would measure nothing), minus, DISCLOSED not dropped — 5 entries whose package no longer
resolves from npm (`command-injection/{corenlp-js-interface_1.0.3, corenlp-js-prefab_1.0.1,
effect_1.0.4, jison_0.4.17}`, `path-traversal/srverqq_1.0.0`) and 10 multi-dependency entries with no
single target package for the scanner to scope to (`path-traversal/{aso-server_0.4.3,
starfruit_0.2.2}`, `command-injection/{arpping_2.0.0, git_0.1.5, gity_1.0.5, imagickal_5.0.1,
local-devices_2.0.0, node-unrar_0.1.0}`, `code-injection/{is-my-json-valid_2.20.0,
mongo-parse_2.1.0}`). 311 entries in the three classes → 296 scanned.

**The rise from 34.0% to 52.0% is a denominator change, not a detector change.** Scanning the same
296 sources with the pre-#1235 rules gives the identical 154/296 (see the #1222 A/B at the top of
this document), and no `harvey-lib-*` rule was edited between the two runs.

Up from a measured 0. path-traversal moves most because its dominant shape is the raw-http-server
request-callback param, an intra-procedural `req.url → concat → fs.readFile` flow semgrep follows
cleanly. command-injection and code-injection move least: their real flows are dominated by
**cross-function** (`aaptjs.list()` builds the command string, hands it to a separate `promistify()`
that runs `exec`) and **non-exported internal helpers** — both past OSS Semgrep's intra-procedural
taint ceiling (#873), which parameter-sourcing extends but does not lift. ~~This is a SUBSET
measurement (97 entries) … the full-corpus number awaits building the whole `--library-source-tree`
out of process.~~ **CLOSED 2026-07-27:** that tree was built for every installable single-target
entry in the three rule-covered classes (296), so the number above is no longer a subset — the
remaining 15 exclusions are enumerated by name. This number is REPORTED DISTINCTLY from the SCA
number and the request-sourced pathway — never blended.

## The free/mechanical-tier answer for #868

**Harvey's free/mechanical-tier recall on SecBench.js is a dependency-CVE (SCA) number: 433/594
(72.9%) of installable entries flagged as known-vulnerable (measured 2026-07-24, reproduced exactly
2026-07-27). The REQUEST-sourced detector recall is a measured 0/600 (2026-07-24) / 1/600
(2026-07-27); the LIBRARY-internal source recall is a separately-measured 154/296 (52.0%,
2026-07-27) over the three rule-covered classes.** These are separate tiers and MUST NOT be blended into one "free-tier recall on real CVEs"
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
  per-entry matcher (`matchEntryOsv`, scoped to the entry's OWN target package), and scorers
  (`scoreSecbench` for SCA; `scoreLibrarySource` for the #946 library-internal source axis). Each
  takes its denominator set separately (installable / scanned) from the report, because a clean entry
  is absent from the tool's JSON — using the report's own keys as the denominator would drop every
  real miss and manufacture a higher number.
- `src/cli/validate-secbench.ts` — the CLI that joins the inputs and prints the per-class tables.
  Runs the request-sourced semgrep pass live (or reads a precomputed `--semgrep-json`); runs the
  #946 library-internal `harvey-lib-*` pass over `--library-source-tree` when provided.
- `src/scan/secbench.test.ts` — offline Layer-1 test (in `pnpm verify`, no clone, no network):
  proves the loader, the target-package scoping, the transitive-dep exclusion, and the denominator
  honesty of BOTH scorers (an installable/scanned-but-clean entry is a MISS, not dropped).

No `pnpm` script alias was added — the recorded reason was that `package.json` is supervised, which is FALSE (operator ruling 2026-07-27). Invoke via
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

# 5. (#946, library-internal source axis) For each entry, ACTUALLY install its target package into
#    <libtree>/<class>/<slug>/node_modules/<pkg> (a real `npm install`, not --package-lock-only), then:
pnpm exec tsx src/cli/validate-secbench.ts \
    --dir SecBench.js --osv-report osv-report.json --lockfile-tree <work> \
    --library-source-tree <libtree>
#    The --library-source-tree pass scans each installed target-package source with the harvey-lib-*
#    parameter-sourced rules and prints the per-class library-internal source recall.
```

## Guardrail honored

Per #879: **the vibe-dummy FP oracle (0 false positives) remains the precision gate — untouched.**
SecBench has no benign negatives (every entry is a positive), so precision/FPR are not measurable
from it; this gate reports RECALL only, and nothing was tuned in response to the score.

## Provenance

Every number NOT marked 2026-07-27 is from a run observed 2026-07-24 on the cloned source (deleted
after). `osv-scanner 2.3.8`; semgrep with the same config `runMechanicalScan` uses. Full corpus
scored (600 entries; 594 installable; 6 declared env gaps). No Harvey detector changed; no benchmark
chasing.

**2026-07-27 re-run (#1222).** Same pin, fetched as the commit-SHA tarball
(`codeload.github.com/cristianstaicu/SecBench.js/tar.gz/bc31562…`) into scratch and deleted after;
no source vendored. `semgrep 1.164.0`, `osv-scanner 2.3.8`, `npm 11.12.1`, macOS, HEAD `cafd8f3`
(includes PR #1235 / commit `1caa9e3`). 600 entries loaded, 594 lockfiles generated (the same 6
packages failed to resolve), `osv-scanner --format json -r` exited 1 (vulnerabilities found), the
gate exited 0. The library-source arm additionally installed 305 target packages and scanned 296.
The A/B against the pre-#1235 rules was run with the same per-entry scope the gate uses
(`--exclude node_modules` over `<tree>/<class>/<slug>/node_modules/<pkg>`) and independently
reproduced the gate's 154/296. **No Harvey detector, rule, corpus entry or gate was changed to
produce these numbers** — the only repo change from this run is this document.
