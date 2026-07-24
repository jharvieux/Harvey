# BenchProctor evaluation — external generic source-detection recall gate (spike #973)

**Verdict: DON'T-ADOPT as a wired recall gate.** Keep this document as the one-time measured
baseline. Reasoning and every number below come from a run performed 2026-07-24 in this session
against the pinned release `2026.07.22`; nothing here is carried from the issue, the README, or a
prior session.

## What BenchProctor is (mapped from the actual clone, not the marketing page)

`github.com/TheAuditorTool/BenchProctor`, Apache-2.0, release `2026.07.22`. Cloned to scratch
(never committed — 2.9M-case corpus). The repo root ships **only** per-language ZIP bundles under
`Benchmarks/{quicktest,normal,enterprise}/<language>/`, plus `scripts/score_sarif.py`. The cases
themselves live inside the ZIPs; you extract the tier/language you want.

- **Three sizes:** `quicktest` (34–62 categories/framework, 50 vuln + 50 safe per category),
  `normal` (up to 100+100), `enterprise` (up to 250+250). Same categories, deeper sampling.
- **JS bundle:** frameworks `express` + `koa`. **TS bundle:** `express_ts` + `nestjs`. Each
  framework suite in quicktest = 62 categories × 100 = **6,200 scored cases** (+ a handful of
  shared companion files: `shared.js`, `routes.js`, `shared.mjs`, not scored).
- **Case shape:** one function per file, e.g. `testcode/benchmark_test_00115.js`, no comments, no
  CWE tags, no category in the filename (anti-leakage by construction — verified: the case files
  carry only `// SPDX-License-Identifier: Apache-2.0` and code).
- **Answer key:** `expectedresults-2026.07.22.csv`, one row per case:
  `test name,category,real vulnerability,CWE` — e.g. `BenchmarkTest00115,idor,true,639`. Note the
  CSV key is CamelCase `BenchmarkTestNNNNN` while the file on disk is lowercase
  `benchmark_test_NNNNN.js`; the scorer bridges the two.

### How `score_sarif.py` matches a scanner's SARIF to labels (read in full)

For JS/TS the CSV keys match `BenchmarkTest\d{5,}$`, so the scorer uses **filename + CWE matching**
(`compute_detections_filename_cataware`), NOT the annotation mode used for Rust/Bash/PHP/Ruby:

1. It extracts `BenchmarkTestNNNNN` from each SARIF result's `physicalLocation.artifactLocation.uri`
   (regex `benchmark_test_(\d{5,})\.\w+`, so Harvey's repo-relative `benchmark_test_00115.js:7` URIs
   resolve correctly).
2. **Default `cwe` mode:** a case counts as detected only if a finding is on that file **AND** carries
   the case's expected CWE. The CWE is recovered from the `ruleId`, the result/rule
   `properties.cwe`/`tags`, or CWE taxa — via `cwe_from_text`, which parses `89`, `CWE-89`, `cwe-089`,
   `external/cwe/cwe-89`. Harvey's SARIF (`src/sarif.ts`) puts each `f.cwe` value into the rule's
   `properties.tags`, so `build_rule_cwe_index` harvests them. This means CWE matching works **only for
   the Harvey rules that actually tag a CWE** (see the mechanical finding below).
3. `--match-mode filename`: any finding on a vulnerable file counts, CWE ignored. This rewards
   over-flagging; it is the **detection ceiling**, not a fair score.
4. Scoring: per-category confusion matrix, `TPR = TP/(TP+FN)`, `FPR = FP/(FP+TN)`,
   `J = TPR − FPR`. Reported both flat-aggregate and category-averaged (macro).

## The make-or-break question: does A01 touch Harvey's multi-tenant core? **NO.**

BenchProctor's Broken-Access-Control cases are **generic web-authz (missing / incorrect
function-level authorization), not the ownership / IDOR / tenant-scope shape Harvey's M1 detectors
fire on.** Evidence from the actual case files (JS/Express quicktest):

The access-control categories and their CWEs: `idor`→639, `authzfailure`→862, `authzincorrect`→863,
`privescalation`→269, `missingcritauthn`→306.

Every one models the same abstract shape — untrusted input reaches an authorization **grant**
decision; the vulnerable variant grants a role, the safe twin gates on a session role-check. The
`idor` (CWE-639) vulnerable case `benchmark_test_00115.js`:

```js
async function BenchmarkTest00115(req, res) {
  const userInput = req.body || "";
  const data = userInput != null ? userInput : '';
  const allowedActions = ['read', 'write', 'admin'];
  if (allowedActions.includes(String(data))) { res.json({access: "granted", role: "admin"}); return; }
  res.json({ done: true });
}
```

Its safe twin `benchmark_test_00076.js`:

```js
const { authzCheck } = require("./shared");
async function BenchmarkTest00076(req, res) {
  const userInput = req.headers.authorization || "";
  const data = String(userInput).replace(/\u0000/g, "");
  if (!authzCheck(req.session.user, data)) { res.status(403).json({error: "forbidden"}); return; }
  res.json({ done: true });
}
```

`authzfailure` (CWE-862) `benchmark_test_00012.js` is the same grant-shape from `req.body.field`;
`privescalation` (CWE-269) `benchmark_test_00047.js` the same from `req.headers.authorization`. The
safe twins call the shared helper `authzCheck = (user, resource) => Boolean(user) &&
Array.isArray(user.roles) && user.roles.includes(String(resource))` — a **role-membership** check.

**Decisive:** across all 6,203 files of the JS/Express suite, `grep` for `tenant`, `owner_id`,
`org_id` returns **0 matches**. There is no multi-tenant data model, no per-row ownership, no
`SELECT … WHERE id = req.params.id AND tenant_id = session.tenant` scoping — i.e. none of the
`P-IDOR-PARAM` / `P-BOLA-BODY-OWNER` / Prisma-tenant-scope request→sink shapes that are Harvey's M1
core. BenchProctor "IDOR" is CWE-639 authorization-bypass-through-user-controlled-key at the
function level, an **adjacent generic class**, not Harvey's tenant-isolation core.

This is confirmed by the run: Harvey scores **0.0% TPR on `idor`, `authzfailure`, `authzincorrect`,
`privescalation`, and `missingcritauthn` in BOTH cwe and filename modes** — it does not flag them at
all, in either language.

## Measured Harvey-vs-BenchProctor scores

**Disclosed slice — exactly what was run:** the `quicktest` tier, **JS/Express (6,200 cases)** and
**TS/Express (6,200 cases)** = **12,400 scored cases** across 62 categories each (50/50 vuln/safe).
Harvey's source/mechanical tier via `pnpm quick-scan --dir <testcode> --sarif-out …`
(`runMechanicalScan`: semgrep custom + registry packs, AST detectors, trufflehog, gitleaks,
osv-scanner), scored with the bundled `score_sarif.py`.

**NOT run (disclosed):** the `koa` and `nestjs` framework suites; the `normal` and `enterprise`
tiers (~580k more JS/TS cases); and the other 9 languages. Quicktest is the representative tier —
same 62 categories, same 50/50 balance — so these numbers characterize Harvey-vs-BenchProctor for
JS/TS server code; they are not the whole 2.9M corpus.

| Slice | Mode | TPR | FPR | Youden J |
|---|---|---:|---:|---:|
| JS/Express, all 62 cats (6,200) | cwe (default, fair) | 8.7% | 4.7% | **+4.0%** |
| JS/Express, all 62 cats (6,200) | filename (ceiling) | 25.5% | 15.4% | +10.1% |
| JS/Express, in-scope 28 cats (2,800) | cwe | 15.6% | 10.4% | **+5.1%** |
| JS/Express, in-scope 28 cats (2,800) | filename (ceiling) | 32.0% | 22.7% | +9.3% |
| TS/Express, all 62 cats (6,200) | cwe (default) | — | — | **+3.9%** |
| TS/Express, in-scope 28 cats (2,800) | cwe | 15.2% | 10.4% | **+4.9%** |

(Flat and macro aggregates were identical to one decimal on these balanced slices. "In-scope 28
cats" = the injection / XSS / SSRF / open-redirect / path-traversal / access-control categories that
Harvey's source-detector answer key targets.)

**Per-category J where Harvey discriminated (JS/Express, cwe mode):** xss(79) +42, deserial(502)
+38, cmdi(78) +30, eval_injection(95) +18, codeinj(94) +10, sqli(89) +10, ssti(1336) +4,
redirect(601) +2, pathtraver(22) **−10**. Outside the in-scope slice, tlsverify(295) scored +100 and
hardcodedcreds(798) +4. TS/Express was within ~2 pts of JS on every one.

### Why the number is low — three concrete, measured causes (not a Harvey capability verdict)

Harvey's own app-layer source gate (#945) measures 97.4% recall on request→sink fixtures, and the
M1 calibration gate ~198/201. The low BenchProctor J is a **corpus-fit** result, not a contradiction:

1. **CWE-strict scoring under-credits Harvey structurally.** Harvey's SARIF carries a CWE tag on only
   ~12 distinct rules (16 CWE strings total in the 1,673-result JS export). The CWE-mode winners
   (79, 78, 502, 22, 95, 94, 89, 798, 601, 1336, 295) are *exactly* the categories that scored >0.
   Categories where Harvey clearly fires but tags no CWE — argument_injection(88), genericcmdi(77),
   el_injection(917), basic_xss(80), loginjection(117), corsmisconfig(942) — score 0 in cwe mode and
   only appear in the filename ceiling. A CWE-strict external benchmark measures "does the harvey-*
   rule happen to carry BenchProctor's CWE," not capability.
2. **High FPR on adversarial "broken-safeguard" safe twins.** BenchProctor's safe twin defeats a
   pattern matcher on purpose (flawed regex, wrong-context escape, insufficient limit). Harvey's
   mechanical tier flags many safe twins too: eval_injection 62% FPR, ssti 58%, cmdi 48%, xss 38%.
   That collapses J even where TPR is high (eval_injection 80% TPR → J only +18). Distinguishing an
   *ineffective* safeguard from an effective one is Harvey's paid-LLM triage tier's job, not the
   mechanical tier's — so this corpus scores the wrong tier.
3. **Framework-native / multi-step taint Harvey's request→sink rules don't latch onto.** ssrf(918),
   xxe(611), nosql(943), prototypepollution(1321), ldapi(90), xpathi(643), crlfinjection(93) score
   0% TPR even in filename mode — Harvey has detectors for these classes but its taint rules need a
   recognizable `req.*` source→sink shape the synthetic combinatorial cases don't present in a form
   it matches.

## Recommendation: DON'T-ADOPT (as a wired gate). Record the baseline; do not build `validate-benchproctor`.

1. **It does not exercise Harvey's core.** A01 is generic function-level authz (0% either way, both
   languages); there is no multi-tenant / ownership / tenant-scope content anywhere in the corpus.
   The one thing the spike most needed BenchProctor to cover, it does not (this also confirms #882's
   note that BenchProctor does not fill the multi-tenant gap).
2. **On the generic classes it does touch, the measured J (+4–5%) reflects corpus-fit, not
   capability.** A gate built on it would fire on CWE-tag drift and on broken-safeguard FPR — noise,
   not regressions — and would contradict Harvey's own request→sink recall gate (#945, 97.4%). It
   would be a misleading number to publish next to the others.
3. **It is SYNTHETIC.** Per the issue it complements #945 but does **not** satisfy #960's real-code
   aim. A low synthetic number is worth *recording* (Harvey's mechanical tier is weak at adversarial
   safe-twin discrimination — a real, honest signal), but it is a poor regression *gate*.
4. **The gate scaffolding it would mirror isn't on `main` yet.** `validate-secbench` (#879) and
   `validate-source-recall` (#945) — the two gates this spike was told to mirror — live on unmerged
   branches; their helpers (`recallPct`, the `assert*Resolvable` fail-loud pattern) aren't importable
   from `main`. A `validate-benchproctor` can't cleanly share their shape until they land, which is a
   further reason not to force wiring in this spike.

**No gate was wired.** If a future engagement wants a BenchProctor number, the reproducible harness
is below; it is opt-in and external by nature (it unzips a corpus outside the repo), exactly as
`validate-secbench` stays out of the offline `pnpm verify` path.

### If this is ever revisited — the two follow-ups that would make it meaningful

- **CWE-enrich the `harvey-*` semgrep rules' `metadata.cwe`.** The filename-vs-cwe gap (+10.1% vs
  +4.0% whole-suite) is almost entirely missing CWE tags on rules that already fire. This is
  independently valuable (ticket-routing / compliance mapping, #455) and would roughly double the
  fair score. Cheap, high-leverage, and not BenchProctor-specific.
- **A safeguard-aware precision corpus** (broken-safeguard safe twins) for the paid-LLM triage tier —
  the tier that actually decides "is this safeguard effective." That is where BenchProctor's hard
  cases belong, not the mechanical gate.

## Reproduction (opt-in, external — do NOT add to `pnpm verify`)

```bash
# 1. clone to scratch (never commit — ~2.9M-case corpus, Apache-2.0)
git clone https://github.com/TheAuditorTool/BenchProctor.git   # release 2026.07.22

# 2. extract one JS/TS quicktest bundle
unzip BenchProctor/Benchmarks/quicktest/javascript/benchproctor-javascript-quicktest-2026.07.22.zip -d js-quicktest

# 3. Harvey mechanical tier → SARIF over one framework's testcode
pnpm exec tsx src/cli/quick-scan.ts --dir js-quicktest/express/testcode \
  --sarif-out harvey-js-express.sarif --json --out /dev/null

# 4. score (default cwe mode is the fair score; --match-mode filename is the ceiling)
python3 js-quicktest/score_sarif.py harvey-js-express.sarif \
  js-quicktest/express/expectedresults-2026.07.22.csv
```
