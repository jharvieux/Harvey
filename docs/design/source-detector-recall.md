# App-layer source-detector recall (#945)

The free tier's **source-detector recall** — how many application-code vulnerabilities with a genuine
untrusted-input → dangerous-sink flow the mechanical tier catches — had no scored number. This gate
produces one, and reports it **distinctly** from the two numbers it is easy to confuse it with.

## Why the SecBench number is not this number

The SecBench.js gate (#879) measured Harvey's source rules at **0/600**. That is a *corpus mismatch*,
not a capability figure, and it was re-verified on 2026-07-24 before this gate was built:

- SecBench's vulnerability lives **inside a library** (the sink is in `node_modules`, which Harvey does
  not scan) and its exploit is a **jest test with no HTTP request source**. Harvey's source rules follow
  `request → sink` taint, so on a corpus with no request layer they have nothing to latch onto. SecBench
  is the right yardstick for the **SCA** engine (the #879 gate reports that figure), scored via `osv-scanner` over the
  pinned vulnerable dependency — not for source detection. See `secbench-recall-measurement.md`.

<!--
REASON: SecBench is scored as Harvey's SCA yardstick, not its source-detection yardstick — a product-scope ruling about which corpus measures which engine, not a claim that library-internal sinks are unreachable in principle
KIND: decisional
PROVENANCE: MEASURED 2026-07-24 (the #946 ruling, recorded here and in secbench-recall-measurement.md)
OWNER: operator
DECISION: #946; docs/design/secbench-recall-measurement.md
-->

This gate scores the **same source detectors** against an **app-layer** answer key — the request→sink
fixtures in `targets/calibration`, where the detectors *do* have a request source — and gets the number
SecBench structurally cannot.

## The measured number

Run: `pnpm exec tsx src/cli/validate-source-recall.ts` (needs the mechanical binaries: semgrep etc.).
Re-measured **2026-07-31** on this machine against `targets/calibration`:

| Metric | Value |
|---|---|
| Positives caught (any tier) | **39 / 39 — 100.0%** |
| Positives caught at HIGH (free-count) tier | 8 / 39 |
| Negatives cleared (benign request→sink lookalikes) | 31 / 31 |
| Precision / FPR | 100.0% / 0.0% |
| F1 / Youden's J | 100.0% / 1.000 |

MEASURED 2026-07-31 (`pnpm exec tsx src/cli/validate-source-recall.ts`). The figures above read
**38 / 39 — 97.4%** until that day, and the single gap was **P-HOST-HEADER-URL** (Host header
trusted to build a password-reset URL), recorded here and in the corpus as *no mechanical rule — a
paid-LLM-tier catch*. #1366 re-tested that reason and it was false: the header read and the URL
authority sit in the same expression in the same file, so no cross-function taint is involved.
`leftover-auth`'s `host-header-url` check now catches it at review tier and the corpus row carries
`mustCatch`, so a regression is a GATE FAIL rather than a tracked gap.

The gap was kept in the denominator on purpose while it was open — excluding known-hard classes to
reach 100% would be exactly the kind of rigging this gate exists to avoid — and it was closed by
building the rule, not by moving the row.

This is **measured, never asserted** — the number comes from a live scan, and the gate exits non-zero
only on a credibility regression (a free-count false positive, or a high-tier positive going dark),
never on a recall gap, because a recall gap is the measurement.

## Three numbers, never blended (the #868 caveat)

| Number | Corpus | Engine | Value |
|---|---|---|---|
| **Source-detector recall (this gate)** | app-layer request→sink fixtures | semgrep taint + AST taint detectors | **39/39 (100.0%, MEASURED 2026-07-31)** |
| SCA / SecBench (#879) | ~600 real npm CVEs (library-internal) | osv-scanner | 0/600 source; SCA per the #879 gate |
| M1 mixed corpus (`validate-calibration`) | all M1 mechanical classes | all mechanical engines | **354/354 (100.0%, MEASURED 2026-07-31)** |

The M1 mixed number blends the source detectors with the SCA, secret, security-header, crypto-primitive,
`next.config`, and RLS-config/schema tiers — a different answer key measuring a different thing. No
single figure may stand in for the source-detector number; that blend is the caveat #868 must avoid.

## The answer key — what counts as a "source detector"

The answer key is an explicit ID list in `src/scan/source-recall.ts` (`SOURCE_TIER_IDS`), kept next to
this rationale so the in/out call on each class is reviewable in one place. The rule:

- **IN** — a detector that traces an untrusted **input value** to a dangerous **sink** (a taint /
  data-flow detector):
  - Injection & code-execution: SQLi, command injection, code injection (`eval`), PostgREST-filter
    injection, prototype pollution, unsafe deserialization, XXE, path traversal, zip-slip, SSTI, ReDoS,
    log forging.
  - XSS & client-side sinks: DOM `innerHTML` / `document.write`, stored / prop / reflected
    `dangerouslySetInnerHTML`, `javascript:`-URL `href` / `setAttribute`, open-URL sink.
  - SSRF; open redirect.
  - Request→sink **access control**: IDOR / BOLA by a request-supplied id, mass-assignment of the
    request body, reflected-`Origin` CORS-with-credentials, client-trusted privilege flag,
    client-supplied payment amount, Host-header URL poisoning.
- **OUT** — flags the *absence of a control* or a static config/dependency/secret fact:
  - Absence-of-control heuristics: route-noauth, missing role check, no rate limiter, hardcoded
    bypass, missing `server-only`, public bucket, unsigned webhook, missing upload limit, unguarded
    `draftMode`, middleware-matcher gaps, client-render-only authz.
  - The SCA/dependency tier; secrets-in-files; TLS/security-header hardening; crypto-primitive choice;
    `next.config` flags; and the DB-layer RLS/Supabase-config/schema classes.
  - Two adjacent **source-code** detectors are deliberately OUT of THIS taint-only answer key because
    they are not request→sink injection/access-control flows: `server-client-leak` (excessive data
    exposure — a DB row spread into a Client Component) and `client-side-authz` (an authz decision made
    in the wrong tier). They are not left unscored, though — see "The M9 source-code (non-taint) tier"
    below, which folds both into their own tier (#1011).

### Fail-loud maintenance

`assertSourceTierResolvable()` throws if a listed id is renamed, removed, or gains a `module` tag
(which would drop it out of the mechanical scan) — so drift is a gate failure, never a silent smaller
denominator. `source-recall.test.ts` pins the 39/31 positive/negative split so a change to the answer
key population is a conscious edit. When you add a request→sink taint fixture to any `*.entries.ts`, add
its id to `SOURCE_TIER_IDS` too.

## Where it runs in CI

Like the mixed calibration gate, the **live** binary run (`validate-source-recall.ts`) is operator-run
(it needs semgrep on PATH, exactly as `validate:calibration` does — neither lives in a workflow). The
answer-key integrity and scoring logic are held in CI by `src/scan/source-recall.test.ts` under
`pnpm verify`, the same offline/binary split `calibration.test.ts` uses for the mixed gate.

## Honest scope (a legitimate partial)

The 39-positive answer key is a real, defensible spread across the injection, XSS, SSRF, open-redirect
and access-control (IDOR/BOLA/mass-assignment/CORS/client-trust) request→sink classes — not thin. But
it is scored on the **planted** `targets/calibration` fixtures, not on real-world app code. The
complementary real-code tier (the pinned external corpus in `external-corpus.ts`) is a *quality-module
drift* baseline with finding counts, not a scored source-recall answer key.

## The real-code tier (#960, the corpus-growth remainder)

`src/scan/real-source-recall.ts` + `validate-source-recall.ts --real` extend recall scoring onto REAL,
already-disclosed vulnerabilities in three of the six repos `external-corpus.ts` already pins by commit
(cloned on demand, same "manifest, not vendored fixtures" doctrine that file documents — several of the
six ship no LICENSE, so their source is never copied into this repo, only scanned from a throwaway
clone). Each entry is one of THIS repo's own filed responsible-disclosure issues, not a guess:

| Target | Disclosure | Class | Caught? |
|---|---|---|---|
| proposit (`JakeLeoDev/proposit`) | #214 High | invitation-accept `.insert()` trusts a client-supplied `userId` | **NO** |
| saas-lite (`makerkit/nextjs-saas-starter-kit-lite`) | #219 Low | open redirect, source and sink in different monorepo packages | **NO** |
| subscription-payments (`vercel/nextjs-subscription-payments`) | #215 Medium | checkout re-derives trial length from a client-supplied price object | **NO** |

**MEASURED 2026-07-24: 0/3 (0.0%)** — `pnpm exec tsx src/cli/validate-source-recall.ts --real` (needs
network + the mechanical binaries). This is a genuinely low, honestly-reported number, and each gap has
a named, distinct cause (never blended into one "hard" bucket):

- proposit's BOLA is an `.insert()` whose tainted value arrives as a **Server Action function
  parameter**, not a `.eq()`-filtered read — outside `bola-owner.ts`'s current pattern. (The file also
  draws `harvey-csrf-missing` + `harvey-server-action-noauth`, both absence-of-control classes already
  OUT of the source-tier answer key — a location-only match would have misreported this as "caught"; the
  entry's `match: ["bola", "mass-assign"]` keyword gate is what keeps that honest.)
- saas-lite's open redirect crosses a **monorepo package boundary** (the tainted read and the `redirect()`
  sink are two different `packages/`/`apps/` in the same Turborepo) — beyond same-file/same-function
  taint scope.
- subscription-payments' trial-length trust needs "should this field be re-read server-side?" **business
  context** no AST pattern can distinguish from the benign re-derivation this same code shape usually is
  — already named as an open gap by the planted corpus's own `m9-authz.entries.ts` header.

Like the planted-fixture gate, a recall gap here is **the measurement, not a gate failure** — `--real`
always exits 0 and reports; it does not fail a build. Distinct from every other number on this page:
never blend 0/3 into 39/39, or either into the M1 mixed figure (218/221 as measured 2026-07-24 — a
number that moves with every detector that lands, so re-run `validate-calibration` rather than quoting
it). The real value of this tier is turning
"real code is presumably harder than what we planted" from an assumption into three itemized, re-testable,
named limitations — a punch list for cross-file taint and function-parameter-sourced BOLA, not just a
lower percentage.

## The M9 source-code (non-taint) tier (#1011)

`server-client-leak` and `client-side-authz` (named as OUT above) are now scored too — not left as an
unscored "candidate for the corpus-growth remainder" as an earlier revision of this doc had it. That
earlier revision also claimed *both* detectors live under M9's boundary-model pass and both carry
`module: "M9"` in the calibration corpus — **wrong on re-verification** (a stale reason that had decayed;
see `CLAUDE.md`'s "a recorded reason is a claim about the world" doctrine). Only `server-client-leak` is
module-tagged M9 (`M9C-LEAK-POS`/`-NEG` in `m9-checks.entries.ts`, scored by the M9 AST pass —
`detectAppRouterFindings` — against its own committed `src/detectors/__fixtures__/server-client-leak/`
fixtures, never against `targets/calibration` or `runMechanicalScan`). `client-side-authz` is actually a
**mechanical** `leftover-auth.ts` grep: its corpus entries (`P-CLIENT-AUTHZ-STORAGE`,
`P-CLIENT-AUTHZ-USER`, `N-CLIENT-AUTHZ-SERVER-CHECK` in `b14-applogic.entries.ts`) carry **no** `module`
tag, so they were already inside `mechanicalCorpus()` and already caught by the same
`runMechanicalScan(targets/calibration)` call this gate makes — nothing new needed to run it.

Both stay OUT of `SOURCE_TIER_IDS` itself: neither is a request→sink taint flow (the definition that
answer key exists to score), so blending them in would corrupt that clean number even though
`client-side-authz` happens to share its execution pipeline. Instead, `src/scan/source-recall.ts` adds a
second, parallel answer key — `M9_SOURCE_TIER_IDS` (5 entries: the 2 `server-client-leak` +
3 `client-side-authz`) — resolved against the **whole** corpus (not `mechanicalCorpus()`, since it spans
a module-tagged and a module-less entry, via `assertM9SourceTierResolvable()`), scored via
`scoreM9SourceRecall()`, and reported by `validate-source-recall.ts` as its own
**"M9 SOURCE-CODE (non-taint) recall"** section: distinct rows, distinct positives/negatives, distinct
pass/fail gate, never blended into the 39/39 headline number or the real-code 0/3. `validate-source-recall.ts`
runs `detectAppRouterFindings` itself over the `server-client-leak` fixtures (the same load-and-prefix
approach `calibration.test.ts`'s `#848` block uses) and merges those findings with the mechanical scan's
before scoring, since the two detectors' findings come from two different passes.

**Measured 2026-07-24: 3/3 positives caught, 2/2 negatives cleared (100%/100%)** —
`pnpm exec tsx src/cli/validate-source-recall.ts`. A perfect score here reflects a 5-entry answer key,
not a claim of broad coverage — this tier is exactly as thin as the two detectors' own corpora.
