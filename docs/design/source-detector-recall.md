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

This gate scores the **same source detectors** against an **app-layer** answer key — the request→sink
fixtures in `targets/calibration`, where the detectors *do* have a request source — and gets the number
SecBench structurally cannot.

## The measured number

Run: `pnpm exec tsx src/cli/validate-source-recall.ts` (needs the mechanical binaries: semgrep etc.).
Measured **2026-07-24** on this machine against `targets/calibration`:

| Metric | Value |
|---|---|
| Positives caught (any tier) | **38 / 39 — 97.4%** |
| Positives caught at HIGH (free-count) tier | 8 / 39 |
| Negatives cleared (benign request→sink lookalikes) | 31 / 31 |
| Precision / FPR | 100.0% / 0.0% |
| F1 / Youden's J | 98.7% / 0.974 |

The single recall gap is **P-HOST-HEADER-URL** (Host header trusted to build a password-reset URL) —
a class the corpus itself records as having *no mechanical rule* (a paid-LLM-tier catch). It is kept
in the denominator on purpose: excluding known-hard classes to reach 100% would be exactly the kind of
rigging this gate exists to avoid. 38/39 is the honest figure with that gap counted.

This is **measured, never asserted** — the number comes from a live scan, and the gate exits non-zero
only on a credibility regression (a free-count false positive, or a high-tier positive going dark),
never on a recall gap, because a recall gap is the measurement.

## Three numbers, never blended (the #868 caveat)

| Number | Corpus | Engine | Value |
|---|---|---|---|
| **Source-detector recall (this gate)** | app-layer request→sink fixtures | semgrep taint + AST taint detectors | **38/39 (97.4%)** |
| SCA / SecBench (#879) | ~600 real npm CVEs (library-internal) | osv-scanner | 0/600 source; SCA per the #879 gate |
| M1 mixed corpus (`validate-calibration`) | all M1 mechanical classes | all mechanical engines | ~198/201 |

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
  - Two adjacent **source-code** detectors are deliberately OUT because they are not request→sink
    injection/access-control flows: `server-client-leak` (excessive data exposure — a DB row spread
    into a Client Component) and `client-side-authz` (an authz decision made in the wrong tier). They
    are candidates for the corpus-growth remainder, not this number.

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
drift* baseline with finding counts, not a scored source-recall answer key. Extending source-detector
recall scoring onto real request→sink vulnerabilities (and folding in the two adjacent detectors noted
above) is tracked as the corpus-growth remainder of #945.
