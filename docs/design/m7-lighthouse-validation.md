# M7 Lighthouse tier — first live end-to-end validation (#488)

The M7 [L] tier (`src/lighthouse.ts` + `src/cli/lighthouse-scan.ts`, built in #387) was only
unit-tested against a fixture LHR until this run. #488 asked for a real build → serve → Chrome →
Lighthouse pass against a live target, with the LHR shape/units confirmed and any drift fixed.

## What was run (2026-07-18)

- **Target:** `vandyand/saas-security-teardown` (Next.js 16.2.10 / Turbopack, React 19, Supabase
  SSR) — cloned to `/private/tmp`, torn down after.
- **Backend:** none needed. The marketing (`/`), `/login`, and `/security` pages are static /
  client-rendered; the authenticated pages redirect anonymous requests to `/login` (HTTP 200).
  Lighthouse audits an anonymous session, so no local Supabase stack was required — a `.env.local`
  with placeholder `NEXT_PUBLIC_SUPABASE_*` values was enough for the client modules to construct
  without throwing. `next build` + `next start` served it.
- **Command:** `pnpm lighthouse-scan /private/tmp/saas-security-teardown --route / --route /login
  --route /security --route /dashboard --port 3111 --out …`
- **Browser:** system **Google Chrome** (see the bug below — this was the fix).

## Result — real measured findings

After the fixes below, the pipeline ran end-to-end and emitted a genuine measured finding:

```
M7L-01  "2 pages with LCP above Google's \"Good\" 2.5s (worst: 3.1s)"  severity Low
        evidence: Lighthouse lab LCP, worst-first: /security (3.1s), /dashboard (2.6s)
```

LCP was measured under Lighthouse's default simulated mobile throttling. `/security` 3.1s and
`/dashboard` 2.6s both sit between the "Good" (2.5s) and "Poor" (4.0s) boundaries → `Low`, exactly
as the threshold logic intends. `/` and `/login` were within "Good" and correctly produced no
finding. Performance scores on the passing pages were 0.98–0.99. This confirms the LHR shape and
units the transform assumes are correct on a real Lighthouse 13.4.0 run: `categories.performance
.score` is a 0–1 number, and `largest-contentful-paint` / `total-blocking-time` /
`cumulative-layout-shift` carry `numericValue` in ms / ms / unitless respectively.

## Two real bugs found and fixed (first live run)

### 1. Silent false-clean — an unmeasured run read as a clean bill of health (critical)

The first live run reported **"4 pages audited → 0 findings"** — which looked like a fast, healthy
app. It was not. A raw-LHR probe showed every page had `categories.performance.score === null` and
a `runtimeError` of **`NO_FCP`** ("The page did not paint any content"). Lighthouse had measured
*nothing*, yet `parseLighthouseFindings` filters metrics on `typeof value === "number"` and score
on `typeof score === "number"`, so an all-`null` (errored) result silently yields zero findings —
indistinguishable from a genuinely clean pass. This is precisely the failure the coverage doctrine
forbids: an unassessed thing reading as a clean result.

**Fix:** `lighthouseRunErrorReason(result)` (new, in `src/lighthouse.ts`, unit-tested) returns a
human reason when a page result carries a `runtimeError` or has no numeric performance score.
`auditRoute` (CLI) throws with that reason, and the existing catch turns it into the fail-loud
**M7L-00** disclosure ("Core Web Vitals not measured … NO_FCP …"). Verified: forcing the broken
browser now emits M7L-00 with the NO_FCP reason instead of a silent "0 findings".

### 2. The default browser (Playwright "Chrome for Testing") fails Lighthouse with NO_FCP

Root cause of the NO_FCP above: the CLI defaulted to the Playwright chromium the repo installs for
`report-template` (via `chromium.executablePath()` when `LIGHTHOUSE_CHROME_PATH` is unset). That
build — "Google Chrome for Testing" — yields `NO_FCP` under Lighthouse **regardless of `--headless`
vs `--headless=new`**. A system Google Chrome, which `chrome-launcher` auto-detects, works fine
(score 0.98–0.99, LCP ~2.1s). Because every Harvey machine installs the Playwright chromium
(report-template), the *documented default path was non-functional* for Lighthouse.

Measured matrix (target `/`, served locally):

| Browser | flags | result |
|---|---|---|
| Playwright "Chrome for Testing" | `--headless=new` | **NO_FCP**, score null |
| Playwright "Chrome for Testing" | `--headless` (old) | **NO_FCP**, score null |
| system Google Chrome | `--headless=new` | OK, score 0.98, LCP 2137ms |
| system Google Chrome | `--headless` (old) | OK, score 0.99, LCP 2058ms |

**Fix:** `launchChrome()` (CLI) now **prefers a system Chrome** (`chrome-launcher` auto-detect) and
only falls back to the Playwright chromium when no system Chrome exists, warning that the fallback
may NO_FCP. `LIGHTHOUSE_CHROME_PATH` still overrides both. Combined with fix #1, a machine that has
*only* the Playwright build still fails loud (M7L-00 disclosure) rather than silently clean.

## Limitations / carry-forward

- **Playwright-only machines still can't measure CWV.** The fallback browser NO_FCPs; such a run now
  discloses (M7L-00) rather than lying, but produces no scores. If Harvey wants Lighthouse to work
  without a system Chrome, it needs a Lighthouse-compatible headless Chrome provisioned (e.g. the
  `chrome-launcher`-bundled path or a real Chrome install), not the Playwright "for Testing" build.
  Follow-up filed.
- **Orchestrator gap unchanged.** `run-audit`'s M7 probe still never invokes the Lighthouse tier;
  the CWV pass remains an operator-run CLI whose `Finding[]` merges into the engagement findings
  (as designed in #387). Wiring it (or its pass-artifact) into `run-audit` is a separate follow-up
  noted in `docs/design/portability-cold-target.md`.
- A bad `LIGHTHOUSE_CHROME_PATH` (non-existent binary) makes `chrome-launcher` emit an unhandled
  `error` event that escapes `main`'s catch and exits 1 with an `ENOENT` stack — loud (not a false
  clean), but not routed through the M7L-00 disclosure. Low priority; noted.
