# Test targets — public repos to dry-run the audit against (#1502)

> **Authorized-testing guardrail.** Static review of public code is fine. **Dynamic (M2) testing runs ONLY
> against your own self-hosted clone** (your Supabase project, seeded data) — never a maintainer's live
> deployment or a live anon-key endpoint without written authorization. Clone → self-host → audit your instance.

> **How to read the numbers.** Every count below was MEASURED on **2026-07-23** by pulling each repo's git
> tree via the GitHub API and counting paths — not transcribed from a README or a prior session. They are a
> snapshot of *audit surface*, not a quality judgement, and **no repo here has been audited** unless a row
> says so. Star counts are deliberately absent: they predicted nothing useful in the 2026-06 pass, and the
> targets that best exercise the modules are mostly unstarred. Re-measure before quoting.

> **Licence gates what you can DO with a target.** `NONE` / `NOASSERTION` means all-rights-reserved by
> default: clone-and-scan locally is fine, **vendoring source into this repo is not** — the same constraint
> that forced `src/scan/external-corpus.ts` into a pinned-manifest design rather than vendored fixtures.
> Public teardowns need a permissive licence AND responsible disclosure first.

## Bucket A — Supabase, M2-capable (ranked by migration count)

Migration count is the self-hostability signal: it is what `pnpm dynamic-validate <t> --execute` applies to
stand the local stack up. Edge-function count is extra M1 service-role surface.

| Repo | What it is | Licence | Migrations | Edge fns | Tests | TS files |
|---|---|---|---|---|---|---|
| `crbnos/carbon` | Manufacturing ERP / MES / QMS | NOASSERTION | **859** | 39 | 77 | 4,110 |
| `dimthink/PriceAI` | AI-subscription price comparison | NOASSERTION | 144 | 0 | **0** | 360 |
| `srizzon/git-city` | 3D GitHub-profile visualiser | AGPL-3.0 | 115 | 0 | **0** | 647 |
| `liam-hq/liam` | ER-diagram generator | Apache-2.0 | 91 | 0 | 148 | 1,470 |
| `gridaco/grida` | Open canvas / form builder | Apache-2.0 | 79 | 0 | 594 | 3,496 |
| `supabase/supabase` | The platform itself | Apache-2.0 | 73 | 58 | 549 | 7,326 |
| `ArnasDon/wacrm` | Self-hostable WhatsApp CRM | MIT | 36 | 0 | 66 | 359 |
| `marmelab/atomic-crm` | CRM (React + shadcn + Supabase) | MIT | 23 | 6 | 26 | 410 |
| `onlook-dev/onlook` | AI-first design tool | Apache-2.0 | 20 | 0 | 57 | 1,290 |
| `paperclip-cms/supabase-cms-kit` | CMS API + UI layer | NONE | 13 | 0 | 0 | 111 |
| `firecrawl/open-scouts` | AI web-monitoring platform | NONE | 9 | 2 | 0 | 546 |
| `akdeb/ElatoAI` | ESP32 realtime voice AI | NOASSERTION | 4 | 0 | 0 | 177 |

- **`crbnos/carbon` is the largest public Supabase RLS/policy surface found — and is now PINNED in the
  external corpus** (#897, baselined 2026-07-24, `pnpm corpus-drift --target carbon --install` green).
  859 migrations and 39 edge functions is an order of magnitude past anything else in the corpus, and an
  ERP's employee/supplier/customer tables are real M10 PII. Unlicensed → scan locally, do not vendor, do
  not publish. **Scale result: nothing timed out and nothing degraded quadratically** — M10 classified
  4.95 MB of DDL in 0.1 s; the whole free tier ran in 76 s. What DID fail is written up in
  `docs/design/carbon-scale-measurement.md`: 8,027 counted findings from one target, a cry-wolf
  free-tier **F (0/100)** driven entirely by placeholder credentials in self-hosting docs, and an M10
  severity model that topped out at Medium on an HR/supplier schema. **Two of those three are since
  fixed and re-measured 2026-07-24:** #934 + #996 took the grade from F (0/100) to **A (97/100)** with
  all 27 findings still reported, and #936's camelCase tokenization raised M10 from 154 tables /
  Medium ceiling to **214 tables / High ceiling** (60 PII tables had been silently classified NONE).
  The finding-volume problem stands and got larger. Re-check with `pnpm corpus-drift --target carbon`.
- **`marmelab/atomic-crm` is the best next `dynamic-validate --execute` target.** 23 migrations + 6 edge
  functions is enough to be a real M2 test, 834 files is small enough to audit end-to-end in one pass, and
  MIT means a writeup is publishable after disclosure. `ArnasDon/wacrm` is the same shape one size up.

## Bucket B — Prisma / Postgres path (epic #756, ranked by test count)

The Prisma app-layer tier shipped 2026-07-23; the external corpus predates it, so these are the targets that
exercise `detectOrm` routing, the Prisma tenant-scope/BOLA detector (#760), M7 FK-index (#761) and M10
`schema.prisma` classification (#758) against real code.

| Repo | What it is | Licence | Tests | SQL migrations | Files |
|---|---|---|---|---|---|
| `elie222/inbox-zero` | AI email assistant | NOASSERTION | **586** | 223 | 3,899 |
| `calcom/cal.diy` | Scheduling infrastructure | MIT | 424 | 596 | 10,269 |
| `hexclave/hexclave` | User-infrastructure platform | NOASSERTION | 272 | 193 | 4,224 |
| `amplication/amplication` | Backend code generator | NOASSERTION | 198 | 160 | 5,348 |
| `documenso/documenso` | DocuSign alternative | AGPL-3.0 | 128 | 163 | 3,395 |
| `dubinc/dub` | Link-attribution platform | NOASSERTION | 91 | 0 | 5,494 |
| `lukevella/rallly` | Scheduling / polls | AGPL-3.0 | 51 | 137 | 1,921 |
| `ghostfolio/ghostfolio` | Wealth-management software | AGPL-3.0 | 31 | 112 | 2,021 |

- **Four of these are now PINNED in the external corpus** (#894, baselined 2026-07-24, each green under
  `pnpm corpus-drift --target <slug> --install`): `ghostfolio`, `rallly`, `inbox-zero`, `documenso`.
  Before that the Prisma app-layer tier had no real-code regression baseline at all.
- **`ghostfolio` is the M10 pick** — account balances, holdings and transactions in the schema is the
  PII/PCI classification path with real stakes, not a synthetic `users` table. **Measured:** 9 PII-bearing
  models via #758's Prisma classifier, plus the first real-code baseline for #761's unindexed-FK check
  (5 findings).
- **`inbox-zero` is the M8 pick** — 586 test files is the deepest public mutation-testing surface on the
  Prisma side; the current corpus's largest real suite is boxyhq's 8. **Measured:** 305 M8-intent
  findings (100× the corpus's previous maximum) and 40 M9 findings — re-measured 2026-07-24 after
  #964's SSR precision fix dropped 12 FPs from the original 52 — the largest App Router boundary
  surface pinned. The *mutation* tier is still not scoreable on it — `npm install` on a pnpm workspace
  resolves only root packages, so `corpus-m8.yml` has no runner to drive; recorded not-run with that
  reason.
- `calcom/cal.com` **was renamed to `calcom/cal.diy`** — fix the URL anywhere it is still stored.

## Bucket C — Calibration and ground truth

- **`elamilutinovic-vibePep/supabase-security-labs`** (licence NONE, updated 2026-03) — **the only
  Supabase-native paired ground truth that exists.** Two labs, each shaped like a corpus entry:
  `rls-broken-lab/` ships `__lab_schema.sql` → `__lab_broken_rls_and_storage.sql` →
  `__lab_fixes_rls_and_storage.sql` with `posts_list_leaky/` and `posts_list_fixed/` Edge Functions side by
  side and `01_seed.sh` / `02_repro_leak.sh` / `03_verify_fix.sh`; `edge-service-role-lab/` does the same for
  a service-role bypass over a families/memberships/photos multi-tenant schema. The **fixed variants are
  built-in FP traps**. Unstarred, so the labelling is unverified until diffed — and unlicensed, so it must be
  a pinned-clone manifest target, never vendored.
  > **This corrects the 2026-06-27 entry that read "No DVWA-style intentionally-vulnerable Supabase repo
  > exists (confirmed)."** That was true when written. It is no longer true. (CLAUDE.md: a recorded reason is
  > a claim about the world, and claims decay.)
  >
  > **PINNED and VERIFIED 2026-07-24 (#895)** — labelling diffed and then reproduced live in both states
  > with `pnpm dynamic-validate --execute`. Full record: `docs/design/supabase-security-labs-paired-validation.md`.
  > Headline: **M2 discriminates the pair correctly** (3 cross-tenant `families` Highs on the broken
  > variant, gone on the fixed one, none introduced) while the **M1 static tier produces byte-identical
  > output on both** — the planted `USING (true)` class is disclosed-not-detected, and the static reviewer
  > does not track `drop policy`, so the fix is invisible to it. The lab's own "fixed" variant still leaks
  > `public.profiles` to `anon`, an unlabelled bug in the target's ground truth. The fixed variant cannot
  > yet serve as an M1 precision NEGATIVE (it is not distinguishable at that tier, and the licence forbids
  > distilling it into a `*.entries.ts`).
- **`juice-shop/juice-shop`** (MIT) — `data/static/challenges.yml` plus `data/static/codefixes/` with
  `*_correct.ts` and numbered incorrect variants per challenge: a labelled vulnerable/fixed TypeScript
  snippet corpus. Express/Angular, so it scores generic detectors only, not M1's Supabase-specific tier.
- **False-positive traps — correct implementations that must stay quiet.** These libraries exist to do tenant
  scoping right; an M1 tenant-scope finding on them is a precision bug, which makes them negatives for
  `pnpm exec tsx src/cli/validate-precision.ts` (#823):
  `zenstackhq/zenstack` (MIT, Prisma access-control layer, 365 tests) ·
  `s1owjke/prisma-rls` (MIT, Prisma RLS client extension, 39 files — cheapest to run) ·
  `Errorname/prisma-multi-tenant` (MIT, stale since 2023, shape still valid).
- **Harvey-owned fixtures remain the primary ground truth**: `targets/calibration` (planted bugs),
  `targets/vuln-seam-app` (#718, M2 seam + rate-limit proven branches), `targets/prisma-xtenant-app` (#796).
- **External benchmark suites, checked 2026-07-23:** `kolega-ai/Real-Vuln-Benchmark` is **Python only**
  today (JS/TS on the roadmap) — not a target, but its harness design is worth copying: JSON ground truth
  with file + line range + primary CWE + `acceptable_cwes`, explicit `is_vulnerable: false` FP traps,
  ±10-line match tolerance, F2 scoring. SastBench (2,737 samples, 299 TP / 2,438 FP, 38 languages incl.
  JS/TS, CVE cutoff after Feb-2025 to block memorisation) is paper-side; the public `sargemonkey/SASTBench`
  repo is Python tooling only. SecBench.js is tracked separately as #879; OWASP crAPI / VAmPI as #880.
- **Legacy vulnerable Node apps**, all confirmed live but all pre-App-Router Express — partial fit at best:
  `appsecco/dvna`, `OWASP/NodeGoat` (stale since 2024), `cr0hn/vulnerable-node`, `snoopysecurity/dvws-node`,
  `dolevf/Damn-Vulnerable-GraphQL-Application`. `lirantal/vulnerable-nextjs-14-CVE-2025-29927` is a precise
  single-CVE reproduction (Next.js middleware auth bypass) — a regression fixture, not a corpus.

## Bucket D — Zero-test targets (the M8 zero-coverage path)

Measured, not assumed. A large schema with no tests at all is a realistic client, and #224 exists for exactly
this case — M8 must emit a zero-coverage finding, never skip:

`dimthink/PriceAI` (144 migrations, **0 tests**) · `srizzon/git-city` (115 migrations, **0 tests**) ·
`firecrawl/open-scouts` (0 tests) · `paperclip-cms/supabase-cms-kit` (0 tests) · `akdeb/ElatoAI` (0 tests).

Every small Supabase starter kit surveyed had zero unit tests. That is a property of the population, not of
the sample.

## Bucket E — The original 2026-06 shortlist (status as of 2026-07-23)

Six of these are now the pinned external regression corpus in `src/scan/external-corpus.ts`, scored by
`pnpm corpus-drift`: `JakeLeoDev/proposit`, `vercel/nextjs-subscription-payments`, `boxyhq/saas-starter-kit`,
`Wallens11/supabase-multi-tenant-starter`, `devtodollars/mvp-boilerplate`,
`makerkit/nextjs-saas-starter-kit-lite`. `Wallens11` was disclosed under #217 (1 Critical, 1 High).

Still unaudited from that list: `ShenSeanChen/launch-mvp-stripe-nextjs-supabase` — but it ships **0
migrations in-tree**, so an M2 stand-up needs a hand-built schema; Bucket A is the better dynamic-tier queue.
`antoineross/Hikari` (MIT, Next 14 App Router + Stripe + Supabase, 2 migrations) is the strongest remaining
untouched starter kit.

## Where NOT to look

**GitLab.** Queried the public projects API directly on 2026-07-23 for `supabase+saas`, `multi-tenant+saas`
and `nextjs+saas`: **zero projects with ≥2 stars** in any of the three. The stack does not live there. Not
worth re-crawling.

## Caveats that keep costing us

- Starter kits often ship a permissive policy **intentionally** "for the demo." Confirm intent before calling
  it a vuln — especially on a vendor-official repo.
- Unstarred and AI-generated repos are the highest-yield calibration (research put ≥1 security flaw in ~98%
  of vibe-coded apps) and the lowest-yield marketing. Use them to prove the scanner fires, not to prove a point.

## Tooling spotted (for M2, not targets)

- **SupaSec** — offensive RLS tester with a "Safe Exploit Mode": sends a malicious PATCH/DELETE with the
  `Prefer: tx=rollback,return=representation` header → the API evaluates RLS, returns the result, then rolls
  back in ms (zero production impact). Genuinely useful primitive for the M2 probe kit.
- `hand-dot/supabase-rls-checker` — defensive RLS presence checker (reference, not a target).

## Sources
- Measured 2026-07-23 via `gh api repos/<r>/git/trees/HEAD?recursive=1` over 253 candidate repos gathered
  from GitHub topic sweeps (`supabase`, `nextjs`, `prisma`, `row-level-security`, `multi-tenant`) plus
  non-SaaS app-category searches (CRM, CMS, ecommerce, chat, dashboard, LMS, booking, inventory).
- https://github.com/kolega-ai/Real-Vuln-Benchmark · https://arxiv.org/pdf/2601.02941 (SastBench)
- https://vibeappscanner.com/supabase-security · https://vibeappscanner.com/supabase-row-level-security
- https://www.precursorsecurity.com/blog/row-level-recklessness-testing-supabase-security
- https://medium.com/@jorge.jarne/how-to-harden-your-lovable-supabase-setup-a-guide-to-row-level-security-cf290a61c0cf
- https://github.com/hand-dot/supabase-rls-checker
