# M6 — first real-target verdict (#283)

The first execution of M6 (Simplification / maintainability) against a **real** engagement target,
not the calibration fixtures. It is the reviewed judgment #351 requires to clear M6 from the
never-executed ledger: `simplify-scan` assembles a packet, but the packet is an *input*, not a
verdict — a reviewer must read it and name replacements. This document is that reviewer pass.

## What ran

| | |
|---|---|
| Target | `stoimera/Cravab` (`git clone --depth 1`, a real AI-generated Supabase/Next.js SaaS; the #543 corpus repo with the richest hand-rolled-primitive signal) |
| Packet | `pnpm simplify-scan <target>` → 357 source files + the `briefs/quality-extras.txt` M6 rubric + the target's `package.json` dependency manifest |
| Reviewer pass | manual review of the packet, grounded by targeted searches over the cloned source |
| Recorded as | `pnpm record-pass --module M6 --pass verdict …` → `M6.pass.json` (6 findings), then `run-audit <target> --llm --artifacts-dir <dir> --record` derived M6 `ran` from the fresh verdict artifact and banked it into `audit-execution-log.json` |

The packet was **not thin** — Cravab carries a large amount of hand-rolled infrastructure, and the
dependency manifest showed that several standard libraries are already installed (so the
"already in the dependency tree" class applies with evidence, not from memory).

## The verdict — six findings

Severity is Info (maintainability); the paid tier names a concrete replacement per the locked M6
free/paid split. Findings 1–4 are high-confidence; 5–6 are lower-confidence and flagged as such.

1. **Two parallel in-memory `RateLimiter` implementations** — `src/lib/rate-limiting.ts` (353 LOC)
   and `src/lib/security/rate-limiter.ts` (163 LOC). Both are `RateLimiter` singletons over a
   `Map<string,{count,resetTime}>` fixed-window store with the same reset logic and the same
   api/auth/webhook tiers. *Replacement:* converge on one module (no rate-limit lib is in the tree,
   so this is de-duplication, not a swap); adopt `rate-limiter-flexible` / `@upstash/ratelimit`
   only if durable cross-instance limiting is later wanted.

2. **Nine hand-rolled TTL cache managers (~2,100 LOC) while `@tanstack/react-query` is installed** —
   `src/lib/cache/*.ts` (AppCache, AppointmentCache, CacheHealthMonitor, CacheInitializationService,
   CacheInvalidationService, SimplifiedCacheManager, WebhookCacheManager), `src/lib/performance/cache-manager.ts`,
   `src/lib/offline-cache.ts`. Each reimplements a `Map + timestamp + ttl` store with its own cleanup
   interval; AppCache.ts even comments "Aligned with other cache layers". `@tanstack/react-query`
   (+ devtools) is in `package.json` and wired via `QueryProvider`/`lib/query`. *Replacement:*
   client-side server-state caches → react-query (already installed); the genuinely server-side ones
   (AppCache's webhook/tenant context inside API routes, where react-query does not apply) → one
   small TTL cache (`lru-cache` or Next's `unstable_cache`/`use cache`) — not seven bespoke classes.

3. **Three overlapping error-handling modules** — `src/lib/error-handling.ts` (`CRAVABError`),
   `src/lib/error-handler.ts` (`AppError`), `src/lib/errors/standard-errors.ts` (`ApiError`). Three
   Error base classes; `logError` defined in all three; `formatErrorResponse`, `asyncHandler`, and
   `createRateLimitError` each defined twice. *Replacement:* converge on one module + one base class
   (keep the typed `CRAVABError` hierarchy; fold in `standard-errors.ts`'s `ERROR_CODES`/`HTTP_STATUS`).

4. **Unique-ID generation done three ways** — the `uuid` package (v4), native `crypto.randomUUID()`,
   and a hand-rolled `Date.now()_Math.random().toString(36)` chain (JarvisChatbot, DocumentUpload,
   offline-queue, performance-monitoring, PWAStorage). *Replacement:* standardise on native
   `crypto.randomUUID()` (already used, no dep, collision-safe); the `uuid` dependency can then drop.

5. **Hand-rolled email/phone/UUID validators alongside an installed `zod`** (confidence: Review) —
   `src/lib/error-handling.ts:429-443` regex-validates email/phone/UUID; the book route inline-validates
   phone. `zod ^3.23.8` + `@hookform/resolvers` are installed and zod is used in ~7 files.
   *Replacement:* route the validators through zod (`z.string().email()`/`.uuid()`, a shared phone
   schema). *Note:* phone `.replace(/\D/g,'')` normalisation is legitimately kept — the finding is the
   validators specifically.

6. **Hand-rolled retry/backoff loop in the API client** (confidence: Review — deliberately low per the
   rubric's retry/backoff caveat) — `src/lib/api-client.ts:71-139` runs a manual attempt loop with
   linear backoff. A centralised client is a reasonable shape; react-query (installed) already provides
   retry for query paths. *Recommendation:* optional — lean on react-query's `retry` for calls that go
   through it, so backoff policy lives in one place; keep the loop for non-query calls as a deliberate choice.

## False positives deliberately NOT flagged (rigor)

- `src/lib/utils.ts` `cn()` — correct `twMerge(clsx(...))`, the idiomatic shape (both deps installed).
- `formatDate`/`formatTime`/`formatDateTime` via `Intl.DateTimeFormat` — a legitimate native choice,
  not a reinvention of date-fns.
- `formatPhoneNumber` — no phone-formatting library is in the tree, so hand-rolled is appropriate.
- `src/lib/crypto.ts` and `src/lib/security/encryption*.ts` — hand-rolled crypto is M1's domain, not M6's.

## Provenance

Findings artifact: `M6.pass.json` (`pass: "verdict"`, 6 report-schema findings). Execution banked in
`audit-execution-log.json` (module M6, target `/private/tmp/cravab-m6`). The cloned target lived under
`/private/tmp` and was deleted after the run; re-clone `stoimera/Cravab` to reproduce.
