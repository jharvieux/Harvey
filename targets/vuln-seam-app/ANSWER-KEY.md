# Harvey answer key — `targets/vuln-seam-app`

**Date:** 2026-07-22
**Target:** `targets/vuln-seam-app` — a Harvey-**owned**, in-repo, deliberately-vulnerable Supabase/
Next.js 14 App Router fixture (#718). Unlike the external recall targets (cipherx, vandyand,
SuperRedHat), this one is versioned in-repo and exists for a single purpose: to ship the four
insecure inter-service **seam** surfaces so the M2 seam probes' and the NO-RATE-LIMIT loop's
**proven** (finding-producing) branches can be exercised end-to-end and kept as a regression target.

**This is an ANSWER KEY.** It is the denominator a `pnpm dynamic-validate targets/vuln-seam-app
--execute` run is scored against: **recall** (each vulnerable seam reaches a proven verdict) and
**zero-FP** (each negative control stays not-vulnerable). Every entry cites the exact route source and
the exact probe request from `src/pentest/verify.ts`.

## Why this fixture exists

Every real corpus app Harvey has tested is hardened — every webhook verifies its signature, every
service endpoint is fronted, every high-value flow is throttled — so the seam probes, though wired and
reachability-proven (#161/#714/#716/#719), had never driven their positive branches. Cloning external
vulnerable labs is fragile (they get patched/deleted and none ship these particular seam surfaces —
#717). A small owned fixture is the permanent fix. It unblocks:

- **#717** — the seam probes' proven/applicable branches (`CROSS-SERVICE-WEBHOOK`,
  `DIRECT-SERVICE-CALL`, `SERVICE-JWT-UNVERIFIED`).
- **#159** — the `NO-RATE-LIMIT` loop end-to-end.

## Target shape (predicts what the probes see)

- **Framework:** pure Next.js 14 App Router route handlers, `app/api/**/route.js`. They are discovered
  by `discoverRoutes` (`src/pentest/discovery.ts`) and classified into `profile.seams` by
  `buildTargetProfile`. Verified by running `discoverProfile` over the fixture (see "Classification
  verification" below).
- **Seams present:** exactly the four classes, each with a **vulnerable** route and a **negative
  control** route so both recall and zero-FP are scorable.
- **Tenancy:** a minimal org-tenant schema (`tenants` / `profiles` FK `auth.users` / tenant-scoped
  `documents` with RLS) in `supabase/migrations/0001_schema.sql`. **No RLS bug is planted** — the
  schema exists only so the M2 stand-up's two-tenant seed binds and the Tier-1 PostgREST matrix has a
  surface. The planted vulnerabilities are the seam **routes**, below.

## The answer key — four planted seam vulnerabilities + four negative controls

Each probe iterates its candidate endpoints and returns **proven** on the first that exhibits the bug;
a profile containing only the control endpoint returns **unproven** (the zero-FP check). Verdicts below
were confirmed by invoking each route handler with the probe's exact request (`8 passed, 0 failed` on
2026-07-22 — see "Runtime verification").

### 1. `CROSS-SERVICE-WEBHOOK` (High)

- **Vulnerable — `POST /api/webhooks/stripe`** (`app/api/webhooks/stripe/route.js`). Reads the
  `stripe-signature` header (so `discoverRoutes` classifies it `webhookReceiver`) but **never verifies
  it**, processes the event, and returns a body carrying processing evidence
  (`{received, processed, ledgerId}`). Probe (`replayCrossServiceWebhook`): `POST` with
  `x-signature: harvey-invalid-signature`, body `{event:"HARVEY_PROBE_UNSIGNED"}`. Response is
  `200` + non-trivial body ⇒ `hasNonTrivialBody` true ⇒ **proven**.
- **Negative control — `POST /api/webhooks/stripe-verified`**. HMAC-verifies the signature over the
  raw body and, on failure, returns an **empty `200`** without processing (the boxyhq-dsync shape the
  #713/#716 acceptance-evidence gate was built for). The probe's forged signature fails verification ⇒
  empty 2xx ⇒ no processing evidence ⇒ **unproven**.

### 2. `DIRECT-SERVICE-CALL` (High)

- **Vulnerable — `GET /api/internal/users`** (`app/api/internal/users/route.js`). An `/internal`
  segment route (⇒ classified `internalService`) that answers a direct anon `GET` with a non-empty
  JSON array of user records — no caller-identity check; the `/internal` path is the only "control".
  Probe (`replayDirectServiceCall`): anon `GET`. `200` + non-empty body ⇒ **proven**.
- **Negative control — `GET /api/internal/reports`**. Also `/internal`, but requires the fronting
  app's shared `x-internal-secret` header; a direct anon call lacks it ⇒ `401`, no data ⇒ **unproven**.

### 3. `SERVICE-JWT-UNVERIFIED` (Critical)

- **Vulnerable — `GET /api/ingest/events`** (`app/api/ingest/events/route.js`). Reads
  `Authorization: Bearer` and checks `claims.role === "service"` (⇒ classified `serviceJwt`), but
  **decodes** the JWT payload instead of verifying its signature — so a forged `alg:none` token is
  accepted. Probe (`replayServiceJwtUnverified`): `GET` with `Authorization: Bearer <alg:none token
  claiming role service>` (`FORGED_SERVICE_JWT`). Returns `200` ⇒ **proven**.
- **Negative control — `GET /api/ingest/events-verified`**. Same gate, but **RS256-verifies** the
  signature against an embedded public key (private key deliberately absent from the repo) and rejects
  any `alg` ≠ `RS256`. The forged `alg:none` token fails ⇒ `401` ⇒ **unproven**.

### 4. `NO-RATE-LIMIT` (High)

- **Vulnerable — `POST /api/coupon/redeem`** (`app/api/coupon/redeem/route.js`). A high-value flow
  (`coupon` + `redeem` are both high-value segments ⇒ classified `highValue`) with no throttle and no
  one-time-use check. Probe (`replayNoRateLimit`): the same `POST` (`{code:"HARVEY_PROBE_TOKEN"}`)
  replayed 5×. All 5 accepted (`200`) ⇒ **proven**.
- **Negative control — `POST /api/checkout`**. Also high-value, but a per-process token bucket lets
  the first call through and returns `429` for calls 2–5 ⇒ the probe never sees 5/5 ⇒ **unproven**.

### 5. `MISSING-AUTH-SWEEP` precision pair (#792, the #791 FP class)

Not one of the four seam classes above — this pair regression-gates the discovered-route sweep probe
itself (`replayMissingAuth` / `bodyExposesData`, `src/pentest/verify.ts`) against the exact FP class
#791 shipped live: a public route with a trivial status/greeting body must stay silent, and it must
still fire on a genuinely unauth data-exposing route (so the silence proves the gate works rather than
the probe being broken). Scored independently of the four-seam recall/zero-FP denominator above —
each route is probed alone (`src/pentest/vuln-seam-app.test.ts`), the way the seam controls are.

- **Negative control — `GET /api/status`** (`app/api/status/route.js`). A public status/version
  endpoint returning `{status, version}` — every key is in `bodyExposesData`'s `TRIVIAL_BODY_KEYS`
  set, and the path is deliberately NOT on `PUBLIC_ROUTE_ALLOWLIST`, so the sweep actually probes it
  and the verdict rests on the body-content gate, not the allowlist. Anon `GET` → `200` + trivial
  body ⇒ `bodyExposesData` false ⇒ **unproven**.
- **Positive control — `GET /api/profile`** (`app/api/profile/route.js`). Returns real tenant/user
  data (`email`, `tenant_id`, `role`) with no caller-identity check. Anon `GET` → `200` + a body
  carrying non-trivial keys ⇒ `bodyExposesData` true ⇒ **proven**.

## Scoring

| Probe | Vulnerable route | Expected | Control route | Expected |
|-------|------------------|----------|---------------|----------|
| `CROSS-SERVICE-WEBHOOK` | `POST /api/webhooks/stripe` | **proven** | `POST /api/webhooks/stripe-verified` | not-vulnerable |
| `DIRECT-SERVICE-CALL` | `GET /api/internal/users` | **proven** | `GET /api/internal/reports` | not-vulnerable |
| `SERVICE-JWT-UNVERIFIED` | `GET /api/ingest/events` | **proven** | `GET /api/ingest/events-verified` | not-vulnerable |
| `NO-RATE-LIMIT` | `POST /api/coupon/redeem` | **proven** | `POST /api/checkout` | not-vulnerable |

**Recall denominator = 4** (one proven per class). **Zero-FP denominator = 4** (one not-vulnerable per
control). A live `dynamic-validate --execute` run is scored: 4/4 proven and 0 controls flagged.

**Scoring note on control isolation.** Each seam probe short-circuits on the first proven endpoint, so
in a single run against the whole fixture the vulnerable route is what produces the verdict; the
control is not independently re-reported. To score a control as not-vulnerable in isolation, run the
probe against a profile containing only the control endpoint (the classification/runtime harness below
does exactly this per-route). The controls also guard **classification-level** FPs — e.g. an outbound
fetcher must not be classified a webhook — which `discoverProfile` over the fixture confirms.

## Classification verification (2026-07-22, offline, no Docker)

`discoverProfile(['app/api'], [], 'http://127.0.0.1:3000')` over the fixture yields exactly:

- `seams.webhookEndpoints` → `/api/webhooks/stripe`, `/api/webhooks/stripe-verified`
- `seams.serviceEndpoints` → `/api/internal/reports`, `/api/internal/users`
- `seams.serviceJwtEndpoints` → `/api/ingest/events`, `/api/ingest/events-verified`
- `highValue` → `/api/checkout`, `/api/coupon/redeem`

No route is cross-classified (the RS256 control uses `crypto.verify`, not `createHmac`, so it does not
trip the webhook-verify heuristic; the service-JWT routes sit off the `/internal|/service` segments so
they are not also `internalService`).

## Runtime verification (2026-07-22, offline, no Docker)

Each route handler was invoked directly with the probe's exact request and the verdict computed with
the probe's own predicate (`hasNonTrivialBody`, the 2xx checks, the 5× replay). Result: **8 passed, 0
failed** — the four vulnerable routes → proven, the four controls → unproven. `next build` compiles all
eight routes as dynamic handlers.

## Live verification (2026-07-22, Docker + Supabase CLI)

The full live `pnpm dynamic-validate targets/vuln-seam-app --execute` run was executed for real and
scored **4/4 proven, zero controls flagged** — each seam probe and the NO-RATE-LIMIT loop reached
`proven` on its **vulnerable** route (`/api/webhooks/stripe`, `/api/internal/users`,
`/api/ingest/events`, `/api/coupon/redeem`). Full record (versions, verdicts, repros, teardown):
`docs/design/vuln-seam-app-live-validation.md`; raw artifact: `reports/vuln-seam-app/M2.pass.json`.
The standing offline regression guard is `src/pentest/vuln-seam-app.test.ts` (runs in `pnpm verify`).
This closed the live proven-branch step for #717 and #159 and the "run it live" half of #738.
