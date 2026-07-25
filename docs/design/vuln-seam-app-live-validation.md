# M2 seam + rate-limit proven branches — live validation record

**What this proves:** the four inter-service **seam** probes and the **NO-RATE-LIMIT** loop drive their
*positive* (finding-producing) branches to a **proven** verdict end-to-end against a booted target —
the step #718 could only verify offline (route classification + per-handler invocation). This closes
the live proven-branch gap tracked by **#717** (the three seam probes) and **#159** (NO-RATE-LIMIT),
and the "run it live once, for real" half of **#738**.

Everything below was executed for real on 2026-07-22 — a "measure, don't recall" record, not intent.

- Docker 29.5.2, Supabase CLI 2.102.0, psql (PostgreSQL) 18.4, node v24.15.0
- Target: `targets/vuln-seam-app` (the Harvey-owned deliberately-vulnerable fixture, #718)
- Answer key scored against: `targets/vuln-seam-app/ANSWER-KEY.md` (moved fixture-adjacent by #994)

## Command under test

```
pnpm dynamic-validate targets/vuln-seam-app --execute --out reports/vuln-seam-app
```

The autonomous pipeline (`src/pentest/live-standup.ts` `createLiveStandUp`): `supabase start` an
isolated stack (project-id `harvey-dv-b25cfd0ee7`, ports api=57901 db=57902) → apply the fixture's
migration → create two auth users + the two-tenant seed → **Tier 1** live PostgREST matrix +
auth-attack → **Tier 2** `npm install` + `next build` + `next start` → health-check → the app-route +
seam replays (`pentest.ts --mode=verify … --app-dir`) against the running app → write
`M2.pass.json` → `supabase stop` + scoped volume removal in a `finally`.

## Result — GO (full coverage), 8 findings, clean teardown

The four planted seams and the un-rate-limited flow each reached **proven**, hitting their
**vulnerable** route (not the control). Scored against the answer key: **4/4 recall, zero controls
flagged.**

| Probe (answer key class) | Live finding | Severity | Route reached (vulnerable) |
|---|---|---|---|
| `CROSS-SERVICE-WEBHOOK` (#717) | `M2-APP-CROSS-SERVICE-WEBHOOK` | High | `POST /api/webhooks/stripe` |
| `DIRECT-SERVICE-CALL` (#717) | `M2-APP-DIRECT-SERVICE-CALL` | High | `GET /api/internal/users` |
| `SERVICE-JWT-UNVERIFIED` (#717) | `M2-APP-SERVICE-JWT-UNVERIFIED` | Critical | `GET /api/ingest/events` |
| `NO-RATE-LIMIT` (#159) | `M2-APP-NO-RATE-LIMIT` | High | `POST /api/coupon/redeem` (5/5 accepted) |

Each finding carries the exact curl repro. Example (CROSS-SERVICE-WEBHOOK):

```
curl -s -X POST 'http://127.0.0.1:3000/api/webhooks/stripe' \
  -H 'Content-Type: application/json' -H 'x-signature: harvey-invalid-signature' \
  -d '{"event":"HARVEY_PROBE_UNSIGNED"}'
expected: 401 — an invalid webhook signature is rejected
actual:   status 200, payload with a bogus signature accepted and processed
```

**Control isolation:** in a single whole-fixture run each seam probe short-circuits on the first
proven endpoint, so the vulnerable route is what produces the verdict and the control is not
independently re-reported — no control was flagged. The controls are scored **not-vulnerable in
isolation** by the standing offline check below (a control-only profile → every probe `unproven`).

**Other findings in the run (not controls, not false positives):**

- `M2-APP-MISSING-AUTH-SWEEP` (Critical) — a genuine true positive: the fixture's vulnerable seam
  routes answer anonymous requests by design, which the missing-auth sweep correctly reports.
- `M2-AUTH-AUTH-ENUMERATION` / `-JWT-TAMPER` / `-RATELIMIT-LOGIN` — the auth-attack suite against the
  local GoTrue stack's default configuration; unrelated to the seam fixture.

The isolated stack was torn down: after the run, `docker ps` and `docker volume ls` show no
`harvey-dv-*` container or volume.

## Standing regression guard

`src/pentest/vuln-seam-app.test.ts` is the CI-run (`pnpm verify`) smoke check that keeps these
branches from silently regressing, offline (no Docker). It drives the **real** classifier
(`discoverProfile` over the fixture) and the **real** route handlers (imported and invoked in-process
through the `HttpClient` seam) through the **real** probe code (`runVerify`), and asserts:

1. each of the four seam classes classifies into exactly its vulnerable + control endpoint, nothing
   cross-classified;
2. the four vulnerable routes reach `proven` (with a repro);
3. the four negative controls, each scored in isolation, stay `unproven` (zero-FP);
4. the answer key still names all eight route paths (so a rename can't leave a stale denominator).

A regression in the classifier, any seam/rate-limit probe, or a fixture route fails the check. The
raw live artifact is committed at `reports/vuln-seam-app/M2.pass.json`.
