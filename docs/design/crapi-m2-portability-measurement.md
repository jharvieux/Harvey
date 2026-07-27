# Harvey M2 probe portability — OWASP crAPI (multi-container Java/Python BOLA target)

**Date:** 2026-07-24
**Target:** OWASP **crAPI** (`OWASP/crAPI`, `docker-compose`), the standard BOLA-heavy scanner-evaluation
app: Java (Spring Boot) `identity`, Python (Django) `workshop`, Go `community` microservices behind
Postgres + Mongo, plus mailhog. Booted locally from its shipped compose (6-container core:
`crapi-identity`, `crapi-community`, `crapi-workshop`, `postgresdb`, `mongodb`, `mailhog`; the
`chatbot`/`chromadb`/gateway/web tiers were left down — see topology note). Torn down after
(`docker compose down -v`). **Issue:** jharvieux/Harvey#941, the declared multi-container remainder of
#880 (the VAmPI half shipped in #942, `docs/design/vampi-m2-portability-measurement.md`).

This is a MEASUREMENT: every verdict below is from **Harvey's actual, UNMODIFIED M2 replay probes**
(`runVerify` from `src/pentest/engine.ts`, the code path `dynamic-validate` drives) pointed at live
crAPI via a scratch driver that logs in crAPI's own seeded identities and passes their crAPI JWT
bearers as the probe personas. No Harvey probe was changed. It re-answers #880's question against a
harder target than VAmPI and **re-verifies #942's "IDOR-OBJECT does not port" reasons on crAPI rather
than carrying them forward** — one holds identically, one holds in class but for a *different concrete
reason*, and crAPI surfaces two gaps VAmPI did not.

## Identities and topology

crAPI pre-seeds users with fixed, email-verified credentials (`services/identity/.../TestUsers.java`),
so no mailhog OTP dance is needed:

- **Adam** `adam007@example.com` / `adam007!123` — persona **tenantA** (victim / owned-object source)
- **Pogba** `pogba006@example.com` / `pogba006!123` — persona **tenantB** (attacker)
- **Admin** `admin@example.com` / `Admin!123` — persona **admin**

Login is `POST /identity/api/auth/login` → `{token}`, an **RS256** JWT (JWKS-verified at
`/identity/api/auth/jwks.json`) — not VAmPI's HS256, and not a Supabase session. crAPI's services
speak **HTTPS with a self-signed cert** on their own ports. Because crAPI is a **multi-service**
app (identity `:8080`, workshop `:8000`, community `:8087`) and its single front door (`crapi-web`)
needs the chatbot upstream to boot, the probes were pointed at each service origin directly; a
production run would point one `appUrl` at the gateway. That multi-origin-vs-single-`appUrl` mismatch
is itself a portability note (gap 4).

## What ran, and the verdict from each probe class

Five route-adaptive replay probes ran over hand-supplied crAPI routes (below). Verdicts are the
probes' own machine output:

| Probe | Verdict on live crAPI | Meaning |
|-------|-----------------------|---------|
| **MISSING-AUTH-SWEEP** (#367) | **PORTS — ran end-to-end, correct negative.** Swept every discovered read route anonymously across all three services; each returned 401. No false positive, no crash. | The language-agnostic persona×verb HTTP sweep executes against Java/Python/Go exactly as against Flask/Node. crAPI simply enforces auth on the swept routes (unlike VAmPI's anon `/_debug`), so the correct verdict is a clean negative — the probe **worked**. |
| **IDOR-OBJECT** (#366) | **BLOCKED / not-applicable (fail-loud).** Pass A: "the oracle exposed no Tenant A object id to substitute." Pass B (foreign id injected): the real cross-user BOLA 200 is classified "no such object". | The real BOLA exists and was proven out-of-band; the probe **structurally cannot reach it** for two code-grounded reasons, both re-measured on crAPI (below). |
| **MASS-ASSIGNMENT** (#368) | **BLOCKED (silent-clean risk).** With `allowDestructive` it sent 7 privilege fields per write route; reported "none of the injected fields persisted" — but with **no PostgREST oracle it never read anything back**. | The write executes, but the **persistence confirmation is PostgREST-oracle-coupled** (same coupling as IDOR-OBJECT id acquisition). With no oracle it degrades to a *vacuous* "none persisted" that reads clean — a fail-loud gap (see gap 5). |
| **CSRF** (#587) | **BLOCKED.** Ran with `allowDestructive`; no persisted change confirmable. | Persistence confirmation is oracle-coupled, and dynamic-route CSRF needs an owned id (same acquisition gap). Ran, could not confirm. |
| **BFLA-ADMIN** (#567) | **PARTIAL / under-discovers.** identity: one `/admin/videos/:id` route probed, admin oracle not established (needs a real video id) → unproven. workshop, community: **not-applicable — "no /admin routes"**. | crAPI's function-level-authz bugs (the `mechanic`/`admin` role split) are **not all under an `/admin/` URL segment**, which the classifier keys on, so the surface is under-discovered (gap 6). |

## The BOLA is real — proven out-of-band with the two identities

Two distinct, live cross-user object reads (Harvey's replay probe could not confirm either, for the
reasons below):

1. **Vehicle location** — `GET /identity/api/v2/vehicle/{carId}/location` as **Pogba** with **Adam's**
   `carId` (`f89b5f21-…`) → **200** `{"carId":"f89b5f21-…","vehicleLocation":{"id":1,"latitude":
   "32.778889","longitude":"-91.919243"},"fullName":"Adam","email":"adam007@example.com"}`. The
   controller is literally named `getLocationBOLA` and performs no ownership check.
2. **Orders** — `GET /workshop/api/shop/orders/{order_id}` as **Adam** (owns order 1) for order ids
   2 and 3 → **200**, returning Pogba's and Robot's orders (`{"order":{"id":2,"user":{"email":
   "pogba006@example.com",…}},"payment":{…}}`).

## Where it ports (the portable core, re-confirmed on crAPI)

- **The persona×verb HTTP sweep is genuinely language-agnostic** — MISSING-AUTH-SWEEP ran end-to-end
  against Spring Boot / Django / Go with a correct verdict and no crash, as it did against VAmPI's Flask.
- **A non-Supabase bearer identity ports.** crAPI's RS256 JWT (a different algorithm from VAmPI's
  HS256, and not a Supabase session) drove every probe as the persona `Authorization: Bearer` with no
  change. Self-signed HTTPS needed only transport-level cert-ignore for a local target.

## Where it does NOT port — the gaps, re-verified against crAPI

> **STATUS UPDATE 2026-07-24 — all six gaps below are CLOSED; this section is the record of what was
> measured, not the current state.**
>
> - **Gaps 1–4 → #965.** The victim-id source is externalized (operator seed `--victim-id` →
>   PostgREST oracle → **victim self-read**, `src/pentest/object-ids.ts`); leak confirmation is
>   **response-shape aware** — it walks the body rather than matching a fixed top-level key list, so
>   domain-named id keys and multi-key envelopes are inspected (`src/pentest/object-leak.ts`); an
>   OpenAPI→`DiscoveredRoute[]` adapter exists and turns **per-path `servers` into per-route
>   origins**, which is gap 4's multi-service wrinkle (`src/pentest/openapi-routes.ts`); and the
>   external entrypoint is `pnpm exec tsx src/cli/pentest.ts --mode=external --app-url <origin>
>   [--openapi <spec>]` (`src/pentest/external-target.ts`). Proven live on VAmPI, where IDOR-OBJECT
>   reached `proven` — **not re-run against crAPI's 8-container stack**, so crAPI's specific shapes
>   (the `{order,payment}` envelope, `carId`) are covered by design and by offline control, not by a
>   live crAPI measurement. That live re-run is the honest remaining verification.
> - **Gap 5 → #995/#966.** MASS-ASSIGNMENT no longer reports a vacuous "none persisted" with no
>   read-back surface; with no oracle it reports **not-applicable**, so the silent clean is gone.
> - **Gap 6 → #995/#967.** Privileged-route discovery no longer keys on an `/admin/` URL segment
>   alone — a role/permission comparison in source (`role === "mechanic"`) now marks the route
>   privileged (`src/pentest/discovery.ts`).
>
> Falsify the crAPI-shape half by re-running the reproduction below through
> `pentest.ts --mode=external --openapi openapi-spec/crapi-openapi-spec.json`.

That remaining verification is an empirical claim, recorded per #1072 with its live-tier falsifier:

> REASON: the #965 externalised-oracle + response-shape-aware IDOR-OBJECT fix is proven live on VAmPI (reached `proven`) and by offline control, but has NOT been re-run against a live crAPI stack — so crAPI's specific BOLA shapes (the {order,payment} envelope, the domain-named carId key) are covered by design and offline fixture, not yet by a live crAPI measurement
> KIND: empirical
> PROVENANCE: TRIED 2026-07-24 (VAmPI live re-run reached `proven`; the crAPI live re-run was not performed and is recorded above as the honest remaining verification)
> FALSIFIER: pnpm exec tsx src/cli/pentest.ts --mode=external --app-url <crapi-gateway> --openapi openapi-spec/crapi-openapi-spec.json | grep -q "IDOR-OBJECT.*proven"
> FALSIFIER-TIER: m2-stack

**Gap 1 — IDOR-OBJECT foreign-id ACQUISITION is PostgREST-oracle-coupled. HOLDS IDENTICALLY.**
`collectOwnedIds` (`src/pentest/verify.ts:459`) discovers the victim ids by reading
`GET {apiUrl}/rest/v1/<table>` with the service-role oracle. crAPI has no PostgREST endpoint, so the
attacker never gets a foreign id and the probe reports a **fail-loud not-applicable** (Pass A). Same as
VAmPI. The confirmation logic is portable; the ground-truth id *source* is not.

**Gap 2 — the leak-CONFIRMATION predicate misses crAPI's BOLA objects. HOLDS IN CLASS, DIFFERENT
REASON.** This is the one #942 measured on VAmPI; re-measured here it manifests differently, which is
exactly why a recorded reason must be re-tested. In Pass B the correct foreign id was **injected** (via
a stub oracle) so `collectOwnedIds` returned it and the *real* `replayIdorObject` confirmation predicate
ran against the *live* crAPI response. Result: the genuine cross-user **200 was classified "no such
object"** and reported unproven.
- The predicate (`verify.ts:492/498`) recognises a leaked object only when it carries a top-level `id`
  field or one of a fixed `OBJECT_SCOPE_KEYS` list (`tenant_id`/`owner_id`/…).
- On **VAmPI** the miss was "the object has **no id at all** (natural key `username`/`title`)".
- On **crAPI** the objects **do carry numeric ids**, but the predicate still misses them because the id
  is not where it looks: the vehicle-location object keys it under a **domain name** (`carId`, plus a
  nested `vehicleLocation.id`), and the order object is wrapped in a **response envelope**
  (`{order:{id:…}, payment:{…}}`) whose top level has no `id`. `bodyObjects` only unwraps a *single-key*
  envelope, so a two-key `{order,payment}` stays wrapped and its inner `id` is never inspected.
- So the fix is the same class #942 named — **target-supplied object-identity/scope keys** — but crAPI
  proves it must ALSO be **response-shape aware** (domain-named id keys; multi-key envelopes), not just a
  wider key list.

**Gap 3 — route discovery is source-based and does not cover Java/Python/Go. HOLDS.** crAPI ships an
**OpenAPI 3.0 spec** (`openapi-spec/crapi-openapi-spec.json`, 40 paths) — the natural portability path —
but no OpenAPI→`DiscoveredRoute[]` adapter exists, so routes were hand-supplied. Same as VAmPI, now with
a concrete spec in hand.

**Gap 4 — no external-target entrypoint, AND a multi-service topology mismatch.** `dynamic-validate`
stands up its own Supabase; there is no `--app-url/--identity/--routes` runner for an app Harvey did not
provision (same as VAmPI). crAPI adds a new wrinkle: it is **three services on three origins**, but
`HarnessConfig` has a single `appUrl`. A real run must target one gateway origin (or the runner must
carry per-route origins).

**Gap 5 — NEW on crAPI: MASS-ASSIGNMENT's persistence confirmation is ALSO oracle-coupled, and fails
QUIETLY.** With `allowDestructive` the probe wrote, then looped over `ctx.tables` to read the value back
— but `tables` is empty on a non-Supabase target, so it confirmed nothing and reported "none of the
injected fields persisted". That reads as a clean pass while actually being *unverifiable*. Unlike
IDOR-OBJECT gap 1 (a loud not-applicable), this is a **silent** clean — a fail-loud violation worth
fixing: with no read-back surface the probe should report not-applicable, not "none persisted".

**Gap 6 — NEW on crAPI: BFLA-ADMIN under-discovers non-`/admin/` privileged routes.** The admin-route
classifier keys on an `/admin/`/`/superadmin/` URL segment (`discovery.ts:59`). crAPI's function-level
authz bugs live behind **role checks** (`mechanic`, `admin`) on ordinary paths (e.g. `workshop/api/
mechanic/*`), not under an `/admin/` segment, so BFLA-ADMIN reported not-applicable on workshop/community
despite real function-level surface being present.

## Score against crAPI's published vulnerability list (the probed surface)

| crAPI vuln class | Harvey M2 result this run |
|------------------|---------------------------|
| BOLA — vehicle location (`/vehicle/{id}/location`) | **MISSED** — gap 1 (Pass A) + gap 2 (Pass B: real 200 unrecognised) |
| BOLA — orders (`/shop/orders/{id}`) | **MISSED** — gap 1 + gap 2 (envelope-wrapped `id`) |
| Excessive data exposure / missing auth | **Correct negative** — MISSING-AUTH-SWEEP ran; crAPI gates the swept routes |
| Mass assignment | **BLOCKED** — write ran, persistence unverifiable without an oracle (gap 5) |
| BFLA (mechanic/admin roles) | **UNDER-DISCOVERED** — not under an `/admin/` URL segment (gap 6) |

**Zero object-authorization classes proven; both headline BOLAs missed for two precise, re-measured
reasons.** As on VAmPI, the harness gaps are the deliverable — and crAPI sharpens the diagnosis: the
confirmation predicate misses even when it *is* handed the id, because crAPI's BOLA responses carry the
id under a domain-named key or inside a multi-key envelope. The industry claim #880 cites (generic
scanners fail BOLA because they cannot infer object ownership) is **confirmed for the un-ported path**:
Harvey infers ownership from a Supabase oracle it did not have, and confirms leaks with a Supabase-shaped
predicate the target's responses do not match. The fixes are externalising the id source and making the
confirmation predicate target-supplied AND response-shape aware — not a new detector.

## Reproduction (2026-07-24)

```bash
# 1. Boot the core (colima bumped to 8GB for the JVM services, restored to 4GB after):
cd crAPI/deploy/docker
docker compose -f docker-compose.yml -f docker-compose.minimal.yml \
  -f <ports-override publishing 8080/8000/8087> up -d \
  postgresdb mongodb crapi-identity crapi-community crapi-workshop mailhog
# 2. Driver (scratch glue, not committed, mirrors #942's): logs in Adam/Pogba/Admin via
#    POST /identity/api/auth/login, builds a HarnessConfig per service (appUrl=service origin,
#    jwts=crAPI RS256 tokens, appAuth=Bearer per persona, profile=hand-supplied crAPI routes as
#    DiscoveredRoute[]), and calls the UNMODIFIED runVerify(client, cfg,
#    ["MISSING-AUTH-SWEEP","IDOR-OBJECT","MASS-ASSIGNMENT","CSRF","BFLA-ADMIN"]).
#    Pass A: tables=[] (no oracle). Pass B: a stub client answers /rest/v1 with the known foreign id
#    so the real IDOR confirmation predicate runs against crAPI's live 200 response.
#    NODE_TLS_REJECT_UNAUTHORIZED=0 for the self-signed local cert.
docker compose ... down -v
```

## Provenance

Every verdict is from a live run observed 2026-07-24 against the local crAPI stack (torn down after,
volumes removed; colima restored to its original 2 CPU / 4 GB). Harvey's `runVerify` was driven
unmodified; the two BOLAs were confirmed out-of-band with the same two seeded identities. Where a claim
carried from #942's VAmPI run, it was **re-tested on crAPI**, not repeated: gap 1 identical, gap 2 same
class / different reason, gaps 5–6 new.
