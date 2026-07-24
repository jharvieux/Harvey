# Harvey M2 probe portability — VAmPI (first non-Supabase deliberately-vulnerable target)

**Date:** 2026-07-24
**Target:** OWASP **VAmPI** (`erev0s/vampi:latest`, Docker Hub), a deliberately-vulnerable Python/
Flask REST API built "to evaluate the efficiency of tools used to detect security issues in APIs."
Run locally on `http://localhost:5001` (its own container, disposable; torn down after). **Issue:**
jharvieux/Harvey#880. This is the smaller/faster half of #880 — **crAPI (the 8-container run) is the
declared remainder** (see the split issue).

This is a MEASUREMENT: every verdict below is from **Harvey's actual M2 replay probes** (`runVerify`
from `src/pentest/engine.ts`, the same code path `dynamic-validate` drives) pointed at live VAmPI via
a driver that logs in two real VAmPI identities and passes VAmPI's own JWT bearer tokens as the probe
personas. No Harvey probe was modified. It answers #880's question — *does the BOLA/HTTP probe
methodology port to an app whose data model we did not seed?* — and records precisely where it does
and does not.

## What ran, and the verdict from each probe

Two VAmPI identities (`name1`, `name2`; VAmPI mints a 60-second HS256 bearer per login) drove the
three route-adaptive replay probes over VAmPI's documented routes (`/users/v1/_debug`,
`/users/v1/:username`, `/users/v1/:username/email`, `/books/v1`, `/books/v1/:title`, …), supplied as
Harvey `DiscoveredRoute`s.

| Probe | Verdict on live VAmPI | What it means |
|-------|-----------------------|---------------|
| **MISSING-AUTH-SWEEP** (#367) | **PROVEN (High)** — `GET /users/v1/_debug` answered an anonymous request with the full user table (usernames, emails, **cleartext passwords**). | **The methodology PORTS.** Harvey's persona×verb HTTP sweep caught a real VAmPI vulnerability (Excessive Data Exposure / missing auth) on a non-Supabase, non-Node app it never modeled. |
| **IDOR-OBJECT** (#366) | **not-applicable (fail-loud unproven)** — "Probed 4 dynamic-id route(s) but the oracle exposed no Tenant A object id to substitute." | The probe's foreign-id acquisition is Supabase-coupled (below). It fail-LOUD (self-reported not-applicable with the reason) rather than a false clean — the coverage guard working. |
| **MASS-ASSIGNMENT** (#368) | **unproven** — probed 4 in-place object writes with 7 privilege fields; none persisted. | A legitimate not-proven for the routes probed: VAmPI's mass-assignment is at **registration** (`POST /users/v1/register` with `admin:true`), a different surface than the in-place dynamic-id write this probe targets. A surface gap, not a detection failure. |

**The BOLA IS present** and was confirmed out-of-band with the same two identities:
`GET /users/v1/name1` with **name2's** token returns name1's object — an unauthenticated/cross-user
object read. So VAmPI has exactly the BOLA class IDOR-OBJECT exists to prove, and the probe did not
prove it — for the two precise, code-grounded reasons below.

## Where it ports (the portable core)

- **Auth is non-Supabase and ports.** VAmPI uses a custom HS256 `Authorization: Bearer <token>`, not
  a Supabase session. Harvey's personas carried it with no change (the `appAuth`/#571 path, and the
  persona `Authorization: Bearer` header). Bearer identities drove every probe correctly.
- **The persona×verb HTTP sweep is genuinely language-agnostic.** MISSING-AUTH-SWEEP proved a real
  vuln on a Python/Flask app — its confirmation logic (2xx + non-trivial body to an anonymous
  request ⇒ no server-side auth) needs nothing Supabase-specific, and it fired.

## Where it does NOT port (the harness gaps — #880's real deliverable)

1. **IDOR-OBJECT's foreign-id ACQUISITION is PostgREST-service-role-oracle-coupled.**
   `collectOwnedIds` (`src/pentest/verify.ts:459`) discovers the victim object ids to substitute by
   reading `GET {apiUrl}/rest/v1/<table>` with the **service-role oracle** header. That is a Supabase
   PostgREST call; VAmPI (and crAPI) expose no such ground-truth endpoint, so the attacker never gets
   a foreign id and the probe reports not-applicable. **The confirmation logic is portable; the
   ground-truth id SOURCE is not.** A non-Supabase run needs foreign ids supplied another way (an
   OpenAPI-enumerated id, a second identity's own object id, or an operator-provided seed).
2. **Even given a foreign id, the leak-CONFIRMATION predicate keys on Supabase-convention columns.**
   `replayIdorObject` (`verify.ts:492/498`) confirms a leak only when the returned object carries an
   `id` field OR one of `OBJECT_SCOPE_KEYS` (`tenant_id`/`owner_id`/`user_id`/`org_id`/…). VAmPI's
   objects are keyed by a **natural key** (`username`; books by `title`) and carry none of those, so
   the predicate would classify name1's leaked `{username, email}` as "no object found" — a **silent
   miss**, unlike gap 1's loud not-applicable. Porting IDOR-OBJECT needs the object-identity/scope
   keys to be target-supplied, not a fixed Supabase list.
3. **Route discovery is source-based and does not cover Python/Java.** Harvey discovers routes by
   parsing Next/Express source (`buildTargetProfile` consumes discovered routes). VAmPI (Flask) and
   crAPI (Java/Python) are not parsed, so their route surface must come from elsewhere. Both ship an
   **OpenAPI spec** — the natural portability path — but no OpenAPI→`DiscoveredRoute[]` adapter exists;
   for this run the routes were supplied by hand.
4. **No "point at a running external app" entrypoint.** `dynamic-validate` orchestrates a self-stood-
   up Supabase stack; there is no CLI mode that takes `--app-url <base> --identity <token> --identity
   <token> --routes <openapi>` and runs the app-route probe tier against an app Harvey did not
   provision. This driver was scratch glue; productizing #880 means an external-target runner.

## Score against VAmPI's published vulnerability list

VAmPI's documented classes and Harvey's mechanical/M2 result this run:

| VAmPI vuln | Harvey M2 result |
|------------|------------------|
| Excessive Data Exposure (`/users/v1/_debug`) | **CAUGHT** (MISSING-AUTH-SWEEP, proven High) |
| BOLA (`GET /users/v1/:username`) | **MISSED** — gaps 1+2 above (oracle-coupled acquisition; non-matching scope keys) |
| BOLA update (`PUT /users/v1/:username/email`) | not reached (same acquisition gap) |
| Mass assignment (register `admin:true`) | **MISSED** (surface: registration, not in-place write) |
| Broken auth (JWT) / user enumeration / RegexDoS | out of the three replay probes' scope this run |

**1 of the object-authorization classes proven, the headline BOLA missed for two precise reasons.**
This matches #880's expectation ("record the harness gaps this surfaces … those are the portability
findings, and they are the real deliverable even if the score is mediocre"). The industry claim
#880 cites — that generic scanners fail BOLA because they cannot infer object ownership — is
*confirmed for the un-ported path here*: Harvey infers ownership from a Supabase oracle it did not
have, so it could not substitute a foreign id. The fix is to externalize the id source and scope
keys, not a new detector.

## Reproduction (2026-07-24)

```bash
docker run -d --name vampi -p 5001:5000 erev0s/vampi:latest
curl -s http://localhost:5001/createdb              # seed name1/name2/admin
# driver: login name1 + name2, build a HarnessConfig (appUrl=VAmPI, jwts=VAmPI tokens,
# profile=VAmPI routes as DiscoveredRoute[]), runVerify(client, cfg,
#   ["IDOR-OBJECT","MISSING-AUTH-SWEEP","MASS-ASSIGNMENT"]).
docker rm -f vampi
```

## Provenance

Every verdict is from a live run observed 2026-07-24 against the local VAmPI container (torn down
after; `docker rm -f vampi`). Harvey's `runVerify` was driven unmodified. crAPI's multi-container
run is the declared #880 remainder.
