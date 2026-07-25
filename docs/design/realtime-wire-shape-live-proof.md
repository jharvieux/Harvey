# Realtime probe — Phoenix wire shape, live proof (#1003)

Remainder of #951. #951 shipped the control-gated Realtime subscribe-and-assert probe but could not
validate its Phoenix wire shape against a running `supabase/realtime`; the join/change frame shapes in
`src/pentest/realtime-transport.ts` were labelled CANDIDATE. This is the measurement that closes that.

Date: 2026-07-24. All frames below are verbatim wire captures with tokens/keys redacted.

## What was run, against what

| Target | Realtime version | What was done |
|---|---|---|
| Local `supabase start` stack (scratch project, throwaway) | `public.ecr.aws/supabase/realtime:v2.100.0` | full probe: subscribe, own-changes control, cross-tenant assertion, both verdicts |
| Hosted Supabase project (operator-authorized, ATC TEST) | hosted (version not exposed on the wire) | READ-ONLY: connect + `phx_join` + read frames. No write, no DDL, no seed |

The hosted run was authorized for observation only, so it could not drive a row change and therefore
could not fire the own-changes control. It proves the *connect and join* half against hosted infra; the
*change-frame* half is proven on the local stack only. Stated plainly rather than blended.

## Verdict: the candidate shape was CORRECT — with one load-bearing correction

The `phx_join` frame and the `payload.data.record` / `payload.data.table` change parse both matched the
running service unchanged. The own-changes control fired.

The correction the capture forced: **the join's `phx_reply` returns `status: "ok"` even when the
`postgres_changes` subscription then fails.** The real subscribe verdict arrives in a *separate*
`system` frame. The original transport ignored that frame entirely, so a dead subscription was
indistinguishable from a live-but-quiet one — the probe still reached the right *verdict* (the control
gate caught it), but it could only report the failure as a list of candidate causes. It now records
the service's own words and quotes them in the NOT-ASSESSED reason.

## Captured frames

Healthy subscription, local stack, topic `realtime:public:notes`:

```
→ {"topic":"realtime:public:notes","event":"phx_join","payload":{"config":{"postgres_changes":[{"event":"*","schema":"public","table":"notes"}]},"access_token":"<REDACTED>"},"ref":"1"}
← {"ref":"1","event":"phx_reply","payload":{"status":"ok","response":{"postgres_changes":[{"id":23809488,"event":"*","schema":"public","table":"notes"}]}},"topic":"realtime:public:notes"}
← {"ref":null,"event":"system","payload":{"message":"Subscribed to PostgreSQL","status":"ok","extension":"postgres_changes","channel":"public:notes"},"topic":"realtime:public:notes"}
← {"ref":null,"event":"postgres_changes","payload":{"data":{"table":"notes","type":"UPDATE","record":{"id":"aaaaaaaa-…","body":"a-note","tenant_id":"11111111-…"},"columns":[…],"errors":null,"schema":"public","commit_timestamp":"2026-07-24T22:45:56.067Z","old_record":{…}},"ids":[23809488]},"topic":"realtime:public:notes"}
```

Failing subscription — table not in the `supabase_realtime` publication. Note the `status: "ok"` reply
*preceding* the error, which is the whole point:

```
← {"ref":"1","event":"phx_reply","payload":{"status":"ok","response":{"postgres_changes":[{"id":2665251,"event":"*","schema":"public","table":"tenants"}]}},"topic":"realtime:public:tenants"}
← {"ref":null,"event":"system","payload":{"message":"Unable to subscribe to changes with given parameters. Please check Realtime is enabled for the given connect parameters: [event: *, schema: public, table: tenants, filters: []]","status":"error","extension":"postgres_changes","channel":"public:tenants"},"topic":"realtime:public:tenants"}
```

Join rejected outright (malformed `access_token`) — this one *does* come back on the `phx_reply`:

```
← {"ref":"1","event":"phx_reply","payload":{"status":"error","response":{"reason":"MalformedJWT: The token provided is not a valid JWT"}},"topic":"realtime:public:notes"}
```

Hosted project, read-only, same join frame — accepted, then refused because the observed table is not
in that project's publication. Same two-frame sequence as local, so the shape is not a local-stack
artifact:

```
← {"ref":"1","event":"phx_reply","payload":{"status":"ok","response":{"postgres_changes":[{"id":82669809,…}]}},…}
← {"ref":null,"event":"system","payload":{"message":"Unable to subscribe to changes with given parameters. …","status":"error","extension":"postgres_changes",…}}
```

## Both acceptance verdicts, live

Same stack, same probe binary (`pentest.ts --mode=realtime --allow-destructive`), one table, two RLS
configurations.

**Leak case** — `public.notes` in the publication, `anon` granted a `using (true)` SELECT policy:

```
M2-REALTIME-LEAK-notes — High, status Proven
actual: tenant A's subscription received a tenant-B (tenant_id=2222…) row change
```

**Scoped case** — policy replaced with
`using (tenant_id = (auth.jwt()->'app_metadata'->>'tenant_id')::uuid)`, probing with two real GoTrue
sessions carrying per-tenant `app_metadata`:

```
M2-REALTIME-SCOPE — "VERIFIED not-vulnerable: … own-changes control confirmed the subscription was
live, drove a tenant-B row change via the oracle, and tenant A did NOT receive it within 3000ms"
```

The control fired in both runs, so neither verdict is a guess about a quiet socket.

## Inline fix the proof run surfaced

The scoped run shipped that VERIFIED result under the title *"Realtime channel authorization: NOT
ASSESSED (treat as UNVERIFIED)"*, with the "treat as UNVERIFIED, not as clean" tail appended — a proven
result presented as an unassessed one. `realtimeScopeDisclosure` now retitles a VERIFIED reason and
swaps the tail for a scope caveat (the verdict covers the probed table only). Regression-tested.

## What is still NOT proven

- Only `postgres_changes` was exercised. Realtime's **Broadcast** and **Presence** channels, and RLS on
  `realtime.messages` (Realtime Authorization), were not probed at all.
- Only ONE table per run is probed (`cfg.tables[0]`), so other tables in the publication stay
  unassessed — the VERIFIED row now says so explicitly.
- Realtime versions other than v2.100.0 are unmeasured. The own-changes control is the standing guard:
  if the shape drifts, the control does not fire and the probe returns NOT ASSESSED, never a false clean.
- The hosted observation covered connect + join only; no hosted change frame was observed, because
  generating one would have required a write to a project authorized for read-only observation.
