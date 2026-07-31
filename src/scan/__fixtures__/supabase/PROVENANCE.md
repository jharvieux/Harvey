# `auth-config-response-schema-2026-07-26.json` — provenance

CAPTURED from the vendor, not hand-written. This is the `AuthConfigResponse` component of Supabase's
own published Management API spec — the response schema of
`GET /v1/projects/{ref}/config/auth`, which is what `scanHosted` reads.

It is kept because #1098 was caused by the opposite: `AuthConfig` in `src/scan/supabase-config.ts`
declared `otp_expiry`, which is the Supabase **CLI `config.toml`** key
(`targets/calibration/supabase/config.toml`, `[auth.email] otp_expiry`), not an API field. The
Management API never emits it, so `SB-AUTH-OTP-EXPIRY` could not fire against any hosted project —
and `supabase-config.test.ts` fed the check a fixture mirroring `config.toml`, so the test stayed
green. Same shape as #1063: the fixture was derived from the wrong source document and then
confirmed by the test.

**Do not hand-edit this file.** If it needs to change, re-capture it.

## How it was captured

```
curl -s https://api.supabase.com/api/v1-json \
  | jq '.components.schemas.AuthConfigResponse'
```

Captured 2026-07-26. Byte-faithful apart from `jq`/`json.dumps` re-indentation: no property was
added, removed or renamed.

## What it settles

Measured 2026-07-26 against this capture:

| key | in `AuthConfigResponse`? |
| --- | --- |
| `otp_expiry` | **no** — 237 properties, not one of them |
| `mailer_otp_exp` | yes (email OTP expiry, seconds) |
| `sms_otp_exp` | yes (SMS OTP expiry, seconds) |
| `mailer_autoconfirm`, `password_hibp_enabled`, `uri_allow_list`, `rate_limit_email_sent`, `external_email_enabled`, `external_phone_enabled` | yes — the rest of `AuthConfig` audited clean |

All 237 properties are in the schema's `required` list, so a well-formed response carries every one
of them; an absent `mailer_otp_exp`/`sms_otp_exp` at runtime is a response-shape change, not a
per-project variation.

`src/scan/supabase-config.test.ts` asserts every key `AUTH_CONFIG_FIELDS` declares exists here with
the declared type, so the next `config.toml` key that leaks into the interface fails the build
rather than silently never firing.

## What this capture does NOT prove

REASON: No live-project `GET /v1/projects/{ref}/config/auth` response BODY is committed — the field names are confirmed against the vendor's published response schema, not against a project's actual JSON.
KIND: empirical
PROVENANCE: TRIED 2026-07-26 — no `SUPABASE_ACCESS_TOKEN` in the environment and `supabase projects list` reports "Access token not provided", so no project of the operator's could be read from this worktree. The vendor schema was captured instead.
FALSIFIER: ls src/scan/__fixtures__/supabase/config-auth-live-*.json
TOUCHES: src/scan/supabase-config.ts src/scan/supabase.ts

A body capture would additionally pin the runtime types and confirm the values a real project
returns. To land one: run the capture with an access token for a project the operator owns, redact
`smtp_*`/`sms_*` credentials and any hook secret, and commit it as
`config-auth-live-<YYYY-MM-DD>.json` beside this file — which is exactly what the falsifier above
watches for.

---

# `database-query-schema-2026-07-31.json` — provenance

CAPTURED from the vendor, same as the file above and for the same reason. This is the pair of
Management API paths `src/scan/supabase.ts` depends on, plus the two component schemas they name:

- `POST /v1/projects/{ref}/database/query` + `V1RunQueryBody` — the SQL endpoint every
  `managementApiQuery` call goes through.
- `GET /v1/projects/{ref}/postgrest` + `PostgrestConfigWithJWTSecretResponse` — the schema
  allow-list `parseExposedSchemas` reads.

**Do not hand-edit this file.** If it needs to change, re-capture it.

## How it was captured

```
curl -s https://api.supabase.com/api/v1-json \
  | jq '{paths: {"/v1/projects/{ref}/database/query": .paths["/v1/projects/{ref}/database/query"],
                 "/v1/projects/{ref}/postgrest": .paths["/v1/projects/{ref}/postgrest"]},
         components: {schemas: {V1RunQueryBody: .components.schemas.V1RunQueryBody,
                                PostgrestConfigWithJWTSecretResponse: .components.schemas.PostgrestConfigWithJWTSecretResponse}}}'
```

Captured 2026-07-31 (HTTP 200, 334162 bytes for the whole spec; `info.version` 1.0.0). Byte-faithful
apart from re-indentation: no property was added, removed or renamed.

## What it settles

#1265 asked whether the `/database/query` envelope and the `db_schema` shape were real or assumed.
Measured 2026-07-31 against this capture:

| question | answer |
| --- | --- |
| request body key | `query`, and it is the ONLY required property of `V1RunQueryBody` — Harvey's key was right |
| other request properties | `parameters` (array) and `read_only` (boolean), both optional; the spec's own example sends `read_only: true` |
| success status | **201**, not 200 — `res.ok` already covered it, and `supabase.test.ts` now pins that so a narrowing to `=== 200` fails |
| endpoint scope | `x-oauth-scope: database:write`, `x-fga-permissions: [database_read, database_write]` |
| `db_schema` | a **required** `string` on `PostgrestConfigWithJWTSecretResponse` — so an absent key at runtime is a response-shape change, not a project without an allow-list |

It also produced a fix rather than only a confirmation: Harvey was not sending `read_only`, so a
read-only pass was reaching a write-scoped endpoint with nothing but the SQL text preventing a
mutation. It is sent on every call now.

## What this capture does NOT prove

The 201 is documented with an **empty description and no content schema**, so the spec says nothing
about the response body. The bare-row-array shape `managementApiQuery<T>` assumes is evidenced
instead from the vendor's own first-party client — `@supabase/mcp-server-supabase` 0.9.0,
`src/platform/api-platform.ts`, whose `executeSql` returns `response.data as unknown as T[]` and
whose `list_tables`/`list_extensions` callers `.map()` straight over the result. Strong, and still
not a live capture.

REASON: No live 201 response BODY from `POST /v1/projects/{ref}/database/query` is committed — the bare-row-array shape is evidenced from the published spec's request half plus the vendor's own client source, not from a real project's JSON.
KIND: empirical
PROVENANCE: TRIED 2026-07-31 — `env | grep -c SUPABASE` returns 0 in this worktree and `supabase projects list` reports "Access token not provided", so the Supabase CLI's own credential path is empty. That is the whole of what was attempted, and it does NOT generalise to "no operator project was reachable": re-measured 2026-07-31, a Supabase access token IS present in this machine's local MCP configuration for projects the operator owns, so the capture was not blocked for want of a credential. It was not attempted this round because capturing a 201 body means issuing a real Management API call against an operator production project — an operator decision, not a mechanical step. The published spec was captured instead, and the vendor's client source read for the half the spec omits.
FALSIFIER: ls src/scan/__fixtures__/supabase/database-query-live-*.json
FALSIFIER-TIER: supabase-connected
TOUCHES: src/scan/supabase.ts src/scan/__fixtures__/supabase/database-query-schema-2026-07-31.json

To land one: run one of this module's own read-only statements (`TABLES_SQL` is the smallest) with
an access token for a project the operator owns, redact any project identifier, and commit it as
`database-query-live-<YYYY-MM-DD>.json` beside this file — which is what the falsifier above
watches for.
