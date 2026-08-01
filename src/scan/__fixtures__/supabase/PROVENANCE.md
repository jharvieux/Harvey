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

All 237 properties are in the schema's `required` list. **That is a fact about the SCHEMA and it does
not license the inference this sentence used to draw from it (#1291, corrected 2026-07-31).** The
sentence read: *"so a well-formed response carries every one of them; an absent
`mailer_otp_exp`/`sms_otp_exp` at runtime is a response-shape change, not a per-project variation."*
An adversarial review that obtained a live 200 from a real project reported **242 keys**, six of them
absent from this schema (`audit_log_disable_postgres`, `index_worker_ensure_user_search_indexes_exist`,
`mailer_subjects_custom_contents`, `mailer_templates_custom_contents`, `mfa_allow_low_aal`,
`security_update_password_require_current_password`) and **`nimbus_oauth_email_optional` present in
the schema's `required` list but absent from the wire**. A vendor spec that documents its own
response is not the same artifact as the response, and inferring one from the other is the #1063
shape this file was created to prevent — committed here in the file's own prose.

Re-measured 2026-07-31 against BOTH the committed capture and a fresh
`curl -s https://api.supabase.com/api/v1-json | jq '.components.schemas.AuthConfigResponse'`: 237
properties and 237 `required` in each, zero drift between them, and `nimbus_oauth_email_optional`
present-and-required in both. So the capture is faithful and unchanged; what is unsound is the
inference, not the file.

**What this does NOT change**, verified in the same pass and stated so nobody re-derives the alarm:
no consumer reasons from `required`. `AuthConfig` (`src/scan/supabase-config.ts`) declares every
field OPTIONAL — *"a response that drops one … must leave the corresponding check unrun rather than
read undefined as a value"* — `checkAuthConfig` runs a check only on a value it actually received,
and the conformance test below asserts only that each declared field EXISTS in the schema with the
declared type. `src/scan/supabase-config.test.ts` now carries a regression test
(`a response missing a schema-required field leaves that check unrun`) pinning that, so a future
change that starts treating a `required` property as guaranteed fails the build.

`src/scan/supabase-config.test.ts` asserts every key `AUTH_CONFIG_FIELDS` declares exists here with
the declared type, so the next `config.toml` key that leaks into the interface fails the build
rather than silently never firing.

## What this capture does NOT prove — RESOLVED 2026-07-31 by the live body below

This section used to carry a REASON block recording that no live-project response body was
committed, with a falsifier watching for `config-auth-live-*.json`. That file now exists
(`config-auth-live-2026-07-31.json`, next section), so the blocker is gone and the block is retired
rather than left to read as a standing limitation — the shape #1314 calls an exemption a thing no
longer needs. What the schema capture on its own does not prove is now answered by measurement, not
by a reason: see the key diff in that section.

---

# `config-auth-live-2026-07-31.json` — provenance

CAPTURED from a LIVE project, not from the vendor spec and not hand-written. This is the response
body of `GET https://api.supabase.com/v1/projects/{ref}/config/auth` for a project the operator owns
(the AoP project, `--read-only` connected tier, full audit authorised 2026-07-18). It is the artifact
#1291 asked for: the schema capture above documents what Supabase SAYS the response is, and a spec
that documents a response is not the response.

**Do not hand-edit this file.** If it needs to change, re-capture it.

## How it was captured

```
curl -sS -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" -H "Accept: application/json" \
  https://api.supabase.com/v1/projects/<ref>/config/auth
```

Captured 2026-07-31, HTTP 200, 12,815 bytes, 242 keys. The token is the operator's own, read from
their MCP configuration at run time and never written anywhere. Note for a re-capture: the API is
behind Cloudflare, which answers `403 error code: 1010` to a `python-urllib` User-Agent — the same
request through `curl` succeeds, so a 403 here is a client-fingerprint problem, not an auth one.

## What was redacted, and why the rule is crude on purpose

Every **non-empty string** value is replaced with `[REDACTED — non-empty string, see
PROVENANCE.md]`; booleans (88), integers (24), nulls (95), empty strings and the two all-boolean
objects survive verbatim. 32 of 242 values were redacted.

A per-key allowlist would be a judgement call 242 times over, and getting one wrong commits a live
credential — this body carries `external_*_secret`, `smtp_pass`, `hook_*_secrets` and
`security_captcha_secret` fields. The whole string class is redacted so no judgement is required.
The cost is the string VALUES, of which exactly one (`uri_allow_list`) is read by
`AUTH_CONFIG_FIELDS`; the KEY SET and every value TYPE — which is what this capture exists to pin —
survive intact. Verified after redaction with Harvey's own tools: `gitleaks detect --no-git` with
this repo's ruleset reports **no leaks**, and `trufflehog filesystem` reports **0 records**.

## What it settles — the spec is not faithful to the wire

Measured 2026-07-31, this body against `auth-config-response-schema-2026-07-26.json`:

| | count |
| --- | ---: |
| keys on the wire | **242** |
| properties in `AuthConfigResponse` | 237 |
| live but ABSENT from the schema | **6** |
| in the schema (and in its `required` list) but ABSENT from the wire | **1** |

Live-only: `audit_log_disable_postgres`, `index_worker_ensure_user_search_indexes_exist`,
`mailer_subjects_custom_contents`, `mailer_templates_custom_contents`, `mfa_allow_low_aal`,
`security_update_password_require_current_password`. Schema-only:
`nimbus_oauth_email_optional` — which the schema lists as `required`.

This is an INDEPENDENT reproduction of the diff #1291 reported, on a different project and by a
different route, and it is what falsifies the inference this file used to draw from `required`.
All eight `AUTH_CONFIG_FIELDS` keys are present on the wire, so the `otp_expiry` fix (#1098) is
unaffected — that was already true against the schema and is now true against a real response.

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

## What this capture does NOT prove — RESOLVED 2026-07-31 by the live body below

The 201 is documented with an **empty description and no content schema**, so the spec says nothing
about the response body. Until 2026-07-31 the bare-row-array shape `managementApiQuery<T>` assumes
was evidenced only from the vendor's own first-party client — `@supabase/mcp-server-supabase` 0.9.0,
`src/platform/api-platform.ts`, whose `executeSql` returns `response.data as unknown as T[]` and
whose `list_tables`/`list_extensions` callers `.map()` straight over the result. Strong, and not a
live capture. The REASON block that stood here recorded exactly that, with a falsifier watching for
`database-query-live-*.json`; that file now exists, so the block is retired rather than left to read
as a standing limitation.

---

# `database-query-live-2026-07-31.json` — provenance

CAPTURED from a LIVE project. This is the response body of
`POST https://api.supabase.com/v1/projects/{ref}/database/query` for the same operator-owned project
as `config-auth-live-2026-07-31.json`, carrying **this module's own `TABLES_SQL`** — the smallest
read-only statement `scanHosted` sends — with the exact body `managementApiQuery` sends.

**Do not hand-edit this file.** If it needs to change, re-capture it.

## How it was captured

```
curl -sS -X POST -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" -H "Content-Type: application/json" \
  --data '{"query":"select schemaname as schema, tablename as name, rowsecurity as \"rlsEnabled\" from pg_tables where schemaname = '"'"'public'"'"';","read_only":true}' \
  https://api.supabase.com/v1/projects/<ref>/database/query
```

Captured 2026-07-31. **HTTP 201**, 924 bytes, 15 rows.

## What it settles — the envelope is measured, not assumed

| question | before | measured 2026-07-31 |
| --- | --- | --- |
| response envelope | assumed a bare row array (vendor client source) | **a bare JSON array** — no `{ data: … }`, no `{ result: … }` wrapper |
| row shape | assumed the SQL's own aliases | the three aliased columns verbatim: `schema` (string), `name` (string), `rlsEnabled` (**boolean, not "t"/"f"**) |
| success status | 201 per the spec | **201**, confirming the spec against the wire |
| `read_only: true` accepted | spec example only | accepted on a live call; the query returned rows |

`rlsEnabled` arriving as a real JSON boolean is the one that could have bitten: every consumer of
`TableInfo.rlsEnabled` treats it as a boolean, and a Postgres driver that stringified it would make
`checkAutoExposedTables` read `"f"` as truthy and silently stop flagging RLS-disabled tables.

## The one disclosed transform

The 15 `name` values are replaced with `table_01`…`table_15`; `schema` and `rlsEnabled` are verbatim
and no row was added, removed or reordered. Table names are the operator's own application schema and
name it identifiably, and this fixture exists for the ENVELOPE, not for what the tables are called.
