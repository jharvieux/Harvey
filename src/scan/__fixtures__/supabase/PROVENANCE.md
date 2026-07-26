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
