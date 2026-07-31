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

## What this capture does NOT prove

REASON: No live-project `GET /v1/projects/{ref}/config/auth` response BODY is committed — the field names are confirmed against the vendor's published response schema, not against a project's actual JSON, and #1291 reports a live 200 that differs from that schema in six keys.
KIND: empirical
PROVENANCE: TRIED 2026-07-31 (re-tested, #1291) — `supabase projects list` still reports "Access token not provided", `env | grep -c SUPABASE` is 0 and `/Users/<user>/.supabase` holds only telemetry, so no project of the operator's can be read from this worktree. A fresh `curl -s https://api.supabase.com/api/v1-json` succeeded and re-confirmed the vendor schema at 237 properties / 237 required with zero drift from the 2026-07-26 capture, which is what makes this a MISSING-CREDENTIAL blocker rather than a missing-network one. The falsifier's first form was a bare `test -n "$(git ls-files …)"`, which SWALLOWS the subshell's own failure: MEASURED 2026-07-31 with git absent from PATH it printed "git: command not found" and exited 1 — i.e. it reported the blocker as still holding when it had in fact measured nothing, the direction the #1246 rule requires to be 127. The `command -v git` / `git rev-parse --git-dir` preamble makes that path explicit, and all three directions were then exercised verbatim: exit 1 as committed (no live capture tracked), exit 0 with a `config-auth-live-*.json` staged (blocker gone), exit 127 with git off PATH (unverifiable).
FALSIFIER: command -v git >/dev/null 2>&1 || exit 127; git rev-parse --git-dir >/dev/null 2>&1 || exit 127; test -n "$(git ls-files 'src/scan/__fixtures__/supabase/config-auth-live-*.json')"
TOUCHES: src/scan/supabase-config.ts src/scan/supabase.ts

A body capture would additionally pin the runtime types and confirm the values a real project
returns. To land one: run the capture with an access token for a project the operator owns, redact
`smtp_*`/`sms_*` credentials and any hook secret, and commit it as
`config-auth-live-<YYYY-MM-DD>.json` beside this file — which is exactly what the falsifier above
watches for.
