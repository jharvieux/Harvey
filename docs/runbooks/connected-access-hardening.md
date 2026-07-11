# Paid connected-tier — customer DB access (DRAFT for review)

Proposed hardening for how a paid engagement gets read-only database access. Intended to slot into `docs/runbooks/engagement-access.md` and the intake questionnaire — this is the "how we connect" step made least-privilege, revocable, and auditable.

## Principles

Read-only. Least-privilege. Time-boxed. Revocable. Logged. The customer should never hand over a standing superuser password, and we should never hold long-lived broad credentials.

## Preferred credential, in order

1. **Dedicated read-only role, provisioned for the engagement.** The customer creates a role scoped to the catalog/metadata the scan reads — `pg_catalog`, `information_schema`, `pg_policies`, `pg_proc`, table/column grants — ideally without broad table-data `SELECT`. Time-boxed; revoked at engagement close. *Best option: least data exposure, revocable, clearly scoped.*
2. **Read replica connection.** If the customer has a replica, connect there — zero write path to prod, isolated load.
3. **Supabase Management-API token (scoped).** Pulls advisors and runs read-only SQL via the platform API without a raw DB password; token-scoped and revocable. Good where direct DB connections aren't practical.
4. **`service_role` key — read-only use only, last resort.** Works for advisor + PostgREST-level checks when a scoped role isn't feasible. Because it's broad, prefer options 1–3; if used, treat as time-boxed and rotate at close.

## What NOT to do

- **Don't use MCP as the engagement data plane.** MCP is an interactive, agent-coupled channel with inconsistent availability (a customer's prod project may not expose SQL at all). Fine for our own dogfooding; wrong for delivering a client scan. The scanner's direct read-only connection is the right mechanism.
- **Don't accept a standing superuser / owner password.** Ask for a scoped role or replica instead.
- **Don't store credentials in the repo, findings files, tickets, or logs.** Secrets manager / env only.

## Mechanics

- Connection string held only in the engagement environment (secrets manager or env var), never committed. The scanner reads it via `SUPABASE_DB_URL` and runs read-only.
- Define an **engagement window**; the customer revokes/rotates the credential at close, and we confirm.
- The scan is read-only by construction (catalog reads); keep a record of the queries run so the customer can audit exactly what we touched.
- On multi-backend / monorepo targets, request one scoped credential per backend (main, RAG, etc.), matching the existing manifest/enumeration step.

## Intake questionnaire — add

- Which connection method (scoped role / replica / Management-API token / service_role)?
- Per backend: host, database, the read-only credential, and the write-safe/test designation.
- Engagement window + who revokes at close.
- Confirmation that the credential is read-only and scoped (or a replica).

## Trust ladder this supports

Free source-only scan (no credentials) → paid connected (this scoped, revocable read-only credential) → paid dynamic (staging instance + scoped destructive-safe access). Each step asks for a little more access after the prior one has already delivered value.
