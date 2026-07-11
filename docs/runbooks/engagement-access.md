# Engagement access — provisioning & teardown

Operator checklist for what to request from a client at kickoff and what to
destroy at close. Extracted from `docs/design/architecture.md` §4 (access
modes) and §6 (secrets/retention), which remain the source of truth for the
underlying design decisions — this doc is the runbook, not a re-derivation.

Credential-channel language matches the intake site (`intake-site/`, issues
#32/#33): tokens and connection strings move as an **expiring, view-limited
share link** from the client's own password manager, or Bitwarden Send if
they don't have one. Never through the intake form, never by plain email.

## Provisioning (engagement open)

Request these in order — each depends on confirming the previous one, and
none should be requested before the engagement is actually scoped and
quoted.

1. **Repository read access.** Collaborator invite with read permission, or
   a zip export if the client prefers not to add a collaborator. Verify by
   cloning (or unzipping) before proceeding — confirm you can read the repo
   and cannot push to it.

2. **Fine-grained GitHub PAT**, requested once repo access is confirmed.
   - Scopes must be **exactly** `contents:read`, plus `pull_requests:write`
     only if fix delivery was purchased. Nothing broader — no
     `contents:write`, no other repos, no org-wide access.
   - Verify before accepting: open the token's permissions page (GitHub
     Settings → Developer settings → Fine-grained tokens) and confirm the
     repository list and permission set match exactly. Reject and ask for
     reissue if it's broader than requested.

3. **Target manifest — enumerate apps, backends, and seams first.** Once the
   repo is cloned, build the target manifest (`discoverTargets`, `src/pentest/targets.ts`):
   every workspace app, every distinct Supabase backend (by env-var
   convention), and every inter-service seam (service URLs, webhook secrets,
   service JWTs). Confirm the app inventory with the client (questionnaire §0)
   and flag anything deployed from outside the repo. The manifest drives the
   **completeness gate** — every enumerated app/backend/seam must have a
   recorded test result at close, or the engagement is not complete.

4. **Read-only Supabase connection string — one per backend.** A monorepo has
   more than one database (ATC: a primary project + a separate RAG project);
   request a set for **each** backend in the manifest, not one for the repo.
   - Per backend: the project URL, anon/publishable key, and a Postgres
     role/connection scoped to `SELECT` only — no `INSERT`/`UPDATE`/`DELETE`/DDL.
   - Verify before use: check the role's grants (`\du`, or query
     `information_schema.role_table_grants`) and confirm no write privileges
     are present. Do not verify by attempting a live write — inspect grants instead.

5. **Write-safe environment credentials — per backend, optional.** Cross-tenant
   *write* probes and rate-limit loops mutate data, so they run only against a
   **non-production** instance the client designates as write-safe (questionnaire
   §0). For each such instance, request a service-role key and the JWT secret
   (needed to mint the "Tenant A" / "Tenant B" identities the RLS probes act as),
   scoped to that instance and valid for the engagement window.
   - Verify the connection targets the write-safe instance, not production
     (distinct hostname/connection string / project ref), before running anything.
   - A backend that is a single production-serving database with no test
     instance stays **read-only** — no service-role/write step for it.
   - If a backend has no write-safe instance at all, run its dynamic probes
     against a locally seeded stack instead.

6. **Inter-service seam details.** For each seam in the manifest: the internal
   service URL and whether it's network-restricted or publicly reachable, the
   service-to-service auth mechanism (shared JWT / mTLS / header secret), and how
   each cross-service webhook verifies authenticity. Needed so the seam probes
   (direct-service-call, service-JWT-verification, cross-service-webhook) target
   real endpoints.

7. **Auth questionnaire answers** (`docs/templates/auth-questionnaire.md`, or the
   intake-site form fields — `intake-site/index.html`'s "Application & backend
   topology" through "Context" sections). Should already be in hand from intake;
   confirm nothing is blank before kickoff, including the §0 topology/connection
   answers that steps 3–6 depend on.

### Where client secrets live during the engagement

- macOS keychain, or an env var/`.env` scoped to the engagement machine
  only. Never committed to this repo or the client's repo, never written
  into `findings/*.json` or any file under the engagement directory, never
  logged (the audit-trail log in architecture.md §6 records router calls
  and finding ids — never secret values or prompt bodies).
- One named human, one machine per engagement — credentials and checkout
  are not shared across engagements or team members.
- The engagement directory (`~/harvey-engagements/<slug>/` — see
  architecture.md §3) holds findings, reports, logs, and scan artifacts.
  Secrets are never part of that tree.

## Teardown (engagement close)

### Revoke / ask-revoke checklist

- [ ] Ask the client to revoke or delete the fine-grained PAT (or confirm
      it has already expired)
- [ ] Ask the client to revoke or rotate the read-only DB role/connection
      string **for each backend** issued (main, RAG, …)
- [ ] Ask the client to revoke the write-safe-instance service-role keys and
      JWT secrets, per backend, if any were issued (or confirm engagement-window
      expiry)
- [ ] Remove repo collaborator access if it was granted directly (in
      addition to, or instead of, the PAT)

### Purge checklist (operator side)

- [ ] Delete the local git checkout / zip extraction
- [ ] Delete scan artifacts (`raw/<runId>/<module>/` scratch output)
- [ ] Delete findings drafts that didn't make the final delivered report
- [ ] Delete this engagement's secrets from keychain/env
- [ ] Run `harvey purge <slug>` (architecture.md's designed purge command)
      once the retention window closes — default 90 days post-delivery
      unless the engagement contract states otherwise

**Retained:** the delivered report and the engagement record (Supabase
metadata rows — slug, dates, token spend; no client code or content).
**Destroyed:** local checkout, scan artifacts, findings drafts, credentials.

### Client-facing confirmation-note template

```
Subject: Harvey engagement — access teardown confirmed

Hi <name>,

Teardown for the <repo/org> engagement is complete as of <date>:

- The fine-grained GitHub token has been [revoked by you / confirmed expired].
- The read-only database connection(s) for each backend have been [revoked by you / confirmed expired].
- [Write-safe-instance service credentials have been revoked by you / confirmed expired. / N/A — none were issued.]
- The local repository checkout and all scan artifacts on our side have been deleted.

We retain the delivered report and a business record of the engagement
(dates, scope — no code or client data). Nothing else survives on our end.

Thanks for working with us.

— Harvey
```
