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

3. **Read-only Supabase connection string.**
   - Request a Postgres role/connection scoped to `SELECT` only — no
     `INSERT`/`UPDATE`/`DELETE`/DDL.
   - Verify before use: check the role's grants (`\du`, or query
     `information_schema.role_table_grants`) and confirm no write
     privileges are present. Do not verify by attempting a live write —
     inspect grants instead.

4. **Staging environment credentials** — optional. Only requested if the
   client has a staging environment for M2 dynamic testing; otherwise we
   run those probes against a locally seeded stack instead, and no
   additional credential is needed.
   - Request credentials scoped to staging only, valid for the engagement
     window.
   - Verify the connection targets staging, not production (distinct
     hostname/connection string), before running anything against it.

5. **Auth questionnaire answers** (issue #31 doc when it lands, or the
   intake-site form fields today — `intake-site/index.html`'s "Tenancy &
   authentication" through "Context" sections). Should already be in hand
   from intake; confirm nothing is blank before kickoff.

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
      string
- [ ] Ask the client to revoke staging credentials, if any were issued (or
      confirm engagement-window expiry)
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
- The read-only database connection has been [revoked by you / confirmed expired].
- [Staging credentials have been revoked by you / confirmed expired. / N/A — no staging was used.]
- The local repository checkout and all scan artifacts on our side have been deleted.

We retain the delivered report and a business record of the engagement
(dates, scope — no code or client data). Nothing else survives on our end.

Thanks for working with us.

— Harvey
```
