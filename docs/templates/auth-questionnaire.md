# Auth & tenancy kickoff questionnaire (canonical)

> **Detect > ask.** Per `docs/audit-modules.md` M10 and the applicability framework in
> `docs/tier1-runbook.md` §5: anything derivable from code, schema, or config is detected, not
> asked (e.g. PII/PHI/PCI columns are matched against infoType dictionaries, never self-reported).
> This questionnaire covers **only the remainder** — facts that live in the client's head or their
> platform dashboard, not in the repo. It is the single source of truth for the kickoff question
> set referenced by `docs/audit-report-skeleton.md` §0 and `docs/example-report-atc.md`, and for the
> Tier-1-relevant subset in `docs/tier1-runbook.md` §3. The client intake site
> (`intake-site/index.html`) renders a client-facing form covering the same ground — keep the two in
> sync; this doc is the source of truth if they ever diverge.

**Rule, applied throughout:** where a question below asks about a control or practice, "I don't
know" is not a non-answer — it's itself a finding (unverified security posture), and gets tagged
and reported as such, same as a confirmed gap. See `docs/tier1-runbook.md` §3.

---

## 0. Application & backend topology (monorepo-aware)

*Why: a customer repo is often several apps on several backends with trust boundaries between
them — e.g. a Next.js `apps/main` + `apps/rag` + a browser `apps/extension`, each with its own
Supabase project, plus service-to-service calls and cross-service webhooks. We enumerate this from
your repo (workspace manifest, route trees, env-var names — the target-manifest step in
`docs/runbooks/engagement-access.md`), and every enumerated app/backend/seam must have a recorded
test result before the engagement is "complete" (the coverage gate fails loud on any that don't).
Three things here can't be read from code and must come from you; the first is a confirmation so
nothing is silently skipped.*

- **Confirm the app/service inventory.** We'll show you the apps/services we found in your workspace
  (each deployable app, plus client-only surfaces like a browser extension). Confirm it's complete
  and flag anything deployed from *outside* this repo (a separate service, an edge/function set, a
  mobile client).
- **Backends and connection info — one set per distinct database/project.** For **each** backend
  (e.g. a primary Supabase project *and* a separate RAG/analytics project), we need: the project
  URL, the anon/publishable key, a **read-only** Postgres connection string (SELECT-only), and —
  only for the write-safe environment below — a service-role key and the JWT secret so we can mint
  test identities. Provide these **per backend**; don't assume one set covers all of them (missing
  one is how a whole backend goes untested).
- **Which environment is safe for write/destructive testing?** Cross-tenant *write* probes and
  rate-limit loops mutate data, so they only run against a **non-production** target you designate.
  Tell us, per backend, which instance is write-safe — and if a backend is a single
  production-serving database with no test instance, say so and we keep it **read-only**.
- **Inter-service trust boundaries (seams).** For each service-to-service link: what's the internal
  service URL (network-restricted or publicly reachable?), how is the calling service authenticated
  (a shared service JWT, mTLS, a header secret?), and how is each cross-service webhook's
  authenticity verified? These seams fall between the per-app checks and are where
  monorepo-specific bugs live.

## 1. Tenancy model intent

*Why: the scan needs to know what "correct" tenant isolation looks like before it can find where
the code deviates from it. This can't be inferred reliably from schema alone — a table without an
obvious tenant column might be intentionally global, or might be a missed isolation boundary.*

- How are tenants modeled? Organizations/workspaces (users belong to an org), per-user-is-the-tenant,
  schema-per-tenant, or something else?
- What column or mechanism ties a row to its tenant (e.g. `org_id` on every table, a tenant-scoped
  schema, a join through a membership table)?
- Is tenant scoping consistent across the whole app, or are there known exceptions (e.g. a shared
  reference-data table, a public-by-design resource)?
- **Multi-tenancy membership rules:** can a single user belong to more than one tenant? If so, how
  do they switch context, and how is the "current tenant" determined server-side (session, header,
  route param)? Is there a cross-tenant support/admin role, and if so, how is *its* access scoped
  (all tenants unconditionally, or per-tenant grant)?

## 2. Auth provider and authorization enforcement (as intended)

*Why: findings are a diff between intended and actual enforcement. Without a stated intent, every
gap looks equally uncertain; with it, a missing RLS policy on a table the client says should be
enforced at the API layer only might be fine — or a genuine gap if they say RLS was supposed to be
the backstop.*

- Auth provider (Supabase Auth, Clerk, Auth0, NextAuth/Auth.js, custom, other)?
- Where is authorization *intended* to be enforced — check all that apply: Postgres row-level
  security policies, Next.js middleware, per-route/API handler checks, database functions/stored
  procedures? Is enforcement supposed to be defense-in-depth (multiple layers) or is one layer
  meant to be authoritative?
- Are there routes or tables that are intentionally public (no tenant/auth check by design)? List
  them so the scan doesn't flag them as gaps.

## 3. Roles and permissions matrix

*Why: "who can do what" is business intent, not something derivable from code — a role name in the
database tells us nothing about whether its permissions match what the client actually wants.*

- What user roles exist, and what should each be able to do? Include any cross-tenant or
  support/admin roles and exactly what elevated access they're meant to have (see §1's
  cross-tenant-role question — the two should agree).
- Are role/permission checks meant to be uniform across the app, or does a role's authority vary
  by feature/resource?

## 4. Data sensitivity and compliance context

*Why: `tools/pii-classify.mjs` (M10) detects PII/PHI/PCI-shaped columns from the schema — that part
is never asked. What's asked here is the parts detection can't reach: whether a compliance regime
applies (a business/legal decision, not a schema fact) and any data handling the client considers
sensitive that doesn't look like standard PII by column name.*

- Do you handle PII, PHI (health data), or payment/cardholder data — and is there anything sensitive
  in your domain that a generic PII scan might miss (e.g. an industry-specific identifier)?
- Which compliance regimes apply to you: SOC 2, HIPAA, PCI-DSS, GDPR, none/not yet? If "not yet,"
  is one anticipated (e.g. pursuing SOC 2 for an enterprise deal) — this changes which gaps are
  worth flagging now versus later.

## 5. Staging environment and M2 dynamic testing

*Why: M2 (local penetration test, `docs/audit-modules.md`) proves the highest-severity static
findings by actually attempting cross-tenant access. It needs somewhere to run that isn't
production, and needs the client's consent to put synthetic data there.*

- Do you have a staging environment we could use for dynamic testing? If not, could one be stood up,
  or should we run probes against a locally seeded copy of your stack instead?
- **Seeded test tenants:** is it acceptable to create synthetic test tenants/users (e.g. two
  throwaway orgs, "Tenant A" / "Tenant B") in that environment so we can assert neither can reach
  the other's data? If staging shares infrastructure with anything sensitive (e.g. a shared
  payment-processor sandbox), say so — it changes what we're willing to seed there.
- **Per backend:** the write-safe target is designated **per backend** in §0 — a multi-backend app
  may have a write-safe test instance for one database and a read-only-only production database for
  another. Write probes run only against the instances marked write-safe there.

## 6. Integrations and security surface

*Why: webhooks, background jobs, and edge functions are often auth-adjacent surface that's easy to
miss in a code-only review — a webhook handler's authenticity check, a queue consumer's tenant
scoping, or an edge function's exposure aren't always obvious from reading the route tree alone,
and knowing they exist up front means the scan brief actually looks for them.*

- What webhooks do you receive or send (e.g. Stripe, a payment processor, a CRM)? How is inbound
  webhook authenticity verified (signature check, shared secret, IP allowlist)?
- What background jobs or queues exist, and do any of them process cross-tenant data (e.g. a
  batch job that touches every tenant's rows deliberately)?
- Do you use edge functions (Vercel Edge, Supabase Edge Functions)? Do any of them bypass the
  normal request path's auth checks (e.g. a public edge function that calls a privileged API)?
- **Inter-service seams (monorepo):** if your services call each other (see §0), how does the
  receiving service authenticate the caller, and is each internal endpoint reachable only through
  its fronting app or also directly? We probe these seams specifically — direct-service-call
  (can the internal service be hit without the gateway?), service-JWT verification (is a forged
  token rejected, or only decoded?), and cross-service webhook signatures.

## 7. Audit motivation and history

*Why: a client who says "we had a near-miss on tenant isolation last quarter" changes where we
look first and how hard we press on the areas adjacent to that incident. This is context no scan
can generate on its own.*

- What prompted this audit (new enterprise customer's security review, a compliance deadline, a
  general health check, something else)?
- Are there known problem areas you'd want us to prioritize, or parts of the codebase you already
  suspect are weak?
- Any past security incidents, near-misses, or bug-bounty/pentest findings we should know about?
- Timeline: as soon as possible, within the month, this quarter, or just exploring?

---

## Relationship to the platform-config checklist

`docs/tier1-runbook.md` §3 lists a shorter, Tier-1-scan-relevant checklist of Supabase
auth/platform-config items that can't be derived from SQL alone (splinter reads the database, not
the project's Auth settings page): leaked-password protection, MFA enforcement, minimum password
strength, email confirmation, sign-in/sign-up rate-limiting, the redirect-URL allowlist,
session/JWT expiry and refresh-token rotation, service-role-key hygiene (server-only, rotated,
never bundled — cross-check M9), RLS-enabled-by-default discipline on new tables, and custom SMTP.
Those items are confirmed during kickoff (platform dashboard walkthrough or direct answers from
whoever administers the Supabase project), using the same rule as everything above: an unconfirmed
item is a finding, not a pass. Treat that list as part of this questionnaire's scope, not a
separate one to keep in sync by hand.
