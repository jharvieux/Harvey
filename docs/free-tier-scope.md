# Free-tier scan — scope definition (DRAFT for review)

**Positioning:** the free scan runs on source alone — no database, no credentials, no contact with production. It surfaces what the code *indicates* is wrong and explains it, building trust before the customer hands over any access. The paid tiers then confirm against production and prove exploitability.

## Onboarding (the whole point: no credentials)

- **Preferred:** read-only access to the repository **with git history** (a read-only GitHub invite / deploy key, or a mirror).
- **Acceptable:** a code archive (zip/tarball).
- **Not required:** any database connection, service-role key, deploy URL, or `.env`.
- Turnaround target: same-day, because there's nothing to provision.

> Why history matters: the hotspots module (churn × complexity, knowledge-risk, AI-provenance) reads git history. A bare code copy still gets everything else, but loses those signals — so prefer repo access with history.

## What the free scan delivers (source-only)

| Module | Source-only coverage |
|---|---|
| **M1 Multi-tenant security** | **Supabase targets:** RLS policies in migration SQL (disabled / missing / `USING(true)` / user-metadata / wrong-column & weak-WITH-CHECK semantic review); SECURITY DEFINER functions with unguarded privileged writes; `service_role` usage on client-reachable paths; missing admin-auth guards, per-route role checks (an authenticated route that never compares a role), error/PII egress, unvalidated redirect URLs, inbound webhooks with no signature verification, rate limiters backed by process-local state (a `Map` counter that resets on every serverless cold start). **Non-Supabase targets are also supported, detection-gated:** the DB-level RLS tier doesn't apply on Prisma/Drizzle/Kysely/TypeORM/Sequelize/Knex/Mongoose/raw-SQL data layers, so it's named not-assessed-by-architecture (`M1-ARCH-<LAYER>`) rather than silently skipped; tenant-scope/BOLA is instead checked app-layer, with a real detector for the Prisma and Drizzle query-builder idioms and a named not-assessed row for the remaining query-builder shapes, where Harvey has no detector yet. A non-JS/TS language in the mix gets its own named not-assessed row too (`M1-LANG-00`) — an unassessable layer or language is disclosed by name, never left silent. |
| **M3 Hotspots** | Churn × complexity, coupling, knowledge-risk, AI-provenance (needs git history). |
| **M4 Duplication** | jscpd. |
| **M5 Slop / dead code** | knip + slop detection. |
| **M6 Simplification / reuse** | **Indicators only, non-grading:** mechanically-recognisable hand-rolled shapes listed as "this looks hand-rolled; may be worth investigating" — never naming a replacement (that judgment is paid). Same form as the M1 source-tier RLS/authz indicators. Operator ruling 2026-07-15; the detectors shipped in #267 and this section renders in the free report today. Run `pnpm detector-census` for the current M6 count — don't quote a stored one. |
| **M7 Performance** | Code-level: render patterns, hook dependencies, oversized assets. Bundle-size pass **if** a build artifact is provided. |
| **M8 Test quality** | Static test-intent detectors: assertion-free, tautological, mock-of-the-subject, snapshot-only, call-count-only, tenant-isolation tests that mock the DB client, happy-path-only coverage on security-critical code. No tests at all is itself a finding, never a skip. Running the suite (mutation testing) is paid. |
| **M9 Server→client boundary / cache correctness** | Static — and no longer Next-only (#916–#918): a framework-agnostic boundary model routes **Remix**, **React Router 7** and **TanStack Start** to their own adapters alongside Next App Router. Astro/SvelteKit/Nuxt get a named not-assessed row rather than a silent Next-premise run. |
| **M10 PII/PHI/PCI** | Detection: classify sensitive columns from the schema in migrations — "here's every sensitive column and where it lives." |

### Machine-readable exports (#867/#887)

The free source scan can also emit the two artifacts a buyer's own tooling ingests:
`quick-scan --sarif-out <file>` writes SARIF 2.1.0 for GitHub code scanning / ASPM, and
`--sbom-out <file>` writes a CycloneDX 1.5 dependency inventory. Both flags are also on `run-audit`,
where the SARIF additionally carries the per-module coverage ledger as `toolExecutionNotifications`
— so a module that did not run cannot disappear into "no results." Prefer the `run-audit` form when
the ledger matters.

## What source-only structurally cannot see (the mechanical ceiling)

Most of our custom semgrep rules are syntactic patterns; a minority use taint mode, and the OSS engine does not follow a tainted value out of the function it was read in. Measured in this repo 2026-07-23: request input reaching `exec()` inside the same function is caught; the identical flow is missed the moment it passes through a helper — whether that helper is in the same file or another one. (Re-derive the split by counting `mode: taint` in `src/scan/rules/semgrep/*.yml`; `pnpm detector-census` gives the per-module detector counts. Don't quote a stored number.)

That is the ceiling, and it is where real authorization bypasses live: middleware admits the route, the handler trusts the caller, the repository issues an unscoped query. No single function contains the bug. Mechanical misses of that class are **not fixable rule gaps** — they route by design to the paid semantic (LLM) pass, which reads across files, and to the dynamic pen-test, which proves the bypass from the outside. Where a free report is silent on cross-file authorization, it is silent because it could not look — not because it looked and found nothing.

## Explicitly reserved for paid

- **Connected (read-only DB):** live confirmation vs production — Supabase security/performance advisors, default privileges, pg_cron, realtime exposure, exposed schemas, the M7 DB advisor, the M10 protection-adequacy judgment. *"Is prod actually in this state."*
- **Dynamic (pen-test, M2):** proving a cross-tenant read returns another tenant's rows, no-rate-limit, service-seam bypass. Needs a running/staging instance. *"We proved it's exploitable."*
- **Cross-file authorization (the semantic pass):** the dataflow the mechanical tier structurally cannot follow — see the ceiling section above. *"We read the route end to end, not one function at a time."*
- **Webhook replay protection (the semantic pass):** the free tier flags an inbound webhook that never verifies a signature — a positive fact about missing code. Proving a *replay* guard's ABSENCE is the opposite shape: a rule flagging every HMAC webhook without a recognised nonce would fire on handlers that dedupe through an idempotency key, provider-side dedupe, or a database unique constraint. Measured as an LLM-tier class and recorded as an intended mechanical gap, gated so the corpus fails loud if a mechanical rule ever starts firing on it (`src/scan/calibration/b17-race-unscoped.entries.ts`). *"We read the handler and its callees and can tell a real replay defence from none."*
- **Permission-matrix coverage:** the free tier's role check is per-route — an authenticated route that never compares a role. Whether the roles × resources matrix as a whole has a hole is a question about intended authority, not about code shape, and stays with the semantic pass and the M2 pen-test.
- **M8 mutation testing:** the free tier reads tests statically; the paid pass runs the suite against mutated code to find the tests that cannot fail. Needs a runnable suite, so it is not source-only.
- **M6 verdicts:** the free tier says a shape *looks* hand-rolled; the paid pass triages each candidate and names the concrete replacement (and clears the ones that were deliberate — a `// WHY:` comment recording a considered tradeoff is an answer, not a defect). *"Here's what to replace it with, and what to leave alone."*

## Report framing (protects the brand, creates the upsell)

- Findings are **indicators, not verdicts**: "static analysis indicates X; confirm by…" — never "you are exploitable." Static has a higher false-positive rate; live confirmation is exactly the paid value.
- Every free report carries the point-in-time / not-a-guarantee / not-a-pen-test language already in the report cover.
- The gap between "indicated" and "confirmed/proved" is the natural bridge to the connected and dynamic tiers.

## Internal capture per free scan (feeds the go/no-go)

- Time spent, token/$ COGS, findings by severity, and one anonymizable finding for teardown content.
- Prospect reaction: would they pay to confirm? What would they pay?
