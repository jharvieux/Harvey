# Free-tier scan — scope definition (DRAFT for review)

**Positioning:** the free scan runs on source alone — no database, no credentials, no contact with production. It surfaces what the code *indicates* is wrong and explains it, building trust before the customer hands over any access. The paid tiers then confirm against production and prove exploitability.

## Indicated vs proved — the honest free-tier claim (and the upsell)

The free (mechanical) tier produces **indicators, not verdicts.** It reads source and reports what the code *indicates* — it does not, and structurally cannot, prove that a finding is reachable or exploitable in production. That gap between **indicated** (free, mechanical) and **proved** (paid: semantic cross-file review, connected read-only confirmation, dynamic pen-test) is the product's spine, not a disclaimer to bury.

**This is measured, not asserted.** `docs/design/free-tier-recall-measurement.md` (2026-07-26) records the free mechanical tier's recall against answer keys other people wrote. The honest form is a **range, not a single number**: mechanical recall against independent keys is **shape-dependent** — strong when a target matches the org-tenant / Supabase-Auth / App-Router / migration-SQL shapes the rules are written against, and low when it doesn't (the extreme case, a target engineered to defeat linters, asserts none of its planted flaws mechanically and is carried entirely by the paid semantic tier). Even on our own fixtures, only a fraction of request→sink source bugs fire at the high-confidence tier; the rest surface as lower-confidence indicators. Quote the measurement doc's dated range, never a number from memory.

**What this means for how the free report reads:** a strong free result is a genuine head start; a thin free result on an evasive target is **not a clean bill of health** — it is exactly where the paid tiers earn their keep. The free scan's job is to be honestly useful and to make that boundary legible, so "static analysis indicates X; confirm it by…" is the natural bridge to paid confirmation, not a hedge. Where the free tier is silent on a whole class — open-ended authorization reasoning, live RLS effect, exploitability — it is silent because it could not look, and it says so (see the ceiling and reserved-for-paid sections below). **The classes that need judgment or a running system are not gaps to apologize for; they are the paid tier's remit** — the concrete "indicated vs proved" upsell for each is spelled out in *Explicitly reserved for paid*.

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

**Which modules appear in this table is a one-field product lever (#1415, operator ruling
2026-07-28).** `MODULES[<id>].freeTier` in `src/audit-coverage.ts` is the authoritative commercial
flag and is read by `selectFreeFindings` (`src/quick-scan.ts`) — the function that decides what a
free-tier client actually receives. `needs` in the same table is a purely TECHNICAL statement (what
a module requires to execute) and the two are deliberately allowed to disagree: a paid-LLM module
can be given away as an acquisition hook, and a source-only module can be moved behind the paywall,
without touching any other code. `src/audit-coverage.test.ts` reads THIS table and fails if a value
here and the code disagree, so changing the free tier means editing both together — which is the
intended friction, because this table is what a client was promised.

### Machine-readable exports (#867/#887)

The free source scan can also emit the two artifacts a buyer's own tooling ingests:
`quick-scan --sarif-out <file>` writes SARIF 2.1.0 for GitHub code scanning / ASPM, and
`--sbom-out <file>` writes a CycloneDX 1.5 dependency inventory. Both flags are also on `run-audit`,
where the SARIF additionally carries the per-module coverage ledger as `toolExecutionNotifications`
— so a module that did not run cannot disappear into "no results." Prefer the `run-audit` form when
the ledger matters.

## What source-only structurally cannot see (the mechanical ceiling)

Most of our custom semgrep rules are syntactic patterns; a minority use taint mode, and the OSS engine does not follow a tainted value out of the function it was read in. Measured in this repo 2026-07-23: request input reaching `exec()` inside the same function is caught; the identical flow is missed the moment it passes through a helper — whether that helper is in the same file or another one. (Re-derive the split by counting `mode: taint` in `src/scan/rules/semgrep/*.yml`; `pnpm detector-census` gives the per-module detector counts. Don't quote a stored number.)

That is the ceiling **of the semgrep engine**, and the distinction matters more than it looks. It is where real authorization bypasses live: middleware admits the route, the handler trusts the caller, the repository issues an unscoped query. No single function contains the bug — so the semgrep layer does not see it, and a free report's silence on that shape is not evidence of its absence.

**But Harvey's own AST layer is not the semgrep engine, and it does follow imports** (corrected 2026-07-31, #1267). `resolveImport`/`buildImportGraph` (`src/detectors/app-router.ts`, #380) resolve tsconfig path aliases and workspace packages, and **five production source files** build on them. MEASURED 2026-07-31, and quote the predicate with the number: non-test `.ts` files under `src/` that *import* either symbol from `app-router.ts` — four of them, `src/detectors/perf-code.ts` (the M7 entry-closure passes), `src/scan/service-role-literal.ts`, `src/scan/ssrf-wrapper.ts` (route → imported helper → `fetch()`) and, since #1267, `src/scan/bola-cross-file.ts` (authenticated route → imported repository → an ownership-scoped query on a service-role client) — plus `app-router.ts` itself, which defines them and drives its own M9 server-only and client-reachability passes with them. A bare `git grep -nE 'buildImportGraph|resolveImport' -- src/detectors/` returns 27 lines and is NOT this number: three further files only NAME the identifiers in prose (`src/detectors/slop.ts` calls `buildImportGraph` an untried candidate, `src/scan/external-corpus.ts` is a measurement note, `src/unstructured-claims-baseline.ts` is a verbatim copy of CLAUDE.md). So a specific cross-file chain, named and shaped, is a detector we can write, and two of them ship. What stays paid is the OPEN-ENDED version: deciding whether *any* path through an arbitrary codebase authorizes a request, which needs intent, not reachability. Every such detector ships at **review** tier, because an AST proves the chain, never that no gate exists in a module it did not read.

**Not every mechanical miss is the ceiling, though.** Some are *closeable* rule gaps — a shape a new detector could catch — and those are tracked as improvement issues, not framed as paid-only (measurement docs' per-target gap analyses distinguish the two; the closeable ones filed under #868 are the storage-bucket, PII-aware `USING(true)`, and verbose-error passes). The upsell is only for what an AST is the wrong instrument for — intent and live/exploitability — never for a mechanization we simply haven't shipped.

**Cross-file reachability used to be on that list and should not have been (#1267).** It was added on the strength of a measurement about semgrep OSS's taint engine, restated as a property of the mechanical tier as a whole, while the import-graph machinery was already shipping in the same repo. That is the shape this document has to guard against, because a foreclosing claim closes a file: nobody re-tests a path recorded that way, and the claim then reads as a product boundary for as long as it stands. When a class is not built, the honest wording is *not built*, with what it would take — a statement about our afternoon, not about the world.

## Explicitly reserved for paid

- **Connected (read-only DB):** live confirmation vs production — Supabase security/performance advisors, default privileges, pg_cron, realtime exposure, exposed schemas, the M7 DB advisor, the M10 protection-adequacy judgment. *"Is prod actually in this state."*
- **Dynamic (pen-test, M2):** proving a cross-tenant read returns another tenant's rows, no-rate-limit, service-seam bypass. Needs a running/staging instance. *"We proved it's exploitable."*
- **Cross-file authorization (the semantic pass):** the OPEN-ENDED version — whether any path through the codebase authorizes a request, which is a question about intended authority rather than about reachability. Named, shaped chains are mechanical and two ship today (`ssrf-wrapper.ts`, `bola-cross-file.ts`, both review tier); what they do not do is enumerate the chains nobody wrote a rule for, or read a gate in a module outside the resolved import. See the ceiling section above. *"We read the route end to end, not one function at a time."*
- **Webhook replay protection (the semantic pass):** the free tier flags an inbound webhook that never verifies a signature — a positive fact about missing code. Proving a *replay* guard's ABSENCE is the opposite shape: a rule flagging every HMAC webhook without a recognised nonce would fire on handlers that dedupe through an idempotency key, provider-side dedupe, or a database unique constraint. Measured as an LLM-tier class and recorded as an intended mechanical gap, gated so the corpus fails loud if a mechanical rule ever starts firing on it (`src/scan/calibration/b17-race-unscoped.entries.ts`). *"We read the handler and its callees and can tell a real replay defence from none."*
- **Permission-matrix coverage — the INTENDED-AUTHORITY half only (#1370 split this, 2026-07-30).** Which cells the roles × resources matrix *ought* to contain is a question about intended authority, not about code shape, and stays with the semantic pass and the M2 pen-test. Which cells *exist* is code shape, and the free tier now reports it: `SB-RLS-CMDGAP-ROLLUP` (`src/scan/supabase-static.ts`) reads table × command × role off the live policy set at the end of migration history — `parseLivePolicies` has carried both axes since #937 — and asks, for every RLS-enabled table whose policies leave SELECT/INSERT/UPDATE/DELETE uncovered, which connection performs the uncovered command. Review tier, rolled up, never graded. Note what the finding does and does not claim: a missing policy is **fail-closed** (Postgres denies the command), so the row is not "this table is exposed" — it is "if this operation works, it reaches the table through a service-role connection, a SECURITY DEFINER function or the table owner, and its tenant scoping is enforced in application code this RLS pass does not read." The sentence this bullet replaced declined the whole class as intended-authority-only, untested, in the same commit that retired the advertised capability.
- **M8 mutation testing:** the free tier reads tests statically; the paid pass runs the suite against mutated code to find the tests that cannot fail. Needs a runnable suite, so it is not source-only.
- **M6 verdicts:** the free tier says a shape *looks* hand-rolled; the paid pass triages each candidate and names the concrete replacement (and clears the ones that were deliberate — a `// WHY:` comment recording a considered tradeoff is an answer, not a defect). *"Here's what to replace it with, and what to leave alone."*

## Report framing (protects the brand, creates the upsell)

- Findings are **indicators, not verdicts**: "static analysis indicates X; confirm by…" — never "you are exploitable." Static has a higher false-positive rate; live confirmation is exactly the paid value.
- Every free report carries the point-in-time / not-a-guarantee / not-a-pen-test language already in the report cover.
- The gap between "indicated" and "confirmed/proved" is the natural bridge to the connected and dynamic tiers.

## Internal capture per free scan (feeds the go/no-go)

- Time spent, token/$ COGS, findings by severity, and one anonymizable finding for teardown content.
- Prospect reaction: would they pay to confirm? What would they pay?
