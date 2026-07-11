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
| **M1 Multi-tenant security** (lead) | RLS policies in migration SQL (disabled / missing / `USING(true)` / user-metadata / wrong-column & weak-WITH-CHECK semantic review); SECURITY DEFINER functions with unguarded privileged writes; `service_role` usage on client-reachable paths; missing admin-auth guards, permission-matrix gaps, error/PII egress, unvalidated redirect URLs, missing webhook-replay protection, in-memory rate limits. |
| **M3 Hotspots** | Churn × complexity, coupling, knowledge-risk, AI-provenance (needs git history). |
| **M4 Duplication** | jscpd. |
| **M5 Slop / dead code** | knip + slop detection. |
| **M6 Simplification / reuse** | quality pass. |
| **M7 Performance** | Code-level: render patterns, hook dependencies, oversized assets. Bundle-size pass **if** a build artifact is provided. |
| **M9 App-router / cache correctness** | Static. |
| **M10 PII/PHI/PCI** | Detection: classify sensitive columns from the schema in migrations — "here's every sensitive column and where it lives." |

## Explicitly reserved for paid

- **Connected (read-only DB):** live confirmation vs production — Supabase security/performance advisors, migration-vs-prod drift, default privileges, pg_cron, realtime exposure, exposed schemas, the M7 DB advisor, the M10 protection-adequacy judgment. *"Is prod actually in this state."*
- **Dynamic (pen-test, M2):** proving a cross-tenant read returns another tenant's rows, no-rate-limit, service-seam bypass. Needs a running/staging instance. *"We proved it's exploitable."*

## Report framing (protects the brand, creates the upsell)

- Findings are **indicators, not verdicts**: "static analysis indicates X; confirm by…" — never "you are exploitable." Static has a higher false-positive rate; live confirmation is exactly the paid value.
- Every free report carries the point-in-time / not-a-guarantee / not-a-pen-test language already in the report cover.
- The gap between "indicated" and "confirmed/proved" is the natural bridge to the connected and dynamic tiers.

## Internal capture per free scan (feeds the go/no-go)

- Time spent, token/$ COGS, findings by severity, and one anonymizable finding for teardown content.
- Prospect reaction: would they pay to confirm? What would they pay?
