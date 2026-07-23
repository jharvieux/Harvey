# prisma-xtenant-app — offline cross-tenant BOLA fixture (#796)

**INTENTIONALLY VULNERABLE. Never deploy.**

A minimal Prisma membership app — `User <- TeamMember(teamId, userId, role) -> Team` plus two
tenant-scoped resource models (`Document`, `ApiKey`) — built to regression-gate the **authenticated
cross-tenant BOLA/IDOR probe** (`src/pentest/prisma-xtenant.ts`, `crossTenantProbe`, #787) offline,
the M2 analogue of M1's calibration negatives. It is the cross-tenant counterpart to
`targets/vuln-seam-app` (which gates the seam + missing-auth probes): that fixture is a plain
Supabase/RLS app with no Prisma membership model, so the cross-tenant control was split here (#796).

On a Prisma app the HTTP route is the only tenancy gate, so the leak signal is simply: an
authenticated non-member reaching another team's scoped route and receiving data.

## Seed

| team | slug | member |
|------|------|--------|
| team-a | `harvey-seed-a` | user-a (session `sess-user-a`) |
| team-b | `harvey-seed-b` | user-b (session `sess-user-b`) |

user-a is a member of team-a only, so user-a reaching team-b is a genuine cross-tenant access.

## Answer key — scored by `src/pentest/prisma-xtenant-fixture.test.ts`

| route | scoping | probe verdict |
|-------|---------|---------------|
| `GET /api/teams/[slug]/members` | membership-checked (403 for non-members) | **unproven / clean** (negative control) |
| `GET /api/teams/[slug]/documents` | UNSCOPED — no membership check | **proven** cross-tenant BOLA (positive control) |

Both are team-scoped routes (`:slug` tenant segment) that authenticate the caller; only `/documents`
omits the membership check. The offline standing check drives the real `crossTenantProbe` against each
route in isolation via the probe's own synchronous `XtSend` seam — no Docker, no app boot — so it runs
in `pnpm verify` and CI. The live end-to-end proof (Docker + Postgres + `prisma migrate` + minted
next-auth sessions) is `prisma-standup.ts`; this is its offline precision gate.
