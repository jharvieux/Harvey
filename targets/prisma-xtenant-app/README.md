# prisma-xtenant-app — cross-tenant BOLA fixture (#796/#1163)

**INTENTIONALLY VULNERABLE. Never deploy.**

A minimal Prisma membership app — `User <- TeamMember(teamId, userId, role) -> Team` plus two
tenant-scoped resource models (`Document`, `ApiKey`) — built to regression-gate the **authenticated
cross-tenant BOLA/IDOR probe** (`src/pentest/prisma-xtenant.ts`, `crossTenantProbe`, #787). It is the
cross-tenant counterpart to `targets/vuln-seam-app` (which gates the seam + missing-auth probes): that
fixture is a plain Supabase/RLS app with no Prisma membership model, so the cross-tenant control was
split here (#796).

On a Prisma app the HTTP route is the only tenancy gate, so the leak signal is simply: an
authenticated non-member reaching another team's scoped route and receiving data.

## How it is exercised

It is a **real, bootable** Next.js 14 App Router app (#1163): next-auth (JWT sessions) + Prisma. The
route handlers authenticate the caller by decoding the next-auth session cookie and read team data via
Prisma; the tenancy decision itself lives in the shared pure core `app/api/teams/_tenancy.js`.

- **Offline** (`src/pentest/prisma-xtenant-fixture.test.ts`, in `pnpm verify`): drives the shared
  `_tenancy.js` core over the in-memory `app/api/teams/_db.js` seed through the real `crossTenantProbe`
  — no Docker, no app boot.
- **Live** (`src/pentest/prisma-standup.ts`, `pnpm dynamic-validate targets/prisma-xtenant-app
  --execute`): stands up a real Postgres, applies this schema with the resolved `prisma` CLI (Prisma 7
  supplies the datasource URL out-of-schema, #1163), seeds two teams, boots the app, mints two
  next-auth sessions, and drives the same core through the booted app over HTTP.

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
omits the membership check. Live, Harvey's generic two-tenant seed assigns the two teams the slugs
`harvey-seed-a` / `harvey-seed-b` (matching the offline seed above) and adds two distinct member users,
so the same answer key holds against the booted app.
