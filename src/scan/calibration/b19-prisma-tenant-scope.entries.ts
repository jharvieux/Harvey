// Batch B19 (#760, part of #756) — the Prisma-idiom of the cross-tenant BOLA class graduates into
// the scored M1 recall corpus, mirroring #433 (bola-owner) and #681/#684 (job-tenant-scope). The
// detector (src/scan/prisma-tenant-scope.ts, registered as scanPrismaTenantScope in
// runMechanicalScan) flags a `prisma.<model>.<verb>({ where: { id } })` read/write filtered by
// primary key alone with no tenant/owner column — the isolation gate a Prisma app has instead of
// RLS. Stays REVIEW tier: the AST proves the where clause carries no tenant column, not that an
// ownership check in a wrapper it can't see is absent. The negative scopes each query to
// organizationId and must clear. See #760, GROUND-TRUTH.md §B19.

import type { CorpusEntry } from "./types.js";

export const b19PrismaTenantScopeEntries: CorpusEntry[] = [
  {
    id: "P-PRISMA-TENANT-SCOPE",
    kind: "positive",
    cls: "Prisma query filtered by primary key with no tenant scope (cross-tenant BOLA/IDOR)",
    location: "src/db/task-repo.ts",
    match: ["prisma-tenant-scope"],
    expectedTier: "review",
    note: "#760: src/db/task-repo.ts calls prisma.task.findUnique/update/delete({ where: { id } }) — filtered by primary key alone. A Prisma app has no database-level tenant enforcement (no RLS), so this where clause is the only isolation gate; filtered by id alone, any authenticated caller who substitutes another tenant's task id reads or mutates that tenant's row — the shape that made proposit Critical. scanPrismaTenantScope (src/scan/prisma-tenant-scope.ts) proves the prisma.<model>.<verb> shape, an `id` filter, and NO tenant/owner column anywhere in the where → review. Discriminator: the MISSING tenant column, not the query's presence. Stays review: the AST can't see an ownership check in a wrapper. The negative adds organizationId and clears.",
  },
  {
    id: "N-PRISMA-TENANT-SCOPED",
    kind: "negative",
    cls: "same Prisma reads/writes, each scoped to the caller's organizationId in the where",
    location: "src/db/task-repo-safe.ts",
    match: ["prisma-tenant-scope"],
    note: "#760: src/db/task-repo-safe.ts runs the same reads/writes but with { where: { id, organizationId } } (findFirst/updateMany/deleteMany for the non-unique tenant predicate) — the tenant column confines the row to the caller's tenant, so hasTenantScopeKey() is satisfied and no finding fires. Cleared. Recorded to complete the corpus pair.",
  },
];
