// Batch B20 (#901, remainder of #869) — the Drizzle-idiom of the cross-tenant BOLA class graduates
// into the scored M1 recall corpus, mirroring B19 (#760, Prisma). The detector
// (src/scan/drizzle-tenant-scope.ts, registered as scanDrizzleTenantScope in runMechanicalScan)
// flags a db.select()/update()/delete()...where(eq(table.id, …)) read/write filtered by primary key
// alone with no tenant/owner column — the isolation gate a Drizzle app has instead of RLS. Stays
// REVIEW tier: the AST proves the where clause carries no tenant column, not that an ownership check
// in a wrapper it can't see is absent. The negative scopes each query to organizationId and clears.

import type { CorpusEntry } from "./types.js";

export const b20DrizzleTenantScopeEntries: CorpusEntry[] = [
  {
    id: "P-DRIZZLE-TENANT-SCOPE",
    kind: "positive",
    cls: "Drizzle query filtered by primary key with no tenant scope (cross-tenant BOLA/IDOR)",
    location: "src/db/task-repo-drizzle.ts",
    match: ["drizzle-tenant-scope"],
    expectedTier: "review",
    note: "#901: src/db/task-repo-drizzle.ts runs db.select().from(tasks).where(eq(tasks.id, id)) plus the update/delete equivalents — filtered by primary key alone. A Drizzle app has no database-level tenant enforcement (no RLS), so this where clause is the only isolation gate; filtered by id alone, any authenticated caller who substitutes another tenant's task id reads or mutates that tenant's row — the shape that made proposit Critical. scanDrizzleTenantScope (src/scan/drizzle-tenant-scope.ts) proves the builder-chain shape, an eq(t.id, …) filter, and NO tenant/owner column in any comparison → review. Discriminator: the MISSING tenant column, not the query's presence. Stays review: the AST can't see an ownership check in a wrapper. The negative adds eq(tasks.organizationId, …) and clears.",
  },
  {
    id: "N-DRIZZLE-TENANT-SCOPED",
    kind: "negative",
    cls: "same Drizzle reads/writes, each scoped to the caller's organizationId in the where",
    location: "src/db/task-repo-drizzle-safe.ts",
    match: ["drizzle-tenant-scope"],
    note: "#901: src/db/task-repo-drizzle-safe.ts runs the same reads/writes but with .where(and(eq(tasks.id, id), eq(tasks.organizationId, organizationId))) — the tenant column confines the row to the caller's tenant, so filteredColumns() sees organizationId and no finding fires. Cleared. Recorded to complete the corpus pair.",
  },
];
