import { and, eq } from "drizzle-orm";
import { db } from "./drizzle-client";
import { tasks } from "./drizzle-schema";

// #901 negative fixture: the same builder-chain reads/writes, each scoped to the caller's
// organizationId, so the where clause confines the row to the caller's tenant. The
// drizzle-tenant-scope pass must stay fully silent here (a tenant/owner column present in the where
// clears the finding).

export async function getTask(id: string, organizationId: string) {
  return db.select().from(tasks).where(and(eq(tasks.id, id), eq(tasks.organizationId, organizationId)));
}

export async function renameTask(id: string, organizationId: string, name: string) {
  return db.update(tasks).set({ name }).where(and(eq(tasks.id, id), eq(tasks.organizationId, organizationId)));
}

export async function deleteTask(id: string, organizationId: string) {
  return db.delete(tasks).where(and(eq(tasks.id, id), eq(tasks.organizationId, organizationId)));
}
