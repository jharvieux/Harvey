import { eq } from "drizzle-orm";
import { db } from "./drizzle-client";
import { tasks } from "./drizzle-schema";

// #901 positive fixture: a Drizzle app has no RLS, so these builder-chain queries' where clauses are
// the only tenant-isolation gate — and they filter by primary key alone. Any authenticated caller
// who substitutes another tenant's task id reads or mutates that tenant's row (cross-tenant BOLA).

export async function getTask(id: string) {
  return db.select().from(tasks).where(eq(tasks.id, id));
}

export async function renameTask(id: string, name: string) {
  return db.update(tasks).set({ name }).where(eq(tasks.id, id));
}

export async function deleteTask(id: string) {
  return db.delete(tasks).where(eq(tasks.id, id));
}
