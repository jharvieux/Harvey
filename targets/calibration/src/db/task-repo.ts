import { prisma } from "./client";

// #760 positive fixture: a Prisma app has no RLS, so these repo functions' where clauses are the
// only tenant-isolation gate — and they filter by primary key alone. Any authenticated caller who
// substitutes another tenant's task id reads or mutates that tenant's row (cross-tenant BOLA).

export async function getTask(id: string) {
  return prisma.task.findUnique({ where: { id } });
}

export async function renameTask(id: string, name: string) {
  return prisma.task.update({ where: { id }, data: { name } });
}

export async function deleteTask(id: string) {
  return prisma.task.delete({ where: { id } });
}
